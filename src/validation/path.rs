//! Path validation for secure file operations.
//!
//! Validates paths against allowed prefixes and prevents traversal attacks.

use std::path::{Component, Path, PathBuf};

use tracing::warn;

use crate::error::{DaemonError, ValidationErrorKind};

use super::whitelist::get_additional_path_prefixes;

/// Known safe system symlinks that should not trigger rejection.
/// On macOS, these are standard system configurations:
/// - /tmp -> private/tmp
/// - /var -> private/var
/// - /home -> /System/Volumes/Data/home
const SAFE_SYSTEM_SYMLINKS: &[&str] = &["/tmp", "/var", "/home"];

/// Check if a symlink is a known safe system symlink.
/// These are system-level symlinks like /tmp -> private/tmp on macOS.
fn is_safe_system_symlink(path: &Path) -> bool {
    let path_str = path.to_string_lossy();

    // Check if this is one of the known safe system symlinks
    for safe_symlink in SAFE_SYSTEM_SYMLINKS {
        if path_str == *safe_symlink {
            // Verify it actually resolves to a known system location
            if let Ok(resolved) = path.canonicalize() {
                let resolved_str = resolved.to_string_lossy();
                // On macOS, these are standard system symlinks:
                // - /tmp -> /private/tmp
                // - /var -> /private/var
                // - /home -> /System/Volumes/Data/home
                if resolved_str.starts_with("/private")
                    || resolved_str.starts_with("/System/Volumes/Data")
                {
                    return true;
                }
            }
        }
    }
    false
}

/// Check if any component of the path is a symlink.
///
/// This function uses `symlink_metadata` (lstat) to check each path component
/// without following symlinks, preventing TOCTOU race conditions.
///
/// Known safe system symlinks (like /tmp -> /private/tmp on macOS) are allowed.
fn contains_symlink(path: &Path) -> Result<bool, std::io::Error> {
    let mut current = PathBuf::new();

    for component in path.components() {
        match component {
            Component::RootDir => {
                current.push("/");
            }
            Component::Normal(name) => {
                current.push(name);
                if current.exists() {
                    // Use symlink_metadata to NOT follow symlinks
                    let metadata = std::fs::symlink_metadata(&current)?;
                    if metadata.file_type().is_symlink() {
                        // Allow known safe system symlinks
                        if !is_safe_system_symlink(&current) {
                            return Ok(true);
                        }
                    }
                }
            }
            Component::Prefix(prefix) => {
                current.push(prefix.as_os_str());
            }
            // Skip current dir (.) and parent dir (..) - parent dir is already rejected
            _ => {}
        }
    }

    Ok(false)
}

/// Allowed path prefixes for file operations.
///
/// These paths are considered safe for the daemon to write to.
/// Note: /tmp/lumo/ and /private/tmp/lumo/ are included for testing purposes.
/// On macOS, /tmp is a symlink to /private/tmp.
const ALLOWED_PREFIXES: &[&str] = &[
    "/tmp/lumo/",
    "/private/tmp/lumo/", // macOS: /tmp -> /private/tmp
    "/home/",
    "/etc/nginx/",
    "/etc/php/",
    "/etc/redis/",
    "/etc/supervisor/",
    "/etc/memcached/",
    "/etc/ssl/",
    "/etc/letsencrypt/",
    "/var/log/",
    "/var/www/",
];

/// Protected files that should never be modified.
const PROTECTED_FILES: &[&str] = &[
    "/etc/passwd",
    "/etc/shadow",
    "/etc/sudoers",
    "/etc/hosts",
    "/etc/resolv.conf",
];

/// Validates a path and returns the canonicalized version.
///
/// # Security Checks
///
/// 1. Path must start with an allowed prefix
/// 2. Path must not contain traversal sequences after canonicalization
/// 3. Path must not be a protected system file
///
/// # Arguments
///
/// * `path` - The path to validate
///
/// # Returns
///
/// The canonicalized path if validation passes, or an error.
pub fn validate_path(path: impl AsRef<Path>) -> Result<PathBuf, DaemonError> {
    let path = path.as_ref();

    // First, check for obvious traversal attempts in the raw path
    let path_str = path.to_string_lossy();
    if path_str.contains("..") {
        return Err(DaemonError::Validation {
            kind: ValidationErrorKind::PathTraversal {
                path: path.to_path_buf(),
            },
        });
    }

    // Security: Check for symlinks in the path to prevent TOCTOU attacks
    // We reject any path that contains a symlink component
    match contains_symlink(path) {
        Ok(true) => {
            warn!(path = %path.display(), "Rejecting path containing symlink");
            return Err(DaemonError::Validation {
                kind: ValidationErrorKind::PathTraversal {
                    path: path.to_path_buf(),
                },
            });
        }
        Err(e) => {
            warn!(path = %path.display(), error = %e, "Failed to check path for symlinks");
            return Err(DaemonError::Validation {
                kind: ValidationErrorKind::PathNotAllowed {
                    path: path.to_path_buf(),
                },
            });
        }
        Ok(false) => {
            // Path is safe, continue validation
        }
    }

    // For new files that don't exist yet, we validate the parent directory
    let (check_path, is_new_file) = if path.exists() {
        (path.to_path_buf(), false)
    } else {
        // For non-existent paths, validate the parent exists and is allowed
        let parent = path.parent().ok_or_else(|| DaemonError::Validation {
            kind: ValidationErrorKind::PathNotAllowed {
                path: path.to_path_buf(),
            },
        })?;

        if !parent.exists() {
            // Parent doesn't exist either - check if grandparent or higher exists
            // and is within allowed paths
            let mut ancestor = parent.to_path_buf();
            while !ancestor.exists() {
                ancestor = ancestor.parent().map(|p| p.to_path_buf()).ok_or_else(|| {
                    DaemonError::Validation {
                        kind: ValidationErrorKind::PathNotAllowed {
                            path: path.to_path_buf(),
                        },
                    }
                })?;
            }
            (ancestor, true)
        } else {
            (parent.to_path_buf(), true)
        }
    };

    // Canonicalize the existing portion of the path
    let canonical = check_path
        .canonicalize()
        .map_err(|_| DaemonError::Validation {
            kind: ValidationErrorKind::PathNotAllowed {
                path: path.to_path_buf(),
            },
        })?;

    // Reconstruct the full canonical path for new files
    let full_canonical = if is_new_file {
        let file_name = path.file_name().ok_or_else(|| DaemonError::Validation {
            kind: ValidationErrorKind::PathNotAllowed {
                path: path.to_path_buf(),
            },
        })?;

        // If there were intermediate directories, add them back
        // Safety: if we got a file_name, there must be a parent
        let parent = path.parent().unwrap_or(path);
        if parent.exists() {
            canonical.join(file_name)
        } else {
            // Need to add back the non-existent intermediate path components
            let existing_ancestor =
                check_path
                    .canonicalize()
                    .map_err(|_| DaemonError::Validation {
                        kind: ValidationErrorKind::PathNotAllowed {
                            path: path.to_path_buf(),
                        },
                    })?;

            // Strip the existing ancestor from the original path to get relative part
            let original_abs = if path.is_absolute() {
                path.to_path_buf()
            } else {
                std::env::current_dir()
                    .map_err(|_| DaemonError::Validation {
                        kind: ValidationErrorKind::PathNotAllowed {
                            path: path.to_path_buf(),
                        },
                    })?
                    .join(path)
            };

            // Find the relative suffix after the existing ancestor
            if let Ok(suffix) = original_abs.strip_prefix(&check_path) {
                existing_ancestor.join(suffix)
            } else {
                existing_ancestor.join(file_name)
            }
        }
    } else {
        canonical
    };

    let canonical_str = full_canonical.to_string_lossy();

    // Check against protected files
    for protected in PROTECTED_FILES {
        if canonical_str == *protected {
            return Err(DaemonError::Validation {
                kind: ValidationErrorKind::ProtectedFile {
                    path: full_canonical,
                },
            });
        }
    }

    // Check against allowed prefixes (built-in + configured)
    let is_allowed = ALLOWED_PREFIXES
        .iter()
        .any(|prefix| canonical_str.starts_with(prefix))
        || get_additional_path_prefixes()
            .iter()
            .any(|prefix| canonical_str.starts_with(prefix));

    if !is_allowed {
        return Err(DaemonError::Validation {
            kind: ValidationErrorKind::PathNotAllowed {
                path: full_canonical,
            },
        });
    }

    Ok(full_canonical)
}

/// Validates a path for directory creation.
///
/// Similar to `validate_path` but handles the case where
/// the target directory doesn't exist yet.
pub fn validate_directory_path(path: impl AsRef<Path>) -> Result<PathBuf, DaemonError> {
    let path = path.as_ref();

    // Check for traversal attempts
    let path_str = path.to_string_lossy();
    if path_str.contains("..") {
        return Err(DaemonError::Validation {
            kind: ValidationErrorKind::PathTraversal {
                path: path.to_path_buf(),
            },
        });
    }

    // Security: Check for symlinks in the path to prevent TOCTOU attacks
    match contains_symlink(path) {
        Ok(true) => {
            warn!(path = %path.display(), "Rejecting directory path containing symlink");
            return Err(DaemonError::Validation {
                kind: ValidationErrorKind::PathTraversal {
                    path: path.to_path_buf(),
                },
            });
        }
        Err(e) => {
            // For non-existent paths, symlink check may fail - that's okay
            // as long as existing components don't contain symlinks
            if path.exists() {
                warn!(path = %path.display(), error = %e, "Failed to check directory path for symlinks");
                return Err(DaemonError::Validation {
                    kind: ValidationErrorKind::PathNotAllowed {
                        path: path.to_path_buf(),
                    },
                });
            }
        }
        Ok(false) => {
            // Path is safe, continue validation
        }
    }

    // For directory paths, we need to check the path string directly
    // since the directory may not exist
    let is_allowed = ALLOWED_PREFIXES
        .iter()
        .any(|prefix| path_str.starts_with(prefix))
        || get_additional_path_prefixes()
            .iter()
            .any(|prefix| path_str.starts_with(prefix));

    if !is_allowed {
        return Err(DaemonError::Validation {
            kind: ValidationErrorKind::PathNotAllowed {
                path: path.to_path_buf(),
            },
        });
    }

    // If the path already exists, canonicalize and re-check
    if path.exists() {
        let canonical = path.canonicalize().map_err(|_| DaemonError::Validation {
            kind: ValidationErrorKind::PathNotAllowed {
                path: path.to_path_buf(),
            },
        })?;

        let canonical_str = canonical.to_string_lossy();
        let is_canonical_allowed = ALLOWED_PREFIXES
            .iter()
            .any(|prefix| canonical_str.starts_with(prefix))
            || get_additional_path_prefixes()
                .iter()
                .any(|prefix| canonical_str.starts_with(prefix));

        if !is_canonical_allowed {
            return Err(DaemonError::Validation {
                kind: ValidationErrorKind::PathNotAllowed { path: canonical },
            });
        }

        Ok(canonical)
    } else {
        // Return the absolute path
        if path.is_absolute() {
            Ok(path.to_path_buf())
        } else {
            std::env::current_dir()
                .map(|cwd| cwd.join(path))
                .map_err(|_| DaemonError::Validation {
                    kind: ValidationErrorKind::PathNotAllowed {
                        path: path.to_path_buf(),
                    },
                })
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    #[test]
    fn test_allowed_path() {
        // Create test directory
        let test_dir = PathBuf::from("/tmp/lumo");
        fs::create_dir_all(&test_dir).ok();

        let result = validate_path("/tmp/lumo/test.txt");
        assert!(result.is_ok());
    }

    #[test]
    fn test_disallowed_path() {
        let result = validate_path("/root/.bashrc");
        assert!(result.is_err());
    }

    #[test]
    fn test_traversal_attack() {
        let result = validate_path("/tmp/lumo/../../../etc/passwd");
        assert!(result.is_err());
        if let Err(DaemonError::Validation { kind }) = result {
            assert!(matches!(kind, ValidationErrorKind::PathTraversal { .. }));
        }
    }

    #[test]
    fn test_protected_file() {
        let result = validate_path("/etc/passwd");
        assert!(result.is_err());
    }

    #[test]
    fn test_home_directory() {
        // /home/ prefix is allowed
        let result = validate_directory_path("/home/testuser/public_html/");
        assert!(result.is_ok());
    }

    #[test]
    fn test_var_www() {
        let result = validate_directory_path("/var/www/html/");
        assert!(result.is_ok());
    }
}
