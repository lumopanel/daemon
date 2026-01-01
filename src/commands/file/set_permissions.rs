//! Set permissions command.

use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;

use tracing::{debug, info, warn};

use crate::error::{CommandErrorKind, DaemonError, ValidationErrorKind};
use crate::validation::validate_path;

use super::super::traits::Command;
use super::super::types::{CommandParams, CommandResult, ExecutionContext};

/// Set file or directory permissions.
///
/// # Parameters
///
/// - `path` (required): The path to modify
/// - `mode` (required): Permissions in octal (e.g., "0644")
/// - `recursive` (optional): Apply recursively to directories (default: false)
pub struct SetPermissionsCommand;

impl Command for SetPermissionsCommand {
    fn name(&self) -> &'static str {
        "file.chmod"
    }

    fn validate(&self, params: &CommandParams) -> Result<(), DaemonError> {
        params.require_string("path")?;
        params.require_string("mode")?;
        Ok(())
    }

    fn execute(
        &self,
        ctx: &ExecutionContext,
        params: CommandParams,
    ) -> Result<CommandResult, DaemonError> {
        let path_str = params.get_string("path")?;
        let mode_str = params.get_string("mode")?;
        let recursive = params.get_optional_bool("recursive", false);

        // Validate the path
        let path = validate_path(&path_str)?;

        // Parse the mode
        let mode = parse_mode(&mode_str)?;

        debug!(
            request_id = %ctx.request_id,
            path = %path.display(),
            mode = format!("{:o}", mode),
            recursive = recursive,
            "Setting permissions"
        );

        // Check that the path exists and get metadata without following symlinks
        let metadata = fs::symlink_metadata(&path).map_err(|_| DaemonError::Command {
            kind: CommandErrorKind::ExecutionFailed {
                message: "Path does not exist".to_string(),
            },
        })?;

        // Refuse to operate on symlinks directly
        if metadata.file_type().is_symlink() {
            return Err(DaemonError::Command {
                kind: CommandErrorKind::ExecutionFailed {
                    message: "Cannot set permissions on symlink".to_string(),
                },
            });
        }

        let count = if recursive && metadata.is_dir() {
            set_permissions_recursive(&path, mode)?
        } else {
            let permissions = fs::Permissions::from_mode(mode);
            fs::set_permissions(&path, permissions).map_err(|e| DaemonError::Command {
                kind: CommandErrorKind::ExecutionFailed {
                    message: format!("Failed to set permissions: {}", e),
                },
            })?;
            1
        };

        info!(
            request_id = %ctx.request_id,
            path = %path.display(),
            mode = format!("{:o}", mode),
            count = count,
            "Permissions set successfully"
        );

        Ok(CommandResult::success(serde_json::json!({
            "path": path.to_string_lossy(),
            "mode": format!("{:04o}", mode),
            "files_modified": count,
        })))
    }
}

/// Parse an octal mode string (e.g., "0644") to a u32.
fn parse_mode(mode_str: &str) -> Result<u32, DaemonError> {
    let mode_str = mode_str.trim_start_matches('0');
    if mode_str.is_empty() {
        return Ok(0);
    }
    u32::from_str_radix(mode_str, 8).map_err(|_| DaemonError::Validation {
        kind: ValidationErrorKind::InvalidParameter {
            param: "mode".to_string(),
            message: "Invalid octal mode".to_string(),
        },
    })
}

/// Recursively set permissions on a directory and its contents.
///
/// Security: Uses symlink_metadata to avoid following symlinks, preventing
/// attackers from using symlinks to escape validated paths.
fn set_permissions_recursive(path: &Path, mode: u32) -> Result<usize, DaemonError> {
    let mut count = 0;

    // Set permissions on the directory itself
    let permissions = fs::Permissions::from_mode(mode);
    fs::set_permissions(path, permissions.clone()).map_err(|e| DaemonError::Command {
        kind: CommandErrorKind::ExecutionFailed {
            message: format!("Failed to set permissions on {}: {}", path.display(), e),
        },
    })?;
    count += 1;

    // Recurse into contents
    let entries = fs::read_dir(path).map_err(|e| DaemonError::Command {
        kind: CommandErrorKind::ExecutionFailed {
            message: format!("Failed to read directory {}: {}", path.display(), e),
        },
    })?;

    for entry in entries {
        let entry = entry.map_err(|e| DaemonError::Command {
            kind: CommandErrorKind::ExecutionFailed {
                message: format!("Failed to read directory entry: {}", e),
            },
        })?;

        let entry_path = entry.path();

        // Security: Use symlink_metadata to NOT follow symlinks
        let metadata = fs::symlink_metadata(&entry_path).map_err(|e| DaemonError::Command {
            kind: CommandErrorKind::ExecutionFailed {
                message: format!(
                    "Failed to read metadata for {}: {}",
                    entry_path.display(),
                    e
                ),
            },
        })?;

        // Skip symlinks entirely to prevent escaping validated paths
        if metadata.file_type().is_symlink() {
            warn!(
                path = %entry_path.display(),
                "Skipping symlink in recursive chmod"
            );
            continue;
        }

        if metadata.is_dir() {
            count += set_permissions_recursive(&entry_path, mode)?;
        } else {
            fs::set_permissions(&entry_path, permissions.clone()).map_err(|e| {
                DaemonError::Command {
                    kind: CommandErrorKind::ExecutionFailed {
                        message: format!(
                            "Failed to set permissions on {}: {}",
                            entry_path.display(),
                            e
                        ),
                    },
                }
            })?;
            count += 1;
        }
    }

    Ok(count)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::auth::PeerInfo;
    use std::fs::{self, File};
    use uuid::Uuid;

    fn create_test_context() -> ExecutionContext {
        ExecutionContext::new(
            Uuid::new_v4(),
            PeerInfo {
                uid: 1000,
                gid: 1000,
                pid: 12345,
            },
            1234567890,
            "file.chmod".to_string(),
        )
    }

    #[test]
    fn test_chmod_name() {
        let cmd = SetPermissionsCommand;
        assert_eq!(cmd.name(), "file.chmod");
    }

    #[test]
    fn test_chmod_validate() {
        let cmd = SetPermissionsCommand;

        let params = CommandParams::new(serde_json::json!({
            "path": "/tmp/lumo/test.txt",
            "mode": "0644"
        }));
        assert!(cmd.validate(&params).is_ok());

        let params = CommandParams::new(serde_json::json!({
            "path": "/tmp/lumo/test.txt"
        }));
        assert!(cmd.validate(&params).is_err());
    }

    #[test]
    fn test_chmod_execute() {
        // Ensure test directory exists
        fs::create_dir_all("/tmp/lumo").ok();

        // Create a test file
        let test_path = "/tmp/lumo/test_chmod.txt";
        File::create(test_path).unwrap();

        let cmd = SetPermissionsCommand;
        let ctx = create_test_context();
        let params = CommandParams::new(serde_json::json!({
            "path": test_path,
            "mode": "0755"
        }));

        let result = cmd.execute(&ctx, params).unwrap();
        assert!(result.success);

        // Verify permissions were set
        let metadata = fs::metadata(test_path).unwrap();
        assert_eq!(metadata.permissions().mode() & 0o777, 0o755);

        // Cleanup
        fs::remove_file(test_path).ok();
    }

    #[test]
    fn test_parse_mode_variations() {
        assert_eq!(parse_mode("0644").unwrap(), 0o644);
        assert_eq!(parse_mode("644").unwrap(), 0o644);
        assert_eq!(parse_mode("0755").unwrap(), 0o755);
        assert_eq!(parse_mode("0600").unwrap(), 0o600);
        assert!(parse_mode("invalid").is_err());
    }
}
