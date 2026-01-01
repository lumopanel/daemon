//! Package name validation.
//!
//! Validates that package names are in the allowed whitelist.

use std::collections::HashSet;
use std::sync::LazyLock;

use crate::error::{DaemonError, ValidationErrorKind};

use super::whitelist::{
    is_additional_package, is_additional_php_extension, is_additional_php_version,
};

/// PHP versions supported
const PHP_VERSIONS: &[&str] = &["8.1", "8.2", "8.3", "8.4"];

/// PHP extensions that can be installed
const PHP_EXTENSIONS: &[&str] = &[
    "fpm",
    "cli",
    "common",
    "mysql",
    "pgsql",
    "sqlite3",
    "redis",
    "memcached",
    "mongodb",
    "curl",
    "gd",
    "imagick",
    "intl",
    "mbstring",
    "xml",
    "zip",
    "bcmath",
    "soap",
    "opcache",
    "readline",
    "ldap",
    "imap",
    "gmp",
    "xdebug",
    "dev",
    "apcu",
    "igbinary",
    "msgpack",
];

/// Statically allowed packages (non-PHP).
const STATIC_PACKAGES: &[&str] = &[
    // Web servers
    "nginx",
    "nginx-extras",
    "nginx-full",
    // Cache
    "redis-server",
    "redis-tools",
    "memcached",
    "libmemcached-tools",
    // Databases
    "postgresql",
    "postgresql-client",
    "postgresql-14",
    "postgresql-15",
    "postgresql-16",
    "postgresql-17",
    "mariadb-server",
    "mariadb-client",
    "mysql-server",
    "mysql-client",
    // Process managers
    "supervisor",
    // Node.js
    "nodejs",
    "npm",
    // SSL/Certbot
    "certbot",
    "python3-certbot-nginx",
    // Common utilities
    "git",
    "unzip",
    "zip",
    "curl",
    "wget",
];

/// Lazily computed set of all allowed packages.
static ALLOWED_PACKAGES: LazyLock<HashSet<String>> = LazyLock::new(|| {
    let mut set = HashSet::new();

    // Add static packages
    for pkg in STATIC_PACKAGES {
        set.insert((*pkg).to_string());
    }

    // Generate PHP package names for all versions and extensions
    for version in PHP_VERSIONS {
        for ext in PHP_EXTENSIONS {
            set.insert(format!("php{}-{}", version, ext));
        }
    }

    set
});

/// Check if a package name is in the allowed whitelist.
pub fn is_package_allowed(name: &str) -> bool {
    // Strip version specifier if present (e.g., "nginx=1.18.0-0ubuntu1" -> "nginx")
    let base_name = name.split('=').next().unwrap_or(name);

    // Check static whitelist first
    if ALLOWED_PACKAGES.contains(base_name) {
        return true;
    }

    // Check if it's an additional package from config
    if is_additional_package(base_name) {
        return true;
    }

    // Check if it's a PHP package with additional version/extension
    if let Some(php_part) = base_name.strip_prefix("php") {
        // Parse "8.3-redis" format
        if let Some(dash_pos) = php_part.find('-') {
            let version = &php_part[..dash_pos];
            let ext = &php_part[dash_pos + 1..];

            // Check if version is allowed (built-in or additional)
            let version_allowed =
                PHP_VERSIONS.contains(&version) || is_additional_php_version(version);

            // Check if extension is allowed (built-in or additional)
            let ext_allowed = PHP_EXTENSIONS.contains(&ext) || is_additional_php_extension(ext);

            if version_allowed && ext_allowed {
                return true;
            }
        }
    }

    false
}

/// Validate that a package name is in the allowed list.
///
/// # Arguments
///
/// * `name` - The package name to validate
///
/// # Returns
///
/// Returns `Ok(())` if the package name is allowed, or an error if not.
pub fn validate_package_name(name: &str) -> Result<(), DaemonError> {
    // Check for empty package name
    if name.is_empty() {
        return Err(DaemonError::Validation {
            kind: ValidationErrorKind::InvalidParameter {
                param: "package".to_string(),
                message: "Package name cannot be empty".to_string(),
            },
        });
    }

    // Check for dangerous characters
    if name.contains("..") || name.contains('/') || name.contains('\n') || name.contains(';') {
        return Err(DaemonError::Validation {
            kind: ValidationErrorKind::InvalidParameter {
                param: "package".to_string(),
                message: "Package name contains invalid characters".to_string(),
            },
        });
    }

    // Check against whitelist
    if !is_package_allowed(name) {
        return Err(DaemonError::Validation {
            kind: ValidationErrorKind::PackageNotWhitelisted {
                package: name.to_string(),
            },
        });
    }

    Ok(())
}

/// Validate a list of package names.
///
/// # Arguments
///
/// * `packages` - The list of package names to validate
///
/// # Returns
///
/// Returns `Ok(())` if all package names are allowed, or the first error encountered.
pub fn validate_package_list(packages: &[String]) -> Result<(), DaemonError> {
    if packages.is_empty() {
        return Err(DaemonError::Validation {
            kind: ValidationErrorKind::InvalidParameter {
                param: "packages".to_string(),
                message: "Package list cannot be empty".to_string(),
            },
        });
    }

    if packages.len() > 20 {
        return Err(DaemonError::Validation {
            kind: ValidationErrorKind::InvalidParameter {
                param: "packages".to_string(),
                message: format!("Too many packages ({}), maximum is 20", packages.len()),
            },
        });
    }

    for package in packages {
        validate_package_name(package)?;
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_static_packages_allowed() {
        assert!(is_package_allowed("nginx"));
        assert!(is_package_allowed("redis-server"));
        assert!(is_package_allowed("postgresql"));
        assert!(is_package_allowed("supervisor"));
        assert!(is_package_allowed("nodejs"));
        assert!(is_package_allowed("certbot"));
    }

    #[test]
    fn test_php_packages_allowed() {
        assert!(is_package_allowed("php8.1-fpm"));
        assert!(is_package_allowed("php8.2-cli"));
        assert!(is_package_allowed("php8.3-mysql"));
        assert!(is_package_allowed("php8.4-redis"));
        assert!(is_package_allowed("php8.3-imagick"));
    }

    #[test]
    fn test_version_specifier_stripped() {
        // Package with version specifier should still be allowed
        assert!(is_package_allowed("nginx=1.18.0-0ubuntu1"));
        assert!(is_package_allowed("php8.3-fpm=8.3.0-1"));
    }

    #[test]
    fn test_unknown_packages_rejected() {
        assert!(!is_package_allowed("unknown-package"));
        assert!(!is_package_allowed("malware"));
        assert!(!is_package_allowed("php7.4-fpm")); // Old PHP version not allowed
    }

    #[test]
    fn test_dangerous_packages_rejected() {
        assert!(!is_package_allowed("ssh"));
        assert!(!is_package_allowed("openssh-server"));
        assert!(!is_package_allowed("cron"));
        assert!(!is_package_allowed("sudo"));
    }

    #[test]
    fn test_validate_empty_name() {
        let result = validate_package_name("");
        assert!(matches!(
            result,
            Err(DaemonError::Validation {
                kind: ValidationErrorKind::InvalidParameter { .. }
            })
        ));
    }

    #[test]
    fn test_validate_dangerous_characters() {
        assert!(validate_package_name("../etc/passwd").is_err());
        assert!(validate_package_name("nginx; rm -rf /").is_err());
        assert!(validate_package_name("nginx\nmalicious").is_err());
        assert!(validate_package_name("nginx/../../etc").is_err());
    }

    #[test]
    fn test_validate_package_list() {
        // Valid list
        let packages = vec!["nginx".to_string(), "redis-server".to_string()];
        assert!(validate_package_list(&packages).is_ok());

        // Empty list
        let empty: Vec<String> = vec![];
        assert!(validate_package_list(&empty).is_err());

        // List with invalid package
        let invalid = vec!["nginx".to_string(), "malware".to_string()];
        assert!(validate_package_list(&invalid).is_err());
    }

    #[test]
    fn test_validate_package_list_max_size() {
        // Create list with 21 packages (exceeds max of 20)
        let packages: Vec<String> = (0..21).map(|_| "nginx".to_string()).collect();
        assert!(validate_package_list(&packages).is_err());

        // Create list with 20 packages (at max)
        let packages: Vec<String> = (0..20).map(|_| "nginx".to_string()).collect();
        assert!(validate_package_list(&packages).is_ok());
    }
}
