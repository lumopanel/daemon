//! Service name validation.
//!
//! Validates that service names are in the allowed whitelist.

use crate::error::{DaemonError, ValidationErrorKind};

use super::whitelist::is_additional_service;

/// Allowed service names that can be controlled via the daemon.
///
/// This is a security-critical list. Only add services that should be
/// manageable through the daemon.
const ALLOWED_SERVICES: &[&str] = &[
    // Web servers
    "nginx",
    // PHP-FPM (various versions)
    "php8.1-fpm",
    "php8.2-fpm",
    "php8.3-fpm",
    "php8.4-fpm",
    // Databases
    "mysql",
    "mariadb",
    "postgresql",
    "redis-server",
    // Cache
    "memcached",
    // Process managers
    "supervisor",
    "supervisord",
];

/// Check if a service is allowed (built-in or configured).
fn is_service_allowed(name: &str) -> bool {
    ALLOWED_SERVICES.contains(&name) || is_additional_service(name)
}

/// Validate that a service name is in the allowed list.
///
/// # Arguments
///
/// * `name` - The service name to validate
///
/// # Returns
///
/// Returns `Ok(())` if the service name is allowed, or an error if not.
///
/// # Example
///
/// ```
/// use lumo_daemon::validation::validate_service_name;
///
/// assert!(validate_service_name("nginx").is_ok());
/// assert!(validate_service_name("malicious-service").is_err());
/// ```
pub fn validate_service_name(name: &str) -> Result<(), DaemonError> {
    // Check for empty service name
    if name.is_empty() {
        return Err(DaemonError::Validation {
            kind: ValidationErrorKind::InvalidParameter {
                param: "service".to_string(),
                message: "Service name cannot be empty".to_string(),
            },
        });
    }

    // Check against whitelist (built-in + configured)
    if !is_service_allowed(name) {
        return Err(DaemonError::Validation {
            kind: ValidationErrorKind::UnknownService {
                service: name.to_string(),
            },
        });
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_allowed_services() {
        // All whitelisted services should be valid
        assert!(validate_service_name("nginx").is_ok());
        assert!(validate_service_name("redis-server").is_ok());
        assert!(validate_service_name("php8.3-fpm").is_ok());
        assert!(validate_service_name("mysql").is_ok());
        assert!(validate_service_name("supervisor").is_ok());
    }

    #[test]
    fn test_unknown_service() {
        let result = validate_service_name("unknown-service");
        assert!(matches!(
            result,
            Err(DaemonError::Validation {
                kind: ValidationErrorKind::UnknownService { .. }
            })
        ));
    }

    #[test]
    fn test_empty_service_name() {
        let result = validate_service_name("");
        assert!(matches!(
            result,
            Err(DaemonError::Validation {
                kind: ValidationErrorKind::InvalidParameter { .. }
            })
        ));
    }

    #[test]
    fn test_dangerous_service_names() {
        // These should all be rejected
        assert!(validate_service_name("ssh").is_err());
        assert!(validate_service_name("sshd").is_err());
        assert!(validate_service_name("cron").is_err());
        assert!(validate_service_name("systemd").is_err());
        assert!(validate_service_name("dbus").is_err());
    }

    #[test]
    fn test_path_injection_attempts() {
        // Attempts to inject paths should be rejected
        assert!(validate_service_name("../etc/passwd").is_err());
        assert!(validate_service_name("nginx; rm -rf /").is_err());
        assert!(validate_service_name("nginx\nmalicious").is_err());
    }
}
