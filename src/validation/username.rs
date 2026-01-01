//! System username validation.
//!
//! Validates usernames for safe use with system user management commands.

use crate::error::{DaemonError, ValidationErrorKind};

/// Maximum length for system usernames (Linux standard).
const MAX_USERNAME_LENGTH: usize = 32;

/// Reserved system usernames that cannot be created or deleted.
const RESERVED_USERNAMES: &[&str] = &[
    "root",
    "daemon",
    "bin",
    "sys",
    "sync",
    "games",
    "man",
    "lp",
    "mail",
    "news",
    "uucp",
    "proxy",
    "www-data",
    "backup",
    "list",
    "irc",
    "gnats",
    "nobody",
    "systemd-network",
    "systemd-resolve",
    "messagebus",
    "sshd",
    "mysql",
    "postgres",
    "redis",
    "nginx",
    "apache",
    "_apt",
];

/// Validate a system username.
///
/// Rules:
/// - Must not be empty
/// - Must not exceed 32 characters
/// - Must start with a lowercase letter
/// - May only contain lowercase letters, digits, underscores, and hyphens
/// - Must not be a reserved system username
///
/// # Arguments
///
/// * `username` - The username to validate
///
/// # Returns
///
/// The validated username string if valid.
///
/// # Errors
///
/// Returns an error if the username fails validation.
pub fn validate_system_username(username: &str) -> Result<&str, DaemonError> {
    // Check for empty username
    if username.is_empty() {
        return Err(DaemonError::Validation {
            kind: ValidationErrorKind::InvalidParameter {
                param: "username".to_string(),
                message: "Username cannot be empty".to_string(),
            },
        });
    }

    // Check length
    if username.len() > MAX_USERNAME_LENGTH {
        return Err(DaemonError::Validation {
            kind: ValidationErrorKind::InvalidParameter {
                param: "username".to_string(),
                message: format!(
                    "Username exceeds maximum length of {} characters",
                    MAX_USERNAME_LENGTH
                ),
            },
        });
    }

    // Must start with a lowercase letter
    let first = username.chars().next().unwrap();
    if !first.is_ascii_lowercase() {
        return Err(DaemonError::Validation {
            kind: ValidationErrorKind::InvalidParameter {
                param: "username".to_string(),
                message: "Username must start with a lowercase letter".to_string(),
            },
        });
    }

    // Only allowed characters: lowercase letters, digits, underscore, hyphen
    for c in username.chars() {
        if !c.is_ascii_lowercase() && !c.is_ascii_digit() && c != '_' && c != '-' {
            return Err(DaemonError::Validation {
                kind: ValidationErrorKind::InvalidParameter {
                    param: "username".to_string(),
                    message: format!(
                        "Username contains invalid character '{}'. Only lowercase letters, digits, underscores, and hyphens are allowed",
                        c
                    ),
                },
            });
        }
    }

    // Check against reserved usernames
    if RESERVED_USERNAMES.contains(&username) {
        return Err(DaemonError::Validation {
            kind: ValidationErrorKind::InvalidParameter {
                param: "username".to_string(),
                message: format!("Username '{}' is reserved and cannot be used", username),
            },
        });
    }

    Ok(username)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_valid_usernames() {
        assert!(validate_system_username("john").is_ok());
        assert!(validate_system_username("john_doe").is_ok());
        assert!(validate_system_username("john-doe").is_ok());
        assert!(validate_system_username("john123").is_ok());
        assert!(validate_system_username("j").is_ok());
        assert!(validate_system_username("user_name-123").is_ok());
    }

    #[test]
    fn test_empty_username() {
        assert!(validate_system_username("").is_err());
    }

    #[test]
    fn test_too_long_username() {
        let long_name = "a".repeat(33);
        assert!(validate_system_username(&long_name).is_err());

        // Exactly 32 should be ok
        let exact_name = "a".repeat(32);
        assert!(validate_system_username(&exact_name).is_ok());
    }

    #[test]
    fn test_must_start_with_lowercase() {
        assert!(validate_system_username("1john").is_err());
        assert!(validate_system_username("_john").is_err());
        assert!(validate_system_username("-john").is_err());
        assert!(validate_system_username("John").is_err());
    }

    #[test]
    fn test_invalid_characters() {
        assert!(validate_system_username("john.doe").is_err());
        assert!(validate_system_username("john@doe").is_err());
        assert!(validate_system_username("john doe").is_err());
        assert!(validate_system_username("john$").is_err());
        assert!(validate_system_username("John").is_err()); // uppercase
    }

    #[test]
    fn test_reserved_usernames() {
        assert!(validate_system_username("root").is_err());
        assert!(validate_system_username("www-data").is_err());
        assert!(validate_system_username("nobody").is_err());
        assert!(validate_system_username("mysql").is_err());
    }
}
