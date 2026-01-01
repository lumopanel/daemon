//! Database validation for secure database operations.
//!
//! Validates database names, usernames, and types to prevent injection attacks.

use crate::error::{DaemonError, ValidationErrorKind};

/// Valid database types.
const VALID_DATABASE_TYPES: &[&str] = &["mysql", "postgresql"];

/// Maximum length for database names.
const MAX_DATABASE_NAME_LENGTH: usize = 64;

/// Maximum length for database usernames.
const MAX_DATABASE_USERNAME_LENGTH: usize = 32;

/// Validates a database name.
///
/// # Rules
///
/// - Must be 1-64 characters
/// - Must start with a letter or underscore
/// - Can contain only alphanumeric characters and underscores
/// - Cannot be a reserved MySQL/PostgreSQL keyword
///
/// # Arguments
///
/// * `name` - The database name to validate
///
/// # Returns
///
/// The validated name or an error.
pub fn validate_database_name(name: &str) -> Result<&str, DaemonError> {
    // Check for empty name
    if name.is_empty() {
        return Err(DaemonError::Validation {
            kind: ValidationErrorKind::InvalidParameter {
                param: "name".to_string(),
                message: "Database name cannot be empty".to_string(),
            },
        });
    }

    // Check length
    if name.len() > MAX_DATABASE_NAME_LENGTH {
        return Err(DaemonError::Validation {
            kind: ValidationErrorKind::InvalidParameter {
                param: "name".to_string(),
                message: format!(
                    "Database name exceeds maximum length of {} characters",
                    MAX_DATABASE_NAME_LENGTH
                ),
            },
        });
    }

    // Check first character (must be letter or underscore)
    let first_char = name.chars().next().unwrap();
    if !first_char.is_ascii_alphabetic() && first_char != '_' {
        return Err(DaemonError::Validation {
            kind: ValidationErrorKind::InvalidParameter {
                param: "name".to_string(),
                message: "Database name must start with a letter or underscore".to_string(),
            },
        });
    }

    // Check all characters (alphanumeric and underscore only)
    if !name.chars().all(|c| c.is_ascii_alphanumeric() || c == '_') {
        return Err(DaemonError::Validation {
            kind: ValidationErrorKind::InvalidParameter {
                param: "name".to_string(),
                message: "Database name can only contain letters, numbers, and underscores"
                    .to_string(),
            },
        });
    }

    // Check against reserved keywords
    let lower = name.to_lowercase();
    if is_reserved_keyword(&lower) {
        return Err(DaemonError::Validation {
            kind: ValidationErrorKind::InvalidParameter {
                param: "name".to_string(),
                message: format!("'{}' is a reserved database keyword", name),
            },
        });
    }

    Ok(name)
}

/// Validates a database username.
///
/// # Rules
///
/// - Must be 1-32 characters
/// - Must start with a letter or underscore
/// - Can contain only alphanumeric characters and underscores
///
/// # Arguments
///
/// * `username` - The database username to validate
///
/// # Returns
///
/// The validated username or an error.
pub fn validate_database_username(username: &str) -> Result<&str, DaemonError> {
    // Check for empty username
    if username.is_empty() {
        return Err(DaemonError::Validation {
            kind: ValidationErrorKind::InvalidParameter {
                param: "username".to_string(),
                message: "Database username cannot be empty".to_string(),
            },
        });
    }

    // Check length
    if username.len() > MAX_DATABASE_USERNAME_LENGTH {
        return Err(DaemonError::Validation {
            kind: ValidationErrorKind::InvalidParameter {
                param: "username".to_string(),
                message: format!(
                    "Database username exceeds maximum length of {} characters",
                    MAX_DATABASE_USERNAME_LENGTH
                ),
            },
        });
    }

    // Check first character (must be letter or underscore)
    let first_char = username.chars().next().unwrap();
    if !first_char.is_ascii_alphabetic() && first_char != '_' {
        return Err(DaemonError::Validation {
            kind: ValidationErrorKind::InvalidParameter {
                param: "username".to_string(),
                message: "Database username must start with a letter or underscore".to_string(),
            },
        });
    }

    // Check all characters (alphanumeric and underscore only)
    if !username
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '_')
    {
        return Err(DaemonError::Validation {
            kind: ValidationErrorKind::InvalidParameter {
                param: "username".to_string(),
                message: "Database username can only contain letters, numbers, and underscores"
                    .to_string(),
            },
        });
    }

    Ok(username)
}

/// Validates a database type.
///
/// # Valid Types
///
/// - "mysql"
/// - "postgresql"
///
/// # Arguments
///
/// * `db_type` - The database type to validate
///
/// # Returns
///
/// The validated type or an error.
pub fn validate_database_type(db_type: &str) -> Result<&str, DaemonError> {
    let lower = db_type.to_lowercase();
    if VALID_DATABASE_TYPES.contains(&lower.as_str()) {
        Ok(db_type)
    } else {
        Err(DaemonError::Validation {
            kind: ValidationErrorKind::InvalidParameter {
                param: "type".to_string(),
                message: format!(
                    "Invalid database type '{}', must be one of: {}",
                    db_type,
                    VALID_DATABASE_TYPES.join(", ")
                ),
            },
        })
    }
}

/// Check if a name is a reserved database keyword.
fn is_reserved_keyword(name: &str) -> bool {
    const RESERVED: &[&str] = &[
        // MySQL reserved
        "mysql",
        "information_schema",
        "performance_schema",
        "sys",
        // PostgreSQL reserved
        "postgres",
        "template0",
        "template1",
        // Common reserved
        "root",
        "admin",
        "test",
    ];
    RESERVED.contains(&name)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_valid_database_name() {
        assert!(validate_database_name("my_database").is_ok());
        assert!(validate_database_name("app_production").is_ok());
        assert!(validate_database_name("_private_db").is_ok());
        assert!(validate_database_name("db1").is_ok());
    }

    #[test]
    fn test_invalid_database_name() {
        // Empty
        assert!(validate_database_name("").is_err());
        // Starts with number
        assert!(validate_database_name("1database").is_err());
        // Contains special characters
        assert!(validate_database_name("my-database").is_err());
        assert!(validate_database_name("my.database").is_err());
        assert!(validate_database_name("my database").is_err());
        // SQL injection attempt
        assert!(validate_database_name("db; DROP TABLE users;--").is_err());
    }

    #[test]
    fn test_reserved_database_names() {
        assert!(validate_database_name("mysql").is_err());
        assert!(validate_database_name("information_schema").is_err());
        assert!(validate_database_name("postgres").is_err());
    }

    #[test]
    fn test_database_name_length() {
        let long_name = "a".repeat(65);
        assert!(validate_database_name(&long_name).is_err());
        let max_name = "a".repeat(64);
        assert!(validate_database_name(&max_name).is_ok());
    }

    #[test]
    fn test_valid_database_username() {
        assert!(validate_database_username("app_user").is_ok());
        assert!(validate_database_username("readonly").is_ok());
        assert!(validate_database_username("_admin").is_ok());
    }

    #[test]
    fn test_invalid_database_username() {
        // Empty
        assert!(validate_database_username("").is_err());
        // Starts with number
        assert!(validate_database_username("1user").is_err());
        // Contains special characters
        assert!(validate_database_username("user@host").is_err());
    }

    #[test]
    fn test_database_username_length() {
        let long_name = "a".repeat(33);
        assert!(validate_database_username(&long_name).is_err());
        let max_name = "a".repeat(32);
        assert!(validate_database_username(&max_name).is_ok());
    }

    #[test]
    fn test_valid_database_types() {
        assert!(validate_database_type("mysql").is_ok());
        assert!(validate_database_type("MySQL").is_ok());
        assert!(validate_database_type("postgresql").is_ok());
        assert!(validate_database_type("PostgreSQL").is_ok());
    }

    #[test]
    fn test_invalid_database_types() {
        assert!(validate_database_type("sqlite").is_err());
        assert!(validate_database_type("oracle").is_err());
        assert!(validate_database_type("").is_err());
    }
}
