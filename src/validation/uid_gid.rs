//! UID and GID validation.
//!
//! Provides validators for user and group IDs to prevent integer overflow
//! when converting from i64 (JSON number) to u32 (Unix UID/GID).

use crate::error::{DaemonError, ValidationErrorKind};

/// Validate a user ID value.
///
/// Ensures the value is within the valid range for a Unix UID (0 to u32::MAX).
///
/// # Arguments
///
/// * `value` - The i64 value from JSON parameters
///
/// # Returns
///
/// * `Ok(u32)` - The validated UID
/// * `Err(DaemonError)` - If the value is negative or exceeds u32::MAX
pub fn validate_uid(value: i64) -> Result<u32, DaemonError> {
    if value < 0 {
        return Err(DaemonError::Validation {
            kind: ValidationErrorKind::InvalidParameter {
                param: "owner".to_string(),
                message: format!("UID cannot be negative: {}", value),
            },
        });
    }
    if value > u32::MAX as i64 {
        return Err(DaemonError::Validation {
            kind: ValidationErrorKind::InvalidParameter {
                param: "owner".to_string(),
                message: format!("UID exceeds maximum value ({}): {}", u32::MAX, value),
            },
        });
    }
    Ok(value as u32)
}

/// Validate a group ID value.
///
/// Ensures the value is within the valid range for a Unix GID (0 to u32::MAX).
///
/// # Arguments
///
/// * `value` - The i64 value from JSON parameters
///
/// # Returns
///
/// * `Ok(u32)` - The validated GID
/// * `Err(DaemonError)` - If the value is negative or exceeds u32::MAX
pub fn validate_gid(value: i64) -> Result<u32, DaemonError> {
    if value < 0 {
        return Err(DaemonError::Validation {
            kind: ValidationErrorKind::InvalidParameter {
                param: "group".to_string(),
                message: format!("GID cannot be negative: {}", value),
            },
        });
    }
    if value > u32::MAX as i64 {
        return Err(DaemonError::Validation {
            kind: ValidationErrorKind::InvalidParameter {
                param: "group".to_string(),
                message: format!("GID exceeds maximum value ({}): {}", u32::MAX, value),
            },
        });
    }
    Ok(value as u32)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_validate_uid_valid() {
        assert_eq!(validate_uid(0).unwrap(), 0);
        assert_eq!(validate_uid(1000).unwrap(), 1000);
        assert_eq!(validate_uid(65534).unwrap(), 65534); // nobody
        assert_eq!(validate_uid(u32::MAX as i64).unwrap(), u32::MAX);
    }

    #[test]
    fn test_validate_uid_negative() {
        let result = validate_uid(-1);
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(matches!(err, DaemonError::Validation { .. }));
    }

    #[test]
    fn test_validate_uid_overflow() {
        let result = validate_uid(u32::MAX as i64 + 1);
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(matches!(err, DaemonError::Validation { .. }));
    }

    #[test]
    fn test_validate_gid_valid() {
        assert_eq!(validate_gid(0).unwrap(), 0);
        assert_eq!(validate_gid(1000).unwrap(), 1000);
        assert_eq!(validate_gid(65534).unwrap(), 65534); // nogroup
        assert_eq!(validate_gid(u32::MAX as i64).unwrap(), u32::MAX);
    }

    #[test]
    fn test_validate_gid_negative() {
        let result = validate_gid(-1);
        assert!(result.is_err());
    }

    #[test]
    fn test_validate_gid_overflow() {
        let result = validate_gid(u32::MAX as i64 + 1);
        assert!(result.is_err());
    }
}
