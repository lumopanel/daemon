//! Domain name validation.
//!
//! Validates domain names for SSL certificates and Nginx configuration.

use crate::error::{DaemonError, ValidationErrorKind};

/// Maximum length for a domain name.
const MAX_DOMAIN_LENGTH: usize = 253;

/// Maximum length for a domain label (part between dots).
const MAX_LABEL_LENGTH: usize = 63;

/// Validates a domain name.
///
/// # Rules
///
/// - Must be 1-253 characters
/// - Each label (part between dots) must be 1-63 characters
/// - Labels must start and end with alphanumeric characters
/// - Labels can contain hyphens but not at start or end
/// - No wildcards allowed (for security)
/// - Must have at least one dot (no bare TLDs)
///
/// # Arguments
///
/// * `domain` - The domain name to validate
///
/// # Returns
///
/// The validated domain or an error.
pub fn validate_domain(domain: &str) -> Result<&str, DaemonError> {
    // Check for empty domain
    if domain.is_empty() {
        return Err(DaemonError::Validation {
            kind: ValidationErrorKind::InvalidParameter {
                param: "domain".to_string(),
                message: "Domain name cannot be empty".to_string(),
            },
        });
    }

    // Check total length
    if domain.len() > MAX_DOMAIN_LENGTH {
        return Err(DaemonError::Validation {
            kind: ValidationErrorKind::InvalidParameter {
                param: "domain".to_string(),
                message: format!(
                    "Domain name exceeds maximum length of {} characters",
                    MAX_DOMAIN_LENGTH
                ),
            },
        });
    }

    // Reject wildcards for security
    if domain.contains('*') {
        return Err(DaemonError::Validation {
            kind: ValidationErrorKind::InvalidParameter {
                param: "domain".to_string(),
                message: "Wildcard domains are not allowed".to_string(),
            },
        });
    }

    // Reject trailing dot (we normalize without it)
    let domain = domain.trim_end_matches('.');

    // Split into labels
    let labels: Vec<&str> = domain.split('.').collect();

    // Must have at least 2 labels (domain + TLD)
    if labels.len() < 2 {
        return Err(DaemonError::Validation {
            kind: ValidationErrorKind::InvalidParameter {
                param: "domain".to_string(),
                message: "Domain must have at least two parts (e.g., example.com)".to_string(),
            },
        });
    }

    // Validate each label
    for label in &labels {
        validate_domain_label(label)?;
    }

    Ok(domain)
}

/// Validates a single domain label (part between dots).
fn validate_domain_label(label: &str) -> Result<(), DaemonError> {
    // Check for empty label
    if label.is_empty() {
        return Err(DaemonError::Validation {
            kind: ValidationErrorKind::InvalidParameter {
                param: "domain".to_string(),
                message: "Domain contains empty label (consecutive dots)".to_string(),
            },
        });
    }

    // Check label length
    if label.len() > MAX_LABEL_LENGTH {
        return Err(DaemonError::Validation {
            kind: ValidationErrorKind::InvalidParameter {
                param: "domain".to_string(),
                message: format!(
                    "Domain label '{}' exceeds maximum length of {} characters",
                    label, MAX_LABEL_LENGTH
                ),
            },
        });
    }

    let chars: Vec<char> = label.chars().collect();

    // First character must be alphanumeric
    if !chars[0].is_ascii_alphanumeric() {
        return Err(DaemonError::Validation {
            kind: ValidationErrorKind::InvalidParameter {
                param: "domain".to_string(),
                message: format!(
                    "Domain label '{}' must start with a letter or number",
                    label
                ),
            },
        });
    }

    // Last character must be alphanumeric
    if !chars[chars.len() - 1].is_ascii_alphanumeric() {
        return Err(DaemonError::Validation {
            kind: ValidationErrorKind::InvalidParameter {
                param: "domain".to_string(),
                message: format!("Domain label '{}' must end with a letter or number", label),
            },
        });
    }

    // All characters must be alphanumeric or hyphen
    for c in &chars {
        if !c.is_ascii_alphanumeric() && *c != '-' {
            return Err(DaemonError::Validation {
                kind: ValidationErrorKind::InvalidParameter {
                    param: "domain".to_string(),
                    message: format!(
                        "Domain label '{}' contains invalid character '{}'",
                        label, c
                    ),
                },
            });
        }
    }

    Ok(())
}

/// Validates a Nginx site name.
///
/// # Rules
///
/// - Must be 1-64 characters
/// - Can contain alphanumeric, dots, dashes, and underscores
/// - Must start with alphanumeric character
///
/// # Arguments
///
/// * `site_name` - The site name to validate
///
/// # Returns
///
/// The validated site name or an error.
pub fn validate_site_name(site_name: &str) -> Result<&str, DaemonError> {
    // Check for empty name
    if site_name.is_empty() {
        return Err(DaemonError::Validation {
            kind: ValidationErrorKind::InvalidParameter {
                param: "site_name".to_string(),
                message: "Site name cannot be empty".to_string(),
            },
        });
    }

    // Check length
    if site_name.len() > 64 {
        return Err(DaemonError::Validation {
            kind: ValidationErrorKind::InvalidParameter {
                param: "site_name".to_string(),
                message: "Site name exceeds maximum length of 64 characters".to_string(),
            },
        });
    }

    // First character must be alphanumeric
    let first_char = site_name.chars().next().unwrap();
    if !first_char.is_ascii_alphanumeric() {
        return Err(DaemonError::Validation {
            kind: ValidationErrorKind::InvalidParameter {
                param: "site_name".to_string(),
                message: "Site name must start with a letter or number".to_string(),
            },
        });
    }

    // All characters must be valid
    for c in site_name.chars() {
        if !c.is_ascii_alphanumeric() && c != '.' && c != '-' && c != '_' {
            return Err(DaemonError::Validation {
                kind: ValidationErrorKind::InvalidParameter {
                    param: "site_name".to_string(),
                    message: format!("Site name contains invalid character '{}'", c),
                },
            });
        }
    }

    // Check for path traversal attempts
    if site_name.contains("..") {
        return Err(DaemonError::Validation {
            kind: ValidationErrorKind::InvalidParameter {
                param: "site_name".to_string(),
                message: "Site name contains path traversal sequence".to_string(),
            },
        });
    }

    Ok(site_name)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_valid_domains() {
        assert!(validate_domain("example.com").is_ok());
        assert!(validate_domain("sub.example.com").is_ok());
        assert!(validate_domain("my-site.example.org").is_ok());
        assert!(validate_domain("a1.b2.c3.example.net").is_ok());
    }

    #[test]
    fn test_invalid_domains() {
        // Empty
        assert!(validate_domain("").is_err());
        // No TLD
        assert!(validate_domain("localhost").is_err());
        // Wildcard
        assert!(validate_domain("*.example.com").is_err());
        // Invalid characters
        assert!(validate_domain("example_site.com").is_err());
        assert!(validate_domain("example site.com").is_err());
        // Starting with hyphen
        assert!(validate_domain("-example.com").is_err());
        // Ending with hyphen
        assert!(validate_domain("example-.com").is_err());
        // Empty label
        assert!(validate_domain("example..com").is_err());
    }

    #[test]
    fn test_valid_site_names() {
        assert!(validate_site_name("example.com").is_ok());
        assert!(validate_site_name("my-site").is_ok());
        assert!(validate_site_name("site_config").is_ok());
        assert!(validate_site_name("default").is_ok());
    }

    #[test]
    fn test_invalid_site_names() {
        // Empty
        assert!(validate_site_name("").is_err());
        // Path traversal
        assert!(validate_site_name("../etc/passwd").is_err());
        assert!(validate_site_name("site..conf").is_err());
        // Invalid characters
        assert!(validate_site_name("site/config").is_err());
        assert!(validate_site_name("site;rm -rf").is_err());
    }
}
