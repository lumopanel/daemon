//! Repository validation.
//!
//! Validates that repository strings are in the allowed whitelist.

use std::collections::HashSet;
use std::sync::LazyLock;

use crate::error::{DaemonError, ValidationErrorKind};

use super::whitelist::is_additional_repository;

/// Allowed PPA repositories.
///
/// Only these specific PPAs can be added to the system.
const ALLOWED_PPAS: &[&str] = &[
    // PHP
    "ppa:ondrej/php",
    // Nginx
    "ppa:ondrej/nginx",
    "ppa:ondrej/nginx-mainline",
    // Redis
    "ppa:redislabs/redis",
    // Certbot/Let's Encrypt
    "ppa:certbot/certbot",
    // Git
    "ppa:git-core/ppa",
];

/// Lazily computed set of allowed repositories.
static ALLOWED_REPOSITORIES: LazyLock<HashSet<&'static str>> = LazyLock::new(|| {
    ALLOWED_PPAS.iter().copied().collect()
});

/// Check if a repository is in the allowed whitelist.
pub fn is_repository_allowed(repo: &str) -> bool {
    ALLOWED_REPOSITORIES.contains(repo) || is_additional_repository(repo)
}

/// Validate that a repository string is safe and allowed.
///
/// # Arguments
///
/// * `repo` - The repository string to validate (e.g., "ppa:ondrej/php")
///
/// # Returns
///
/// Returns `Ok(())` if the repository is allowed, or an error if not.
pub fn validate_repository(repo: &str) -> Result<(), DaemonError> {
    // Check for empty repository
    if repo.is_empty() {
        return Err(DaemonError::Validation {
            kind: ValidationErrorKind::InvalidParameter {
                param: "repository".to_string(),
                message: "Repository cannot be empty".to_string(),
            },
        });
    }

    // Check for dangerous characters (shell metacharacters)
    const DANGEROUS_CHARS: &[char] = &[';', '|', '&', '$', '`', '(', ')', '{', '}', '[', ']',
                                        '<', '>', '\n', '\r', '\\', '"', '\'', '*', '?', '!'];

    if repo.chars().any(|c| DANGEROUS_CHARS.contains(&c)) {
        return Err(DaemonError::Validation {
            kind: ValidationErrorKind::InvalidParameter {
                param: "repository".to_string(),
                message: "Repository contains invalid characters".to_string(),
            },
        });
    }

    // Validate format: must be ppa:owner/name format
    if !repo.starts_with("ppa:") {
        return Err(DaemonError::Validation {
            kind: ValidationErrorKind::InvalidParameter {
                param: "repository".to_string(),
                message: "Repository must be in ppa:owner/name format".to_string(),
            },
        });
    }

    // Check against whitelist
    if !is_repository_allowed(repo) {
        return Err(DaemonError::Validation {
            kind: ValidationErrorKind::RepositoryNotWhitelisted {
                repository: repo.to_string(),
            },
        });
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_allowed_ppas() {
        assert!(is_repository_allowed("ppa:ondrej/php"));
        assert!(is_repository_allowed("ppa:ondrej/nginx"));
        assert!(is_repository_allowed("ppa:redislabs/redis"));
        assert!(is_repository_allowed("ppa:certbot/certbot"));
        assert!(is_repository_allowed("ppa:git-core/ppa"));
    }

    #[test]
    fn test_disallowed_ppas() {
        assert!(!is_repository_allowed("ppa:unknown/repo"));
        assert!(!is_repository_allowed("ppa:malicious/package"));
        assert!(!is_repository_allowed("ppa:"));
    }

    #[test]
    fn test_validate_empty() {
        let result = validate_repository("");
        assert!(matches!(
            result,
            Err(DaemonError::Validation {
                kind: ValidationErrorKind::InvalidParameter { .. }
            })
        ));
    }

    #[test]
    fn test_validate_dangerous_chars() {
        // Shell injection attempts
        assert!(validate_repository("ppa:ondrej/php; rm -rf /").is_err());
        assert!(validate_repository("ppa:ondrej/php | cat /etc/passwd").is_err());
        assert!(validate_repository("ppa:ondrej/php && malicious").is_err());
        assert!(validate_repository("ppa:ondrej/php$(whoami)").is_err());
        assert!(validate_repository("ppa:ondrej/php`whoami`").is_err());
        assert!(validate_repository("ppa:ondrej/php\nmalicious").is_err());
    }

    #[test]
    fn test_validate_non_ppa_format() {
        // Non-PPA formats not allowed
        let result = validate_repository("deb http://example.com/ubuntu focal main");
        assert!(matches!(
            result,
            Err(DaemonError::Validation {
                kind: ValidationErrorKind::InvalidParameter { .. }
            })
        ));
    }

    #[test]
    fn test_validate_unknown_ppa() {
        let result = validate_repository("ppa:unknown/repo");
        assert!(matches!(
            result,
            Err(DaemonError::Validation {
                kind: ValidationErrorKind::RepositoryNotWhitelisted { .. }
            })
        ));
    }

    #[test]
    fn test_validate_allowed_ppa() {
        assert!(validate_repository("ppa:ondrej/php").is_ok());
        assert!(validate_repository("ppa:ondrej/nginx").is_ok());
        assert!(validate_repository("ppa:certbot/certbot").is_ok());
    }
}
