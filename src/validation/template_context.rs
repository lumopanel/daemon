//! Template context validation.
//!
//! Validates context values used in templates like nginx site configurations.

use crate::error::{DaemonError, ValidationErrorKind};

/// Allowed prefixes for document root paths.
const ALLOWED_DOCROOT_PREFIXES: &[&str] = &["/var/www/", "/home/", "/srv/"];

/// Allowed prefixes for PHP socket paths.
const ALLOWED_SOCKET_PREFIXES: &[&str] = &["/var/run/", "/run/"];

/// Allowed prefixes for nginx include files.
const ALLOWED_INCLUDE_PREFIXES: &[&str] = &["/etc/nginx/"];

/// Allowed prefixes for SSL certificate paths.
const ALLOWED_SSL_PREFIXES: &[&str] = &["/etc/ssl/", "/etc/letsencrypt/", "/etc/nginx/ssl/"];

/// Validates a document root path for nginx configuration.
///
/// # Rules
///
/// - Must be an absolute path
/// - Must start with an allowed prefix (/var/www/, /home/, /srv/)
/// - Cannot contain path traversal sequences (..)
/// - Cannot contain null bytes or newlines
///
/// # Arguments
///
/// * `path` - The document root path to validate
///
/// # Returns
///
/// The validated path or an error.
pub fn validate_document_root(path: &str) -> Result<&str, DaemonError> {
    validate_template_path(path, "document_root", ALLOWED_DOCROOT_PREFIXES)
}

/// Validates a PHP socket path for nginx configuration.
///
/// # Rules
///
/// - Must be an absolute path
/// - Must start with an allowed prefix (/var/run/, /run/)
/// - Must end with .sock
/// - Cannot contain path traversal sequences (..)
///
/// # Arguments
///
/// * `path` - The socket path to validate
///
/// # Returns
///
/// The validated path or an error.
pub fn validate_php_socket(path: &str) -> Result<&str, DaemonError> {
    let path = validate_template_path(path, "php_socket", ALLOWED_SOCKET_PREFIXES)?;

    // Must end with .sock
    if !path.ends_with(".sock") {
        return Err(DaemonError::Validation {
            kind: ValidationErrorKind::InvalidParameter {
                param: "php_socket".to_string(),
                message: "PHP socket path must end with .sock".to_string(),
            },
        });
    }

    Ok(path)
}

/// Validates a custom config file path for nginx include directive.
///
/// # Rules
///
/// - Must be an absolute path
/// - Must start with an allowed prefix (/etc/nginx/)
/// - Must end with .conf
/// - Cannot contain path traversal sequences (..)
///
/// # Arguments
///
/// * `path` - The config file path to validate
///
/// # Returns
///
/// The validated path or an error.
pub fn validate_custom_config_file(path: &str) -> Result<&str, DaemonError> {
    let path = validate_template_path(path, "custom_config_file", ALLOWED_INCLUDE_PREFIXES)?;

    // Must end with .conf
    if !path.ends_with(".conf") {
        return Err(DaemonError::Validation {
            kind: ValidationErrorKind::InvalidParameter {
                param: "custom_config_file".to_string(),
                message: "Custom config file must end with .conf".to_string(),
            },
        });
    }

    Ok(path)
}

/// Validates an SSL certificate path.
///
/// # Rules
///
/// - Must be an absolute path
/// - Must start with an allowed prefix (/etc/ssl/, /etc/letsencrypt/, /etc/nginx/ssl/)
/// - Must end with .pem, .crt, or .cer
/// - Cannot contain path traversal sequences (..)
///
/// # Arguments
///
/// * `path` - The certificate path to validate
///
/// # Returns
///
/// The validated path or an error.
pub fn validate_ssl_certificate(path: &str) -> Result<&str, DaemonError> {
    let path = validate_template_path(path, "ssl_certificate", ALLOWED_SSL_PREFIXES)?;

    // Must end with valid extension
    if !path.ends_with(".pem") && !path.ends_with(".crt") && !path.ends_with(".cer") {
        return Err(DaemonError::Validation {
            kind: ValidationErrorKind::InvalidParameter {
                param: "ssl_certificate".to_string(),
                message: "SSL certificate must end with .pem, .crt, or .cer".to_string(),
            },
        });
    }

    Ok(path)
}

/// Validates an SSL certificate key path.
///
/// # Rules
///
/// - Must be an absolute path
/// - Must start with an allowed prefix (/etc/ssl/, /etc/letsencrypt/, /etc/nginx/ssl/)
/// - Must end with .pem or .key
/// - Cannot contain path traversal sequences (..)
///
/// # Arguments
///
/// * `path` - The key path to validate
///
/// # Returns
///
/// The validated path or an error.
pub fn validate_ssl_certificate_key(path: &str) -> Result<&str, DaemonError> {
    let path = validate_template_path(path, "ssl_certificate_key", ALLOWED_SSL_PREFIXES)?;

    // Must end with valid extension
    if !path.ends_with(".pem") && !path.ends_with(".key") {
        return Err(DaemonError::Validation {
            kind: ValidationErrorKind::InvalidParameter {
                param: "ssl_certificate_key".to_string(),
                message: "SSL certificate key must end with .pem or .key".to_string(),
            },
        });
    }

    Ok(path)
}

/// Internal helper to validate a template path with common checks.
fn validate_template_path<'a>(
    path: &'a str,
    param_name: &str,
    allowed_prefixes: &[&str],
) -> Result<&'a str, DaemonError> {
    // Check for empty path
    if path.is_empty() {
        return Err(DaemonError::Validation {
            kind: ValidationErrorKind::InvalidParameter {
                param: param_name.to_string(),
                message: "Path cannot be empty".to_string(),
            },
        });
    }

    // Must be absolute path
    if !path.starts_with('/') {
        return Err(DaemonError::Validation {
            kind: ValidationErrorKind::InvalidParameter {
                param: param_name.to_string(),
                message: "Path must be absolute (start with /)".to_string(),
            },
        });
    }

    // Check for path traversal
    if path.contains("..") {
        return Err(DaemonError::Validation {
            kind: ValidationErrorKind::InvalidParameter {
                param: param_name.to_string(),
                message: "Path cannot contain path traversal sequences (..)".to_string(),
            },
        });
    }

    // Check for null bytes (injection attack)
    if path.contains('\0') {
        return Err(DaemonError::Validation {
            kind: ValidationErrorKind::InvalidParameter {
                param: param_name.to_string(),
                message: "Path cannot contain null bytes".to_string(),
            },
        });
    }

    // Check for newlines (injection attack in nginx config)
    if path.contains('\n') || path.contains('\r') {
        return Err(DaemonError::Validation {
            kind: ValidationErrorKind::InvalidParameter {
                param: param_name.to_string(),
                message: "Path cannot contain newline characters".to_string(),
            },
        });
    }

    // Check for semicolons (nginx directive separator)
    if path.contains(';') {
        return Err(DaemonError::Validation {
            kind: ValidationErrorKind::InvalidParameter {
                param: param_name.to_string(),
                message: "Path cannot contain semicolons".to_string(),
            },
        });
    }

    // Check prefix
    let has_valid_prefix = allowed_prefixes
        .iter()
        .any(|prefix| path.starts_with(prefix));
    if !has_valid_prefix {
        return Err(DaemonError::Validation {
            kind: ValidationErrorKind::InvalidParameter {
                param: param_name.to_string(),
                message: format!(
                    "Path must start with one of: {}",
                    allowed_prefixes.join(", ")
                ),
            },
        });
    }

    Ok(path)
}

#[cfg(test)]
mod tests {
    use super::*;

    // Document root tests
    #[test]
    fn test_valid_document_root() {
        assert!(validate_document_root("/var/www/html").is_ok());
        assert!(validate_document_root("/var/www/example.com/public").is_ok());
        assert!(validate_document_root("/home/user/public_html").is_ok());
        assert!(validate_document_root("/srv/sites/example").is_ok());
    }

    #[test]
    fn test_invalid_document_root() {
        // Empty
        assert!(validate_document_root("").is_err());
        // Not absolute
        assert!(validate_document_root("var/www/html").is_err());
        // Path traversal
        assert!(validate_document_root("/var/www/../etc/passwd").is_err());
        // Wrong prefix
        assert!(validate_document_root("/etc/nginx/html").is_err());
        assert!(validate_document_root("/tmp/www").is_err());
        // Null byte
        assert!(validate_document_root("/var/www/\0html").is_err());
        // Newline
        assert!(validate_document_root("/var/www/html\n/etc/passwd").is_err());
        // Semicolon
        assert!(validate_document_root("/var/www/html;").is_err());
    }

    // PHP socket tests
    #[test]
    fn test_valid_php_socket() {
        assert!(validate_php_socket("/var/run/php/php8.3-fpm.sock").is_ok());
        assert!(validate_php_socket("/run/php-fpm/www.sock").is_ok());
    }

    #[test]
    fn test_invalid_php_socket() {
        // Wrong extension
        assert!(validate_php_socket("/var/run/php/php.pid").is_err());
        // Wrong prefix
        assert!(validate_php_socket("/tmp/php.sock").is_err());
        // Path traversal
        assert!(validate_php_socket("/var/run/../etc/passwd.sock").is_err());
    }

    // Custom config file tests
    #[test]
    fn test_valid_custom_config_file() {
        assert!(validate_custom_config_file("/etc/nginx/snippets/ssl.conf").is_ok());
        assert!(validate_custom_config_file("/etc/nginx/sites-available/custom.conf").is_ok());
    }

    #[test]
    fn test_invalid_custom_config_file() {
        // Wrong extension
        assert!(validate_custom_config_file("/etc/nginx/evil.php").is_err());
        // Wrong prefix
        assert!(validate_custom_config_file("/tmp/evil.conf").is_err());
        assert!(validate_custom_config_file("/etc/apache2/evil.conf").is_err());
        // Path traversal
        assert!(validate_custom_config_file("/etc/nginx/../passwd.conf").is_err());
    }

    // SSL certificate tests
    #[test]
    fn test_valid_ssl_certificate() {
        assert!(validate_ssl_certificate("/etc/ssl/certs/example.pem").is_ok());
        assert!(
            validate_ssl_certificate("/etc/letsencrypt/live/example.com/fullchain.pem").is_ok()
        );
        assert!(validate_ssl_certificate("/etc/nginx/ssl/cert.crt").is_ok());
    }

    #[test]
    fn test_invalid_ssl_certificate() {
        // Wrong extension
        assert!(validate_ssl_certificate("/etc/ssl/certs/example.txt").is_err());
        // Wrong prefix
        assert!(validate_ssl_certificate("/tmp/cert.pem").is_err());
        // Path traversal
        assert!(validate_ssl_certificate("/etc/ssl/../etc/passwd.pem").is_err());
    }

    // SSL key tests
    #[test]
    fn test_valid_ssl_certificate_key() {
        assert!(validate_ssl_certificate_key("/etc/ssl/private/example.key").is_ok());
        assert!(
            validate_ssl_certificate_key("/etc/letsencrypt/live/example.com/privkey.pem").is_ok()
        );
    }

    #[test]
    fn test_invalid_ssl_certificate_key() {
        // Wrong extension
        assert!(validate_ssl_certificate_key("/etc/ssl/private/example.pub").is_err());
        // Wrong prefix
        assert!(validate_ssl_certificate_key("/tmp/key.pem").is_err());
    }
}
