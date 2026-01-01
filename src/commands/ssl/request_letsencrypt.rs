//! Request Let's Encrypt certificate command.

use std::time::Duration;

use tracing::{debug, info};

use crate::error::DaemonError;
use crate::executor::{run_command, SubprocessResult};
use crate::validation::{validate_domain, validate_path};

use super::super::traits::Command;
use super::super::types::{CommandParams, CommandResult, ExecutionContext};

/// Timeout for certbot operations (can take a while for DNS propagation).
const CERTBOT_TIMEOUT: Duration = Duration::from_secs(300);

/// Request a Let's Encrypt certificate using certbot.
///
/// # Parameters
///
/// - `domain` (required): The domain name for the certificate
/// - `email` (required): Email address for Let's Encrypt notifications
/// - `webroot` (required): Path to the webroot directory for HTTP-01 challenge
/// - `staging` (optional): Use Let's Encrypt staging server (default: false)
///
/// Uses certbot's webroot plugin for domain validation.
pub struct RequestLetsEncryptCommand;

impl Command for RequestLetsEncryptCommand {
    fn name(&self) -> &'static str {
        "ssl.request_letsencrypt"
    }

    fn validate(&self, params: &CommandParams) -> Result<(), DaemonError> {
        params.require_string("domain")?;
        params.require_string("email")?;
        params.require_string("webroot")?;

        let domain = params.get_string("domain")?;
        validate_domain(&domain)?;

        let email = params.get_string("email")?;
        validate_email(&email)?;

        let webroot = params.get_string("webroot")?;
        validate_path(&webroot)?;

        Ok(())
    }

    fn execute(
        &self,
        ctx: &ExecutionContext,
        params: CommandParams,
    ) -> Result<CommandResult, DaemonError> {
        let domain = params.get_string("domain")?;
        let email = params.get_string("email")?;
        let webroot = params.get_string("webroot")?;
        let staging = params.get_bool("staging").unwrap_or(false);

        // Re-validate for safety
        validate_domain(&domain)?;
        validate_email(&email)?;
        validate_path(&webroot)?;

        debug!(
            request_id = %ctx.request_id,
            domain = domain,
            webroot = webroot,
            staging = staging,
            "Requesting Let's Encrypt certificate"
        );

        let result = request_certificate(&domain, &email, &webroot, staging)?;

        if result.success {
            info!(
                request_id = %ctx.request_id,
                domain = domain,
                "Let's Encrypt certificate obtained successfully"
            );

            // Certificate paths (certbot default locations)
            let cert_path = format!("/etc/letsencrypt/live/{}/fullchain.pem", domain);
            let key_path = format!("/etc/letsencrypt/live/{}/privkey.pem", domain);

            Ok(CommandResult::success(serde_json::json!({
                "domain": domain,
                "cert_path": cert_path,
                "key_path": key_path,
                "staging": staging,
                "obtained": true,
            })))
        } else {
            Ok(CommandResult::failure(
                "LETSENCRYPT_FAILED",
                format!(
                    "Failed to obtain Let's Encrypt certificate: {}",
                    result.stderr.trim()
                ),
            ))
        }
    }
}

/// Request a certificate using certbot.
fn request_certificate(
    domain: &str,
    email: &str,
    webroot: &str,
    staging: bool,
) -> Result<SubprocessResult, DaemonError> {
    let mut args = vec![
        "certonly".to_string(),
        "--webroot".to_string(),
        "-w".to_string(),
        webroot.to_string(),
        "-d".to_string(),
        domain.to_string(),
        "--email".to_string(),
        email.to_string(),
        "--agree-tos".to_string(),
        "--non-interactive".to_string(),
        "--keep-until-expiring".to_string(),
    ];

    if staging {
        args.push("--staging".to_string());
    }

    let args_refs: Vec<&str> = args.iter().map(|s| s.as_str()).collect();
    run_command("certbot", &args_refs, CERTBOT_TIMEOUT)
}

/// Validates an email address (basic validation).
fn validate_email(email: &str) -> Result<(), DaemonError> {
    // Basic email validation
    if email.is_empty() {
        return Err(DaemonError::Validation {
            kind: crate::error::ValidationErrorKind::InvalidParameter {
                param: "email".to_string(),
                message: "Email cannot be empty".to_string(),
            },
        });
    }

    if email.len() > 254 {
        return Err(DaemonError::Validation {
            kind: crate::error::ValidationErrorKind::InvalidParameter {
                param: "email".to_string(),
                message: "Email exceeds maximum length".to_string(),
            },
        });
    }

    // Must contain @ and have parts on both sides
    let parts: Vec<&str> = email.split('@').collect();
    if parts.len() != 2 || parts[0].is_empty() || parts[1].is_empty() {
        return Err(DaemonError::Validation {
            kind: crate::error::ValidationErrorKind::InvalidParameter {
                param: "email".to_string(),
                message: "Invalid email format".to_string(),
            },
        });
    }

    // Domain part must contain a dot
    if !parts[1].contains('.') {
        return Err(DaemonError::Validation {
            kind: crate::error::ValidationErrorKind::InvalidParameter {
                param: "email".to_string(),
                message: "Email domain must contain a dot".to_string(),
            },
        });
    }

    // Check for invalid characters - block shell metacharacters and control characters
    // that could be used for command/argument injection
    for c in email.chars() {
        let is_invalid = c.is_whitespace()
            || c.is_control()
            || matches!(
                c,
                '<' | '>'
                    | '"'
                    | '\''
                    | '`'
                    | '$'
                    | '&'
                    | '|'
                    | ';'
                    | '('
                    | ')'
                    | '['
                    | ']'
                    | '{'
                    | '}'
                    | '\\'
                    | '!'
                    | '#'
                    | '*'
                    | '?'
                    | '~'
            );
        if is_invalid {
            return Err(DaemonError::Validation {
                kind: crate::error::ValidationErrorKind::InvalidParameter {
                    param: "email".to_string(),
                    message: format!("Email contains invalid character: '{}'", c),
                },
            });
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::auth::PeerInfo;
    use uuid::Uuid;

    #[allow(dead_code)]
    fn create_test_context() -> ExecutionContext {
        ExecutionContext::new(
            Uuid::new_v4(),
            PeerInfo {
                uid: 1000,
                gid: 1000,
                pid: 12345,
            },
            1234567890,
            "ssl.request_letsencrypt".to_string(),
        )
    }

    #[test]
    fn test_command_name() {
        let cmd = RequestLetsEncryptCommand;
        assert_eq!(cmd.name(), "ssl.request_letsencrypt");
    }

    #[test]
    fn test_validate_email_valid() {
        assert!(validate_email("admin@example.com").is_ok());
        assert!(validate_email("user.name@subdomain.example.org").is_ok());
        assert!(validate_email("test+tag@example.com").is_ok());
    }

    #[test]
    fn test_validate_email_invalid() {
        assert!(validate_email("").is_err());
        assert!(validate_email("no-at-sign").is_err());
        assert!(validate_email("@example.com").is_err());
        assert!(validate_email("user@").is_err());
        assert!(validate_email("user@nodot").is_err());
        assert!(validate_email("user name@example.com").is_err());
    }

    #[test]
    fn test_validate_missing_domain() {
        let cmd = RequestLetsEncryptCommand;
        let params = CommandParams::new(serde_json::json!({
            "email": "admin@example.com",
            "webroot": "/var/www/html"
        }));
        assert!(cmd.validate(&params).is_err());
    }

    #[test]
    fn test_validate_missing_email() {
        let cmd = RequestLetsEncryptCommand;
        let params = CommandParams::new(serde_json::json!({
            "domain": "example.com",
            "webroot": "/var/www/html"
        }));
        assert!(cmd.validate(&params).is_err());
    }

    #[test]
    fn test_validate_missing_webroot() {
        let cmd = RequestLetsEncryptCommand;
        let params = CommandParams::new(serde_json::json!({
            "domain": "example.com",
            "email": "admin@example.com"
        }));
        assert!(cmd.validate(&params).is_err());
    }
}
