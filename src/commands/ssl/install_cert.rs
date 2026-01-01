//! Install SSL certificate command.

use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::time::Duration;

use tracing::{debug, info};

use crate::error::DaemonError;
use crate::executor::{run_command, SubprocessResult};
use crate::validation::{validate_domain, validate_path};

use super::super::traits::Command;
use super::super::types::{CommandParams, CommandResult, ExecutionContext};

/// Default timeout for certificate operations.
const DEFAULT_TIMEOUT: Duration = Duration::from_secs(30);

/// Install an SSL certificate for a domain.
///
/// # Parameters
///
/// - `domain` (required): The domain name for the certificate
/// - `certificate` (required): The certificate content (PEM format)
/// - `private_key` (required): The private key content (PEM format)
/// - `chain` (optional): The certificate chain content (PEM format)
///
/// Certificates are installed to `/etc/ssl/certs/` and `/etc/ssl/private/`.
pub struct InstallCertificateCommand;

impl Command for InstallCertificateCommand {
    fn name(&self) -> &'static str {
        "ssl.install_cert"
    }

    fn validate(&self, params: &CommandParams) -> Result<(), DaemonError> {
        params.require_string("domain")?;
        params.require_string("certificate")?;
        params.require_string("private_key")?;

        let domain = params.get_string("domain")?;
        validate_domain(&domain)?;

        // Validate certificate format (basic check)
        let cert = params.get_string("certificate")?;
        if !cert.contains("-----BEGIN CERTIFICATE-----") {
            return Err(DaemonError::Validation {
                kind: crate::error::ValidationErrorKind::InvalidParameter {
                    param: "certificate".to_string(),
                    message: "Certificate must be in PEM format".to_string(),
                },
            });
        }

        // Validate private key format (basic check)
        let key = params.get_string("private_key")?;
        if !key.contains("-----BEGIN") || !key.contains("PRIVATE KEY-----") {
            return Err(DaemonError::Validation {
                kind: crate::error::ValidationErrorKind::InvalidParameter {
                    param: "private_key".to_string(),
                    message: "Private key must be in PEM format".to_string(),
                },
            });
        }

        Ok(())
    }

    fn execute(
        &self,
        ctx: &ExecutionContext,
        params: CommandParams,
    ) -> Result<CommandResult, DaemonError> {
        let domain = params.get_string("domain")?;
        let certificate = params.get_string("certificate")?;
        let private_key = params.get_string("private_key")?;
        let chain = params.get_string("chain").ok();

        // Re-validate for safety
        validate_domain(&domain)?;

        debug!(
            request_id = %ctx.request_id,
            domain = domain,
            "Installing SSL certificate"
        );

        // Build paths
        let cert_path = PathBuf::from(format!("/etc/ssl/certs/{}.crt", domain));
        let key_path = PathBuf::from(format!("/etc/ssl/private/{}.key", domain));
        let chain_path = if chain.is_some() {
            Some(PathBuf::from(format!(
                "/etc/ssl/certs/{}.chain.crt",
                domain
            )))
        } else {
            None
        };

        // Validate paths
        validate_path(&cert_path)?;
        validate_path(&key_path)?;
        if let Some(ref path) = chain_path {
            validate_path(path)?;
        }

        // Ensure directories exist
        fs::create_dir_all("/etc/ssl/certs").map_err(|e| DaemonError::Command {
            kind: crate::error::CommandErrorKind::ExecutionFailed {
                message: format!("Failed to create certs directory: {}", e),
            },
        })?;
        fs::create_dir_all("/etc/ssl/private").map_err(|e| DaemonError::Command {
            kind: crate::error::CommandErrorKind::ExecutionFailed {
                message: format!("Failed to create private directory: {}", e),
            },
        })?;

        // Write certificate
        fs::write(&cert_path, &certificate).map_err(|e| DaemonError::Command {
            kind: crate::error::CommandErrorKind::ExecutionFailed {
                message: format!("Failed to write certificate: {}", e),
            },
        })?;
        fs::set_permissions(&cert_path, fs::Permissions::from_mode(0o644)).map_err(|e| {
            DaemonError::Command {
                kind: crate::error::CommandErrorKind::ExecutionFailed {
                    message: format!("Failed to set certificate permissions: {}", e),
                },
            }
        })?;

        // Write private key with restrictive permissions
        fs::write(&key_path, &private_key).map_err(|e| DaemonError::Command {
            kind: crate::error::CommandErrorKind::ExecutionFailed {
                message: format!("Failed to write private key: {}", e),
            },
        })?;
        fs::set_permissions(&key_path, fs::Permissions::from_mode(0o600)).map_err(|e| {
            DaemonError::Command {
                kind: crate::error::CommandErrorKind::ExecutionFailed {
                    message: format!("Failed to set private key permissions: {}", e),
                },
            }
        })?;

        // Write chain if provided
        if let (Some(chain_content), Some(chain_file)) = (chain, chain_path.as_ref()) {
            fs::write(chain_file, &chain_content).map_err(|e| DaemonError::Command {
                kind: crate::error::CommandErrorKind::ExecutionFailed {
                    message: format!("Failed to write certificate chain: {}", e),
                },
            })?;
            fs::set_permissions(chain_file, fs::Permissions::from_mode(0o644)).map_err(|e| {
                DaemonError::Command {
                    kind: crate::error::CommandErrorKind::ExecutionFailed {
                        message: format!("Failed to set chain permissions: {}", e),
                    },
                }
            })?;
        }

        // Verify certificate with openssl
        let verify_result = verify_certificate(&cert_path, &key_path)?;
        if !verify_result.success {
            // Clean up on verification failure
            let _ = fs::remove_file(&cert_path);
            let _ = fs::remove_file(&key_path);
            if let Some(ref path) = chain_path {
                let _ = fs::remove_file(path);
            }

            return Ok(CommandResult::failure(
                "CERTIFICATE_INVALID",
                format!(
                    "Certificate verification failed: {}",
                    verify_result.stderr.trim()
                ),
            ));
        }

        info!(
            request_id = %ctx.request_id,
            domain = domain,
            cert_path = %cert_path.display(),
            key_path = %key_path.display(),
            "SSL certificate installed successfully"
        );

        Ok(CommandResult::success(serde_json::json!({
            "domain": domain,
            "cert_path": cert_path.to_string_lossy(),
            "key_path": key_path.to_string_lossy(),
            "chain_path": chain_path.map(|p| p.to_string_lossy().to_string()),
            "installed": true,
        })))
    }
}

/// Verify that the certificate and key match.
fn verify_certificate(cert_path: &Path, key_path: &Path) -> Result<SubprocessResult, DaemonError> {
    // Get certificate modulus
    let cert_result = run_command(
        "openssl",
        &[
            "x509",
            "-noout",
            "-modulus",
            "-in",
            &cert_path.to_string_lossy(),
        ],
        DEFAULT_TIMEOUT,
    )?;

    if !cert_result.success {
        return Ok(cert_result);
    }

    // Get key modulus
    let key_result = run_command(
        "openssl",
        &[
            "rsa",
            "-noout",
            "-modulus",
            "-in",
            &key_path.to_string_lossy(),
        ],
        DEFAULT_TIMEOUT,
    )?;

    if !key_result.success {
        return Ok(key_result);
    }

    // Compare modulus values
    if cert_result.stdout.trim() != key_result.stdout.trim() {
        return Ok(SubprocessResult {
            success: false,
            exit_code: Some(1),
            stdout: String::new(),
            stderr: "Certificate and private key do not match".to_string(),
        });
    }

    Ok(SubprocessResult {
        success: true,
        exit_code: Some(0),
        stdout: String::new(),
        stderr: String::new(),
    })
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
            "ssl.install_cert".to_string(),
        )
    }

    #[test]
    fn test_command_name() {
        let cmd = InstallCertificateCommand;
        assert_eq!(cmd.name(), "ssl.install_cert");
    }

    #[test]
    fn test_validate_valid_params() {
        let cmd = InstallCertificateCommand;
        let params = CommandParams::new(serde_json::json!({
            "domain": "example.com",
            "certificate": "-----BEGIN CERTIFICATE-----\nMIIB...\n-----END CERTIFICATE-----",
            "private_key": "-----BEGIN PRIVATE KEY-----\nMIIE...\n-----END PRIVATE KEY-----"
        }));
        assert!(cmd.validate(&params).is_ok());
    }

    #[test]
    fn test_validate_missing_domain() {
        let cmd = InstallCertificateCommand;
        let params = CommandParams::new(serde_json::json!({
            "certificate": "-----BEGIN CERTIFICATE-----\nMIIB...\n-----END CERTIFICATE-----",
            "private_key": "-----BEGIN PRIVATE KEY-----\nMIIE...\n-----END PRIVATE KEY-----"
        }));
        assert!(cmd.validate(&params).is_err());
    }

    #[test]
    fn test_validate_invalid_certificate_format() {
        let cmd = InstallCertificateCommand;
        let params = CommandParams::new(serde_json::json!({
            "domain": "example.com",
            "certificate": "not a pem certificate",
            "private_key": "-----BEGIN PRIVATE KEY-----\nMIIE...\n-----END PRIVATE KEY-----"
        }));
        assert!(cmd.validate(&params).is_err());
    }

    #[test]
    fn test_validate_invalid_key_format() {
        let cmd = InstallCertificateCommand;
        let params = CommandParams::new(serde_json::json!({
            "domain": "example.com",
            "certificate": "-----BEGIN CERTIFICATE-----\nMIIB...\n-----END CERTIFICATE-----",
            "private_key": "not a pem key"
        }));
        assert!(cmd.validate(&params).is_err());
    }
}
