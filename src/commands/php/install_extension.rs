//! Install PHP extension command.

use std::time::Duration;

use tracing::{debug, info};

use crate::error::DaemonError;
use crate::executor::{run_command, SubprocessResult};
use crate::validation::whitelist::is_additional_php_extension;

use super::super::traits::Command;
use super::super::types::{CommandParams, CommandResult, ExecutionContext};
use super::install_version::validate_php_version;

/// Timeout for apt-get operations.
const APT_TIMEOUT: Duration = Duration::from_secs(300);

/// Allowed PHP extensions (common extensions that are safe to install).
const ALLOWED_EXTENSIONS: &[&str] = &[
    "bcmath",
    "bz2",
    "curl",
    "dba",
    "enchant",
    "gd",
    "gmp",
    "imap",
    "interbase",
    "intl",
    "ldap",
    "mbstring",
    "mysql",
    "odbc",
    "pgsql",
    "pspell",
    "readline",
    "snmp",
    "soap",
    "sqlite3",
    "sybase",
    "tidy",
    "xml",
    "xmlrpc",
    "xsl",
    "zip",
    "redis",
    "memcached",
    "imagick",
    "apcu",
    "opcache",
];

/// Install a PHP extension.
///
/// # Parameters
///
/// - `version` (required): The PHP version (8.1, 8.2, 8.3, or 8.4)
/// - `extension` (required): The extension name (e.g., "redis", "imagick")
pub struct InstallPhpExtensionCommand;

impl Command for InstallPhpExtensionCommand {
    fn name(&self) -> &'static str {
        "php.install_extension"
    }

    fn validate(&self, params: &CommandParams) -> Result<(), DaemonError> {
        params.require_string("version")?;
        params.require_string("extension")?;

        let version = params.get_string("version")?;
        validate_php_version(&version)?;

        let extension = params.get_string("extension")?;
        validate_php_extension(&extension)?;

        Ok(())
    }

    fn execute(
        &self,
        ctx: &ExecutionContext,
        params: CommandParams,
    ) -> Result<CommandResult, DaemonError> {
        let version = params.get_string("version")?;
        let extension = params.get_string("extension")?;

        // Re-validate for safety
        validate_php_version(&version)?;
        validate_php_extension(&extension)?;

        debug!(
            request_id = %ctx.request_id,
            version = version,
            extension = extension,
            "Installing PHP extension"
        );

        // Install the extension package
        let package = format!("php{}-{}", version, extension);
        let result = install_package(&package)?;

        if result.success {
            info!(
                request_id = %ctx.request_id,
                version = version,
                extension = extension,
                package = package,
                "PHP extension installed successfully"
            );

            Ok(CommandResult::success(serde_json::json!({
                "version": version,
                "extension": extension,
                "package": package,
                "installed": true,
            })))
        } else {
            Ok(CommandResult::failure(
                "EXTENSION_INSTALL_FAILED",
                format!(
                    "Failed to install PHP extension {}: {}",
                    extension,
                    result.stderr.trim()
                ),
            ))
        }
    }
}

/// Validate a PHP extension name.
pub fn validate_php_extension(extension: &str) -> Result<(), DaemonError> {
    // Check if empty
    if extension.is_empty() {
        return Err(DaemonError::Validation {
            kind: crate::error::ValidationErrorKind::InvalidParameter {
                param: "extension".to_string(),
                message: "Extension name cannot be empty".to_string(),
            },
        });
    }

    // Check against built-in whitelist
    if ALLOWED_EXTENSIONS.contains(&extension) {
        return Ok(());
    }

    // Check against additional extensions from configuration
    if is_additional_php_extension(extension) {
        return Ok(());
    }

    Err(DaemonError::Validation {
        kind: crate::error::ValidationErrorKind::InvalidParameter {
            param: "extension".to_string(),
            message: format!(
                "Extension '{}' is not in the allowed list. Allowed extensions: {}",
                extension,
                ALLOWED_EXTENSIONS.join(", ")
            ),
        },
    })
}

/// Install a package using apt-get.
fn install_package(package: &str) -> Result<SubprocessResult, DaemonError> {
    run_command(
        "apt-get",
        &["install", "-y", "--no-install-recommends", package],
        APT_TIMEOUT,
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::auth::PeerInfo;
    use uuid::Uuid;

    fn create_test_context() -> ExecutionContext {
        ExecutionContext::new(
            Uuid::new_v4(),
            PeerInfo {
                uid: 1000,
                gid: 1000,
                pid: 12345,
            },
            1234567890,
            "php.install_extension".to_string(),
        )
    }

    #[test]
    fn test_command_name() {
        let cmd = InstallPhpExtensionCommand;
        assert_eq!(cmd.name(), "php.install_extension");
    }

    #[test]
    fn test_validate_valid_extensions() {
        assert!(validate_php_extension("redis").is_ok());
        assert!(validate_php_extension("imagick").is_ok());
        assert!(validate_php_extension("gd").is_ok());
        assert!(validate_php_extension("mbstring").is_ok());
    }

    #[test]
    fn test_validate_invalid_extensions() {
        assert!(validate_php_extension("").is_err());
        assert!(validate_php_extension("malicious").is_err());
        assert!(validate_php_extension("unknown_ext").is_err());
    }

    #[test]
    fn test_validate_valid_params() {
        let cmd = InstallPhpExtensionCommand;
        let params = CommandParams::new(serde_json::json!({
            "version": "8.2",
            "extension": "redis"
        }));
        assert!(cmd.validate(&params).is_ok());
    }

    #[test]
    fn test_validate_missing_extension() {
        let cmd = InstallPhpExtensionCommand;
        let params = CommandParams::new(serde_json::json!({
            "version": "8.2"
        }));
        assert!(cmd.validate(&params).is_err());
    }
}
