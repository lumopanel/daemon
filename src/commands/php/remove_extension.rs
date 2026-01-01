//! Remove PHP extension command.

use std::time::Duration;

use tracing::{info, warn};

use crate::error::DaemonError;
use crate::executor::{run_command, SubprocessResult};

use super::super::traits::Command;
use super::super::types::{CommandParams, CommandResult, ExecutionContext};
use super::install_extension::validate_php_extension;
use super::install_version::validate_php_version;

/// Timeout for apt-get operations.
const APT_TIMEOUT: Duration = Duration::from_secs(300);

/// Remove a PHP extension.
///
/// # Parameters
///
/// - `version` (required): The PHP version (8.1, 8.2, 8.3, or 8.4)
/// - `extension` (required): The extension name (e.g., "redis", "imagick")
pub struct RemovePhpExtensionCommand;

impl Command for RemovePhpExtensionCommand {
    fn name(&self) -> &'static str {
        "php.remove_extension"
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

        warn!(
            request_id = %ctx.request_id,
            version = version,
            extension = extension,
            "Removing PHP extension (destructive operation)"
        );

        // Remove the extension package
        let package = format!("php{}-{}", version, extension);
        let result = remove_package(&package)?;

        if result.success {
            info!(
                request_id = %ctx.request_id,
                version = version,
                extension = extension,
                package = package,
                "PHP extension removed successfully"
            );

            Ok(CommandResult::success(serde_json::json!({
                "version": version,
                "extension": extension,
                "package": package,
                "removed": true,
            })))
        } else {
            Ok(CommandResult::failure(
                "EXTENSION_REMOVE_FAILED",
                format!(
                    "Failed to remove PHP extension {}: {}",
                    extension,
                    result.stderr.trim()
                ),
            ))
        }
    }
}

/// Remove a package using apt-get.
fn remove_package(package: &str) -> Result<SubprocessResult, DaemonError> {
    run_command(
        "apt-get",
        &["remove", "-y", "--purge", package],
        APT_TIMEOUT,
    )
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
            "php.remove_extension".to_string(),
        )
    }

    #[test]
    fn test_command_name() {
        let cmd = RemovePhpExtensionCommand;
        assert_eq!(cmd.name(), "php.remove_extension");
    }

    #[test]
    fn test_validate_valid_params() {
        let cmd = RemovePhpExtensionCommand;
        let params = CommandParams::new(serde_json::json!({
            "version": "8.2",
            "extension": "redis"
        }));
        assert!(cmd.validate(&params).is_ok());
    }

    #[test]
    fn test_validate_missing_extension() {
        let cmd = RemovePhpExtensionCommand;
        let params = CommandParams::new(serde_json::json!({
            "version": "8.2"
        }));
        assert!(cmd.validate(&params).is_err());
    }

    #[test]
    fn test_validate_missing_version() {
        let cmd = RemovePhpExtensionCommand;
        let params = CommandParams::new(serde_json::json!({
            "extension": "redis"
        }));
        assert!(cmd.validate(&params).is_err());
    }

    #[test]
    fn test_validate_invalid_extension() {
        let cmd = RemovePhpExtensionCommand;
        let params = CommandParams::new(serde_json::json!({
            "version": "8.2",
            "extension": "malicious"
        }));
        assert!(cmd.validate(&params).is_err());
    }

    #[test]
    fn test_validate_invalid_version() {
        let cmd = RemovePhpExtensionCommand;
        let params = CommandParams::new(serde_json::json!({
            "version": "7.4",
            "extension": "redis"
        }));
        assert!(cmd.validate(&params).is_err());
    }
}
