//! Remove PHP version command.

use std::time::Duration;

use tracing::{info, warn};

use crate::error::DaemonError;
use crate::executor::{run_command, SubprocessResult};

use super::super::traits::Command;
use super::super::types::{CommandParams, CommandResult, ExecutionContext};
use super::install_version::validate_php_version;

/// Timeout for apt-get operations.
const APT_TIMEOUT: Duration = Duration::from_secs(300);

/// Remove a PHP version.
///
/// # Parameters
///
/// - `version` (required): The PHP version (8.1, 8.2, 8.3, or 8.4)
///
/// # Warning
///
/// This will remove PHP and all its extensions for the specified version.
pub struct RemovePhpVersionCommand;

impl Command for RemovePhpVersionCommand {
    fn name(&self) -> &'static str {
        "php.remove_version"
    }

    fn validate(&self, params: &CommandParams) -> Result<(), DaemonError> {
        params.require_string("version")?;
        let version = params.get_string("version")?;
        validate_php_version(&version)?;
        Ok(())
    }

    fn execute(
        &self,
        ctx: &ExecutionContext,
        params: CommandParams,
    ) -> Result<CommandResult, DaemonError> {
        let version = params.get_string("version")?;

        // Re-validate for safety
        validate_php_version(&version)?;

        warn!(
            request_id = %ctx.request_id,
            version = version,
            "Removing PHP version (destructive operation)"
        );

        // Remove all PHP packages for this version
        let pattern = format!("php{}*", version);
        let result = remove_packages(&pattern)?;

        if result.success {
            info!(
                request_id = %ctx.request_id,
                version = version,
                "PHP version removed successfully"
            );

            Ok(CommandResult::success(serde_json::json!({
                "version": version,
                "removed": true,
            })))
        } else {
            Ok(CommandResult::failure(
                "PHP_REMOVE_FAILED",
                format!("Failed to remove PHP {}: {}", version, result.stderr.trim()),
            ))
        }
    }
}

/// Remove packages using apt-get.
fn remove_packages(pattern: &str) -> Result<SubprocessResult, DaemonError> {
    run_command(
        "apt-get",
        &["remove", "-y", "--purge", pattern],
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
            "php.remove_version".to_string(),
        )
    }

    #[test]
    fn test_command_name() {
        let cmd = RemovePhpVersionCommand;
        assert_eq!(cmd.name(), "php.remove_version");
    }

    #[test]
    fn test_validate_valid_params() {
        let cmd = RemovePhpVersionCommand;
        let params = CommandParams::new(serde_json::json!({
            "version": "8.2"
        }));
        assert!(cmd.validate(&params).is_ok());
    }

    #[test]
    fn test_validate_missing_version() {
        let cmd = RemovePhpVersionCommand;
        let params = CommandParams::new(serde_json::json!({}));
        assert!(cmd.validate(&params).is_err());
    }

    #[test]
    fn test_validate_invalid_version() {
        let cmd = RemovePhpVersionCommand;
        let params = CommandParams::new(serde_json::json!({
            "version": "7.4"
        }));
        assert!(cmd.validate(&params).is_err());
    }
}
