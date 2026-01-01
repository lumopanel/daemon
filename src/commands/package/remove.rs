//! Package remove command.
//!
//! Removes packages via apt-get.

use std::process::Command as ProcessCommand;
use std::time::Duration;

use tracing::{debug, info, warn};

use crate::commands::traits::Command;
use crate::commands::types::{CommandParams, CommandResult, ExecutionContext};
use crate::error::{CommandErrorKind, DaemonError};
use crate::executor::sanitize_output;
use crate::validation::validate_package_list;

/// Remove packages via apt-get.
pub struct RemovePackageCommand;

impl Command for RemovePackageCommand {
    fn name(&self) -> &'static str {
        "package.remove"
    }

    fn validate(&self, params: &CommandParams) -> Result<(), DaemonError> {
        let packages = params.get_string_array("packages")?;
        validate_package_list(&packages)?;
        Ok(())
    }

    fn execute(
        &self,
        ctx: &ExecutionContext,
        params: CommandParams,
    ) -> Result<CommandResult, DaemonError> {
        let packages = params.get_string_array("packages")?;
        let purge = params.get_optional_bool("purge", false);

        let action = if purge { "purge" } else { "remove" };

        debug!(
            request_id = %ctx.request_id,
            packages = ?packages,
            purge = purge,
            "Removing packages"
        );

        // Build apt-get command
        let mut cmd = ProcessCommand::new("apt-get");
        cmd.args([action, "-y"]);
        cmd.args(&packages);

        // Set environment to avoid prompts
        cmd.env("DEBIAN_FRONTEND", "noninteractive");

        let output = cmd.output().map_err(|e| DaemonError::Command {
            kind: CommandErrorKind::ExecutionFailed {
                message: format!("Failed to execute apt-get: {}", e),
            },
        })?;

        let stdout = String::from_utf8_lossy(&output.stdout).to_string();
        let stderr = String::from_utf8_lossy(&output.stderr).to_string();

        if !output.status.success() {
            warn!(
                request_id = %ctx.request_id,
                packages = ?packages,
                stderr = %stderr,
                "Failed to remove packages"
            );
            return Err(DaemonError::Command {
                kind: CommandErrorKind::ExecutionFailed {
                    message: format!("apt-get {} failed: {}", action, sanitize_output(&stderr, 5)),
                },
            });
        }

        info!(
            request_id = %ctx.request_id,
            packages = ?packages,
            purge = purge,
            "Packages removed successfully"
        );

        Ok(CommandResult::success(serde_json::json!({
            "packages": packages,
            "action": action,
            "purge": purge,
            "stdout": stdout,
        })))
    }

    fn timeout(&self) -> Duration {
        Duration::from_secs(300) // 5 minutes for package removal
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_remove_command_name() {
        let cmd = RemovePackageCommand;
        assert_eq!(cmd.name(), "package.remove");
    }

    #[test]
    fn test_validate_valid_packages() {
        let cmd = RemovePackageCommand;
        let params = CommandParams::new(serde_json::json!({
            "packages": ["nginx", "redis-server"]
        }));
        assert!(cmd.validate(&params).is_ok());
    }

    #[test]
    fn test_validate_invalid_package() {
        let cmd = RemovePackageCommand;
        let params = CommandParams::new(serde_json::json!({
            "packages": ["nginx", "malware"]
        }));
        assert!(cmd.validate(&params).is_err());
    }

    #[test]
    fn test_validate_empty_packages() {
        let cmd = RemovePackageCommand;
        let params = CommandParams::new(serde_json::json!({
            "packages": []
        }));
        assert!(cmd.validate(&params).is_err());
    }

    #[test]
    fn test_timeout_value() {
        assert_eq!(RemovePackageCommand.timeout(), Duration::from_secs(300));
    }
}
