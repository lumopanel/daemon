//! Package update command.
//!
//! Updates package lists via apt-get update.

use std::process::Command as ProcessCommand;
use std::time::Duration;

use tracing::{debug, info, warn};

use crate::commands::traits::Command;
use crate::commands::types::{CommandParams, CommandResult, ExecutionContext};
use crate::error::{CommandErrorKind, DaemonError};
use crate::executor::sanitize_output;

/// Update package lists via apt-get update.
pub struct UpdatePackageCommand;

impl Command for UpdatePackageCommand {
    fn name(&self) -> &'static str {
        "package.update"
    }

    fn validate(&self, _params: &CommandParams) -> Result<(), DaemonError> {
        // No parameters required
        Ok(())
    }

    fn execute(
        &self,
        ctx: &ExecutionContext,
        _params: CommandParams,
    ) -> Result<CommandResult, DaemonError> {
        debug!(
            request_id = %ctx.request_id,
            "Updating package lists"
        );

        // Run apt-get update
        let mut cmd = ProcessCommand::new("apt-get");
        cmd.arg("update");

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
                stderr = %stderr,
                "Failed to update package lists"
            );
            return Err(DaemonError::Command {
                kind: CommandErrorKind::ExecutionFailed {
                    message: format!("apt-get update failed: {}", sanitize_output(&stderr, 5)),
                },
            });
        }

        info!(
            request_id = %ctx.request_id,
            "Package lists updated successfully"
        );

        Ok(CommandResult::success(serde_json::json!({
            "action": "update",
            "stdout": stdout,
        })))
    }

    fn timeout(&self) -> Duration {
        Duration::from_secs(300) // 5 minutes for update
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_update_command_name() {
        let cmd = UpdatePackageCommand;
        assert_eq!(cmd.name(), "package.update");
    }

    #[test]
    fn test_validate_no_params() {
        let cmd = UpdatePackageCommand;
        let params = CommandParams::new(serde_json::json!({}));
        assert!(cmd.validate(&params).is_ok());
    }

    #[test]
    fn test_timeout_value() {
        assert_eq!(UpdatePackageCommand.timeout(), Duration::from_secs(300));
    }
}
