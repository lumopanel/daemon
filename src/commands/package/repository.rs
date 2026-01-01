//! Package repository command.
//!
//! Adds whitelisted PPA repositories via add-apt-repository.

use std::process::Command as ProcessCommand;
use std::time::Duration;

use tracing::{debug, info, warn};

use crate::commands::traits::Command;
use crate::commands::types::{CommandParams, CommandResult, ExecutionContext};
use crate::error::{CommandErrorKind, DaemonError};
use crate::executor::sanitize_output;
use crate::validation::validate_repository;

/// Add a PPA repository.
pub struct AddRepositoryCommand;

impl Command for AddRepositoryCommand {
    fn name(&self) -> &'static str {
        "package.add_repository"
    }

    fn validate(&self, params: &CommandParams) -> Result<(), DaemonError> {
        let repository = params.get_string("repository")?;
        validate_repository(&repository)?;
        Ok(())
    }

    fn execute(
        &self,
        ctx: &ExecutionContext,
        params: CommandParams,
    ) -> Result<CommandResult, DaemonError> {
        let repository = params.get_string("repository")?;

        debug!(
            request_id = %ctx.request_id,
            repository = %repository,
            "Adding repository"
        );

        // Build add-apt-repository command
        let mut cmd = ProcessCommand::new("add-apt-repository");
        cmd.args([
            "-y", // Non-interactive
            &repository,
        ]);

        // Set environment to avoid prompts
        cmd.env("DEBIAN_FRONTEND", "noninteractive");

        let output = cmd.output().map_err(|e| DaemonError::Command {
            kind: CommandErrorKind::ExecutionFailed {
                message: format!("Failed to execute add-apt-repository: {}", e),
            },
        })?;

        let stdout = String::from_utf8_lossy(&output.stdout).to_string();
        let stderr = String::from_utf8_lossy(&output.stderr).to_string();

        if !output.status.success() {
            warn!(
                request_id = %ctx.request_id,
                repository = %repository,
                stderr = %stderr,
                "Failed to add repository"
            );
            return Err(DaemonError::Command {
                kind: CommandErrorKind::ExecutionFailed {
                    message: format!("add-apt-repository failed: {}", sanitize_output(&stderr, 5)),
                },
            });
        }

        info!(
            request_id = %ctx.request_id,
            repository = %repository,
            "Repository added successfully"
        );

        Ok(CommandResult::success(serde_json::json!({
            "repository": repository,
            "action": "add",
            "stdout": stdout,
        })))
    }

    fn timeout(&self) -> Duration {
        Duration::from_secs(300) // 5 minutes for repository operations
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_add_repository_command_name() {
        let cmd = AddRepositoryCommand;
        assert_eq!(cmd.name(), "package.add_repository");
    }

    #[test]
    fn test_validate_valid_repository() {
        let cmd = AddRepositoryCommand;
        let params = CommandParams::new(serde_json::json!({
            "repository": "ppa:ondrej/php"
        }));
        assert!(cmd.validate(&params).is_ok());
    }

    #[test]
    fn test_validate_invalid_repository() {
        let cmd = AddRepositoryCommand;
        let params = CommandParams::new(serde_json::json!({
            "repository": "ppa:unknown/malicious"
        }));
        assert!(cmd.validate(&params).is_err());
    }

    #[test]
    fn test_validate_missing_repository() {
        let cmd = AddRepositoryCommand;
        let params = CommandParams::new(serde_json::json!({}));
        assert!(cmd.validate(&params).is_err());
    }

    #[test]
    fn test_validate_empty_repository() {
        let cmd = AddRepositoryCommand;
        let params = CommandParams::new(serde_json::json!({
            "repository": ""
        }));
        assert!(cmd.validate(&params).is_err());
    }

    #[test]
    fn test_validate_injection_attempt() {
        let cmd = AddRepositoryCommand;
        let params = CommandParams::new(serde_json::json!({
            "repository": "ppa:ondrej/php; rm -rf /"
        }));
        assert!(cmd.validate(&params).is_err());
    }

    #[test]
    fn test_timeout_value() {
        assert_eq!(AddRepositoryCommand.timeout(), Duration::from_secs(300));
    }
}
