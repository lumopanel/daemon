//! Delete user command.
//!
//! Deletes a system user, optionally removing their home directory.

use std::process::Command as ProcessCommand;
use std::time::Duration;

use tracing::{debug, info, warn};

use crate::commands::traits::Command;
use crate::commands::types::{CommandParams, CommandResult, ExecutionContext};
use crate::error::{CommandErrorKind, DaemonError};
use crate::validation::validate_system_username;

/// Delete a system user.
pub struct DeleteUserCommand;

impl Command for DeleteUserCommand {
    fn name(&self) -> &'static str {
        "user.delete"
    }

    fn validate(&self, params: &CommandParams) -> Result<(), DaemonError> {
        // Validate username
        let username = params.get_string("username")?;
        validate_system_username(&username)?;

        Ok(())
    }

    fn execute(
        &self,
        ctx: &ExecutionContext,
        params: CommandParams,
    ) -> Result<CommandResult, DaemonError> {
        let username = params.get_string("username")?;
        let remove_home = params.get_optional_bool("remove_home", false);

        debug!(
            request_id = %ctx.request_id,
            username = %username,
            remove_home = remove_home,
            "Deleting user"
        );

        // Check if user exists first
        let check_output = ProcessCommand::new("id")
            .arg(&username)
            .output()
            .map_err(|e| DaemonError::Command {
                kind: CommandErrorKind::ExecutionFailed {
                    message: format!("Failed to execute id: {}", e),
                },
            })?;

        if !check_output.status.success() {
            return Err(DaemonError::Command {
                kind: CommandErrorKind::ExecutionFailed {
                    message: format!("User '{}' does not exist", username),
                },
            });
        }

        // Build userdel arguments
        let mut args = Vec::new();
        if remove_home {
            args.push("--remove");
        }
        args.push(&username);

        // Execute userdel
        let output = ProcessCommand::new("userdel")
            .args(&args)
            .output()
            .map_err(|e| DaemonError::Command {
                kind: CommandErrorKind::ExecutionFailed {
                    message: format!("Failed to execute userdel: {}", e),
                },
            })?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            let exit_code = output.status.code().unwrap_or(-1);

            warn!(
                request_id = %ctx.request_id,
                username = %username,
                exit_code = exit_code,
                stderr = %stderr,
                "Failed to delete user"
            );

            // Parse common userdel exit codes
            let error_message = match exit_code {
                1 => format!(
                    "Cannot update password file when deleting user '{}'",
                    username
                ),
                2 => "Invalid command syntax for userdel".to_string(),
                6 => format!("User '{}' does not exist", username),
                8 => format!("User '{}' is currently logged in", username),
                10 => format!("Cannot update group file when deleting user '{}'", username),
                12 => format!("Cannot remove home directory for user '{}'", username),
                _ => format!("userdel failed (exit {}): {}", exit_code, stderr.trim()),
            };

            return Err(DaemonError::Command {
                kind: CommandErrorKind::ExecutionFailed {
                    message: error_message,
                },
            });
        }

        info!(
            request_id = %ctx.request_id,
            username = %username,
            remove_home = remove_home,
            "User deleted successfully"
        );

        Ok(CommandResult::success(serde_json::json!({
            "username": username,
            "removed_home": remove_home,
        })))
    }

    fn timeout(&self) -> Duration {
        Duration::from_secs(30)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_command_name() {
        let cmd = DeleteUserCommand;
        assert_eq!(cmd.name(), "user.delete");
    }

    #[test]
    fn test_validate_valid_username() {
        let cmd = DeleteUserCommand;
        let params = CommandParams::new(serde_json::json!({
            "username": "testuser"
        }));
        assert!(cmd.validate(&params).is_ok());
    }

    #[test]
    fn test_validate_with_remove_home() {
        let cmd = DeleteUserCommand;
        let params = CommandParams::new(serde_json::json!({
            "username": "testuser",
            "remove_home": true
        }));
        assert!(cmd.validate(&params).is_ok());
    }

    #[test]
    fn test_validate_reserved_username() {
        let cmd = DeleteUserCommand;
        let params = CommandParams::new(serde_json::json!({
            "username": "root"
        }));
        assert!(cmd.validate(&params).is_err());
    }

    #[test]
    fn test_validate_reserved_www_data() {
        let cmd = DeleteUserCommand;
        let params = CommandParams::new(serde_json::json!({
            "username": "www-data"
        }));
        assert!(cmd.validate(&params).is_err());
    }

    #[test]
    fn test_validate_missing_username() {
        let cmd = DeleteUserCommand;
        let params = CommandParams::new(serde_json::json!({}));
        assert!(cmd.validate(&params).is_err());
    }

    #[test]
    fn test_timeout() {
        let cmd = DeleteUserCommand;
        assert_eq!(cmd.timeout(), Duration::from_secs(30));
    }
}
