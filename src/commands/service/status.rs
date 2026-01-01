//! Service status command.
//!
//! Query the status of a service.

use std::process::Command as ProcessCommand;
use std::time::Duration;

use tracing::debug;

use crate::commands::traits::Command;
use crate::commands::types::{CommandParams, CommandResult, ExecutionContext};
use crate::error::{CommandErrorKind, DaemonError};
use crate::validation::validate_service_name;

/// Get the status of a service.
pub struct StatusServiceCommand;

impl Command for StatusServiceCommand {
    fn name(&self) -> &'static str {
        "service.status"
    }

    fn validate(&self, params: &CommandParams) -> Result<(), DaemonError> {
        let service = params.get_string("service")?;
        validate_service_name(&service)?;
        Ok(())
    }

    fn execute(
        &self,
        ctx: &ExecutionContext,
        params: CommandParams,
    ) -> Result<CommandResult, DaemonError> {
        let service = params.get_string("service")?;

        debug!(
            request_id = %ctx.request_id,
            service = %service,
            "Getting service status"
        );

        // Check if service is active
        let is_active_output = ProcessCommand::new("systemctl")
            .args(["is-active", &service])
            .output()
            .map_err(|e| DaemonError::Command {
                kind: CommandErrorKind::ExecutionFailed {
                    message: format!("Failed to execute systemctl: {}", e),
                },
            })?;

        let status = String::from_utf8_lossy(&is_active_output.stdout)
            .trim()
            .to_string();
        let active = is_active_output.status.success();

        // Check if service is enabled
        let is_enabled_output = ProcessCommand::new("systemctl")
            .args(["is-enabled", &service])
            .output()
            .map_err(|e| DaemonError::Command {
                kind: CommandErrorKind::ExecutionFailed {
                    message: format!("Failed to execute systemctl: {}", e),
                },
            })?;

        let enabled_status = String::from_utf8_lossy(&is_enabled_output.stdout)
            .trim()
            .to_string();
        let enabled = enabled_status == "enabled";

        // Try to get the main PID if active
        let pid: Option<i64> = if active {
            let show_output = ProcessCommand::new("systemctl")
                .args(["show", &service, "--property=MainPID", "--value"])
                .output()
                .ok()
                .and_then(|output| {
                    String::from_utf8_lossy(&output.stdout)
                        .trim()
                        .parse::<i64>()
                        .ok()
                        .filter(|&pid| pid > 0)
                });
            show_output
        } else {
            None
        };

        debug!(
            request_id = %ctx.request_id,
            service = %service,
            active = active,
            enabled = enabled,
            status = %status,
            "Service status retrieved"
        );

        Ok(CommandResult::success(serde_json::json!({
            "service": service,
            "active": active,
            "enabled": enabled,
            "status": status,
            "pid": pid,
        })))
    }

    fn timeout(&self) -> Duration {
        Duration::from_secs(30)
    }

    fn requires_audit(&self) -> bool {
        // Status queries are read-only and high-frequency, skip audit
        false
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_status_command_name() {
        let cmd = StatusServiceCommand;
        assert_eq!(cmd.name(), "service.status");
    }

    #[test]
    fn test_validate_valid_service() {
        let cmd = StatusServiceCommand;
        let params = CommandParams::new(serde_json::json!({
            "service": "nginx"
        }));
        assert!(cmd.validate(&params).is_ok());
    }

    #[test]
    fn test_validate_invalid_service() {
        let cmd = StatusServiceCommand;
        let params = CommandParams::new(serde_json::json!({
            "service": "malicious-service"
        }));
        assert!(cmd.validate(&params).is_err());
    }

    #[test]
    fn test_validate_missing_service() {
        let cmd = StatusServiceCommand;
        let params = CommandParams::new(serde_json::json!({}));
        assert!(cmd.validate(&params).is_err());
    }

    #[test]
    fn test_timeout_value() {
        assert_eq!(StatusServiceCommand.timeout(), Duration::from_secs(30));
    }

    #[test]
    fn test_requires_audit() {
        let cmd = StatusServiceCommand;
        assert!(!cmd.requires_audit());
    }
}
