//! Service enable/disable commands.
//!
//! Commands for enabling and disabling services at boot.

use std::process::Command as ProcessCommand;
use std::time::Duration;

use tracing::{debug, info, warn};

use crate::commands::traits::Command;
use crate::commands::types::{CommandParams, CommandResult, ExecutionContext};
use crate::error::{CommandErrorKind, DaemonError};
use crate::validation::validate_service_name;

/// Enable a service to start at boot.
pub struct EnableServiceCommand;

impl Command for EnableServiceCommand {
    fn name(&self) -> &'static str {
        "service.enable"
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
            "Enabling service"
        );

        let output = ProcessCommand::new("systemctl")
            .args(["enable", &service])
            .output()
            .map_err(|e| DaemonError::Command {
                kind: CommandErrorKind::ExecutionFailed {
                    message: format!("Failed to execute systemctl: {}", e),
                },
            })?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            warn!(
                request_id = %ctx.request_id,
                service = %service,
                stderr = %stderr,
                "Failed to enable service"
            );
            return Err(DaemonError::Command {
                kind: CommandErrorKind::ExecutionFailed {
                    message: format!("systemctl enable {} failed: {}", service, stderr),
                },
            });
        }

        info!(
            request_id = %ctx.request_id,
            service = %service,
            "Service enabled successfully"
        );

        Ok(CommandResult::success(serde_json::json!({
            "service": service,
            "action": "enable",
            "enabled": true,
        })))
    }

    fn timeout(&self) -> Duration {
        Duration::from_secs(30)
    }
}

/// Disable a service from starting at boot.
pub struct DisableServiceCommand;

impl Command for DisableServiceCommand {
    fn name(&self) -> &'static str {
        "service.disable"
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
            "Disabling service"
        );

        let output = ProcessCommand::new("systemctl")
            .args(["disable", &service])
            .output()
            .map_err(|e| DaemonError::Command {
                kind: CommandErrorKind::ExecutionFailed {
                    message: format!("Failed to execute systemctl: {}", e),
                },
            })?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            warn!(
                request_id = %ctx.request_id,
                service = %service,
                stderr = %stderr,
                "Failed to disable service"
            );
            return Err(DaemonError::Command {
                kind: CommandErrorKind::ExecutionFailed {
                    message: format!("systemctl disable {} failed: {}", service, stderr),
                },
            });
        }

        info!(
            request_id = %ctx.request_id,
            service = %service,
            "Service disabled successfully"
        );

        Ok(CommandResult::success(serde_json::json!({
            "service": service,
            "action": "disable",
            "enabled": false,
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
    fn test_enable_command_name() {
        let cmd = EnableServiceCommand;
        assert_eq!(cmd.name(), "service.enable");
    }

    #[test]
    fn test_disable_command_name() {
        let cmd = DisableServiceCommand;
        assert_eq!(cmd.name(), "service.disable");
    }

    #[test]
    fn test_validate_valid_service() {
        let cmd = EnableServiceCommand;
        let params = CommandParams::new(serde_json::json!({
            "service": "nginx"
        }));
        assert!(cmd.validate(&params).is_ok());

        let cmd = DisableServiceCommand;
        assert!(cmd.validate(&params).is_ok());
    }

    #[test]
    fn test_validate_invalid_service() {
        let cmd = EnableServiceCommand;
        let params = CommandParams::new(serde_json::json!({
            "service": "malicious-service"
        }));
        assert!(cmd.validate(&params).is_err());
    }

    #[test]
    fn test_timeout_values() {
        assert_eq!(EnableServiceCommand.timeout(), Duration::from_secs(30));
        assert_eq!(DisableServiceCommand.timeout(), Duration::from_secs(30));
    }
}
