//! Service control commands.
//!
//! Commands for starting, stopping, restarting, and reloading services.

use std::process::Command as ProcessCommand;
use std::time::Duration;

use tracing::{debug, info, warn};

use crate::commands::traits::Command;
use crate::commands::types::{CommandParams, CommandResult, ExecutionContext};
use crate::error::{CommandErrorKind, DaemonError};
use crate::validation::validate_service_name;

/// Start a service.
pub struct StartServiceCommand;

impl Command for StartServiceCommand {
    fn name(&self) -> &'static str {
        "service.start"
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
            "Starting service"
        );

        let output = ProcessCommand::new("systemctl")
            .args(["start", &service])
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
                "Failed to start service"
            );
            return Err(DaemonError::Command {
                kind: CommandErrorKind::ExecutionFailed {
                    message: format!("systemctl start {} failed: {}", service, stderr),
                },
            });
        }

        info!(
            request_id = %ctx.request_id,
            service = %service,
            "Service started successfully"
        );

        Ok(CommandResult::success(serde_json::json!({
            "service": service,
            "action": "start",
        })))
    }

    fn timeout(&self) -> Duration {
        Duration::from_secs(120)
    }
}

/// Stop a service.
pub struct StopServiceCommand;

impl Command for StopServiceCommand {
    fn name(&self) -> &'static str {
        "service.stop"
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
            "Stopping service"
        );

        let output = ProcessCommand::new("systemctl")
            .args(["stop", &service])
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
                "Failed to stop service"
            );
            return Err(DaemonError::Command {
                kind: CommandErrorKind::ExecutionFailed {
                    message: format!("systemctl stop {} failed: {}", service, stderr),
                },
            });
        }

        info!(
            request_id = %ctx.request_id,
            service = %service,
            "Service stopped successfully"
        );

        Ok(CommandResult::success(serde_json::json!({
            "service": service,
            "action": "stop",
        })))
    }

    fn timeout(&self) -> Duration {
        Duration::from_secs(120)
    }
}

/// Restart a service.
pub struct RestartServiceCommand;

impl Command for RestartServiceCommand {
    fn name(&self) -> &'static str {
        "service.restart"
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
            "Restarting service"
        );

        let output = ProcessCommand::new("systemctl")
            .args(["restart", &service])
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
                "Failed to restart service"
            );
            return Err(DaemonError::Command {
                kind: CommandErrorKind::ExecutionFailed {
                    message: format!("systemctl restart {} failed: {}", service, stderr),
                },
            });
        }

        info!(
            request_id = %ctx.request_id,
            service = %service,
            "Service restarted successfully"
        );

        Ok(CommandResult::success(serde_json::json!({
            "service": service,
            "action": "restart",
        })))
    }

    fn timeout(&self) -> Duration {
        Duration::from_secs(120)
    }
}

/// Reload a service configuration.
pub struct ReloadServiceCommand;

impl Command for ReloadServiceCommand {
    fn name(&self) -> &'static str {
        "service.reload"
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
            "Reloading service"
        );

        let output = ProcessCommand::new("systemctl")
            .args(["reload", &service])
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
                "Failed to reload service"
            );
            return Err(DaemonError::Command {
                kind: CommandErrorKind::ExecutionFailed {
                    message: format!("systemctl reload {} failed: {}", service, stderr),
                },
            });
        }

        info!(
            request_id = %ctx.request_id,
            service = %service,
            "Service reloaded successfully"
        );

        Ok(CommandResult::success(serde_json::json!({
            "service": service,
            "action": "reload",
        })))
    }

    fn timeout(&self) -> Duration {
        Duration::from_secs(60)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_start_command_name() {
        let cmd = StartServiceCommand;
        assert_eq!(cmd.name(), "service.start");
    }

    #[test]
    fn test_stop_command_name() {
        let cmd = StopServiceCommand;
        assert_eq!(cmd.name(), "service.stop");
    }

    #[test]
    fn test_restart_command_name() {
        let cmd = RestartServiceCommand;
        assert_eq!(cmd.name(), "service.restart");
    }

    #[test]
    fn test_reload_command_name() {
        let cmd = ReloadServiceCommand;
        assert_eq!(cmd.name(), "service.reload");
    }

    #[test]
    fn test_validate_valid_service() {
        let cmd = StartServiceCommand;
        let params = CommandParams::new(serde_json::json!({
            "service": "nginx"
        }));
        assert!(cmd.validate(&params).is_ok());
    }

    #[test]
    fn test_validate_invalid_service() {
        let cmd = StartServiceCommand;
        let params = CommandParams::new(serde_json::json!({
            "service": "malicious-service"
        }));
        assert!(cmd.validate(&params).is_err());
    }

    #[test]
    fn test_validate_missing_service() {
        let cmd = StartServiceCommand;
        let params = CommandParams::new(serde_json::json!({}));
        assert!(cmd.validate(&params).is_err());
    }

    #[test]
    fn test_timeout_values() {
        assert_eq!(StartServiceCommand.timeout(), Duration::from_secs(120));
        assert_eq!(StopServiceCommand.timeout(), Duration::from_secs(120));
        assert_eq!(RestartServiceCommand.timeout(), Duration::from_secs(120));
        assert_eq!(ReloadServiceCommand.timeout(), Duration::from_secs(60));
    }
}
