//! Ping command for health checking.

use std::time::{SystemTime, UNIX_EPOCH};

use crate::error::DaemonError;

use super::super::traits::Command;
use super::super::types::{CommandParams, CommandResult, ExecutionContext};

/// Simple ping command that returns a pong response.
///
/// Used for health checks and verifying the daemon is responsive.
pub struct PingCommand;

impl Command for PingCommand {
    fn name(&self) -> &'static str {
        "system.ping"
    }

    fn validate(&self, _params: &CommandParams) -> Result<(), DaemonError> {
        // Ping has no required parameters
        Ok(())
    }

    fn execute(
        &self,
        ctx: &ExecutionContext,
        _params: CommandParams,
    ) -> Result<CommandResult, DaemonError> {
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);

        Ok(CommandResult::success(serde_json::json!({
            "pong": true,
            "timestamp": timestamp,
            "request_id": ctx.request_id.to_string(),
        })))
    }

    fn requires_audit(&self) -> bool {
        // Ping is a high-frequency health check, skip audit logging
        false
    }
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
            "system.ping".to_string(),
        )
    }

    #[test]
    fn test_ping_name() {
        let cmd = PingCommand;
        assert_eq!(cmd.name(), "system.ping");
    }

    #[test]
    fn test_ping_validate() {
        let cmd = PingCommand;
        let params = CommandParams::new(serde_json::json!({}));
        assert!(cmd.validate(&params).is_ok());
    }

    #[test]
    fn test_ping_execute() {
        let cmd = PingCommand;
        let ctx = create_test_context();
        let params = CommandParams::new(serde_json::json!({}));

        let result = cmd.execute(&ctx, params).unwrap();
        assert!(result.success);

        let data = result.data.unwrap();
        assert_eq!(data["pong"], true);
        assert!(data["timestamp"].is_u64());
    }
}
