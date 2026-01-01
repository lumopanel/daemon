//! Test Nginx configuration command.

use std::time::Duration;

use tracing::{debug, info};

use crate::error::DaemonError;
use crate::executor::{run_command, SubprocessResult};

use super::super::traits::Command;
use super::super::types::{CommandParams, CommandResult, ExecutionContext};

/// Timeout for nginx -t.
const NGINX_TIMEOUT: Duration = Duration::from_secs(30);

/// Test the Nginx configuration for syntax errors.
///
/// # Parameters
///
/// None required.
///
/// Runs `nginx -t` to validate the configuration.
pub struct TestNginxConfigCommand;

impl Command for TestNginxConfigCommand {
    fn name(&self) -> &'static str {
        "nginx.test_config"
    }

    fn validate(&self, _params: &CommandParams) -> Result<(), DaemonError> {
        // No parameters to validate
        Ok(())
    }

    fn execute(
        &self,
        ctx: &ExecutionContext,
        _params: CommandParams,
    ) -> Result<CommandResult, DaemonError> {
        debug!(
            request_id = %ctx.request_id,
            "Testing Nginx configuration"
        );

        let result = test_nginx_config()?;

        if result.success {
            info!(
                request_id = %ctx.request_id,
                "Nginx configuration test passed"
            );

            Ok(CommandResult::success(serde_json::json!({
                "valid": true,
                "output": result.stderr.trim(), // nginx -t writes to stderr
            })))
        } else {
            // Config test failed - return the error details
            Ok(CommandResult::failure(
                "CONFIG_INVALID",
                format!("Nginx configuration test failed:\n{}", result.stderr.trim()),
            ))
        }
    }
}

/// Run nginx -t to test the configuration.
fn test_nginx_config() -> Result<SubprocessResult, DaemonError> {
    run_command("nginx", &["-t"], NGINX_TIMEOUT)
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
            "nginx.test_config".to_string(),
        )
    }

    #[test]
    fn test_command_name() {
        let cmd = TestNginxConfigCommand;
        assert_eq!(cmd.name(), "nginx.test_config");
    }

    #[test]
    fn test_validate_no_params_needed() {
        let cmd = TestNginxConfigCommand;
        let params = CommandParams::new(serde_json::json!({}));
        assert!(cmd.validate(&params).is_ok());
    }
}
