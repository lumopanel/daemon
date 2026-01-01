//! Command trait definition.

use std::time::Duration;

use crate::error::DaemonError;

use super::types::{CommandParams, CommandResult, ExecutionContext};

/// Core trait for all executable commands.
///
/// Every command the daemon can execute implements this trait.
/// This is the primary extension point for adding new functionality.
///
/// # Example
///
/// ```ignore
/// pub struct MyCommand;
///
/// impl Command for MyCommand {
///     fn name(&self) -> &'static str {
///         "my.command"
///     }
///
///     fn validate(&self, params: &CommandParams) -> Result<(), DaemonError> {
///         params.require_string("required_param")?;
///         Ok(())
///     }
///
///     fn execute(
///         &self,
///         ctx: &ExecutionContext,
///         params: CommandParams,
///     ) -> Result<CommandResult, DaemonError> {
///         let value = params.get_string("required_param")?;
///         Ok(CommandResult::success(serde_json::json!({"value": value})))
///     }
/// }
/// ```
pub trait Command: Send + Sync {
    /// Unique command identifier (e.g., "file.write", "service.restart").
    ///
    /// This is the name used in request messages to invoke this command.
    fn name(&self) -> &'static str;

    /// Validate the command parameters before execution.
    ///
    /// This is called before `execute()` to ensure all required parameters
    /// are present and valid. Return an error if validation fails.
    fn validate(&self, params: &CommandParams) -> Result<(), DaemonError>;

    /// Execute the command.
    ///
    /// This method performs the actual work of the command. It receives
    /// the execution context (with peer info and request metadata) and
    /// the validated parameters.
    ///
    /// Note: This may be called from a blocking context via `spawn_blocking`.
    fn execute(
        &self,
        ctx: &ExecutionContext,
        params: CommandParams,
    ) -> Result<CommandResult, DaemonError>;

    /// Timeout for this command.
    ///
    /// If the command takes longer than this duration, it will be cancelled.
    /// Override this for long-running commands like package installation.
    fn timeout(&self) -> Duration {
        Duration::from_secs(60)
    }

    /// Whether this command requires audit logging.
    ///
    /// Most commands should be audited. Only disable for high-frequency
    /// status queries that would generate too much log volume.
    fn requires_audit(&self) -> bool {
        true
    }
}
