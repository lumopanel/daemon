//! Package install command.
//!
//! Installs whitelisted packages via apt-get.

use std::process::Command as ProcessCommand;
use std::time::Duration;

use tracing::{debug, info, warn};

use crate::commands::traits::Command;
use crate::commands::types::{CommandParams, CommandResult, ExecutionContext};
use crate::error::{CommandErrorKind, DaemonError};
use crate::executor::sanitize_output;
use crate::validation::validate_package_list;

/// Install packages via apt-get.
pub struct InstallPackageCommand;

impl Command for InstallPackageCommand {
    fn name(&self) -> &'static str {
        "package.install"
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

        debug!(
            request_id = %ctx.request_id,
            packages = ?packages,
            "Installing packages"
        );

        // Build apt-get command with security flags
        let mut cmd = ProcessCommand::new("apt-get");
        cmd.args([
            "install",
            "-y",                      // Non-interactive
            "--no-install-recommends", // Minimize attack surface
            "-o",
            "Dpkg::Options::=--force-confdef",
            "-o",
            "Dpkg::Options::=--force-confold",
        ]);
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
                "Failed to install packages"
            );
            return Err(DaemonError::Command {
                kind: CommandErrorKind::ExecutionFailed {
                    message: format!("apt-get install failed: {}", sanitize_output(&stderr, 5)),
                },
            });
        }

        info!(
            request_id = %ctx.request_id,
            packages = ?packages,
            "Packages installed successfully"
        );

        Ok(CommandResult::success(serde_json::json!({
            "packages": packages,
            "action": "install",
            "stdout": stdout,
        })))
    }

    fn timeout(&self) -> Duration {
        Duration::from_secs(600) // 10 minutes for package installations
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_install_command_name() {
        let cmd = InstallPackageCommand;
        assert_eq!(cmd.name(), "package.install");
    }

    #[test]
    fn test_validate_valid_packages() {
        let cmd = InstallPackageCommand;
        let params = CommandParams::new(serde_json::json!({
            "packages": ["nginx", "redis-server"]
        }));
        assert!(cmd.validate(&params).is_ok());
    }

    #[test]
    fn test_validate_invalid_package() {
        let cmd = InstallPackageCommand;
        let params = CommandParams::new(serde_json::json!({
            "packages": ["nginx", "malware"]
        }));
        assert!(cmd.validate(&params).is_err());
    }

    #[test]
    fn test_validate_empty_packages() {
        let cmd = InstallPackageCommand;
        let params = CommandParams::new(serde_json::json!({
            "packages": []
        }));
        assert!(cmd.validate(&params).is_err());
    }

    #[test]
    fn test_validate_missing_packages() {
        let cmd = InstallPackageCommand;
        let params = CommandParams::new(serde_json::json!({}));
        assert!(cmd.validate(&params).is_err());
    }

    #[test]
    fn test_timeout_value() {
        assert_eq!(InstallPackageCommand.timeout(), Duration::from_secs(600));
    }
}
