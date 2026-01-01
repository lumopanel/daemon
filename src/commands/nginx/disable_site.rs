//! Disable Nginx site command.

use std::fs;
use std::path::PathBuf;

use tracing::{debug, info};

use crate::error::DaemonError;
use crate::validation::validate_site_name;

use super::super::traits::Command;
use super::super::types::{CommandParams, CommandResult, ExecutionContext};

/// Disable an Nginx site by removing the symlink from sites-enabled.
///
/// # Parameters
///
/// - `site_name` (required): The site configuration file name (without path)
///
/// Removes the symlink from `/etc/nginx/sites-enabled/{site_name}`.
pub struct DisableNginxSiteCommand;

impl Command for DisableNginxSiteCommand {
    fn name(&self) -> &'static str {
        "nginx.disable_site"
    }

    fn validate(&self, params: &CommandParams) -> Result<(), DaemonError> {
        params.require_string("site_name")?;
        let site_name = params.get_string("site_name")?;
        validate_site_name(&site_name)?;
        Ok(())
    }

    fn execute(
        &self,
        ctx: &ExecutionContext,
        params: CommandParams,
    ) -> Result<CommandResult, DaemonError> {
        let site_name = params.get_string("site_name")?;

        // Re-validate for safety
        validate_site_name(&site_name)?;

        debug!(
            request_id = %ctx.request_id,
            site_name = site_name,
            "Disabling Nginx site"
        );

        let enabled_path = PathBuf::from(format!("/etc/nginx/sites-enabled/{}", site_name));

        // Check if the symlink exists
        if !enabled_path.exists() {
            return Ok(CommandResult::success(serde_json::json!({
                "site_name": site_name,
                "disabled": true,
                "already_disabled": true,
            })));
        }

        // Verify it's a symlink, not a regular file
        let metadata = fs::symlink_metadata(&enabled_path).map_err(|e| DaemonError::Command {
            kind: crate::error::CommandErrorKind::ExecutionFailed {
                message: format!("Failed to get file metadata: {}", e),
            },
        })?;

        if !metadata.file_type().is_symlink() {
            return Ok(CommandResult::failure(
                "NOT_A_SYMLINK",
                format!(
                    "Path {} is not a symlink. Refusing to delete for safety.",
                    enabled_path.display()
                ),
            ));
        }

        // Remove the symlink
        fs::remove_file(&enabled_path).map_err(|e| DaemonError::Command {
            kind: crate::error::CommandErrorKind::ExecutionFailed {
                message: format!("Failed to remove symlink: {}", e),
            },
        })?;

        info!(
            request_id = %ctx.request_id,
            site_name = site_name,
            enabled_path = %enabled_path.display(),
            "Nginx site disabled successfully"
        );

        Ok(CommandResult::success(serde_json::json!({
            "site_name": site_name,
            "enabled_path": enabled_path.to_string_lossy(),
            "disabled": true,
        })))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::auth::PeerInfo;
    use uuid::Uuid;

    #[allow(dead_code)]
    fn create_test_context() -> ExecutionContext {
        ExecutionContext::new(
            Uuid::new_v4(),
            PeerInfo {
                uid: 1000,
                gid: 1000,
                pid: 12345,
            },
            1234567890,
            "nginx.disable_site".to_string(),
        )
    }

    #[test]
    fn test_command_name() {
        let cmd = DisableNginxSiteCommand;
        assert_eq!(cmd.name(), "nginx.disable_site");
    }

    #[test]
    fn test_validate_valid_params() {
        let cmd = DisableNginxSiteCommand;
        let params = CommandParams::new(serde_json::json!({
            "site_name": "example.com"
        }));
        assert!(cmd.validate(&params).is_ok());
    }

    #[test]
    fn test_validate_missing_site_name() {
        let cmd = DisableNginxSiteCommand;
        let params = CommandParams::new(serde_json::json!({}));
        assert!(cmd.validate(&params).is_err());
    }

    #[test]
    fn test_validate_path_traversal() {
        let cmd = DisableNginxSiteCommand;
        let params = CommandParams::new(serde_json::json!({
            "site_name": "../../etc/nginx.conf"
        }));
        assert!(cmd.validate(&params).is_err());
    }
}
