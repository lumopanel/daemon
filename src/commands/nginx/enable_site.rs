//! Enable Nginx site command.

use std::fs;
use std::os::unix::fs as unix_fs;
use std::path::PathBuf;

use tracing::{debug, info};

use crate::error::DaemonError;
use crate::validation::validate_site_name;

use super::super::traits::Command;
use super::super::types::{CommandParams, CommandResult, ExecutionContext};

/// Enable an Nginx site by creating a symlink from sites-available to sites-enabled.
///
/// # Parameters
///
/// - `site_name` (required): The site configuration file name (without path)
///
/// Creates a symlink in `/etc/nginx/sites-enabled/` pointing to
/// `/etc/nginx/sites-available/{site_name}`.
pub struct EnableNginxSiteCommand;

impl Command for EnableNginxSiteCommand {
    fn name(&self) -> &'static str {
        "nginx.enable_site"
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
            "Enabling Nginx site"
        );

        let available_path = PathBuf::from(format!("/etc/nginx/sites-available/{}", site_name));
        let enabled_path = PathBuf::from(format!("/etc/nginx/sites-enabled/{}", site_name));

        // Check that the site config exists in sites-available
        if !available_path.exists() {
            return Ok(CommandResult::failure(
                "SITE_NOT_FOUND",
                format!(
                    "Site configuration not found: {}",
                    available_path.display()
                ),
            ));
        }

        // Check if already enabled
        if enabled_path.exists() {
            // Check if it's pointing to the right place
            if let Ok(target) = fs::read_link(&enabled_path) {
                if target == available_path {
                    return Ok(CommandResult::success(serde_json::json!({
                        "site_name": site_name,
                        "enabled": true,
                        "already_enabled": true,
                    })));
                } else {
                    // Symlink exists but points elsewhere - remove it
                    fs::remove_file(&enabled_path).map_err(|e| DaemonError::Command {
                        kind: crate::error::CommandErrorKind::ExecutionFailed {
                            message: format!("Failed to remove existing symlink: {}", e),
                        },
                    })?;
                }
            } else {
                // It's a regular file, not a symlink - error
                return Ok(CommandResult::failure(
                    "FILE_EXISTS",
                    format!(
                        "A file (not symlink) already exists at {}",
                        enabled_path.display()
                    ),
                ));
            }
        }

        // Ensure sites-enabled directory exists
        let sites_enabled = PathBuf::from("/etc/nginx/sites-enabled");
        if !sites_enabled.exists() {
            fs::create_dir_all(&sites_enabled).map_err(|e| DaemonError::Command {
                kind: crate::error::CommandErrorKind::ExecutionFailed {
                    message: format!("Failed to create sites-enabled directory: {}", e),
                },
            })?;
        }

        // Create the symlink
        unix_fs::symlink(&available_path, &enabled_path).map_err(|e| DaemonError::Command {
            kind: crate::error::CommandErrorKind::ExecutionFailed {
                message: format!("Failed to create symlink: {}", e),
            },
        })?;

        info!(
            request_id = %ctx.request_id,
            site_name = site_name,
            available_path = %available_path.display(),
            enabled_path = %enabled_path.display(),
            "Nginx site enabled successfully"
        );

        Ok(CommandResult::success(serde_json::json!({
            "site_name": site_name,
            "available_path": available_path.to_string_lossy(),
            "enabled_path": enabled_path.to_string_lossy(),
            "enabled": true,
        })))
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
            "nginx.enable_site".to_string(),
        )
    }

    #[test]
    fn test_command_name() {
        let cmd = EnableNginxSiteCommand;
        assert_eq!(cmd.name(), "nginx.enable_site");
    }

    #[test]
    fn test_validate_valid_params() {
        let cmd = EnableNginxSiteCommand;
        let params = CommandParams::new(serde_json::json!({
            "site_name": "example.com"
        }));
        assert!(cmd.validate(&params).is_ok());
    }

    #[test]
    fn test_validate_missing_site_name() {
        let cmd = EnableNginxSiteCommand;
        let params = CommandParams::new(serde_json::json!({}));
        assert!(cmd.validate(&params).is_err());
    }

    #[test]
    fn test_validate_invalid_site_name() {
        let cmd = EnableNginxSiteCommand;
        let params = CommandParams::new(serde_json::json!({
            "site_name": "../etc/passwd"
        }));
        assert!(cmd.validate(&params).is_err());
    }
}
