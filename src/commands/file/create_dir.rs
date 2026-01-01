//! Create directory command.

use std::fs;
use std::os::unix::fs::{chown, PermissionsExt};

use tracing::{debug, info};

use crate::error::{CommandErrorKind, DaemonError, ValidationErrorKind};
use crate::validation::{validate_directory_path, validate_gid, validate_uid};

use super::super::traits::Command;
use super::super::types::{CommandParams, CommandResult, ExecutionContext};

/// Create a directory.
///
/// # Parameters
///
/// - `path` (required): The directory path to create
/// - `owner` (optional): Owner UID for the directory
/// - `group` (optional): Group GID for the directory
/// - `mode` (optional): Directory permissions in octal (e.g., "0755")
/// - `recursive` (optional): Create parent directories if needed (default: true)
pub struct CreateDirectoryCommand;

impl Command for CreateDirectoryCommand {
    fn name(&self) -> &'static str {
        "file.mkdir"
    }

    fn validate(&self, params: &CommandParams) -> Result<(), DaemonError> {
        params.require_string("path")?;
        Ok(())
    }

    fn execute(
        &self,
        ctx: &ExecutionContext,
        params: CommandParams,
    ) -> Result<CommandResult, DaemonError> {
        let path_str = params.get_string("path")?;
        let owner = params
            .get_optional_i64("owner")
            .map(validate_uid)
            .transpose()?;
        let group = params
            .get_optional_i64("group")
            .map(validate_gid)
            .transpose()?;
        let mode_str = params.get_optional_string("mode");
        let recursive = params.get_optional_bool("recursive", true);

        // Validate the path
        let path = validate_directory_path(&path_str)?;

        debug!(
            request_id = %ctx.request_id,
            path = %path.display(),
            recursive = recursive,
            "Creating directory"
        );

        // Check if directory already exists
        if path.exists() {
            if path.is_dir() {
                return Ok(CommandResult::success(serde_json::json!({
                    "path": path.to_string_lossy(),
                    "created": false,
                    "reason": "Directory already exists"
                })));
            } else {
                return Err(DaemonError::Command {
                    kind: CommandErrorKind::ExecutionFailed {
                        message: "Path exists but is not a directory".to_string(),
                    },
                });
            }
        }

        // Create the directory
        if recursive {
            fs::create_dir_all(&path)
        } else {
            fs::create_dir(&path)
        }
        .map_err(|e| DaemonError::Command {
            kind: CommandErrorKind::ExecutionFailed {
                message: format!("Failed to create directory: {}", e),
            },
        })?;

        // Set permissions if specified
        if let Some(mode_str) = &mode_str {
            let mode = parse_mode(mode_str)?;
            let permissions = fs::Permissions::from_mode(mode);
            fs::set_permissions(&path, permissions).map_err(|e| DaemonError::Command {
                kind: CommandErrorKind::ExecutionFailed {
                    message: format!("Failed to set permissions: {}", e),
                },
            })?;
        }

        // Set ownership if specified (requires root)
        if owner.is_some() || group.is_some() {
            chown(&path, owner, group).map_err(|e| DaemonError::Command {
                kind: CommandErrorKind::ExecutionFailed {
                    message: format!("Failed to set ownership: {}", e),
                },
            })?;
        }

        info!(
            request_id = %ctx.request_id,
            path = %path.display(),
            "Directory created successfully"
        );

        Ok(CommandResult::success(serde_json::json!({
            "path": path.to_string_lossy(),
            "created": true,
        })))
    }
}

/// Parse an octal mode string (e.g., "0755") to a u32.
fn parse_mode(mode_str: &str) -> Result<u32, DaemonError> {
    let mode_str = mode_str.trim_start_matches('0');
    u32::from_str_radix(mode_str, 8).map_err(|_| DaemonError::Validation {
        kind: ValidationErrorKind::InvalidParameter {
            param: "mode".to_string(),
            message: "Invalid octal mode".to_string(),
        },
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::auth::PeerInfo;
    use std::fs;
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
            "file.mkdir".to_string(),
        )
    }

    #[test]
    fn test_mkdir_name() {
        let cmd = CreateDirectoryCommand;
        assert_eq!(cmd.name(), "file.mkdir");
    }

    #[test]
    fn test_mkdir_validate() {
        let cmd = CreateDirectoryCommand;

        let params = CommandParams::new(serde_json::json!({
            "path": "/tmp/lumo/testdir"
        }));
        assert!(cmd.validate(&params).is_ok());

        let params = CommandParams::new(serde_json::json!({}));
        assert!(cmd.validate(&params).is_err());
    }

    #[test]
    fn test_mkdir_execute() {
        let test_dir = "/tmp/lumo/test_mkdir_cmd";

        // Ensure it doesn't exist
        fs::remove_dir_all(test_dir).ok();

        let cmd = CreateDirectoryCommand;
        let ctx = create_test_context();
        let params = CommandParams::new(serde_json::json!({
            "path": test_dir
        }));

        let result = cmd.execute(&ctx, params).unwrap();
        assert!(result.success);
        assert!(std::path::Path::new(test_dir).is_dir());

        // Cleanup
        fs::remove_dir_all(test_dir).ok();
    }

    #[test]
    fn test_mkdir_already_exists() {
        // Use a subdirectory since /tmp/lumo/ prefix is required
        fs::create_dir_all("/tmp/lumo/existing_dir").ok();

        let cmd = CreateDirectoryCommand;
        let ctx = create_test_context();
        let params = CommandParams::new(serde_json::json!({
            "path": "/tmp/lumo/existing_dir"
        }));

        let result = cmd.execute(&ctx, params).unwrap();
        assert!(result.success);
        assert_eq!(result.data.unwrap()["created"], false);

        // Cleanup
        fs::remove_dir_all("/tmp/lumo/existing_dir").ok();
    }
}
