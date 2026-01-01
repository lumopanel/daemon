//! Write file command.

use std::fs::{self, OpenOptions};
use std::io::Write;
use std::os::unix::fs::{chown, PermissionsExt};

use tracing::{debug, info};
use uuid::Uuid;

use crate::error::{CommandErrorKind, DaemonError, ValidationErrorKind};
use crate::validation::{validate_gid, validate_path, validate_uid};

use super::super::traits::Command;
use super::super::types::{CommandParams, CommandResult, ExecutionContext};

/// Write content to a file with atomic write semantics.
///
/// # Parameters
///
/// - `path` (required): The file path to write to
/// - `content` (required): The content to write
/// - `owner` (optional): Owner UID for the file
/// - `group` (optional): Group GID for the file
/// - `mode` (optional): File permissions in octal (e.g., "0644")
///
/// # Atomic Write
///
/// The command writes to a temporary file first, then atomically
/// renames it to the target path to prevent partial writes.
pub struct WriteFileCommand;

impl Command for WriteFileCommand {
    fn name(&self) -> &'static str {
        "file.write"
    }

    fn validate(&self, params: &CommandParams) -> Result<(), DaemonError> {
        params.require_string("path")?;
        params.require_string("content")?;
        Ok(())
    }

    fn execute(
        &self,
        ctx: &ExecutionContext,
        params: CommandParams,
    ) -> Result<CommandResult, DaemonError> {
        let path_str = params.get_string("path")?;
        let content = params.get_string("content")?;
        let owner = params
            .get_optional_i64("owner")
            .map(validate_uid)
            .transpose()?;
        let group = params
            .get_optional_i64("group")
            .map(validate_gid)
            .transpose()?;
        let mode_str = params.get_optional_string("mode");

        // Validate the path
        let path = validate_path(&path_str)?;

        debug!(
            request_id = %ctx.request_id,
            path = %path.display(),
            content_len = content.len(),
            "Writing file"
        );

        // Ensure parent directory exists
        if let Some(parent) = path.parent() {
            if !parent.exists() {
                fs::create_dir_all(parent).map_err(|e| DaemonError::Command {
                    kind: CommandErrorKind::ExecutionFailed {
                        message: format!("Failed to create parent directory: {}", e),
                    },
                })?;
            }
        }

        // Write to a temporary file first (atomic write pattern)
        // Security: Use random suffix to prevent symlink pre-creation attacks
        let temp_name = format!(
            ".{}.{}.tmp",
            path.file_name().unwrap_or_default().to_string_lossy(),
            Uuid::new_v4().simple()
        );
        let temp_path = path.with_file_name(temp_name);
        // Security: Use create_new() for exclusive creation (O_EXCL) to prevent TOCTOU races
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&temp_path)
            .map_err(|e| DaemonError::Command {
                kind: CommandErrorKind::ExecutionFailed {
                    message: format!("Failed to create temp file: {}", e),
                },
            })?;

        file.write_all(content.as_bytes())
            .map_err(|e| DaemonError::Command {
                kind: CommandErrorKind::ExecutionFailed {
                    message: format!("Failed to write content: {}", e),
                },
            })?;

        file.sync_all().map_err(|e| DaemonError::Command {
            kind: CommandErrorKind::ExecutionFailed {
                message: format!("Failed to sync file: {}", e),
            },
        })?;

        // Set permissions before moving if specified
        if let Some(mode_str) = &mode_str {
            let mode = parse_mode(mode_str)?;
            let permissions = fs::Permissions::from_mode(mode);
            fs::set_permissions(&temp_path, permissions).map_err(|e| DaemonError::Command {
                kind: CommandErrorKind::ExecutionFailed {
                    message: format!("Failed to set permissions: {}", e),
                },
            })?;
        }

        // Set ownership if specified (requires root)
        if owner.is_some() || group.is_some() {
            chown(&temp_path, owner, group).map_err(|e| DaemonError::Command {
                kind: CommandErrorKind::ExecutionFailed {
                    message: format!("Failed to set ownership: {}", e),
                },
            })?;
        }

        // Atomic rename
        fs::rename(&temp_path, &path).map_err(|e| DaemonError::Command {
            kind: CommandErrorKind::ExecutionFailed {
                message: format!("Failed to rename temp file: {}", e),
            },
        })?;

        info!(
            request_id = %ctx.request_id,
            path = %path.display(),
            bytes = content.len(),
            "File written successfully"
        );

        Ok(CommandResult::success(serde_json::json!({
            "path": path.to_string_lossy(),
            "bytes_written": content.len(),
        })))
    }
}

/// Parse an octal mode string (e.g., "0644") to a u32.
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
            "file.write".to_string(),
        )
    }

    #[test]
    fn test_write_file_name() {
        let cmd = WriteFileCommand;
        assert_eq!(cmd.name(), "file.write");
    }

    #[test]
    fn test_write_file_validate() {
        let cmd = WriteFileCommand;

        // Valid params
        let params = CommandParams::new(serde_json::json!({
            "path": "/tmp/lumo/test.txt",
            "content": "hello"
        }));
        assert!(cmd.validate(&params).is_ok());

        // Missing path
        let params = CommandParams::new(serde_json::json!({
            "content": "hello"
        }));
        assert!(cmd.validate(&params).is_err());

        // Missing content
        let params = CommandParams::new(serde_json::json!({
            "path": "/tmp/lumo/test.txt"
        }));
        assert!(cmd.validate(&params).is_err());
    }

    #[test]
    fn test_write_file_execute() {
        // Ensure test directory exists
        fs::create_dir_all("/tmp/lumo").ok();

        let cmd = WriteFileCommand;
        let ctx = create_test_context();
        let params = CommandParams::new(serde_json::json!({
            "path": "/tmp/lumo/test_write.txt",
            "content": "Hello, World!"
        }));

        let result = cmd.execute(&ctx, params).unwrap();
        assert!(result.success);

        // Verify file was written
        let content = fs::read_to_string("/tmp/lumo/test_write.txt").unwrap();
        assert_eq!(content, "Hello, World!");

        // Cleanup
        fs::remove_file("/tmp/lumo/test_write.txt").ok();
    }

    #[test]
    fn test_parse_mode() {
        assert_eq!(parse_mode("0644").unwrap(), 0o644);
        assert_eq!(parse_mode("644").unwrap(), 0o644);
        assert_eq!(parse_mode("0755").unwrap(), 0o755);
        assert!(parse_mode("invalid").is_err());
    }
}
