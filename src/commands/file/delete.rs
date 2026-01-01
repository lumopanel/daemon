//! Delete file command.

use std::fs;

use tracing::{debug, info};

use crate::error::{CommandErrorKind, DaemonError};
use crate::validation::validate_path;

use super::super::traits::Command;
use super::super::types::{CommandParams, CommandResult, ExecutionContext};

/// Delete a file.
///
/// # Parameters
///
/// - `path` (required): The file path to delete
///
/// # Notes
///
/// - Only deletes files, not directories
/// - Path must be within allowed prefixes
pub struct DeleteFileCommand;

impl Command for DeleteFileCommand {
    fn name(&self) -> &'static str {
        "file.delete"
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

        // Validate the path
        let path = validate_path(&path_str)?;

        debug!(
            request_id = %ctx.request_id,
            path = %path.display(),
            "Deleting file"
        );

        // Check that it's a file, not a directory
        if path.is_dir() {
            return Err(DaemonError::Command {
                kind: CommandErrorKind::ExecutionFailed {
                    message: "Cannot delete directories with file.delete, use file.rmdir"
                        .to_string(),
                },
            });
        }

        // Check if file exists
        if !path.exists() {
            return Ok(CommandResult::success(serde_json::json!({
                "path": path.to_string_lossy(),
                "deleted": false,
                "reason": "File does not exist"
            })));
        }

        // Delete the file
        fs::remove_file(&path).map_err(|e| DaemonError::Command {
            kind: CommandErrorKind::ExecutionFailed {
                message: format!("Failed to delete file: {}", e),
            },
        })?;

        info!(
            request_id = %ctx.request_id,
            path = %path.display(),
            "File deleted successfully"
        );

        Ok(CommandResult::success(serde_json::json!({
            "path": path.to_string_lossy(),
            "deleted": true,
        })))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::auth::PeerInfo;
    use std::fs::{self, File};
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
            "file.delete".to_string(),
        )
    }

    #[test]
    fn test_delete_file_name() {
        let cmd = DeleteFileCommand;
        assert_eq!(cmd.name(), "file.delete");
    }

    #[test]
    fn test_delete_file_validate() {
        let cmd = DeleteFileCommand;

        let params = CommandParams::new(serde_json::json!({
            "path": "/tmp/lumo/test.txt"
        }));
        assert!(cmd.validate(&params).is_ok());

        let params = CommandParams::new(serde_json::json!({}));
        assert!(cmd.validate(&params).is_err());
    }

    #[test]
    fn test_delete_file_execute() {
        // Ensure test directory exists
        fs::create_dir_all("/tmp/lumo").ok();

        // Create a test file
        let test_path = "/tmp/lumo/test_delete.txt";
        File::create(test_path).unwrap();

        let cmd = DeleteFileCommand;
        let ctx = create_test_context();
        let params = CommandParams::new(serde_json::json!({
            "path": test_path
        }));

        let result = cmd.execute(&ctx, params).unwrap();
        assert!(result.success);

        // Verify file was deleted
        assert!(!std::path::Path::new(test_path).exists());
    }

    #[test]
    fn test_delete_nonexistent_file() {
        let cmd = DeleteFileCommand;
        let ctx = create_test_context();
        let params = CommandParams::new(serde_json::json!({
            "path": "/tmp/lumo/nonexistent_file_12345.txt"
        }));

        let result = cmd.execute(&ctx, params).unwrap();
        assert!(result.success);
        assert_eq!(result.data.unwrap()["deleted"], false);
    }
}
