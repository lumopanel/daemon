//! Write template command.
//!
//! Renders a template and writes the result to a file.

use std::fs::{self, OpenOptions};
use std::io::Write;
use std::os::unix::fs::{chown, PermissionsExt};
use std::sync::Arc;

use tracing::{debug, info};
use uuid::Uuid;

use crate::error::{CommandErrorKind, DaemonError, ValidationErrorKind};
use crate::templates::TemplateEngine;
use crate::validation::{validate_gid, validate_path, validate_uid};

use super::super::traits::Command;
use super::super::types::{CommandParams, CommandResult, ExecutionContext};

/// Render a template and write the result to a file.
///
/// # Parameters
///
/// - `path` (required): The file path to write to
/// - `template` (required): Template name (e.g., "nginx/site.conf.tera")
/// - `context` (required): Template context variables as JSON object
/// - `owner` (optional): Owner UID for the file
/// - `group` (optional): Group GID for the file
/// - `mode` (optional): File permissions in octal (e.g., "0644")
///
/// # Atomic Write
///
/// The command renders to a temporary file first, then atomically
/// renames it to the target path to prevent partial writes.
pub struct WriteTemplateCommand {
    engine: Arc<TemplateEngine>,
}

impl WriteTemplateCommand {
    /// Create a new WriteTemplateCommand with the given template engine.
    pub fn new(engine: Arc<TemplateEngine>) -> Self {
        Self { engine }
    }
}

impl Command for WriteTemplateCommand {
    fn name(&self) -> &'static str {
        "file.write_template"
    }

    fn validate(&self, params: &CommandParams) -> Result<(), DaemonError> {
        // Required parameters
        params.require_string("path")?;
        params.require_string("template")?;

        // Context must be present (can be empty object)
        if !params.has("context") {
            return Err(DaemonError::Validation {
                kind: ValidationErrorKind::MissingParameter {
                    param: "context".to_string(),
                },
            });
        }

        // Validate template exists
        let template = params.get_string("template")?;
        if !self.engine.has_template(&template) {
            return Err(DaemonError::Template {
                message: format!("Template '{}' not found", template),
            });
        }

        Ok(())
    }

    fn execute(
        &self,
        ctx: &ExecutionContext,
        params: CommandParams,
    ) -> Result<CommandResult, DaemonError> {
        let path_str = params.get_string("path")?;
        let template = params.get_string("template")?;
        let context = params
            .as_value()
            .get("context")
            .cloned()
            .unwrap_or(serde_json::json!({}));
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
            template = %template,
            "Rendering and writing template"
        );

        // Render the template
        let content = self.engine.render(&template, &context)?;

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
            template = %template,
            bytes = content.len(),
            "Template rendered and written successfully"
        );

        Ok(CommandResult::success(serde_json::json!({
            "path": path.to_string_lossy(),
            "template": template,
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
    use std::io::Write as IoWrite;
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
            "file.write_template".to_string(),
        )
    }

    fn create_test_engine() -> Arc<TemplateEngine> {
        // Create a temp directory with a test template
        // Note: We use write_all to avoid format string interpretation of {{ as {
        let dir = tempfile::tempdir().unwrap();
        let template_path = dir.path().join("test.conf.tera");
        let mut file = fs::File::create(&template_path).unwrap();
        file.write_all(b"# Config for {{ name }}\n").unwrap();
        file.write_all(b"port = {{ port }}\n").unwrap();

        // Leak the tempdir so it persists (for testing only)
        let path = dir.path().to_path_buf();
        std::mem::forget(dir);

        Arc::new(TemplateEngine::new(&path).unwrap())
    }

    #[test]
    fn test_write_template_name() {
        let engine = Arc::new(TemplateEngine::empty());
        let cmd = WriteTemplateCommand::new(engine);
        assert_eq!(cmd.name(), "file.write_template");
    }

    #[test]
    fn test_write_template_validate_missing_params() {
        let engine = Arc::new(TemplateEngine::empty());
        let cmd = WriteTemplateCommand::new(engine);

        // Missing path
        let params = CommandParams::new(serde_json::json!({
            "template": "test.tera",
            "context": {}
        }));
        assert!(cmd.validate(&params).is_err());

        // Missing template
        let params = CommandParams::new(serde_json::json!({
            "path": "/tmp/lumo/test.txt",
            "context": {}
        }));
        assert!(cmd.validate(&params).is_err());

        // Missing context
        let params = CommandParams::new(serde_json::json!({
            "path": "/tmp/lumo/test.txt",
            "template": "test.tera"
        }));
        assert!(cmd.validate(&params).is_err());
    }

    #[test]
    fn test_write_template_execute() {
        // Ensure test directory exists
        fs::create_dir_all("/tmp/lumo").ok();

        let engine = create_test_engine();
        let cmd = WriteTemplateCommand::new(engine);
        let ctx = create_test_context();

        let params = CommandParams::new(serde_json::json!({
            "path": "/tmp/lumo/template_test.conf",
            "template": "test.conf.tera",
            "context": {
                "name": "my-service",
                "port": 8080
            }
        }));

        let result = cmd.execute(&ctx, params).unwrap();
        assert!(result.success);

        // Verify file was written with rendered content
        let content = fs::read_to_string("/tmp/lumo/template_test.conf").unwrap();
        assert!(content.contains("# Config for my-service"));
        assert!(content.contains("port = 8080"));

        // Cleanup
        fs::remove_file("/tmp/lumo/template_test.conf").ok();
    }
}
