//! Write PHP INI settings command.

use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;

use tracing::{debug, info};

use crate::error::DaemonError;
use crate::validation::validate_path;

use super::super::traits::Command;
use super::super::types::{CommandParams, CommandResult, ExecutionContext};
use super::install_version::validate_php_version;

/// Write custom PHP INI settings.
///
/// # Parameters
///
/// - `version` (required): The PHP version (8.1, 8.2, 8.3, or 8.4)
/// - `settings` (required): Object with INI settings (key-value pairs)
/// - `pool` (optional): FPM pool name (default: "www")
///
/// Settings are written to `/etc/php/{version}/fpm/conf.d/99-custom.ini`
/// or `/etc/php/{version}/fpm/pool.d/{pool}.conf` for pool-specific settings.
pub struct WritePhpIniCommand;

impl Command for WritePhpIniCommand {
    fn name(&self) -> &'static str {
        "php.write_ini"
    }

    fn validate(&self, params: &CommandParams) -> Result<(), DaemonError> {
        params.require_string("version")?;

        let version = params.get_string("version")?;
        validate_php_version(&version)?;

        // Validate settings is an object
        let settings =
            params
                .as_value()
                .get("settings")
                .ok_or_else(|| DaemonError::Validation {
                    kind: crate::error::ValidationErrorKind::MissingParameter {
                        param: "settings".to_string(),
                    },
                })?;

        if !settings.is_object() {
            return Err(DaemonError::Validation {
                kind: crate::error::ValidationErrorKind::InvalidParameter {
                    param: "settings".to_string(),
                    message: "Settings must be an object".to_string(),
                },
            });
        }

        // Validate each setting key
        if let Some(obj) = settings.as_object() {
            for key in obj.keys() {
                validate_ini_key(key)?;
            }
        }

        Ok(())
    }

    fn execute(
        &self,
        ctx: &ExecutionContext,
        params: CommandParams,
    ) -> Result<CommandResult, DaemonError> {
        let version = params.get_string("version")?;
        let settings = params
            .as_value()
            .get("settings")
            .cloned()
            .unwrap_or_default();

        // Re-validate for safety
        validate_php_version(&version)?;

        debug!(
            request_id = %ctx.request_id,
            version = version,
            "Writing PHP INI settings"
        );

        // Build the INI content
        let mut ini_content = String::from("; Custom PHP settings managed by Lumo\n");
        ini_content.push_str("; Do not edit manually - changes will be overwritten\n\n");

        if let Some(obj) = settings.as_object() {
            for (key, value) in obj {
                validate_ini_key(key)?;
                let value_str = match value {
                    serde_json::Value::String(s) => s.clone(),
                    serde_json::Value::Number(n) => n.to_string(),
                    serde_json::Value::Bool(b) => {
                        if *b {
                            "On".to_string()
                        } else {
                            "Off".to_string()
                        }
                    }
                    _ => value.to_string(),
                };
                ini_content.push_str(&format!("{} = {}\n", key, value_str));
            }
        }

        // Determine the path
        let ini_path = PathBuf::from(format!("/etc/php/{}/fpm/conf.d/99-custom.ini", version));

        // Validate path
        validate_path(&ini_path)?;

        // Ensure parent directory exists
        if let Some(parent) = ini_path.parent() {
            if !parent.exists() {
                fs::create_dir_all(parent).map_err(|e| DaemonError::Command {
                    kind: crate::error::CommandErrorKind::ExecutionFailed {
                        message: format!("Failed to create directory: {}", e),
                    },
                })?;
            }
        }

        // Write the INI file
        fs::write(&ini_path, &ini_content).map_err(|e| DaemonError::Command {
            kind: crate::error::CommandErrorKind::ExecutionFailed {
                message: format!("Failed to write INI file: {}", e),
            },
        })?;

        // Set permissions
        fs::set_permissions(&ini_path, fs::Permissions::from_mode(0o644)).map_err(|e| {
            DaemonError::Command {
                kind: crate::error::CommandErrorKind::ExecutionFailed {
                    message: format!("Failed to set INI file permissions: {}", e),
                },
            }
        })?;

        info!(
            request_id = %ctx.request_id,
            version = version,
            path = %ini_path.display(),
            "PHP INI settings written successfully"
        );

        Ok(CommandResult::success(serde_json::json!({
            "version": version,
            "path": ini_path.to_string_lossy(),
            "written": true,
        })))
    }
}

/// Validate an INI setting key.
fn validate_ini_key(key: &str) -> Result<(), DaemonError> {
    // Check for empty key
    if key.is_empty() {
        return Err(DaemonError::Validation {
            kind: crate::error::ValidationErrorKind::InvalidParameter {
                param: "settings".to_string(),
                message: "INI key cannot be empty".to_string(),
            },
        });
    }

    // Check length
    if key.len() > 128 {
        return Err(DaemonError::Validation {
            kind: crate::error::ValidationErrorKind::InvalidParameter {
                param: "settings".to_string(),
                message: format!("INI key '{}' is too long (max 128 chars)", key),
            },
        });
    }

    // Allow alphanumeric, underscores, dots, and brackets (for array settings)
    for c in key.chars() {
        if !c.is_ascii_alphanumeric() && c != '_' && c != '.' && c != '[' && c != ']' {
            return Err(DaemonError::Validation {
                kind: crate::error::ValidationErrorKind::InvalidParameter {
                    param: "settings".to_string(),
                    message: format!("INI key '{}' contains invalid character: '{}'", key, c),
                },
            });
        }
    }

    // Prevent dangerous settings
    let dangerous_keys = [
        "disable_functions",
        "disable_classes",
        "open_basedir",
        "safe_mode",
        "extension_dir",
        "extension",
        "zend_extension",
    ];

    for dangerous in dangerous_keys {
        if key.eq_ignore_ascii_case(dangerous) {
            return Err(DaemonError::Validation {
                kind: crate::error::ValidationErrorKind::InvalidParameter {
                    param: "settings".to_string(),
                    message: format!("INI key '{}' is not allowed for security reasons", key),
                },
            });
        }
    }

    Ok(())
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
            "php.write_ini".to_string(),
        )
    }

    #[test]
    fn test_command_name() {
        let cmd = WritePhpIniCommand;
        assert_eq!(cmd.name(), "php.write_ini");
    }

    #[test]
    fn test_validate_ini_key_valid() {
        assert!(validate_ini_key("memory_limit").is_ok());
        assert!(validate_ini_key("upload_max_filesize").is_ok());
        assert!(validate_ini_key("post_max_size").is_ok());
        assert!(validate_ini_key("max_execution_time").is_ok());
        assert!(validate_ini_key("session.gc_maxlifetime").is_ok());
    }

    #[test]
    fn test_validate_ini_key_invalid() {
        assert!(validate_ini_key("").is_err());
        assert!(validate_ini_key("key with spaces").is_err());
        assert!(validate_ini_key("key;semicolon").is_err());
    }

    #[test]
    fn test_validate_ini_key_dangerous() {
        assert!(validate_ini_key("disable_functions").is_err());
        assert!(validate_ini_key("extension").is_err());
        assert!(validate_ini_key("zend_extension").is_err());
    }

    #[test]
    fn test_validate_valid_params() {
        let cmd = WritePhpIniCommand;
        let params = CommandParams::new(serde_json::json!({
            "version": "8.2",
            "settings": {
                "memory_limit": "256M",
                "upload_max_filesize": "64M"
            }
        }));
        assert!(cmd.validate(&params).is_ok());
    }

    #[test]
    fn test_validate_missing_version() {
        let cmd = WritePhpIniCommand;
        let params = CommandParams::new(serde_json::json!({
            "settings": {
                "memory_limit": "256M"
            }
        }));
        assert!(cmd.validate(&params).is_err());
    }

    #[test]
    fn test_validate_missing_settings() {
        let cmd = WritePhpIniCommand;
        let params = CommandParams::new(serde_json::json!({
            "version": "8.2"
        }));
        assert!(cmd.validate(&params).is_err());
    }
}
