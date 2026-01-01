//! Create user command.
//!
//! Creates a new system user with specified home directory and shell.

use std::process::Command as ProcessCommand;
use std::time::Duration;

use tracing::{debug, info, warn};

use crate::commands::traits::Command;
use crate::commands::types::{CommandParams, CommandResult, ExecutionContext};
use crate::error::{CommandErrorKind, DaemonError};
use crate::validation::validate_system_username;

/// Allowed login shells for user creation.
const ALLOWED_SHELLS: &[&str] = &[
    "/bin/bash",
    "/bin/sh",
    "/usr/bin/bash",
    "/usr/bin/sh",
    "/bin/zsh",
    "/usr/bin/zsh",
    "/usr/sbin/nologin",
    "/bin/false",
];

/// Create a new system user.
pub struct CreateUserCommand;

impl Command for CreateUserCommand {
    fn name(&self) -> &'static str {
        "user.create"
    }

    fn validate(&self, params: &CommandParams) -> Result<(), DaemonError> {
        // Validate username
        let username = params.get_string("username")?;
        validate_system_username(&username)?;

        // Validate shell if provided
        if let Some(shell) = params.get_optional_string("shell") {
            if !ALLOWED_SHELLS.contains(&shell.as_str()) {
                return Err(DaemonError::Validation {
                    kind: crate::error::ValidationErrorKind::InvalidParameter {
                        param: "shell".to_string(),
                        message: format!(
                            "Invalid shell '{}'. Allowed shells: {:?}",
                            shell, ALLOWED_SHELLS
                        ),
                    },
                });
            }
        }

        // Validate home_dir if provided (basic path validation)
        if let Some(home_dir) = params.get_optional_string("home_dir") {
            // Must be an absolute path
            if !home_dir.starts_with('/') {
                return Err(DaemonError::Validation {
                    kind: crate::error::ValidationErrorKind::InvalidParameter {
                        param: "home_dir".to_string(),
                        message: "Home directory must be an absolute path".to_string(),
                    },
                });
            }
            // Check for path traversal attempts
            if home_dir.contains("..") {
                return Err(DaemonError::Validation {
                    kind: crate::error::ValidationErrorKind::InvalidParameter {
                        param: "home_dir".to_string(),
                        message: "Home directory cannot contain path traversal sequences (..)".to_string(),
                    },
                });
            }
            // Must be under /home or /var
            if !home_dir.starts_with("/home/") && !home_dir.starts_with("/var/") {
                return Err(DaemonError::Validation {
                    kind: crate::error::ValidationErrorKind::InvalidParameter {
                        param: "home_dir".to_string(),
                        message: "Home directory must be under /home/ or /var/".to_string(),
                    },
                });
            }
        }

        // Validate groups if provided
        if let Some(groups) = params.get_optional_string_array("groups") {
            for group in &groups {
                // Basic group name validation (similar to username rules)
                if group.is_empty() || group.len() > 32 {
                    return Err(DaemonError::Validation {
                        kind: crate::error::ValidationErrorKind::InvalidParameter {
                            param: "groups".to_string(),
                            message: format!("Invalid group name '{}': must be 1-32 characters", group),
                        },
                    });
                }
                // Only alphanumeric, underscore, hyphen
                if !group.chars().all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-') {
                    return Err(DaemonError::Validation {
                        kind: crate::error::ValidationErrorKind::InvalidParameter {
                            param: "groups".to_string(),
                            message: format!("Invalid group name '{}': contains invalid characters", group),
                        },
                    });
                }
            }
        }

        Ok(())
    }

    fn execute(
        &self,
        ctx: &ExecutionContext,
        params: CommandParams,
    ) -> Result<CommandResult, DaemonError> {
        let username = params.get_string("username")?;
        let shell = params
            .get_optional_string("shell")
            .unwrap_or_else(|| "/bin/bash".to_string());
        let home_dir = params
            .get_optional_string("home_dir")
            .unwrap_or_else(|| format!("/home/{}", username));
        let groups = params.get_optional_string_array("groups");

        debug!(
            request_id = %ctx.request_id,
            username = %username,
            shell = %shell,
            home_dir = %home_dir,
            "Creating user"
        );

        // Build useradd arguments
        let mut args = vec![
            "--create-home".to_string(),
            "--home-dir".to_string(),
            home_dir.clone(),
            "--shell".to_string(),
            shell.clone(),
        ];

        // Add groups if specified
        if let Some(ref group_list) = groups {
            if !group_list.is_empty() {
                args.push("--groups".to_string());
                args.push(group_list.join(","));
            }
        }

        // Username must be last
        args.push(username.clone());

        // Execute useradd
        let output = ProcessCommand::new("useradd")
            .args(&args)
            .output()
            .map_err(|e| DaemonError::Command {
                kind: CommandErrorKind::ExecutionFailed {
                    message: format!("Failed to execute useradd: {}", e),
                },
            })?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            let exit_code = output.status.code().unwrap_or(-1);

            warn!(
                request_id = %ctx.request_id,
                username = %username,
                exit_code = exit_code,
                stderr = %stderr,
                "Failed to create user"
            );

            // Parse common useradd exit codes
            let error_message = match exit_code {
                1 => format!("Cannot update password file for user '{}'", username),
                2 => format!("Invalid command syntax for useradd"),
                3 => format!("Invalid argument for useradd option"),
                4 => format!("UID already in use"),
                6 => format!("Group does not exist: {}", stderr.trim()),
                9 => format!("Username '{}' already exists", username),
                12 => format!("Cannot create home directory '{}'", home_dir),
                _ => format!("useradd failed (exit {}): {}", exit_code, stderr.trim()),
            };

            return Err(DaemonError::Command {
                kind: CommandErrorKind::ExecutionFailed {
                    message: error_message,
                },
            });
        }

        info!(
            request_id = %ctx.request_id,
            username = %username,
            home_dir = %home_dir,
            shell = %shell,
            "User created successfully"
        );

        Ok(CommandResult::success(serde_json::json!({
            "username": username,
            "home_dir": home_dir,
            "shell": shell,
            "groups": groups.unwrap_or_default(),
        })))
    }

    fn timeout(&self) -> Duration {
        Duration::from_secs(30)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_command_name() {
        let cmd = CreateUserCommand;
        assert_eq!(cmd.name(), "user.create");
    }

    #[test]
    fn test_validate_valid_username() {
        let cmd = CreateUserCommand;
        let params = CommandParams::new(serde_json::json!({
            "username": "testuser"
        }));
        assert!(cmd.validate(&params).is_ok());
    }

    #[test]
    fn test_validate_with_all_options() {
        let cmd = CreateUserCommand;
        let params = CommandParams::new(serde_json::json!({
            "username": "testuser",
            "home_dir": "/home/testuser",
            "shell": "/bin/bash",
            "groups": ["www-data", "docker"]
        }));
        assert!(cmd.validate(&params).is_ok());
    }

    #[test]
    fn test_validate_invalid_username() {
        let cmd = CreateUserCommand;
        let params = CommandParams::new(serde_json::json!({
            "username": "root"
        }));
        assert!(cmd.validate(&params).is_err());
    }

    #[test]
    fn test_validate_invalid_shell() {
        let cmd = CreateUserCommand;
        let params = CommandParams::new(serde_json::json!({
            "username": "testuser",
            "shell": "/bin/malicious"
        }));
        assert!(cmd.validate(&params).is_err());
    }

    #[test]
    fn test_validate_invalid_home_dir() {
        let cmd = CreateUserCommand;
        let params = CommandParams::new(serde_json::json!({
            "username": "testuser",
            "home_dir": "/etc/malicious"
        }));
        assert!(cmd.validate(&params).is_err());
    }

    #[test]
    fn test_validate_relative_home_dir() {
        let cmd = CreateUserCommand;
        let params = CommandParams::new(serde_json::json!({
            "username": "testuser",
            "home_dir": "home/testuser"
        }));
        assert!(cmd.validate(&params).is_err());
    }

    #[test]
    fn test_validate_nologin_shell() {
        let cmd = CreateUserCommand;
        let params = CommandParams::new(serde_json::json!({
            "username": "serviceuser",
            "shell": "/usr/sbin/nologin"
        }));
        assert!(cmd.validate(&params).is_ok());
    }

    #[test]
    fn test_timeout() {
        let cmd = CreateUserCommand;
        assert_eq!(cmd.timeout(), Duration::from_secs(30));
    }
}
