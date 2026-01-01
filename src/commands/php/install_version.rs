//! Install PHP version command.

use std::time::Duration;

use tracing::{debug, info};

use crate::error::DaemonError;
use crate::executor::{run_command, SubprocessResult};
use crate::validation::whitelist::is_additional_php_version;

use super::super::traits::Command;
use super::super::types::{CommandParams, CommandResult, ExecutionContext};

/// Timeout for apt-get operations.
const APT_TIMEOUT: Duration = Duration::from_secs(600);

/// Allowed PHP versions.
const ALLOWED_PHP_VERSIONS: &[&str] = &["8.1", "8.2", "8.3", "8.4"];

/// Install a PHP version with FPM.
///
/// # Parameters
///
/// - `version` (required): The PHP version (8.1, 8.2, 8.3, or 8.4)
pub struct InstallPhpVersionCommand;

impl Command for InstallPhpVersionCommand {
    fn name(&self) -> &'static str {
        "php.install_version"
    }

    fn validate(&self, params: &CommandParams) -> Result<(), DaemonError> {
        params.require_string("version")?;
        let version = params.get_string("version")?;
        validate_php_version(&version)?;
        Ok(())
    }

    fn execute(
        &self,
        ctx: &ExecutionContext,
        params: CommandParams,
    ) -> Result<CommandResult, DaemonError> {
        let version = params.get_string("version")?;

        // Re-validate for safety
        validate_php_version(&version)?;

        debug!(
            request_id = %ctx.request_id,
            version = version,
            "Installing PHP version"
        );

        // Update package lists first
        let update_result = run_command("apt-get", &["update"], APT_TIMEOUT)?;
        if !update_result.success {
            return Ok(CommandResult::failure(
                "APT_UPDATE_FAILED",
                format!("Failed to update package lists: {}", update_result.stderr.trim()),
            ));
        }

        // Install PHP-FPM and common modules
        let packages = vec![
            format!("php{}-fpm", version),
            format!("php{}-cli", version),
            format!("php{}-common", version),
        ];

        let result = install_packages(&packages)?;

        if result.success {
            info!(
                request_id = %ctx.request_id,
                version = version,
                "PHP version installed successfully"
            );

            Ok(CommandResult::success(serde_json::json!({
                "version": version,
                "packages": packages,
                "installed": true,
            })))
        } else {
            Ok(CommandResult::failure(
                "PHP_INSTALL_FAILED",
                format!("Failed to install PHP {}: {}", version, result.stderr.trim()),
            ))
        }
    }
}

/// Validate a PHP version string.
pub fn validate_php_version(version: &str) -> Result<(), DaemonError> {
    // Check built-in allowed versions
    if ALLOWED_PHP_VERSIONS.contains(&version) {
        return Ok(());
    }

    // Check additional versions from configuration
    if is_additional_php_version(version) {
        return Ok(());
    }

    Err(DaemonError::Validation {
        kind: crate::error::ValidationErrorKind::InvalidParameter {
            param: "version".to_string(),
            message: format!(
                "Invalid PHP version '{}'. Allowed versions: {}",
                version,
                ALLOWED_PHP_VERSIONS.join(", ")
            ),
        },
    })
}

/// Install packages using apt-get.
fn install_packages(packages: &[String]) -> Result<SubprocessResult, DaemonError> {
    let mut args = vec![
        "install",
        "-y",
        "--no-install-recommends",
    ];

    let package_refs: Vec<&str> = packages.iter().map(|s| s.as_str()).collect();
    args.extend(package_refs);

    run_command("apt-get", &args, APT_TIMEOUT)
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
            "php.install_version".to_string(),
        )
    }

    #[test]
    fn test_command_name() {
        let cmd = InstallPhpVersionCommand;
        assert_eq!(cmd.name(), "php.install_version");
    }

    #[test]
    fn test_validate_valid_versions() {
        assert!(validate_php_version("8.1").is_ok());
        assert!(validate_php_version("8.2").is_ok());
        assert!(validate_php_version("8.3").is_ok());
        assert!(validate_php_version("8.4").is_ok());
    }

    #[test]
    fn test_validate_invalid_versions() {
        assert!(validate_php_version("7.4").is_err());
        assert!(validate_php_version("8.0").is_err());
        assert!(validate_php_version("9.0").is_err());
        assert!(validate_php_version("invalid").is_err());
    }

    #[test]
    fn test_validate_missing_version() {
        let cmd = InstallPhpVersionCommand;
        let params = CommandParams::new(serde_json::json!({}));
        assert!(cmd.validate(&params).is_err());
    }
}
