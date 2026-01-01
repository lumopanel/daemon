//! Configuration settings for the Lumo daemon.

use serde::Deserialize;
use std::path::{Path, PathBuf};

use crate::error::DaemonError;

/// Main configuration structure for the daemon.
#[derive(Debug, Clone, Deserialize)]
pub struct Settings {
    pub socket: SocketConfig,
    pub security: SecurityConfig,
    pub redis: RedisConfig,
    pub paths: PathsConfig,
    pub logging: LoggingConfig,
    pub limits: LimitsConfig,
    #[serde(default)]
    pub audit: AuditConfig,
    #[serde(default)]
    pub whitelists: WhitelistsConfig,
}

/// Socket configuration.
#[derive(Debug, Clone, Deserialize)]
pub struct SocketConfig {
    /// Path to the Unix socket file.
    pub path: PathBuf,
    /// Socket file permissions (e.g., "0660").
    #[serde(default = "default_socket_permissions")]
    pub permissions: String,
    /// Socket file owner.
    #[serde(default = "default_owner")]
    pub owner: String,
    /// Socket file group.
    #[serde(default = "default_group")]
    pub group: String,
}

/// Security configuration.
#[derive(Debug, Clone, Deserialize)]
pub struct SecurityConfig {
    /// Path to the HMAC secret file.
    pub hmac_secret_path: PathBuf,
    /// Nonce time-to-live in seconds.
    #[serde(default = "default_nonce_ttl")]
    pub nonce_ttl_seconds: u64,
    /// Maximum age of requests in seconds.
    #[serde(default = "default_max_request_age")]
    pub max_request_age_seconds: u64,
    /// List of allowed peer UIDs.
    #[serde(default)]
    pub allowed_peer_uids: Vec<u32>,
    /// Maximum requests per UID per window.
    #[serde(default = "default_rate_limit_requests")]
    pub rate_limit_requests: usize,
    /// Rate limit window in seconds.
    #[serde(default = "default_rate_limit_window")]
    pub rate_limit_window_seconds: u64,
}

/// Redis configuration.
#[derive(Debug, Clone, Deserialize)]
pub struct RedisConfig {
    /// Redis connection URL.
    #[serde(default = "default_redis_url")]
    pub url: String,
    /// Connection pool size.
    #[serde(default = "default_pool_size")]
    pub pool_size: u32,
}

/// Paths configuration.
#[derive(Debug, Clone, Deserialize)]
pub struct PathsConfig {
    /// Directory containing built-in templates.
    #[serde(default = "default_templates_dir")]
    pub templates_dir: PathBuf,
    /// Directory containing custom templates.
    #[serde(default = "default_custom_templates_dir")]
    pub custom_templates_dir: PathBuf,
    /// Directory for log files.
    #[serde(default = "default_log_dir")]
    pub log_dir: PathBuf,
}

/// Logging configuration.
#[derive(Debug, Clone, Deserialize)]
pub struct LoggingConfig {
    /// Log level (trace, debug, info, warn, error).
    #[serde(default = "default_log_level")]
    pub level: String,
    /// Log format ("pretty" or "json").
    #[serde(default = "default_log_format")]
    pub format: String,
    /// Optional log file path.
    pub file: Option<PathBuf>,
}

/// Limits configuration.
#[derive(Debug, Clone, Deserialize)]
pub struct LimitsConfig {
    /// Maximum message size in bytes.
    #[serde(default = "default_max_message_size")]
    pub max_message_size: usize,
    /// Default command timeout in seconds.
    #[serde(default = "default_timeout")]
    pub default_timeout_seconds: u64,
    /// Maximum concurrent requests.
    #[serde(default = "default_max_concurrent")]
    pub max_concurrent_requests: usize,
    /// Socket read/write timeout in seconds.
    #[serde(default = "default_socket_timeout")]
    pub socket_timeout_seconds: u64,
}

/// Audit logging configuration.
#[derive(Debug, Clone, Deserialize)]
pub struct AuditConfig {
    /// Whether audit logging is enabled.
    #[serde(default = "default_audit_enabled")]
    pub enabled: bool,
    /// Path to the audit log file.
    #[serde(default = "default_audit_log_path")]
    pub log_path: PathBuf,
}

/// Configurable whitelists for extending default allowed values.
///
/// These lists are *additional* to the built-in defaults, not replacements.
/// This allows extending the allowed services, packages, etc. without
/// removing the secure defaults.
#[derive(Debug, Clone, Deserialize, Default)]
pub struct WhitelistsConfig {
    /// Additional allowed services (beyond built-in defaults).
    #[serde(default)]
    pub additional_services: Vec<String>,
    /// Additional allowed packages (beyond built-in defaults).
    #[serde(default)]
    pub additional_packages: Vec<String>,
    /// Additional allowed PHP versions (beyond 8.1-8.4).
    #[serde(default)]
    pub additional_php_versions: Vec<String>,
    /// Additional allowed PHP extensions (beyond built-in defaults).
    #[serde(default)]
    pub additional_php_extensions: Vec<String>,
    /// Additional allowed PPA repositories (beyond built-in defaults).
    #[serde(default)]
    pub additional_repositories: Vec<String>,
    /// Additional allowed path prefixes for file operations.
    #[serde(default)]
    pub additional_path_prefixes: Vec<String>,
}

// Default value functions
fn default_socket_permissions() -> String {
    "0660".to_string()
}

fn default_owner() -> String {
    "root".to_string()
}

fn default_group() -> String {
    "www-data".to_string()
}

fn default_nonce_ttl() -> u64 {
    300
}

fn default_max_request_age() -> u64 {
    60
}

fn default_redis_url() -> String {
    "redis://127.0.0.1:6379".to_string()
}

fn default_pool_size() -> u32 {
    4
}

fn default_templates_dir() -> PathBuf {
    PathBuf::from("/usr/share/lumo/templates")
}

fn default_custom_templates_dir() -> PathBuf {
    PathBuf::from("/etc/lumo/templates")
}

fn default_log_dir() -> PathBuf {
    PathBuf::from("/var/log/lumo")
}

fn default_log_level() -> String {
    "info".to_string()
}

fn default_log_format() -> String {
    "pretty".to_string()
}

fn default_max_message_size() -> usize {
    1_048_576 // 1MB
}

fn default_timeout() -> u64 {
    60
}

fn default_max_concurrent() -> usize {
    100
}

fn default_socket_timeout() -> u64 {
    30
}

fn default_rate_limit_requests() -> usize {
    100
}

fn default_rate_limit_window() -> u64 {
    60
}

fn default_audit_enabled() -> bool {
    true
}

fn default_audit_log_path() -> PathBuf {
    PathBuf::from("/var/log/lumo/audit.log")
}

impl Default for AuditConfig {
    fn default() -> Self {
        Self {
            enabled: default_audit_enabled(),
            log_path: default_audit_log_path(),
        }
    }
}

impl Settings {
    /// Load settings from a TOML configuration file.
    pub fn load<P: AsRef<Path>>(path: P) -> Result<Self, DaemonError> {
        let path = path.as_ref();
        let content = std::fs::read_to_string(path).map_err(|e| DaemonError::Config {
            message: format!("Failed to read config file '{}': {}", path.display(), e),
        })?;

        let settings: Settings = toml::from_str(&content).map_err(|e| DaemonError::Config {
            message: format!("Failed to parse config file '{}': {}", path.display(), e),
        })?;

        settings.validate()?;

        Ok(settings)
    }

    /// Validate the settings.
    fn validate(&self) -> Result<(), DaemonError> {
        // Validate log level
        let valid_levels = ["trace", "debug", "info", "warn", "error"];
        if !valid_levels.contains(&self.logging.level.to_lowercase().as_str()) {
            return Err(DaemonError::Config {
                message: format!(
                    "Invalid log level '{}'. Valid levels: {:?}",
                    self.logging.level, valid_levels
                ),
            });
        }

        // Validate log format
        let valid_formats = ["pretty", "json"];
        if !valid_formats.contains(&self.logging.format.to_lowercase().as_str()) {
            return Err(DaemonError::Config {
                message: format!(
                    "Invalid log format '{}'. Valid formats: {:?}",
                    self.logging.format, valid_formats
                ),
            });
        }

        // Validate socket permissions format
        if !self.socket.permissions.chars().all(|c| c.is_ascii_digit()) {
            return Err(DaemonError::Config {
                message: format!(
                    "Invalid socket permissions '{}'. Must be octal (e.g., '0660')",
                    self.socket.permissions
                ),
            });
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_values() {
        assert_eq!(default_socket_permissions(), "0660");
        assert_eq!(default_log_level(), "info");
        assert_eq!(default_log_format(), "pretty");
    }
}
