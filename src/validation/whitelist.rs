//! Global whitelist configuration for validation.
//!
//! Provides access to configurable whitelists that extend the built-in defaults.

use std::collections::HashSet;
use std::sync::OnceLock;

use crate::config::WhitelistsConfig;

/// Global whitelist configuration storage.
static WHITELISTS: OnceLock<RuntimeWhitelists> = OnceLock::new();

/// Runtime whitelists derived from configuration.
#[derive(Debug, Clone, Default)]
pub struct RuntimeWhitelists {
    pub additional_services: HashSet<String>,
    pub additional_packages: HashSet<String>,
    pub additional_php_versions: HashSet<String>,
    pub additional_php_extensions: HashSet<String>,
    pub additional_repositories: HashSet<String>,
    pub additional_path_prefixes: Vec<String>,
}

impl RuntimeWhitelists {
    /// Create runtime whitelists from configuration.
    ///
    /// Path prefixes are normalized to ensure they end with '/' to prevent
    /// prefix matching bypasses (e.g., /home/user matching /home/userevil).
    pub fn from_config(config: &WhitelistsConfig) -> Self {
        // Normalize path prefixes to ensure they end with '/'
        let normalized_prefixes: Vec<String> = config
            .additional_path_prefixes
            .iter()
            .map(|p| {
                if p.ends_with('/') {
                    p.clone()
                } else {
                    format!("{}/", p)
                }
            })
            .collect();

        Self {
            additional_services: config.additional_services.iter().cloned().collect(),
            additional_packages: config.additional_packages.iter().cloned().collect(),
            additional_php_versions: config.additional_php_versions.iter().cloned().collect(),
            additional_php_extensions: config.additional_php_extensions.iter().cloned().collect(),
            additional_repositories: config.additional_repositories.iter().cloned().collect(),
            additional_path_prefixes: normalized_prefixes,
        }
    }
}

/// Initialize the global whitelists from configuration.
///
/// This should be called once at daemon startup.
/// Subsequent calls are ignored (first initialization wins).
pub fn init_whitelists(config: &WhitelistsConfig) {
    let _ = WHITELISTS.set(RuntimeWhitelists::from_config(config));
}

/// Get the current whitelists.
///
/// Returns an empty whitelist if not initialized.
pub fn get_whitelists() -> &'static RuntimeWhitelists {
    WHITELISTS.get_or_init(RuntimeWhitelists::default)
}

/// Check if a service is in the additional whitelist.
pub fn is_additional_service(name: &str) -> bool {
    get_whitelists().additional_services.contains(name)
}

/// Check if a package is in the additional whitelist.
pub fn is_additional_package(name: &str) -> bool {
    get_whitelists().additional_packages.contains(name)
}

/// Check if a PHP version is in the additional whitelist.
pub fn is_additional_php_version(version: &str) -> bool {
    get_whitelists().additional_php_versions.contains(version)
}

/// Check if a PHP extension is in the additional whitelist.
pub fn is_additional_php_extension(ext: &str) -> bool {
    get_whitelists().additional_php_extensions.contains(ext)
}

/// Check if a repository is in the additional whitelist.
pub fn is_additional_repository(repo: &str) -> bool {
    get_whitelists().additional_repositories.contains(repo)
}

/// Get additional path prefixes.
pub fn get_additional_path_prefixes() -> &'static [String] {
    &get_whitelists().additional_path_prefixes
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_whitelists_empty() {
        // Fresh whitelists should be empty
        let wl = RuntimeWhitelists::default();
        assert!(wl.additional_services.is_empty());
        assert!(wl.additional_packages.is_empty());
    }

    #[test]
    fn test_from_config() {
        let config = WhitelistsConfig {
            additional_services: vec!["custom-service".to_string()],
            additional_packages: vec!["custom-package".to_string()],
            additional_php_versions: vec!["8.5".to_string()],
            additional_php_extensions: vec!["custom-ext".to_string()],
            additional_repositories: vec!["ppa:custom/repo".to_string()],
            additional_path_prefixes: vec!["/custom/path/".to_string()],
        };

        let wl = RuntimeWhitelists::from_config(&config);
        assert!(wl.additional_services.contains("custom-service"));
        assert!(wl.additional_packages.contains("custom-package"));
        assert!(wl.additional_php_versions.contains("8.5"));
        assert!(wl.additional_php_extensions.contains("custom-ext"));
        assert!(wl.additional_repositories.contains("ppa:custom/repo"));
        assert!(wl.additional_path_prefixes.contains(&"/custom/path/".to_string()));
    }
}
