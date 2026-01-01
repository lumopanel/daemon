//! PHP-FPM service definition.

use super::traits::ServiceDefinition;

/// PHP-FPM service.
///
/// Supports multiple PHP versions.
pub struct PhpFpmService;

impl PhpFpmService {
    /// Create a new PHP-FPM service.
    ///
    /// # Arguments
    ///
    /// * `_version` - PHP version (reserved for future use)
    pub fn new(_version: &str) -> Self {
        Self
    }
}

impl ServiceDefinition for PhpFpmService {
    fn name(&self) -> &'static str {
        "php-fpm"
    }

    fn display_name(&self) -> &'static str {
        "PHP-FPM"
    }

    fn systemd_units(&self) -> Vec<&'static str> {
        // We can't return a reference to the dynamic unit_name,
        // so we return common PHP-FPM unit patterns
        vec![
            "php8.1-fpm",
            "php8.2-fpm",
            "php8.3-fpm",
            "php8.4-fpm",
        ]
    }

    fn config_paths(&self) -> Vec<&'static str> {
        vec![
            "/etc/php/8.1/fpm/pool.d",
            "/etc/php/8.2/fpm/pool.d",
            "/etc/php/8.3/fpm/pool.d",
            "/etc/php/8.4/fpm/pool.d",
        ]
    }

    fn config_template(&self) -> Option<&'static str> {
        Some("php-fpm/pool.conf.tera")
    }

    fn default_config(&self) -> serde_json::Value {
        serde_json::json!({
            "pm_type": "dynamic",
            "pm_max_children": 5,
            "pm_start_servers": 2,
            "pm_min_spare_servers": 1,
            "pm_max_spare_servers": 3,
            "pm_max_requests": 500,
            "request_timeout": 300,
            "memory_limit": "256M",
            "upload_max_filesize": "64M",
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_php_fpm_service() {
        let service = PhpFpmService::new("8.3");
        assert_eq!(service.name(), "php-fpm");
        assert_eq!(service.display_name(), "PHP-FPM");
        assert!(!service.systemd_units().is_empty());
        assert!(service.config_template().is_some());
    }

    #[test]
    fn test_php_fpm_versions() {
        let service83 = PhpFpmService::new("8.3");
        let service82 = PhpFpmService::new("8.2");

        // Both should have the same name for registry purposes
        assert_eq!(service83.name(), service82.name());
    }
}
