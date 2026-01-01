//! Service definition traits.
//!
//! Defines the interface for manageable services.

/// Defines a manageable service.
///
/// This trait provides metadata about a service that can be controlled
/// by the daemon. Services implement this trait to describe their
/// systemd units, configuration paths, and templates.
///
/// # Example
///
/// ```ignore
/// pub struct NginxService;
///
/// impl ServiceDefinition for NginxService {
///     fn name(&self) -> &'static str { "nginx" }
///     fn display_name(&self) -> &'static str { "Nginx Web Server" }
///     fn systemd_units(&self) -> Vec<&'static str> { vec!["nginx"] }
///     fn config_paths(&self) -> Vec<&'static str> { vec!["/etc/nginx/nginx.conf"] }
///     fn config_template(&self) -> Option<&'static str> { Some("nginx/site.conf.tera") }
/// }
/// ```
pub trait ServiceDefinition: Send + Sync {
    /// Service identifier (e.g., "redis", "nginx").
    ///
    /// This should be unique across all registered services.
    fn name(&self) -> &'static str;

    /// Human-readable display name (e.g., "Redis", "Nginx Web Server").
    fn display_name(&self) -> &'static str;

    /// Systemd service unit name(s).
    ///
    /// Returns the unit names used with systemctl commands.
    /// Most services have a single unit, but some (like PHP-FPM with
    /// multiple versions) may have multiple.
    fn systemd_units(&self) -> Vec<&'static str>;

    /// Configuration file paths managed by this service.
    ///
    /// These are the main configuration files that the daemon can
    /// modify for this service.
    fn config_paths(&self) -> Vec<&'static str>;

    /// Template name for generating primary config.
    ///
    /// If the service has a Tera template for configuration,
    /// return its path relative to the templates directory.
    fn config_template(&self) -> Option<&'static str> {
        None
    }

    /// Default configuration values.
    ///
    /// Returns a JSON object with default values that can be used
    /// when rendering the config template.
    fn default_config(&self) -> serde_json::Value {
        serde_json::json!({})
    }
}
