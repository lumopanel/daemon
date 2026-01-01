//! Nginx service definition.

use super::traits::ServiceDefinition;

/// Nginx web server service.
pub struct NginxService;

impl ServiceDefinition for NginxService {
    fn name(&self) -> &'static str {
        "nginx"
    }

    fn display_name(&self) -> &'static str {
        "Nginx Web Server"
    }

    fn systemd_units(&self) -> Vec<&'static str> {
        vec!["nginx"]
    }

    fn config_paths(&self) -> Vec<&'static str> {
        vec![
            "/etc/nginx/nginx.conf",
            "/etc/nginx/sites-available",
            "/etc/nginx/sites-enabled",
            "/etc/nginx/conf.d",
        ]
    }

    fn config_template(&self) -> Option<&'static str> {
        Some("nginx/site.conf.tera")
    }

    fn default_config(&self) -> serde_json::Value {
        serde_json::json!({
            "worker_processes": "auto",
            "worker_connections": 1024,
            "keepalive_timeout": 65,
            "client_max_body_size": "64m",
            "gzip": true,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_nginx_service() {
        let service = NginxService;
        assert_eq!(service.name(), "nginx");
        assert_eq!(service.display_name(), "Nginx Web Server");
        assert_eq!(service.systemd_units(), vec!["nginx"]);
        assert!(service.config_template().is_some());
    }
}
