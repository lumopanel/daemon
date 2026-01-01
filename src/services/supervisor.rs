//! Supervisor service definition.

use super::traits::ServiceDefinition;

/// Supervisor process manager service.
pub struct SupervisorService;

impl ServiceDefinition for SupervisorService {
    fn name(&self) -> &'static str {
        "supervisor"
    }

    fn display_name(&self) -> &'static str {
        "Supervisor"
    }

    fn systemd_units(&self) -> Vec<&'static str> {
        vec!["supervisor"]
    }

    fn config_paths(&self) -> Vec<&'static str> {
        vec![
            "/etc/supervisor/supervisord.conf",
            "/etc/supervisor/conf.d",
        ]
    }

    fn config_template(&self) -> Option<&'static str> {
        Some("services/supervisor.conf.tera")
    }

    fn default_config(&self) -> serde_json::Value {
        serde_json::json!({
            "socket_path": "/var/run/supervisor.sock",
            "socket_mode": "0700",
            "log_path": "/var/log/supervisor/supervisord.log",
            "log_level": "info",
            "pidfile": "/var/run/supervisord.pid",
            "child_logdir": "/var/log/supervisor",
            "user": "root",
            "minfds": 1024,
            "minprocs": 200
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_supervisor_service() {
        let service = SupervisorService;
        assert_eq!(service.name(), "supervisor");
        assert_eq!(service.display_name(), "Supervisor");
        assert_eq!(service.systemd_units(), vec!["supervisor"]);
    }

    #[test]
    fn test_supervisor_config_paths() {
        let service = SupervisorService;
        let paths = service.config_paths();
        assert!(paths.contains(&"/etc/supervisor/supervisord.conf"));
        assert!(paths.contains(&"/etc/supervisor/conf.d"));
    }

    #[test]
    fn test_supervisor_has_template() {
        let service = SupervisorService;
        assert!(service.config_template().is_some());
        assert_eq!(
            service.config_template().unwrap(),
            "services/supervisor.conf.tera"
        );
    }

    #[test]
    fn test_supervisor_default_config() {
        let service = SupervisorService;
        let config = service.default_config();
        assert_eq!(config["socket_path"], "/var/run/supervisor.sock");
        assert_eq!(config["log_level"], "info");
    }
}
