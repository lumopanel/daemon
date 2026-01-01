//! PostgreSQL service definition.

use super::traits::ServiceDefinition;

/// PostgreSQL database service.
pub struct PostgresqlService;

impl ServiceDefinition for PostgresqlService {
    fn name(&self) -> &'static str {
        "postgresql"
    }

    fn display_name(&self) -> &'static str {
        "PostgreSQL"
    }

    fn systemd_units(&self) -> Vec<&'static str> {
        vec!["postgresql"]
    }

    fn config_paths(&self) -> Vec<&'static str> {
        vec![
            "/etc/postgresql/16/main/postgresql.conf",
            "/etc/postgresql/15/main/postgresql.conf",
            "/etc/postgresql/14/main/postgresql.conf",
        ]
    }

    fn default_config(&self) -> serde_json::Value {
        serde_json::json!({
            "port": 5432,
            "listen_addresses": "localhost",
            "max_connections": 100,
            "shared_buffers": "128MB",
            "effective_cache_size": "256MB",
            "work_mem": "4MB",
            "maintenance_work_mem": "64MB",
            "log_destination": "stderr",
            "logging_collector": true,
            "log_directory": "log",
            "log_filename": "postgresql-%Y-%m-%d.log"
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_postgresql_service() {
        let service = PostgresqlService;
        assert_eq!(service.name(), "postgresql");
        assert_eq!(service.display_name(), "PostgreSQL");
        assert_eq!(service.systemd_units(), vec!["postgresql"]);
    }

    #[test]
    fn test_postgresql_config_paths() {
        let service = PostgresqlService;
        let paths = service.config_paths();
        assert!(paths.contains(&"/etc/postgresql/16/main/postgresql.conf"));
        assert!(paths.contains(&"/etc/postgresql/15/main/postgresql.conf"));
        assert!(paths.contains(&"/etc/postgresql/14/main/postgresql.conf"));
    }

    #[test]
    fn test_postgresql_default_config() {
        let service = PostgresqlService;
        let config = service.default_config();
        assert_eq!(config["port"], 5432);
        assert_eq!(config["listen_addresses"], "localhost");
        assert_eq!(config["max_connections"], 100);
    }
}
