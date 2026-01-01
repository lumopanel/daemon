//! MySQL service definition.

use super::traits::ServiceDefinition;

/// MySQL database service.
///
/// This covers both MySQL and MariaDB installations.
pub struct MysqlService;

impl ServiceDefinition for MysqlService {
    fn name(&self) -> &'static str {
        "mysql"
    }

    fn display_name(&self) -> &'static str {
        "MySQL"
    }

    fn systemd_units(&self) -> Vec<&'static str> {
        vec!["mysql"]
    }

    fn config_paths(&self) -> Vec<&'static str> {
        vec![
            "/etc/mysql/mysql.conf.d/mysqld.cnf",
            "/etc/mysql/mariadb.conf.d/50-server.cnf",
            "/etc/mysql/my.cnf",
        ]
    }

    fn default_config(&self) -> serde_json::Value {
        serde_json::json!({
            "port": 3306,
            "bind_address": "127.0.0.1",
            "max_connections": 151,
            "innodb_buffer_pool_size": "128M",
            "innodb_log_file_size": "48M",
            "innodb_flush_log_at_trx_commit": 1,
            "key_buffer_size": "16M",
            "table_open_cache": 2000,
            "sort_buffer_size": "256K",
            "read_buffer_size": "256K",
            "log_error": "/var/log/mysql/error.log",
            "slow_query_log": true,
            "slow_query_log_file": "/var/log/mysql/mysql-slow.log",
            "long_query_time": 2
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_mysql_service() {
        let service = MysqlService;
        assert_eq!(service.name(), "mysql");
        assert_eq!(service.display_name(), "MySQL");
        assert_eq!(service.systemd_units(), vec!["mysql"]);
    }

    #[test]
    fn test_mysql_config_paths() {
        let service = MysqlService;
        let paths = service.config_paths();
        assert!(paths.contains(&"/etc/mysql/mysql.conf.d/mysqld.cnf"));
        assert!(paths.contains(&"/etc/mysql/mariadb.conf.d/50-server.cnf"));
        assert!(paths.contains(&"/etc/mysql/my.cnf"));
    }

    #[test]
    fn test_mysql_default_config() {
        let service = MysqlService;
        let config = service.default_config();
        assert_eq!(config["port"], 3306);
        assert_eq!(config["bind_address"], "127.0.0.1");
        assert_eq!(config["max_connections"], 151);
    }
}
