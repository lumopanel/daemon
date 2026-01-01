//! Redis service definition.

use super::traits::ServiceDefinition;

/// Redis cache service.
pub struct RedisService;

impl ServiceDefinition for RedisService {
    fn name(&self) -> &'static str {
        "redis"
    }

    fn display_name(&self) -> &'static str {
        "Redis"
    }

    fn systemd_units(&self) -> Vec<&'static str> {
        vec!["redis-server"]
    }

    fn config_paths(&self) -> Vec<&'static str> {
        vec!["/etc/redis/redis.conf"]
    }

    fn config_template(&self) -> Option<&'static str> {
        Some("services/redis.conf.tera")
    }

    fn default_config(&self) -> serde_json::Value {
        serde_json::json!({
            "bind_address": "127.0.0.1",
            "port": 6379,
            "max_memory": "256mb",
            "eviction_policy": "allkeys-lru",
            "persistence_enabled": true,
            "aof_enabled": false,
            "databases": 16,
            "log_level": "notice",
            "max_clients": 10000,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_redis_service() {
        let service = RedisService;
        assert_eq!(service.name(), "redis");
        assert_eq!(service.display_name(), "Redis");
        assert_eq!(service.systemd_units(), vec!["redis-server"]);
        assert!(service.config_template().is_some());
    }

    #[test]
    fn test_redis_default_config() {
        let service = RedisService;
        let config = service.default_config();
        assert_eq!(config["port"], 6379);
        assert_eq!(config["bind_address"], "127.0.0.1");
    }
}
