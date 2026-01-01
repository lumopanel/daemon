//! Memcached service definition.

use super::traits::ServiceDefinition;

/// Memcached cache service.
pub struct MemcachedService;

impl ServiceDefinition for MemcachedService {
    fn name(&self) -> &'static str {
        "memcached"
    }

    fn display_name(&self) -> &'static str {
        "Memcached"
    }

    fn systemd_units(&self) -> Vec<&'static str> {
        vec!["memcached"]
    }

    fn config_paths(&self) -> Vec<&'static str> {
        vec!["/etc/memcached.conf"]
    }

    fn default_config(&self) -> serde_json::Value {
        serde_json::json!({
            "port": 11211,
            "listen_address": "127.0.0.1",
            "memory_limit": 64,
            "max_connections": 1024,
            "user": "memcache"
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_memcached_service() {
        let service = MemcachedService;
        assert_eq!(service.name(), "memcached");
        assert_eq!(service.display_name(), "Memcached");
        assert_eq!(service.systemd_units(), vec!["memcached"]);
        assert_eq!(service.config_paths(), vec!["/etc/memcached.conf"]);
    }

    #[test]
    fn test_memcached_default_config() {
        let service = MemcachedService;
        let config = service.default_config();
        assert_eq!(config["port"], 11211);
        assert_eq!(config["listen_address"], "127.0.0.1");
        assert_eq!(config["memory_limit"], 64);
    }
}
