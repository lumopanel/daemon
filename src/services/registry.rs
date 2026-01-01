//! Service registry.
//!
//! Central registry for all service definitions.

use std::collections::HashMap;
use std::sync::Arc;

use tracing::info;

use super::memcached::MemcachedService;
use super::mysql::MysqlService;
use super::nginx::NginxService;
use super::php_fpm::PhpFpmService;
use super::postgresql::PostgresqlService;
use super::redis::RedisService;
use super::supervisor::SupervisorService;
use super::traits::ServiceDefinition;

/// Registry of all available service definitions.
pub struct ServiceRegistry {
    services: HashMap<&'static str, Arc<dyn ServiceDefinition>>,
}

impl ServiceRegistry {
    /// Create a new service registry with all built-in services.
    pub fn new() -> Self {
        let mut registry = Self {
            services: HashMap::new(),
        };

        // Register built-in services
        registry.register(Arc::new(NginxService));
        registry.register(Arc::new(PhpFpmService::new("8.3"))); // Default PHP version
        registry.register(Arc::new(RedisService));
        registry.register(Arc::new(MemcachedService));
        registry.register(Arc::new(MysqlService));
        registry.register(Arc::new(PostgresqlService));
        registry.register(Arc::new(SupervisorService));

        info!(
            count = registry.services.len(),
            "Service registry initialized"
        );

        registry
    }

    /// Register a service definition.
    fn register(&mut self, service: Arc<dyn ServiceDefinition>) {
        let name = service.name();
        self.services.insert(name, service);
    }

    /// Get a service definition by name.
    pub fn get(&self, name: &str) -> Option<Arc<dyn ServiceDefinition>> {
        self.services.get(name).cloned()
    }

    /// List all registered service names.
    pub fn list(&self) -> Vec<&'static str> {
        self.services.keys().copied().collect()
    }

    /// Get the count of registered services.
    pub fn count(&self) -> usize {
        self.services.len()
    }
}

impl Default for ServiceRegistry {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_registry_has_services() {
        let registry = ServiceRegistry::new();
        assert!(registry.count() >= 7);
        assert!(registry.get("nginx").is_some());
        assert!(registry.get("redis").is_some());
        assert!(registry.get("php-fpm").is_some());
        assert!(registry.get("memcached").is_some());
        assert!(registry.get("mysql").is_some());
        assert!(registry.get("postgresql").is_some());
        assert!(registry.get("supervisor").is_some());
    }

    #[test]
    fn test_registry_unknown_service() {
        let registry = ServiceRegistry::new();
        assert!(registry.get("unknown-service").is_none());
    }

    #[test]
    fn test_list_services() {
        let registry = ServiceRegistry::new();
        let services = registry.list();
        assert!(services.contains(&"nginx"));
        assert!(services.contains(&"redis"));
    }
}
