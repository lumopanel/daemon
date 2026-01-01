//! Service definitions module.
//!
//! Contains service definitions and the service registry.
//!
//! ## Adding a New Service
//!
//! 1. Create a new file in this directory (e.g., `newservice.rs`)
//! 2. Implement the `ServiceDefinition` trait
//! 3. Register the service in `ServiceRegistry::new()`

mod memcached;
mod mysql;
mod nginx;
mod php_fpm;
mod postgresql;
mod redis;
mod registry;
mod supervisor;
mod traits;

pub use memcached::MemcachedService;
pub use mysql::MysqlService;
pub use nginx::NginxService;
pub use php_fpm::PhpFpmService;
pub use postgresql::PostgresqlService;
pub use redis::RedisService;
pub use registry::ServiceRegistry;
pub use supervisor::SupervisorService;
pub use traits::ServiceDefinition;
