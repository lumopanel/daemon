//! Input validation module.
//!
//! Provides validators for paths, usernames, domains, service names, packages, repositories,
//! and template context values.

mod database;
mod domain;
mod package_name;
mod path;
mod repository;
mod service_name;
mod template_context;
mod uid_gid;
mod username;
pub mod whitelist;

pub use database::{validate_database_name, validate_database_type, validate_database_username};
pub use domain::{validate_domain, validate_site_name};
pub use package_name::{is_package_allowed, validate_package_list, validate_package_name};
pub use path::{validate_directory_path, validate_path};
pub use repository::{is_repository_allowed, validate_repository};
pub use service_name::validate_service_name;
pub use template_context::{
    validate_custom_config_file, validate_document_root, validate_php_socket,
    validate_ssl_certificate, validate_ssl_certificate_key,
};
pub use uid_gid::{validate_gid, validate_uid};
pub use username::validate_system_username;
pub use whitelist::{get_whitelists, init_whitelists};
