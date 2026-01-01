//! Audit logging module.
//!
//! Provides structured audit logging for all daemon operations.
//! Logs are written in JSON lines format for easy parsing by log analysis tools.
//!
//! ## Features
//!
//! - Structured JSON log entries with request details
//! - Automatic parameter sanitization (redacting sensitive keys)
//! - Truncation of large content fields
//! - Thread-safe file writing with sync for durability

mod entry;
mod logger;
mod sanitize;

pub use entry::{AuditEntry, AuditResult};
pub use logger::{AuditLogger, NullAuditLogger};
pub use sanitize::sanitize_params;
