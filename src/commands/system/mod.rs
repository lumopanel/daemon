//! System commands module.
//!
//! Contains system-level commands like ping for health checking and metrics for monitoring.

mod metrics;
mod ping;

pub use metrics::MetricsCommand;
pub use ping::PingCommand;
