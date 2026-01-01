//! Metrics command for monitoring daemon health.

use std::sync::Arc;
use std::time::{Duration, Instant};

use crate::auth::NonceStore;
use crate::error::DaemonError;
use crate::socket::ConnectionMetrics;

use super::super::traits::Command;
use super::super::types::{CommandParams, CommandResult, ExecutionContext};

const VERSION: &str = env!("CARGO_PKG_VERSION");

/// Metrics command that returns daemon health statistics.
///
/// Returns:
/// - uptime_seconds: How long the daemon has been running
/// - requests_total: Total number of requests processed
/// - requests_failed: Number of failed requests
/// - active_connections: Currently active connections
/// - nonce_store_size: Number of stored nonces (for replay protection)
/// - version: Daemon version
pub struct MetricsCommand {
    start_time: Instant,
    metrics: Arc<ConnectionMetrics>,
    nonce_store: Arc<NonceStore>,
}

impl MetricsCommand {
    /// Create a new metrics command.
    pub fn new(metrics: Arc<ConnectionMetrics>, nonce_store: Arc<NonceStore>) -> Self {
        Self {
            start_time: Instant::now(),
            metrics,
            nonce_store,
        }
    }

    /// Get the daemon uptime.
    pub fn uptime(&self) -> Duration {
        self.start_time.elapsed()
    }
}

impl Command for MetricsCommand {
    fn name(&self) -> &'static str {
        "system.metrics"
    }

    fn validate(&self, _params: &CommandParams) -> Result<(), DaemonError> {
        // Metrics has no required parameters
        Ok(())
    }

    fn execute(
        &self,
        _ctx: &ExecutionContext,
        _params: CommandParams,
    ) -> Result<CommandResult, DaemonError> {
        let uptime = self.uptime();

        Ok(CommandResult::success(serde_json::json!({
            "uptime_seconds": uptime.as_secs(),
            "requests_total": self.metrics.total_requests(),
            "requests_failed": self.metrics.failed_requests(),
            "active_connections": self.metrics.active(),
            "nonce_store_size": self.nonce_store.len(),
            "version": VERSION,
        })))
    }

    fn requires_audit(&self) -> bool {
        // Metrics is a monitoring endpoint, skip audit logging
        false
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::auth::PeerInfo;
    use uuid::Uuid;

    fn create_test_context() -> ExecutionContext {
        ExecutionContext::new(
            Uuid::new_v4(),
            PeerInfo {
                uid: 1000,
                gid: 1000,
                pid: 12345,
            },
            1234567890,
            "system.metrics".to_string(),
        )
    }

    #[test]
    fn test_metrics_name() {
        let metrics = Arc::new(ConnectionMetrics::new());
        let nonce_store = Arc::new(NonceStore::new(Duration::from_secs(60)));
        let cmd = MetricsCommand::new(metrics, nonce_store);
        assert_eq!(cmd.name(), "system.metrics");
    }

    #[test]
    fn test_metrics_validate() {
        let metrics = Arc::new(ConnectionMetrics::new());
        let nonce_store = Arc::new(NonceStore::new(Duration::from_secs(60)));
        let cmd = MetricsCommand::new(metrics, nonce_store);
        let params = CommandParams::new(serde_json::json!({}));
        assert!(cmd.validate(&params).is_ok());
    }

    #[test]
    fn test_metrics_execute() {
        let metrics = Arc::new(ConnectionMetrics::new());
        let nonce_store = Arc::new(NonceStore::new(Duration::from_secs(60)));
        let cmd = MetricsCommand::new(metrics, nonce_store);
        let ctx = create_test_context();
        let params = CommandParams::new(serde_json::json!({}));

        let result = cmd.execute(&ctx, params).unwrap();
        assert!(result.success);

        let data = result.data.unwrap();
        assert!(data["uptime_seconds"].is_u64());
        assert_eq!(data["requests_total"], 0);
        assert_eq!(data["requests_failed"], 0);
        assert_eq!(data["active_connections"], 0);
        assert!(data["version"].is_string());
    }

    #[test]
    fn test_metrics_tracks_requests() {
        let metrics = Arc::new(ConnectionMetrics::new());
        let nonce_store = Arc::new(NonceStore::new(Duration::from_secs(60)));

        // Simulate some requests
        metrics.record_request(true);
        metrics.record_request(true);
        metrics.record_request(false);

        let cmd = MetricsCommand::new(Arc::clone(&metrics), nonce_store);
        let ctx = create_test_context();
        let params = CommandParams::new(serde_json::json!({}));

        let result = cmd.execute(&ctx, params).unwrap();
        let data = result.data.unwrap();

        assert_eq!(data["requests_total"], 3);
        assert_eq!(data["requests_failed"], 1);
    }

    #[test]
    fn test_requires_no_audit() {
        let metrics = Arc::new(ConnectionMetrics::new());
        let nonce_store = Arc::new(NonceStore::new(Duration::from_secs(60)));
        let cmd = MetricsCommand::new(metrics, nonce_store);
        assert!(!cmd.requires_audit());
    }
}
