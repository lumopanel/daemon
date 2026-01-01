//! Unix socket listener.

use std::os::unix::fs::PermissionsExt;
use std::path::Path;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;

use tokio::net::UnixListener;
use tokio::sync::{Notify, Semaphore};
use tracing::{debug, error, info, warn};

use crate::audit::AuditLogger;
use crate::auth::{HmacValidator, NonceStore, RateLimiter};
use crate::commands::CommandRegistry;
use crate::config::Settings;
use crate::error::DaemonError;
use crate::templates::TemplateEngine;

use super::handle_connection;

/// Connection metrics for monitoring.
#[derive(Debug, Default)]
pub struct ConnectionMetrics {
    /// Total requests processed.
    pub requests_total: AtomicU64,
    /// Total failed requests.
    pub requests_failed: AtomicU64,
    /// Currently active connections.
    pub active_connections: AtomicUsize,
}

impl ConnectionMetrics {
    /// Create new connection metrics.
    pub fn new() -> Self {
        Self::default()
    }

    /// Increment request count.
    pub fn record_request(&self, success: bool) {
        self.requests_total.fetch_add(1, Ordering::Relaxed);
        if !success {
            self.requests_failed.fetch_add(1, Ordering::Relaxed);
        }
    }

    /// Get total request count.
    pub fn total_requests(&self) -> u64 {
        self.requests_total.load(Ordering::Relaxed)
    }

    /// Get failed request count.
    pub fn failed_requests(&self) -> u64 {
        self.requests_failed.load(Ordering::Relaxed)
    }

    /// Get active connection count.
    pub fn active(&self) -> usize {
        self.active_connections.load(Ordering::Relaxed)
    }
}

/// Unix socket server.
pub struct SocketListener {
    listener: UnixListener,
    settings: Arc<Settings>,
    hmac_validator: Arc<HmacValidator>,
    command_registry: Arc<CommandRegistry>,
    audit_logger: Option<Arc<AuditLogger>>,
    metrics: Arc<ConnectionMetrics>,
    nonce_store: Arc<NonceStore>,
    /// Semaphore for connection limiting
    connection_semaphore: Arc<Semaphore>,
    /// Per-UID rate limiter
    rate_limiter: Arc<RateLimiter>,
}

impl SocketListener {
    /// Create and bind a new socket listener.
    pub async fn bind(
        settings: Arc<Settings>,
        nonce_store: Arc<NonceStore>,
    ) -> Result<Self, DaemonError> {
        let socket_path = &settings.socket.path;

        // Remove existing socket file if present
        // Security: Use symlink_metadata to detect symlinks without following them
        if let Ok(metadata) = std::fs::symlink_metadata(socket_path) {
            // Refuse to remove if the path is a symlink (prevents arbitrary file deletion)
            if metadata.file_type().is_symlink() {
                return Err(DaemonError::Socket {
                    message: format!(
                        "Socket path {} is a symlink, refusing to remove for security",
                        socket_path.display()
                    ),
                });
            }

            std::fs::remove_file(socket_path).map_err(|e| DaemonError::Socket {
                message: format!(
                    "Failed to remove existing socket file {}: {}",
                    socket_path.display(),
                    e
                ),
            })?;
        }

        // Create parent directory if needed
        if let Some(parent) = socket_path.parent() {
            std::fs::create_dir_all(parent).map_err(|e| DaemonError::Socket {
                message: format!(
                    "Failed to create socket directory {}: {}",
                    parent.display(),
                    e
                ),
            })?;
        }

        // Bind to the socket
        let listener = UnixListener::bind(socket_path).map_err(|e| DaemonError::Socket {
            message: format!("Failed to bind to socket {}: {}", socket_path.display(), e),
        })?;

        // Set socket permissions
        Self::set_socket_permissions(socket_path, &settings.socket.permissions)?;

        // Load HMAC secret and create validator
        let hmac_secret = HmacValidator::load_secret(&settings.security.hmac_secret_path)?;
        let hmac_validator = Arc::new(HmacValidator::new(
            &hmac_secret,
            Arc::clone(&nonce_store),
            settings.security.max_request_age_seconds,
        ));

        // Create connection metrics
        let metrics = Arc::new(ConnectionMetrics::new());

        // Create connection semaphore for limiting concurrent connections
        let connection_semaphore = Arc::new(Semaphore::new(settings.limits.max_concurrent_requests));
        info!(
            max_connections = settings.limits.max_concurrent_requests,
            "Connection limiting enabled"
        );

        // Create per-UID rate limiter
        let rate_limiter = Arc::new(RateLimiter::new(
            settings.security.rate_limit_requests,
            settings.security.rate_limit_window_seconds,
        ));
        // Start rate limiter cleanup task to prevent memory growth
        rate_limiter.start_cleanup_task(Duration::from_secs(60));
        info!(
            max_requests = settings.security.rate_limit_requests,
            window_seconds = settings.security.rate_limit_window_seconds,
            "Per-UID rate limiting enabled"
        );

        // Create the template engine
        let template_engine = Arc::new(
            TemplateEngine::new(&settings.paths.templates_dir).unwrap_or_else(|e| {
                warn!(error = %e, "Failed to load templates, using empty engine");
                TemplateEngine::empty()
            }),
        );

        // Create the command registry with template engine and metrics
        let command_registry = Arc::new(CommandRegistry::new(
            template_engine,
            Some(Arc::clone(&metrics)),
            Some(Arc::clone(&nonce_store)),
        ));

        // Create the audit logger if enabled
        let audit_logger = if settings.audit.enabled {
            match AuditLogger::new(&settings.audit.log_path) {
                Ok(logger) => {
                    info!(
                        path = %settings.audit.log_path.display(),
                        "Audit logging enabled"
                    );
                    Some(Arc::new(logger))
                }
                Err(e) => {
                    warn!(
                        error = %e,
                        path = %settings.audit.log_path.display(),
                        "Failed to create audit logger, audit logging disabled"
                    );
                    None
                }
            }
        } else {
            info!("Audit logging disabled");
            None
        };

        info!(
            path = %socket_path.display(),
            "Socket listener bound"
        );

        Ok(Self {
            listener,
            settings,
            hmac_validator,
            command_registry,
            audit_logger,
            metrics,
            nonce_store,
            connection_semaphore,
            rate_limiter,
        })
    }

    /// Get connection metrics.
    pub fn metrics(&self) -> Arc<ConnectionMetrics> {
        Arc::clone(&self.metrics)
    }

    /// Get the nonce store.
    pub fn nonce_store(&self) -> Arc<NonceStore> {
        Arc::clone(&self.nonce_store)
    }

    /// Set socket file permissions.
    fn set_socket_permissions(path: &Path, permissions_str: &str) -> Result<(), DaemonError> {
        let mode = u32::from_str_radix(permissions_str, 8).map_err(|e| DaemonError::Socket {
            message: format!("Invalid socket permissions '{}': {}", permissions_str, e),
        })?;

        let permissions = std::fs::Permissions::from_mode(mode);
        std::fs::set_permissions(path, permissions).map_err(|e| DaemonError::Socket {
            message: format!(
                "Failed to set socket permissions on {}: {}",
                path.display(),
                e
            ),
        })?;

        Ok(())
    }

    /// Run the socket listener, accepting connections.
    ///
    /// The listener will stop accepting new connections when `shutdown` is notified.
    /// Active connections will continue until they complete or are explicitly closed.
    pub async fn run(&self, shutdown: Arc<Notify>) -> Result<(), DaemonError> {
        info!("Socket listener running, waiting for connections...");

        loop {
            tokio::select! {
                result = self.listener.accept() => {
                    match result {
                        Ok((stream, _addr)) => {
                            // Try to acquire a connection permit
                            let permit = match self.connection_semaphore.clone().try_acquire_owned() {
                                Ok(permit) => permit,
                                Err(_) => {
                                    warn!(
                                        max = self.settings.limits.max_concurrent_requests,
                                        "Connection limit reached, rejecting connection"
                                    );
                                    // Connection will be dropped, rejecting the client
                                    continue;
                                }
                            };

                            let settings = Arc::clone(&self.settings);
                            let hmac_validator = Arc::clone(&self.hmac_validator);
                            let command_registry = Arc::clone(&self.command_registry);
                            let audit_logger = self.audit_logger.clone();
                            let metrics = Arc::clone(&self.metrics);
                            let rate_limiter = Arc::clone(&self.rate_limiter);

                            // Track active connection
                            metrics.active_connections.fetch_add(1, Ordering::Relaxed);
                            debug!(
                                active = metrics.active(),
                                "New connection accepted"
                            );

                            // Spawn a task to handle the connection
                            // Permit is moved into the task and dropped when task completes
                            tokio::spawn(async move {
                                let _permit = permit; // Dropped when task completes, releasing semaphore
                                let success = match handle_connection(
                                    stream,
                                    settings,
                                    hmac_validator,
                                    command_registry,
                                    audit_logger,
                                    rate_limiter,
                                ).await {
                                    Ok(()) => true,
                                    Err(e) => {
                                        // Don't log ConnectionClosed as an error
                                        if !matches!(
                                            &e,
                                            DaemonError::Protocol {
                                                kind: crate::error::ProtocolErrorKind::ConnectionClosed
                                            }
                                        ) {
                                            error!(error = %e, "Connection handler error");
                                        }
                                        false
                                    }
                                };

                                // Track request completion and decrement connection count
                                metrics.record_request(success);
                                metrics.active_connections.fetch_sub(1, Ordering::Relaxed);
                                debug!(
                                    active = metrics.active(),
                                    success = success,
                                    "Connection closed"
                                );
                            });
                        }
                        Err(e) => {
                            warn!(error = %e, "Failed to accept connection");
                        }
                    }
                }
                _ = shutdown.notified() => {
                    info!("Shutdown signal received, stopping listener");
                    break;
                }
            }
        }

        Ok(())
    }

    /// Wait for all active connections to drain.
    ///
    /// Returns immediately if there are no active connections.
    pub async fn wait_for_drain(&self) {
        let poll_interval = std::time::Duration::from_millis(100);

        while self.metrics.active() > 0 {
            debug!(
                active = self.metrics.active(),
                "Waiting for connections to drain"
            );
            tokio::time::sleep(poll_interval).await;
        }

        info!("All connections drained");
    }
}
