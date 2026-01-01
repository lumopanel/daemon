//! Integration tests for the Lumo daemon.
//!
//! These tests start a real daemon instance and communicate with it
//! over the Unix socket to verify end-to-end functionality.

use std::io::{Read, Write};
use std::os::unix::net::UnixStream;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use nix::unistd::getuid;

use ring::hmac;
use serde_json::{json, Value};
use tempfile::TempDir;

use lumo_daemon::auth::NonceStore;
use lumo_daemon::config::{
    AuditConfig, LimitsConfig, LoggingConfig, PathsConfig, RedisConfig,
    SecurityConfig, Settings, SocketConfig, WhitelistsConfig,
};
use lumo_daemon::socket::SocketListener;

/// Test daemon instance.
struct TestDaemon {
    socket_path: PathBuf,
    hmac_secret: String,
    _temp_dir: TempDir,
    shutdown: Arc<tokio::sync::Notify>,
}

impl TestDaemon {
    /// Create a new test daemon.
    async fn start() -> Self {
        let temp_dir = TempDir::new().expect("Failed to create temp directory");
        let socket_path = temp_dir.path().join("daemon.sock");
        let hmac_secret = "test-secret-key-for-integration-tests";

        // Create HMAC secret file with secure permissions
        let secret_path = temp_dir.path().join("hmac.key");
        std::fs::write(&secret_path, hmac_secret).expect("Failed to write HMAC secret");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&secret_path, std::fs::Permissions::from_mode(0o600))
                .expect("Failed to set HMAC secret permissions");
        }

        // Create templates directory
        let templates_dir = temp_dir.path().join("templates");
        std::fs::create_dir_all(&templates_dir).expect("Failed to create templates dir");

        // Create test settings
        let settings = Settings {
            socket: SocketConfig {
                path: socket_path.clone(),
                permissions: "0600".to_string(),
                owner: "root".to_string(),
                group: "root".to_string(),
            },
            security: SecurityConfig {
                hmac_secret_path: secret_path,
                nonce_ttl_seconds: 300,
                max_request_age_seconds: 60,
                // Include current user's UID for testing (fail-closed requires explicit UIDs)
                allowed_peer_uids: vec![getuid().as_raw()],
                rate_limit_requests: 100,
                rate_limit_window_seconds: 60,
            },
            redis: RedisConfig {
                url: "redis://127.0.0.1:6379".to_string(),
                pool_size: 4,
            },
            paths: PathsConfig {
                templates_dir,
                custom_templates_dir: PathBuf::from("/tmp/lumo/custom_templates"),
                log_dir: PathBuf::from("/tmp/lumo/logs"),
            },
            logging: LoggingConfig {
                level: "warn".to_string(),
                format: "pretty".to_string(),
                file: None,
            },
            limits: LimitsConfig {
                max_message_size: 1_048_576,
                default_timeout_seconds: 60,
                max_concurrent_requests: 100,
                socket_timeout_seconds: 30,
            },
            audit: AuditConfig {
                enabled: false,
                log_path: temp_dir.path().join("audit.log"),
            },
            whitelists: WhitelistsConfig::default(),
        };

        // Create nonce store
        let nonce_store = Arc::new(NonceStore::new(Duration::from_secs(300)));

        // Create and bind the listener
        let listener = SocketListener::bind(Arc::new(settings), nonce_store)
            .await
            .expect("Failed to bind socket");

        // Create shutdown signal
        let shutdown = Arc::new(tokio::sync::Notify::new());
        let shutdown_for_run = Arc::clone(&shutdown);

        // Start the listener in a background task
        tokio::spawn(async move {
            eprintln!("Starting listener...");
            match listener.run(shutdown_for_run).await {
                Ok(()) => eprintln!("Listener exited normally"),
                Err(e) => eprintln!("Listener error: {}", e),
            }
        });

        // Wait for socket to be ready
        tokio::time::sleep(Duration::from_millis(200)).await;

        Self {
            socket_path,
            hmac_secret: hmac_secret.to_string(),
            _temp_dir: temp_dir,
            shutdown,
        }
    }

    /// Send a request to the daemon and get the response.
    fn send_request(&self, command: &str, params: Value) -> Result<Value, String> {
        let mut stream = UnixStream::connect(&self.socket_path)
            .map_err(|e| format!("Failed to connect: {}", e))?;

        // Use longer timeouts for stability
        stream.set_read_timeout(Some(Duration::from_secs(30)))
            .map_err(|e| format!("Failed to set read timeout: {}", e))?;
        stream.set_write_timeout(Some(Duration::from_secs(30)))
            .map_err(|e| format!("Failed to set write timeout: {}", e))?;

        let timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let nonce = uuid::Uuid::new_v4().to_string();

        // Sign the request
        // Format: {command}:{params_json}:{timestamp}:{nonce}
        let params_json = serde_json::to_string(&params).unwrap_or_default();
        let signing_message = format!("{}:{}:{}:{}", command, params_json, timestamp, nonce);
        let key = hmac::Key::new(hmac::HMAC_SHA256, self.hmac_secret.as_bytes());
        let signature = hmac::sign(&key, signing_message.as_bytes());
        let signature_hex = hex::encode(signature.as_ref());

        let request = json!({
            "command": command,
            "params": params,
            "timestamp": timestamp,
            "nonce": nonce,
            "signature": signature_hex,
        });

        let request_bytes = serde_json::to_vec(&request)
            .map_err(|e| format!("Failed to serialize: {}", e))?;

        let length = request_bytes.len() as u32;
        eprintln!("Sending {} bytes to daemon...", length);
        stream.write_all(&length.to_be_bytes())
            .map_err(|e| format!("Failed to write length: {}", e))?;
        stream.write_all(&request_bytes)
            .map_err(|e| format!("Failed to write request: {}", e))?;
        stream.flush()
            .map_err(|e| format!("Failed to flush: {}", e))?;
        eprintln!("Sent, waiting for response...");

        let mut length_bytes = [0u8; 4];
        stream.read_exact(&mut length_bytes)
            .map_err(|e| format!("Failed to read response length: {}", e))?;
        eprintln!("Got response length bytes");
        let response_length = u32::from_be_bytes(length_bytes) as usize;

        let mut response_bytes = vec![0u8; response_length];
        stream.read_exact(&mut response_bytes)
            .map_err(|e| format!("Failed to read response: {}", e))?;

        serde_json::from_slice(&response_bytes)
            .map_err(|e| format!("Failed to parse: {}", e))
    }

    /// Send a raw request with custom auth parameters.
    fn send_raw_request(
        &self,
        command: &str,
        params: Value,
        timestamp: u64,
        nonce: &str,
        signature: &str,
    ) -> Result<Value, String> {
        let mut stream = UnixStream::connect(&self.socket_path)
            .map_err(|e| format!("Failed to connect: {}", e))?;

        stream.set_read_timeout(Some(Duration::from_secs(30)))
            .map_err(|e| format!("Failed to set read timeout: {}", e))?;
        stream.set_write_timeout(Some(Duration::from_secs(30)))
            .map_err(|e| format!("Failed to set write timeout: {}", e))?;

        let request = json!({
            "command": command,
            "params": params,
            "timestamp": timestamp,
            "nonce": nonce,
            "signature": signature,
        });

        let request_bytes = serde_json::to_vec(&request)
            .map_err(|e| format!("Failed to serialize: {}", e))?;

        let length = request_bytes.len() as u32;
        stream.write_all(&length.to_be_bytes())
            .map_err(|e| format!("Failed to write: {}", e))?;
        stream.write_all(&request_bytes)
            .map_err(|e| format!("Failed to write: {}", e))?;
        stream.flush()
            .map_err(|e| format!("Failed to flush: {}", e))?;

        let mut length_bytes = [0u8; 4];
        stream.read_exact(&mut length_bytes)
            .map_err(|e| format!("Failed to read: {}", e))?;
        let response_length = u32::from_be_bytes(length_bytes) as usize;

        let mut response_bytes = vec![0u8; response_length];
        stream.read_exact(&mut response_bytes)
            .map_err(|e| format!("Failed to read: {}", e))?;

        serde_json::from_slice(&response_bytes)
            .map_err(|e| format!("Failed to parse: {}", e))
    }

    /// Stop the test daemon.
    async fn stop(self) {
        self.shutdown.notify_waiters();
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
}

// ============================================================================
// Socket Tests
// ============================================================================

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_socket_connection() {
    let daemon = TestDaemon::start().await;
    assert!(daemon.socket_path.exists(), "Socket file should exist");
    daemon.stop().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_basic_request_response() {
    let daemon = TestDaemon::start().await;

    let response = daemon.send_request("system.ping", json!({}));
    assert!(response.is_ok(), "Request should succeed: {:?}", response);

    let response = response.unwrap();
    assert_eq!(response["success"], true, "Response: {:?}", response);
    assert_eq!(response["data"]["pong"], true);

    daemon.stop().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_multiple_requests() {
    let daemon = TestDaemon::start().await;

    for i in 0..5 {
        let response = daemon.send_request("system.ping", json!({}));
        assert!(response.is_ok(), "Request {} should succeed", i);
        let response = response.unwrap();
        assert_eq!(response["success"], true, "Request {} response: {:?}", i, response);
    }

    daemon.stop().await;
}

// ============================================================================
// Auth Tests
// ============================================================================

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_valid_signature_accepted() {
    let daemon = TestDaemon::start().await;

    let response = daemon.send_request("system.ping", json!({}));
    assert!(response.is_ok());
    assert_eq!(response.unwrap()["success"], true);

    daemon.stop().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_invalid_signature_rejected() {
    let daemon = TestDaemon::start().await;

    let timestamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let nonce = uuid::Uuid::new_v4().to_string();

    let response = daemon.send_raw_request(
        "system.ping",
        json!({}),
        timestamp,
        &nonce,
        "0000000000000000000000000000000000000000000000000000000000000000",
    );

    assert!(response.is_ok());
    let response = response.unwrap();
    assert_eq!(response["success"], false, "Expected auth failure: {:?}", response);
    let error_code = response["error"]["code"].as_str().unwrap_or("");
    let error_msg = response["error"]["message"].as_str().unwrap_or("").to_lowercase();
    // Error messages are sanitized - check for auth error code or sanitized message
    assert!(error_code == "AUTH_ERROR" || error_msg.contains("authentication"), "Expected auth error, got code: {}, msg: {}", error_code, error_msg);

    daemon.stop().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_expired_request_rejected() {
    let daemon = TestDaemon::start().await;

    let old_timestamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs() - 120;
    let nonce = uuid::Uuid::new_v4().to_string();

    // Format: {command}:{params_json}:{timestamp}:{nonce}
    let signing_message = format!("system.ping:{}:{}:{}", "{}", old_timestamp, nonce);
    let key = hmac::Key::new(hmac::HMAC_SHA256, daemon.hmac_secret.as_bytes());
    let signature = hmac::sign(&key, signing_message.as_bytes());
    let signature_hex = hex::encode(signature.as_ref());

    let response = daemon.send_raw_request(
        "system.ping",
        json!({}),
        old_timestamp,
        &nonce,
        &signature_hex,
    );

    assert!(response.is_ok());
    let response = response.unwrap();
    assert_eq!(response["success"], false, "Expected expired request failure: {:?}", response);
    let error_code = response["error"]["code"].as_str().unwrap_or("");
    let error_msg = response["error"]["message"].as_str().unwrap_or("").to_lowercase();
    // Error messages are sanitized - check for auth error code or sanitized message
    assert!(error_code == "AUTH_ERROR" || error_msg.contains("authentication"), "Expected auth error for expired request, got code: {}, msg: {}", error_code, error_msg);

    daemon.stop().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_nonce_reuse_rejected() {
    let daemon = TestDaemon::start().await;

    let timestamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let nonce = uuid::Uuid::new_v4().to_string();

    // Format: {command}:{params_json}:{timestamp}:{nonce}
    let signing_message = format!("system.ping:{}:{}:{}", "{}", timestamp, nonce);
    let key = hmac::Key::new(hmac::HMAC_SHA256, daemon.hmac_secret.as_bytes());
    let signature = hmac::sign(&key, signing_message.as_bytes());
    let signature_hex = hex::encode(signature.as_ref());

    // First request should succeed
    let response = daemon.send_raw_request(
        "system.ping",
        json!({}),
        timestamp,
        &nonce,
        &signature_hex,
    );
    assert!(response.is_ok());
    let first_response = response.unwrap();
    assert_eq!(first_response["success"], true, "First request should succeed: {:?}", first_response);

    // Second request with same nonce should fail
    let response = daemon.send_raw_request(
        "system.ping",
        json!({}),
        timestamp,
        &nonce,
        &signature_hex,
    );

    assert!(response.is_ok());
    let response = response.unwrap();
    assert_eq!(response["success"], false, "Expected nonce reuse failure: {:?}", response);
    let error_code = response["error"]["code"].as_str().unwrap_or("");
    let error_msg = response["error"]["message"].as_str().unwrap_or("").to_lowercase();
    // Error messages are sanitized - check for auth error code or sanitized message
    assert!(error_code == "AUTH_ERROR" || error_msg.contains("authentication"), "Expected auth error for nonce reuse, got code: {}, msg: {}", error_code, error_msg);

    daemon.stop().await;
}

// ============================================================================
// Command Tests
// ============================================================================

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_ping_command() {
    let daemon = TestDaemon::start().await;

    let response = daemon.send_request("system.ping", json!({})).unwrap();
    assert_eq!(response["success"], true);
    assert_eq!(response["data"]["pong"], true);
    assert!(response["data"]["timestamp"].is_u64());

    daemon.stop().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_metrics_command() {
    let daemon = TestDaemon::start().await;

    // Generate some requests first
    for _ in 0..3 {
        let _ = daemon.send_request("system.ping", json!({}));
    }

    let response = daemon.send_request("system.metrics", json!({})).unwrap();
    assert_eq!(response["success"], true);

    let data = &response["data"];
    assert!(data["uptime_seconds"].is_u64());
    assert!(data["requests_total"].is_u64());
    assert!(data["version"].is_string());

    daemon.stop().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_unknown_command() {
    let daemon = TestDaemon::start().await;

    let response = daemon.send_request("nonexistent.command", json!({})).unwrap();
    assert_eq!(response["success"], false, "Expected unknown command failure: {:?}", response);
    let error_code = response["error"]["code"].as_str().unwrap_or("");
    let error_msg = response["error"]["message"].as_str().unwrap_or("").to_lowercase();
    // Error messages are sanitized - check for execution error code or sanitized message
    assert!(error_code == "EXECUTION_ERROR" || error_msg.contains("execution") || error_msg.contains("error"), "Expected execution error for unknown command, got code: {}, msg: {}", error_code, error_msg);

    daemon.stop().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_validation_error() {
    let daemon = TestDaemon::start().await;

    let response = daemon.send_request("service.start", json!({
        "service": "invalid-service"
    })).unwrap();

    assert_eq!(response["success"], false, "Expected validation failure: {:?}", response);
    let error_code = response["error"]["code"].as_str().unwrap_or("");
    let error_msg = response["error"]["message"].as_str().unwrap_or("").to_lowercase();
    // Error messages are sanitized - check for validation error code or sanitized message
    assert!(error_code == "VALIDATION_ERROR" || error_code == "EXECUTION_ERROR" || error_msg.contains("invalid") || error_msg.contains("request") || error_msg.contains("execution"), "Expected validation error, got code: {}, msg: {}", error_code, error_msg);

    daemon.stop().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_missing_required_parameter() {
    let daemon = TestDaemon::start().await;

    let response = daemon.send_request("service.start", json!({})).unwrap();
    assert_eq!(response["success"], false, "Expected missing param failure: {:?}", response);
    let error_code = response["error"]["code"].as_str().unwrap_or("");
    let error_msg = response["error"]["message"].as_str().unwrap_or("").to_lowercase();
    // Error messages are sanitized - check for validation/execution error code or sanitized message
    assert!(error_code == "VALIDATION_ERROR" || error_code == "EXECUTION_ERROR" || error_msg.contains("invalid") || error_msg.contains("request") || error_msg.contains("execution"), "Expected validation error for missing param, got code: {}, msg: {}", error_code, error_msg);

    daemon.stop().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_path_validation_protected_file() {
    let daemon = TestDaemon::start().await;

    let response = daemon.send_request("file.write", json!({
        "path": "/etc/passwd",
        "content": "test"
    })).unwrap();

    assert_eq!(response["success"], false, "Expected protected file failure: {:?}", response);
    let error_code = response["error"]["code"].as_str().unwrap_or("");
    let error_msg = response["error"]["message"].as_str().unwrap_or("").to_lowercase();
    // Error messages are sanitized - check for validation/execution error code or sanitized message
    assert!(error_code == "VALIDATION_ERROR" || error_code == "EXECUTION_ERROR" || error_msg.contains("invalid") || error_msg.contains("request") || error_msg.contains("execution"), "Expected validation error for protected file, got code: {}, msg: {}", error_code, error_msg);

    daemon.stop().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_path_traversal_blocked() {
    let daemon = TestDaemon::start().await;

    let response = daemon.send_request("file.write", json!({
        "path": "/tmp/lumo/../../../etc/passwd",
        "content": "test"
    })).unwrap();

    assert_eq!(response["success"], false, "Expected path traversal failure: {:?}", response);
    let error_code = response["error"]["code"].as_str().unwrap_or("");
    let error_msg = response["error"]["message"].as_str().unwrap_or("").to_lowercase();
    // Error messages are sanitized - check for validation/execution error code or sanitized message
    assert!(error_code == "VALIDATION_ERROR" || error_code == "EXECUTION_ERROR" || error_msg.contains("invalid") || error_msg.contains("request") || error_msg.contains("execution"), "Expected validation error for path traversal, got code: {}, msg: {}", error_code, error_msg);

    daemon.stop().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_package_not_whitelisted() {
    let daemon = TestDaemon::start().await;

    let response = daemon.send_request("package.install", json!({
        "packages": ["malware-package"]
    })).unwrap();

    assert_eq!(response["success"], false, "Expected whitelist failure: {:?}", response);
    let error_code = response["error"]["code"].as_str().unwrap_or("");
    let error_msg = response["error"]["message"].as_str().unwrap_or("").to_lowercase();
    // Error messages are sanitized - check for validation/execution error code or sanitized message
    assert!(error_code == "VALIDATION_ERROR" || error_code == "EXECUTION_ERROR" || error_msg.contains("invalid") || error_msg.contains("request") || error_msg.contains("execution"), "Expected validation error for non-whitelisted package, got code: {}, msg: {}", error_code, error_msg);

    daemon.stop().await;
}
