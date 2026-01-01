//! Per-connection handler.

use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use chrono::Utc;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::UnixStream;
use tracing::{debug, error, info, warn};
use uuid::Uuid;

use crate::audit::{sanitize_params, AuditEntry, AuditLogger};
use crate::auth::{verify_peer, HmacValidator, PeerInfo, RateLimiter};
use crate::commands::{CommandParams, CommandRegistry, ExecutionContext};
use crate::config::Settings;
use crate::error::{DaemonError, ProtocolErrorKind};
use crate::protocol::{read_message_with_timeout, write_message_with_timeout, Response, SignedRequest};

/// Handle a single client connection.
pub async fn handle_connection(
    stream: UnixStream,
    settings: Arc<Settings>,
    hmac_validator: Arc<HmacValidator>,
    command_registry: Arc<CommandRegistry>,
    audit_logger: Option<Arc<AuditLogger>>,
    rate_limiter: Arc<RateLimiter>,
) -> Result<(), DaemonError> {
    // Get the standard library stream for peer credential verification
    let std_stream = stream.into_std().map_err(|e| DaemonError::Socket {
        message: format!("Failed to convert to std stream: {}", e),
    })?;

    // Verify peer credentials
    let peer = verify_peer(&std_stream, &settings.security.allowed_peer_uids)?;
    debug!(uid = peer.uid, gid = peer.gid, pid = peer.pid, "Peer authenticated");

    // Convert back to tokio stream
    std_stream.set_nonblocking(true).map_err(|e| DaemonError::Socket {
        message: format!("Failed to set non-blocking: {}", e),
    })?;
    let stream = UnixStream::from_std(std_stream).map_err(|e| DaemonError::Socket {
        message: format!("Failed to convert back to tokio stream: {}", e),
    })?;

    // Split into read/write halves
    let (mut reader, mut writer) = stream.into_split();

    // Process requests in a loop
    loop {
        let result = process_request(
            &mut reader,
            &mut writer,
            &settings,
            &hmac_validator,
            &command_registry,
            &peer,
            audit_logger.as_ref(),
            &rate_limiter,
        )
        .await;

        match result {
            Ok(()) => continue,
            Err(DaemonError::Protocol {
                kind: ProtocolErrorKind::ConnectionClosed,
            }) => {
                debug!(uid = peer.uid, "Client disconnected");
                return Ok(());
            }
            Err(DaemonError::Protocol {
                kind: ProtocolErrorKind::ConnectionTimeout,
            }) => {
                warn!(uid = peer.uid, "Connection timed out");
                return Ok(());
            }
            Err(e) => return Err(e),
        }
    }
}

/// Process a single request from the client.
async fn process_request<R, W>(
    reader: &mut R,
    writer: &mut W,
    settings: &Settings,
    hmac_validator: &HmacValidator,
    command_registry: &CommandRegistry,
    peer: &PeerInfo,
    audit_logger: Option<&Arc<AuditLogger>>,
    rate_limiter: &RateLimiter,
) -> Result<(), DaemonError>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    // Read the incoming message with timeout
    let socket_timeout = Duration::from_secs(settings.limits.socket_timeout_seconds);
    let msg = read_message_with_timeout(reader, settings.limits.max_message_size, socket_timeout).await?;

    // Parse the request
    let request: SignedRequest = serde_json::from_slice(&msg).map_err(|e| DaemonError::Protocol {
        kind: ProtocolErrorKind::InvalidMessageFormat {
            message: format!("Invalid JSON: {}", e),
        },
    })?;

    let request_id = Uuid::new_v4();
    let start_time = Instant::now();

    info!(
        request_id = %request_id,
        command = %request.command,
        uid = peer.uid,
        "Received request"
    );

    // Check rate limit for this UID
    if !rate_limiter.check_and_record(peer.uid) {
        warn!(
            request_id = %request_id,
            uid = peer.uid,
            "Rate limit exceeded"
        );

        let response = Response::error_with_id(request_id, "RATE_LIMITED", "Too many requests");
        let response_bytes = serde_json::to_vec(&response)?;
        write_message_with_timeout(writer, &response_bytes, socket_timeout).await?;
        return Ok(());
    }

    // Check if this command requires audit logging
    let requires_audit = command_registry
        .get(&request.command)
        .map(|cmd| cmd.requires_audit())
        .unwrap_or(true); // Unknown commands still get audited

    // Sanitize params for audit logging
    let sanitized_params = if requires_audit && audit_logger.is_some() {
        Some(sanitize_params(&request.params))
    } else {
        None
    };

    // Validate the request (signature and nonce)
    let response = match hmac_validator.validate(&request).await {
        Ok(()) => {
            // Create execution context
            let timestamp = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map(|d| d.as_secs())
                .unwrap_or(0);

            let ctx = ExecutionContext::new(
                request_id,
                peer.clone(),
                timestamp,
                request.command.clone(),
            );

            // Create command params
            let params = CommandParams::new(request.params.clone());

            // Dispatch to command handler using spawn_blocking for sync commands
            let command_registry = command_registry.clone();
            let command_name = request.command.clone();

            let result = tokio::task::spawn_blocking(move || {
                command_registry.dispatch(&ctx, &command_name, params)
            })
            .await;

            match result {
                Ok(Ok(cmd_result)) => {
                    info!(
                        request_id = %request_id,
                        command = %request.command,
                        success = cmd_result.success,
                        "Command executed"
                    );

                    let response = if cmd_result.success {
                        Response::success_with_id(
                            request_id,
                            cmd_result.data.clone().unwrap_or(serde_json::json!({})),
                        )
                    } else {
                        Response::error_with_id(
                            request_id,
                            cmd_result.error_code.clone().unwrap_or_else(|| "COMMAND_ERROR".to_string()),
                            cmd_result.error_message.clone().unwrap_or_else(|| "Unknown error".to_string()),
                        )
                    };

                    // Log audit entry for successful dispatch
                    if let (Some(logger), Some(params)) = (audit_logger, &sanitized_params) {
                        let duration_ms = start_time.elapsed().as_millis() as u64;
                        let entry = if cmd_result.success {
                            AuditEntry::success(
                                Utc::now().to_rfc3339(),
                                request_id,
                                request.command.clone(),
                                params.clone(),
                                peer.uid,
                                peer.gid,
                                peer.pid,
                                cmd_result.data,
                                duration_ms,
                            )
                        } else {
                            AuditEntry::failure(
                                Utc::now().to_rfc3339(),
                                request_id,
                                request.command.clone(),
                                params.clone(),
                                peer.uid,
                                peer.gid,
                                peer.pid,
                                cmd_result.error_code.unwrap_or_else(|| "COMMAND_ERROR".to_string()),
                                cmd_result.error_message.unwrap_or_else(|| "Unknown error".to_string()),
                                duration_ms,
                            )
                        };
                        if let Err(e) = logger.log(&entry) {
                            error!(error = %e, "Failed to write audit log entry");
                        }
                    }

                    response
                }
                Ok(Err(e)) => {
                    error!(
                        request_id = %request_id,
                        command = %request.command,
                        error = %e,
                        "Command execution failed"
                    );

                    // Log audit entry for execution error
                    if let (Some(logger), Some(params)) = (audit_logger, &sanitized_params) {
                        let duration_ms = start_time.elapsed().as_millis() as u64;
                        let entry = AuditEntry::failure(
                            Utc::now().to_rfc3339(),
                            request_id,
                            request.command.clone(),
                            params.clone(),
                            peer.uid,
                            peer.gid,
                            peer.pid,
                            "EXECUTION_ERROR".to_string(),
                            e.to_string(),
                            duration_ms,
                        );
                        if let Err(e) = logger.log(&entry) {
                            error!(error = %e, "Failed to write audit log entry");
                        }
                    }

                    Response::error_with_id(request_id, "EXECUTION_ERROR", e.to_string())
                }
                Err(e) => {
                    error!(
                        request_id = %request_id,
                        command = %request.command,
                        error = %e,
                        "Command task panicked"
                    );

                    // Log audit entry for panic
                    if let (Some(logger), Some(params)) = (audit_logger, &sanitized_params) {
                        let duration_ms = start_time.elapsed().as_millis() as u64;
                        let entry = AuditEntry::failure(
                            Utc::now().to_rfc3339(),
                            request_id,
                            request.command.clone(),
                            params.clone(),
                            peer.uid,
                            peer.gid,
                            peer.pid,
                            "INTERNAL_ERROR".to_string(),
                            "Command execution failed".to_string(),
                            duration_ms,
                        );
                        if let Err(e) = logger.log(&entry) {
                            error!(error = %e, "Failed to write audit log entry");
                        }
                    }

                    Response::error_with_id(request_id, "INTERNAL_ERROR", "Command execution failed")
                }
            }
        }
        Err(e) => {
            warn!(
                request_id = %request_id,
                command = %request.command,
                error = %e,
                "Request validation failed"
            );

            // Log audit entry for auth error
            if let (Some(logger), Some(params)) = (audit_logger, &sanitized_params) {
                let duration_ms = start_time.elapsed().as_millis() as u64;
                let entry = AuditEntry::failure(
                    Utc::now().to_rfc3339(),
                    request_id,
                    request.command.clone(),
                    params.clone(),
                    peer.uid,
                    peer.gid,
                    peer.pid,
                    "AUTH_ERROR".to_string(),
                    e.to_string(),
                    duration_ms,
                );
                if let Err(e) = logger.log(&entry) {
                    error!(error = %e, "Failed to write audit log entry");
                }
            }

            Response::error_with_id(request_id, "AUTH_ERROR", e.to_string())
        }
    };

    // Send the response with timeout
    let response_bytes = serde_json::to_vec(&response)?;
    write_message_with_timeout(writer, &response_bytes, socket_timeout).await?;

    Ok(())
}

#[cfg(test)]
mod tests {
    // Integration tests would go here, but require setting up Unix sockets
    // which is complex for unit testing. See tests/integration/ for full tests.
}
