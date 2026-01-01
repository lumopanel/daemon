//! Audit entry types.
//!
//! Defines the structure of audit log entries.

use serde::Serialize;
use uuid::Uuid;

/// A single audit log entry.
///
/// Records details about a command execution including the command,
/// parameters (sanitized), peer information, result, and timing.
#[derive(Debug, Clone, Serialize)]
pub struct AuditEntry {
    /// ISO 8601 timestamp when the command was executed.
    pub timestamp: String,
    /// Unique identifier for the request.
    pub request_id: Uuid,
    /// The command that was executed.
    pub command: String,
    /// Sanitized parameters (sensitive values redacted).
    pub params: serde_json::Value,
    /// UID of the peer that made the request.
    pub peer_uid: u32,
    /// GID of the peer that made the request.
    pub peer_gid: u32,
    /// PID of the peer process.
    pub peer_pid: i32,
    /// Result of the command execution.
    pub result: AuditResult,
    /// Execution duration in milliseconds.
    pub duration_ms: u64,
}

impl AuditEntry {
    /// Create a new audit entry for a successful command.
    pub fn success(
        timestamp: String,
        request_id: Uuid,
        command: String,
        params: serde_json::Value,
        peer_uid: u32,
        peer_gid: u32,
        peer_pid: i32,
        data: Option<serde_json::Value>,
        duration_ms: u64,
    ) -> Self {
        Self {
            timestamp,
            request_id,
            command,
            params,
            peer_uid,
            peer_gid,
            peer_pid,
            result: AuditResult::Success { data },
            duration_ms,
        }
    }

    /// Create a new audit entry for a failed command.
    pub fn failure(
        timestamp: String,
        request_id: Uuid,
        command: String,
        params: serde_json::Value,
        peer_uid: u32,
        peer_gid: u32,
        peer_pid: i32,
        error_code: String,
        error_message: String,
        duration_ms: u64,
    ) -> Self {
        Self {
            timestamp,
            request_id,
            command,
            params,
            peer_uid,
            peer_gid,
            peer_pid,
            result: AuditResult::Failure {
                error_code,
                error_message,
            },
            duration_ms,
        }
    }
}

/// Result of a command execution for audit purposes.
#[derive(Debug, Clone, Serialize)]
#[serde(tag = "status")]
pub enum AuditResult {
    /// Command executed successfully.
    #[serde(rename = "success")]
    Success {
        /// Optional result data.
        #[serde(skip_serializing_if = "Option::is_none")]
        data: Option<serde_json::Value>,
    },
    /// Command execution failed.
    #[serde(rename = "failure")]
    Failure {
        /// Error code.
        error_code: String,
        /// Error message.
        error_message: String,
    },
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_audit_entry_success_serialization() {
        let entry = AuditEntry::success(
            "2024-01-15T10:30:45.123Z".to_string(),
            Uuid::nil(),
            "file.write".to_string(),
            serde_json::json!({"path": "/tmp/test.txt"}),
            1000,
            1000,
            12345,
            Some(serde_json::json!({"bytes_written": 100})),
            15,
        );

        let json = serde_json::to_string(&entry).unwrap();
        assert!(json.contains("\"status\":\"success\""));
        assert!(json.contains("\"command\":\"file.write\""));
        assert!(json.contains("\"peer_uid\":1000"));
        assert!(json.contains("\"duration_ms\":15"));
    }

    #[test]
    fn test_audit_entry_failure_serialization() {
        let entry = AuditEntry::failure(
            "2024-01-15T10:30:45.123Z".to_string(),
            Uuid::nil(),
            "file.write".to_string(),
            serde_json::json!({"path": "/etc/passwd"}),
            1000,
            1000,
            12345,
            "VALIDATION_ERROR".to_string(),
            "Path not allowed".to_string(),
            5,
        );

        let json = serde_json::to_string(&entry).unwrap();
        assert!(json.contains("\"status\":\"failure\""));
        assert!(json.contains("\"error_code\":\"VALIDATION_ERROR\""));
        assert!(json.contains("\"error_message\":\"Path not allowed\""));
    }

    #[test]
    fn test_audit_result_success_without_data() {
        let result = AuditResult::Success { data: None };
        let json = serde_json::to_string(&result).unwrap();
        assert!(json.contains("\"status\":\"success\""));
        assert!(!json.contains("\"data\""));
    }
}
