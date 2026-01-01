//! Command types: parameters, results, and execution context.

use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::auth::PeerInfo;
use crate::error::{DaemonError, ValidationErrorKind};

/// Wrapper around command parameters with helper methods.
#[derive(Debug, Clone)]
pub struct CommandParams {
    inner: serde_json::Value,
}

impl CommandParams {
    /// Create new command parameters from a JSON value.
    pub fn new(value: serde_json::Value) -> Self {
        Self { inner: value }
    }

    /// Get the underlying JSON value.
    pub fn as_value(&self) -> &serde_json::Value {
        &self.inner
    }

    /// Get a required string parameter.
    pub fn get_string(&self, key: &str) -> Result<String, DaemonError> {
        self.inner
            .get(key)
            .and_then(|v| v.as_str())
            .map(|s| s.to_string())
            .ok_or_else(|| DaemonError::Validation {
                kind: ValidationErrorKind::MissingParameter {
                    param: key.to_string(),
                },
            })
    }

    /// Get an optional string parameter.
    pub fn get_optional_string(&self, key: &str) -> Option<String> {
        self.inner.get(key).and_then(|v| v.as_str()).map(|s| s.to_string())
    }

    /// Get a required boolean parameter.
    pub fn get_bool(&self, key: &str) -> Result<bool, DaemonError> {
        self.inner
            .get(key)
            .and_then(|v| v.as_bool())
            .ok_or_else(|| DaemonError::Validation {
                kind: ValidationErrorKind::MissingParameter {
                    param: key.to_string(),
                },
            })
    }

    /// Get an optional boolean parameter with a default.
    pub fn get_optional_bool(&self, key: &str, default: bool) -> bool {
        self.inner
            .get(key)
            .and_then(|v| v.as_bool())
            .unwrap_or(default)
    }

    /// Get a required integer parameter.
    pub fn get_i64(&self, key: &str) -> Result<i64, DaemonError> {
        self.inner
            .get(key)
            .and_then(|v| v.as_i64())
            .ok_or_else(|| DaemonError::Validation {
                kind: ValidationErrorKind::MissingParameter {
                    param: key.to_string(),
                },
            })
    }

    /// Get an optional integer parameter.
    pub fn get_optional_i64(&self, key: &str) -> Option<i64> {
        self.inner.get(key).and_then(|v| v.as_i64())
    }

    /// Get a required array of strings.
    pub fn get_string_array(&self, key: &str) -> Result<Vec<String>, DaemonError> {
        self.inner
            .get(key)
            .and_then(|v| v.as_array())
            .map(|arr| {
                arr.iter()
                    .filter_map(|v| v.as_str().map(|s| s.to_string()))
                    .collect()
            })
            .ok_or_else(|| DaemonError::Validation {
                kind: ValidationErrorKind::MissingParameter {
                    param: key.to_string(),
                },
            })
    }

    /// Get an optional array of strings.
    pub fn get_optional_string_array(&self, key: &str) -> Option<Vec<String>> {
        self.inner
            .get(key)
            .and_then(|v| v.as_array())
            .map(|arr| {
                arr.iter()
                    .filter_map(|v| v.as_str().map(|s| s.to_string()))
                    .collect()
            })
    }

    /// Get an optional boolean parameter.
    pub fn get_optional_bool_opt(&self, key: &str) -> Option<bool> {
        self.inner.get(key).and_then(|v| v.as_bool())
    }

    /// Check if a parameter exists.
    pub fn has(&self, key: &str) -> bool {
        self.inner.get(key).is_some()
    }

    /// Require that a string parameter exists (for validation).
    pub fn require_string(&self, key: &str) -> Result<(), DaemonError> {
        if self.inner.get(key).and_then(|v| v.as_str()).is_some() {
            Ok(())
        } else {
            Err(DaemonError::Validation {
                kind: ValidationErrorKind::MissingParameter {
                    param: key.to_string(),
                },
            })
        }
    }
}

impl From<serde_json::Value> for CommandParams {
    fn from(value: serde_json::Value) -> Self {
        Self::new(value)
    }
}

/// Result of command execution.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CommandResult {
    /// Whether the command succeeded.
    pub success: bool,
    /// Result data on success.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub data: Option<serde_json::Value>,
    /// Error code on failure.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error_code: Option<String>,
    /// Error message on failure.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error_message: Option<String>,
}

impl CommandResult {
    /// Create a success result with data.
    pub fn success(data: serde_json::Value) -> Self {
        Self {
            success: true,
            data: Some(data),
            error_code: None,
            error_message: None,
        }
    }

    /// Create a success result with no data.
    pub fn success_empty() -> Self {
        Self {
            success: true,
            data: None,
            error_code: None,
            error_message: None,
        }
    }

    /// Create a failure result.
    pub fn failure(code: impl Into<String>, message: impl Into<String>) -> Self {
        Self {
            success: false,
            data: None,
            error_code: Some(code.into()),
            error_message: Some(message.into()),
        }
    }
}

/// Execution context for a command.
///
/// Contains metadata about the request and the connected peer.
#[derive(Debug, Clone)]
pub struct ExecutionContext {
    /// Unique identifier for this request.
    pub request_id: Uuid,
    /// Information about the connected peer.
    pub peer: PeerInfo,
    /// Timestamp when the request was received.
    pub timestamp: u64,
    /// The command being executed.
    pub command: String,
}

impl ExecutionContext {
    /// Create a new execution context.
    pub fn new(request_id: Uuid, peer: PeerInfo, timestamp: u64, command: String) -> Self {
        Self {
            request_id,
            peer,
            timestamp,
            command,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_command_params_get_string() {
        let params = CommandParams::new(serde_json::json!({
            "name": "test",
            "count": 42
        }));

        assert_eq!(params.get_string("name").unwrap(), "test");
        assert!(params.get_string("missing").is_err());
    }

    #[test]
    fn test_command_params_optional() {
        let params = CommandParams::new(serde_json::json!({
            "name": "test"
        }));

        assert_eq!(params.get_optional_string("name"), Some("test".to_string()));
        assert_eq!(params.get_optional_string("missing"), None);
    }

    #[test]
    fn test_command_result_success() {
        let result = CommandResult::success(serde_json::json!({"key": "value"}));
        assert!(result.success);
        assert!(result.data.is_some());
        assert!(result.error_code.is_none());
    }

    #[test]
    fn test_command_result_failure() {
        let result = CommandResult::failure("ERR_CODE", "Something failed");
        assert!(!result.success);
        assert!(result.data.is_none());
        assert_eq!(result.error_code, Some("ERR_CODE".to_string()));
    }
}
