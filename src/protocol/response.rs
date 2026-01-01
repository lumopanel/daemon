//! Response types for the daemon protocol.

use serde::{Deserialize, Serialize};
use tracing::debug;
use uuid::Uuid;

/// Sanitize error messages before sending to clients.
///
/// This prevents information disclosure by replacing detailed error messages
/// with generic, user-friendly messages while preserving the error code.
fn sanitize_error_message(code: &str, _original: &str) -> String {
    match code {
        "AUTH_ERROR" => "Authentication failed".to_string(),
        "VALIDATION_ERROR" => "Invalid request parameters".to_string(),
        "COMMAND_ERROR" => "Command execution failed".to_string(),
        "EXECUTION_ERROR" => "Internal execution error".to_string(),
        "INTERNAL_ERROR" => "Internal server error".to_string(),
        "RATE_LIMITED" => "Too many requests".to_string(),
        "CONNECTION_TIMEOUT" => "Connection timed out".to_string(),
        _ => "An error occurred".to_string(),
    }
}

/// A response from the daemon.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Response {
    /// Whether the request succeeded.
    pub success: bool,

    /// Unique identifier for this request/response pair.
    pub request_id: Uuid,

    /// Response data on success.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub data: Option<serde_json::Value>,

    /// Error details on failure.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<ErrorResponse>,
}

/// Error details in a response.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ErrorResponse {
    /// Error code (e.g., "VALIDATION_ERROR", "AUTH_ERROR").
    pub code: String,

    /// Human-readable error message.
    pub message: String,

    /// Additional error details.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub details: Option<serde_json::Value>,
}

impl Response {
    /// Create a success response.
    pub fn success(data: serde_json::Value) -> Self {
        Self {
            success: true,
            request_id: Uuid::new_v4(),
            data: Some(data),
            error: None,
        }
    }

    /// Create a success response with no data.
    pub fn success_empty() -> Self {
        Self {
            success: true,
            request_id: Uuid::new_v4(),
            data: None,
            error: None,
        }
    }

    /// Create an error response.
    pub fn error(code: impl Into<String>, message: impl Into<String>) -> Self {
        Self {
            success: false,
            request_id: Uuid::new_v4(),
            data: None,
            error: Some(ErrorResponse {
                code: code.into(),
                message: message.into(),
                details: None,
            }),
        }
    }

    /// Create an error response with details.
    pub fn error_with_details(
        code: impl Into<String>,
        message: impl Into<String>,
        details: serde_json::Value,
    ) -> Self {
        Self {
            success: false,
            request_id: Uuid::new_v4(),
            data: None,
            error: Some(ErrorResponse {
                code: code.into(),
                message: message.into(),
                details: Some(details),
            }),
        }
    }

    /// Set the request ID (for correlating with the original request).
    pub fn with_request_id(mut self, id: Uuid) -> Self {
        self.request_id = id;
        self
    }

    /// Create a success response with a specific request ID.
    pub fn success_with_id(request_id: Uuid, data: serde_json::Value) -> Self {
        Self {
            success: true,
            request_id,
            data: Some(data),
            error: None,
        }
    }

    /// Create an error response with a specific request ID.
    ///
    /// The error message is sanitized before being sent to the client to prevent
    /// information disclosure. The original error is logged server-side for debugging.
    pub fn error_with_id(
        request_id: Uuid,
        code: impl Into<String>,
        message: impl Into<String>,
    ) -> Self {
        let code_str = code.into();
        let original_message = message.into();

        // Log full error server-side for debugging
        debug!(
            request_id = %request_id,
            code = %code_str,
            message = %original_message,
            "Error response (sanitized for client)"
        );

        Self {
            success: false,
            request_id,
            data: None,
            error: Some(ErrorResponse {
                code: code_str.clone(),
                message: sanitize_error_message(&code_str, &original_message),
                details: None,
            }),
        }
    }
}

impl ErrorResponse {
    /// Create a new error response.
    pub fn new(code: impl Into<String>, message: impl Into<String>) -> Self {
        Self {
            code: code.into(),
            message: message.into(),
            details: None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_success_response() {
        let response = Response::success(serde_json::json!({"result": "ok"}));
        assert!(response.success);
        assert!(response.data.is_some());
        assert!(response.error.is_none());
    }

    #[test]
    fn test_error_response() {
        let response = Response::error("TEST_ERROR", "Something went wrong");
        assert!(!response.success);
        assert!(response.data.is_none());
        assert!(response.error.is_some());

        let error = response.error.unwrap();
        assert_eq!(error.code, "TEST_ERROR");
        assert_eq!(error.message, "Something went wrong");
    }

    #[test]
    fn test_response_serialization() {
        let response = Response::success(serde_json::json!({"key": "value"}));
        let json = serde_json::to_string(&response).unwrap();

        assert!(json.contains("\"success\":true"));
        assert!(json.contains("\"request_id\""));
        assert!(!json.contains("\"error\"")); // Should be skipped when None
    }
}
