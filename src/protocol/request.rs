//! Request types for the daemon protocol.

use serde::{Deserialize, Serialize};

/// A signed request from a client.
///
/// All requests must be signed with HMAC-SHA256 to prevent tampering.
/// The nonce prevents replay attacks.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignedRequest {
    /// The command to execute (e.g., "file.write", "service.restart").
    pub command: String,

    /// Command parameters as a JSON object.
    pub params: serde_json::Value,

    /// Unix timestamp when the request was created.
    pub timestamp: u64,

    /// Unique nonce to prevent replay attacks.
    pub nonce: String,

    /// HMAC-SHA256 signature (hex-encoded).
    pub signature: String,
}

impl SignedRequest {
    /// Create a new unsigned request (for testing purposes).
    #[cfg(test)]
    pub fn new(command: impl Into<String>) -> Self {
        Self {
            command: command.into(),
            params: serde_json::json!({}),
            timestamp: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs(),
            nonce: uuid::Uuid::new_v4().to_string(),
            signature: String::new(),
        }
    }

    /// Add a parameter to the request (builder pattern, for testing).
    #[cfg(test)]
    pub fn with_param(mut self, key: &str, value: impl Into<serde_json::Value>) -> Self {
        if let Some(obj) = self.params.as_object_mut() {
            obj.insert(key.to_string(), value.into());
        }
        self
    }

    /// Get the message to sign.
    ///
    /// Format: `{command}:{params_json}:{timestamp}:{nonce}`
    pub fn signing_message(&self) -> String {
        format!(
            "{}:{}:{}:{}",
            self.command,
            serde_json::to_string(&self.params).unwrap_or_default(),
            self.timestamp,
            self.nonce
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_signing_message_format() {
        let request = SignedRequest {
            command: "file.write".to_string(),
            params: serde_json::json!({"path": "/tmp/test"}),
            timestamp: 1234567890,
            nonce: "abc123".to_string(),
            signature: String::new(),
        };

        let msg = request.signing_message();
        assert!(msg.starts_with("file.write:"));
        assert!(msg.contains("1234567890"));
        assert!(msg.ends_with(":abc123"));
    }

    #[test]
    fn test_request_serialization() {
        let request = SignedRequest {
            command: "test.command".to_string(),
            params: serde_json::json!({"key": "value"}),
            timestamp: 1234567890,
            nonce: "nonce123".to_string(),
            signature: "sig456".to_string(),
        };

        let json = serde_json::to_string(&request).unwrap();
        let parsed: SignedRequest = serde_json::from_str(&json).unwrap();

        assert_eq!(parsed.command, request.command);
        assert_eq!(parsed.timestamp, request.timestamp);
        assert_eq!(parsed.nonce, request.nonce);
    }
}
