//! Parameter sanitization for audit logging.
//!
//! Removes or redacts sensitive information from command parameters
//! before they are written to the audit log.

use serde_json::{Map, Value};

/// Keys that should be redacted from audit logs.
const SENSITIVE_KEYS: &[&str] = &[
    "password",
    "secret",
    "key",
    "token",
    "credential",
    "private_key",
    "hmac_secret",
    "api_key",
    "auth",
    "authorization",
];

/// Maximum length for string values before truncation.
const MAX_STRING_LENGTH: usize = 1024;

/// Keys whose values should be truncated if too long.
const TRUNCATABLE_KEYS: &[&str] = &["content", "data", "body", "payload"];

/// Sanitize parameters for audit logging.
///
/// This function:
/// 1. Redacts values for sensitive keys (password, secret, etc.)
/// 2. Truncates large string values in content/data fields
/// 3. Recursively processes nested objects and arrays
///
/// # Arguments
///
/// * `params` - The parameters to sanitize
///
/// # Returns
///
/// A sanitized copy of the parameters.
pub fn sanitize_params(params: &Value) -> Value {
    sanitize_value(params, false)
}

/// Recursively sanitize a JSON value.
fn sanitize_value(value: &Value, is_truncatable: bool) -> Value {
    match value {
        Value::Object(map) => {
            let mut sanitized = Map::new();
            for (key, val) in map {
                let key_lower = key.to_lowercase();

                // Check if this key contains a sensitive word
                let is_sensitive = SENSITIVE_KEYS.iter().any(|&s| key_lower.contains(s));

                // Check if this key's value should be truncatable
                let should_truncate = TRUNCATABLE_KEYS.iter().any(|&s| key_lower.contains(s));

                if is_sensitive {
                    sanitized.insert(key.clone(), Value::String("[REDACTED]".to_string()));
                } else {
                    sanitized.insert(key.clone(), sanitize_value(val, should_truncate));
                }
            }
            Value::Object(sanitized)
        }
        Value::Array(arr) => Value::Array(
            arr.iter()
                .map(|v| sanitize_value(v, is_truncatable))
                .collect(),
        ),
        Value::String(s) if is_truncatable && s.len() > MAX_STRING_LENGTH => {
            Value::String(format!("[TRUNCATED - {} bytes]", s.len()))
        }
        _ => value.clone(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn test_sanitize_password() {
        let params = json!({
            "username": "admin",
            "password": "super_secret_123"
        });
        let sanitized = sanitize_params(&params);
        assert_eq!(sanitized["username"], "admin");
        assert_eq!(sanitized["password"], "[REDACTED]");
    }

    #[test]
    fn test_sanitize_various_sensitive_keys() {
        let params = json!({
            "api_key": "key123",
            "secret_token": "token456",
            "auth_header": "Bearer xyz",
            "private_key": "-----BEGIN RSA PRIVATE KEY-----"
        });
        let sanitized = sanitize_params(&params);
        assert_eq!(sanitized["api_key"], "[REDACTED]");
        assert_eq!(sanitized["secret_token"], "[REDACTED]");
        assert_eq!(sanitized["auth_header"], "[REDACTED]");
        assert_eq!(sanitized["private_key"], "[REDACTED]");
    }

    #[test]
    fn test_sanitize_nested_objects() {
        let params = json!({
            "user": {
                "name": "test",
                "login": {
                    "password": "secret"
                }
            }
        });
        let sanitized = sanitize_params(&params);
        assert_eq!(sanitized["user"]["name"], "test");
        assert_eq!(sanitized["user"]["login"]["password"], "[REDACTED]");
    }

    #[test]
    fn test_sanitize_key_containing_sensitive_word() {
        // Keys containing sensitive words should have their values redacted
        let params = json!({
            "user_credentials": {"nested": "data"},
            "my_secret_config": {"value": 123}
        });
        let sanitized = sanitize_params(&params);
        assert_eq!(sanitized["user_credentials"], "[REDACTED]");
        assert_eq!(sanitized["my_secret_config"], "[REDACTED]");
    }

    #[test]
    fn test_sanitize_arrays() {
        let params = json!({
            "users": [
                {"name": "user1", "password": "pass1"},
                {"name": "user2", "password": "pass2"}
            ]
        });
        let sanitized = sanitize_params(&params);
        assert_eq!(sanitized["users"][0]["name"], "user1");
        assert_eq!(sanitized["users"][0]["password"], "[REDACTED]");
        assert_eq!(sanitized["users"][1]["password"], "[REDACTED]");
    }

    #[test]
    fn test_truncate_large_content() {
        let large_content = "x".repeat(2000);
        let params = json!({
            "path": "/tmp/test.txt",
            "content": large_content
        });
        let sanitized = sanitize_params(&params);
        assert_eq!(sanitized["path"], "/tmp/test.txt");
        assert_eq!(sanitized["content"], "[TRUNCATED - 2000 bytes]");
    }

    #[test]
    fn test_small_content_not_truncated() {
        let params = json!({
            "path": "/tmp/test.txt",
            "content": "Hello, World!"
        });
        let sanitized = sanitize_params(&params);
        assert_eq!(sanitized["content"], "Hello, World!");
    }

    #[test]
    fn test_non_sensitive_keys_preserved() {
        let params = json!({
            "path": "/tmp/test.txt",
            "mode": "0644",
            "owner": 1000
        });
        let sanitized = sanitize_params(&params);
        assert_eq!(sanitized["path"], "/tmp/test.txt");
        assert_eq!(sanitized["mode"], "0644");
        assert_eq!(sanitized["owner"], 1000);
    }

    #[test]
    fn test_case_insensitive_sensitive_keys() {
        let params = json!({
            "PASSWORD": "secret1",
            "Api_Key": "secret2",
            "SECRET_TOKEN": "secret3"
        });
        let sanitized = sanitize_params(&params);
        assert_eq!(sanitized["PASSWORD"], "[REDACTED]");
        assert_eq!(sanitized["Api_Key"], "[REDACTED]");
        assert_eq!(sanitized["SECRET_TOKEN"], "[REDACTED]");
    }
}
