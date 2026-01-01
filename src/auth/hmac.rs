//! HMAC-SHA256 request signing and verification.

use std::path::Path;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use ring::hmac;

use crate::error::{AuthErrorKind, DaemonError};
use crate::protocol::SignedRequest;

use super::NonceStore;

/// HMAC validator for request authentication.
pub struct HmacValidator {
    key: hmac::Key,
    nonce_store: Arc<NonceStore>,
    max_age: Duration,
}

impl HmacValidator {
    /// Create a new HMAC validator.
    pub fn new(secret: &[u8], nonce_store: Arc<NonceStore>, max_age_seconds: u64) -> Self {
        let key = hmac::Key::new(hmac::HMAC_SHA256, secret);
        Self {
            key,
            nonce_store,
            max_age: Duration::from_secs(max_age_seconds),
        }
    }

    /// Load HMAC secret from a file.
    ///
    /// Security: Verifies the file has restrictive permissions (0600 or 0400)
    /// before loading to prevent secrets from being readable by other users.
    pub fn load_secret(path: &Path) -> Result<Vec<u8>, DaemonError> {
        // Check file permissions first
        let metadata = std::fs::metadata(path).map_err(|e| DaemonError::Auth {
            kind: AuthErrorKind::HmacSecretError {
                message: format!(
                    "Failed to read HMAC secret metadata from {}: {}",
                    path.display(),
                    e
                ),
            },
        })?;

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = metadata.permissions().mode();
            // Check that group and world bits are all zero (only owner can access)
            if mode & 0o077 != 0 {
                return Err(DaemonError::Auth {
                    kind: AuthErrorKind::HmacSecretError {
                        message: format!(
                            "HMAC secret file {} has insecure permissions {:04o}, expected 0600 or 0400",
                            path.display(),
                            mode & 0o777
                        ),
                    },
                });
            }
        }

        std::fs::read(path).map_err(|e| DaemonError::Auth {
            kind: AuthErrorKind::HmacSecretError {
                message: format!("Failed to read HMAC secret from {}: {}", path.display(), e),
            },
        })
    }

    /// Validate a signed request.
    ///
    /// Checks:
    /// 1. Request is not expired (timestamp within max_age)
    /// 2. Signature is valid
    /// 3. Nonce has not been used before
    pub async fn validate(&self, request: &SignedRequest) -> Result<(), DaemonError> {
        // 1. Check timestamp freshness
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|e| DaemonError::Auth {
                kind: AuthErrorKind::HmacSecretError {
                    message: format!("System time error: {}", e),
                },
            })?
            .as_secs();

        let age = now.saturating_sub(request.timestamp);
        if age > self.max_age.as_secs() {
            return Err(DaemonError::Auth {
                kind: AuthErrorKind::RequestExpired { age_seconds: age },
            });
        }

        // Also reject requests from the future (clock skew protection)
        if request.timestamp > now + 60 {
            return Err(DaemonError::Auth {
                kind: AuthErrorKind::RequestExpired {
                    age_seconds: request.timestamp - now,
                },
            });
        }

        // 2. Verify signature
        let message = request.signing_message();
        let signature_bytes = hex::decode(&request.signature).map_err(|_| DaemonError::Auth {
            kind: AuthErrorKind::InvalidSignature,
        })?;

        hmac::verify(&self.key, message.as_bytes(), &signature_bytes).map_err(|_| {
            DaemonError::Auth {
                kind: AuthErrorKind::InvalidSignature,
            }
        })?;

        // 3. Check nonce (replay prevention)
        if !self.nonce_store.check_and_store(&request.nonce).await {
            return Err(DaemonError::Auth {
                kind: AuthErrorKind::NonceReused,
            });
        }

        Ok(())
    }

    /// Sign a request (for testing purposes).
    #[cfg(test)]
    pub fn sign(&self, request: &mut SignedRequest) {
        let message = request.signing_message();
        let tag = hmac::sign(&self.key, message.as_bytes());
        request.signature = hex::encode(tag.as_ref());
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocol::SignedRequest;

    fn create_test_validator() -> HmacValidator {
        let secret = b"test-secret-key-32-bytes-long!!";
        let nonce_store = Arc::new(NonceStore::new(Duration::from_secs(300)));
        HmacValidator::new(secret, nonce_store, 60)
    }

    #[tokio::test]
    async fn test_valid_signature() {
        let validator = create_test_validator();

        let mut request = SignedRequest::new("test.command");
        validator.sign(&mut request);

        let result = validator.validate(&request).await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_invalid_signature() {
        let validator = create_test_validator();

        let mut request = SignedRequest::new("test.command");
        request.signature = "invalid_signature".to_string();

        let result = validator.validate(&request).await;
        assert!(matches!(
            result,
            Err(DaemonError::Auth {
                kind: AuthErrorKind::InvalidSignature
            })
        ));
    }

    #[tokio::test]
    async fn test_expired_request() {
        let validator = create_test_validator();

        let mut request = SignedRequest::new("test.command");
        request.timestamp = 1000; // Very old timestamp
        validator.sign(&mut request);

        let result = validator.validate(&request).await;
        assert!(matches!(
            result,
            Err(DaemonError::Auth {
                kind: AuthErrorKind::RequestExpired { .. }
            })
        ));
    }

    #[tokio::test]
    async fn test_nonce_reuse() {
        let validator = create_test_validator();

        let mut request = SignedRequest::new("test.command");
        validator.sign(&mut request);

        // First request should succeed
        let result = validator.validate(&request).await;
        assert!(result.is_ok());

        // Same nonce should fail
        let result = validator.validate(&request).await;
        assert!(matches!(
            result,
            Err(DaemonError::Auth {
                kind: AuthErrorKind::NonceReused
            })
        ));
    }
}
