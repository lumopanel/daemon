//! In-memory nonce store for replay attack prevention.

use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{Duration, Instant};

/// Thread-safe in-memory nonce store with TTL-based expiry.
pub struct NonceStore {
    /// Map of nonce -> expiry time.
    nonces: Mutex<HashMap<String, Instant>>,
    /// Time-to-live for nonces.
    ttl: Duration,
}

impl NonceStore {
    /// Create a new nonce store with the given TTL.
    pub fn new(ttl: Duration) -> Self {
        Self {
            nonces: Mutex::new(HashMap::new()),
            ttl,
        }
    }

    /// Check if a nonce has been used, and store it if not.
    ///
    /// Returns `true` if the nonce is new (valid), `false` if already used.
    pub async fn check_and_store(&self, nonce: &str) -> bool {
        self.check_and_store_sync(nonce)
    }

    /// Synchronous version of check_and_store (for internal use).
    fn check_and_store_sync(&self, nonce: &str) -> bool {
        let mut nonces = match self.nonces.lock() {
            Ok(guard) => guard,
            Err(poisoned) => poisoned.into_inner(), // Recover from mutex poisoning
        };
        let now = Instant::now();

        // Clean up expired nonces (lazy cleanup)
        nonces.retain(|_, expiry| *expiry > now);

        // Check if nonce already exists
        if nonces.contains_key(nonce) {
            return false;
        }

        // Store the new nonce with expiry
        let expiry = now + self.ttl;
        nonces.insert(nonce.to_string(), expiry);

        true
    }

    /// Get the current number of stored nonces (for monitoring).
    pub fn len(&self) -> usize {
        match self.nonces.lock() {
            Ok(guard) => guard.len(),
            Err(poisoned) => poisoned.into_inner().len(),
        }
    }

    /// Check if the store is empty.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Force cleanup of expired nonces.
    pub fn cleanup(&self) {
        let mut nonces = match self.nonces.lock() {
            Ok(guard) => guard,
            Err(poisoned) => poisoned.into_inner(),
        };
        let now = Instant::now();
        nonces.retain(|_, expiry| *expiry > now);
    }

    /// Start a background cleanup task.
    ///
    /// This spawns a tokio task that periodically cleans up expired nonces.
    pub fn start_cleanup_task(self: &std::sync::Arc<Self>, interval: Duration) {
        let store = std::sync::Arc::clone(self);
        tokio::spawn(async move {
            let mut interval_timer = tokio::time::interval(interval);
            loop {
                interval_timer.tick().await;
                store.cleanup();
            }
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_new_nonce_accepted() {
        let store = NonceStore::new(Duration::from_secs(60));
        assert!(store.check_and_store("nonce1").await);
        assert!(store.check_and_store("nonce2").await);
    }

    #[tokio::test]
    async fn test_duplicate_nonce_rejected() {
        let store = NonceStore::new(Duration::from_secs(60));
        assert!(store.check_and_store("nonce1").await);
        assert!(!store.check_and_store("nonce1").await);
    }

    #[tokio::test]
    async fn test_expired_nonce_cleaned_up() {
        // Use a very short TTL
        let store = NonceStore::new(Duration::from_millis(10));
        assert!(store.check_and_store("nonce1").await);

        // Wait for expiry
        tokio::time::sleep(Duration::from_millis(20)).await;

        // Nonce should be cleaned up and accepted again
        assert!(store.check_and_store("nonce1").await);
    }

    #[test]
    fn test_len_and_cleanup() {
        let store = NonceStore::new(Duration::from_secs(60));
        store.check_and_store_sync("nonce1");
        store.check_and_store_sync("nonce2");
        assert_eq!(store.len(), 2);

        store.cleanup();
        assert_eq!(store.len(), 2); // Not expired yet
    }
}
