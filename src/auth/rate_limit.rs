//! Per-UID rate limiting.
//!
//! Provides a sliding window rate limiter to prevent abuse by limiting
//! the number of requests a single UID can make within a time window.

use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{Duration, Instant};

/// A sliding window rate limiter that tracks requests per UID.
///
/// Uses a time-based sliding window to limit requests. Each UID can make
/// at most `max_requests` within `window` duration.
pub struct RateLimiter {
    /// Request timestamps per UID
    requests: Mutex<HashMap<u32, Vec<Instant>>>,
    /// Maximum requests allowed per window
    max_requests: usize,
    /// Time window for rate limiting
    window: Duration,
}

impl RateLimiter {
    /// Create a new rate limiter.
    ///
    /// # Arguments
    ///
    /// * `max_requests` - Maximum requests allowed per window
    /// * `window_seconds` - Duration of the sliding window in seconds
    pub fn new(max_requests: usize, window_seconds: u64) -> Self {
        Self {
            requests: Mutex::new(HashMap::new()),
            max_requests,
            window: Duration::from_secs(window_seconds),
        }
    }

    /// Check if a request from the given UID is allowed and record it.
    ///
    /// Returns `true` if the request is allowed, `false` if rate limited.
    pub fn check_and_record(&self, uid: u32) -> bool {
        let mut requests = self.requests.lock().unwrap_or_else(|e| e.into_inner());
        let now = Instant::now();
        let cutoff = now - self.window;

        let entry = requests.entry(uid).or_default();

        // Remove old requests outside the window
        entry.retain(|&t| t > cutoff);

        if entry.len() >= self.max_requests {
            return false; // Rate limited
        }

        entry.push(now);
        true
    }

    /// Check if a request from the given UID would be allowed without recording.
    ///
    /// Returns `true` if a request would be allowed, `false` if rate limited.
    #[allow(dead_code)]
    pub fn check(&self, uid: u32) -> bool {
        let requests = self.requests.lock().unwrap_or_else(|e| e.into_inner());
        let cutoff = Instant::now() - self.window;

        if let Some(times) = requests.get(&uid) {
            let valid_requests = times.iter().filter(|&&t| t > cutoff).count();
            valid_requests < self.max_requests
        } else {
            true
        }
    }

    /// Periodically clean up stale entries.
    ///
    /// This should be called periodically to prevent unbounded memory growth.
    pub fn cleanup(&self) {
        let mut requests = self.requests.lock().unwrap_or_else(|e| e.into_inner());
        let cutoff = Instant::now() - self.window;

        requests.retain(|_, times| {
            times.retain(|&t| t > cutoff);
            !times.is_empty()
        });
    }

    /// Get the number of UIDs being tracked.
    #[allow(dead_code)]
    pub fn tracked_uids(&self) -> usize {
        self.requests
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .len()
    }

    /// Start a background cleanup task.
    ///
    /// This spawns a tokio task that periodically cleans up stale rate limit entries
    /// to prevent unbounded memory growth.
    pub fn start_cleanup_task(self: &std::sync::Arc<Self>, interval: Duration) {
        let limiter = std::sync::Arc::clone(self);
        tokio::spawn(async move {
            let mut interval_timer = tokio::time::interval(interval);
            loop {
                interval_timer.tick().await;
                limiter.cleanup();
            }
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::thread;

    #[test]
    fn test_rate_limiter_allows_under_limit() {
        let limiter = RateLimiter::new(5, 60);

        // Should allow up to 5 requests
        for _ in 0..5 {
            assert!(limiter.check_and_record(1000));
        }
    }

    #[test]
    fn test_rate_limiter_blocks_over_limit() {
        let limiter = RateLimiter::new(3, 60);

        // Should allow 3 requests
        assert!(limiter.check_and_record(1000));
        assert!(limiter.check_and_record(1000));
        assert!(limiter.check_and_record(1000));

        // Should block the 4th request
        assert!(!limiter.check_and_record(1000));
    }

    #[test]
    fn test_rate_limiter_separate_uids() {
        let limiter = RateLimiter::new(2, 60);

        // UID 1000 gets 2 requests
        assert!(limiter.check_and_record(1000));
        assert!(limiter.check_and_record(1000));
        assert!(!limiter.check_and_record(1000));

        // UID 1001 should still be allowed
        assert!(limiter.check_and_record(1001));
        assert!(limiter.check_and_record(1001));
        assert!(!limiter.check_and_record(1001));
    }

    #[test]
    fn test_rate_limiter_window_expiry() {
        // Very short window for testing
        let limiter = RateLimiter::new(2, 1);

        // Exhaust the limit
        assert!(limiter.check_and_record(1000));
        assert!(limiter.check_and_record(1000));
        assert!(!limiter.check_and_record(1000));

        // Wait for window to expire
        thread::sleep(Duration::from_secs(2));

        // Should be allowed again
        assert!(limiter.check_and_record(1000));
    }

    #[test]
    fn test_rate_limiter_cleanup() {
        let limiter = RateLimiter::new(10, 1);

        // Add requests from multiple UIDs
        limiter.check_and_record(1000);
        limiter.check_and_record(1001);
        limiter.check_and_record(1002);

        assert_eq!(limiter.tracked_uids(), 3);

        // Wait for window to expire
        thread::sleep(Duration::from_secs(2));

        // Cleanup should remove all entries
        limiter.cleanup();
        assert_eq!(limiter.tracked_uids(), 0);
    }

    #[test]
    fn test_check_without_recording() {
        let limiter = RateLimiter::new(2, 60);

        // Check without recording
        assert!(limiter.check(1000));

        // Record two requests
        limiter.check_and_record(1000);
        limiter.check_and_record(1000);

        // Check should show rate limited
        assert!(!limiter.check(1000));

        // But another UID should still be ok
        assert!(limiter.check(1001));
    }
}
