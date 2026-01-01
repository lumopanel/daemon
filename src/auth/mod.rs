//! Authentication module.
//!
//! Handles peer credential verification, HMAC signing, nonce tracking,
//! and per-UID rate limiting.

mod hmac;
mod nonce;
mod peer_creds;
mod rate_limit;

pub use hmac::HmacValidator;
pub use nonce::NonceStore;
pub use peer_creds::{verify_peer, PeerInfo};
pub use rate_limit::RateLimiter;
