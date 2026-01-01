//! Wire protocol module.
//!
//! Defines request/response types and message framing for socket communication.
//!
//! ## Wire Format
//!
//! Messages are length-prefixed JSON:
//! ```text
//! [4 bytes: length (big-endian u32)][JSON payload]
//! ```

mod request;
mod response;
mod wire;

pub use request::SignedRequest;
pub use response::{ErrorResponse, Response};
pub use wire::{read_message, read_message_with_timeout, write_message, write_message_with_timeout};
