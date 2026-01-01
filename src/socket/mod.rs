//! Unix socket server module.
//!
//! Handles Unix socket listening and connection management.

mod connection;
mod listener;

pub use connection::handle_connection;
pub use listener::{ConnectionMetrics, SocketListener};
