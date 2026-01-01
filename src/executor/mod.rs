//! Command executor module.
//!
//! Handles safe subprocess spawning and execution timeouts.

mod subprocess;
mod timeout;

pub use subprocess::{
    run_command, run_command_sensitive, run_command_with_env, SubprocessBuilder, SubprocessResult,
};
pub use timeout::{sanitize_output, with_timeout};
