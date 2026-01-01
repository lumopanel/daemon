//! Command handlers module.
//!
//! Contains the command registry and all command implementations.
//!
//! ## Adding a New Command
//!
//! 1. Create a new file in the appropriate subdirectory (e.g., `file/`, `service/`)
//! 2. Implement the `Command` trait
//! 3. Register the command in `CommandRegistry::new()`

mod registry;
mod traits;
mod types;

pub mod database;
pub mod file;
pub mod nginx;
pub mod package;
pub mod php;
pub mod service;
pub mod ssl;
pub mod system;
pub mod user;

pub use registry::CommandRegistry;
pub use traits::Command;
pub use types::{CommandParams, CommandResult, ExecutionContext};
