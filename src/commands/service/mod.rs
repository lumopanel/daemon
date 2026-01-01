//! Service management commands.
//!
//! Provides commands for controlling system services via systemctl:
//! - `service.start` - Start a service
//! - `service.stop` - Stop a service
//! - `service.restart` - Restart a service
//! - `service.reload` - Reload service configuration
//! - `service.enable` - Enable service at boot
//! - `service.disable` - Disable service at boot
//! - `service.status` - Get service status

mod control;
mod enable;
mod status;

pub use control::{ReloadServiceCommand, RestartServiceCommand, StartServiceCommand, StopServiceCommand};
pub use enable::{DisableServiceCommand, EnableServiceCommand};
pub use status::StatusServiceCommand;
