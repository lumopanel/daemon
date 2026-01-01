//! Package management commands.
//!
//! Provides commands for managing system packages via apt-get:
//! - `package.install` - Install whitelisted packages
//! - `package.remove` - Remove packages
//! - `package.update` - Update package lists
//! - `package.add_repository` - Add whitelisted PPA repositories

mod install;
mod remove;
mod repository;
mod update;

pub use install::InstallPackageCommand;
pub use remove::RemovePackageCommand;
pub use repository::AddRepositoryCommand;
pub use update::UpdatePackageCommand;
