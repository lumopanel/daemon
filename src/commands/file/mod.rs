//! File operation commands.
//!
//! Provides commands for file manipulation:
//! - `file.write` - Write content to a file
//! - `file.write_template` - Render and write a template
//! - `file.delete` - Delete a file
//! - `file.mkdir` - Create a directory
//! - `file.chmod` - Set file permissions

mod create_dir;
mod delete;
mod set_permissions;
mod write;
mod write_template;

pub use create_dir::CreateDirectoryCommand;
pub use delete::DeleteFileCommand;
pub use set_permissions::SetPermissionsCommand;
pub use write::WriteFileCommand;
pub use write_template::WriteTemplateCommand;
