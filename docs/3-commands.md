# Commands Overview

The daemon uses a command-based architecture where all operations are implemented as discrete, executable commands. This design provides a consistent interface for all functionality, enables validation and auditing, and makes the system easily extensible.

## Command System Architecture

Commands are the primary extension point for adding new functionality to the daemon. Each command is a self-contained unit that:

- Has a unique identifier (e.g., `file.write`, `service.restart`)
- Validates its input parameters before execution
- Executes the requested operation
- Returns a structured result indicating success or failure

The command system follows a simple flow:

```
Request → Registry Lookup → Validation → Execution → Result
```

## The Command Trait

Every command implements the `Command` trait, defined in `src/commands/traits.rs`:

```rust
pub trait Command: Send + Sync {
    /// Unique command identifier (e.g., "file.write", "service.restart").
    fn name(&self) -> &'static str;

    /// Validate the command parameters before execution.
    fn validate(&self, params: &CommandParams) -> Result<(), DaemonError>;

    /// Execute the command.
    fn execute(
        &self,
        ctx: &ExecutionContext,
        params: CommandParams,
    ) -> Result<CommandResult, DaemonError>;

    /// Timeout for this command (default: 60 seconds).
    fn timeout(&self) -> Duration {
        Duration::from_secs(60)
    }

    /// Whether this command requires audit logging (default: true).
    fn requires_audit(&self) -> bool {
        true
    }
}
```

### Trait Methods

| Method | Required | Description |
|--------|----------|-------------|
| `name()` | Yes | Returns the unique command identifier |
| `validate()` | Yes | Validates parameters before execution |
| `execute()` | Yes | Performs the actual command operation |
| `timeout()` | No | Override for long-running commands (default: 60s) |
| `requires_audit()` | No | Set to `false` for high-frequency queries |

### Example Implementation

```rust
pub struct MyCommand;

impl Command for MyCommand {
    fn name(&self) -> &'static str {
        "my.command"
    }

    fn validate(&self, params: &CommandParams) -> Result<(), DaemonError> {
        params.require_string("required_param")?;
        Ok(())
    }

    fn execute(
        &self,
        ctx: &ExecutionContext,
        params: CommandParams,
    ) -> Result<CommandResult, DaemonError> {
        let value = params.get_string("required_param")?;
        Ok(CommandResult::success(serde_json::json!({"value": value})))
    }
}
```

## CommandParams

`CommandParams` is a wrapper around JSON values that provides type-safe parameter extraction. It offers helper methods for retrieving required and optional parameters.

### Available Methods

| Method | Returns | Description |
|--------|---------|-------------|
| `get_string(key)` | `Result<String, DaemonError>` | Get a required string |
| `get_optional_string(key)` | `Option<String>` | Get an optional string |
| `get_bool(key)` | `Result<bool, DaemonError>` | Get a required boolean |
| `get_optional_bool(key, default)` | `bool` | Get optional boolean with default |
| `get_i64(key)` | `Result<i64, DaemonError>` | Get a required integer |
| `get_optional_i64(key)` | `Option<i64>` | Get an optional integer |
| `get_string_array(key)` | `Result<Vec<String>, DaemonError>` | Get a required string array |
| `get_optional_string_array(key)` | `Option<Vec<String>>` | Get an optional string array |
| `has(key)` | `bool` | Check if a parameter exists |
| `require_string(key)` | `Result<(), DaemonError>` | Validate that a string exists |

### Usage Example

```rust
fn validate(&self, params: &CommandParams) -> Result<(), DaemonError> {
    params.require_string("path")?;  // Required parameter
    Ok(())
}

fn execute(&self, ctx: &ExecutionContext, params: CommandParams) -> Result<CommandResult, DaemonError> {
    let path = params.get_string("path")?;
    let recursive = params.get_optional_bool("recursive", false);
    let mode = params.get_optional_i64("mode");
    // ...
}
```

## CommandResult

`CommandResult` represents the outcome of command execution, containing success status and either result data or error information.

### Structure

```rust
pub struct CommandResult {
    pub success: bool,
    pub data: Option<serde_json::Value>,      // Present on success
    pub error_code: Option<String>,            // Present on failure
    pub error_message: Option<String>,         // Present on failure
}
```

### Factory Methods

| Method | Description |
|--------|-------------|
| `CommandResult::success(data)` | Create a success result with data |
| `CommandResult::success_empty()` | Create a success result without data |
| `CommandResult::failure(code, message)` | Create a failure result |

### Examples

```rust
// Success with data
CommandResult::success(serde_json::json!({
    "path": "/etc/nginx/sites-enabled/example.conf",
    "bytes_written": 1024
}))

// Success without data
CommandResult::success_empty()

// Failure
CommandResult::failure("FILE_NOT_FOUND", "The specified file does not exist")
```

## ExecutionContext

`ExecutionContext` provides metadata about the current request, including information about the connected peer and request details.

### Structure

```rust
pub struct ExecutionContext {
    pub request_id: Uuid,     // Unique identifier for this request
    pub peer: PeerInfo,       // Information about the connected peer
    pub timestamp: u64,       // When the request was received
    pub command: String,      // The command being executed
}
```

### PeerInfo

The `peer` field contains information about the Unix socket connection:

- `uid` - User ID of the connecting process
- `gid` - Group ID of the connecting process
- `pid` - Process ID of the connecting process

This information can be used for authorization decisions or audit logging.

## Command Registration

Commands are registered in the `CommandRegistry`, which is created at daemon startup. The registry maintains a map of command names to command implementations.

### Registration Process

1. Commands are registered in `CommandRegistry::new()` in `src/commands/registry.rs`
2. Each command is wrapped in an `Arc` for thread-safe sharing
3. The command's `name()` is used as the lookup key

```rust
// In CommandRegistry::new()
registry.register(Arc::new(WriteFileCommand));
registry.register(Arc::new(DeleteFileCommand));
registry.register(Arc::new(CreateDirectoryCommand));
```

### Adding a New Command

1. Create a new file in the appropriate subdirectory (e.g., `file/`, `service/`)
2. Implement the `Command` trait
3. Export the command from the module
4. Register the command in `CommandRegistry::new()`

## Command Categories

The daemon organizes commands into categories based on their functionality. Each category has its own module under `src/commands/`.

### System Commands

Health checks and daemon status monitoring.

| Command | Description |
|---------|-------------|
| `system.ping` | Health check that returns "pong" |
| `system.metrics` | Returns daemon performance metrics |

See: [3.1 System Commands](3.1-system-commands.md)

### File Commands

File system operations for managing configuration files and directories.

| Command | Description |
|---------|-------------|
| `file.write` | Write content to a file |
| `file.delete` | Delete a file |
| `file.mkdir` | Create a directory |
| `file.chmod` | Set file permissions |
| `file.write_template` | Render and write a template |

See: [3.2 File Commands](3.2-file-commands.md)

### Service Commands

Systemd service management for controlling daemons.

| Command | Description |
|---------|-------------|
| `service.start` | Start a service |
| `service.stop` | Stop a service |
| `service.restart` | Restart a service |
| `service.reload` | Reload service configuration |
| `service.enable` | Enable service at boot |
| `service.disable` | Disable service at boot |
| `service.status` | Get service status |

See: [3.3 Service Commands](3.3-service-commands.md)

### Package Commands

System package management for installing and updating software.

| Command | Description |
|---------|-------------|
| `package.install` | Install a package |
| `package.remove` | Remove a package |
| `package.update` | Update package lists and packages |
| `package.add_repository` | Add a package repository |

See: [3.4 Package Commands](3.4-package-commands.md)

### Database Commands

MySQL/MariaDB database and user management.

| Command | Description |
|---------|-------------|
| `database.create_db` | Create a database |
| `database.create_user` | Create a database user |
| `database.drop_db` | Drop a database |

See: [3.5 Database Commands](3.5-database-commands.md)

### SSL Commands

SSL/TLS certificate management including Let's Encrypt integration.

| Command | Description |
|---------|-------------|
| `ssl.install_cert` | Install an SSL certificate |
| `ssl.request_letsencrypt` | Request a Let's Encrypt certificate |

See: [3.6 SSL Commands](3.6-ssl-commands.md)

### PHP Commands

PHP version and configuration management.

| Command | Description |
|---------|-------------|
| `php.install_version` | Install a PHP version |
| `php.remove_version` | Remove a PHP version |
| `php.install_extension` | Install a PHP extension |
| `php.write_ini` | Write PHP configuration |

See: [3.7 PHP Commands](3.7-php-commands.md)

### Nginx Commands

Nginx web server configuration management.

| Command | Description |
|---------|-------------|
| `nginx.enable_site` | Enable a site configuration |
| `nginx.disable_site` | Disable a site configuration |
| `nginx.test_config` | Test Nginx configuration validity |

See: [3.8 Nginx Commands](3.8-nginx-commands.md)

### User Commands

System user account management.

| Command | Description |
|---------|-------------|
| `user.create` | Create a system user |
| `user.delete` | Delete a system user |

See: [3.9 User Commands](3.9-user-commands.md)

## Common Patterns

### Calling Commands from the Control Panel

Commands are called by sending a request message over the Unix socket:

```json
{
  "id": "550e8400-e29b-41d4-a716-446655440000",
  "command": "file.write",
  "params": {
    "path": "/etc/nginx/sites-available/example.conf",
    "content": "server { ... }",
    "mode": 420
  },
  "timestamp": 1699900000,
  "nonce": "unique-nonce-value",
  "signature": "base64-signature"
}
```

### Handling Results

Always check the `success` field in the response:

```json
// Success response
{
  "id": "550e8400-e29b-41d4-a716-446655440000",
  "success": true,
  "data": {
    "path": "/etc/nginx/sites-available/example.conf",
    "bytes_written": 256
  }
}

// Error response
{
  "id": "550e8400-e29b-41d4-a716-446655440000",
  "success": false,
  "error_code": "PERMISSION_DENIED",
  "error_message": "Cannot write to path: /etc/nginx/sites-available/example.conf"
}
```

### Chaining Commands

Some operations require multiple commands. For example, creating a new site:

1. `file.write_template` - Write the Nginx configuration
2. `nginx.enable_site` - Enable the site
3. `nginx.test_config` - Verify configuration is valid
4. `service.reload` - Reload Nginx to apply changes

If any step fails, the control panel should handle rollback appropriately.

### Long-Running Commands

Some commands (like package installation) may take longer than the default 60-second timeout. These commands override the `timeout()` method:

```rust
fn timeout(&self) -> Duration {
    Duration::from_secs(300)  // 5 minutes for package operations
}
```

### Disabling Audit Logging

High-frequency commands that would generate excessive logs can disable auditing:

```rust
fn requires_audit(&self) -> bool {
    false  // For status polling commands
}
```

## Adding a New Command (Extensibility Guide)

The command system is designed to be easily extensible. Follow these steps to add a new command.

### Step 1: Choose the Appropriate Module

Commands are organized by category. Place your command in the appropriate module:

| Category | Module Path | Use For |
|----------|-------------|---------|
| System | `src/commands/system/` | Health checks, metrics, daemon status |
| File | `src/commands/file/` | File system operations |
| Service | `src/commands/service/` | Systemd service management |
| Package | `src/commands/package/` | Package installation and management |
| Database | `src/commands/database/` | Database operations |
| SSL | `src/commands/ssl/` | Certificate management |
| PHP | `src/commands/php/` | PHP version and configuration |
| Nginx | `src/commands/nginx/` | Nginx configuration management |
| User | `src/commands/user/` | System user management |

### Step 2: Create the Command File

Create a new file in the appropriate module directory. For example, to add a `file.copy` command:

```rust
// src/commands/file/copy.rs

use std::fs;
use std::time::Duration;

use crate::error::{CommandErrorKind, DaemonError};
use crate::validation::validate_path;

use super::super::traits::Command;
use super::super::types::{CommandParams, CommandResult, ExecutionContext};

/// Copy a file from one location to another.
///
/// # Parameters
///
/// - `source` (required): The source file path
/// - `destination` (required): The destination file path
/// - `overwrite` (optional): Whether to overwrite existing files (default: false)
pub struct CopyFileCommand;

impl Command for CopyFileCommand {
    fn name(&self) -> &'static str {
        "file.copy"
    }

    fn validate(&self, params: &CommandParams) -> Result<(), DaemonError> {
        params.require_string("source")?;
        params.require_string("destination")?;
        Ok(())
    }

    fn execute(
        &self,
        ctx: &ExecutionContext,
        params: CommandParams,
    ) -> Result<CommandResult, DaemonError> {
        let source_str = params.get_string("source")?;
        let dest_str = params.get_string("destination")?;
        let overwrite = params.get_optional_bool("overwrite", false);

        // Validate paths
        let source = validate_path(&source_str)?;
        let destination = validate_path(&dest_str)?;

        // Check if destination exists
        if destination.exists() && !overwrite {
            return Err(DaemonError::Command {
                kind: CommandErrorKind::ExecutionFailed {
                    message: "Destination file already exists".to_string(),
                },
            });
        }

        // Perform the copy
        let bytes_copied = fs::copy(&source, &destination)
            .map_err(|e| DaemonError::Command {
                kind: CommandErrorKind::ExecutionFailed {
                    message: format!("Failed to copy file: {}", e),
                },
            })?;

        Ok(CommandResult::success(serde_json::json!({
            "source": source.to_string_lossy(),
            "destination": destination.to_string_lossy(),
            "bytes_copied": bytes_copied,
        })))
    }

    // Optional: Override timeout for slow operations
    fn timeout(&self) -> Duration {
        Duration::from_secs(120)  // 2 minutes for large files
    }
}
```

### Step 3: Export from the Module

Add your command to the module's `mod.rs` file:

```rust
// src/commands/file/mod.rs

mod copy;
mod delete;
mod directory;
mod permissions;
mod template;
mod write;

pub use copy::CopyFileCommand;
pub use delete::DeleteFileCommand;
// ... other exports
```

### Step 4: Register the Command

Add your command to the registry in `src/commands/registry.rs`:

```rust
// In CommandRegistry::new()

// File commands
registry.register(Arc::new(WriteFileCommand));
registry.register(Arc::new(DeleteFileCommand));
registry.register(Arc::new(CreateDirectoryCommand));
registry.register(Arc::new(SetPermissionsCommand));
registry.register(Arc::new(WriteTemplateCommand::new(template_engine)));
registry.register(Arc::new(CopyFileCommand));  // Add your new command
```

### Step 5: Add Tests

Create unit tests for your command:

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use crate::auth::PeerInfo;
    use uuid::Uuid;

    fn create_test_context() -> ExecutionContext {
        ExecutionContext::new(
            Uuid::new_v4(),
            PeerInfo {
                uid: 1000,
                gid: 1000,
                pid: 12345,
            },
            1234567890,
            "file.copy".to_string(),
        )
    }

    #[test]
    fn test_copy_file_name() {
        let cmd = CopyFileCommand;
        assert_eq!(cmd.name(), "file.copy");
    }

    #[test]
    fn test_copy_file_validate() {
        let cmd = CopyFileCommand;

        // Valid params
        let params = CommandParams::new(serde_json::json!({
            "source": "/tmp/source.txt",
            "destination": "/tmp/dest.txt"
        }));
        assert!(cmd.validate(&params).is_ok());

        // Missing source
        let params = CommandParams::new(serde_json::json!({
            "destination": "/tmp/dest.txt"
        }));
        assert!(cmd.validate(&params).is_err());
    }
}
```

### Best Practices

1. **Naming Convention**: Use the format `category.action` (e.g., `file.copy`, `service.restart`)

2. **Validation First**: Always validate all required parameters in `validate()` before execution

3. **Use Path Validation**: Always use `validate_path()` for file paths to prevent path traversal attacks

4. **Atomic Operations**: For file writes, use atomic write patterns (write to temp file, then rename)

5. **Structured Logging**: Use `tracing` macros with the `request_id` from the execution context:
   ```rust
   use tracing::{debug, info};

   debug!(
       request_id = %ctx.request_id,
       source = %source.display(),
       "Copying file"
   );
   ```

6. **Meaningful Results**: Return useful data in successful results (paths, byte counts, etc.)

7. **Clear Error Messages**: Provide actionable error messages that help diagnose issues

8. **Appropriate Timeouts**: Override `timeout()` for operations that may take longer than 60 seconds

9. **Audit Consideration**: Only disable audit logging for high-frequency, low-risk queries

### Command Dependencies

If your command needs external dependencies (like the template engine), inject them via constructor:

```rust
pub struct MyTemplateCommand {
    template_engine: Arc<TemplateEngine>,
}

impl MyTemplateCommand {
    pub fn new(template_engine: Arc<TemplateEngine>) -> Self {
        Self { template_engine }
    }
}
```

Then in the registry:

```rust
registry.register(Arc::new(MyTemplateCommand::new(template_engine.clone())));
```
