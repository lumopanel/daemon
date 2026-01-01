//! Create database command.

use std::time::Duration;

use tracing::{debug, info};

use crate::error::DaemonError;
use crate::executor::{run_command, SubprocessResult};
use crate::validation::{validate_database_name, validate_database_type};

use super::super::traits::Command;
use super::super::types::{CommandParams, CommandResult, ExecutionContext};

/// Default timeout for database operations.
const DEFAULT_TIMEOUT: Duration = Duration::from_secs(30);

/// Create a new database.
///
/// # Parameters
///
/// - `name` (required): The database name (alphanumeric + underscore, 1-64 chars)
/// - `type` (required): Database type ("mysql" or "postgresql")
pub struct CreateDatabaseCommand;

impl Command for CreateDatabaseCommand {
    fn name(&self) -> &'static str {
        "database.create_db"
    }

    fn validate(&self, params: &CommandParams) -> Result<(), DaemonError> {
        params.require_string("name")?;
        params.require_string("type")?;
        let name = params.get_string("name")?;
        let db_type = params.get_string("type")?;
        validate_database_name(&name)?;
        validate_database_type(&db_type)?;
        Ok(())
    }

    fn execute(
        &self,
        ctx: &ExecutionContext,
        params: CommandParams,
    ) -> Result<CommandResult, DaemonError> {
        let name = params.get_string("name")?;
        let db_type = params.get_string("type")?;

        // Re-validate for safety
        validate_database_name(&name)?;
        validate_database_type(&db_type)?;

        debug!(
            request_id = %ctx.request_id,
            name = name,
            db_type = db_type,
            "Creating database"
        );

        let result = match db_type.to_lowercase().as_str() {
            "mysql" => create_mysql_database(&name)?,
            "postgresql" => create_postgresql_database(&name)?,
            _ => unreachable!("Database type was validated"),
        };

        if result.success {
            info!(
                request_id = %ctx.request_id,
                name = name,
                db_type = db_type,
                "Database created successfully"
            );

            Ok(CommandResult::success(serde_json::json!({
                "name": name,
                "type": db_type,
                "created": true,
            })))
        } else {
            Ok(CommandResult::failure(
                "DATABASE_CREATE_FAILED",
                format!(
                    "Failed to create database: {}",
                    result.stderr.trim()
                ),
            ))
        }
    }
}

/// Create a MySQL database.
fn create_mysql_database(name: &str) -> Result<SubprocessResult, DaemonError> {
    let sql = format!("CREATE DATABASE IF NOT EXISTS `{}`", name);
    run_command("mysql", &["-e", &sql], DEFAULT_TIMEOUT)
}

/// Create a PostgreSQL database.
fn create_postgresql_database(name: &str) -> Result<SubprocessResult, DaemonError> {
    // Use createdb utility which handles quoting
    run_command("createdb", &[name], DEFAULT_TIMEOUT)
}

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
            "database.create_db".to_string(),
        )
    }

    #[test]
    fn test_command_name() {
        let cmd = CreateDatabaseCommand;
        assert_eq!(cmd.name(), "database.create_db");
    }

    #[test]
    fn test_validate_valid_params() {
        let cmd = CreateDatabaseCommand;
        let params = CommandParams::new(serde_json::json!({
            "name": "my_database",
            "type": "mysql"
        }));
        assert!(cmd.validate(&params).is_ok());
    }

    #[test]
    fn test_validate_missing_name() {
        let cmd = CreateDatabaseCommand;
        let params = CommandParams::new(serde_json::json!({
            "type": "mysql"
        }));
        assert!(cmd.validate(&params).is_err());
    }

    #[test]
    fn test_validate_missing_type() {
        let cmd = CreateDatabaseCommand;
        let params = CommandParams::new(serde_json::json!({
            "name": "my_database"
        }));
        assert!(cmd.validate(&params).is_err());
    }

    #[test]
    fn test_validate_invalid_name() {
        let cmd = CreateDatabaseCommand;
        let params = CommandParams::new(serde_json::json!({
            "name": "my-database",
            "type": "mysql"
        }));
        assert!(cmd.validate(&params).is_err());
    }

    #[test]
    fn test_validate_invalid_type() {
        let cmd = CreateDatabaseCommand;
        let params = CommandParams::new(serde_json::json!({
            "name": "my_database",
            "type": "sqlite"
        }));
        assert!(cmd.validate(&params).is_err());
    }
}
