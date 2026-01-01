//! Drop database command.

use std::time::Duration;

use tracing::{info, warn};

use crate::error::DaemonError;
use crate::executor::{run_command, SubprocessResult};
use crate::validation::{validate_database_name, validate_database_type};

use super::super::traits::Command;
use super::super::types::{CommandParams, CommandResult, ExecutionContext};

/// Default timeout for database operations.
const DEFAULT_TIMEOUT: Duration = Duration::from_secs(30);

/// Drop an existing database.
///
/// # Parameters
///
/// - `name` (required): The database name (alphanumeric + underscore, 1-64 chars)
/// - `type` (required): Database type ("mysql" or "postgresql")
///
/// # Warning
///
/// This is a destructive operation and will permanently delete all data.
pub struct DropDatabaseCommand;

impl Command for DropDatabaseCommand {
    fn name(&self) -> &'static str {
        "database.drop_db"
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

        warn!(
            request_id = %ctx.request_id,
            name = name,
            db_type = db_type,
            "Dropping database (destructive operation)"
        );

        let result = match db_type.to_lowercase().as_str() {
            "mysql" => drop_mysql_database(&name)?,
            "postgresql" => drop_postgresql_database(&name)?,
            _ => unreachable!("Database type was validated"),
        };

        if result.success {
            info!(
                request_id = %ctx.request_id,
                name = name,
                db_type = db_type,
                "Database dropped successfully"
            );

            Ok(CommandResult::success(serde_json::json!({
                "name": name,
                "type": db_type,
                "dropped": true,
            })))
        } else {
            Ok(CommandResult::failure(
                "DATABASE_DROP_FAILED",
                format!(
                    "Failed to drop database: {}",
                    result.stderr.trim()
                ),
            ))
        }
    }
}

/// Drop a MySQL database.
fn drop_mysql_database(name: &str) -> Result<SubprocessResult, DaemonError> {
    let sql = format!("DROP DATABASE IF EXISTS `{}`", name);
    run_command("mysql", &["-e", &sql], DEFAULT_TIMEOUT)
}

/// Drop a PostgreSQL database.
fn drop_postgresql_database(name: &str) -> Result<SubprocessResult, DaemonError> {
    // Use dropdb utility which handles quoting
    // --if-exists prevents errors if database doesn't exist
    run_command("dropdb", &["--if-exists", name], DEFAULT_TIMEOUT)
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
            "database.drop_db".to_string(),
        )
    }

    #[test]
    fn test_command_name() {
        let cmd = DropDatabaseCommand;
        assert_eq!(cmd.name(), "database.drop_db");
    }

    #[test]
    fn test_validate_valid_params() {
        let cmd = DropDatabaseCommand;
        let params = CommandParams::new(serde_json::json!({
            "name": "old_database",
            "type": "mysql"
        }));
        assert!(cmd.validate(&params).is_ok());
    }

    #[test]
    fn test_validate_missing_name() {
        let cmd = DropDatabaseCommand;
        let params = CommandParams::new(serde_json::json!({
            "type": "mysql"
        }));
        assert!(cmd.validate(&params).is_err());
    }

    #[test]
    fn test_validate_reserved_name() {
        let cmd = DropDatabaseCommand;
        let params = CommandParams::new(serde_json::json!({
            "name": "mysql",
            "type": "mysql"
        }));
        // Should fail because 'mysql' is a reserved name
        assert!(cmd.validate(&params).is_err());
    }
}
