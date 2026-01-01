//! Create database user command.

use std::time::Duration;

use tracing::{debug, info};

use crate::error::DaemonError;
use crate::executor::{run_command_sensitive, SubprocessResult};
use crate::validation::{
    validate_database_name, validate_database_type, validate_database_username,
};

use super::super::traits::Command;
use super::super::types::{CommandParams, CommandResult, ExecutionContext};

/// Default timeout for database operations.
const DEFAULT_TIMEOUT: Duration = Duration::from_secs(30);

/// Create a new database user with access to a specific database.
///
/// # Parameters
///
/// - `username` (required): The username (alphanumeric + underscore, 1-32 chars)
/// - `password` (required): The password for the user
/// - `database` (required): The database to grant access to
/// - `type` (required): Database type ("mysql" or "postgresql")
pub struct CreateDatabaseUserCommand;

impl Command for CreateDatabaseUserCommand {
    fn name(&self) -> &'static str {
        "database.create_user"
    }

    fn validate(&self, params: &CommandParams) -> Result<(), DaemonError> {
        params.require_string("username")?;
        params.require_string("password")?;
        params.require_string("database")?;
        params.require_string("type")?;

        let username = params.get_string("username")?;
        let database = params.get_string("database")?;
        let db_type = params.get_string("type")?;

        validate_database_username(&username)?;
        validate_database_name(&database)?;
        validate_database_type(&db_type)?;
        Ok(())
    }

    fn execute(
        &self,
        ctx: &ExecutionContext,
        params: CommandParams,
    ) -> Result<CommandResult, DaemonError> {
        let username = params.get_string("username")?;
        let password = params.get_string("password")?;
        let database = params.get_string("database")?;
        let db_type = params.get_string("type")?;

        // Re-validate for safety
        validate_database_username(&username)?;
        validate_database_name(&database)?;
        validate_database_type(&db_type)?;

        debug!(
            request_id = %ctx.request_id,
            username = username,
            database = database,
            db_type = db_type,
            "Creating database user"
        );

        let result = match db_type.to_lowercase().as_str() {
            "mysql" => create_mysql_user(&username, &password, &database)?,
            "postgresql" => create_postgresql_user(&username, &password, &database)?,
            _ => unreachable!("Database type was validated"),
        };

        if result.success {
            info!(
                request_id = %ctx.request_id,
                username = username,
                database = database,
                db_type = db_type,
                "Database user created successfully"
            );

            Ok(CommandResult::success(serde_json::json!({
                "username": username,
                "database": database,
                "type": db_type,
                "created": true,
            })))
        } else {
            Ok(CommandResult::failure(
                "USER_CREATE_FAILED",
                format!("Failed to create database user: {}", result.stderr.trim()),
            ))
        }
    }
}

/// Escape a string for use in MySQL single-quoted string literal.
/// Handles all special characters that could break out of the string context.
fn escape_mysql_string(s: &str) -> String {
    let mut result = String::with_capacity(s.len() * 2);
    for c in s.chars() {
        match c {
            '\'' => result.push_str("''"),
            '\\' => result.push_str("\\\\"),
            '\0' => result.push_str("\\0"),
            '\n' => result.push_str("\\n"),
            '\r' => result.push_str("\\r"),
            '\x1a' => result.push_str("\\Z"), // Ctrl+Z
            _ => result.push(c),
        }
    }
    result
}

/// Escape a string for use in PostgreSQL single-quoted string literal.
/// Uses the escape string syntax (E'...') for proper handling.
fn escape_postgresql_string(s: &str) -> String {
    let mut result = String::with_capacity(s.len() * 2);
    for c in s.chars() {
        match c {
            '\'' => result.push_str("''"),
            '\\' => result.push_str("\\\\"),
            _ => result.push(c),
        }
    }
    result
}

/// Create a MySQL user with access to a database.
fn create_mysql_user(
    username: &str,
    password: &str,
    database: &str,
) -> Result<SubprocessResult, DaemonError> {
    // Create user and grant privileges in one transaction
    // Using single quotes for password and backticks for identifiers
    // Username and database are validated to contain only safe characters
    let escaped_password = escape_mysql_string(password);
    let sql = format!(
        "CREATE USER IF NOT EXISTS '{}'@'localhost' IDENTIFIED BY '{}'; \
         GRANT ALL PRIVILEGES ON `{}`.* TO '{}'@'localhost'; \
         FLUSH PRIVILEGES;",
        username, escaped_password, database, username
    );
    run_command_sensitive("mysql", &["-e", &sql], DEFAULT_TIMEOUT)
}

/// Create a PostgreSQL user with access to a database.
fn create_postgresql_user(
    username: &str,
    password: &str,
    database: &str,
) -> Result<SubprocessResult, DaemonError> {
    // Create user first - using E'' syntax for escape string and quoting identifiers
    // Username and database are validated to contain only safe characters
    let escaped_password = escape_postgresql_string(password);
    let create_sql = format!(
        "CREATE USER \"{}\" WITH PASSWORD E'{}';",
        username, escaped_password
    );
    let create_result = run_command_sensitive("psql", &["-c", &create_sql], DEFAULT_TIMEOUT)?;
    if !create_result.success {
        return Ok(create_result);
    }

    // Grant privileges on the database - using double quotes for identifiers
    let grant_sql = format!(
        "GRANT ALL PRIVILEGES ON DATABASE \"{}\" TO \"{}\";",
        database, username
    );
    run_command_sensitive("psql", &["-c", &grant_sql], DEFAULT_TIMEOUT)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::auth::PeerInfo;
    use uuid::Uuid;

    #[allow(dead_code)]
    fn create_test_context() -> ExecutionContext {
        ExecutionContext::new(
            Uuid::new_v4(),
            PeerInfo {
                uid: 1000,
                gid: 1000,
                pid: 12345,
            },
            1234567890,
            "database.create_user".to_string(),
        )
    }

    #[test]
    fn test_command_name() {
        let cmd = CreateDatabaseUserCommand;
        assert_eq!(cmd.name(), "database.create_user");
    }

    #[test]
    fn test_validate_valid_params() {
        let cmd = CreateDatabaseUserCommand;
        let params = CommandParams::new(serde_json::json!({
            "username": "app_user",
            "password": "secret123",
            "database": "my_database",
            "type": "mysql"
        }));
        assert!(cmd.validate(&params).is_ok());
    }

    #[test]
    fn test_validate_missing_username() {
        let cmd = CreateDatabaseUserCommand;
        let params = CommandParams::new(serde_json::json!({
            "password": "secret123",
            "database": "my_database",
            "type": "mysql"
        }));
        assert!(cmd.validate(&params).is_err());
    }

    #[test]
    fn test_validate_missing_password() {
        let cmd = CreateDatabaseUserCommand;
        let params = CommandParams::new(serde_json::json!({
            "username": "app_user",
            "database": "my_database",
            "type": "mysql"
        }));
        assert!(cmd.validate(&params).is_err());
    }

    #[test]
    fn test_validate_invalid_username() {
        let cmd = CreateDatabaseUserCommand;
        let params = CommandParams::new(serde_json::json!({
            "username": "app-user",
            "password": "secret123",
            "database": "my_database",
            "type": "mysql"
        }));
        assert!(cmd.validate(&params).is_err());
    }

    // Tests for escape_mysql_string
    #[test]
    fn test_escape_mysql_string_no_special_chars() {
        assert_eq!(escape_mysql_string("password123"), "password123");
    }

    #[test]
    fn test_escape_mysql_string_single_quote() {
        assert_eq!(escape_mysql_string("pass'word"), "pass''word");
        assert_eq!(escape_mysql_string("'test'"), "''test''");
    }

    #[test]
    fn test_escape_mysql_string_backslash() {
        assert_eq!(escape_mysql_string("pass\\word"), "pass\\\\word");
        assert_eq!(escape_mysql_string("\\\\"), "\\\\\\\\");
    }

    #[test]
    fn test_escape_mysql_string_null_byte() {
        assert_eq!(escape_mysql_string("pass\0word"), "pass\\0word");
    }

    #[test]
    fn test_escape_mysql_string_newline() {
        assert_eq!(escape_mysql_string("pass\nword"), "pass\\nword");
        assert_eq!(escape_mysql_string("pass\rword"), "pass\\rword");
    }

    #[test]
    fn test_escape_mysql_string_ctrl_z() {
        assert_eq!(escape_mysql_string("pass\x1aword"), "pass\\Zword");
    }

    #[test]
    fn test_escape_mysql_string_complex() {
        // Test multiple special characters together
        assert_eq!(
            escape_mysql_string("it's a \"test\" with \\ and \n"),
            "it''s a \"test\" with \\\\ and \\n"
        );
    }

    #[test]
    fn test_escape_mysql_string_empty() {
        assert_eq!(escape_mysql_string(""), "");
    }

    // Tests for escape_postgresql_string
    #[test]
    fn test_escape_postgresql_string_no_special_chars() {
        assert_eq!(escape_postgresql_string("password123"), "password123");
    }

    #[test]
    fn test_escape_postgresql_string_single_quote() {
        assert_eq!(escape_postgresql_string("pass'word"), "pass''word");
        assert_eq!(escape_postgresql_string("'test'"), "''test''");
    }

    #[test]
    fn test_escape_postgresql_string_backslash() {
        assert_eq!(escape_postgresql_string("pass\\word"), "pass\\\\word");
    }

    #[test]
    fn test_escape_postgresql_string_complex() {
        assert_eq!(
            escape_postgresql_string("it's a \\test\\"),
            "it''s a \\\\test\\\\"
        );
    }

    #[test]
    fn test_escape_postgresql_string_empty() {
        assert_eq!(escape_postgresql_string(""), "");
    }
}
