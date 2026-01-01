//! Audit logger for writing audit entries to file.
//!
//! Writes structured audit entries as JSON lines (one JSON object per line)
//! for easy parsing by log analysis tools.

use std::fs::{File, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::Mutex;

use tracing::{debug, warn};

use crate::error::DaemonError;

use super::entry::AuditEntry;

/// Logger for audit entries.
///
/// Writes audit entries to a file in JSON lines format.
/// Thread-safe via internal mutex.
pub struct AuditLogger {
    /// The file handle wrapped in a mutex for thread safety.
    file: Mutex<File>,
    /// Path to the audit log file.
    path: PathBuf,
}

impl AuditLogger {
    /// Create a new audit logger that writes to the specified path.
    ///
    /// Creates the parent directory if it doesn't exist.
    /// Opens the file in append mode.
    ///
    /// # Arguments
    ///
    /// * `path` - Path to the audit log file
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - Parent directory cannot be created
    /// - File cannot be opened for appending
    pub fn new(path: &Path) -> Result<Self, DaemonError> {
        // Create parent directory if needed
        if let Some(parent) = path.parent() {
            if !parent.exists() {
                debug!(path = %parent.display(), "Creating audit log directory");
                std::fs::create_dir_all(parent)?;
            }
        }

        // Open file in append mode
        let file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(path)?;

        debug!(path = %path.display(), "Audit logger initialized");

        Ok(Self {
            file: Mutex::new(file),
            path: path.to_path_buf(),
        })
    }

    /// Log an audit entry.
    ///
    /// Serializes the entry to JSON and writes it as a single line.
    /// Syncs the file after writing for durability.
    ///
    /// # Arguments
    ///
    /// * `entry` - The audit entry to log
    ///
    /// # Errors
    ///
    /// Returns an error if serialization or writing fails.
    pub fn log(&self, entry: &AuditEntry) -> Result<(), DaemonError> {
        // Serialize to JSON
        let json = serde_json::to_string(entry)?;

        // Write with newline
        let mut file = self.file.lock().map_err(|e| DaemonError::Socket {
            message: format!("Failed to acquire audit log lock: {}", e),
        })?;

        writeln!(file, "{}", json)?;

        // Sync for durability
        if let Err(e) = file.sync_data() {
            warn!(error = %e, "Failed to sync audit log");
        }

        debug!(
            request_id = %entry.request_id,
            command = %entry.command,
            "Audit entry logged"
        );

        Ok(())
    }

    /// Get the path to the audit log file.
    pub fn path(&self) -> &Path {
        &self.path
    }
}

/// A no-op audit logger for testing or when audit logging is disabled.
pub struct NullAuditLogger;

impl NullAuditLogger {
    /// Create a new null audit logger.
    pub fn new() -> Self {
        Self
    }

    /// Log an audit entry (does nothing).
    pub fn log(&self, _entry: &AuditEntry) -> Result<(), DaemonError> {
        Ok(())
    }
}

impl Default for NullAuditLogger {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Read;
    use tempfile::TempDir;
    use uuid::Uuid;

    fn create_test_entry() -> AuditEntry {
        AuditEntry::success(
            "2024-01-15T10:30:45.123Z".to_string(),
            Uuid::nil(),
            "test.command".to_string(),
            serde_json::json!({"key": "value"}),
            1000,
            1000,
            12345,
            None,
            10,
        )
    }

    #[test]
    fn test_logger_creates_directory() {
        let temp_dir = TempDir::new().unwrap();
        let log_path = temp_dir.path().join("subdir/audit.log");

        let logger = AuditLogger::new(&log_path).unwrap();
        assert!(log_path.parent().unwrap().exists());
        assert_eq!(logger.path(), log_path);
    }

    #[test]
    fn test_logger_writes_json_lines() {
        let temp_dir = TempDir::new().unwrap();
        let log_path = temp_dir.path().join("audit.log");

        let logger = AuditLogger::new(&log_path).unwrap();

        // Log two entries
        let entry1 = create_test_entry();
        let entry2 = AuditEntry::failure(
            "2024-01-15T10:30:46.456Z".to_string(),
            Uuid::nil(),
            "test.fail".to_string(),
            serde_json::json!({}),
            1000,
            1000,
            12345,
            "TEST_ERROR".to_string(),
            "Test error message".to_string(),
            5,
        );

        logger.log(&entry1).unwrap();
        logger.log(&entry2).unwrap();

        // Read the file and verify
        let mut content = String::new();
        File::open(&log_path)
            .unwrap()
            .read_to_string(&mut content)
            .unwrap();

        let lines: Vec<&str> = content.lines().collect();
        assert_eq!(lines.len(), 2);

        // Verify each line is valid JSON
        let parsed1: serde_json::Value = serde_json::from_str(lines[0]).unwrap();
        assert_eq!(parsed1["command"], "test.command");
        assert_eq!(parsed1["result"]["status"], "success");

        let parsed2: serde_json::Value = serde_json::from_str(lines[1]).unwrap();
        assert_eq!(parsed2["command"], "test.fail");
        assert_eq!(parsed2["result"]["status"], "failure");
        assert_eq!(parsed2["result"]["error_code"], "TEST_ERROR");
    }

    #[test]
    fn test_logger_appends_to_existing_file() {
        let temp_dir = TempDir::new().unwrap();
        let log_path = temp_dir.path().join("audit.log");

        // Write first entry
        {
            let logger = AuditLogger::new(&log_path).unwrap();
            logger.log(&create_test_entry()).unwrap();
        }

        // Create new logger and write second entry
        {
            let logger = AuditLogger::new(&log_path).unwrap();
            logger.log(&create_test_entry()).unwrap();
        }

        // Verify both entries exist
        let mut content = String::new();
        File::open(&log_path)
            .unwrap()
            .read_to_string(&mut content)
            .unwrap();

        assert_eq!(content.lines().count(), 2);
    }

    #[test]
    fn test_null_logger() {
        let logger = NullAuditLogger::new();
        let entry = create_test_entry();
        assert!(logger.log(&entry).is_ok());
    }
}
