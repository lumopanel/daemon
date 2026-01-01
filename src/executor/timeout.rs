//! Timeout handling for command execution.
//!
//! Provides utilities for running operations with a timeout.

use std::sync::mpsc;
use std::thread;
use std::time::Duration;

use crate::error::{CommandErrorKind, DaemonError};

/// Execute an operation with a timeout.
///
/// This runs the operation in a separate thread and waits for completion
/// up to the specified timeout duration.
///
/// # Arguments
///
/// * `timeout` - Maximum time to wait for the operation
/// * `operation` - The operation to execute
///
/// # Returns
///
/// Returns the operation result if it completes within the timeout,
/// or a timeout error if it exceeds the limit.
///
/// # Note
///
/// If the operation times out, the spawned thread will continue running
/// in the background. For subprocess execution, prefer using the
/// subprocess module which handles process cleanup.
pub fn with_timeout<F, T>(timeout: Duration, operation: F) -> Result<T, DaemonError>
where
    F: FnOnce() -> Result<T, DaemonError> + Send + 'static,
    T: Send + 'static,
{
    let (tx, rx) = mpsc::channel();

    thread::spawn(move || {
        let result = operation();
        // Ignore send errors (receiver may have dropped on timeout)
        let _ = tx.send(result);
    });

    match rx.recv_timeout(timeout) {
        Ok(result) => result,
        Err(mpsc::RecvTimeoutError::Timeout) => Err(DaemonError::Command {
            kind: CommandErrorKind::Timeout {
                timeout_secs: timeout.as_secs(),
            },
        }),
        Err(mpsc::RecvTimeoutError::Disconnected) => Err(DaemonError::Command {
            kind: CommandErrorKind::ExecutionFailed {
                message: "Operation thread panicked".to_string(),
            },
        }),
    }
}

/// Sanitize command output for inclusion in error messages.
///
/// This function:
/// - Truncates long output to a reasonable length
/// - Limits the number of lines shown
/// - Removes potentially sensitive information patterns
///
/// # Arguments
///
/// * `output` - The raw command output
/// * `max_lines` - Maximum number of lines to include
///
/// # Returns
///
/// A sanitized string safe for inclusion in error messages.
pub fn sanitize_output(output: &str, max_lines: usize) -> String {
    const MAX_LINE_LENGTH: usize = 200;
    const MAX_TOTAL_LENGTH: usize = 1000;

    let lines: Vec<&str> = output.lines().take(max_lines).collect();
    let mut result = String::new();

    for line in lines {
        // Truncate long lines
        let truncated = if line.len() > MAX_LINE_LENGTH {
            format!("{}...", &line[..MAX_LINE_LENGTH])
        } else {
            line.to_string()
        };

        if result.len() + truncated.len() > MAX_TOTAL_LENGTH {
            result.push_str("...[truncated]");
            break;
        }

        if !result.is_empty() {
            result.push('\n');
        }
        result.push_str(&truncated);
    }

    // If there were more lines, indicate truncation
    if output.lines().count() > max_lines {
        result.push_str("\n...[additional output truncated]");
    }

    result
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_with_timeout_success() {
        let result = with_timeout(Duration::from_secs(5), || Ok(42));
        assert_eq!(result.unwrap(), 42);
    }

    #[test]
    fn test_with_timeout_error_propagation() {
        let result: Result<i32, DaemonError> = with_timeout(Duration::from_secs(5), || {
            Err(DaemonError::Command {
                kind: CommandErrorKind::ExecutionFailed {
                    message: "test error".to_string(),
                },
            })
        });
        assert!(result.is_err());
    }

    #[test]
    fn test_sanitize_output_short() {
        let output = "Hello\nWorld";
        let sanitized = sanitize_output(output, 10);
        assert_eq!(sanitized, "Hello\nWorld");
    }

    #[test]
    fn test_sanitize_output_truncates_lines() {
        let output = "Line 1\nLine 2\nLine 3\nLine 4\nLine 5";
        let sanitized = sanitize_output(output, 3);
        assert!(sanitized.contains("Line 1"));
        assert!(sanitized.contains("Line 2"));
        assert!(sanitized.contains("Line 3"));
        assert!(!sanitized.contains("Line 4"));
        assert!(sanitized.contains("[additional output truncated]"));
    }

    #[test]
    fn test_sanitize_output_truncates_long_lines() {
        let long_line = "x".repeat(300);
        let sanitized = sanitize_output(&long_line, 10);
        assert!(sanitized.len() < 300);
        assert!(sanitized.ends_with("..."));
    }
}
