//! Safe subprocess execution.
//!
//! Provides utilities for running external commands safely with:
//! - No shell interpretation (direct exec)
//! - Configurable timeouts
//! - Captured stdout/stderr
//! - Environment control

use std::collections::HashMap;
use std::process::{Command, Output, Stdio};
use std::time::{Duration, Instant};

use tracing::{debug, warn};

use crate::error::{CommandErrorKind, DaemonError};

/// Result of a subprocess execution.
#[derive(Debug, Clone)]
pub struct SubprocessResult {
    /// Whether the command exited successfully (exit code 0).
    pub success: bool,
    /// The exit code, if available.
    pub exit_code: Option<i32>,
    /// Captured stdout as a string.
    pub stdout: String,
    /// Captured stderr as a string.
    pub stderr: String,
}

impl SubprocessResult {
    /// Create a SubprocessResult from a std::process::Output.
    fn from_output(output: Output) -> Self {
        Self {
            success: output.status.success(),
            exit_code: output.status.code(),
            stdout: String::from_utf8_lossy(&output.stdout).to_string(),
            stderr: String::from_utf8_lossy(&output.stderr).to_string(),
        }
    }
}

/// Builder for subprocess execution.
pub struct SubprocessBuilder {
    program: String,
    args: Vec<String>,
    env: HashMap<String, String>,
    timeout: Duration,
    clear_env: bool,
    /// If true, arguments will not be logged (for commands containing secrets)
    sensitive: bool,
}

impl SubprocessBuilder {
    /// Create a new subprocess builder.
    pub fn new(program: &str) -> Self {
        Self {
            program: program.to_string(),
            args: Vec::new(),
            env: HashMap::new(),
            timeout: Duration::from_secs(60),
            clear_env: false,
            sensitive: false,
        }
    }

    /// Mark this command as containing sensitive data (e.g., passwords).
    /// When set, command arguments will not be logged.
    pub fn sensitive(mut self) -> Self {
        self.sensitive = true;
        self
    }

    /// Add arguments to the command.
    pub fn args<I, S>(mut self, args: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: AsRef<str>,
    {
        self.args.extend(args.into_iter().map(|s| s.as_ref().to_string()));
        self
    }

    /// Add a single argument.
    pub fn arg(mut self, arg: &str) -> Self {
        self.args.push(arg.to_string());
        self
    }

    /// Set an environment variable.
    pub fn env(mut self, key: &str, value: &str) -> Self {
        self.env.insert(key.to_string(), value.to_string());
        self
    }

    /// Set the timeout for the command.
    pub fn timeout(mut self, timeout: Duration) -> Self {
        self.timeout = timeout;
        self
    }

    /// Clear the environment before running (then add only specified env vars).
    pub fn clear_env(mut self) -> Self {
        self.clear_env = true;
        self
    }

    /// Execute the command and wait for completion with timeout enforcement.
    ///
    /// If the process exceeds the configured timeout, it will be killed
    /// and a timeout error will be returned.
    pub fn run(self) -> Result<SubprocessResult, DaemonError> {
        // Log command execution, but redact args for sensitive commands
        if self.sensitive {
            debug!(
                program = %self.program,
                args = "[REDACTED]",
                timeout_secs = self.timeout.as_secs(),
                "Executing subprocess (sensitive)"
            );
        } else {
            debug!(
                program = %self.program,
                args = ?self.args,
                timeout_secs = self.timeout.as_secs(),
                "Executing subprocess"
            );
        }

        let mut cmd = Command::new(&self.program);
        cmd.args(&self.args);
        cmd.stdout(Stdio::piped());
        cmd.stderr(Stdio::piped());

        // Handle environment
        if self.clear_env {
            cmd.env_clear();
        }
        for (key, value) in &self.env {
            cmd.env(key, value);
        }

        // Spawn the process
        let mut child = cmd.spawn().map_err(|e| DaemonError::Command {
            kind: CommandErrorKind::ExecutionFailed {
                message: format!("Failed to spawn {}: {}", self.program, e),
            },
        })?;

        // Poll for completion with timeout enforcement
        let start = Instant::now();
        let poll_interval = Duration::from_millis(100);

        loop {
            match child.try_wait() {
                Ok(Some(_status)) => {
                    // Process has finished - get the full output
                    let output = child.wait_with_output().map_err(|e| DaemonError::Command {
                        kind: CommandErrorKind::ExecutionFailed {
                            message: format!("Failed to get output from {}: {}", self.program, e),
                        },
                    })?;
                    let result = SubprocessResult::from_output(output);
                    debug!(
                        success = result.success,
                        exit_code = ?result.exit_code,
                        duration_ms = start.elapsed().as_millis(),
                        "Subprocess completed"
                    );
                    return Ok(result);
                }
                Ok(None) => {
                    // Process still running - check timeout
                    if start.elapsed() > self.timeout {
                        warn!(
                            program = %self.program,
                            timeout_secs = self.timeout.as_secs(),
                            "Process timed out, killing"
                        );
                        // Kill the process
                        if let Err(e) = child.kill() {
                            warn!(error = %e, "Failed to kill timed-out process");
                        }
                        // Reap the zombie process
                        let _ = child.wait();
                        return Err(DaemonError::Command {
                            kind: CommandErrorKind::Timeout {
                                timeout_secs: self.timeout.as_secs(),
                            },
                        });
                    }
                    // Sleep briefly before next check
                    std::thread::sleep(poll_interval);
                }
                Err(e) => {
                    return Err(DaemonError::Command {
                        kind: CommandErrorKind::ExecutionFailed {
                            message: format!("Failed to check process status: {}", e),
                        },
                    });
                }
            }
        }
    }
}

/// Run a command with the given arguments and timeout.
///
/// This is a convenience function for simple command execution.
///
/// # Arguments
///
/// * `program` - The program to execute
/// * `args` - Arguments to pass to the program
/// * `timeout` - Maximum time to wait for completion
///
/// # Returns
///
/// Returns the subprocess result or an error if execution failed.
pub fn run_command(
    program: &str,
    args: &[&str],
    timeout: Duration,
) -> Result<SubprocessResult, DaemonError> {
    SubprocessBuilder::new(program)
        .args(args.iter().copied())
        .timeout(timeout)
        .run()
}

/// Run a command with environment variables.
///
/// # Arguments
///
/// * `program` - The program to execute
/// * `args` - Arguments to pass to the program
/// * `env` - Environment variables to set
/// * `timeout` - Maximum time to wait for completion
pub fn run_command_with_env(
    program: &str,
    args: &[&str],
    env: &[(&str, &str)],
    timeout: Duration,
) -> Result<SubprocessResult, DaemonError> {
    let mut builder = SubprocessBuilder::new(program)
        .args(args.iter().copied())
        .timeout(timeout);

    for (key, value) in env {
        builder = builder.env(key, value);
    }

    builder.run()
}

/// Run a command that contains sensitive data (passwords, secrets).
///
/// Same as `run_command` but arguments are not logged.
///
/// # Arguments
///
/// * `program` - The program to execute
/// * `args` - Arguments to pass to the program (will not be logged)
/// * `timeout` - Maximum time to wait for completion
pub fn run_command_sensitive(
    program: &str,
    args: &[&str],
    timeout: Duration,
) -> Result<SubprocessResult, DaemonError> {
    SubprocessBuilder::new(program)
        .args(args.iter().copied())
        .timeout(timeout)
        .sensitive()
        .run()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_run_echo() {
        let result = run_command("echo", &["hello", "world"], Duration::from_secs(5)).unwrap();
        assert!(result.success);
        assert_eq!(result.exit_code, Some(0));
        assert_eq!(result.stdout.trim(), "hello world");
    }

    #[test]
    fn test_run_false_command() {
        let result = run_command("false", &[], Duration::from_secs(5)).unwrap();
        assert!(!result.success);
        assert_eq!(result.exit_code, Some(1));
    }

    #[test]
    fn test_subprocess_builder() {
        let result = SubprocessBuilder::new("echo")
            .arg("test")
            .arg("builder")
            .timeout(Duration::from_secs(5))
            .run()
            .unwrap();

        assert!(result.success);
        assert_eq!(result.stdout.trim(), "test builder");
    }

    #[test]
    fn test_run_with_env() {
        let result = run_command_with_env(
            "sh",
            &["-c", "echo $TEST_VAR"],
            &[("TEST_VAR", "hello_env")],
            Duration::from_secs(5),
        )
        .unwrap();

        assert!(result.success);
        assert_eq!(result.stdout.trim(), "hello_env");
    }

    #[test]
    fn test_nonexistent_command() {
        let result = run_command(
            "nonexistent_command_12345",
            &[],
            Duration::from_secs(5),
        );
        assert!(result.is_err());
    }

    #[test]
    fn test_stderr_capture() {
        let result = run_command(
            "sh",
            &["-c", "echo error >&2"],
            Duration::from_secs(5),
        )
        .unwrap();

        assert!(result.success);
        assert_eq!(result.stderr.trim(), "error");
    }
}
