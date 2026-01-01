//! Error types for the Lumo daemon.

use std::path::PathBuf;
use thiserror::Error;

/// Main error type for the daemon.
#[derive(Error, Debug)]
pub enum DaemonError {
    /// Configuration-related errors.
    #[error("Configuration error: {message}")]
    Config { message: String },

    /// Socket-related errors.
    #[error("Socket error: {message}")]
    Socket { message: String },

    /// Authentication errors.
    #[error("Authentication error: {kind}")]
    Auth { kind: AuthErrorKind },

    /// Validation errors.
    #[error("Validation error: {kind}")]
    Validation { kind: ValidationErrorKind },

    /// Command execution errors.
    #[error("Command error: {kind}")]
    Command { kind: CommandErrorKind },

    /// Template-related errors.
    #[error("Template error: {message}")]
    Template { message: String },

    /// Protocol errors.
    #[error("Protocol error: {kind}")]
    Protocol { kind: ProtocolErrorKind },

    /// I/O errors.
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    /// Serialization/deserialization errors.
    #[error("Serialization error: {0}")]
    Serialization(#[from] serde_json::Error),
}

/// Authentication error kinds.
#[derive(Error, Debug)]
pub enum AuthErrorKind {
    #[error("Unauthorized peer: UID {uid} not in allowed list")]
    UnauthorizedPeer { uid: u32 },

    #[error("Invalid signature")]
    InvalidSignature,

    #[error("Request expired: age {age_seconds}s exceeds maximum")]
    RequestExpired { age_seconds: u64 },

    #[error("Nonce already used (replay attack detected)")]
    NonceReused,

    #[error("Failed to read HMAC secret: {message}")]
    HmacSecretError { message: String },
}

/// Validation error kinds.
#[derive(Error, Debug)]
pub enum ValidationErrorKind {
    #[error("Path not allowed: {path}")]
    PathNotAllowed { path: PathBuf },

    #[error("Path traversal detected in: {path}")]
    PathTraversal { path: PathBuf },

    #[error("Protected file cannot be modified: {path}")]
    ProtectedFile { path: PathBuf },

    #[error("Invalid username: {username}")]
    InvalidUsername { username: String },

    #[error("Invalid domain: {domain}")]
    InvalidDomain { domain: String },

    #[error("Package not whitelisted: {package}")]
    PackageNotWhitelisted { package: String },

    #[error("Repository not whitelisted: {repository}")]
    RepositoryNotWhitelisted { repository: String },

    #[error("Service not recognized: {service}")]
    UnknownService { service: String },

    #[error("Missing required parameter: {param}")]
    MissingParameter { param: String },

    #[error("Invalid parameter value for '{param}': {message}")]
    InvalidParameter { param: String, message: String },
}

/// Command error kinds.
#[derive(Error, Debug)]
pub enum CommandErrorKind {
    #[error("Unknown command: {name}")]
    UnknownCommand { name: String },

    #[error("Command execution failed: {message}")]
    ExecutionFailed { message: String },

    #[error("Command timed out after {timeout_secs} seconds")]
    Timeout { timeout_secs: u64 },
}

/// Protocol error kinds.
#[derive(Error, Debug)]
pub enum ProtocolErrorKind {
    #[error("Message too large: {size} bytes exceeds maximum of {max} bytes")]
    MessageTooLarge { size: usize, max: usize },

    #[error("Invalid message format: {message}")]
    InvalidMessageFormat { message: String },

    #[error("Connection closed")]
    ConnectionClosed,

    #[error("Connection timed out")]
    ConnectionTimeout,
}

/// Result type alias for daemon operations.
pub type DaemonResult<T> = Result<T, DaemonError>;
