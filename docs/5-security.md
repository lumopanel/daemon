# Security Documentation

This document provides comprehensive security documentation for the daemon, covering the security architecture, defense-in-depth layers, secure file operations, protected resources, and deployment best practices.

## Table of Contents

1. [Security Architecture Overview](#security-architecture-overview)
2. [Defense in Depth Layers](#defense-in-depth-layers)
3. [Secure File Operations](#secure-file-operations)
4. [Protected Resources](#protected-resources)
5. [Security Configuration Best Practices](#security-configuration-best-practices)
6. [Threat Model and Mitigations](#threat-model-and-mitigations)
7. [Security Checklist for Deployment](#security-checklist-for-deployment)

---

## Security Architecture Overview

The daemon implements a multi-layered security model designed to minimize attack surface and provide defense in depth. The architecture follows the principle of least privilege, where each component has only the permissions necessary for its function.

### Core Security Principles

1. **Fail-Closed Design**: When security checks cannot be performed or return ambiguous results, the system denies access rather than allowing it
2. **Defense in Depth**: Multiple independent security layers ensure that a failure in one layer does not compromise the entire system
3. **Least Privilege**: Operations are restricted to the minimum required permissions
4. **Explicit Allowlists**: Only explicitly permitted operations, paths, services, and packages are allowed

### Security Components

```
+-------------------+     +-------------------+     +-------------------+
|   Unix Socket     |     |   Peer Credential |     |   HMAC Signature  |
|   Permissions     | --> |   Verification    | --> |   Validation      |
|   (0600/0660)     |     |   (SO_PEERCRED)   |     |   (SHA-256)       |
+-------------------+     +-------------------+     +-------------------+
                                    |
                                    v
+-------------------+     +-------------------+     +-------------------+
|   Nonce Replay    |     |   Per-UID Rate    |     |   Input           |
|   Protection      | --> |   Limiting        | --> |   Validation      |
+-------------------+     +-------------------+     +-------------------+
                                    |
                                    v
+-------------------+     +-------------------+     +-------------------+
|   Path Traversal  |     |   Command         |     |   Error Message   |
|   Protection      | --> |   Whitelisting    | --> |   Sanitization    |
+-------------------+     +-------------------+     +-------------------+
```

---

## Defense in Depth Layers

### Layer 1: Unix Socket Permissions

The daemon communicates exclusively via a Unix domain socket, providing inherent security benefits over network sockets.

**Implementation** (`src/socket/listener.rs`):

```rust
// Set socket file permissions
fn set_socket_permissions(path: &Path, permissions_str: &str) -> Result<(), DaemonError> {
    let mode = u32::from_str_radix(permissions_str, 8).map_err(|e| DaemonError::Socket {
        message: format!("Invalid socket permissions '{}': {}", permissions_str, e),
    })?;

    let permissions = std::fs::Permissions::from_mode(mode);
    std::fs::set_permissions(path, permissions).map_err(|e| DaemonError::Socket {
        message: format!(
            "Failed to set socket permissions on {}: {}",
            path.display(),
            e
        ),
    })?;

    Ok(())
}
```

**Security Benefits**:
- Socket file permissions (typically `0600` or `0660`) restrict which users can connect
- No network exposure - cannot be accessed from remote machines
- Kernel-enforced access control

**Symlink Protection**:

The daemon protects against symlink attacks when creating the socket:

```rust
// Security: Use symlink_metadata to detect symlinks without following them
if let Ok(metadata) = std::fs::symlink_metadata(socket_path) {
    // Refuse to remove if the path is a symlink (prevents arbitrary file deletion)
    if metadata.file_type().is_symlink() {
        return Err(DaemonError::Socket {
            message: format!(
                "Socket path {} is a symlink, refusing to remove for security",
                socket_path.display()
            ),
        });
    }
    // ... remove existing socket file
}
```

This prevents an attacker from placing a symlink at the socket path to trick the daemon into deleting arbitrary files.

### Layer 2: Peer Credential Verification

After socket connection, the daemon verifies the connecting process's identity using kernel-provided credentials.

**Implementation** (`src/auth/peer_creds.rs`):

```rust
// Linux: Uses SO_PEERCRED
#[cfg(target_os = "linux")]
pub fn verify_peer<S: AsRawFd>(stream: &S, allowed_uids: &[u32]) -> Result<PeerInfo, DaemonError> {
    use nix::sys::socket::{getsockopt, sockopt::PeerCredentials};

    let creds = getsockopt(stream.as_raw_fd(), PeerCredentials).map_err(|e| DaemonError::Socket {
        message: format!("Failed to get peer credentials: {}", e),
    })?;

    let peer = PeerInfo {
        uid: creds.uid(),
        gid: creds.gid(),
        pid: creds.pid(),
    };

    // Security: Fail-closed on empty UID list - reject all if no UIDs configured
    if allowed_uids.is_empty() {
        return Err(DaemonError::Auth {
            kind: AuthErrorKind::UnauthorizedPeer { uid: peer.uid },
        });
    }

    if !allowed_uids.contains(&peer.uid) {
        return Err(DaemonError::Auth {
            kind: AuthErrorKind::UnauthorizedPeer { uid: peer.uid },
        });
    }

    Ok(peer)
}

// macOS: Uses LOCAL_PEERCRED
#[cfg(target_os = "macos")]
pub fn verify_peer<S: AsRawFd>(stream: &S, allowed_uids: &[u32]) -> Result<PeerInfo, DaemonError> {
    // Uses LOCAL_PEERCRED socket option for macOS compatibility
    // ...
}
```

**Security Properties**:
- Credentials are provided by the kernel and cannot be spoofed
- Fail-closed behavior: empty allowed UID list rejects all connections
- Both Linux (`SO_PEERCRED`) and macOS (`LOCAL_PEERCRED`) are supported

**PeerInfo Structure**:
```rust
pub struct PeerInfo {
    pub uid: u32,   // User ID of the peer process
    pub gid: u32,   // Group ID of the peer process
    pub pid: i32,   // Process ID (may be 0 on some platforms)
}
```

### Layer 3: HMAC Signature Validation

All requests must be cryptographically signed using HMAC-SHA256 to prove authenticity.

**Implementation** (`src/auth/hmac.rs`):

```rust
pub struct HmacValidator {
    key: hmac::Key,
    nonce_store: Arc<NonceStore>,
    max_age: Duration,
}

impl HmacValidator {
    /// Validate a signed request.
    ///
    /// Checks:
    /// 1. Request is not expired (timestamp within max_age)
    /// 2. Signature is valid
    /// 3. Nonce has not been used before
    pub async fn validate(&self, request: &SignedRequest) -> Result<(), DaemonError> {
        // 1. Check timestamp freshness
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)?
            .as_secs();

        let age = now.saturating_sub(request.timestamp);
        if age > self.max_age.as_secs() {
            return Err(DaemonError::Auth {
                kind: AuthErrorKind::RequestExpired { age_seconds: age },
            });
        }

        // Also reject requests from the future (clock skew protection)
        if request.timestamp > now + 60 {
            return Err(DaemonError::Auth {
                kind: AuthErrorKind::RequestExpired {
                    age_seconds: request.timestamp - now,
                },
            });
        }

        // 2. Verify signature
        let message = request.signing_message();
        let signature_bytes = hex::decode(&request.signature)?;
        hmac::verify(&self.key, message.as_bytes(), &signature_bytes)?;

        // 3. Check nonce (replay prevention)
        if !self.nonce_store.check_and_store(&request.nonce).await {
            return Err(DaemonError::Auth {
                kind: AuthErrorKind::NonceReused,
            });
        }

        Ok(())
    }
}
```

**Secret File Security**:

The HMAC secret file must have restrictive permissions:

```rust
pub fn load_secret(path: &Path) -> Result<Vec<u8>, DaemonError> {
    let metadata = std::fs::metadata(path)?;

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = metadata.permissions().mode();
        // Check that group and world bits are all zero (only owner can access)
        if mode & 0o077 != 0 {
            return Err(DaemonError::Auth {
                kind: AuthErrorKind::HmacSecretError {
                    message: format!(
                        "HMAC secret file {} has insecure permissions {:04o}, expected 0600 or 0400",
                        path.display(),
                        mode & 0o777
                    ),
                },
            });
        }
    }

    std::fs::read(path)
}
```

### Layer 4: Nonce Replay Protection

Each request includes a unique nonce to prevent replay attacks.

**Implementation** (`src/auth/nonce.rs`):

```rust
/// Thread-safe in-memory nonce store with TTL-based expiry.
pub struct NonceStore {
    /// Map of nonce -> expiry time.
    nonces: Mutex<HashMap<String, Instant>>,
    /// Time-to-live for nonces.
    ttl: Duration,
}

impl NonceStore {
    /// Check if a nonce has been used, and store it if not.
    ///
    /// Returns `true` if the nonce is new (valid), `false` if already used.
    pub async fn check_and_store(&self, nonce: &str) -> bool {
        let mut nonces = self.nonces.lock().unwrap_or_else(|e| e.into_inner());
        let now = Instant::now();

        // Clean up expired nonces (lazy cleanup)
        nonces.retain(|_, expiry| *expiry > now);

        // Check if nonce already exists
        if nonces.contains_key(nonce) {
            return false;
        }

        // Store the new nonce with expiry
        let expiry = now + self.ttl;
        nonces.insert(nonce.to_string(), expiry);

        true
    }

    /// Start a background cleanup task.
    pub fn start_cleanup_task(self: &std::sync::Arc<Self>, interval: Duration) {
        let store = std::sync::Arc::clone(self);
        tokio::spawn(async move {
            let mut interval_timer = tokio::time::interval(interval);
            loop {
                interval_timer.tick().await;
                store.cleanup();
            }
        });
    }
}
```

**Security Properties**:
- Prevents replay of captured requests
- TTL-based expiry prevents unbounded memory growth
- Thread-safe implementation handles concurrent access
- Recovers gracefully from mutex poisoning

### Layer 5: Rate Limiting

Per-UID rate limiting prevents abuse and denial-of-service attacks.

**Implementation** (`src/auth/rate_limit.rs`):

```rust
/// A sliding window rate limiter that tracks requests per UID.
pub struct RateLimiter {
    /// Request timestamps per UID
    requests: Mutex<HashMap<u32, Vec<Instant>>>,
    /// Maximum requests allowed per window
    max_requests: usize,
    /// Time window for rate limiting
    window: Duration,
}

impl RateLimiter {
    /// Check if a request from the given UID is allowed and record it.
    ///
    /// Returns `true` if the request is allowed, `false` if rate limited.
    pub fn check_and_record(&self, uid: u32) -> bool {
        let mut requests = self.requests.lock().unwrap_or_else(|e| e.into_inner());
        let now = Instant::now();
        let cutoff = now - self.window;

        let entry = requests.entry(uid).or_insert_with(Vec::new);

        // Remove old requests outside the window
        entry.retain(|&t| t > cutoff);

        if entry.len() >= self.max_requests {
            return false; // Rate limited
        }

        entry.push(now);
        true
    }
}
```

**Initialization** (`src/socket/listener.rs`):

```rust
// Create per-UID rate limiter
let rate_limiter = Arc::new(RateLimiter::new(
    settings.security.rate_limit_requests,
    settings.security.rate_limit_window_seconds,
));
info!(
    max_requests = settings.security.rate_limit_requests,
    window_seconds = settings.security.rate_limit_window_seconds,
    "Per-UID rate limiting enabled"
);
```

### Layer 6: Input Validation (Whitelists)

All input is validated against strict whitelists before processing.

#### Service Name Validation

**Implementation** (`src/validation/service_name.rs`):

```rust
/// Allowed service names that can be controlled via the daemon.
const ALLOWED_SERVICES: &[&str] = &[
    // Web servers
    "nginx",
    // PHP-FPM (various versions)
    "php8.1-fpm", "php8.2-fpm", "php8.3-fpm", "php8.4-fpm",
    // Databases
    "mysql", "mariadb", "postgresql", "redis-server",
    // Cache
    "memcached",
    // Process managers
    "supervisor", "supervisord",
];

pub fn validate_service_name(name: &str) -> Result<(), DaemonError> {
    if name.is_empty() {
        return Err(DaemonError::Validation { ... });
    }

    if !is_service_allowed(name) {
        return Err(DaemonError::Validation {
            kind: ValidationErrorKind::UnknownService {
                service: name.to_string(),
            },
        });
    }

    Ok(())
}
```

#### Package Name Validation

**Implementation** (`src/validation/package_name.rs`):

```rust
/// Statically allowed packages (non-PHP).
const STATIC_PACKAGES: &[&str] = &[
    // Web servers
    "nginx", "nginx-extras", "nginx-full",
    // Cache
    "redis-server", "redis-tools", "memcached", "libmemcached-tools",
    // Databases
    "postgresql", "postgresql-client", "postgresql-14", /* ... */
    "mariadb-server", "mariadb-client", "mysql-server", "mysql-client",
    // Process managers
    "supervisor",
    // Node.js
    "nodejs", "npm",
    // SSL/Certbot
    "certbot", "python3-certbot-nginx",
    // Common utilities
    "git", "unzip", "zip", "curl", "wget",
];

pub fn validate_package_name(name: &str) -> Result<(), DaemonError> {
    // Check for dangerous characters
    if name.contains("..") || name.contains('/') || name.contains('\n') || name.contains(';') {
        return Err(DaemonError::Validation { ... });
    }

    // Check against whitelist
    if !is_package_allowed(name) {
        return Err(DaemonError::Validation {
            kind: ValidationErrorKind::PackageNotWhitelisted { ... },
        });
    }

    Ok(())
}
```

#### Repository Validation

**Implementation** (`src/validation/repository.rs`):

```rust
/// Allowed PPA repositories.
const ALLOWED_PPAS: &[&str] = &[
    "ppa:ondrej/php",
    "ppa:ondrej/nginx",
    "ppa:ondrej/nginx-mainline",
    "ppa:redislabs/redis",
    "ppa:certbot/certbot",
    "ppa:git-core/ppa",
];

pub fn validate_repository(repo: &str) -> Result<(), DaemonError> {
    // Check for dangerous characters (shell metacharacters)
    const DANGEROUS_CHARS: &[char] = &[';', '|', '&', '$', '`', '(', ')', '{', '}', '[', ']',
                                        '<', '>', '\n', '\r', '\\', '"', '\'', '*', '?', '!'];

    if repo.chars().any(|c| DANGEROUS_CHARS.contains(&c)) {
        return Err(DaemonError::Validation { ... });
    }

    // Validate format: must be ppa:owner/name format
    if !repo.starts_with("ppa:") {
        return Err(DaemonError::Validation { ... });
    }

    // Check against whitelist
    if !is_repository_allowed(repo) {
        return Err(DaemonError::Validation { ... });
    }

    Ok(())
}
```

#### Domain Validation

**Implementation** (`src/validation/domain.rs`):

```rust
pub fn validate_domain(domain: &str) -> Result<&str, DaemonError> {
    // Check total length (max 253 characters)
    if domain.len() > MAX_DOMAIN_LENGTH {
        return Err(...);
    }

    // Reject wildcards for security
    if domain.contains('*') {
        return Err(DaemonError::Validation {
            kind: ValidationErrorKind::InvalidParameter {
                param: "domain".to_string(),
                message: "Wildcard domains are not allowed".to_string(),
            },
        });
    }

    // Must have at least 2 labels (domain + TLD)
    let labels: Vec<&str> = domain.split('.').collect();
    if labels.len() < 2 {
        return Err(...);
    }

    // Validate each label
    for label in &labels {
        validate_domain_label(label)?;
    }

    Ok(domain)
}
```

#### Database Validation

**Implementation** (`src/validation/database.rs`):

```rust
pub fn validate_database_name(name: &str) -> Result<&str, DaemonError> {
    // Check length (max 64 characters)
    if name.len() > MAX_DATABASE_NAME_LENGTH {
        return Err(...);
    }

    // Check first character (must be letter or underscore)
    let first_char = name.chars().next().unwrap();
    if !first_char.is_ascii_alphabetic() && first_char != '_' {
        return Err(...);
    }

    // Check all characters (alphanumeric and underscore only)
    if !name.chars().all(|c| c.is_ascii_alphanumeric() || c == '_') {
        return Err(...);
    }

    // Check against reserved keywords
    if is_reserved_keyword(&name.to_lowercase()) {
        return Err(...);
    }

    Ok(name)
}

/// Reserved keywords that cannot be used as database names
const RESERVED: &[&str] = &[
    "mysql", "information_schema", "performance_schema", "sys",
    "postgres", "template0", "template1",
    "root", "admin", "test",
];
```

#### Username Validation

**Implementation** (`src/validation/username.rs`):

```rust
/// Reserved system usernames that cannot be created or deleted.
const RESERVED_USERNAMES: &[&str] = &[
    "root", "daemon", "bin", "sys", "sync", "games", "man", "lp", "mail",
    "news", "uucp", "proxy", "www-data", "backup", "list", "irc", "gnats",
    "nobody", "systemd-network", "systemd-resolve", "messagebus", "sshd",
    "mysql", "postgres", "redis", "nginx", "apache", "_apt",
];

pub fn validate_system_username(username: &str) -> Result<&str, DaemonError> {
    // Must not exceed 32 characters (Linux standard)
    if username.len() > MAX_USERNAME_LENGTH {
        return Err(...);
    }

    // Must start with a lowercase letter
    let first = username.chars().next().unwrap();
    if !first.is_ascii_lowercase() {
        return Err(...);
    }

    // Only allowed characters: lowercase letters, digits, underscore, hyphen
    for c in username.chars() {
        if !c.is_ascii_lowercase() && !c.is_ascii_digit() && c != '_' && c != '-' {
            return Err(...);
        }
    }

    // Check against reserved usernames
    if RESERVED_USERNAMES.contains(&username) {
        return Err(...);
    }

    Ok(username)
}
```

#### UID/GID Validation

**Implementation** (`src/validation/uid_gid.rs`):

```rust
pub fn validate_uid(value: i64) -> Result<u32, DaemonError> {
    if value < 0 {
        return Err(DaemonError::Validation {
            kind: ValidationErrorKind::InvalidParameter {
                param: "owner".to_string(),
                message: format!("UID cannot be negative: {}", value),
            },
        });
    }
    if value > u32::MAX as i64 {
        return Err(DaemonError::Validation {
            kind: ValidationErrorKind::InvalidParameter {
                param: "owner".to_string(),
                message: format!("UID exceeds maximum value ({}): {}", u32::MAX, value),
            },
        });
    }
    Ok(value as u32)
}
```

#### Configurable Whitelists

**Implementation** (`src/validation/whitelist.rs`):

The daemon supports runtime extension of whitelists through configuration:

```rust
pub struct RuntimeWhitelists {
    pub additional_services: HashSet<String>,
    pub additional_packages: HashSet<String>,
    pub additional_php_versions: HashSet<String>,
    pub additional_php_extensions: HashSet<String>,
    pub additional_repositories: HashSet<String>,
    pub additional_path_prefixes: Vec<String>,
}

/// Initialize the global whitelists from configuration.
pub fn init_whitelists(config: &WhitelistsConfig) {
    let _ = WHITELISTS.set(RuntimeWhitelists::from_config(config));
}
```

### Layer 7: Path Traversal Protection

All file paths are validated to prevent directory traversal attacks.

**Implementation** (`src/validation/path.rs`):

```rust
/// Allowed path prefixes for file operations.
const ALLOWED_PREFIXES: &[&str] = &[
    "/tmp/lumo/",
    "/private/tmp/lumo/",  // macOS compatibility
    "/home/",
    "/etc/nginx/",
    "/etc/php/",
    "/etc/redis/",
    "/etc/supervisor/",
    "/etc/memcached/",
    "/etc/ssl/",
    "/etc/letsencrypt/",
    "/var/log/",
    "/var/www/",
];

/// Protected files that should never be modified.
const PROTECTED_FILES: &[&str] = &[
    "/etc/passwd",
    "/etc/shadow",
    "/etc/sudoers",
    "/etc/hosts",
    "/etc/resolv.conf",
];

pub fn validate_path(path: impl AsRef<Path>) -> Result<PathBuf, DaemonError> {
    let path = path.as_ref();

    // 1. Check for obvious traversal attempts in the raw path
    let path_str = path.to_string_lossy();
    if path_str.contains("..") {
        return Err(DaemonError::Validation {
            kind: ValidationErrorKind::PathTraversal { path: path.to_path_buf() },
        });
    }

    // 2. Check for symlinks in the path (TOCTOU prevention)
    match contains_symlink(path) {
        Ok(true) => {
            warn!(path = %path.display(), "Rejecting path containing symlink");
            return Err(DaemonError::Validation {
                kind: ValidationErrorKind::PathTraversal { path: path.to_path_buf() },
            });
        }
        Err(e) => { ... }
        Ok(false) => { /* Path is safe */ }
    }

    // 3. Canonicalize and verify against allowed prefixes
    let canonical = check_path.canonicalize()?;

    // 4. Check against protected files
    for protected in PROTECTED_FILES {
        if canonical_str == *protected {
            return Err(DaemonError::Validation {
                kind: ValidationErrorKind::ProtectedFile { path: full_canonical },
            });
        }
    }

    // 5. Verify path is within allowed prefixes
    let is_allowed = ALLOWED_PREFIXES.iter().any(|prefix| canonical_str.starts_with(prefix))
        || get_additional_path_prefixes().iter().any(|prefix| canonical_str.starts_with(prefix));

    if !is_allowed {
        return Err(DaemonError::Validation {
            kind: ValidationErrorKind::PathNotAllowed { path: full_canonical },
        });
    }

    Ok(full_canonical)
}
```

**Symlink Detection**:

```rust
/// Check if any component of the path is a symlink.
fn contains_symlink(path: &Path) -> Result<bool, std::io::Error> {
    let mut current = PathBuf::new();

    for component in path.components() {
        match component {
            Component::RootDir => current.push("/"),
            Component::Normal(name) => {
                current.push(name);
                if current.exists() {
                    // Use symlink_metadata to NOT follow symlinks
                    let metadata = std::fs::symlink_metadata(&current)?;
                    if metadata.file_type().is_symlink() {
                        // Allow known safe system symlinks (/tmp, /var, /home on macOS)
                        if !is_safe_system_symlink(&current) {
                            return Ok(true);
                        }
                    }
                }
            }
            _ => {}
        }
    }

    Ok(false)
}
```

### Layer 8: Error Message Sanitization

Error messages are sanitized before being sent to clients to prevent information disclosure.

**Implementation** (`src/protocol/response.rs`):

```rust
/// Sanitize error messages before sending to clients.
fn sanitize_error_message(code: &str, _original: &str) -> String {
    match code {
        "AUTH_ERROR" => "Authentication failed".to_string(),
        "VALIDATION_ERROR" => "Invalid request parameters".to_string(),
        "COMMAND_ERROR" => "Command execution failed".to_string(),
        "EXECUTION_ERROR" => "Internal execution error".to_string(),
        "INTERNAL_ERROR" => "Internal server error".to_string(),
        "RATE_LIMITED" => "Too many requests".to_string(),
        "CONNECTION_TIMEOUT" => "Connection timed out".to_string(),
        _ => "An error occurred".to_string(),
    }
}

/// Create an error response with a specific request ID.
///
/// The error message is sanitized before being sent to the client.
/// The original error is logged server-side for debugging.
pub fn error_with_id(
    request_id: Uuid,
    code: impl Into<String>,
    message: impl Into<String>,
) -> Self {
    let code_str = code.into();
    let original_message = message.into();

    // Log full error server-side for debugging
    debug!(
        request_id = %request_id,
        code = %code_str,
        message = %original_message,
        "Error response (sanitized for client)"
    );

    Self {
        success: false,
        request_id,
        error: Some(ErrorResponse {
            code: code_str.clone(),
            message: sanitize_error_message(&code_str, &original_message),
            details: None,
        }),
        data: None,
    }
}
```

---

## Secure File Operations

### Atomic Writes

File write operations use atomic write semantics to prevent data corruption and partial writes.

**Implementation** (`src/commands/file/write.rs`):

```rust
/// Write content to a file with atomic write semantics.
pub fn execute(&self, ctx: &ExecutionContext, params: CommandParams) -> Result<CommandResult, DaemonError> {
    let path = validate_path(&path_str)?;

    // 1. Write to a temporary file first (atomic write pattern)
    //    Security: Use random suffix to prevent symlink pre-creation attacks
    let temp_name = format!(
        ".{}.{}.tmp",
        path.file_name().unwrap_or_default().to_string_lossy(),
        Uuid::new_v4().simple()
    );
    let temp_path = path.with_file_name(temp_name);

    // 2. Security: Use create_new() for exclusive creation (O_EXCL)
    //    This prevents TOCTOU races where an attacker creates a file between check and create
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)  // O_EXCL flag
        .open(&temp_path)?;

    // 3. Write content
    file.write_all(content.as_bytes())?;

    // 4. Ensure data is flushed to disk
    file.sync_all()?;

    // 5. Set permissions before moving if specified
    if let Some(mode_str) = &mode_str {
        let mode = parse_mode(mode_str)?;
        let permissions = fs::Permissions::from_mode(mode);
        fs::set_permissions(&temp_path, permissions)?;
    }

    // 6. Set ownership if specified (requires root)
    if owner.is_some() || group.is_some() {
        chown(&temp_path, owner, group)?;
    }

    // 7. Atomic rename - this is the key operation
    //    On POSIX systems, rename() is atomic within the same filesystem
    fs::rename(&temp_path, &path)?;

    Ok(CommandResult::success(...))
}
```

### TOCTOU Prevention

Time-of-Check to Time-of-Use (TOCTOU) attacks are prevented through several mechanisms:

1. **Exclusive File Creation**: Using `OpenOptions::new().create_new(true)` (equivalent to `O_EXCL` flag) ensures the file does not exist when created, preventing race conditions.

2. **Random Temp File Names**: Using UUID-based random suffixes prevents attackers from predicting and pre-creating temp files.

3. **Symlink Detection with `symlink_metadata`**: Using `symlink_metadata()` (equivalent to `lstat()`) instead of `metadata()` (equivalent to `stat()`) allows detection of symlinks without following them.

4. **Atomic Operations**: Using `rename()` for the final move is atomic on POSIX systems, preventing partial states.

---

## Protected Resources

### Protected System Files

The following files are explicitly protected and cannot be modified:

| File | Reason |
|------|--------|
| `/etc/passwd` | User account database |
| `/etc/shadow` | Password hashes |
| `/etc/sudoers` | Sudo privileges |
| `/etc/hosts` | Network hostname resolution |
| `/etc/resolv.conf` | DNS resolver configuration |

### Reserved System Usernames

The following usernames cannot be created or deleted:

```
root, daemon, bin, sys, sync, games, man, lp, mail, news,
uucp, proxy, www-data, backup, list, irc, gnats, nobody,
systemd-network, systemd-resolve, messagebus, sshd,
mysql, postgres, redis, nginx, apache, _apt
```

### Reserved Database Names

The following database names cannot be used:

```
mysql, information_schema, performance_schema, sys,
postgres, template0, template1,
root, admin, test
```

### Restricted Services

Only the following services can be managed:

- **Web Servers**: nginx
- **PHP-FPM**: php8.1-fpm, php8.2-fpm, php8.3-fpm, php8.4-fpm
- **Databases**: mysql, mariadb, postgresql, redis-server
- **Cache**: memcached
- **Process Managers**: supervisor, supervisord

---

## Security Configuration Best Practices

### 1. HMAC Secret Configuration

```bash
# Generate a secure secret
openssl rand -base64 32 > /etc/daemon/hmac.secret

# Set restrictive permissions (REQUIRED)
chmod 0600 /etc/daemon/hmac.secret
chown root:root /etc/daemon/hmac.secret
```

The daemon will refuse to start if the secret file has permissions other than `0600` or `0400`.

### 2. Socket Permissions

```toml
[socket]
path = "/run/daemon/daemon.sock"
permissions = "0660"  # Owner and group can access
```

For maximum security in single-user environments:
```toml
permissions = "0600"  # Only owner can access
```

### 3. Rate Limiting

```toml
[security]
rate_limit_requests = 100      # Max requests per window
rate_limit_window_seconds = 60  # Window duration
```

Adjust based on expected load:
- **Development**: 1000 requests per 60 seconds
- **Production**: 100 requests per 60 seconds
- **High Security**: 20 requests per 60 seconds

### 4. Request Age Limits

```toml
[security]
max_request_age_seconds = 60  # Reject requests older than 60 seconds
```

Lower values increase security but require synchronized clocks:
- **Normal**: 60 seconds
- **High Security**: 30 seconds
- **With NTP sync**: 10 seconds

### 5. Allowed UIDs

```toml
[security]
allowed_uids = [0, 1000]  # Only root and user 1000 can connect
```

**Best Practice**: Use the principle of least privilege - only allow UIDs that genuinely need access.

### 6. Connection Limits

```toml
[limits]
max_concurrent_requests = 10  # Maximum concurrent connections
```

### 7. Extending Whitelists

```toml
[whitelists]
additional_services = ["custom-app"]
additional_packages = ["custom-package"]
additional_path_prefixes = ["/custom/path/"]
additional_repositories = ["ppa:custom/repo"]
```

**Warning**: Extending whitelists increases attack surface. Only add trusted entries.

---

## Threat Model and Mitigations

### Threat: Unauthorized Access

| Attack Vector | Mitigation |
|---------------|------------|
| Network access | Unix socket (no network exposure) |
| Unauthorized local user | Socket permissions + UID whitelist |
| Forged credentials | Kernel-provided SO_PEERCRED/LOCAL_PEERCRED |

### Threat: Replay Attacks

| Attack Vector | Mitigation |
|---------------|------------|
| Captured request replay | Nonce tracking with TTL |
| Old request replay | Timestamp validation |
| Future-dated requests | Clock skew protection (60s tolerance) |

### Threat: Request Forgery

| Attack Vector | Mitigation |
|---------------|------------|
| Modified request | HMAC-SHA256 signature validation |
| Brute-force signature | Cryptographic strength (256-bit) |
| Stolen HMAC secret | File permission enforcement (0600) |

### Threat: Denial of Service

| Attack Vector | Mitigation |
|---------------|------------|
| Request flooding | Per-UID rate limiting |
| Connection exhaustion | Connection semaphore limit |
| Memory exhaustion | Nonce TTL cleanup + rate limit cleanup |

### Threat: Path Traversal

| Attack Vector | Mitigation |
|---------------|------------|
| `../` sequences | Explicit detection + canonicalization |
| Symlink following | `symlink_metadata()` detection |
| Double-encoding | Validation on raw and canonical paths |
| Protected file access | Explicit protected file list |

### Threat: Command Injection

| Attack Vector | Mitigation |
|---------------|------------|
| Shell metacharacters | Whitelist validation, character filtering |
| Malicious service names | Service whitelist |
| Malicious package names | Package whitelist |
| SQL injection | Database name character restrictions |

### Threat: Information Disclosure

| Attack Vector | Mitigation |
|---------------|------------|
| Error message leakage | Error message sanitization |
| Stack traces | Generic error codes for clients |
| File path disclosure | Validation error generalization |

### Threat: Race Conditions (TOCTOU)

| Attack Vector | Mitigation |
|---------------|------------|
| Symlink swap | `symlink_metadata()` + atomic rename |
| File replacement | `O_EXCL` exclusive creation |
| Predictable temp files | UUID-based random names |

---

## Security Checklist for Deployment

### Pre-Deployment

- [ ] Generate HMAC secret with `openssl rand -base64 32`
- [ ] Set HMAC secret file permissions to `0600` or `0400`
- [ ] Configure socket permissions (recommend `0660` or `0600`)
- [ ] Define allowed UIDs list (do not leave empty)
- [ ] Review and minimize whitelist extensions
- [ ] Set appropriate rate limits for expected load
- [ ] Configure request age limits based on clock sync accuracy

### Deployment

- [ ] Verify daemon runs as appropriate user (typically root for system management)
- [ ] Verify socket file created with correct permissions
- [ ] Verify HMAC secret file permissions are enforced
- [ ] Test peer credential verification with unauthorized UID
- [ ] Test rate limiting triggers correctly
- [ ] Verify audit logging is enabled and working

### Post-Deployment

- [ ] Monitor audit logs for suspicious activity
- [ ] Review rate limit metrics for anomalies
- [ ] Rotate HMAC secret periodically (e.g., quarterly)
- [ ] Keep daemon updated for security patches
- [ ] Periodically review whitelist entries

### Incident Response

- [ ] Document procedure for HMAC secret rotation
- [ ] Document procedure for UID whitelist modification
- [ ] Configure log aggregation for audit trails
- [ ] Set up alerting for authentication failures
- [ ] Document recovery procedure for compromised secrets

---

## Summary

The daemon implements a comprehensive security model with eight distinct layers of defense:

1. **Unix Socket Permissions** - OS-level access control
2. **Peer Credential Verification** - Kernel-enforced identity verification
3. **HMAC Signature Validation** - Cryptographic request authentication
4. **Nonce Replay Protection** - Prevents captured request replay
5. **Per-UID Rate Limiting** - DoS protection and abuse prevention
6. **Input Validation Whitelists** - Explicit allow-listing of safe values
7. **Path Traversal Protection** - Filesystem access control
8. **Error Message Sanitization** - Information disclosure prevention

Combined with secure file operations (atomic writes, TOCTOU prevention), protected resource lists, and fail-closed design principles, the daemon provides robust security for privileged system operations.
