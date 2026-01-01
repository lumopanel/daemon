# Configuration

The Lumo daemon is configured through a TOML configuration file. This document describes all available configuration options, their default values, and environment-specific considerations.

## Configuration File Location

The daemon expects its configuration file at `/etc/lumo/daemon.toml` by default. You can specify an alternate location using the `--config` command-line option:

```bash
lumo-daemon --config /path/to/custom/daemon.toml
```

## Configuration File Format

The configuration file uses [TOML](https://toml.io/) format. TOML is a human-readable configuration format that uses simple key-value pairs organized into sections (tables).

Example structure:

```toml
[section]
key = "value"
number = 42
list = ["item1", "item2"]
```

---

## Configuration Sections

### socket

Controls the Unix domain socket used for client-daemon communication.

| Setting | Type | Default | Required | Description |
|---------|------|---------|----------|-------------|
| `path` | String | - | **Yes** | Path to the Unix socket file |
| `permissions` | String | `"0660"` | No | Socket file permissions (octal format) |
| `owner` | String | `"root"` | No | Socket file owner username |
| `group` | String | `"www-data"` | No | Socket file group name |

**Example:**

```toml
[socket]
path = "/var/run/lumo/daemon.sock"
permissions = "0660"
owner = "root"
group = "www-data"
```

**Notes:**
- The socket permissions should be restrictive. `0660` allows read/write for owner and group only.
- The `group` setting typically matches the web server group (e.g., `www-data` for nginx/Apache on Debian/Ubuntu).
- The parent directory must exist and be writable by the daemon process.

---

### security

Controls authentication, authorization, and rate limiting.

| Setting | Type | Default | Required | Description |
|---------|------|---------|----------|-------------|
| `hmac_secret_path` | String | - | **Yes** | Path to the HMAC secret key file |
| `nonce_ttl_seconds` | Integer | `300` | No | Nonce time-to-live for replay prevention (seconds) |
| `max_request_age_seconds` | Integer | `60` | No | Maximum age of valid requests (seconds) |
| `allowed_peer_uids` | Array[Integer] | `[]` | No | List of allowed Unix user IDs |
| `rate_limit_requests` | Integer | `100` | No | Maximum requests per UID per window |
| `rate_limit_window_seconds` | Integer | `60` | No | Rate limit window duration (seconds) |

**Example:**

```toml
[security]
hmac_secret_path = "/etc/lumo/hmac.key"
nonce_ttl_seconds = 300
max_request_age_seconds = 60
allowed_peer_uids = [33]  # www-data UID on Debian/Ubuntu
rate_limit_requests = 100
rate_limit_window_seconds = 60
```

**Notes:**
- The HMAC secret file **must** have restrictive permissions (`0600`) and contain a secure random key.
- `allowed_peer_uids` implements fail-closed security: an empty list rejects all connections.
- To find a user's UID, use: `id -u username`
- Common UIDs:
  - `33` - www-data on Debian/Ubuntu
  - `82` - www-data on Alpine Linux
  - `48` - apache on RHEL/CentOS

---

### redis

Configures the Redis connection used for nonce storage and rate limiting.

| Setting | Type | Default | Required | Description |
|---------|------|---------|----------|-------------|
| `url` | String | `"redis://127.0.0.1:6379"` | No | Redis connection URL |
| `pool_size` | Integer | `4` | No | Connection pool size |

**Example:**

```toml
[redis]
url = "redis://127.0.0.1:6379"
pool_size = 4
```

**URL Format:**

```
redis://[username:password@]host[:port][/database]
```

Examples:
- `redis://127.0.0.1:6379` - Local Redis, default port
- `redis://127.0.0.1:6379/0` - Local Redis, database 0
- `redis://:password@redis.example.com:6379` - Remote with password
- `redis://user:password@redis.example.com:6379/1` - Full authentication

**Notes:**
- Pool size should be tuned based on expected concurrent connections.
- For high-traffic scenarios, increase `pool_size` proportionally.

---

### paths

Configures file system paths for templates and logs.

| Setting | Type | Default | Required | Description |
|---------|------|---------|----------|-------------|
| `templates_dir` | String | `"/usr/share/lumo/templates"` | No | Directory containing built-in templates |
| `custom_templates_dir` | String | `"/etc/lumo/templates"` | No | Directory containing custom templates |
| `log_dir` | String | `"/var/log/lumo"` | No | Directory for log files |

**Example:**

```toml
[paths]
templates_dir = "/usr/share/lumo/templates"
custom_templates_dir = "/etc/lumo/templates"
log_dir = "/var/log/lumo"
```

**Notes:**
- Custom templates in `custom_templates_dir` override built-in templates with the same name.
- All directories must exist and be readable by the daemon process.
- The `log_dir` must be writable if file logging is enabled.

---

### logging

Configures daemon logging behavior.

| Setting | Type | Default | Required | Description |
|---------|------|---------|----------|-------------|
| `level` | String | `"info"` | No | Log level |
| `format` | String | `"pretty"` | No | Log output format |
| `file` | String | `null` | No | Log file path (optional) |

**Log Levels** (from most to least verbose):
- `trace` - Extremely detailed debugging information
- `debug` - Debugging information
- `info` - General operational information
- `warn` - Warning conditions
- `error` - Error conditions

**Log Formats:**
- `pretty` - Human-readable colored output (recommended for development)
- `json` - Structured JSON output (recommended for production/log aggregation)

**Example:**

```toml
[logging]
level = "info"
format = "json"
file = "/var/log/lumo/daemon.log"
```

**Notes:**
- If `file` is not specified, logs are written to stdout.
- For systemd services, stdout logging is typically preferred as journald handles log management.
- Use `json` format when integrating with log aggregation systems (ELK, Loki, etc.).

---

### limits

Configures operational limits for the daemon.

| Setting | Type | Default | Required | Description |
|---------|------|---------|----------|-------------|
| `max_message_size` | Integer | `1048576` | No | Maximum message size in bytes (1 MB) |
| `default_timeout_seconds` | Integer | `60` | No | Default command execution timeout |
| `max_concurrent_requests` | Integer | `100` | No | Maximum simultaneous requests |
| `socket_timeout_seconds` | Integer | `30` | No | Socket read/write timeout |

**Example:**

```toml
[limits]
max_message_size = 1048576      # 1 MB
default_timeout_seconds = 60
max_concurrent_requests = 100
socket_timeout_seconds = 30
```

**Notes:**
- `max_message_size` prevents memory exhaustion from oversized requests.
- `default_timeout_seconds` applies to command execution; individual commands may override this.
- `max_concurrent_requests` limits resource usage under load.
- `socket_timeout_seconds` prevents hung connections from consuming resources.

---

### audit

Configures security audit logging.

| Setting | Type | Default | Required | Description |
|---------|------|---------|----------|-------------|
| `enabled` | Boolean | `true` | No | Enable/disable audit logging |
| `log_path` | String | `"/var/log/lumo/audit.log"` | No | Path to audit log file |

**Example:**

```toml
[audit]
enabled = true
log_path = "/var/log/lumo/audit.log"
```

**Notes:**
- Audit logs record all daemon operations for security review.
- The audit log file must be writable by the daemon process.
- For compliance requirements, ensure audit logs are preserved and rotated appropriately.

---

### whitelists

Configures additional allowed values beyond the secure built-in defaults. These lists **extend** (not replace) the defaults.

| Setting | Type | Default | Description |
|---------|------|---------|-------------|
| `additional_services` | Array[String] | `[]` | Additional systemd services that can be controlled |
| `additional_packages` | Array[String] | `[]` | Additional packages that can be installed |
| `additional_php_versions` | Array[String] | `[]` | Additional PHP versions (beyond 8.1-8.4) |
| `additional_php_extensions` | Array[String] | `[]` | Additional PHP extensions |
| `additional_repositories` | Array[String] | `[]` | Additional PPA repositories |
| `additional_path_prefixes` | Array[String] | `[]` | Additional path prefixes for file operations |

**Example:**

```toml
[whitelists]
# Allow controlling a custom service
additional_services = ["my-custom-app", "another-service"]

# Allow installing custom packages
additional_packages = ["custom-package", "internal-tool"]

# Allow PHP 8.5 when released
additional_php_versions = ["8.5"]

# Allow additional PHP extensions
additional_php_extensions = ["custom-ext", "proprietary-ext"]

# Allow additional PPA repositories
additional_repositories = ["ppa:custom/repo"]

# Allow file operations in custom paths (must end with /)
additional_path_prefixes = ["/opt/myapp/", "/srv/custom/"]
```

**Notes:**
- These settings extend built-in whitelists; they do not replace them.
- Path prefixes **must** end with a forward slash (`/`).
- Exercise caution when extending whitelists as it expands the daemon's attack surface.

---

## Complete Configuration Example

```toml
# Lumo Daemon Configuration
# /etc/lumo/daemon.toml

[socket]
path = "/var/run/lumo/daemon.sock"
permissions = "0660"
owner = "root"
group = "www-data"

[security]
hmac_secret_path = "/etc/lumo/hmac.key"
nonce_ttl_seconds = 300
max_request_age_seconds = 60
allowed_peer_uids = [33]
rate_limit_requests = 100
rate_limit_window_seconds = 60

[redis]
url = "redis://127.0.0.1:6379"
pool_size = 4

[paths]
templates_dir = "/usr/share/lumo/templates"
custom_templates_dir = "/etc/lumo/templates"
log_dir = "/var/log/lumo"

[logging]
level = "info"
format = "json"
file = "/var/log/lumo/daemon.log"

[limits]
max_message_size = 1048576
default_timeout_seconds = 60
max_concurrent_requests = 100
socket_timeout_seconds = 30

[audit]
enabled = true
log_path = "/var/log/lumo/audit.log"

[whitelists]
additional_services = []
additional_packages = []
additional_php_versions = []
additional_php_extensions = []
additional_repositories = []
additional_path_prefixes = []
```

---

## Default Values Summary

| Section | Setting | Default Value |
|---------|---------|---------------|
| socket | permissions | `"0660"` |
| socket | owner | `"root"` |
| socket | group | `"www-data"` |
| security | nonce_ttl_seconds | `300` |
| security | max_request_age_seconds | `60` |
| security | allowed_peer_uids | `[]` |
| security | rate_limit_requests | `100` |
| security | rate_limit_window_seconds | `60` |
| redis | url | `"redis://127.0.0.1:6379"` |
| redis | pool_size | `4` |
| paths | templates_dir | `"/usr/share/lumo/templates"` |
| paths | custom_templates_dir | `"/etc/lumo/templates"` |
| paths | log_dir | `"/var/log/lumo"` |
| logging | level | `"info"` |
| logging | format | `"pretty"` |
| logging | file | `null` (stdout) |
| limits | max_message_size | `1048576` (1 MB) |
| limits | default_timeout_seconds | `60` |
| limits | max_concurrent_requests | `100` |
| limits | socket_timeout_seconds | `30` |
| audit | enabled | `true` |
| audit | log_path | `"/var/log/lumo/audit.log"` |
| whitelists | (all) | `[]` |

---

## Environment-Specific Considerations

### Development Environment

For local development and testing, use relaxed settings:

```toml
[socket]
path = "/tmp/lumo-daemon.sock"
permissions = "0666"  # Allow all users
owner = "root"
group = "wheel"  # macOS group

[security]
hmac_secret_path = "./test-config/hmac.secret"
allowed_peer_uids = []  # Empty = testing mode (allow all)

[paths]
templates_dir = "./templates"
custom_templates_dir = "./custom-templates"
log_dir = "/tmp/lumo-logs"

[logging]
level = "debug"
format = "pretty"
# No file = stdout logging

[audit]
enabled = true
log_path = "/tmp/lumo-logs/audit.log"
```

**Warning:** Never use development settings in production. Empty `allowed_peer_uids` and permissive socket permissions are security risks.

### Production Environment

For production deployments:

```toml
[socket]
path = "/var/run/lumo/daemon.sock"
permissions = "0660"
owner = "root"
group = "www-data"

[security]
hmac_secret_path = "/etc/lumo/hmac.key"
nonce_ttl_seconds = 300
max_request_age_seconds = 60
allowed_peer_uids = [33]  # Specific UID only
rate_limit_requests = 100
rate_limit_window_seconds = 60

[logging]
level = "info"  # Or "warn" for quieter logs
format = "json"  # For log aggregation
file = "/var/log/lumo/daemon.log"

[audit]
enabled = true
log_path = "/var/log/lumo/audit.log"
```

### High-Traffic Environment

For high-traffic scenarios, tune limits and pool sizes:

```toml
[redis]
pool_size = 16  # Increase pool size

[limits]
max_concurrent_requests = 500  # Handle more simultaneous requests
socket_timeout_seconds = 15    # Fail faster on hung connections

[security]
rate_limit_requests = 500      # Higher rate limit
rate_limit_window_seconds = 60
```

### Containerized Deployment

For Docker/container deployments:

```toml
[socket]
path = "/var/run/lumo/daemon.sock"
# Socket can be mounted as a volume for host communication

[redis]
url = "redis://redis:6379"  # Use container hostname

[logging]
level = "info"
format = "json"
# No file - log to stdout for container log collection

[paths]
templates_dir = "/app/templates"
custom_templates_dir = "/app/custom-templates"
log_dir = "/var/log/lumo"
```

---

## Configuration Validation

The daemon validates configuration on startup. Invalid configurations cause the daemon to exit with an error message.

**Validated settings:**
- `logging.level` must be one of: `trace`, `debug`, `info`, `warn`, `error`
- `logging.format` must be one of: `pretty`, `json`
- `socket.permissions` must be a valid octal string (e.g., `"0660"`)

**Example error:**
```
Error: Invalid log level 'verbose'. Valid levels: ["trace", "debug", "info", "warn", "error"]
```

---

## Generating HMAC Secret

The HMAC secret should be a cryptographically secure random key:

```bash
# Generate a 256-bit secret
openssl rand -base64 32 > /etc/lumo/hmac.key

# Set restrictive permissions
chmod 600 /etc/lumo/hmac.key
chown root:root /etc/lumo/hmac.key
```

**Important:** The HMAC secret must be:
- At least 32 bytes (256 bits) for security
- Kept confidential and not committed to version control
- Shared securely with clients that need to communicate with the daemon
