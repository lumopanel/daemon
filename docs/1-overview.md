# Lumo Daemon Overview

Lumo Daemon is a privilege daemon for executing privileged operations via Unix socket. It enables unprivileged web applications to safely execute system administration commands by delegating privileged operations to a trusted daemon running with elevated permissions.

## Use Case

Web hosting control panels and similar applications often need to perform system-level operations (creating users, managing services, installing packages) but should not run with root privileges. Lumo Daemon solves this by:

1. Running as a privileged service (typically as root)
2. Listening on a Unix socket with restricted permissions
3. Authenticating requests via peer credentials and HMAC signatures
4. Executing only whitelisted, validated commands
5. Providing comprehensive audit logging

## Architecture Overview

The daemon is organized into modular components, each with a focused responsibility:

```
+------------------+     +------------------+     +------------------+
|     socket       |---->|      auth        |---->|    commands      |
| (listener,       |     | (peer_creds,     |     | (registry,       |
|  connection)     |     |  hmac, nonce,    |     |  traits, types)  |
+------------------+     |  rate_limit)     |     +------------------+
                         +------------------+              |
                                                           v
+------------------+     +------------------+     +------------------+
|     audit        |<----|    executor      |<----|   validation     |
| (entry, logger,  |     | (subprocess,     |     | (path, domain,   |
|  sanitize)       |     |  timeout)        |     |  username, ...)  |
+------------------+     +------------------+     +------------------+
                                                           |
+------------------+     +------------------+              v
|     config       |     |    protocol      |     +------------------+
| (settings)       |     | (request,        |     |    templates     |
+------------------+     |  response, wire) |     | (engine)         |
                         +------------------+     +------------------+
```

### Module Responsibilities

| Module | Purpose |
|--------|---------|
| `socket` | Unix socket listener and per-connection handling |
| `auth` | Peer credential verification, HMAC validation, nonce tracking, rate limiting |
| `commands` | Command registry, trait definitions, and command implementations |
| `executor` | Safe subprocess spawning with timeout support |
| `validation` | Input validators for paths, domains, usernames, packages, etc. |
| `audit` | Structured JSON audit logging with parameter sanitization |
| `protocol` | Wire format (length-prefixed JSON), request/response types |
| `config` | TOML configuration loading and settings management |
| `templates` | Tera template engine for generating configuration files |
| `services` | Service manager abstraction (systemd, etc.) |

### Command Categories

The registry includes commands for:

- **System**: `system.ping`, `system.metrics`
- **File**: `file.write`, `file.delete`, `file.create_dir`, `file.set_permissions`, `file.write_template`
- **Service**: `service.start`, `service.stop`, `service.restart`, `service.reload`, `service.enable`, `service.disable`, `service.status`
- **Package**: `package.install`, `package.remove`, `package.update`, `package.add_repository`
- **Database**: `database.create_db`, `database.create_user`, `database.drop_db`
- **SSL**: `ssl.install_cert`, `ssl.request_letsencrypt`
- **PHP**: `php.install_version`, `php.remove_version`, `php.install_extension`, `php.write_ini`
- **Nginx**: `nginx.enable_site`, `nginx.disable_site`, `nginx.test_config`
- **User**: `user.create`, `user.delete`

## Key Design Principles

### Defense-in-Depth Security

Multiple security layers protect against unauthorized access:

1. **Unix socket permissions**: Only specific users/groups can connect
2. **Peer credential verification**: Kernel-verified UID/GID/PID of connecting process
3. **Allowed UID whitelist**: Only configured UIDs may send commands
4. **HMAC request signing**: Requests must be signed with a shared secret
5. **Nonce tracking**: Prevents replay attacks via Redis-backed nonce store
6. **Per-UID rate limiting**: Prevents abuse from any single user
7. **Input validation**: Strict validation of all command parameters
8. **Whitelisted commands**: Only registered commands can be executed
9. **No shell execution**: Commands are executed as subprocesses with explicit arguments
10. **Comprehensive audit logging**: All operations are logged for forensics

### Async Rust with Tokio

The daemon uses Tokio for efficient async I/O:

- Non-blocking socket accept and connection handling
- Concurrent request processing across connections
- Graceful shutdown with connection draining (30s timeout)
- Signal handling (SIGTERM/SIGINT for shutdown, SIGHUP for config reload)
- Timeout support for all I/O operations

### Registry-Based Command Dispatch

Commands are registered in a central registry (`CommandRegistry`) that:

- Maps command names to handler implementations
- Enforces the `Command` trait interface (name, validate, execute)
- Validates parameters before execution
- Enables easy addition of new commands
- Supports introspection (listing available commands)

## Technology Stack

| Component | Technology | Purpose |
|-----------|------------|---------|
| Language | Rust 2021 Edition | Memory safety, performance |
| Async Runtime | Tokio | Non-blocking I/O, concurrency |
| Cryptography | Ring | HMAC-SHA256 signing/verification |
| Serialization | Serde + serde_json | JSON encoding/decoding |
| Configuration | TOML | Human-readable config files |
| Templates | Tera | Configuration file generation |
| Logging | Tracing + tracing-subscriber | Structured logging (JSON/pretty) |
| Unix APIs | nix, users | Socket credentials, user lookup |
| Nonce Store | Redis | Distributed replay attack prevention |
| Error Handling | thiserror, anyhow | Typed error handling |

## Request Flow

```
Client Application (unprivileged, e.g., www-data)
        |
        | 1. Connect to Unix socket
        v
+------------------+
|  SocketListener  |  2. Accept connection
+------------------+
        |
        | 3. Verify peer credentials (SO_PEERCRED)
        v
+------------------+
|   verify_peer    |  4. Check UID against allowed list
+------------------+
        |
        | 5. Read length-prefixed JSON message
        v
+------------------+
|  SignedRequest   |  6. Parse request (command, params, timestamp, nonce, signature)
+------------------+
        |
        | 7. Check rate limit for UID
        v
+------------------+
|   RateLimiter    |
+------------------+
        |
        | 8. Validate HMAC signature
        v
+------------------+
|  HmacValidator   |  9. Check nonce not reused (prevent replay)
+------------------+
        |
        | 10. Look up command in registry
        v
+------------------+
| CommandRegistry  |  11. Validate command parameters
+------------------+
        |
        | 12. Execute command (spawn_blocking for sync ops)
        v
+------------------+
|  Command impl    |  13. Run operation (file write, subprocess, etc.)
+------------------+
        |
        | 14. Log to audit log (sanitized params)
        v
+------------------+
|   AuditLogger    |
+------------------+
        |
        | 15. Send JSON response
        v
Client Application
```

## Wire Protocol

Messages use length-prefixed JSON framing:

```
+----------------+---------------------------+
|  Length (4B)   |      JSON Payload         |
|  big-endian    |                           |
+----------------+---------------------------+
```

### Request Example

```json
{
  "command": "service.restart",
  "params": { "service": "nginx" },
  "timestamp": 1703808000,
  "nonce": "550e8400-e29b-41d4-a716-446655440000",
  "signature": "a1b2c3d4e5f6..."
}
```

### Response Example

```json
{
  "request_id": "660e8400-e29b-41d4-a716-446655440001",
  "success": true,
  "data": { "message": "Service restarted successfully" }
}
```

## Configuration

The daemon reads configuration from TOML (default: `/etc/lumo/daemon.toml`):

- **Socket**: Path, permissions, owner/group
- **Security**: Allowed peer UIDs, HMAC secret path, nonce TTL
- **Logging**: Level (debug/info/warn/error), format (pretty/json)
- **Limits**: Max message size, socket timeout, rate limits
- **Audit**: Log path, retention settings
- **Whitelists**: Additional allowed services, packages, paths

Configuration can be reloaded at runtime via SIGHUP without restarting the daemon.

## Further Reading

- [Authentication](./2-authentication.md) - HMAC signing, peer credentials, nonce tracking
- [Commands](./3-commands.md) - Full command reference and parameters
- [Configuration](./4-configuration.md) - Detailed configuration options
- [Security](./5-security.md) - Security architecture and best practices
- [Audit Logging](./6-audit-logging.md) - Audit log format and analysis
- [Wire Protocol](./7-wire-protocol.md) - Protocol specification
