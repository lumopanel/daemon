# Lumo Daemon

A secure privilege daemon for executing privileged operations via Unix domain sockets. Lumo Daemon provides a safe interface for web applications to perform system administration tasks that require elevated privileges.

## Features

- **Secure Authentication**: HMAC-SHA256 signed requests with nonce-based replay protection
- **Peer Verification**: Unix socket peer credentials (SO_PEERCRED) for UID-based authorization
- **Rate Limiting**: Per-UID rate limiting to prevent abuse
- **Comprehensive Audit Logging**: JSON-lines audit trail with sensitive data redaction
- **Path Validation**: Multi-layer protection against path traversal and symlink attacks
- **Atomic File Operations**: Safe file writes using temp file + rename pattern
- **Template Engine**: Tera-based configuration file generation
- **Systemd Integration**: Service management via systemctl

## Supported Commands

| Category | Commands |
|----------|----------|
| **File Operations** | `file.write`, `file.write_template`, `file.delete`, `file.mkdir`, `file.chmod` |
| **Service Management** | `service.start`, `service.stop`, `service.restart`, `service.reload`, `service.status`, `service.enable`, `service.disable` |
| **Database** | `database.create_db`, `database.drop_db`, `database.create_user` |
| **SSL/TLS** | `ssl.install_cert`, `ssl.request_letsencrypt` |
| **PHP** | `php.install_version`, `php.remove_version`, `php.install_extension`, `php.write_ini` |
| **Nginx** | `nginx.enable_site`, `nginx.disable_site`, `nginx.test_config` |
| **Packages** | `package.install`, `package.remove`, `package.update`, `package.add_repository` |
| **Users** | `user.create`, `user.delete` |
| **System** | `system.ping`, `system.metrics` |

## Quick Start

### Prerequisites

- Rust 1.70+ (for building)
- Linux with systemd (for deployment)
- Root access (daemon runs as root)

### Building

```bash
cargo build --release
```

### Installation

```bash
# Download and run the install script
curl -sSL https://raw.githubusercontent.com/lumopanel/daemon/main/deploy/install.sh | sudo bash
```

Or manually:

```bash
# Copy binary
sudo cp target/release/lumo-daemon /usr/bin/
sudo chmod 755 /usr/bin/lumo-daemon

# Create directories
sudo mkdir -p /etc/lumo/templates /var/run/lumo /var/log/lumo

# Copy configuration
sudo cp deploy/daemon.toml.example /etc/lumo/daemon.toml
sudo chmod 600 /etc/lumo/daemon.toml

# Generate HMAC secret
sudo head -c 32 /dev/urandom > /etc/lumo/hmac.key
sudo chmod 600 /etc/lumo/hmac.key

# Install systemd service
sudo cp deploy/lumo-daemon.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now lumo-daemon
```

### Configuration

Edit `/etc/lumo/daemon.toml` to configure:

- `security.allowed_peer_uids`: UIDs allowed to connect (e.g., `[33]` for www-data)
- `security.hmac_secret_path`: Path to the HMAC secret file
- `paths.socket_path`: Unix socket location
- `whitelists.*`: Additional allowed services, packages, paths

See [Configuration Documentation](docs/4-configuration.md) for full options.

## Client Example

```rust
use std::os::unix::net::UnixStream;
use std::io::{Read, Write};

// Connect to the daemon
let mut stream = UnixStream::connect("/var/run/lumo/daemon.sock")?;

// Build signed request
let request = json!({
    "command": "system.ping",
    "params": {},
    "timestamp": current_unix_timestamp(),
    "nonce": uuid::Uuid::new_v4().to_string(),
    "signature": compute_hmac_signature(...)
});

// Send length-prefixed JSON
let json_bytes = serde_json::to_vec(&request)?;
stream.write_all(&(json_bytes.len() as u32).to_be_bytes())?;
stream.write_all(&json_bytes)?;

// Read response
let mut len_buf = [0u8; 4];
stream.read_exact(&mut len_buf)?;
let len = u32::from_be_bytes(len_buf) as usize;
let mut response_buf = vec![0u8; len];
stream.read_exact(&mut response_buf)?;

let response: serde_json::Value = serde_json::from_slice(&response_buf)?;
println!("Response: {}", response);
```

## Security

Lumo Daemon implements defense-in-depth security:

- **Authentication**: Multi-layer auth (peer UID + HMAC signature + nonce)
- **Authorization**: Whitelist-based service, package, and path validation
- **Input Validation**: Strict validation of all parameters
- **Sandboxing**: Systemd security hardening (ProtectSystem, PrivateTmp, etc.)
- **Audit Trail**: All operations logged with sanitized parameters

See [Security Documentation](docs/5-security.md) for details.

## Documentation

- [Authentication](docs/2-authentication.md)
- [Commands Overview](docs/3-commands.md)
- [Configuration](docs/4-configuration.md)
- [Security](docs/5-security.md)
- [Audit Logging](docs/6-audit-logging.md)
- [Wire Protocol](docs/7-wire-protocol.md)

## Development

```bash
# Run tests
cargo test

# Run with debug logging
RUST_LOG=debug cargo run -- --config config/daemon.example.toml

# Check formatting
cargo fmt --check

# Run clippy
cargo clippy --all-targets --all-features -- -D warnings
```

## License

MIT License - see [LICENSE](LICENSE) for details.

## Contributing

Contributions are welcome! Please ensure:

1. All tests pass (`cargo test`)
2. Code is formatted (`cargo fmt`)
3. No clippy warnings (`cargo clippy -- -D warnings`)
4. Security-sensitive changes are documented
