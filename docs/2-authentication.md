# Authentication

This document describes the authentication system used by the Lumo Daemon to secure client-server communication over Unix domain sockets.

## Overview

The Lumo Daemon implements a multi-layered authentication system that combines:

1. **Unix Peer Credential Verification** - Verifies the connecting process identity using `SO_PEERCRED` (Linux) or `LOCAL_PEERCRED` (macOS)
2. **HMAC-SHA256 Request Signing** - Cryptographic signature verification for all requests
3. **Nonce-Based Replay Protection** - Prevents replay attacks using unique, time-limited nonces
4. **Request Timestamp Validation** - Rejects stale or future-dated requests
5. **Per-UID Rate Limiting** - Sliding window rate limiting to prevent abuse

## Authentication Flow

```
Client                                         Daemon
  |                                              |
  |------- Connect via Unix Socket ------------->|
  |                                              |
  |                    [1. Verify Peer Credentials (UID check)]
  |                                              |
  |<------ Connection Accepted/Rejected ---------|
  |                                              |
  |------- Send Signed Request ----------------->|
  |         {command, params, timestamp,         |
  |          nonce, signature}                   |
  |                                              |
  |                    [2. Validate Timestamp (freshness check)]
  |                    [3. Verify HMAC Signature]
  |                    [4. Check Nonce (replay prevention)]
  |                    [5. Apply Rate Limiting]
  |                                              |
  |<------ Response or Error --------------------|
```

All five checks must pass for a request to be processed. The daemon uses a "fail-closed" security model - any authentication failure results in request rejection.

---

## HMAC-SHA256 Signature Generation

### Signing Message Format

The signature is computed over a canonical message string with the following format:

```
{command}:{params_json}:{timestamp}:{nonce}
```

Where:
- `command` - The command string (e.g., `"file.write"`, `"service.restart"`)
- `params_json` - The JSON-serialized parameters object (compact, no extra whitespace)
- `timestamp` - Unix timestamp as a decimal integer (seconds since epoch)
- `nonce` - Unique identifier string (typically a UUID v4)

**Example signing message:**

```
file.write:{"path":"/tmp/test","content":"hello"}:1703980800:550e8400-e29b-41d4-a716-446655440000
```

### Computing the Signature

1. Construct the signing message string as described above
2. Compute HMAC-SHA256 using the shared secret key
3. Encode the resulting signature as lowercase hexadecimal

The daemon uses the `ring` cryptographic library for HMAC operations, specifically `ring::hmac::HMAC_SHA256`.

### Shared Secret Requirements

The HMAC secret is loaded from a file with strict permission requirements:

- **Permissions**: Must be `0600` or `0400` (owner read/write or read-only)
- **Group/World bits**: Must all be zero (no access for group or others)
- **Minimum length**: Should be at least 32 bytes for security

If the secret file has insecure permissions, the daemon will refuse to start.

### Client-Side Signature Generation

#### Rust Example

```rust
use ring::hmac;
use serde_json::json;
use std::time::{SystemTime, UNIX_EPOCH};
use uuid::Uuid;

fn create_signed_request(
    command: &str,
    params: serde_json::Value,
    secret: &[u8],
) -> SignedRequest {
    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let nonce = Uuid::new_v4().to_string();

    // Construct signing message
    let params_json = serde_json::to_string(&params).unwrap();
    let signing_message = format!("{}:{}:{}:{}", command, params_json, timestamp, nonce);

    // Compute HMAC-SHA256
    let key = hmac::Key::new(hmac::HMAC_SHA256, secret);
    let tag = hmac::sign(&key, signing_message.as_bytes());
    let signature = hex::encode(tag.as_ref());

    SignedRequest {
        command: command.to_string(),
        params,
        timestamp,
        nonce,
        signature,
    }
}
```

#### Python Example

```python
import hmac
import hashlib
import json
import time
import uuid

def create_signed_request(command: str, params: dict, secret: bytes) -> dict:
    timestamp = int(time.time())
    nonce = str(uuid.uuid4())

    # Construct signing message
    params_json = json.dumps(params, separators=(',', ':'))  # Compact JSON
    signing_message = f"{command}:{params_json}:{timestamp}:{nonce}"

    # Compute HMAC-SHA256
    signature = hmac.new(
        secret,
        signing_message.encode('utf-8'),
        hashlib.sha256
    ).hexdigest()

    return {
        "command": command,
        "params": params,
        "timestamp": timestamp,
        "nonce": nonce,
        "signature": signature
    }

# Example usage
secret = b"your-32-byte-secret-key-here!!!"
request = create_signed_request(
    "file.write",
    {"path": "/tmp/test", "content": "hello"},
    secret
)
```

#### Shell/cURL Example

```bash
#!/bin/bash

# Configuration
SECRET="your-32-byte-secret-key-here!!!"
COMMAND="file.write"
PARAMS='{"path":"/tmp/test","content":"hello"}'
TIMESTAMP=$(date +%s)
NONCE=$(uuidgen | tr '[:upper:]' '[:lower:]')

# Construct signing message
SIGNING_MESSAGE="${COMMAND}:${PARAMS}:${TIMESTAMP}:${NONCE}"

# Compute HMAC-SHA256 signature
SIGNATURE=$(echo -n "$SIGNING_MESSAGE" | openssl dgst -sha256 -hmac "$SECRET" | awk '{print $2}')

# Build JSON request
REQUEST=$(cat <<EOF
{
  "command": "$COMMAND",
  "params": $PARAMS,
  "timestamp": $TIMESTAMP,
  "nonce": "$NONCE",
  "signature": "$SIGNATURE"
}
EOF
)

echo "$REQUEST"
```

#### Go Example

```go
package main

import (
    "crypto/hmac"
    "crypto/sha256"
    "encoding/hex"
    "encoding/json"
    "fmt"
    "time"

    "github.com/google/uuid"
)

type SignedRequest struct {
    Command   string                 `json:"command"`
    Params    map[string]interface{} `json:"params"`
    Timestamp int64                  `json:"timestamp"`
    Nonce     string                 `json:"nonce"`
    Signature string                 `json:"signature"`
}

func CreateSignedRequest(command string, params map[string]interface{}, secret []byte) SignedRequest {
    timestamp := time.Now().Unix()
    nonce := uuid.New().String()

    // Construct signing message
    paramsJSON, _ := json.Marshal(params)
    signingMessage := fmt.Sprintf("%s:%s:%d:%s", command, string(paramsJSON), timestamp, nonce)

    // Compute HMAC-SHA256
    h := hmac.New(sha256.New, secret)
    h.Write([]byte(signingMessage))
    signature := hex.EncodeToString(h.Sum(nil))

    return SignedRequest{
        Command:   command,
        Params:    params,
        Timestamp: timestamp,
        Nonce:     nonce,
        Signature: signature,
    }
}
```

---

## Nonce-Based Replay Protection

### Purpose

Nonces prevent replay attacks where an attacker captures a valid signed request and re-sends it to the daemon. Each nonce can only be used once within its time-to-live (TTL) window.

### Nonce Requirements

- **Uniqueness**: Each nonce must be unique across all requests within the TTL window
- **Format**: String value (UUID v4 recommended for guaranteed uniqueness)
- **Length**: No strict limit, but UUIDs (36 characters) are typical

### TTL and Expiry

The nonce store maintains an in-memory map of used nonces with the following behavior:

| Parameter | Description |
|-----------|-------------|
| TTL | Time-to-live for stored nonces (typically 300 seconds / 5 minutes) |
| Lazy Cleanup | Expired nonces are removed during subsequent `check_and_store` calls |
| Background Cleanup | Optional periodic cleanup task prevents unbounded memory growth |

**How it works:**

1. When a request arrives, the nonce is checked against the store
2. If the nonce exists and hasn't expired, the request is rejected (`NonceReused`)
3. If the nonce is new or expired, it's stored with an expiry timestamp
4. The nonce will be retained until its TTL expires

**Important**: The nonce TTL should be at least as long as the request `max_age` to ensure proper replay protection. If the nonce expires before the request would be rejected for being stale, a replay window exists.

### Memory Management

The `NonceStore` provides methods for memory management:

```rust
// Get current number of stored nonces
let count = nonce_store.len();

// Force cleanup of expired nonces
nonce_store.cleanup();

// Start background cleanup task (recommended for production)
nonce_store.start_cleanup_task(Duration::from_secs(60));
```

---

## Unix Peer Credential Verification

The daemon verifies the identity of connecting clients using kernel-level peer credentials, which cannot be spoofed by userspace processes.

### SO_PEERCRED (Linux)

On Linux, the daemon uses the `SO_PEERCRED` socket option to retrieve:

| Field | Description |
|-------|-------------|
| `uid` | User ID of the connecting process |
| `gid` | Group ID of the connecting process |
| `pid` | Process ID of the connecting process |

### LOCAL_PEERCRED (macOS)

On macOS, the daemon uses `LOCAL_PEERCRED` with the `xucred` structure:

| Field | Description |
|-------|-------------|
| `cr_uid` | User ID of the connecting process |
| `cr_groups[0]` | Primary group ID |
| PID | Not available on macOS via this mechanism |

### Allowed UIDs Configuration

The daemon maintains a list of allowed UIDs that are permitted to connect:

```rust
// Example: Allow root (0) and specific user (1000)
let allowed_uids = vec![0, 1000];

let peer_info = verify_peer(&stream, &allowed_uids)?;
println!("Authenticated peer: UID={}, GID={}", peer_info.uid, peer_info.gid);
```

**Security Notes:**

- **Fail-closed**: If the allowed UIDs list is empty, ALL connections are rejected
- **No wildcards**: Each allowed UID must be explicitly listed
- **Root access**: Including UID 0 grants root processes access

### PeerInfo Structure

Successfully verified connections return a `PeerInfo` structure:

```rust
pub struct PeerInfo {
    pub uid: u32,   // User ID
    pub gid: u32,   // Group ID
    pub pid: i32,   // Process ID (may be 0 on macOS)
}
```

---

## Request Timestamp Validation

Timestamps prevent old captured requests from being replayed after their nonces have expired.

### Validation Rules

| Check | Condition | Error |
|-------|-----------|-------|
| Too old | `now - timestamp > max_age` | `RequestExpired` |
| Future | `timestamp > now + 60` | `RequestExpired` |

- **Max Age**: Configurable, typically 60 seconds
- **Clock Skew Tolerance**: 60 seconds into the future is allowed to handle minor clock differences

### Timestamp Format

- Unix timestamp (seconds since January 1, 1970 00:00:00 UTC)
- 64-bit unsigned integer
- No fractional seconds

### Example Validation Flow

```
Request timestamp: 1703980800
Current time:      1703980830
Max age:           60 seconds

Age = 1703980830 - 1703980800 = 30 seconds
30 < 60 --> Request is valid (timestamp check passes)
```

---

## Rate Limiting per UID

The daemon implements sliding window rate limiting to prevent abuse and denial-of-service attacks.

### How It Works

Each UID has a separate request counter with timestamps:

1. When a request arrives, old timestamps outside the window are removed
2. If the remaining count is at or above the limit, the request is rejected
3. Otherwise, the current timestamp is added and the request proceeds

### Configuration

```rust
// Allow 100 requests per 60 seconds per UID
let limiter = RateLimiter::new(100, 60);
```

| Parameter | Description |
|-----------|-------------|
| `max_requests` | Maximum requests allowed per window |
| `window_seconds` | Duration of the sliding window |

### Sliding Window Behavior

Unlike fixed windows that reset at intervals, the sliding window counts requests within the last N seconds from the current time. This provides smoother rate limiting without allowing bursts at window boundaries.

**Example:**

```
Window: 60 seconds
Max requests: 5

Time    Request  Count  Allowed?
----------------------------------
t=0     R1       1      Yes
t=10    R2       2      Yes
t=20    R3       3      Yes
t=30    R4       4      Yes
t=40    R5       5      Yes
t=50    R6       5      No (limit reached)
t=61    R7       4      Yes (R1 expired)
```

### Memory Management

The rate limiter tracks request timestamps per UID. For production deployments with many clients:

```rust
// Periodically clean up stale entries
limiter.cleanup();
```

---

## Common Authentication Errors and Troubleshooting

### Error Reference

| Error | Cause | Solution |
|-------|-------|----------|
| `UnauthorizedPeer { uid }` | Connecting UID not in allowed list | Add the UID to the allowed list or connect as an authorized user |
| `InvalidSignature` | HMAC signature verification failed | Check secret key matches, verify signing message format |
| `NonceReused` | Same nonce used in multiple requests | Generate a new unique nonce for each request |
| `RequestExpired { age_seconds }` | Request timestamp too old or in future | Ensure client clock is synchronized, reduce request latency |
| `HmacSecretError` | Cannot load or invalid HMAC secret file | Check file exists, has correct permissions (0600/0400) |
| `RateLimited` | Too many requests from this UID | Wait for the rate limit window to pass, reduce request frequency |

### Troubleshooting Guide

#### "InvalidSignature" Errors

1. **Verify the secret key**: Ensure client and daemon use the same secret
2. **Check signing message format**: Must be exactly `{command}:{params_json}:{timestamp}:{nonce}`
3. **JSON serialization**: Ensure compact JSON with no extra whitespace
4. **Encoding**: Signature must be lowercase hexadecimal
5. **Byte-level comparison**: Print the signing message on both sides to compare

**Debug checklist:**

```bash
# On client, print the signing message before computing HMAC
echo "Signing message: ${COMMAND}:${PARAMS}:${TIMESTAMP}:${NONCE}"

# Verify signature manually
echo -n "file.write:{\"path\":\"/tmp/test\"}:1703980800:abc123" | \
  openssl dgst -sha256 -hmac "your-secret-key"
```

#### "RequestExpired" Errors

1. **Check system clock**: Run `date` on both client and server
2. **Synchronize with NTP**: Ensure both systems use NTP
3. **Network latency**: High latency can cause requests to expire in transit
4. **Increase max_age**: If clock sync is difficult, consider a larger window

#### "NonceReused" Errors

1. **Check nonce generation**: Ensure truly random/unique nonces
2. **Don't retry with same nonce**: Generate new nonce for each request
3. **UUID recommended**: Use UUID v4 for guaranteed uniqueness

#### "UnauthorizedPeer" Errors

1. **Check your UID**: Run `id -u` to see your user ID
2. **Verify allowed_uids**: Ensure your UID is in the daemon's allowed list
3. **Run as correct user**: Use `sudo -u <user>` if needed

#### "HmacSecretError" - Permission Issues

```bash
# Check current permissions
ls -la /path/to/hmac.secret

# Fix permissions
chmod 600 /path/to/hmac.secret

# Verify owner
chown <daemon_user>:<daemon_group> /path/to/hmac.secret
```

### Security Best Practices

1. **Rotate secrets periodically**: Change HMAC secrets on a regular schedule
2. **Use strong secrets**: At least 32 bytes of cryptographically random data
3. **Minimize allowed UIDs**: Only add UIDs that truly need access
4. **Monitor rate limiting**: Track rate limit hits to detect abuse
5. **Sync clocks**: Use NTP to keep client and server clocks aligned
6. **Secure secret storage**: Never commit secrets to version control

### Generating a Secure HMAC Secret

```bash
# Generate a 32-byte random secret
openssl rand -hex 32 > /etc/lumo/hmac.secret
chmod 600 /etc/lumo/hmac.secret
```

Or in a development environment:

```bash
# Generate and display (don't use in production)
openssl rand -hex 32
```
