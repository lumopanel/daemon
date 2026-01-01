# Wire Protocol

This document describes the wire protocol used for communication between clients and the daemon over Unix domain sockets.

## Protocol Overview

The daemon uses a simple, length-prefixed JSON protocol for all communication. This design provides:

- **Simplicity**: JSON payloads are human-readable and easy to debug
- **Framing**: Length prefixes ensure message boundaries are unambiguous
- **Security**: All requests must be cryptographically signed with HMAC-SHA256
- **Replay protection**: Timestamps and nonces prevent replay attacks

Communication follows a strict request-response pattern where clients send signed requests and receive JSON responses.

## Message Framing Format

All messages (both requests and responses) use length-prefixed framing:

```
+------------------+------------------------+
| Length (4 bytes) | JSON Payload (N bytes) |
+------------------+------------------------+
```

### Length Prefix

- **Size**: 4 bytes
- **Encoding**: Big-endian unsigned 32-bit integer (u32)
- **Value**: The exact byte length of the JSON payload that follows

### Example

For a JSON payload of `{"command":"ping"}` (18 bytes):

```
Bytes 0-3:  0x00 0x00 0x00 0x12  (18 in big-endian)
Bytes 4-21: {"command":"ping"}
```

### Reading Messages

1. Read exactly 4 bytes from the socket
2. Interpret as big-endian u32 to get payload length
3. Validate length against maximum message size
4. Read exactly that many bytes for the JSON payload
5. Parse JSON payload

### Writing Messages

1. Serialize the message to JSON bytes
2. Write the length as 4 big-endian bytes
3. Write the JSON bytes
4. Flush the socket

## Request Format (SignedRequest)

All client requests must conform to the `SignedRequest` structure:

```json
{
  "command": "file.write",
  "params": {
    "path": "/tmp/test.txt",
    "content": "Hello, World!"
  },
  "timestamp": 1704067200,
  "nonce": "550e8400-e29b-41d4-a716-446655440000",
  "signature": "a1b2c3d4e5f6..."
}
```

### Fields

| Field | Type | Description |
|-------|------|-------------|
| `command` | string | The command to execute (e.g., `file.write`, `service.restart`) |
| `params` | object | Command-specific parameters as a JSON object |
| `timestamp` | u64 | Unix timestamp (seconds since epoch) when the request was created |
| `nonce` | string | Unique identifier (UUID v4 recommended) to prevent replay attacks |
| `signature` | string | HMAC-SHA256 signature of the request (hex-encoded) |

### Signature Computation

The signature is computed over a canonical string representation of the request:

```
{command}:{params_json}:{timestamp}:{nonce}
```

Where:
- `command` is the command string
- `params_json` is the JSON-serialized params object
- `timestamp` is the decimal timestamp
- `nonce` is the nonce string

Example signing message:
```
file.write:{"path":"/tmp/test.txt","content":"Hello, World!"}:1704067200:550e8400-e29b-41d4-a716-446655440000
```

The signature is the HMAC-SHA256 of this message using the shared secret key, hex-encoded.

## Response Format

All daemon responses conform to this structure:

```json
{
  "success": true,
  "request_id": "7f3c8a2e-1b4d-4c6f-9e8a-2b5d7c9e0f1a",
  "data": { ... }
}
```

### Fields

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `success` | boolean | Yes | Whether the request succeeded |
| `request_id` | UUID | Yes | Unique identifier for this request/response pair |
| `data` | object | No | Response data (present on success, omitted on failure) |
| `error` | object | No | Error details (present on failure, omitted on success) |

### Success Response Example

```json
{
  "success": true,
  "request_id": "7f3c8a2e-1b4d-4c6f-9e8a-2b5d7c9e0f1a",
  "data": {
    "bytes_written": 13,
    "path": "/tmp/test.txt"
  }
}
```

### Error Response Example

```json
{
  "success": false,
  "request_id": "7f3c8a2e-1b4d-4c6f-9e8a-2b5d7c9e0f1a",
  "error": {
    "code": "VALIDATION_ERROR",
    "message": "Invalid request parameters",
    "details": {
      "field": "path",
      "reason": "Path must be absolute"
    }
  }
}
```

## Error Response Structure

When a request fails, the `error` field contains:

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `code` | string | Yes | Machine-readable error code |
| `message` | string | Yes | Human-readable error message (sanitized) |
| `details` | object | No | Additional error context |

### Error Codes

| Code | Sanitized Message | Description |
|------|-------------------|-------------|
| `AUTH_ERROR` | "Authentication failed" | Signature validation failed or authentication issue |
| `VALIDATION_ERROR` | "Invalid request parameters" | Request parameters are invalid or missing |
| `COMMAND_ERROR` | "Command execution failed" | The command could not be executed |
| `EXECUTION_ERROR` | "Internal execution error" | Error during command execution |
| `INTERNAL_ERROR` | "Internal server error" | Unexpected server-side error |
| `RATE_LIMITED` | "Too many requests" | Client has exceeded rate limits |
| `CONNECTION_TIMEOUT` | "Connection timed out" | Operation timed out |

**Note**: Error messages are sanitized before being sent to clients to prevent information disclosure. Detailed error information is logged server-side for debugging.

## Connection Lifecycle

Understanding the connection lifecycle is important for implementing robust clients.

### Connection States

```
[Client]                                    [Daemon]
    |                                           |
    |-------- Connect (Unix Socket) ----------->|
    |                                           |
    |           [Peer Credential Verification]  |
    |           [UID check against allowed_uids]|
    |                                           |
    |<------- Connection Accepted --------------|
    |                                           |
    |======= Request/Response Loop =============|
    |                                           |
    |-------- Send Signed Request ------------>|
    |                                           |
    |           [Rate Limit Check]              |
    |           [HMAC Validation]               |
    |           [Timestamp Check]               |
    |           [Nonce Check]                   |
    |           [Command Execution]             |
    |                                           |
    |<------- Response ------------------------|
    |                                           |
    |    (repeat for additional requests...)    |
    |                                           |
    |-------- Close Connection ---------------->|
    |                                           |
```

### Persistent Connections

The daemon supports persistent connections. After receiving a response, clients can immediately send another request on the same connection. This is more efficient than establishing a new connection for each request.

**Benefits:**
- Eliminates connection setup overhead
- Peer credentials are verified once per connection
- Useful for batch operations

**Considerations:**
- Each request is independently authenticated (HMAC, nonce, timestamp)
- Rate limiting applies across all requests on the connection
- Idle connections may be closed after the socket timeout

### Connection Termination

Connections can be terminated by:

1. **Client close**: Client closes the socket after completing requests
2. **Idle timeout**: Daemon closes connections that exceed `socket_timeout_seconds` without activity
3. **Read/Write timeout**: Individual operations that exceed the timeout trigger `ConnectionTimeout`
4. **Server shutdown**: Daemon gracefully closes all connections on SIGTERM/SIGINT

### Graceful Shutdown

When the daemon receives a shutdown signal:

1. Stop accepting new connections
2. Allow in-flight requests to complete (up to 30 second timeout)
3. Close all remaining connections
4. Exit cleanly

## Message Size Limits

The protocol enforces a maximum message size to prevent resource exhaustion:

| Limit | Value | Description |
|-------|-------|-------------|
| Default maximum | 1 MB (1,048,576 bytes) | Default maximum message size |
| Configurable via | `limits.max_message_size` | Can be adjusted in daemon.toml |

If a client attempts to send a message larger than the configured maximum:

1. The server reads the 4-byte length prefix
2. If length exceeds the maximum, the server returns a `MessageTooLarge` error
3. The connection may be closed

### Handling Large Messages

If you need to transfer large data:

1. Use chunked transfer with multiple smaller requests
2. Reference external files by path instead of embedding content
3. Request a configuration change for the specific use case

## Timeout Handling

The protocol supports timeouts for both read and write operations:

| Operation | Behavior |
|-----------|----------|
| Read timeout | If reading a message takes longer than the timeout, a `ConnectionTimeout` error is raised |
| Write timeout | If writing a message takes longer than the timeout, a `ConnectionTimeout` error is raised |

Clients should:

1. Set reasonable timeouts for their use case
2. Handle timeout errors gracefully
3. Implement retry logic with exponential backoff if appropriate

## Example Client Implementation

Below is pseudocode for a minimal client implementation:

```python
import socket
import json
import hmac
import hashlib
import time
import uuid

class DaemonClient:
    def __init__(self, socket_path, secret_key):
        self.socket_path = socket_path
        self.secret_key = secret_key
        self.sock = None

    def connect(self):
        """Connect to the daemon socket."""
        self.sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.sock.connect(self.socket_path)

    def disconnect(self):
        """Close the connection."""
        if self.sock:
            self.sock.close()
            self.sock = None

    def send_request(self, command, params=None):
        """Send a signed request and return the response."""
        if params is None:
            params = {}

        # Build the request
        request = {
            "command": command,
            "params": params,
            "timestamp": int(time.time()),
            "nonce": str(uuid.uuid4()),
            "signature": ""  # Will be computed
        }

        # Compute signature
        signing_message = f"{command}:{json.dumps(params)}:{request['timestamp']}:{request['nonce']}"
        signature = hmac.new(
            self.secret_key.encode(),
            signing_message.encode(),
            hashlib.sha256
        ).hexdigest()
        request["signature"] = signature

        # Serialize and send
        payload = json.dumps(request).encode()
        length = len(payload).to_bytes(4, byteorder='big')
        self.sock.sendall(length + payload)

        # Read response
        length_bytes = self._read_exact(4)
        response_length = int.from_bytes(length_bytes, byteorder='big')
        response_bytes = self._read_exact(response_length)

        return json.loads(response_bytes)

    def _read_exact(self, n):
        """Read exactly n bytes from the socket."""
        data = b''
        while len(data) < n:
            chunk = self.sock.recv(n - len(data))
            if not chunk:
                raise ConnectionError("Connection closed")
            data += chunk
        return data


# Usage example
client = DaemonClient("/var/run/daemon.sock", "your-secret-key")
client.connect()

response = client.send_request("file.read", {"path": "/etc/hostname"})
if response["success"]:
    print("Content:", response["data"])
else:
    print("Error:", response["error"]["message"])

client.disconnect()
```

### Key Implementation Points

1. **Socket type**: Use `AF_UNIX` and `SOCK_STREAM` for Unix domain sockets
2. **Byte order**: Always use big-endian for the length prefix
3. **Read exactly**: Ensure you read the exact number of bytes specified
4. **Signature format**: The signing message must match the server's expected format exactly
5. **JSON serialization**: Ensure consistent JSON serialization for signature verification

## Debugging Tips

### 1. Capture Raw Traffic

Use `socat` to inspect raw socket traffic:

```bash
# Create a proxy that logs traffic
socat -v UNIX-LISTEN:/tmp/debug.sock,fork UNIX-CONNECT:/var/run/daemon.sock
```

### 2. Verify Message Framing

If you receive parse errors, verify the length prefix:

```python
# Hex dump the first few bytes
data = sock.recv(20)
print("Length bytes:", data[:4].hex())
print("Length value:", int.from_bytes(data[:4], 'big'))
print("Payload start:", data[4:])
```

### 3. Check Signature Computation

Common signature issues:

- **Wrong byte order in length prefix**: Must be big-endian
- **JSON serialization differences**: Whitespace or key ordering
- **Encoding issues**: Ensure UTF-8 encoding throughout
- **Clock skew**: Timestamp may be rejected if too far from server time

Debug signature computation:

```python
# Print the exact signing message
signing_msg = f"{command}:{json.dumps(params)}:{timestamp}:{nonce}"
print("Signing message:", repr(signing_msg))
print("Signature:", hmac.new(key, signing_msg.encode(), hashlib.sha256).hexdigest())
```

### 4. Handle Connection Errors

Common connection issues:

| Error | Possible Cause | Solution |
|-------|---------------|----------|
| Connection refused | Daemon not running | Start the daemon |
| Permission denied | Socket permissions | Check socket file permissions |
| Connection reset | Server closed connection | Check server logs, retry |
| Timeout | Slow response or deadlock | Increase timeout, check server |

### 5. Enable Server Logging

Increase server log verbosity to see detailed request processing:

```bash
RUST_LOG=debug ./daemon
```

Server logs include:
- Request receipt and parsing
- Signature verification results
- Command execution details
- Full error information (sanitized in responses)

### 6. Test with Simple Commands

Start with simple commands to verify connectivity:

```python
# Test basic connectivity
response = client.send_request("ping", {})
print(response)
```

### 7. Validate JSON Payload

Before sending, validate your JSON:

```python
import json

payload = json.dumps(request)
print("Payload length:", len(payload))
print("Payload:", payload)

# Verify it can be parsed
parsed = json.loads(payload)
assert parsed == request
```

## Example Wire Format Exchanges

This section provides complete examples showing the exact bytes sent over the wire, useful for implementing clients or debugging protocol issues.

### Example 1: Simple Ping Request

A minimal request to verify connectivity.

**Request JSON:**
```json
{
  "command": "system.ping",
  "params": {},
  "timestamp": 1704067200,
  "nonce": "550e8400-e29b-41d4-a716-446655440000",
  "signature": "a1b2c3d4e5f6789012345678901234567890abcdef1234567890abcdef123456"
}
```

**Wire Format (hex dump):**
```
Offset  Hex                                              ASCII
------  -----------------------------------------------  ----------------
0000    00 00 00 c8                                      ....
        ^^^^^^^^^^ Length prefix: 200 bytes (0x000000c8)

0004    7b 22 63 6f 6d 6d 61 6e  64 22 3a 22 73 79 73 74  {"command":"syst
0014    65 6d 2e 70 69 6e 67 22  2c 22 70 61 72 61 6d 73  em.ping","params
0024    22 3a 7b 7d 2c 22 74 69  6d 65 73 74 61 6d 70 22  ":{},"timestamp"
0034    3a 31 37 30 34 30 36 37  32 30 30 2c 22 6e 6f 6e  :1704067200,"non
0044    63 65 22 3a 22 35 35 30  65 38 34 30 30 2d 65 32  ce":"550e8400-e2
0054    39 62 2d 34 31 64 34 2d  61 37 31 36 2d 34 34 36  9b-41d4-a716-446
0064    36 35 35 34 34 30 30 30  30 22 2c 22 73 69 67 6e  655440000","sign
0074    61 74 75 72 65 22 3a 22  61 31 62 32 63 33 64 34  ature":"a1b2c3d4
0084    65 35 66 36 37 38 39 30  31 32 33 34 35 36 37 38  e5f6789012345678
0094    39 30 31 32 33 34 35 36  37 38 39 30 61 62 63 64  901234567890abcd
00a4    65 66 31 32 33 34 35 36  37 38 39 30 61 62 63 64  ef1234567890abcd
00b4    65 66 31 32 33 34 35 36  22 7d                    ef123456"}
```

**Signing Message (for HMAC computation):**
```
system.ping:{}:1704067200:550e8400-e29b-41d4-a716-446655440000
```

**Success Response JSON:**
```json
{
  "success": true,
  "request_id": "7f3c8a2e-1b4d-4c6f-9e8a-2b5d7c9e0f1a",
  "data": {
    "message": "pong",
    "timestamp": 1704067200
  }
}
```

**Response Wire Format (hex dump):**
```
Offset  Hex                                              ASCII
------  -----------------------------------------------  ----------------
0000    00 00 00 7a                                      ...z
        ^^^^^^^^^^ Length prefix: 122 bytes (0x0000007a)

0004    7b 22 73 75 63 63 65 73  73 22 3a 74 72 75 65 2c  {"success":true,
0014    22 72 65 71 75 65 73 74  5f 69 64 22 3a 22 37 66  "request_id":"7f
0024    33 63 38 61 32 65 2d 31  62 34 64 2d 34 63 36 66  3c8a2e-1b4d-4c6f
0034    2d 39 65 38 61 2d 32 62  35 64 37 63 39 65 30 66  -9e8a-2b5d7c9e0f
0044    31 61 22 2c 22 64 61 74  61 22 3a 7b 22 6d 65 73  1a","data":{"mes
0054    73 61 67 65 22 3a 22 70  6f 6e 67 22 2c 22 74 69  sage":"pong","ti
0064    6d 65 73 74 61 6d 70 22  3a 31 37 30 34 30 36 37  mestamp":1704067
0074    32 30 30 7d 7d                                   200}}
```

### Example 2: File Write Request

A request to write content to a file.

**Request JSON:**
```json
{
  "command": "file.write",
  "params": {
    "path": "/tmp/test.txt",
    "content": "Hello, World!",
    "mode": "0644"
  },
  "timestamp": 1704067200,
  "nonce": "660e8400-e29b-41d4-a716-446655440001",
  "signature": "b2c3d4e5f67890123456789012345678901234567890abcdef1234567890ab"
}
```

**Signing Message:**
```
file.write:{"path":"/tmp/test.txt","content":"Hello, World!","mode":"0644"}:1704067200:660e8400-e29b-41d4-a716-446655440001
```

**Wire Format - Length Prefix Breakdown:**

| Bytes | Hex | Decimal | Description |
|-------|-----|---------|-------------|
| 0-3 | `00 00 01 0a` | 266 | JSON payload length |
| 4+ | `7b 22 63 6f...` | - | JSON payload bytes |

**Success Response:**
```json
{
  "success": true,
  "request_id": "8e4d9b3f-2c5e-4d7g-0f9b-3c6e8d0g2h3i",
  "data": {
    "bytes_written": 13,
    "path": "/tmp/test.txt"
  }
}
```

### Example 3: Error Response

When authentication fails (e.g., invalid signature):

**Error Response JSON:**
```json
{
  "success": false,
  "request_id": "9f5e0c4g-3d6f-5e8h-1g0c-4d7f9e1h3i4j",
  "error": {
    "code": "AUTH_ERROR",
    "message": "Authentication failed"
  }
}
```

**Wire Format (hex dump):**
```
Offset  Hex                                              ASCII
------  -----------------------------------------------  ----------------
0000    00 00 00 8c                                      ....
        ^^^^^^^^^^ Length prefix: 140 bytes (0x0000008c)

0004    7b 22 73 75 63 63 65 73  73 22 3a 66 61 6c 73 65  {"success":false
0014    2c 22 72 65 71 75 65 73  74 5f 69 64 22 3a 22 39  ,"request_id":"9
0024    66 35 65 30 63 34 67 2d  33 64 36 66 2d 35 65 38  f5e0c4g-3d6f-5e8
0034    68 2d 31 67 30 63 2d 34  64 37 66 39 65 31 68 33  h-1g0c-4d7f9e1h3
0044    69 34 6a 22 2c 22 65 72  72 6f 72 22 3a 7b 22 63  i4j","error":{"c
0054    6f 64 65 22 3a 22 41 55  54 48 5f 45 52 52 4f 52  ode":"AUTH_ERROR
0064    22 2c 22 6d 65 73 73 61  67 65 22 3a 22 41 75 74  ","message":"Aut
0074    68 65 6e 74 69 63 61 74  69 6f 6e 20 66 61 69 6c  hentication fail
0084    65 64 22 7d 7d                                   ed"}}
```

### Example 4: Complete Request/Response Byte Sequence

Here is a complete byte-by-byte example for a `service.restart` command:

**1. Request Bytes (Client -> Daemon):**

```
# Length prefix (4 bytes, big-endian)
00 00 01 2b    # 299 bytes

# JSON payload (299 bytes)
7b 22 63 6f 6d 6d 61 6e 64 22 3a 22 73 65 72 76
69 63 65 2e 72 65 73 74 61 72 74 22 2c 22 70 61
72 61 6d 73 22 3a 7b 22 73 65 72 76 69 63 65 22
3a 22 6e 67 69 6e 78 22 7d 2c 22 74 69 6d 65 73
74 61 6d 70 22 3a 31 37 30 34 30 36 37 32 30 30
2c 22 6e 6f 6e 63 65 22 3a 22 37 37 30 65 38 34
30 30 2d 65 32 39 62 2d 34 31 64 34 2d 61 37 31
36 2d 34 34 36 36 35 35 34 34 30 30 30 32 22 2c
22 73 69 67 6e 61 74 75 72 65 22 3a 22 63 33 64
34 65 35 66 36 37 38 39 30 31 32 33 34 35 36 37
38 39 30 31 32 33 34 35 36 37 38 39 30 31 32 33
34 35 36 37 38 39 30 61 62 63 64 65 66 31 32 33
34 35 36 37 38 39 30 61 62 63 64 65 66 22 7d
```

**Decoded JSON:**
```json
{
  "command": "service.restart",
  "params": {"service": "nginx"},
  "timestamp": 1704067200,
  "nonce": "770e8400-e29b-41d4-a716-446655440002",
  "signature": "c3d4e5f6789012345678901234567890123456789012345678901234567890abcdef"
}
```

**2. Response Bytes (Daemon -> Client):**

```
# Length prefix (4 bytes, big-endian)
00 00 00 96    # 150 bytes

# JSON payload (150 bytes)
7b 22 73 75 63 63 65 73 73 22 3a 74 72 75 65 2c
22 72 65 71 75 65 73 74 5f 69 64 22 3a 22 61 62
63 64 65 66 31 32 2d 33 34 35 36 2d 37 38 39 30
2d 61 62 63 64 2d 65 66 31 32 33 34 35 36 37 38
22 2c 22 64 61 74 61 22 3a 7b 22 6d 65 73 73 61
67 65 22 3a 22 53 65 72 76 69 63 65 20 72 65 73
74 61 72 74 65 64 20 73 75 63 63 65 73 73 66 75
6c 6c 79 22 2c 22 73 65 72 76 69 63 65 22 3a 22
6e 67 69 6e 78 22 7d 7d
```

**Decoded JSON:**
```json
{
  "success": true,
  "request_id": "abcdef12-3456-7890-abcd-ef1234567890",
  "data": {
    "message": "Service restarted successfully",
    "service": "nginx"
  }
}
```

### Computing Length Prefix

To compute the 4-byte big-endian length prefix:

```python
def make_length_prefix(length: int) -> bytes:
    """Convert an integer to a 4-byte big-endian length prefix."""
    return length.to_bytes(4, byteorder='big')

# Example
json_payload = b'{"command":"system.ping","params":{}}'
length = len(json_payload)  # 37
prefix = make_length_prefix(length)  # b'\x00\x00\x00%'

# Full message
message = prefix + json_payload
```

```rust
fn make_length_prefix(length: usize) -> [u8; 4] {
    (length as u32).to_be_bytes()
}

// Example
let json_payload = b"{\"command\":\"system.ping\",\"params\":{}}";
let length = json_payload.len();  // 37
let prefix = make_length_prefix(length);  // [0, 0, 0, 37]
```

### Parsing Length Prefix

To parse the 4-byte big-endian length prefix:

```python
def parse_length_prefix(prefix_bytes: bytes) -> int:
    """Parse a 4-byte big-endian length prefix."""
    return int.from_bytes(prefix_bytes, byteorder='big')

# Example
prefix = b'\x00\x00\x00\x25'  # First 4 bytes from socket
length = parse_length_prefix(prefix)  # 37
```

```rust
fn parse_length_prefix(prefix: [u8; 4]) -> usize {
    u32::from_be_bytes(prefix) as usize
}

// Example
let prefix = [0x00, 0x00, 0x00, 0x25];
let length = parse_length_prefix(prefix);  // 37
```
