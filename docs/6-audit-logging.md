# Audit Logging

The daemon includes a comprehensive audit logging system that records all command executions for security monitoring, compliance, and debugging purposes.

## Overview

The audit logging system provides:

- **Structured JSON logging**: All entries are written in JSON Lines format (one JSON object per line)
- **Automatic parameter sanitization**: Sensitive values are redacted before logging
- **Content truncation**: Large payloads are automatically truncated to prevent log bloat
- **Thread-safe operation**: Multiple concurrent requests can safely write to the audit log
- **Durable writes**: Each entry is synced to disk immediately after writing
- **Peer identification**: Full tracking of who made each request (UID, GID, PID)

## Log Entry Format

Audit entries are written as JSON Lines - one complete JSON object per line. This format is easily parsed by log analysis tools like `jq`, Elasticsearch, Splunk, and others.

### Entry Structure

```json
{
  "timestamp": "2024-01-15T10:30:45.123Z",
  "request_id": "550e8400-e29b-41d4-a716-446655440000",
  "command": "file.write",
  "params": {
    "path": "/var/www/example.com/config.php",
    "content": "[TRUNCATED - 5000 bytes]"
  },
  "peer_uid": 33,
  "peer_gid": 33,
  "peer_pid": 12345,
  "result": {
    "status": "success",
    "data": {"bytes_written": 5000}
  },
  "duration_ms": 15
}
```

## Fields Captured

### timestamp

ISO 8601 formatted timestamp when the command was executed.

```json
"timestamp": "2024-01-15T10:30:45.123Z"
```

### request_id

UUID v4 identifier that uniquely identifies each request. This ID is also included in responses and can be used to correlate logs with client-side debugging.

```json
"request_id": "550e8400-e29b-41d4-a716-446655440000"
```

### command

The command that was executed (e.g., `file.write`, `service.restart`, `nginx.create_vhost`).

```json
"command": "file.write"
```

### params (Sanitized Parameters)

The command parameters with sensitive values redacted and large content truncated. See [Sensitive Data Sanitization](#sensitive-data-sanitization) for details.

```json
"params": {
  "path": "/tmp/test.txt",
  "content": "Hello, World!",
  "api_key": "[REDACTED]"
}
```

### Peer Information

Information about the Unix socket peer that made the request:

| Field | Type | Description |
|-------|------|-------------|
| `peer_uid` | u32 | User ID of the requesting process |
| `peer_gid` | u32 | Group ID of the requesting process |
| `peer_pid` | i32 | Process ID of the requesting process |

```json
"peer_uid": 33,
"peer_gid": 33,
"peer_pid": 12345
```

This information is obtained from the Unix socket peer credentials and cannot be spoofed by the client.

### result

The result of command execution, tagged by status:

**Success result:**
```json
"result": {
  "status": "success",
  "data": {"bytes_written": 100}
}
```

Note: The `data` field is optional and omitted when there is no result data.

**Failure result:**
```json
"result": {
  "status": "failure",
  "error_code": "VALIDATION_ERROR",
  "error_message": "Path not allowed"
}
```

### duration_ms

Execution duration in milliseconds, useful for performance monitoring and identifying slow commands.

```json
"duration_ms": 15
```

## Sensitive Data Sanitization

The audit system automatically sanitizes parameters before logging to prevent sensitive information from appearing in logs.

### Redacted Keys

Any parameter key containing these words (case-insensitive) will have its value replaced with `[REDACTED]`:

- `password`
- `secret`
- `key`
- `token`
- `credential`
- `private_key`
- `hmac_secret`
- `api_key`
- `auth`
- `authorization`

**Example:**
```json
// Original parameters
{
  "username": "admin",
  "password": "super_secret_123",
  "api_key": "sk-1234567890"
}

// Sanitized in audit log
{
  "username": "admin",
  "password": "[REDACTED]",
  "api_key": "[REDACTED]"
}
```

The matching is substring-based, so keys like `user_credentials`, `my_secret_config`, or `auth_header` will also be redacted.

### Content Truncation

Large string values in content-related fields are automatically truncated to prevent log bloat. Fields containing these words are subject to truncation:

- `content`
- `data`
- `body`
- `payload`

Strings exceeding 1024 characters are replaced with a size indicator:

```json
// Original
{"content": "... 5000 characters of data ..."}

// Sanitized
{"content": "[TRUNCATED - 5000 bytes]"}
```

### Nested Object Handling

Sanitization is applied recursively to nested objects and arrays:

```json
// Original
{
  "user": {
    "name": "test",
    "login": {
      "password": "secret123"
    }
  },
  "users": [
    {"name": "user1", "password": "pass1"},
    {"name": "user2", "password": "pass2"}
  ]
}

// Sanitized
{
  "user": {
    "name": "test",
    "login": {
      "password": "[REDACTED]"
    }
  },
  "users": [
    {"name": "user1", "password": "[REDACTED]"},
    {"name": "user2", "password": "[REDACTED]"}
  ]
}
```

## Configuration Options

Audit logging is configured in the daemon's TOML configuration file under the `[audit]` section:

```toml
[audit]
# Enable or disable audit logging (default: true)
enabled = true

# Path to the audit log file (default: /var/log/lumo/audit.log)
log_path = "/var/log/lumo/audit.log"
```

### Configuration Options Reference

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `enabled` | boolean | `true` | Enable or disable audit logging |
| `log_path` | string | `/var/log/lumo/audit.log` | Path to the audit log file |

When `enabled` is `false`, a null logger is used that discards all audit entries.

### Directory Creation

The audit logger automatically creates parent directories if they don't exist. For example, if `log_path` is set to `/var/log/lumo/audit/daemon.log`, the `/var/log/lumo/audit` directory will be created automatically.

## Log Rotation Recommendations

Since the daemon appends to the audit log continuously, log rotation is essential to prevent disk space exhaustion.

### Using logrotate

Create a logrotate configuration at `/etc/logrotate.d/lumo-audit`:

```
/var/log/lumo/audit.log {
    daily
    rotate 30
    compress
    delaycompress
    missingok
    notifempty
    copytruncate
    dateext
    dateformat -%Y%m%d
}
```

Key options:

- `daily`: Rotate logs daily
- `rotate 30`: Keep 30 days of logs
- `compress`: Compress rotated logs with gzip
- `delaycompress`: Don't compress the most recent rotated file (useful for debugging)
- `copytruncate`: Copy the log and truncate in place (avoids needing to signal the daemon)
- `dateext`: Add date extension to rotated files

### Size-Based Rotation

For high-volume environments, consider size-based rotation:

```
/var/log/lumo/audit.log {
    size 100M
    rotate 10
    compress
    delaycompress
    missingok
    notifempty
    copytruncate
}
```

### Archival Considerations

For compliance requirements, consider:

1. **Long-term archival**: Copy compressed logs to archival storage before rotation removes them
2. **Integrity verification**: Generate checksums for archived logs
3. **Retention policies**: Implement scripts to enforce retention periods

Example archival script:

```bash
#!/bin/bash
ARCHIVE_DIR="/archive/lumo-audit"
LOG_DIR="/var/log/lumo"

# Archive compressed logs older than 7 days
find "$LOG_DIR" -name "audit.log-*.gz" -mtime +7 -exec mv {} "$ARCHIVE_DIR/" \;

# Generate checksums
cd "$ARCHIVE_DIR"
sha256sum audit.log-*.gz > checksums.sha256
```

## Example Log Entries

### Successful File Write

```json
{"timestamp":"2024-01-15T10:30:45.123Z","request_id":"550e8400-e29b-41d4-a716-446655440000","command":"file.write","params":{"path":"/var/www/example.com/index.php","content":"[TRUNCATED - 2500 bytes]","mode":"0644"},"peer_uid":33,"peer_gid":33,"peer_pid":12345,"result":{"status":"success","data":{"bytes_written":2500}},"duration_ms":8}
```

### Failed Permission Validation

```json
{"timestamp":"2024-01-15T10:31:00.456Z","request_id":"661f9511-f30c-52e5-b827-557766551111","command":"file.write","params":{"path":"/etc/passwd"},"peer_uid":1000,"peer_gid":1000,"peer_pid":23456,"result":{"status":"failure","error_code":"VALIDATION_ERROR","error_message":"Path not allowed"},"duration_ms":2}
```

### Service Restart

```json
{"timestamp":"2024-01-15T10:32:15.789Z","request_id":"772a0622-a41d-63f6-c938-668877662222","command":"service.restart","params":{"name":"nginx"},"peer_uid":33,"peer_gid":33,"peer_pid":34567,"result":{"status":"success"},"duration_ms":1250}
```

### Request with Sensitive Data

```json
{"timestamp":"2024-01-15T10:33:30.012Z","request_id":"883b1733-b52e-74g7-d049-779988773333","command":"database.create_user","params":{"username":"app_user","password":"[REDACTED]","database":"myapp"},"peer_uid":33,"peer_gid":33,"peer_pid":45678,"result":{"status":"success"},"duration_ms":45}
```

## Querying and Analyzing Audit Logs

### Using jq

The JSON Lines format makes `jq` ideal for querying audit logs:

```bash
# View all entries (pretty-printed)
cat /var/log/lumo/audit.log | jq .

# Filter by command
cat /var/log/lumo/audit.log | jq 'select(.command == "file.write")'

# Filter by status
cat /var/log/lumo/audit.log | jq 'select(.result.status == "failure")'

# Filter by peer UID
cat /var/log/lumo/audit.log | jq 'select(.peer_uid == 33)'

# Find slow commands (> 1 second)
cat /var/log/lumo/audit.log | jq 'select(.duration_ms > 1000)'

# Get error summary
cat /var/log/lumo/audit.log | jq 'select(.result.status == "failure") | {command, error: .result.error_code}' | jq -s 'group_by(.error) | map({error: .[0].error, count: length})'

# Commands by frequency
cat /var/log/lumo/audit.log | jq -r '.command' | sort | uniq -c | sort -rn
```

### Time-Based Queries

```bash
# Filter by date range (requires gdate on macOS or date on Linux)
START=$(date -d "2024-01-15T00:00:00" +%s)
END=$(date -d "2024-01-16T00:00:00" +%s)

cat /var/log/lumo/audit.log | jq --argjson start "$START" --argjson end "$END" '
  select(
    (.timestamp | fromdateiso8601) >= $start and
    (.timestamp | fromdateiso8601) < $end
  )'
```

### Aggregation Examples

```bash
# Commands per hour
cat /var/log/lumo/audit.log | jq -r '.timestamp[:13]' | sort | uniq -c

# Average duration by command
cat /var/log/lumo/audit.log | jq -s 'group_by(.command) | map({command: .[0].command, avg_ms: (map(.duration_ms) | add / length)})'

# Failed requests by peer
cat /var/log/lumo/audit.log | jq 'select(.result.status == "failure")' | jq -s 'group_by(.peer_uid) | map({uid: .[0].peer_uid, failures: length})'
```

### Integration with Log Analysis Tools

**Elasticsearch/OpenSearch:**
```bash
# Index logs to Elasticsearch
cat /var/log/lumo/audit.log | while read line; do
  curl -X POST "http://localhost:9200/lumo-audit/_doc" \
    -H "Content-Type: application/json" \
    -d "$line"
done
```

**Filebeat configuration:**
```yaml
filebeat.inputs:
  - type: log
    paths:
      - /var/log/lumo/audit.log
    json.keys_under_root: true
    json.add_error_key: true

output.elasticsearch:
  hosts: ["localhost:9200"]
  index: "lumo-audit-%{+yyyy.MM.dd}"
```

## Compliance Considerations

The audit logging system supports various compliance requirements:

### SOC 2 / ISO 27001

- **Access logging**: All API access is logged with peer credentials
- **Change tracking**: All file modifications, service changes, and configuration updates are recorded
- **Timestamp accuracy**: ISO 8601 timestamps with millisecond precision
- **Immutability**: Append-only log format (use file permissions to prevent modification)

### GDPR / Privacy

- **Data minimization**: Sensitive parameters are automatically redacted
- **Content truncation**: Large payloads are summarized, not stored in full
- **Log retention**: Configure logrotate to enforce retention periods

### PCI DSS

- **Audit trail**: Complete record of all privileged actions
- **User identification**: UID/GID/PID tracking identifies the acting user
- **Tamper protection**: Use file permissions and integrity monitoring

### Recommended Security Measures

1. **File permissions**: Restrict audit log access
   ```bash
   chmod 640 /var/log/lumo/audit.log
   chown root:adm /var/log/lumo/audit.log
   ```

2. **Integrity monitoring**: Use AIDE or similar tools
   ```bash
   # /etc/aide/aide.conf
   /var/log/lumo/audit.log$ f p+i+n+u+g+s+sha256
   ```

3. **Real-time alerting**: Monitor for security events
   ```bash
   # Example: Alert on unauthorized access attempts
   tail -F /var/log/lumo/audit.log | jq --unbuffered 'select(.result.error_code == "UNAUTHORIZED")' | while read line; do
     # Send alert
     echo "$line" | mail -s "Lumo Security Alert" security@example.com
   done
   ```

4. **Centralized logging**: Forward logs to a SIEM
   ```bash
   # rsyslog configuration
   module(load="imfile")
   input(type="imfile"
         File="/var/log/lumo/audit.log"
         Tag="lumo-audit"
         Severity="info"
         Facility="local0")
   ```

### Audit Log Fields for Compliance Mapping

| Compliance Requirement | Audit Field(s) |
|----------------------|----------------|
| Who performed the action | `peer_uid`, `peer_gid`, `peer_pid` |
| What action was performed | `command`, `params` |
| When it occurred | `timestamp` |
| Whether it succeeded | `result.status` |
| Why it failed | `result.error_code`, `result.error_message` |
| Request correlation | `request_id` |
| Performance metrics | `duration_ms` |

## Commands Exempt from Audit Logging

Certain commands are excluded from audit logging due to their nature as high-frequency, read-only operations. These commands implement `requires_audit() -> false` to prevent log bloat while maintaining useful audit coverage for security-relevant operations.

### Exempt Commands

| Command | Reason |
|---------|--------|
| `system.ping` | High-frequency health check endpoint used by load balancers and monitoring systems |
| `system.metrics` | Monitoring endpoint called frequently by observability tools |
| `service.status` | Read-only status queries that don't modify system state |

### Rationale

These exemptions follow the principle that audit logs should capture:

1. **State-changing operations**: File writes, service restarts, user creation, configuration changes
2. **Security-relevant events**: Authentication failures, permission denials, policy violations
3. **Administrative actions**: Package installations, SSL certificate operations

Health checks and status queries are excluded because:

- They occur at very high frequency (often every few seconds)
- They don't modify any system state
- They don't pose security risks
- Logging them would overwhelm the audit log with noise
- They can be monitored through other means (metrics, access logs)

### Implementing Custom Audit Exemptions

Commands implement the `Command` trait's `requires_audit()` method to control audit behavior:

```rust
impl Command for MyCommand {
    fn requires_audit(&self) -> bool {
        // Return false to skip audit logging for this command
        false
    }
}
```

By default, all commands are audited unless they explicitly opt out by returning `false` from this method.

## Integration with Monitoring and SIEM Systems

The JSON Lines format makes integration with monitoring and SIEM (Security Information and Event Management) systems straightforward.

### Splunk

**Using Splunk Universal Forwarder:**

Create an inputs.conf file:

```ini
[monitor:///var/log/lumo/audit.log]
disabled = false
sourcetype = lumo:audit
index = security

[lumo:audit]
SHOULD_LINEMERGE = false
LINE_BREAKER = ([\r\n]+)
TIME_PREFIX = "timestamp":"
TIME_FORMAT = %Y-%m-%dT%H:%M:%S.%3N%Z
```

**Sample Splunk queries:**

```spl
# Failed authentication attempts
index=security sourcetype="lumo:audit" result.status=failure error_code=UNAUTHORIZED

# Commands by user
index=security sourcetype="lumo:audit" | stats count by peer_uid, command

# Slow commands
index=security sourcetype="lumo:audit" duration_ms>1000 | table timestamp, command, duration_ms
```

### Datadog

**Using the Datadog Agent:**

Configure `/etc/datadog-agent/conf.d/lumo.d/conf.yaml`:

```yaml
logs:
  - type: file
    path: /var/log/lumo/audit.log
    service: lumo-daemon
    source: lumo
    log_processing_rules:
      - type: multi_line
        name: new_log_start_with_brace
        pattern: \{
```

### Graylog

**GELF input configuration:**

Use a sidecar or Filebeat to forward logs to Graylog with JSON parsing enabled. Create extractors to parse the JSON fields automatically.

### AWS CloudWatch

**Using the CloudWatch Agent:**

Configure `/opt/aws/amazon-cloudwatch-agent/etc/amazon-cloudwatch-agent.json`:

```json
{
  "logs": {
    "logs_collected": {
      "files": {
        "collect_list": [
          {
            "file_path": "/var/log/lumo/audit.log",
            "log_group_name": "lumo-daemon",
            "log_stream_name": "{instance_id}/audit",
            "timestamp_format": "%Y-%m-%dT%H:%M:%S.%fZ"
          }
        ]
      }
    }
  }
}
```

### Custom Alerting Rules

Common alert patterns for security teams:

```yaml
# Example alert definitions (pseudo-YAML)
alerts:
  - name: unauthorized_access_attempt
    condition: result.error_code == "UNAUTHORIZED"
    severity: high

  - name: sensitive_file_access
    condition: command == "file.write" AND params.path CONTAINS "/etc/"
    severity: medium

  - name: high_failure_rate
    condition: count(result.status == "failure") > 10 per 5 minutes per peer_uid
    severity: warning

  - name: unusual_command_volume
    condition: count(*) > 100 per minute per peer_uid
    severity: info
```

### Dashboard Metrics

Key metrics to expose from audit logs:

| Metric | Description | Query |
|--------|-------------|-------|
| Request rate | Commands per second | `count(command) / time_window` |
| Error rate | Percentage of failed requests | `count(result.status=="failure") / count(*)` |
| P95 latency | 95th percentile command duration | `percentile(duration_ms, 95)` |
| Top commands | Most frequently executed commands | `group_by(command) | count | sort desc` |
| Unique users | Distinct peer UIDs | `count(distinct peer_uid)` |
