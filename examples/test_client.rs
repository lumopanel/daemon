//! Simple test client for the Lumo daemon.
//!
//! Run with: cargo run --example test_client
//!
//! Tests:
//! 1. system.ping - Health check
//! 2. file.write - Write a test file
//! 3. file.write_template - Render and write a template
//! 4. file.delete - Delete the test files
//! 5. Path traversal rejection test
//! 6. Unknown command test
//! 7. service.status - Get service status (nginx)
//! 8. Unknown service rejection test
//! 9. package.update - Update package lists (validation only)
//! 10. Unknown package rejection test

use std::io::{Read, Write};
use std::os::unix::net::UnixStream;
use std::time::{SystemTime, UNIX_EPOCH};

use ring::hmac;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("=== Lumo Daemon Test Client ===\n");

    let secret = b"test-secret-key-for-development!!";

    // Test 1: Ping
    println!("Test 1: system.ping");
    let response = send_request("system.ping", serde_json::json!({}), secret)?;
    println!("Response: {}\n", serde_json::to_string_pretty(&response)?);

    // Test 2: Write file
    println!("Test 2: file.write");
    let response = send_request(
        "file.write",
        serde_json::json!({
            "path": "/tmp/lumo/test_file.txt",
            "content": "Hello from Lumo daemon!\nThis file was created by the test client."
        }),
        secret,
    )?;
    println!("Response: {}\n", serde_json::to_string_pretty(&response)?);

    // Test 3: Write template (nginx site config)
    println!("Test 3: file.write_template");
    let response = send_request(
        "file.write_template",
        serde_json::json!({
            "path": "/tmp/lumo/nginx_test.conf",
            "template": "nginx/site.conf.tera",
            "context": {
                "site_name": "example.com",
                "domains": ["example.com", "www.example.com"],
                "document_root": "/var/www/example/public",
                "php_enabled": true,
                "php_socket": "/run/php/php8.2-fpm.sock"
            }
        }),
        secret,
    )?;
    println!("Response: {}\n", serde_json::to_string_pretty(&response)?);

    // Test 4: Delete files
    println!("Test 4: file.delete");
    let response = send_request(
        "file.delete",
        serde_json::json!({
            "path": "/tmp/lumo/test_file.txt"
        }),
        secret,
    )?;
    println!("Response: {}\n", serde_json::to_string_pretty(&response)?);

    let response = send_request(
        "file.delete",
        serde_json::json!({
            "path": "/tmp/lumo/nginx_test.conf"
        }),
        secret,
    )?;
    println!("Cleanup template file: {}\n", serde_json::to_string_pretty(&response)?);

    // Test 5: Path traversal attack (should be rejected)
    println!("Test 5: Path traversal rejection");
    let response = send_request(
        "file.write",
        serde_json::json!({
            "path": "/tmp/lumo/../../../etc/passwd",
            "content": "malicious"
        }),
        secret,
    )?;
    println!("Response: {}\n", serde_json::to_string_pretty(&response)?);

    // Test 6: Unknown command
    println!("Test 6: Unknown command");
    let response = send_request("unknown.command", serde_json::json!({}), secret)?;
    println!("Response: {}\n", serde_json::to_string_pretty(&response)?);

    // Test 7: Service status (read-only, safe to run)
    println!("Test 7: service.status (nginx)");
    let response = send_request(
        "service.status",
        serde_json::json!({
            "service": "nginx"
        }),
        secret,
    )?;
    println!("Response: {}\n", serde_json::to_string_pretty(&response)?);

    // Test 8: Unknown service rejection
    println!("Test 8: Unknown service rejection");
    let response = send_request(
        "service.status",
        serde_json::json!({
            "service": "malicious-service"
        }),
        secret,
    )?;
    println!("Response: {}\n", serde_json::to_string_pretty(&response)?);

    // Test 9: Package update (will fail on macOS but validates correctly)
    println!("Test 9: package.update (validation test)");
    let response = send_request(
        "package.update",
        serde_json::json!({}),
        secret,
    )?;
    println!("Response: {}\n", serde_json::to_string_pretty(&response)?);

    // Test 10: Unknown package rejection
    println!("Test 10: Unknown package rejection");
    let response = send_request(
        "package.install",
        serde_json::json!({
            "packages": ["nginx", "malware"]
        }),
        secret,
    )?;
    println!("Response: {}\n", serde_json::to_string_pretty(&response)?);

    println!("=== All tests completed ===");
    Ok(())
}

fn send_request(
    command: &str,
    params: serde_json::Value,
    secret: &[u8],
) -> Result<serde_json::Value, Box<dyn std::error::Error>> {
    let mut stream = UnixStream::connect("/tmp/lumo-daemon.sock")?;

    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)?
        .as_secs();
    let nonce = uuid::Uuid::new_v4().to_string();

    // Create the message to sign
    let params_json = serde_json::to_string(&params)?;
    let signing_message = format!("{}:{}:{}:{}", command, params_json, timestamp, nonce);

    // Sign with HMAC-SHA256
    let key = hmac::Key::new(hmac::HMAC_SHA256, secret);
    let signature = hmac::sign(&key, signing_message.as_bytes());
    let signature_hex = hex::encode(signature.as_ref());

    // Build the request
    let request = serde_json::json!({
        "command": command,
        "params": params,
        "timestamp": timestamp,
        "nonce": nonce,
        "signature": signature_hex,
    });

    let request_bytes = serde_json::to_vec(&request)?;

    // Send length-prefixed message
    let len_bytes = (request_bytes.len() as u32).to_be_bytes();
    stream.write_all(&len_bytes)?;
    stream.write_all(&request_bytes)?;
    stream.flush()?;

    // Read response length
    let mut len_buf = [0u8; 4];
    stream.read_exact(&mut len_buf)?;
    let len = u32::from_be_bytes(len_buf) as usize;

    // Read response body
    let mut response_bytes = vec![0u8; len];
    stream.read_exact(&mut response_bytes)?;

    // Parse and return response
    let response: serde_json::Value = serde_json::from_slice(&response_bytes)?;
    Ok(response)
}
