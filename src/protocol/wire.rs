//! Wire format for message framing.
//!
//! Messages are length-prefixed: [4 bytes big-endian u32][payload]

use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::time::timeout;

use crate::error::{DaemonError, ProtocolErrorKind};

/// Maximum message size (1 MB by default, can be overridden).
#[allow(dead_code)]
pub const DEFAULT_MAX_MESSAGE_SIZE: usize = 1_048_576;

/// Read a length-prefixed message from the reader.
///
/// Returns the raw bytes of the message payload.
/// Returns an error if the message is too large or if reading fails.
pub async fn read_message<R>(reader: &mut R, max_size: usize) -> Result<Vec<u8>, DaemonError>
where
    R: AsyncReadExt + Unpin,
{
    // Read the 4-byte length prefix
    let mut len_buf = [0u8; 4];
    match reader.read_exact(&mut len_buf).await {
        Ok(_) => {}
        Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => {
            return Err(DaemonError::Protocol {
                kind: ProtocolErrorKind::ConnectionClosed,
            });
        }
        Err(e) => return Err(DaemonError::Io(e)),
    }

    let len = u32::from_be_bytes(len_buf) as usize;

    // Sanity check message size
    if len > max_size {
        return Err(DaemonError::Protocol {
            kind: ProtocolErrorKind::MessageTooLarge {
                size: len,
                max: max_size,
            },
        });
    }

    // Read the message payload
    let mut buf = vec![0u8; len];
    reader.read_exact(&mut buf).await?;

    Ok(buf)
}

/// Write a length-prefixed message to the writer.
pub async fn write_message<W>(writer: &mut W, data: &[u8]) -> Result<(), DaemonError>
where
    W: AsyncWriteExt + Unpin,
{
    let len = (data.len() as u32).to_be_bytes();
    writer.write_all(&len).await?;
    writer.write_all(data).await?;
    writer.flush().await?;
    Ok(())
}

/// Read a length-prefixed message with a timeout.
///
/// Returns a ConnectionTimeout error if the read takes longer than the specified duration.
pub async fn read_message_with_timeout<R>(
    reader: &mut R,
    max_size: usize,
    timeout_duration: Duration,
) -> Result<Vec<u8>, DaemonError>
where
    R: AsyncReadExt + Unpin,
{
    timeout(timeout_duration, read_message(reader, max_size))
        .await
        .map_err(|_| DaemonError::Protocol {
            kind: ProtocolErrorKind::ConnectionTimeout,
        })?
}

/// Write a length-prefixed message with a timeout.
///
/// Returns a ConnectionTimeout error if the write takes longer than the specified duration.
pub async fn write_message_with_timeout<W>(
    writer: &mut W,
    data: &[u8],
    timeout_duration: Duration,
) -> Result<(), DaemonError>
where
    W: AsyncWriteExt + Unpin,
{
    timeout(timeout_duration, write_message(writer, data))
        .await
        .map_err(|_| DaemonError::Protocol {
            kind: ProtocolErrorKind::ConnectionTimeout,
        })?
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    #[tokio::test]
    async fn test_write_and_read_message() {
        let mut buffer = Vec::new();
        let message = b"hello world";

        // Write
        write_message(&mut buffer, message).await.unwrap();

        // Verify format
        assert_eq!(&buffer[0..4], &[0, 0, 0, 11]); // length = 11
        assert_eq!(&buffer[4..], message);

        // Read back
        let mut cursor = Cursor::new(buffer);
        let result = read_message(&mut cursor, DEFAULT_MAX_MESSAGE_SIZE)
            .await
            .unwrap();
        assert_eq!(result, message);
    }

    #[tokio::test]
    async fn test_message_too_large() {
        let data = vec![0u8; 100];
        let mut cursor = Cursor::new(data);

        // Pretend message is 2MB
        let len_bytes = 2_000_000u32.to_be_bytes();
        cursor.get_mut()[0..4].copy_from_slice(&len_bytes);

        let result = read_message(&mut cursor, DEFAULT_MAX_MESSAGE_SIZE).await;
        assert!(matches!(
            result,
            Err(DaemonError::Protocol {
                kind: ProtocolErrorKind::MessageTooLarge { .. }
            })
        ));
    }
}
