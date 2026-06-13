use bytes::Bytes;
use serde::{de::DeserializeOwned, Serialize};
use std::io;

use crate::h2stream::wait_for_send_capacity;

// Control message framing helpers for the H2 `POST /control` stream.
//
// The MONAD control protocol sends one compact JSON object per line, terminated
// by a newline byte (`\n`). Blank lines are not part of the protocol, but the
// decoder skips them defensively so that extra separators cannot stall either
// side's control-loop parser.

pub fn encode_json_line<T: Serialize>(message: &T) -> io::Result<Bytes> {
    let bytes =
        serde_json::to_vec(message).map_err(|e| io::Error::other(format!("json error: {e}")))?;
    let mut frame = Vec::with_capacity(bytes.len() + 1);
    frame.extend_from_slice(&bytes);
    frame.push(b'\n');
    Ok(Bytes::from(frame))
}

pub async fn send_json_line<T: Serialize>(
    h2_send: &mut h2::SendStream<Bytes>,
    message: &T,
) -> io::Result<()> {
    let frame = encode_json_line(message)?;
    h2_send.reserve_capacity(frame.len());
    wait_for_send_capacity(h2_send).await?;
    h2_send
        .send_data(frame, false)
        .map_err(|e| io::Error::other(format!("h2 send error: {e}")))
}

/// Try to decode one newline-delimited JSON object from `buf`.
///
/// Returns:
/// - `Ok(Some(message))` when a complete, non-empty line has been decoded.
/// - `Ok(None)` when no complete line is available yet.
/// - `Err(...)` when a non-empty line cannot be parsed as JSON.
///
/// Blank or whitespace-only lines are consumed and ignored; the decoder keeps
/// scanning for the next non-empty line without returning `Ok(None)`.
pub fn try_decode_json_line<T: DeserializeOwned>(buf: &mut Vec<u8>) -> io::Result<Option<T>> {
    loop {
        let Some(newline_pos) = buf.iter().position(|&b| b == b'\n') else {
            return Ok(None);
        };

        let line: Vec<u8> = buf.drain(..=newline_pos).collect();
        let line = line.trim_ascii();

        if line.is_empty() {
            // Not a protocol frame, but do not let it stall parsing of later
            // valid messages. Keep scanning the buffer.
            continue;
        }

        let message = serde_json::from_slice(line)
            .map_err(|e| io::Error::other(format!("json error: {e}")))?;
        return Ok(Some(message));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde::{Deserialize, Serialize};

    #[derive(Debug, Deserialize, Serialize, PartialEq, Eq)]
    struct TestMessage {
        x: u32,
    }

    #[test]
    fn encode_then_decode_round_trips() {
        let message = TestMessage { x: 42 };
        let frame = encode_json_line(&message).unwrap();

        let mut buf = frame.to_vec();
        let decoded: TestMessage = try_decode_json_line(&mut buf).unwrap().unwrap();

        assert_eq!(decoded, message);
        assert!(buf.is_empty());
    }

    #[test]
    fn blank_line_before_message_is_skipped() {
        let mut buf = b"\n{\"x\":7}\n".to_vec();

        let decoded: TestMessage = try_decode_json_line(&mut buf).unwrap().unwrap();

        assert_eq!(decoded.x, 7);
        assert!(buf.is_empty());
    }

    #[test]
    fn multiple_blank_lines_before_message_are_skipped() {
        let mut buf = b"\n \n\t\n{\"x\":9}\n".to_vec();

        let decoded: TestMessage = try_decode_json_line(&mut buf).unwrap().unwrap();

        assert_eq!(decoded.x, 9);
        assert!(buf.is_empty());
    }

    #[test]
    fn blank_line_before_partial_message_returns_none() {
        let mut buf = b"\n{\"x\":".to_vec();

        assert!(try_decode_json_line::<TestMessage>(&mut buf)
            .unwrap()
            .is_none());
        // The blank line should have been consumed.
        assert_eq!(buf, b"{\"x\":");
    }

    #[test]
    fn invalid_non_empty_line_errors() {
        let mut buf = b"not-json\n".to_vec();

        let err = try_decode_json_line::<TestMessage>(&mut buf).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::Other);
    }

    #[test]
    fn empty_buffer_returns_none() {
        let mut buf = Vec::new();
        assert!(try_decode_json_line::<TestMessage>(&mut buf)
            .unwrap()
            .is_none());
    }
}
