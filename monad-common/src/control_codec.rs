use bytes::Bytes;
use serde::{de::DeserializeOwned, Serialize};
use serde_json::Value;
use std::collections::HashSet;
use std::io;

use crate::h2stream::wait_for_send_capacity;

// Control message framing helpers for the H2 `POST /control` stream.
//
// The MONAD control protocol sends one compact JSON object per line, terminated
// by a newline byte (`\n`). Blank lines are not part of the protocol, but the
// decoder skips them defensively so that extra separators cannot stall either
// side's control-loop parser. Malformed input poisons the decoder buffer: both
// endpoints treat it as a terminal protocol failure rather than attempting to
// resynchronize inside an established paid session.

/// Maximum allowed length for a single control line, excluding the trailing
/// newline. Lines longer than this are a terminal protocol error so a peer
/// cannot grow a control-stream buffer unbounded.
pub const MAX_CONTROL_LINE_LEN: usize = 1_048_576;

/// Maximum JSON nesting depth, counting the root object as depth one.
pub const MAX_CONTROL_JSON_DEPTH: usize = 64;

/// Maximum total object members plus array elements in one control message.
pub const MAX_CONTROL_JSON_MEMBERS_ELEMENTS: usize = 65_536;

/// Maximum UTF-8 byte length of an `Error.message` field.
pub const MAX_CONTROL_ERROR_MESSAGE_LEN: usize = 4_096;

/// Bounded peer-facing text for terminal malformed input.
pub const CONTROL_INVALID_MESSAGE_TEXT: &str = "invalid control message";

pub fn encode_json_line<T: Serialize>(message: &T) -> io::Result<Bytes> {
    let bytes =
        serde_json::to_vec(message).map_err(|e| io::Error::other(format!("json error: {e}")))?;
    if bytes.len() > MAX_CONTROL_LINE_LEN {
        return Err(line_too_long(MAX_CONTROL_LINE_LEN));
    }
    validate_control_message(&bytes)?;

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
/// - `Err(...)` when a non-empty line is malformed, overlong, or structurally
///   invalid.
///
/// Blank or whitespace-only lines are consumed and ignored; the decoder keeps
/// scanning for the next non-empty line without returning `Ok(None)`. Any
/// non-empty decode error clears the entire buffer. Callers must treat that
/// error as terminal rather than retrying or resynchronizing the stream.
pub fn try_decode_json_line<T: DeserializeOwned>(buf: &mut Vec<u8>) -> io::Result<Option<T>> {
    try_decode_json_line_with_limit(buf, MAX_CONTROL_LINE_LEN)
}

fn try_decode_json_line_with_limit<T: DeserializeOwned>(
    buf: &mut Vec<u8>,
    max_line_len: usize,
) -> io::Result<Option<T>> {
    loop {
        let Some(newline_pos) = buf.iter().position(|&b| b == b'\n') else {
            if buf.len() > max_line_len {
                buf.clear();
                return Err(line_too_long(max_line_len));
            }
            return Ok(None);
        };

        if newline_pos > max_line_len {
            buf.clear();
            return Err(line_too_long(max_line_len));
        }

        let line: Vec<u8> = buf.drain(..=newline_pos).collect();
        let line = line.trim_ascii();

        if line.is_empty() {
            // Not a protocol frame, but do not let it stall parsing of later
            // valid messages. Keep scanning the buffer.
            continue;
        }

        let message = validate_control_message(line)
            .and_then(|()| {
                serde_json::from_slice(line)
                    .map_err(|_| invalid_control_message("invalid JSON message"))
            })
            .map_err(|error| {
                buf.clear();
                error
            })?;
        return Ok(Some(message));
    }
}

fn line_too_long(max_line_len: usize) -> io::Error {
    io::Error::new(
        io::ErrorKind::InvalidData,
        format!("control line exceeds maximum length of {max_line_len} bytes"),
    )
}

fn invalid_control_message(reason: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, reason)
}

/// Validate the syntax, structural resource bounds, duplicate-key rule, and
/// bounded `Error.message` before typed protocol decoding. The pre-pass is
/// necessary because ordinary JSON object maps lose duplicate-key information.
fn validate_control_message(line: &[u8]) -> io::Result<()> {
    JsonStructureValidator::new(line).validate()?;
    let value: Value = serde_json::from_slice(line)
        .map_err(|_| invalid_control_message("invalid JSON message"))?;
    if value.get("type").and_then(Value::as_str) == Some("Error") {
        let message_len = value
            .get("message")
            .and_then(Value::as_str)
            .map(str::len)
            .unwrap_or(0);
        if message_len > MAX_CONTROL_ERROR_MESSAGE_LEN {
            return Err(invalid_control_message(
                "control error message exceeds maximum length",
            ));
        }
    }
    Ok(())
}

struct JsonStructureValidator<'a> {
    input: &'a [u8],
    pos: usize,
    aggregate_count: usize,
}

impl<'a> JsonStructureValidator<'a> {
    fn new(input: &'a [u8]) -> Self {
        Self {
            input,
            pos: 0,
            aggregate_count: 0,
        }
    }

    fn validate(&mut self) -> io::Result<()> {
        self.skip_whitespace();
        if self.pos == self.input.len() {
            return Err(invalid_control_message("empty JSON message"));
        }
        self.parse_value(1)?;
        self.skip_whitespace();
        if self.pos != self.input.len() {
            return Err(invalid_control_message("trailing data after JSON message"));
        }
        Ok(())
    }

    fn parse_value(&mut self, depth: usize) -> io::Result<()> {
        if depth > MAX_CONTROL_JSON_DEPTH {
            return Err(invalid_control_message(
                "JSON nesting exceeds maximum depth",
            ));
        }
        match self.peek() {
            Some(b'{') => self.parse_object(depth),
            Some(b'[') => self.parse_array(depth),
            Some(b'"') => self.parse_string_raw().map(|_| ()),
            Some(b't') => self.parse_literal(b"true"),
            Some(b'f') => self.parse_literal(b"false"),
            Some(b'n') => self.parse_literal(b"null"),
            Some(b'-' | b'0'..=b'9') => self.parse_number(),
            _ => Err(invalid_control_message("invalid JSON value")),
        }
    }

    fn parse_object(&mut self, depth: usize) -> io::Result<()> {
        self.pos += 1; // '{'
        self.skip_whitespace();
        if self.consume_byte(b'}') {
            return Ok(());
        }

        let mut keys = HashSet::new();
        loop {
            self.count_member_or_element()?;
            self.skip_whitespace();
            if self.peek() != Some(b'"') {
                return Err(invalid_control_message("object key is not a string"));
            }
            let raw_key = self.parse_string_raw()?;
            let key: String = serde_json::from_slice(raw_key)
                .map_err(|_| invalid_control_message("invalid object key string"))?;
            if !keys.insert(key) {
                return Err(invalid_control_message("duplicate JSON object key"));
            }
            self.skip_whitespace();
            if !self.consume_byte(b':') {
                return Err(invalid_control_message("object member is missing ':'"));
            }
            self.skip_whitespace();
            self.parse_value(depth + 1)?;
            self.skip_whitespace();
            if self.consume_byte(b'}') {
                return Ok(());
            }
            if !self.consume_byte(b',') {
                return Err(invalid_control_message("object member is missing ','"));
            }
            self.skip_whitespace();
        }
    }

    fn parse_array(&mut self, depth: usize) -> io::Result<()> {
        self.pos += 1; // '['
        self.skip_whitespace();
        if self.consume_byte(b']') {
            return Ok(());
        }

        loop {
            self.count_member_or_element()?;
            self.skip_whitespace();
            self.parse_value(depth + 1)?;
            self.skip_whitespace();
            if self.consume_byte(b']') {
                return Ok(());
            }
            if !self.consume_byte(b',') {
                return Err(invalid_control_message("array element is missing ','"));
            }
            self.skip_whitespace();
        }
    }

    fn parse_string_raw(&mut self) -> io::Result<&'a [u8]> {
        let start = self.pos;
        if !self.consume_byte(b'"') {
            return Err(invalid_control_message("expected JSON string"));
        }
        while self.pos < self.input.len() {
            match self.input[self.pos] {
                b'"' => {
                    self.pos += 1;
                    return Ok(&self.input[start..self.pos]);
                }
                b'\\' => {
                    self.pos += 1;
                    let escape = *self
                        .input
                        .get(self.pos)
                        .ok_or_else(|| invalid_control_message("unterminated JSON escape"))?;
                    match escape {
                        b'"' | b'\\' | b'/' | b'b' | b'f' | b'n' | b'r' | b't' => {
                            self.pos += 1;
                        }
                        b'u' => {
                            self.pos += 1;
                            for _ in 0..4 {
                                let digit = *self.input.get(self.pos).ok_or_else(|| {
                                    invalid_control_message("short unicode escape")
                                })?;
                                if !digit.is_ascii_hexdigit() {
                                    return Err(invalid_control_message("invalid unicode escape"));
                                }
                                self.pos += 1;
                            }
                        }
                        _ => return Err(invalid_control_message("invalid JSON escape")),
                    }
                }
                0x00..=0x1f => {
                    return Err(invalid_control_message("control byte in JSON string"));
                }
                _ => self.pos += 1,
            }
        }
        Err(invalid_control_message("unterminated JSON string"))
    }

    fn parse_literal(&mut self, literal: &[u8]) -> io::Result<()> {
        if self.input.len() - self.pos < literal.len()
            || &self.input[self.pos..self.pos + literal.len()] != literal
        {
            return Err(invalid_control_message("invalid JSON literal"));
        }
        self.pos += literal.len();
        Ok(())
    }

    fn parse_number(&mut self) -> io::Result<()> {
        if self.consume_byte(b'-') && self.peek().is_none() {
            return Err(invalid_control_message("invalid JSON number"));
        }
        match self.peek() {
            Some(b'0') => self.pos += 1,
            Some(b'1'..=b'9') => {
                self.pos += 1;
                while matches!(self.peek(), Some(b'0'..=b'9')) {
                    self.pos += 1;
                }
            }
            _ => return Err(invalid_control_message("invalid JSON number")),
        }
        if self.consume_byte(b'.') {
            if !matches!(self.peek(), Some(b'0'..=b'9')) {
                return Err(invalid_control_message("invalid JSON fraction"));
            }
            while matches!(self.peek(), Some(b'0'..=b'9')) {
                self.pos += 1;
            }
        }
        if matches!(self.peek(), Some(b'e' | b'E')) {
            self.pos += 1;
            if matches!(self.peek(), Some(b'+' | b'-')) {
                self.pos += 1;
            }
            if !matches!(self.peek(), Some(b'0'..=b'9')) {
                return Err(invalid_control_message("invalid JSON exponent"));
            }
            while matches!(self.peek(), Some(b'0'..=b'9')) {
                self.pos += 1;
            }
        }
        Ok(())
    }

    fn count_member_or_element(&mut self) -> io::Result<()> {
        self.aggregate_count += 1;
        if self.aggregate_count > MAX_CONTROL_JSON_MEMBERS_ELEMENTS {
            return Err(invalid_control_message(
                "JSON member/element count exceeds maximum",
            ));
        }
        Ok(())
    }

    fn skip_whitespace(&mut self) {
        while matches!(self.peek(), Some(b' ' | b'\t' | b'\r' | b'\n')) {
            self.pos += 1;
        }
    }

    fn consume_byte(&mut self, byte: u8) -> bool {
        if self.peek() == Some(byte) {
            self.pos += 1;
            true
        } else {
            false
        }
    }

    fn peek(&self) -> Option<u8> {
        self.input.get(self.pos).copied()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocol::{ServerErrorCode, ServerMessage};
    use serde::{Deserialize, Serialize};
    use serde_json::json;

    #[derive(Debug, Deserialize, Serialize, PartialEq, Eq)]
    struct TestMessage {
        x: u32,
    }

    fn max_size_value(extra: isize) -> Value {
        let mut value = json!({"x":""});
        let base_len = serde_json::to_vec(&value).unwrap().len() as isize;
        let padding = MAX_CONTROL_LINE_LEN as isize - base_len + extra;
        value["x"] = Value::String("x".repeat(padding as usize));
        value
    }

    fn nested_arrays(array_count: usize) -> Vec<u8> {
        let mut line = vec![b'['; array_count];
        line.push(b'0');
        line.extend(vec![b']'; array_count]);
        line.push(b'\n');
        line
    }

    fn flat_array(element_count: usize) -> Vec<u8> {
        let mut line = String::from("[");
        for index in 0..element_count {
            if index != 0 {
                line.push(',');
            }
            line.push('0');
        }
        line.push_str("]\n");
        line.into_bytes()
    }

    fn server_error(message_len: usize) -> ServerMessage {
        ServerMessage::Error {
            code: ServerErrorCode::InternalError,
            message: "x".repeat(message_len),
        }
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
        // The blank line should have been consumed, while the incomplete final
        // line remains buffered but must never execute without a newline.
        assert_eq!(buf, b"{\"x\":");
    }

    #[test]
    fn invalid_non_empty_line_errors_and_poisons_buffer() {
        let mut buf = b"not-json\n{\"x\":1}\n".to_vec();

        let err = try_decode_json_line::<TestMessage>(&mut buf).unwrap_err();

        assert_eq!(err.kind(), io::ErrorKind::InvalidData);
        assert!(buf.is_empty());
        assert!(try_decode_json_line::<TestMessage>(&mut buf)
            .unwrap()
            .is_none());
    }

    #[test]
    fn empty_buffer_returns_none() {
        let mut buf = Vec::new();
        assert!(try_decode_json_line::<TestMessage>(&mut buf)
            .unwrap()
            .is_none());
    }

    #[test]
    fn line_at_exact_limit_decodes() {
        let message = TestMessage { x: 42 };
        let frame = encode_json_line(&message).unwrap();
        let line_len = frame.len() - 1; // exclude trailing newline
        let small_limit = line_len;

        let mut buf = frame.to_vec();
        let decoded: TestMessage = try_decode_json_line_with_limit(&mut buf, small_limit)
            .unwrap()
            .unwrap();
        assert_eq!(decoded, message);
        assert!(buf.is_empty());
    }

    #[test]
    fn line_over_limit_errors_and_poisons_buffer() {
        let message = TestMessage { x: 42 };
        let frame = encode_json_line(&message).unwrap();
        let line_len = frame.len() - 1; // exclude trailing newline
        let small_limit = line_len - 1;

        let mut buf = frame.to_vec();
        let err =
            try_decode_json_line_with_limit::<TestMessage>(&mut buf, small_limit).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidData);
        assert!(err.to_string().contains("exceeds maximum length"));
        assert!(buf.is_empty());
        assert!(try_decode_json_line::<TestMessage>(&mut buf)
            .unwrap()
            .is_none());
    }

    #[test]
    fn unterminated_line_over_limit_errors_and_poisons_buffer() {
        let mut buf = vec![b'x'; 17]; // no newline
        let err = try_decode_json_line_with_limit::<TestMessage>(&mut buf, 16).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidData);
        assert!(err.to_string().contains("exceeds maximum length"));
        assert!(buf.is_empty());
    }

    #[test]
    fn outbound_exact_line_limit_encodes_and_decodes() {
        let value = max_size_value(0);
        let encoded = serde_json::to_vec(&value).unwrap();
        assert_eq!(encoded.len(), MAX_CONTROL_LINE_LEN);

        let frame = encode_json_line(&value).unwrap();
        assert_eq!(frame.len(), MAX_CONTROL_LINE_LEN + 1);

        let mut buf = frame.to_vec();
        let decoded: Value = try_decode_json_line(&mut buf).unwrap().unwrap();
        assert_eq!(decoded, value);
        assert!(buf.is_empty());
    }

    #[test]
    fn outbound_over_line_limit_is_rejected() {
        let value = max_size_value(1);
        let encoded = serde_json::to_vec(&value).unwrap();
        assert_eq!(encoded.len(), MAX_CONTROL_LINE_LEN + 1);

        let err = encode_json_line(&value).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidData);
        assert!(err.to_string().contains("exceeds maximum length"));
    }

    #[test]
    fn duplicate_object_keys_are_rejected_even_when_escaped() {
        for line in [
            b"{\"x\":1,\"x\":2}\n".to_vec(),
            b"{\"x\":1,\"\\u0078\":2}\n".to_vec(),
            b"{\"outer\":{\"x\":1,\"x\":2}}\n".to_vec(),
        ] {
            let mut buf = line;
            let err = try_decode_json_line::<Value>(&mut buf).unwrap_err();
            assert_eq!(err.kind(), io::ErrorKind::InvalidData);
            assert!(err.to_string().contains("duplicate JSON object key"));
            assert!(buf.is_empty());
        }
    }

    #[test]
    fn json_depth_boundary_is_enforced() {
        let mut exact = nested_arrays(MAX_CONTROL_JSON_DEPTH - 1);
        let decoded: Value = try_decode_json_line(&mut exact).unwrap().unwrap();
        assert!(decoded.is_array());
        assert!(exact.is_empty());

        let mut over = nested_arrays(MAX_CONTROL_JSON_DEPTH);
        let err = try_decode_json_line::<Value>(&mut over).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidData);
        assert!(err.to_string().contains("maximum depth"));
        assert!(over.is_empty());
    }

    #[test]
    fn json_member_and_element_count_boundary_is_enforced() {
        let mut exact = flat_array(MAX_CONTROL_JSON_MEMBERS_ELEMENTS);
        let decoded: Value = try_decode_json_line(&mut exact).unwrap().unwrap();
        assert_eq!(
            decoded.as_array().unwrap().len(),
            MAX_CONTROL_JSON_MEMBERS_ELEMENTS
        );
        assert!(exact.is_empty());

        let mut over = flat_array(MAX_CONTROL_JSON_MEMBERS_ELEMENTS + 1);
        let err = try_decode_json_line::<Value>(&mut over).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidData);
        assert!(err.to_string().contains("member/element count"));
        assert!(over.is_empty());
    }

    #[test]
    fn error_message_boundary_is_enforced_on_outbound_and_inbound() {
        let exact = server_error(MAX_CONTROL_ERROR_MESSAGE_LEN);
        let frame = encode_json_line(&exact).unwrap();
        let mut buf = frame.to_vec();
        let decoded: ServerMessage = try_decode_json_line(&mut buf).unwrap().unwrap();
        match decoded {
            ServerMessage::Error { message, .. } => {
                assert_eq!(message.len(), MAX_CONTROL_ERROR_MESSAGE_LEN);
            }
            other => panic!("expected Error, got {other:?}"),
        }

        let over = server_error(MAX_CONTROL_ERROR_MESSAGE_LEN + 1);
        let err = encode_json_line(&over).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidData);
        assert!(err.to_string().contains("error message"));

        let raw = serde_json::to_vec(&over).unwrap();
        let mut buf = raw.into_iter().chain(std::iter::once(b'\n')).collect();
        let err = try_decode_json_line::<ServerMessage>(&mut buf).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidData);
        assert!(err.to_string().contains("error message"));
        assert!(buf.is_empty());
    }

    #[test]
    fn malformed_json_followed_by_valid_line_cannot_execute_valid_line() {
        let mut buf = b"{\"x\":\n{\"x\":7}\n".to_vec();

        let err = try_decode_json_line::<TestMessage>(&mut buf).unwrap_err();

        assert_eq!(err.kind(), io::ErrorKind::InvalidData);
        assert!(buf.is_empty());
        assert!(try_decode_json_line::<TestMessage>(&mut buf)
            .unwrap()
            .is_none());
    }
}
