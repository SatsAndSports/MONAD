use bytes::Bytes;
use serde::{de::DeserializeOwned, Serialize};
use std::io;

use crate::h2stream::wait_for_send_capacity;

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

pub fn try_decode_json_line<T: DeserializeOwned>(buf: &mut Vec<u8>) -> io::Result<Option<T>> {
    let Some(newline_pos) = buf.iter().position(|&b| b == b'\n') else {
        return Ok(None);
    };
    let line: Vec<u8> = buf.drain(..=newline_pos).collect();
    let line = line.trim_ascii();
    if line.is_empty() {
        return Ok(None);
    }
    let message =
        serde_json::from_slice(line).map_err(|e| io::Error::other(format!("json error: {e}")))?;
    Ok(Some(message))
}
