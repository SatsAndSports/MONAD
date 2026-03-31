//! Control channel protocol message types.
//!
//! These are exchanged over the H2 control stream (POST /control).
//! The data channels use H2 CONNECT directly and don't need these types.

use serde::{Deserialize, Serialize};

/// Messages sent from client to server on the control channel.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type")]
pub enum ClientMessage {
    /// Request to open a tunnel to an external destination.
    /// (This is informational — the actual tunnel is opened via H2 CONNECT.)
    Ping,
    // Future: payment tokens, session management, etc.
}

/// Messages sent from server to client on the control channel.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type")]
pub enum ServerMessage {
    /// Acknowledgement
    Pong,

    /// Server-initiated error or notification
    Error { message: String },
    // Future: payment receipts, bandwidth accounting, etc.
}
