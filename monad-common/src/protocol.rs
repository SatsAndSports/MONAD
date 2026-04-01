//! Control channel protocol message types.
//!
//! These are exchanged over the H2 control stream (POST /control).
//! The data channels use H2 CONNECT directly and don't need these types.

use serde::{Deserialize, Serialize};

/// Messages sent from client to server on the control channel.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type")]
pub enum ClientMessage {
    Ping,
    /// Add fake credit to the current relay session.
    FakePayment {
        milli_sats: u64,
    },
    /// Request a fresh session status snapshot.
    GetSessionStatus,
}

/// Messages sent from server to client on the control channel.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type")]
pub enum ServerMessage {
    /// Acknowledgement
    Pong,

    /// Current session accounting and pause state.
    SessionStatus {
        session_total_in: u64,
        session_total_out: u64,
        remaining_milli_sats: i64,
        paused: bool,
    },

    /// Server-initiated error or notification
    Error { message: String },
}
