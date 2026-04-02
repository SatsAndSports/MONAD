//! Control channel protocol message types.
//!
//! These are exchanged over the H2 control stream (POST /control).
//! The data channels use H2 CONNECT directly and don't need these types.

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

/// Mint URL -> unit -> advertised keyset IDs.
pub type MintUnitKeysets = BTreeMap<String, BTreeMap<String, Vec<String>>>;

/// Messages sent from client to server on the control channel.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type")]
pub enum ClientMessage {
    /// First message on the control stream. Declares the highest
    /// protocol version the client supports.
    Hello { version: u8 },
    /// Add fake credit to the current relay session.
    FakePayment { milli_sats: u64 },
    /// Request a fresh session status snapshot.
    GetSessionStatus,
}

/// Messages sent from server to client on the control channel.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type")]
pub enum ServerMessage {
    /// Fixed pricing and other session parameters for this relay session.
    /// Sent in response to `ClientMessage::Hello`.
    SessionParams {
        version: u8,
        in_bytes_per_millisat: u64,
        out_bytes_per_millisat: u64,
        receiver_pubkey: String,
        mints_units_keysets: MintUnitKeysets,
    },

    /// Current session accounting and pause state.
    SessionStatus {
        session_total_in: u64,
        session_total_out: u64,
        total_paid_millisats: u64,
        remaining_milli_sats: i64,
        paused: bool,
    },

    /// Server-initiated error or notification
    Error { message: String },
}
