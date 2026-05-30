//! Control channel protocol message types.
//!
//! These are exchanged over the H2 control stream (POST /control).
//! The data channels use H2 CONNECT directly and don't need these types.

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

/// Mint URL -> unit -> advertised keyset IDs.
pub type MintUnitKeysets = BTreeMap<String, BTreeMap<String, Vec<String>>>;

/// Advertisement for a specific mint/unit/keyset pricing option.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KeysetAdvertisement {
    pub mint_url: String,
    pub unit: String,
    pub keyset_ids: Vec<String>,
    pub in_bytes_per_millisat: u64,
    pub out_bytes_per_millisat: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct LinkedChannelStatus {
    pub channel_id: String,
    pub balance_raw: u64,
    pub capacity_raw: u64,
    pub unit: String,
}

/// Messages sent from client to server on the control channel.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type")]
pub enum ClientMessage {
    /// First message on the control stream. Declares the highest
    /// protocol version the client supports.
    Hello { version: u8 },
    /// Link a Spilman channel to this session.
    ///
    /// The payload is a serialized `cdk_spilman::Payment` JSON object with
    /// `balance == 0`, plus `params` and `funding_proofs` included.
    ChannelLink { payment_json: String },
    /// Increment session balance.
    ///
    /// The payload is a serialized `cdk_spilman::Payment` JSON object.
    ChannelPayment { payment_json: String },
    /// Add fake credit to the current relay session.
    ///
    /// Temporary compatibility path while the CLI is still being migrated to
    /// real Spilman `ChannelLink` / `ChannelPayment` control flow.
    FakePayment { milli_sats: u64 },
    /// Request a fresh session status snapshot.
    GetSessionStatus,
}

/// Messages sent from server to client on the control channel.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type")]
pub enum ServerMessage {
    /// Consolidated session accounting and state synchronization message.
    /// Sent in response to `ClientMessage::Hello` and whenever the session
    /// state changes (balance, link, pricing).
    SessionStatus {
        // --- Static/Advertisement Info ---
        version: u8,
        receiver_pubkey: String,
        advertisements: Vec<KeysetAdvertisement>,

        // --- Active Session Info ---
        linked_channel: Option<LinkedChannelStatus>,
        active_in_rate: u64,
        active_out_rate: u64,

        // --- Accounting Info ---
        session_total_in: u64,
        session_total_out: u64,
        total_paid_millisats: u64,
        remaining_milli_sats: i64,
        paused: bool,
    },

    /// The server validated and linked the Spilman channel to this session.
    ChannelLinkAccepted { channel_id: String, capacity: u64 },

    /// Another session claimed the channel; this session is now Unlinked.
    ChannelEvicted { channel_id: String },

    /// Server-initiated error or notification
    Error { message: String },
}
