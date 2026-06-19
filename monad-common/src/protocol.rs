//! Control channel protocol message types.
//!
//! These are exchanged over the H2 control stream (POST /control).
//! The data channels use H2 CONNECT directly and don't need these types.

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

/// Mint URL -> unit -> relay-accepted keyset IDs.
///
/// These IDs may include inactive mint keysets so existing channels funded by
/// old keysets can still be re-linked, paid, and closed. A party creating a new
/// mint swap must query/refresh mint state and choose an active output keyset.
pub type MintUnitKeysets = BTreeMap<String, BTreeMap<String, Vec<String>>>;

/// Advertisement for a specific mint/unit pricing option.
///
/// `keyset_ids` are the relay-known keysets accepted by policy for this
/// mint/unit; they are not necessarily all active output keysets at the mint.
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

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ServerErrorCode {
    ControlInvalidMessage,
    LinkInvalidPayment,
    LinkInvalidChannel,
    LinkReceiverMismatch,
    LinkMintOrKeysetUnacceptable,
    LinkUnsupportedCashuSpilmanProtocolVersion,
    LinkUnsupportedUnit,
    LinkNonZeroBalance,
    ChannelExpired,
    ChannelClosed,
    PaymentWrongChannel,
    PaymentUnknownChannel,
    PaymentInvalid,
    PaymentNoNewFunds,
    InternalError,
}

/// Messages sent from client to server on the control channel.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type")]
pub enum ClientMessage {
    /// Link a Spilman channel to this session.
    ///
    /// The payload is a serialized `cdk_spilman::Payment` JSON object with
    /// `balance == 0`, plus `params` and `funding_proofs` included.
    ChannelLink { payment_json: String },
    /// Increment session balance.
    ///
    /// The payload is a serialized `cdk_spilman::Payment` JSON object.
    ChannelPayment { payment_json: String },
    /// Request a fresh session status snapshot.
    GetSessionStatus,
}

/// Messages sent from server to client on the control channel.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type")]
pub enum ServerMessage {
    /// Consolidated session accounting and state synchronization message.
    /// Sent immediately after control stream establishment and whenever the
    /// session state changes (balance, link, pricing).
    SessionStatus {
        // --- Static/Advertisement Info ---
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
        open_connects: u32,
        total_connects: u64,
    },

    /// Another session claimed the channel; this session is now Unlinked.
    ChannelEvicted { channel_id: String },

    /// Server-initiated error or notification
    Error {
        code: ServerErrorCode,
        message: String,
    },
}
