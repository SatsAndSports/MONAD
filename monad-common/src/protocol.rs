//! Control channel protocol message types.
//!
//! These are exchanged over the H2 control stream (POST /control).
//! The data channels use H2 CONNECT directly and don't need these types.

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

/// Internal mint-cache index: mint URL -> unit -> known keyset IDs.
///
/// These IDs may include inactive mint keysets so existing channels funded by
/// old keysets can still be re-linked, paid, and closed. This is not advertised
/// on the control stream. A party creating a new
/// mint swap must query/refresh mint state and choose an active output keyset.
pub type MintUnitKeysets = BTreeMap<String, BTreeMap<String, Vec<String>>>;

/// Mint URL -> supported unit -> funding requirements.
pub type MintUnitAdvertisements = BTreeMap<String, BTreeMap<String, MintUnitAdvertisement>>;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct MintUnitAdvertisement {
    /// Minimum remaining channel lifetime when a link or relink is accepted.
    pub minimum_channel_lifetime_secs: u64,
    /// Required interval between channel expiry and funding keyset final expiry.
    pub funding_keyset_recovery_window_secs: u64,
}

/// Local flattened payment option. Prices come from the session, not the map.
#[derive(Debug, Clone)]
pub struct PaymentOption {
    pub minimum_channel_lifetime_secs: u64,
    pub funding_keyset_recovery_window_secs: u64,
    pub mint_url: String,
    pub unit: String,
    pub in_bytes_per_millisat: u64,
    pub out_bytes_per_millisat: u64,
}

/// Deterministic local traversal; map order is not a relay preference.
pub fn advertisement_options(
    advertisements: &MintUnitAdvertisements,
    in_bytes_per_millisat: u64,
    out_bytes_per_millisat: u64,
) -> Vec<PaymentOption> {
    advertisements
        .iter()
        .flat_map(|(mint_url, units)| {
            units.iter().map(move |(unit, window)| PaymentOption {
                minimum_channel_lifetime_secs: window.minimum_channel_lifetime_secs,
                mint_url: mint_url.clone(),
                unit: unit.clone(),
                funding_keyset_recovery_window_secs: window.funding_keyset_recovery_window_secs,
                in_bytes_per_millisat,
                out_bytes_per_millisat,
            })
        })
        .collect()
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
    ChannelAdmissionDisabled,
    ControlInvalidMessage,
    LinkInvalidPayment,
    LinkInvalidChannel,
    LinkReceiverMismatch,
    LinkMintOrKeysetUnacceptable,
    LinkKeysetRefreshRateLimited,
    LinkKeysetRefreshBusy,
    LinkKeysetRefreshFailed,
    LinkUnsupportedCashuSpilmanProtocolVersion,
    LinkKeysetVersionNotNegotiated,
    LinkUnsupportedUnit,
    LinkNonZeroBalance,
    ChannelExpired,
    ChannelClosed,
    PaymentWrongChannel,
    PaymentUnknownChannel,
    PaymentInvalid,
    PaymentNoNewFunds,
    PaymentConflict,
    InternalError,
    LinkChannelRetired,
    ChannelUnlinkRejected,
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
    /// Stop using a retiring channel after all signed payments are acknowledged.
    ChannelUnlink {
        channel_id: String,
        final_balance_raw: u64,
    },
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
        advertisements: MintUnitAdvertisements,

        // --- Active Session Info ---
        linked_channel: Option<LinkedChannelStatus>,
        #[serde(rename = "bytes_in_per_msat")]
        active_in_rate: u64,
        #[serde(rename = "bytes_out_per_msat")]
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
    ChannelEvicted {
        channel_id: String,
    },
    ChannelReleaseRequested {
        channel_id: String,
    },
    ChannelUnlinked {
        channel_id: String,
        final_balance_raw: u64,
    },

    /// Server-initiated error or notification
    Error {
        code: ServerErrorCode,
        message: String,
    },
}

#[cfg(test)]
mod advertisement_tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn advertisement_order_is_local_and_value_fields_are_explicit() {
        let first: MintUnitAdvertisements = serde_json::from_str(r#"{
            "mint-b":{"sat":{"minimum_channel_lifetime_secs":3600,"funding_keyset_recovery_window_secs":7}},
            "mint-a":{"sat":{"minimum_channel_lifetime_secs":3600,"funding_keyset_recovery_window_secs":9},"msat":{"minimum_channel_lifetime_secs":3600,"funding_keyset_recovery_window_secs":8}}
        }"#).unwrap();
        let reordered: MintUnitAdvertisements = serde_json::from_str(r#"{
            "mint-a":{"msat":{"minimum_channel_lifetime_secs":3600,"funding_keyset_recovery_window_secs":8},"sat":{"minimum_channel_lifetime_secs":3600,"funding_keyset_recovery_window_secs":9}},
            "mint-b":{"sat":{"minimum_channel_lifetime_secs":3600,"funding_keyset_recovery_window_secs":7}}
        }"#).unwrap();
        let order = |ads: &MintUnitAdvertisements| {
            advertisement_options(ads, 11, 22)
                .into_iter()
                .map(|o| (o.mint_url, o.unit, o.funding_keyset_recovery_window_secs))
                .collect::<Vec<_>>()
        };
        assert_eq!(order(&first), order(&reordered));
        assert_eq!(
            order(&first),
            vec![
                ("mint-a".into(), "msat".into(), 8),
                ("mint-a".into(), "sat".into(), 9),
                ("mint-b".into(), "sat".into(), 7)
            ]
        );
        for invalid in [
            json!(86400),
            json!({}),
            json!({"minimum_time_to_expiry":86400}),
            json!({"funding_keyset_recovery_window_secs":86400}),
            json!({"minimum_channel_lifetime_secs":3600}),
            json!({"minimum_channel_lifetime_secs":3600, "funding_keyset_recovery_window_secs":86400, "keyset_ids":[]}),
            json!({"minimum_channel_lifetime_secs":3600, "funding_keyset_recovery_window_secs":86400, "bytes_in_per_msat":1}),
        ] {
            assert!(serde_json::from_value::<MintUnitAdvertisements>(
                json!({"mint":{"sat":invalid}})
            )
            .is_err());
        }
    }

    #[test]
    fn status_wire_has_only_mint_unit_windows_and_session_prices() {
        let status = ServerMessage::SessionStatus {
            receiver_pubkey: "receiver".into(),
            advertisements: BTreeMap::from([
                (
                    "https://mint-b".into(),
                    BTreeMap::from([(
                        "sat".into(),
                        MintUnitAdvertisement {
                            minimum_channel_lifetime_secs: 3600,
                            funding_keyset_recovery_window_secs: 123,
                        },
                    )]),
                ),
                (
                    "https://mint-a".into(),
                    BTreeMap::from([
                        (
                            "sat".into(),
                            MintUnitAdvertisement {
                                minimum_channel_lifetime_secs: 3600,
                                funding_keyset_recovery_window_secs: 0,
                            },
                        ),
                        (
                            "msat".into(),
                            MintUnitAdvertisement {
                                minimum_channel_lifetime_secs: 3600,
                                funding_keyset_recovery_window_secs: 86_400,
                            },
                        ),
                    ]),
                ),
            ]),
            linked_channel: None,
            active_in_rate: 11,
            active_out_rate: 22,
            session_total_in: 0,
            session_total_out: 0,
            total_paid_millisats: 0,
            remaining_milli_sats: 0,
            paused: true,
            open_connects: 0,
            total_connects: 0,
        };
        let value = serde_json::to_value(status).unwrap();
        assert_eq!(
            value["advertisements"],
            json!({
                "https://mint-a": {"sat": {"minimum_channel_lifetime_secs":3600,"funding_keyset_recovery_window_secs": 0}, "msat": {"minimum_channel_lifetime_secs":3600,"funding_keyset_recovery_window_secs": 86400}},
                "https://mint-b": {"sat": {"minimum_channel_lifetime_secs":3600,"funding_keyset_recovery_window_secs": 123}}
            })
        );
        assert_eq!(value["bytes_in_per_msat"], 11);
        assert_eq!(value["bytes_out_per_msat"], 22);
        assert!(value.get("active_in_rate").is_none());
        assert!(value.get("active_out_rate").is_none());
        let ServerMessage::SessionStatus { advertisements, .. } =
            serde_json::from_value::<ServerMessage>(value.clone()).unwrap()
        else {
            panic!()
        };
        let options = advertisement_options(&advertisements, 11, 22);
        assert_eq!(options.len(), 3);
        assert!(options.iter().all(|o| o.in_bytes_per_millisat == 11
            && o.out_bytes_per_millisat == 22
            && o.minimum_channel_lifetime_secs == 3600));
        let mut empty = value.clone();
        empty["advertisements"] = json!({});
        assert!(serde_json::from_value::<ServerMessage>(empty).is_ok());
        let mut legacy = value;
        legacy["advertisements"] = json!([]);
        assert!(serde_json::from_value::<ServerMessage>(legacy).is_err());
    }
}
