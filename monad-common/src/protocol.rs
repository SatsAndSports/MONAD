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
    NumericLimitExceeded,
    InternalError,
    LinkChannelRetired,
    ChannelUnlinkRejected,
}

/// Messages sent from client to server on the control channel.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", deny_unknown_fields)]
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
    /// Release linked ownership of a channel after all signed payments are acknowledged.
    ChannelUnlink { channel_id: String },
    /// Request a fresh session status snapshot.
    GetSessionStatus,
    /// Request correlated control-path liveness evidence.
    Ping { nonce: String },
}

/// Messages sent from server to client on the control channel.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", deny_unknown_fields)]
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
        session_total_bytes_in: u64,
        session_total_bytes_out: u64,
        total_paid_millisats: u64,
        remaining_milli_sats: i64,
        paused: bool,
        open_connects: u32,
        total_connects: u64,
        failed_connects: u64,
    },

    /// Another session claimed the channel; this session is now Unlinked.
    ChannelEvicted {
        channel_id: String,
    },
    ChannelReleaseRequested {
        channel_id: String,
    },
    /// Correlated response to a client Ping.
    Pong {
        nonce: String,
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
            session_total_bytes_in: 0,
            session_total_bytes_out: 0,
            total_paid_millisats: 0,
            remaining_milli_sats: 0,
            paused: true,
            open_connects: 0,
            total_connects: 0,
            failed_connects: 0,
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
        assert_eq!(value["session_total_bytes_in"], 0);
        assert_eq!(value["session_total_bytes_out"], 0);
        assert_eq!(value["failed_connects"], 0);
        assert!(value.get("active_in_rate").is_none());
        assert!(value.get("active_out_rate").is_none());
        assert!(value.get("session_total_in").is_none());
        assert!(value.get("session_total_out").is_none());
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

        for (legacy_name, current_name) in [
            ("session_total_in", "session_total_bytes_in"),
            ("session_total_out", "session_total_bytes_out"),
        ] {
            let mut legacy_names = value.clone();
            let object = legacy_names.as_object_mut().unwrap();
            let legacy_value = object.remove(current_name).unwrap();
            object.insert(legacy_name.into(), legacy_value);
            assert!(serde_json::from_value::<ServerMessage>(legacy_names).is_err());
        }
        let mut missing_failed = value.clone();
        missing_failed
            .as_object_mut()
            .unwrap()
            .remove("failed_connects")
            .unwrap();
        assert!(serde_json::from_value::<ServerMessage>(missing_failed).is_err());

        let mut legacy = value;
        legacy["advertisements"] = json!([]);
        assert!(serde_json::from_value::<ServerMessage>(legacy).is_err());
    }

    #[test]
    fn channel_unlink_is_id_only_and_rejects_legacy_fields() {
        let unlink = ClientMessage::ChannelUnlink {
            channel_id: "a".repeat(64),
        };
        let value = serde_json::to_value(&unlink).unwrap();
        assert_eq!(
            value,
            json!({"type":"ChannelUnlink","channel_id":"a".repeat(64)})
        );
        assert!(serde_json::from_value::<ClientMessage>(value).is_ok());

        let legacy = json!({
            "type":"ChannelUnlink",
            "channel_id":"a".repeat(64),
            "final_balance_raw":0
        });
        assert!(serde_json::from_value::<ClientMessage>(legacy).is_err());
    }

    #[test]
    fn server_wire_rejects_removed_unlink_ack_and_unknown_fields() {
        assert!(serde_json::from_value::<ServerMessage>(json!({
            "type":"ChannelUnlinked",
            "channel_id":"a".repeat(64),
            "final_balance_raw":0
        }))
        .is_err());

        let mut status = serde_json::to_value(ServerMessage::SessionStatus {
            receiver_pubkey: "receiver".into(),
            advertisements: BTreeMap::new(),
            linked_channel: None,
            active_in_rate: 1,
            active_out_rate: 1,
            session_total_bytes_in: 0,
            session_total_bytes_out: 0,
            total_paid_millisats: 0,
            remaining_milli_sats: 0,
            paused: true,
            open_connects: 0,
            total_connects: 0,
            failed_connects: 0,
        })
        .unwrap();
        status["unexpected"] = json!(null);
        assert!(serde_json::from_value::<ServerMessage>(status).is_err());
    }

    #[test]
    fn numeric_limit_error_uses_stable_wire_code() {
        let value = serde_json::to_value(ServerMessage::Error {
            code: ServerErrorCode::NumericLimitExceeded,
            message: "numeric limit exceeded".into(),
        })
        .unwrap();
        assert_eq!(
            value,
            json!({
                "type":"Error",
                "code":"NUMERIC_LIMIT_EXCEEDED",
                "message":"numeric limit exceeded"
            })
        );
        assert!(serde_json::from_value::<ServerMessage>(value).is_ok());
    }

    #[test]
    fn ping_and_pong_preserve_opaque_nonce_and_reject_extra_fields() {
        let nonce = "probe-τ-001".to_string();
        let ping = serde_json::to_value(ClientMessage::Ping {
            nonce: nonce.clone(),
        })
        .unwrap();
        assert_eq!(ping, json!({"type":"Ping","nonce":nonce}));
        assert!(serde_json::from_value::<ClientMessage>(ping).is_ok());

        let pong = serde_json::to_value(ServerMessage::Pong {
            nonce: nonce.clone(),
        })
        .unwrap();
        assert_eq!(pong, json!({"type":"Pong","nonce":nonce}));
        assert!(serde_json::from_value::<ServerMessage>(pong.clone()).is_ok());

        assert!(
            serde_json::from_value::<ServerMessage>(json!({"type":"Ping","nonce":nonce})).is_err()
        );
        assert!(serde_json::from_value::<ClientMessage>(pong).is_err());

        for invalid in [
            json!({"type":"Ping","nonce":"probe","extra":null}),
            json!({"type":"Ping","nonce":1}),
            json!({"type":"Pong","nonce":"probe","extra":null}),
            json!({"type":"Pong","nonce":1}),
        ] {
            assert!(serde_json::from_value::<ClientMessage>(invalid.clone()).is_err());
            assert!(serde_json::from_value::<ServerMessage>(invalid).is_err());
        }
    }
}
