use monad_common::payment_units::{
    msats_to_raw_units as common_msats_to_raw_units,
    raw_units_to_msats as common_raw_units_to_msats,
};
use monad_common::protocol::KeysetAdvertisement;
use rand::RngCore;
use serde_json::json;
use std::collections::BTreeMap;
use std::fmt;
use std::io;
use std::sync::Mutex;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RelayPaymentOffer {
    pub receiver_pubkey: String,
    pub mint_url: String,
    pub unit: String,
    pub accepted_keyset_ids: Vec<String>,
    pub in_bytes_per_millisat: u64,
    pub out_bytes_per_millisat: u64,
}

impl RelayPaymentOffer {
    pub fn from_advertisement(
        receiver_pubkey: String,
        advertisement: &KeysetAdvertisement,
    ) -> Self {
        Self {
            receiver_pubkey,
            mint_url: advertisement.mint_url.clone(),
            unit: advertisement.unit.clone(),
            accepted_keyset_ids: advertisement.keyset_ids.clone(),
            in_bytes_per_millisat: advertisement.in_bytes_per_millisat,
            out_bytes_per_millisat: advertisement.out_bytes_per_millisat,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WalletChannelState {
    Open,
    Closing,
    Closed,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WalletChannel {
    pub channel_id: String,
    pub state: WalletChannelState,
    pub receiver_pubkey: String,
    pub mint_url: String,
    pub unit: String,
    pub keyset_id: String,
    pub attached_session_id: Option<[u8; 32]>,
    pub capacity_msats: u64,
    pub current_signed_balance_msats: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WalletError {
    NotFound,
    NotOpen,
    AttachedToDifferentSession { current: [u8; 32] },
    InsufficientCapacity { requested: u64, capacity: u64 },
    NoNewFunds,
    ChannelUnusable,
    OfferMismatch(String),
    Backend(String),
}

impl fmt::Display for WalletError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NotFound => write!(f, "channel not found"),
            Self::NotOpen => write!(f, "channel not open"),
            Self::AttachedToDifferentSession { .. } => {
                write!(f, "channel attached to different session")
            }
            Self::InsufficientCapacity {
                requested,
                capacity,
            } => write!(
                f,
                "insufficient capacity: requested={requested} capacity={capacity}"
            ),
            Self::NoNewFunds => write!(f, "no new funds"),
            Self::ChannelUnusable => write!(f, "channel unusable"),
            Self::OfferMismatch(message) => write!(f, "offer mismatch: {message}"),
            Self::Backend(message) => write!(f, "backend error: {message}"),
        }
    }
}

impl std::error::Error for WalletError {}

pub trait MonadWallet: Send + Sync + 'static {
    fn list_channels(&self) -> Result<Vec<WalletChannel>, WalletError>;

    fn get_channel(&self, channel_id: &str) -> Result<WalletChannel, WalletError>;

    fn attach_channel_to_session(
        &self,
        channel_id: &str,
        session_id: [u8; 32],
    ) -> Result<(), WalletError>;

    fn detach_channel_from_session(
        &self,
        channel_id: &str,
        session_id: [u8; 32],
    ) -> Result<(), WalletError>;

    fn mark_channel_unusable(&self, channel_id: &str) -> Result<(), WalletError>;

    fn provision_channel(
        &self,
        offer: &RelayPaymentOffer,
        capacity_msats: u64,
    ) -> Result<String, WalletError>;

    fn build_link_request(
        &self,
        channel_id: &str,
        offer: &RelayPaymentOffer,
    ) -> Result<String, WalletError>;

    fn build_channel_payment(
        &self,
        channel_id: &str,
        offer: &RelayPaymentOffer,
        latest_server_balance_raw: u64,
        next_balance_raw: u64,
    ) -> Result<String, WalletError>;
}

pub fn select_channel(
    channels: &[WalletChannel],
    offer: &RelayPaymentOffer,
    session_id: [u8; 32],
) -> Option<WalletChannel> {
    let mut same_session = Vec::new();
    let mut unattached = Vec::new();

    for channel in channels {
        if channel.state != WalletChannelState::Open {
            continue;
        }
        if channel.receiver_pubkey != offer.receiver_pubkey
            || channel.mint_url != offer.mint_url
            || channel.unit != offer.unit
            || !offer
                .accepted_keyset_ids
                .iter()
                .any(|id| id == &channel.keyset_id)
        {
            continue;
        }

        match channel.attached_session_id {
            None => unattached.push(channel.clone()),
            Some(attached) if attached == session_id => same_session.push(channel.clone()),
            Some(_) => {}
        }
    }

    unattached.sort_by(|a, b| a.channel_id.cmp(&b.channel_id));
    same_session.sort_by(|a, b| a.channel_id.cmp(&b.channel_id));

    unattached
        .into_iter()
        .next()
        .or_else(|| same_session.into_iter().next())
}

#[derive(Debug, Clone)]
pub struct MockWallet {
    inner: std::sync::Arc<Mutex<MockWalletInner>>,
}

#[derive(Debug, Default)]
struct MockWalletInner {
    channels: BTreeMap<String, StoredChannel>,
}

#[derive(Debug, Clone)]
struct StoredChannel {
    channel: WalletChannel,
    capacity_raw: u64,
    current_signed_balance_raw: u64,
    next_link_invalid: bool,
    next_link_wrong_receiver: bool,
    next_payment_invalid: bool,
    last_link_payload: Option<String>,
    last_payment_payload: Option<String>,
    successful_payment_builds: u64,
}

impl StoredChannel {
    fn public(&self) -> WalletChannel {
        self.channel.clone()
    }
}

impl MockWallet {
    pub fn new() -> Self {
        Self {
            inner: std::sync::Arc::new(Mutex::new(MockWalletInner::default())),
        }
    }

    pub fn insert_channel(&self, channel: WalletChannel) -> Result<(), WalletError> {
        let (capacity_raw, signed_balance_raw, signed_balance_msats) =
            raw_amounts_for_channel(&channel, channel.current_signed_balance_msats)?;
        let mut inner = self
            .inner
            .lock()
            .map_err(|_| WalletError::Backend("wallet mutex poisoned".to_string()))?;
        inner.channels.insert(
            channel.channel_id.clone(),
            StoredChannel {
                channel: WalletChannel {
                    current_signed_balance_msats: signed_balance_msats,
                    ..channel
                },
                capacity_raw,
                current_signed_balance_raw: signed_balance_raw,
                next_link_invalid: false,
                next_link_wrong_receiver: false,
                next_payment_invalid: false,
                last_link_payload: None,
                last_payment_payload: None,
                successful_payment_builds: 0,
            },
        );
        Ok(())
    }

    pub fn set_attachment(
        &self,
        channel_id: &str,
        session_id: Option<[u8; 32]>,
    ) -> Result<(), WalletError> {
        let mut inner = self
            .inner
            .lock()
            .map_err(|_| WalletError::Backend("wallet mutex poisoned".to_string()))?;
        let stored = inner
            .channels
            .get_mut(channel_id)
            .ok_or(WalletError::NotFound)?;
        stored.channel.attached_session_id = session_id;
        Ok(())
    }

    pub fn set_state(
        &self,
        channel_id: &str,
        state: WalletChannelState,
    ) -> Result<(), WalletError> {
        let mut inner = self
            .inner
            .lock()
            .map_err(|_| WalletError::Backend("wallet mutex poisoned".to_string()))?;
        let stored = inner
            .channels
            .get_mut(channel_id)
            .ok_or(WalletError::NotFound)?;
        stored.channel.state = state;
        if state != WalletChannelState::Open {
            stored.channel.attached_session_id = None;
        }
        Ok(())
    }

    pub fn set_balance(&self, channel_id: &str, balance_msats: u64) -> Result<(), WalletError> {
        let mut inner = self
            .inner
            .lock()
            .map_err(|_| WalletError::Backend("wallet mutex poisoned".to_string()))?;
        let stored = inner
            .channels
            .get_mut(channel_id)
            .ok_or(WalletError::NotFound)?;
        let (_, balance_raw, balance_msats) =
            raw_amounts_for_channel(&stored.channel, balance_msats)?;
        stored.current_signed_balance_raw = balance_raw;
        stored.channel.current_signed_balance_msats = balance_msats;
        Ok(())
    }

    pub fn force_next_link_invalid(&self, channel_id: &str) -> Result<(), WalletError> {
        self.set_flag(channel_id, |stored| stored.next_link_invalid = true)
    }

    pub fn force_next_link_wrong_receiver(&self, channel_id: &str) -> Result<(), WalletError> {
        self.set_flag(channel_id, |stored| stored.next_link_wrong_receiver = true)
    }

    pub fn force_next_payment_invalid(&self, channel_id: &str) -> Result<(), WalletError> {
        self.set_flag(channel_id, |stored| stored.next_payment_invalid = true)
    }

    pub fn last_link_payload(&self, channel_id: &str) -> Result<Option<String>, WalletError> {
        let inner = self
            .inner
            .lock()
            .map_err(|_| WalletError::Backend("wallet mutex poisoned".to_string()))?;
        Ok(inner
            .channels
            .get(channel_id)
            .ok_or(WalletError::NotFound)?
            .last_link_payload
            .clone())
    }

    pub fn last_payment_payload(&self, channel_id: &str) -> Result<Option<String>, WalletError> {
        let inner = self
            .inner
            .lock()
            .map_err(|_| WalletError::Backend("wallet mutex poisoned".to_string()))?;
        Ok(inner
            .channels
            .get(channel_id)
            .ok_or(WalletError::NotFound)?
            .last_payment_payload
            .clone())
    }

    pub fn attachment(&self, channel_id: &str) -> Result<Option<[u8; 32]>, WalletError> {
        let inner = self
            .inner
            .lock()
            .map_err(|_| WalletError::Backend("wallet mutex poisoned".to_string()))?;
        Ok(inner
            .channels
            .get(channel_id)
            .ok_or(WalletError::NotFound)?
            .channel
            .attached_session_id)
    }

    pub fn successful_payment_build_count(&self, channel_id: &str) -> Result<u64, WalletError> {
        let inner = self
            .inner
            .lock()
            .map_err(|_| WalletError::Backend("wallet mutex poisoned".to_string()))?;
        Ok(inner
            .channels
            .get(channel_id)
            .ok_or(WalletError::NotFound)?
            .successful_payment_builds)
    }

    fn set_flag(
        &self,
        channel_id: &str,
        mut update: impl FnMut(&mut StoredChannel),
    ) -> Result<(), WalletError> {
        let mut inner = self
            .inner
            .lock()
            .map_err(|_| WalletError::Backend("wallet mutex poisoned".to_string()))?;
        let stored = inner
            .channels
            .get_mut(channel_id)
            .ok_or(WalletError::NotFound)?;
        update(stored);
        Ok(())
    }
}

impl Default for MockWallet {
    fn default() -> Self {
        Self::new()
    }
}

impl MonadWallet for MockWallet {
    fn list_channels(&self) -> Result<Vec<WalletChannel>, WalletError> {
        let inner = self
            .inner
            .lock()
            .map_err(|_| WalletError::Backend("wallet mutex poisoned".to_string()))?;
        Ok(inner.channels.values().map(StoredChannel::public).collect())
    }

    fn get_channel(&self, channel_id: &str) -> Result<WalletChannel, WalletError> {
        let inner = self
            .inner
            .lock()
            .map_err(|_| WalletError::Backend("wallet mutex poisoned".to_string()))?;
        inner
            .channels
            .get(channel_id)
            .map(StoredChannel::public)
            .ok_or(WalletError::NotFound)
    }

    fn attach_channel_to_session(
        &self,
        channel_id: &str,
        session_id: [u8; 32],
    ) -> Result<(), WalletError> {
        let mut inner = self
            .inner
            .lock()
            .map_err(|_| WalletError::Backend("wallet mutex poisoned".to_string()))?;
        let stored = inner
            .channels
            .get_mut(channel_id)
            .ok_or(WalletError::NotFound)?;
        if stored.channel.state != WalletChannelState::Open {
            return Err(WalletError::NotOpen);
        }
        match stored.channel.attached_session_id {
            Some(current) if current != session_id => {
                Err(WalletError::AttachedToDifferentSession { current })
            }
            Some(_) => Ok(()),
            None => {
                stored.channel.attached_session_id = Some(session_id);
                Ok(())
            }
        }
    }

    fn detach_channel_from_session(
        &self,
        channel_id: &str,
        session_id: [u8; 32],
    ) -> Result<(), WalletError> {
        let mut inner = self
            .inner
            .lock()
            .map_err(|_| WalletError::Backend("wallet mutex poisoned".to_string()))?;
        let stored = inner
            .channels
            .get_mut(channel_id)
            .ok_or(WalletError::NotFound)?;
        if stored.channel.attached_session_id == Some(session_id) {
            stored.channel.attached_session_id = None;
        }
        Ok(())
    }

    fn mark_channel_unusable(&self, channel_id: &str) -> Result<(), WalletError> {
        let mut inner = self
            .inner
            .lock()
            .map_err(|_| WalletError::Backend("wallet mutex poisoned".to_string()))?;
        let stored = inner
            .channels
            .get_mut(channel_id)
            .ok_or(WalletError::NotFound)?;
        stored.channel.state = WalletChannelState::Closing;
        stored.channel.attached_session_id = None;
        Ok(())
    }

    fn provision_channel(
        &self,
        offer: &RelayPaymentOffer,
        capacity_msats: u64,
    ) -> Result<String, WalletError> {
        let mut inner = self
            .inner
            .lock()
            .map_err(|_| WalletError::Backend("wallet mutex poisoned".to_string()))?;
        let channel_id = loop {
            let mut bytes = [0u8; 16];
            rand::rng().fill_bytes(&mut bytes);
            let candidate = format!("mock-chan-{}", hex::encode(bytes));
            if !inner.channels.contains_key(&candidate) {
                break candidate;
            }
        };
        let keyset_id = offer.accepted_keyset_ids.first().cloned().ok_or_else(|| {
            WalletError::OfferMismatch("offer has no accepted keysets".to_string())
        })?;
        let channel = WalletChannel {
            channel_id: channel_id.clone(),
            state: WalletChannelState::Open,
            receiver_pubkey: offer.receiver_pubkey.clone(),
            mint_url: offer.mint_url.clone(),
            unit: offer.unit.clone(),
            keyset_id,
            attached_session_id: None,
            capacity_msats,
            current_signed_balance_msats: 0,
        };
        let (capacity_raw, signed_balance_raw, signed_balance_msats) =
            raw_amounts_for_channel(&channel, channel.current_signed_balance_msats)?;
        inner.channels.insert(
            channel_id.clone(),
            StoredChannel {
                channel: WalletChannel {
                    current_signed_balance_msats: signed_balance_msats,
                    ..channel
                },
                capacity_raw,
                current_signed_balance_raw: signed_balance_raw,
                next_link_invalid: false,
                next_link_wrong_receiver: false,
                next_payment_invalid: false,
                last_link_payload: None,
                last_payment_payload: None,
                successful_payment_builds: 0,
            },
        );
        Ok(channel_id)
    }

    fn build_link_request(
        &self,
        channel_id: &str,
        offer: &RelayPaymentOffer,
    ) -> Result<String, WalletError> {
        let mut inner = self
            .inner
            .lock()
            .map_err(|_| WalletError::Backend("wallet mutex poisoned".to_string()))?;
        let stored = inner
            .channels
            .get_mut(channel_id)
            .ok_or(WalletError::NotFound)?;
        ensure_channel_matches_offer(&stored.channel, offer)?;
        if stored.channel.state != WalletChannelState::Open {
            return Err(WalletError::NotOpen);
        }
        if stored.channel.attached_session_id.is_none() {
            return Err(WalletError::Backend(
                "channel must be attached before linking".to_string(),
            ));
        }

        let mut payload = json!({
            "channel_id": channel_id,
            "balance": 0,
            "capacity": stored.capacity_raw,
            "unit": stored.channel.unit,
        });
        if stored.next_link_invalid {
            payload["invalid"] = json!(true);
            stored.next_link_invalid = false;
        }
        if stored.next_link_wrong_receiver {
            payload["wrong_receiver"] = json!(true);
            stored.next_link_wrong_receiver = false;
        }

        let payload = payload.to_string();
        stored.last_link_payload = Some(payload.clone());
        Ok(payload)
    }

    fn build_channel_payment(
        &self,
        channel_id: &str,
        offer: &RelayPaymentOffer,
        latest_server_balance_raw: u64,
        next_balance_raw: u64,
    ) -> Result<String, WalletError> {
        let mut inner = self
            .inner
            .lock()
            .map_err(|_| WalletError::Backend("wallet mutex poisoned".to_string()))?;
        let stored = inner
            .channels
            .get_mut(channel_id)
            .ok_or(WalletError::NotFound)?;
        ensure_channel_matches_offer(&stored.channel, offer)?;
        if stored.channel.state != WalletChannelState::Open {
            return Err(WalletError::NotOpen);
        }
        if stored.channel.attached_session_id.is_none() {
            return Err(WalletError::Backend(
                "channel must be attached before payment".to_string(),
            ));
        }
        if next_balance_raw <= latest_server_balance_raw {
            return Err(WalletError::NoNewFunds);
        }
        if next_balance_raw > stored.capacity_raw {
            let requested_msats = raw_to_msats(&stored.channel.unit, next_balance_raw)?;
            return Err(WalletError::InsufficientCapacity {
                requested: requested_msats,
                capacity: stored.channel.capacity_msats,
            });
        }
        if stored.current_signed_balance_raw > next_balance_raw {
            return Err(WalletError::Backend(
                "wallet local balance exceeds requested next balance".to_string(),
            ));
        }

        let mut payload = json!({
            "channel_id": channel_id,
            "balance": next_balance_raw,
        });
        if stored.next_payment_invalid {
            payload["invalid"] = json!(true);
            stored.next_payment_invalid = false;
        }

        stored.current_signed_balance_raw = next_balance_raw;
        stored.channel.current_signed_balance_msats =
            raw_to_msats(&stored.channel.unit, next_balance_raw)?;
        stored.successful_payment_builds = stored.successful_payment_builds.saturating_add(1);
        let payload = payload.to_string();
        stored.last_payment_payload = Some(payload.clone());
        Ok(payload)
    }
}

fn ensure_channel_matches_offer(
    channel: &WalletChannel,
    offer: &RelayPaymentOffer,
) -> Result<(), WalletError> {
    if channel.receiver_pubkey != offer.receiver_pubkey {
        return Err(WalletError::OfferMismatch(
            "receiver pubkey mismatch".to_string(),
        ));
    }
    if channel.mint_url != offer.mint_url {
        return Err(WalletError::OfferMismatch("mint URL mismatch".to_string()));
    }
    if channel.unit != offer.unit {
        return Err(WalletError::OfferMismatch("unit mismatch".to_string()));
    }
    if !offer
        .accepted_keyset_ids
        .iter()
        .any(|keyset| keyset == &channel.keyset_id)
    {
        return Err(WalletError::OfferMismatch(
            "keyset not accepted".to_string(),
        ));
    }
    Ok(())
}

fn raw_amounts_for_channel(
    channel: &WalletChannel,
    balance_msats: u64,
) -> Result<(u64, u64, u64), WalletError> {
    let capacity_raw = msats_to_raw_units(&channel.unit, channel.capacity_msats)?;
    let signed_balance_raw = msats_to_raw_units(&channel.unit, balance_msats)?;
    let signed_balance_msats = raw_to_msats(&channel.unit, signed_balance_raw)?;
    Ok((capacity_raw, signed_balance_raw, signed_balance_msats))
}

fn msats_to_raw_units(unit: &str, amount_msats: u64) -> Result<u64, WalletError> {
    common_msats_to_raw_units(unit, amount_msats)
        .map_err(|e| WalletError::OfferMismatch(e.to_string()))
}

fn raw_to_msats(unit: &str, amount_raw: u64) -> Result<u64, WalletError> {
    common_raw_units_to_msats(unit, amount_raw).map_err(|e| match e.kind() {
        io::ErrorKind::InvalidInput => WalletError::OfferMismatch(e.to_string()),
        _ => WalletError::Backend(e.to_string()),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn session(byte: u8) -> [u8; 32] {
        [byte; 32]
    }

    fn offer(unit: &str) -> RelayPaymentOffer {
        RelayPaymentOffer {
            receiver_pubkey: "receiver".to_string(),
            mint_url: "https://mint".to_string(),
            unit: unit.to_string(),
            accepted_keyset_ids: vec!["keyset-a".to_string(), "keyset-b".to_string()],
            in_bytes_per_millisat: 1,
            out_bytes_per_millisat: 1,
        }
    }

    fn channel(channel_id: &str) -> WalletChannel {
        WalletChannel {
            channel_id: channel_id.to_string(),
            state: WalletChannelState::Open,
            receiver_pubkey: "receiver".to_string(),
            mint_url: "https://mint".to_string(),
            unit: "msat".to_string(),
            keyset_id: "keyset-a".to_string(),
            attached_session_id: None,
            capacity_msats: 10_000,
            current_signed_balance_msats: 0,
        }
    }

    #[test]
    fn selector_prefers_unattached_channel() {
        let chosen = select_channel(
            &[
                WalletChannel {
                    attached_session_id: Some(session(2)),
                    ..channel("chan-b")
                },
                channel("chan-a"),
            ],
            &offer("msat"),
            session(1),
        )
        .unwrap();

        assert_eq!(chosen.channel_id, "chan-a");
    }

    #[test]
    fn selector_falls_back_to_same_session_channel() {
        let chosen = select_channel(
            &[WalletChannel {
                attached_session_id: Some(session(1)),
                ..channel("chan-a")
            }],
            &offer("msat"),
            session(1),
        )
        .unwrap();

        assert_eq!(chosen.channel_id, "chan-a");
    }

    #[test]
    fn selector_excludes_wrong_offer_and_non_open_channels() {
        let chosen = select_channel(
            &[
                WalletChannel {
                    state: WalletChannelState::Closing,
                    ..channel("chan-a")
                },
                WalletChannel {
                    keyset_id: "other".to_string(),
                    ..channel("chan-b")
                },
            ],
            &offer("msat"),
            session(1),
        );

        assert!(chosen.is_none());
    }

    #[test]
    fn attach_rejects_different_session() {
        let wallet = MockWallet::new();
        wallet.insert_channel(channel("chan")).unwrap();
        wallet
            .attach_channel_to_session("chan", session(1))
            .unwrap();

        let err = wallet
            .attach_channel_to_session("chan", session(2))
            .unwrap_err();
        assert_eq!(
            err,
            WalletError::AttachedToDifferentSession {
                current: session(1)
            }
        );
    }

    #[test]
    fn mark_unusable_clears_attachment() {
        let wallet = MockWallet::new();
        wallet.insert_channel(channel("chan")).unwrap();
        wallet
            .attach_channel_to_session("chan", session(1))
            .unwrap();

        wallet.mark_channel_unusable("chan").unwrap();

        let stored = wallet.get_channel("chan").unwrap();
        assert_eq!(stored.state, WalletChannelState::Closing);
        assert_eq!(stored.attached_session_id, None);
    }

    #[test]
    fn link_request_includes_zero_balance_capacity_and_unit() {
        let wallet = MockWallet::new();
        wallet.insert_channel(channel("chan")).unwrap();
        wallet
            .attach_channel_to_session("chan", session(1))
            .unwrap();

        let payload = wallet.build_link_request("chan", &offer("msat")).unwrap();
        let value: serde_json::Value = serde_json::from_str(&payload).unwrap();
        assert_eq!(value["balance"], 0);
        assert_eq!(value["capacity"], 10_000);
        assert_eq!(value["unit"], "msat");
    }

    #[test]
    fn payment_requests_exact_next_balance() {
        let wallet = MockWallet::new();
        let mut chan = channel("chan");
        chan.capacity_msats = 20_000;
        chan.current_signed_balance_msats = 7_000;
        wallet.insert_channel(chan).unwrap();
        wallet
            .attach_channel_to_session("chan", session(1))
            .unwrap();

        let payload = wallet
            .build_channel_payment("chan", &offer("msat"), 7_000, 12_000)
            .unwrap();
        let value: serde_json::Value = serde_json::from_str(&payload).unwrap();
        assert_eq!(value["balance"], 12_000);
        assert_eq!(
            wallet
                .get_channel("chan")
                .unwrap()
                .current_signed_balance_msats,
            12_000
        );
    }

    #[test]
    fn sat_payments_round_up_to_next_sat() {
        let wallet = MockWallet::new();
        let mut chan = channel("chan");
        chan.unit = "sat".to_string();
        chan.capacity_msats = 10_000;
        wallet.insert_channel(chan).unwrap();
        wallet
            .attach_channel_to_session("chan", session(1))
            .unwrap();

        let payload = wallet
            .build_channel_payment("chan", &offer("sat"), 0, 2)
            .unwrap();
        let value: serde_json::Value = serde_json::from_str(&payload).unwrap();
        assert_eq!(value["balance"], 2);
        assert_eq!(
            wallet
                .get_channel("chan")
                .unwrap()
                .current_signed_balance_msats,
            2_000
        );
    }

    #[test]
    fn payment_rejects_no_new_funds_and_capacity_overflow() {
        let wallet = MockWallet::new();
        wallet.insert_channel(channel("chan")).unwrap();
        wallet
            .attach_channel_to_session("chan", session(1))
            .unwrap();
        wallet
            .build_channel_payment("chan", &offer("msat"), 0, 5)
            .unwrap();

        let no_new = wallet
            .build_channel_payment("chan", &offer("msat"), 5, 5)
            .unwrap_err();
        assert_eq!(no_new, WalletError::NoNewFunds);

        let overflow = wallet
            .build_channel_payment("chan", &offer("msat"), 5, 20_000)
            .unwrap_err();
        assert_eq!(
            overflow,
            WalletError::InsufficientCapacity {
                requested: 20_000,
                capacity: 10_000,
            }
        );
    }

    #[test]
    fn provisioned_channel_matches_offer() {
        let wallet = MockWallet::new();
        let channel_id = wallet.provision_channel(&offer("sat"), 12_000).unwrap();
        let channel = wallet.get_channel(&channel_id).unwrap();

        assert_eq!(channel.receiver_pubkey, "receiver");
        assert_eq!(channel.mint_url, "https://mint");
        assert_eq!(channel.unit, "sat");
        assert_eq!(channel.keyset_id, "keyset-a");
        assert_eq!(channel.capacity_msats, 12_000);
    }
}
