//! Test-only wallet that produces real Cashu Spilman payment proofs.
//!
//! This wraps `cdk_spilman::SpilmanClientBridge` with an in-memory test mint so
//! that integration tests can exercise the relay's real cryptographic payment
//! validation (`SpilmanRelayPayments` + `SqliteStorage`) instead of the fast
//! mocked path.
//!
//! Tests using this wallet must run on a multi-threaded Tokio runtime because
//! `InMemoryMintNetworking` calls `tokio::task::block_in_place` internally.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use cashu::nuts::SecretKey;
use cdk::mint::Mint;
use cdk_spilman::{
    build_cashu_b_token, ConfigurableClientHost, MemoryClientStorage, OpenChannelResult,
    SpilmanClientBridge,
};
use cdk_spilman_test_mint::InMemoryMintNetworking;
use monad_client::wallet::{
    MonadWallet, RelayPaymentOffer, WalletChannel, WalletChannelState, WalletError,
};
use monad_common::payment_units::raw_units_to_msats;

#[derive(Debug, Clone)]
struct ChannelMetadata {
    channel_id: String,
    receiver_pubkey: String,
    mint_url: String,
    unit: String,
    keyset_id: String,
    capacity_msats: u64,
    capacity_raw: u64,
    current_signed_balance_msats: u64,
    current_signed_balance_raw: u64,
    state: WalletChannelState,
    attached_session_id: Option<[u8; 32]>,
}

#[derive(Debug)]
pub struct TestSigningWallet {
    bridge: Mutex<
        SpilmanClientBridge<ConfigurableClientHost<MemoryClientStorage>, InMemoryMintNetworking>,
    >,
    mint: Arc<Mint>,
    _sender_secret: SecretKey,
    sender_pubkey_hex: String,
    receiver_pubkey_hex: String,
    mint_url: String,
    keyset_id: String,
    keyset_info_json: String,
    channels: Mutex<HashMap<String, ChannelMetadata>>,
}

impl TestSigningWallet {
    /// Create a wallet that signs payments for `receiver_pubkey_hex` using
    /// proofs minted from `mint`.
    ///
    /// `keyset_info_json` must be the full keyset info JSON for `keyset_id` in
    /// the format expected by `cdk_spilman` (as returned by
    /// `TestMintHelper::keyset_info_json`).
    pub async fn new(
        mint: Arc<Mint>,
        receiver_pubkey_hex: String,
        mint_url: String,
        keyset_id: String,
        keyset_info_json: String,
    ) -> Self {
        let sender_secret = SecretKey::generate();
        let sender_pubkey_hex = sender_secret.public_key().to_hex();

        let mut host = ConfigurableClientHost::new_in_memory();
        host.add_key(sender_secret.clone());

        let networking = InMemoryMintNetworking::new(Arc::clone(&mint));
        let bridge = SpilmanClientBridge::new(host, networking);

        Self {
            bridge: Mutex::new(bridge),
            mint,
            _sender_secret: sender_secret,
            sender_pubkey_hex,
            receiver_pubkey_hex,
            mint_url,
            keyset_id,
            keyset_info_json,
            channels: Mutex::new(HashMap::new()),
        }
    }

    /// Mint `capacity_sats` worth of proofs from the test mint and open a real
    /// Spilman channel. Returns the channel id.
    ///
    /// Must be called from within a Tokio runtime context.
    pub async fn pre_create_channel(&self, capacity_sats: u64) -> Result<String, String> {
        let proofs = cdk_spilman_test_mint::mint_test_proofs(&self.mint, capacity_sats)
            .await
            .map_err(|e| format!("failed to mint test proofs: {e}"))?;
        let token = build_cashu_b_token(
            &self.mint_url,
            "sat",
            &serde_json::to_string(&proofs)
                .map_err(|e| format!("failed to serialize proofs: {e}"))?,
        )
        .map_err(|e| format!("failed to build cashu token: {e}"))?;

        let open_result = {
            let bridge = self.bridge.lock().map_err(|_| "bridge mutex poisoned")?;
            bridge
                .open_channel_from_token(
                    &token,
                    &self.receiver_pubkey_hex,
                    &self.sender_pubkey_hex,
                    Self::expiry_timestamp(),
                    &self.keyset_info_json,
                    capacity_sats,
                )
                .map_err(|e| format!("failed to open channel: {e}"))?
        };

        self.record_opened_channel(&open_result)?;
        Ok(open_result.channel_id.clone())
    }

    /// Build a funding-bearing link payment without checking a relay offer.
    ///
    /// This is intentionally test-only escape hatch for negative relay tests
    /// that must send malformed or policy-invalid links which a normal client
    /// wallet would refuse to construct.
    pub fn build_raw_link_request(&self, channel_id: &str) -> Result<String, WalletError> {
        let channels = self
            .channels
            .lock()
            .map_err(|_| WalletError::Backend("channels mutex poisoned".to_string()))?;
        let metadata = channels.get(channel_id).ok_or(WalletError::NotFound)?;
        if metadata.state != WalletChannelState::Open {
            return Err(WalletError::NotOpen);
        }
        if metadata.attached_session_id.is_none() {
            return Err(WalletError::Backend(
                "channel must be attached before linking".to_string(),
            ));
        }

        let bridge = self
            .bridge
            .lock()
            .map_err(|_| WalletError::Backend("bridge mutex poisoned".to_string()))?;
        let payment = bridge
            .create_payment_with_funding(channel_id, 0)
            .map_err(|e| WalletError::Backend(format!("failed to create link payment: {e}")))?;
        serde_json::to_string(&payment)
            .map_err(|e| WalletError::Backend(format!("failed to serialize payment: {e}")))
    }

    fn record_opened_channel(&self, open_result: &OpenChannelResult) -> Result<(), String> {
        let unit = "sat";
        let capacity_msats = raw_units_to_msats(unit, open_result.capacity)
            .map_err(|e| format!("failed to convert capacity to msats: {e}"))?;

        let metadata = ChannelMetadata {
            channel_id: open_result.channel_id.clone(),
            receiver_pubkey: self.receiver_pubkey_hex.clone(),
            mint_url: open_result.mint_url.clone(),
            unit: unit.to_string(),
            keyset_id: self.keyset_id.clone(),
            capacity_msats,
            capacity_raw: open_result.capacity,
            current_signed_balance_msats: 0,
            current_signed_balance_raw: 0,
            state: WalletChannelState::Open,
            attached_session_id: None,
        };

        let mut channels = self
            .channels
            .lock()
            .map_err(|_| "channels mutex poisoned")?;
        channels.insert(metadata.channel_id.clone(), metadata);
        Ok(())
    }

    fn expiry_timestamp() -> u64 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs() + 3600)
            .unwrap_or(3600)
    }

    fn channel_to_wallet_channel(metadata: &ChannelMetadata) -> WalletChannel {
        WalletChannel {
            channel_id: metadata.channel_id.clone(),
            state: metadata.state,
            receiver_pubkey: metadata.receiver_pubkey.clone(),
            mint_url: metadata.mint_url.clone(),
            unit: metadata.unit.clone(),
            keyset_id: metadata.keyset_id.clone(),
            attached_session_id: metadata.attached_session_id,
            capacity_msats: metadata.capacity_msats,
            current_signed_balance_msats: metadata.current_signed_balance_msats,
        }
    }

    fn ensure_matches_offer(
        metadata: &ChannelMetadata,
        offer: &RelayPaymentOffer,
    ) -> Result<(), WalletError> {
        if metadata.receiver_pubkey != offer.receiver_pubkey {
            return Err(WalletError::OfferMismatch(
                "receiver pubkey mismatch".to_string(),
            ));
        }
        if metadata.mint_url != offer.mint_url {
            return Err(WalletError::OfferMismatch("mint URL mismatch".to_string()));
        }
        if metadata.unit != offer.unit {
            return Err(WalletError::OfferMismatch("unit mismatch".to_string()));
        }
        if !offer
            .accepted_keyset_ids
            .iter()
            .any(|keyset| keyset == &metadata.keyset_id)
        {
            return Err(WalletError::OfferMismatch(
                "keyset not accepted".to_string(),
            ));
        }
        Ok(())
    }

    fn raw_to_msats(unit: &str, raw: u64) -> Result<u64, WalletError> {
        raw_units_to_msats(unit, raw).map_err(|e| WalletError::Backend(e.to_string()))
    }
}

impl MonadWallet for TestSigningWallet {
    fn list_channels(&self) -> Result<Vec<WalletChannel>, WalletError> {
        let channels = self
            .channels
            .lock()
            .map_err(|_| WalletError::Backend("channels mutex poisoned".to_string()))?;
        Ok(channels
            .values()
            .map(Self::channel_to_wallet_channel)
            .collect())
    }

    fn get_channel(&self, channel_id: &str) -> Result<WalletChannel, WalletError> {
        let channels = self
            .channels
            .lock()
            .map_err(|_| WalletError::Backend("channels mutex poisoned".to_string()))?;
        let metadata = channels.get(channel_id).ok_or(WalletError::NotFound)?;
        Ok(Self::channel_to_wallet_channel(metadata))
    }

    fn attach_channel_to_session(
        &self,
        channel_id: &str,
        session_id: [u8; 32],
    ) -> Result<(), WalletError> {
        let mut channels = self
            .channels
            .lock()
            .map_err(|_| WalletError::Backend("channels mutex poisoned".to_string()))?;
        let metadata = channels.get_mut(channel_id).ok_or(WalletError::NotFound)?;
        if let Some(current) = metadata.attached_session_id {
            if current != session_id {
                return Err(WalletError::AttachedToDifferentSession { current });
            }
        }
        metadata.attached_session_id = Some(session_id);
        Ok(())
    }

    fn detach_channel_from_session(
        &self,
        channel_id: &str,
        session_id: [u8; 32],
    ) -> Result<(), WalletError> {
        let mut channels = self
            .channels
            .lock()
            .map_err(|_| WalletError::Backend("channels mutex poisoned".to_string()))?;
        let metadata = channels.get_mut(channel_id).ok_or(WalletError::NotFound)?;
        if metadata.attached_session_id == Some(session_id) {
            metadata.attached_session_id = None;
        }
        Ok(())
    }

    fn mark_channel_unusable(&self, channel_id: &str) -> Result<(), WalletError> {
        let mut channels = self
            .channels
            .lock()
            .map_err(|_| WalletError::Backend("channels mutex poisoned".to_string()))?;
        let metadata = channels.get_mut(channel_id).ok_or(WalletError::NotFound)?;
        metadata.state = WalletChannelState::Closed;
        Ok(())
    }

    fn provision_channel(
        &self,
        _offer: &RelayPaymentOffer,
        _capacity_msats: u64,
    ) -> Result<String, WalletError> {
        Err(WalletError::Backend(
            "TestSigningWallet requires pre-created channels".to_string(),
        ))
    }

    fn build_link_request(
        &self,
        channel_id: &str,
        offer: &RelayPaymentOffer,
    ) -> Result<String, WalletError> {
        let channels = self
            .channels
            .lock()
            .map_err(|_| WalletError::Backend("channels mutex poisoned".to_string()))?;
        let metadata = channels.get(channel_id).ok_or(WalletError::NotFound)?;
        if metadata.state != WalletChannelState::Open {
            return Err(WalletError::NotOpen);
        }
        if metadata.attached_session_id.is_none() {
            return Err(WalletError::Backend(
                "channel must be attached before linking".to_string(),
            ));
        }
        Self::ensure_matches_offer(metadata, offer)?;

        let bridge = self
            .bridge
            .lock()
            .map_err(|_| WalletError::Backend("bridge mutex poisoned".to_string()))?;
        let payment = bridge
            .create_payment_with_funding(channel_id, 0)
            .map_err(|e| WalletError::Backend(format!("failed to create link payment: {e}")))?;
        serde_json::to_string(&payment)
            .map_err(|e| WalletError::Backend(format!("failed to serialize payment: {e}")))
    }

    fn build_channel_payment(
        &self,
        channel_id: &str,
        offer: &RelayPaymentOffer,
        latest_server_balance_raw: u64,
        next_balance_raw: u64,
    ) -> Result<String, WalletError> {
        let mut channels = self
            .channels
            .lock()
            .map_err(|_| WalletError::Backend("channels mutex poisoned".to_string()))?;
        let metadata = channels.get_mut(channel_id).ok_or(WalletError::NotFound)?;
        if metadata.state != WalletChannelState::Open {
            return Err(WalletError::NotOpen);
        }
        if metadata.attached_session_id.is_none() {
            return Err(WalletError::Backend(
                "channel must be attached before payment".to_string(),
            ));
        }
        Self::ensure_matches_offer(metadata, offer)?;

        if next_balance_raw <= latest_server_balance_raw {
            return Err(WalletError::NoNewFunds);
        }
        if next_balance_raw > metadata.capacity_raw {
            let requested_msats = Self::raw_to_msats(&metadata.unit, next_balance_raw)?;
            return Err(WalletError::InsufficientCapacity {
                requested: requested_msats,
                capacity: metadata.capacity_msats,
            });
        }
        if metadata.current_signed_balance_raw > next_balance_raw {
            return Err(WalletError::Backend(
                "wallet local balance exceeds requested next balance".to_string(),
            ));
        }

        let bridge = self
            .bridge
            .lock()
            .map_err(|_| WalletError::Backend("bridge mutex poisoned".to_string()))?;
        let payment = bridge
            .create_payment(channel_id, next_balance_raw)
            .map_err(|e| WalletError::Backend(format!("failed to create payment: {e}")))?;

        metadata.current_signed_balance_raw = next_balance_raw;
        metadata.current_signed_balance_msats =
            Self::raw_to_msats(&metadata.unit, next_balance_raw)?;

        serde_json::to_string(&payment)
            .map_err(|e| WalletError::Backend(format!("failed to serialize payment: {e}")))
    }
}
