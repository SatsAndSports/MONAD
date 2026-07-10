use crate::channel_store::ChannelStore;
use crate::listener::{
    shared_spilman_mint_cache, SharedSpilmanMintCache, SpilmanMintCache, TrustedMintUnits,
};
use cashu::nuts::{CurrencyUnit, Id, PublicKey, SecretKey};
use cdk_spilman::{
    compute_channel_secret_from_hex,
    configurable_host::{ClosedDataView, SpilmanStorage},
    sign_with_tweaked_key_util, BridgeError, ChannelFunding, ChannelPolicy, ChannelState,
    CloseError, CloseSuccess, ClosingData, Payment, PaymentProof, SpilmanAsyncKeysetRefresher,
    SpilmanAsyncMintClient, SpilmanBridge, SpilmanHost, SpilmanKeysetRefresher, SpilmanMintClient,
};
use monad_common::config::RelayChannelPolicyConfig;
use monad_common::protocol::{LinkedChannelStatus, ServerErrorCode};
use std::collections::BTreeSet;
use std::fmt;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

pub trait RelayPayments: Send + Sync + 'static {
    fn link_channel(
        &self,
        session_id: [u8; 32],
        payment_json: &str,
    ) -> Result<LinkOutcome, LinkError>;

    fn apply_channel_payment(
        &self,
        expected_channel_id: &str,
        payment_json: &str,
    ) -> Result<PaymentOutcome, ChannelPaymentError>;

    fn linked_channel_status(&self, channel_id: &str) -> Option<LinkedChannelStatus>;

    fn release_channel_ownership(&self, session_id: [u8; 32], channel_id: &str);

    fn channel_state(&self, channel_id: &str) -> Option<ChannelState>;
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LinkOutcome {
    pub channel_id: String,
    pub capacity_millisats: u64,
    pub evicted_session: Option<[u8; 32]>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PaymentOutcome {
    pub channel_id: String,
    pub delta_millisats: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LinkError {
    InvalidPayment(String),
    InvalidChannel(String),
    MintOrKeysetNotAcceptable,
    UnsupportedCashuSpilmanProtocolVersion,
    ReceiverKeyMismatch,
    UnsupportedUnit(String),
    NonZeroLinkBalance,
    ChannelExpired,
    ChannelClosed,
    Internal(String),
}

impl fmt::Display for LinkError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidPayment(s) => write!(f, "invalid payment: {s}"),
            Self::InvalidChannel(s) => write!(f, "invalid channel: {s}"),
            Self::MintOrKeysetNotAcceptable => write!(f, "mint or keyset not acceptable"),
            Self::UnsupportedCashuSpilmanProtocolVersion => {
                write!(f, "unsupported cashu spilman protocol version")
            }
            Self::ReceiverKeyMismatch => write!(f, "receiver key mismatch"),
            Self::UnsupportedUnit(unit) => write!(f, "unsupported unit: {unit}"),
            Self::NonZeroLinkBalance => write!(f, "link balance must be zero"),
            Self::ChannelExpired => write!(f, "channel expired"),
            Self::ChannelClosed => write!(f, "channel closed"),
            Self::Internal(s) => write!(f, "internal error: {s}"),
        }
    }
}

impl std::error::Error for LinkError {}

impl LinkError {
    pub(crate) fn code(&self) -> ServerErrorCode {
        match self {
            Self::InvalidPayment(_) => ServerErrorCode::LinkInvalidPayment,
            Self::InvalidChannel(_) => ServerErrorCode::LinkInvalidChannel,
            Self::MintOrKeysetNotAcceptable => ServerErrorCode::LinkMintOrKeysetUnacceptable,
            Self::UnsupportedCashuSpilmanProtocolVersion => {
                ServerErrorCode::LinkUnsupportedCashuSpilmanProtocolVersion
            }
            Self::ReceiverKeyMismatch => ServerErrorCode::LinkReceiverMismatch,
            Self::UnsupportedUnit(_) => ServerErrorCode::LinkUnsupportedUnit,
            Self::NonZeroLinkBalance => ServerErrorCode::LinkNonZeroBalance,
            Self::ChannelExpired => ServerErrorCode::ChannelExpired,
            Self::ChannelClosed => ServerErrorCode::ChannelClosed,
            Self::Internal(_) => ServerErrorCode::InternalError,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ChannelPaymentError {
    WrongChannel,
    UnknownChannel,
    InvalidPayment(String),
    NoNewFunds,
    ChannelClosed,
    Internal(String),
}

impl fmt::Display for ChannelPaymentError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::WrongChannel => write!(f, "wrong channel"),
            Self::UnknownChannel => write!(f, "unknown channel"),
            Self::InvalidPayment(s) => write!(f, "invalid payment: {s}"),
            Self::NoNewFunds => write!(f, "no new funds"),
            Self::ChannelClosed => write!(f, "channel closed"),
            Self::Internal(s) => write!(f, "internal error: {s}"),
        }
    }
}

impl std::error::Error for ChannelPaymentError {}

impl ChannelPaymentError {
    pub(crate) fn code(&self) -> ServerErrorCode {
        match self {
            Self::WrongChannel => ServerErrorCode::PaymentWrongChannel,
            Self::UnknownChannel => ServerErrorCode::PaymentUnknownChannel,
            Self::InvalidPayment(_) => ServerErrorCode::PaymentInvalid,
            Self::NoNewFunds => ServerErrorCode::PaymentNoNewFunds,
            Self::ChannelClosed => ServerErrorCode::ChannelClosed,
            Self::Internal(_) => ServerErrorCode::InternalError,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ChannelUnit {
    Sat,
    Msat,
}

impl ChannelUnit {
    pub(crate) fn from_str(value: &str) -> Result<Self, LinkError> {
        match value {
            "sat" => Ok(Self::Sat),
            "msat" => Ok(Self::Msat),
            other => Err(LinkError::UnsupportedUnit(other.to_string())),
        }
    }

    pub(crate) fn capacity_millisats(self, capacity_raw: u64) -> Result<u64, LinkError> {
        match self {
            Self::Msat => Ok(capacity_raw),
            Self::Sat => capacity_raw
                .checked_mul(1000)
                .ok_or_else(|| LinkError::InvalidChannel("capacity overflow".to_string())),
        }
    }

    pub(crate) fn delta_millisats(self, delta_raw: u64) -> Result<u64, ChannelPaymentError> {
        match self {
            Self::Msat => Ok(delta_raw),
            Self::Sat => delta_raw
                .checked_mul(1000)
                .ok_or_else(|| ChannelPaymentError::Internal("delta overflow".to_string())),
        }
    }

    pub(crate) fn as_str(self) -> &'static str {
        match self {
            Self::Sat => "sat",
            Self::Msat => "msat",
        }
    }
}

#[derive(Debug, Clone, Copy)]
enum PaymentContext {
    Payment,
}

#[derive(Debug, Clone)]
struct MonadHost {
    receiver_secret: SecretKey,
    mint_cache: SharedSpilmanMintCache,
    trusted_mint_units: TrustedMintUnits,
    channel_policy: RelayChannelPolicyConfig,
    store: ChannelStore,
}

#[derive(Debug)]
pub struct SpilmanRelayPayments {
    bridge: SpilmanBridge<MonadHost, PaymentContext>,
    store: ChannelStore,
}

impl SpilmanRelayPayments {
    pub fn new(
        receiver_secret: SecretKey,
        mint_cache: SpilmanMintCache,
        trusted_mint_units: TrustedMintUnits,
        storage: Arc<dyn SpilmanStorage>,
    ) -> Self {
        Self::from_store(
            receiver_secret,
            shared_spilman_mint_cache(mint_cache),
            trusted_mint_units,
            RelayChannelPolicyConfig::default(),
            ChannelStore::new(storage),
        )
    }

    pub(crate) fn from_store(
        receiver_secret: SecretKey,
        mint_cache: SharedSpilmanMintCache,
        trusted_mint_units: TrustedMintUnits,
        channel_policy: RelayChannelPolicyConfig,
        store: ChannelStore,
    ) -> Self {
        let host = MonadHost {
            receiver_secret,
            mint_cache,
            trusted_mint_units,
            channel_policy,
            store: store.clone(),
        };
        Self {
            bridge: SpilmanBridge::new(host),
            store,
        }
    }

    pub(crate) fn from_store_with_snapshot(
        receiver_secret: SecretKey,
        mint_cache: SpilmanMintCache,
        trusted_mint_units: TrustedMintUnits,
        channel_policy: RelayChannelPolicyConfig,
        store: ChannelStore,
    ) -> Self {
        Self::from_store(
            receiver_secret,
            shared_spilman_mint_cache(mint_cache),
            trusted_mint_units,
            channel_policy,
            store,
        )
    }

    pub fn close_channel<M: SpilmanMintClient, R: SpilmanKeysetRefresher>(
        &self,
        channel_id: &str,
        mint_client: &M,
        keyset_refresher: &R,
    ) -> Result<CloseSuccess, CloseError> {
        self.bridge
            .execute_unilateral_close(channel_id, mint_client, keyset_refresher)
    }

    pub async fn close_channel_async<M: SpilmanAsyncMintClient, R: SpilmanAsyncKeysetRefresher>(
        &self,
        channel_id: &str,
        mint_client: &M,
        keyset_refresher: &R,
    ) -> Result<CloseSuccess, CloseError> {
        self.bridge
            .execute_unilateral_close_async(channel_id, mint_client, keyset_refresher)
            .await
    }

    /// Close a channel regardless of whether it is currently Open or Closing.
    /// Already-closed channels return a synthetic [`CloseSuccess`] with
    /// `already_closed: true`.
    pub async fn close_channel_any_state_async<
        M: SpilmanAsyncMintClient,
        R: SpilmanAsyncKeysetRefresher,
    >(
        &self,
        channel_id: &str,
        mint_client: &M,
        keyset_refresher: &R,
    ) -> Result<CloseSuccess, CloseError> {
        match self.store.channel_state(channel_id) {
            Some(ChannelState::Closed) => {
                let data = self.store.closed_data(channel_id).ok_or_else(|| {
                    CloseError::ValidationFailed {
                        reason: format!(
                            "channel {channel_id} is closed but closed data is missing"
                        ),
                        status: 500,
                        expected_balance: None,
                        actual_balance: None,
                    }
                })?;
                let total_value = data.receiver_sum + data.sender_sum;
                Ok(CloseSuccess {
                    channel_id: channel_id.to_string(),
                    total_value,
                    receiver_sum: data.receiver_sum,
                    sender_sum: data.sender_sum,
                    sender_proofs: data.sender_proofs_json,
                    already_closed: true,
                })
            }
            Some(ChannelState::Closing) => {
                self.bridge
                    .execute_close_for_closing_channel_async(
                        channel_id,
                        mint_client,
                        keyset_refresher,
                    )
                    .await
            }
            _ => {
                self.bridge
                    .execute_unilateral_close_async(channel_id, mint_client, keyset_refresher)
                    .await
            }
        }
    }

    /// Test/observability accessor for the stored closed-channel data.
    pub fn closed_data(&self, channel_id: &str) -> Option<ClosedDataView> {
        self.store.closed_data(channel_id)
    }
}

impl RelayPayments for SpilmanRelayPayments {
    fn link_channel(
        &self,
        session_id: [u8; 32],
        payment_json: &str,
    ) -> Result<LinkOutcome, LinkError> {
        let payment: Payment = serde_json::from_str(payment_json)
            .map_err(|e| LinkError::InvalidPayment(e.to_string()))?;
        if payment.balance != 0 {
            return Err(LinkError::NonZeroLinkBalance);
        }

        let result = self
            .bridge
            .fund_channel_via_json(payment_json)
            .map_err(map_link_bridge_error)?;

        let evicted_session = self
            .store
            .set_channel_owner(&payment.channel_id, session_id)
            .map_err(LinkError::Internal)?;

        let channel = self
            .store
            .get_channel(&payment.channel_id)
            .map_err(LinkError::Internal)?
            .ok_or_else(|| {
                LinkError::Internal("linked channel missing after validation".to_string())
            })?;

        Ok(LinkOutcome {
            channel_id: payment.channel_id,
            capacity_millisats: channel.unit.capacity_millisats(result.capacity)?,
            evicted_session,
        })
    }

    fn apply_channel_payment(
        &self,
        expected_channel_id: &str,
        payment_json: &str,
    ) -> Result<PaymentOutcome, ChannelPaymentError> {
        let payment: Payment = serde_json::from_str(payment_json)
            .map_err(|e| ChannelPaymentError::InvalidPayment(e.to_string()))?;
        if payment.channel_id != expected_channel_id {
            return Err(ChannelPaymentError::WrongChannel);
        }
        if payment.params.is_some() || payment.funding_proofs.is_some() {
            return Err(ChannelPaymentError::InvalidPayment(
                "channel payment must not include funding".to_string(),
            ));
        }

        let (previous_balance, unit, state_kind) = {
            let channel = self
                .store
                .get_channel(expected_channel_id)
                .map_err(ChannelPaymentError::Internal)?
                .ok_or(ChannelPaymentError::UnknownChannel)?;
            (channel.latest_payment.balance, channel.unit, channel.state)
        };

        if state_kind != ChannelState::Open {
            return Err(ChannelPaymentError::ChannelClosed);
        }

        let validation = self
            .bridge
            .validate_payment_via_json(payment_json, &PaymentContext::Payment)
            .map_err(map_payment_bridge_error)?;

        if validation.balance <= previous_balance {
            return Err(ChannelPaymentError::NoNewFunds);
        }

        self.bridge
            .process_payment_via_json(payment_json, &PaymentContext::Payment)
            .map_err(map_payment_bridge_error)?;

        let delta_raw = validation.balance - previous_balance;
        Ok(PaymentOutcome {
            channel_id: payment.channel_id,
            delta_millisats: unit.delta_millisats(delta_raw)?,
        })
    }

    fn linked_channel_status(&self, channel_id: &str) -> Option<LinkedChannelStatus> {
        self.store.linked_channel_status(channel_id)
    }

    fn release_channel_ownership(&self, session_id: [u8; 32], channel_id: &str) {
        let _ = self.store.release_channel_owner(channel_id, session_id);
    }

    fn channel_state(&self, channel_id: &str) -> Option<ChannelState> {
        self.store.channel_state(channel_id)
    }
}

impl SpilmanHost<PaymentContext> for MonadHost {
    fn receiver_key_is_acceptable(&self, receiver_pubkey: &PublicKey) -> bool {
        *receiver_pubkey == self.receiver_secret.public_key()
    }

    fn mint_and_keyset_is_acceptable(&self, mint: &str, keyset_id: &Id) -> bool {
        let trusted_units = self
            .trusted_mint_units
            .get(mint)
            .cloned()
            .unwrap_or_else(BTreeSet::new);
        self.mint_cache
            .read()
            .expect("spilman mint cache lock poisoned")
            .is_acceptable(mint, keyset_id, &trusted_units)
    }

    fn get_funding(&self, channel_id: &str) -> Option<ChannelFunding> {
        self.store
            .get_channel(channel_id)
            .ok()
            .flatten()
            .map(|channel| channel.funding.clone())
    }

    fn save_funding(
        &self,
        channel_id: &str,
        funding: ChannelFunding,
        initial_payment: PaymentProof,
    ) {
        self.store
            .save_funding(channel_id, funding, initial_payment)
            .expect("validated channel funding must be persistable");
    }

    fn get_amount_due(&self, channel_id: &str, _context: Option<&PaymentContext>) -> u64 {
        self.store
            .get_channel(channel_id)
            .ok()
            .flatten()
            .map(|channel| channel.latest_payment.balance)
            .unwrap_or(0)
    }

    fn record_payment(&self, channel_id: &str, payment: PaymentProof, _context: &PaymentContext) {
        let _ = self.store.record_payment(channel_id, payment);
    }

    fn get_channel_state(&self, channel_id: &str) -> ChannelState {
        self.store
            .get_channel(channel_id)
            .ok()
            .flatten()
            .map(|channel| channel.state)
            .unwrap_or(ChannelState::Open)
    }

    fn mark_channel_closing(
        &self,
        channel_id: &str,
        expiry_timestamp: u64,
        payment: PaymentProof,
    ) -> Result<(), String> {
        self.store
            .mark_channel_closing(channel_id, expiry_timestamp, payment)
    }

    fn get_closing_data(&self, channel_id: &str) -> Option<ClosingData> {
        self.store
            .get_channel(channel_id)
            .ok()
            .flatten()
            .and_then(|channel| channel.closing_data.clone())
    }

    fn get_channel_policy(&self, unit: &str) -> Option<ChannelPolicy> {
        relay_channel_policy_for_unit(&self.channel_policy, unit)
    }

    fn now_seconds(&self) -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0)
    }

    fn get_balance_and_signature_for_unilateral_exit(
        &self,
        channel_id: &str,
    ) -> Option<PaymentProof> {
        self.store
            .get_channel(channel_id)
            .ok()
            .flatten()
            .map(|channel| channel.latest_payment.clone())
    }

    fn get_active_keyset_ids(&self, mint: &str, unit: &CurrencyUnit) -> Vec<Id> {
        // Upstream calls this hook to choose an output keyset for swaps.
        // Output keyset choice only needs the mint's current active keyset for
        // the channel unit; relay advertisement/acceptance policy is separate.
        self.mint_cache
            .read()
            .expect("spilman mint cache lock poisoned")
            .active_keyset_ids(mint, &unit.to_string())
    }

    fn has_keysets_for_unit(&self, mint: &str, unit: &CurrencyUnit) -> bool {
        let unit = unit.to_string();
        self.mint_cache
            .read()
            .expect("spilman mint cache lock poisoned")
            .keysets
            .get(mint)
            .is_some_and(|by_id| by_id.values().any(|keyset| keyset.unit == unit))
    }

    fn get_keyset_info(&self, mint: &str, keyset_id: &Id) -> Option<String> {
        self.mint_cache
            .read()
            .expect("spilman mint cache lock poisoned")
            .keyset_info_json(mint, keyset_id)
    }

    fn mark_channel_closed(
        &self,
        channel_id: &str,
        expiry_timestamp: u64,
        balance: u64,
        receiver_proofs_json: &str,
        sender_proofs_json: &str,
        receiver_sum: u64,
        sender_sum: u64,
    ) -> Result<(), String> {
        self.store.mark_channel_closed(
            channel_id,
            ClosedDataView {
                expiry_timestamp,
                closed_amount: balance,
                value_after_stage1: receiver_sum + sender_sum,
                receiver_sum,
                sender_sum,
                receiver_proofs_json: receiver_proofs_json.to_string(),
                sender_proofs_json: sender_proofs_json.to_string(),
            },
        )
    }

    fn compute_channel_secret(
        &self,
        receiver_pubkey_hex: &str,
        sender_pubkey_hex: &str,
    ) -> Result<String, String> {
        let expected = self.receiver_secret.public_key().to_hex();
        if receiver_pubkey_hex != expected {
            return Err(format!(
                "Receiver pubkey mismatch: expected {expected}, got {receiver_pubkey_hex}"
            ));
        }

        compute_channel_secret_from_hex(&self.receiver_secret.to_secret_hex(), sender_pubkey_hex)
    }

    fn sign_with_tweaked_key(
        &self,
        signer_pubkey_hex: &str,
        message_hex: &str,
        tweak_scalar_hex: &str,
    ) -> Result<String, String> {
        let expected = self.receiver_secret.public_key().to_hex();
        if signer_pubkey_hex != expected {
            return Err(format!(
                "Signer pubkey mismatch: expected {expected}, got {signer_pubkey_hex}"
            ));
        }

        sign_with_tweaked_key_util(
            &self.receiver_secret.to_secret_hex(),
            message_hex,
            tweak_scalar_hex,
        )
    }
}

fn relay_channel_policy_for_unit(
    config: &RelayChannelPolicyConfig,
    unit: &str,
) -> Option<ChannelPolicy> {
    match unit {
        "sat" | "msat" => Some(ChannelPolicy {
            min_expiry_in_seconds: config.min_expiry_secs,
            min_capacity: amount_msats_to_raw_ceil(config.min_capacity_msats, unit)?,
            max_amount_per_output: match config.max_amount_per_output_msats {
                Some(amount) => Some(amount_msats_to_raw_ceil(amount, unit)?),
                None => None,
            },
        }),
        _ => None,
    }
}

fn amount_msats_to_raw_ceil(amount_msats: u64, unit: &str) -> Option<u64> {
    match unit {
        "msat" => Some(amount_msats),
        "sat" => Some(amount_msats.div_ceil(1_000)),
        _ => None,
    }
}

fn map_link_bridge_error(err: BridgeError) -> LinkError {
    match err {
        BridgeError::InvalidRequest(s)
        | BridgeError::ValidationFailed(s)
        | BridgeError::InvalidSignature(s)
        | BridgeError::ServerMisconfigured(s)
        | BridgeError::Internal(s) => LinkError::InvalidPayment(s),
        BridgeError::ChannelClosing => LinkError::InvalidPayment(err.to_string()),
        BridgeError::CapacityTooSmall { .. }
        | BridgeError::MaxAmountExceeded { .. }
        | BridgeError::BalanceExceedsCapacity { .. }
        | BridgeError::ChannelIdMismatch => LinkError::InvalidChannel(err.to_string()),
        BridgeError::UnsupportedUnit(unit) => LinkError::UnsupportedUnit(unit),
        BridgeError::ReceiverKeyNotAcceptable => LinkError::ReceiverKeyMismatch,
        BridgeError::MintOrKeysetNotAcceptable => LinkError::MintOrKeysetNotAcceptable,
        BridgeError::ExpiryTooSoon { .. } => LinkError::ChannelExpired,
        BridgeError::ChannelClosed => LinkError::ChannelClosed,
        BridgeError::UnknownChannel => LinkError::InvalidPayment(err.to_string()),
        BridgeError::InsufficientBalance { .. } => LinkError::InvalidPayment(err.to_string()),
        BridgeError::BalanceMismatch { .. } => LinkError::InvalidPayment(err.to_string()),
    }
}

fn map_payment_bridge_error(err: BridgeError) -> ChannelPaymentError {
    match err {
        BridgeError::ChannelClosed | BridgeError::ChannelClosing => {
            ChannelPaymentError::ChannelClosed
        }
        BridgeError::UnknownChannel => ChannelPaymentError::UnknownChannel,
        BridgeError::InsufficientBalance {
            balance,
            amount_due,
        } if balance == amount_due => ChannelPaymentError::NoNewFunds,
        BridgeError::InvalidRequest(s)
        | BridgeError::ValidationFailed(s)
        | BridgeError::InvalidSignature(s)
        | BridgeError::UnsupportedUnit(s)
        | BridgeError::ServerMisconfigured(s)
        | BridgeError::Internal(s) => ChannelPaymentError::InvalidPayment(s),
        BridgeError::CapacityTooSmall { .. }
        | BridgeError::ExpiryTooSoon { .. }
        | BridgeError::MaxAmountExceeded { .. }
        | BridgeError::BalanceExceedsCapacity { .. }
        | BridgeError::ReceiverKeyNotAcceptable
        | BridgeError::MintOrKeysetNotAcceptable
        | BridgeError::ChannelIdMismatch
        | BridgeError::InsufficientBalance { .. }
        | BridgeError::BalanceMismatch { .. } => {
            ChannelPaymentError::InvalidPayment(err.to_string())
        }
    }
}

#[cfg(test)]
mod channel_policy_tests {
    use super::relay_channel_policy_for_unit;
    use monad_common::config::RelayChannelPolicyConfig;

    #[test]
    fn min_capacity_msats_converts_to_unit_raw_amounts() {
        let config = RelayChannelPolicyConfig {
            min_capacity_msats: 1_500,
            ..RelayChannelPolicyConfig::default()
        };

        let sat = relay_channel_policy_for_unit(&config, "sat").unwrap();
        let msat = relay_channel_policy_for_unit(&config, "msat").unwrap();
        assert_eq!(sat.min_capacity, 2);
        assert_eq!(msat.min_capacity, 1_500);
    }

    #[test]
    fn sat_amounts_convert_to_msat_and_sat_policies() {
        let config = RelayChannelPolicyConfig {
            min_capacity_msats: 2_000,
            max_amount_per_output_msats: Some(1_500),
            ..RelayChannelPolicyConfig::default()
        };

        let sat = relay_channel_policy_for_unit(&config, "sat").unwrap();
        let msat = relay_channel_policy_for_unit(&config, "msat").unwrap();
        assert_eq!(sat.min_capacity, 2);
        assert_eq!(msat.min_capacity, 2_000);
        assert_eq!(sat.max_amount_per_output, Some(2));
        assert_eq!(msat.max_amount_per_output, Some(1_500));
    }

    #[test]
    fn unknown_units_do_not_get_channel_policy() {
        let config = RelayChannelPolicyConfig::default();
        assert!(relay_channel_policy_for_unit(&config, "usd").is_none());
    }
}

pub mod testing {
    use super::{
        ChannelPaymentError, ChannelUnit, LinkError, LinkOutcome, PaymentOutcome, RelayPayments,
    };
    use cdk_spilman::{ChannelState, CloseError, CloseSuccess};
    use monad_common::protocol::LinkedChannelStatus;
    use serde_json::Value;
    use std::collections::HashMap;
    use std::sync::Mutex;

    #[derive(Debug, Clone)]
    struct ChannelRecord {
        capacity_raw: u64,
        unit: ChannelUnit,
        latest_balance: u64,
        closed: bool,
        owner: Option<[u8; 32]>,
    }

    #[derive(Debug, Default)]
    struct Inner {
        channels: HashMap<String, ChannelRecord>,
    }

    #[derive(Debug, Default)]
    pub struct InMemoryRelayPayments {
        inner: Mutex<Inner>,
    }

    impl InMemoryRelayPayments {
        pub fn new() -> Self {
            Self::default()
        }

        pub fn owner_of(&self, channel_id: &str) -> Option<[u8; 32]> {
            let inner = self.inner.lock().ok()?;
            inner
                .channels
                .get(channel_id)
                .and_then(|record| record.owner)
        }

        pub fn mark_closed(&self, channel_id: &str) -> bool {
            match self.inner.lock() {
                Ok(mut inner) => {
                    if let Some(record) = inner.channels.get_mut(channel_id) {
                        record.closed = true;
                        true
                    } else {
                        false
                    }
                }
                Err(_) => false,
            }
        }

        pub fn close_channel(&self, channel_id: &str) -> Result<CloseSuccess, CloseError> {
            let mut inner = self.inner.lock().map_err(|_| CloseError::StorageFailed {
                reason: "mutex poisoned".to_string(),
                status: 500,
            })?;
            let record =
                inner
                    .channels
                    .get_mut(channel_id)
                    .ok_or_else(|| CloseError::ValidationFailed {
                        reason: "unknown channel".to_string(),
                        status: 400,
                        expected_balance: None,
                        actual_balance: None,
                    })?;
            if record.closed {
                return Ok(CloseSuccess {
                    channel_id: channel_id.to_string(),
                    total_value: record.capacity_raw,
                    receiver_sum: record.latest_balance,
                    sender_sum: record.capacity_raw.saturating_sub(record.latest_balance),
                    sender_proofs: "[]".to_string(),
                    already_closed: true,
                });
            }
            record.closed = true;
            Ok(CloseSuccess {
                channel_id: channel_id.to_string(),
                total_value: record.capacity_raw,
                receiver_sum: record.latest_balance,
                sender_sum: record.capacity_raw.saturating_sub(record.latest_balance),
                sender_proofs: "[]".to_string(),
                already_closed: false,
            })
        }
    }

    #[derive(Debug)]
    struct ParsedPayment {
        channel_id: String,
        balance: u64,
        capacity: Option<u64>,
        unit: Option<String>,
        has_funding: bool,
        closed: bool,
        invalid: bool,
        wrong_receiver: bool,
    }

    impl ParsedPayment {
        fn parse(payment_json: &str) -> Result<Self, String> {
            let value: Value =
                serde_json::from_str(payment_json).map_err(|e| format!("invalid json: {e}"))?;
            let obj = value
                .as_object()
                .ok_or_else(|| "payment must be a JSON object".to_string())?;

            let channel_id = obj
                .get("channel_id")
                .and_then(Value::as_str)
                .ok_or_else(|| "missing channel_id".to_string())?
                .to_string();
            let balance = obj
                .get("balance")
                .and_then(Value::as_u64)
                .ok_or_else(|| "missing balance".to_string())?;
            let capacity = obj.get("capacity").and_then(Value::as_u64);
            let unit = obj
                .get("unit")
                .and_then(Value::as_str)
                .map(ToString::to_string);
            let has_funding = obj.contains_key("params") || obj.contains_key("funding_proofs");
            let closed = obj.get("closed").and_then(Value::as_bool).unwrap_or(false);
            let invalid = obj.get("invalid").and_then(Value::as_bool).unwrap_or(false);
            let wrong_receiver = obj
                .get("wrong_receiver")
                .and_then(Value::as_bool)
                .unwrap_or(false);

            Ok(Self {
                channel_id,
                balance,
                capacity,
                unit,
                has_funding,
                closed,
                invalid,
                wrong_receiver,
            })
        }
    }

    impl RelayPayments for InMemoryRelayPayments {
        fn link_channel(
            &self,
            session_id: [u8; 32],
            payment_json: &str,
        ) -> Result<LinkOutcome, LinkError> {
            let parsed = ParsedPayment::parse(payment_json).map_err(LinkError::InvalidPayment)?;
            if parsed.invalid {
                return Err(LinkError::InvalidPayment(
                    "forced invalid payment".to_string(),
                ));
            }
            if parsed.wrong_receiver {
                return Err(LinkError::ReceiverKeyMismatch);
            }
            if parsed.balance != 0 {
                return Err(LinkError::NonZeroLinkBalance);
            }

            let mut inner = self
                .inner
                .lock()
                .map_err(|_| LinkError::Internal("mutex poisoned".to_string()))?;

            if let Some(record) = inner.channels.get_mut(&parsed.channel_id) {
                if parsed.closed || record.closed {
                    return Err(LinkError::ChannelClosed);
                }

                let evicted_session = match record.owner {
                    Some(owner) if owner != session_id => Some(owner),
                    _ => None,
                };
                record.owner = Some(session_id);

                return Ok(LinkOutcome {
                    channel_id: parsed.channel_id,
                    capacity_millisats: record.unit.capacity_millisats(record.capacity_raw)?,
                    evicted_session,
                });
            }

            if parsed.closed {
                return Err(LinkError::ChannelClosed);
            }

            let capacity_raw = parsed
                .capacity
                .ok_or_else(|| LinkError::InvalidPayment("missing capacity".to_string()))?;
            let unit_str = parsed
                .unit
                .as_deref()
                .ok_or_else(|| LinkError::InvalidPayment("missing unit".to_string()))?;
            let unit = ChannelUnit::from_str(unit_str)?;
            let capacity_millisats = unit.capacity_millisats(capacity_raw)?;

            inner.channels.insert(
                parsed.channel_id.clone(),
                ChannelRecord {
                    capacity_raw,
                    unit,
                    latest_balance: 0,
                    closed: false,
                    owner: Some(session_id),
                },
            );

            Ok(LinkOutcome {
                channel_id: parsed.channel_id,
                capacity_millisats,
                evicted_session: None,
            })
        }

        fn apply_channel_payment(
            &self,
            expected_channel_id: &str,
            payment_json: &str,
        ) -> Result<PaymentOutcome, ChannelPaymentError> {
            let parsed =
                ParsedPayment::parse(payment_json).map_err(ChannelPaymentError::InvalidPayment)?;
            if parsed.invalid {
                return Err(ChannelPaymentError::InvalidPayment(
                    "forced invalid payment".to_string(),
                ));
            }
            if parsed.channel_id != expected_channel_id {
                return Err(ChannelPaymentError::WrongChannel);
            }
            if parsed.has_funding {
                return Err(ChannelPaymentError::InvalidPayment(
                    "channel payment must not include funding".to_string(),
                ));
            }

            let mut inner = self
                .inner
                .lock()
                .map_err(|_| ChannelPaymentError::Internal("mutex poisoned".to_string()))?;
            let record = inner
                .channels
                .get_mut(expected_channel_id)
                .ok_or(ChannelPaymentError::UnknownChannel)?;

            if parsed.closed || record.closed {
                return Err(ChannelPaymentError::ChannelClosed);
            }
            if parsed.wrong_receiver {
                return Err(ChannelPaymentError::InvalidPayment(
                    "wrong receiver".to_string(),
                ));
            }
            if parsed.balance <= record.latest_balance {
                return Err(ChannelPaymentError::NoNewFunds);
            }

            let delta_raw = parsed.balance - record.latest_balance;
            let delta_millisats = record.unit.delta_millisats(delta_raw)?;
            record.latest_balance = parsed.balance;

            Ok(PaymentOutcome {
                channel_id: parsed.channel_id,
                delta_millisats,
            })
        }

        fn linked_channel_status(&self, channel_id: &str) -> Option<LinkedChannelStatus> {
            let inner = self.inner.lock().ok()?;
            let record = inner.channels.get(channel_id)?;
            Some(LinkedChannelStatus {
                channel_id: channel_id.to_string(),
                balance_raw: record.latest_balance,
                capacity_raw: record.capacity_raw,
                unit: record.unit.as_str().to_string(),
            })
        }

        fn release_channel_ownership(&self, session_id: [u8; 32], channel_id: &str) {
            if let Ok(mut inner) = self.inner.lock() {
                if let Some(record) = inner.channels.get_mut(channel_id) {
                    if record.owner == Some(session_id) {
                        record.owner = None;
                    }
                }
            }
        }

        fn channel_state(&self, channel_id: &str) -> Option<ChannelState> {
            let inner = self.inner.lock().ok()?;
            let record = inner.channels.get(channel_id)?;
            Some(if record.closed {
                ChannelState::Closed
            } else {
                ChannelState::Open
            })
        }
    }

    #[cfg(test)]
    mod tests {
        use super::InMemoryRelayPayments;
        use crate::payments::{ChannelPaymentError, LinkError, RelayPayments};

        fn payment_json(
            channel_id: &str,
            balance: u64,
            capacity: Option<u64>,
            unit: Option<&str>,
        ) -> String {
            let mut json = serde_json::json!({
                "channel_id": channel_id,
                "balance": balance,
            });
            if let Some(capacity) = capacity {
                json["capacity"] = serde_json::json!(capacity);
            }
            if let Some(unit) = unit {
                json["unit"] = serde_json::json!(unit);
            }
            serde_json::to_string(&json).unwrap()
        }

        fn payment_json_with_flag(
            channel_id: &str,
            balance: u64,
            capacity: Option<u64>,
            unit: Option<&str>,
            flag: &str,
            value: bool,
        ) -> String {
            let mut value_json: serde_json::Value =
                serde_json::from_str(&payment_json(channel_id, balance, capacity, unit)).unwrap();
            value_json[flag] = serde_json::json!(value);
            serde_json::to_string(&value_json).unwrap()
        }

        fn payment_json_with_params(channel_id: &str, balance: u64) -> String {
            serde_json::json!({
                "channel_id": channel_id,
                "balance": balance,
                "params": { "fake": true },
            })
            .to_string()
        }

        fn session(byte: u8) -> [u8; 32] {
            [byte; 32]
        }

        #[test]
        fn link_new_msat_channel_starts_at_zero_and_reports_msat_capacity() {
            let payments = InMemoryRelayPayments::new();
            let outcome = payments
                .link_channel(
                    session(1),
                    &payment_json("chan", 0, Some(123), Some("msat")),
                )
                .unwrap();

            assert_eq!(outcome.channel_id, "chan");
            assert_eq!(outcome.capacity_millisats, 123);
            assert_eq!(outcome.evicted_session, None);
        }

        #[test]
        fn link_new_sat_channel_reports_millisat_capacity() {
            let payments = InMemoryRelayPayments::new();
            let outcome = payments
                .link_channel(session(1), &payment_json("chan", 0, Some(5), Some("sat")))
                .unwrap();

            assert_eq!(outcome.capacity_millisats, 5_000);
        }

        #[test]
        fn link_rejects_non_zero_balance_without_storing_channel() {
            let payments = InMemoryRelayPayments::new();
            let err = payments
                .link_channel(session(1), &payment_json("chan", 1, Some(5), Some("msat")))
                .unwrap_err();
            assert_eq!(err, LinkError::NonZeroLinkBalance);

            let err = payments
                .apply_channel_payment("chan", &payment_json("chan", 2, None, None))
                .unwrap_err();
            assert_eq!(err, ChannelPaymentError::UnknownChannel);
        }

        #[test]
        fn relink_non_zero_balance_preserves_existing_latest_balance() {
            let payments = InMemoryRelayPayments::new();
            payments
                .link_channel(session(1), &payment_json("chan", 0, Some(10), Some("msat")))
                .unwrap();
            payments
                .apply_channel_payment("chan", &payment_json("chan", 7, None, None))
                .unwrap();

            let err = payments
                .link_channel(session(2), &payment_json("chan", 3, Some(999), Some("sat")))
                .unwrap_err();
            assert_eq!(err, LinkError::NonZeroLinkBalance);

            let outcome = payments
                .link_channel(session(2), &payment_json("chan", 0, Some(999), Some("sat")))
                .unwrap();
            assert_eq!(outcome.evicted_session, Some(session(1)));

            let payment = payments
                .apply_channel_payment("chan", &payment_json("chan", 10, None, None))
                .unwrap();
            assert_eq!(payment.delta_millisats, 3);
        }

        #[test]
        fn relink_same_session_does_not_evict() {
            let payments = InMemoryRelayPayments::new();
            payments
                .link_channel(session(1), &payment_json("chan", 0, Some(10), Some("msat")))
                .unwrap();

            let outcome = payments
                .link_channel(session(1), &payment_json("chan", 0, Some(99), Some("sat")))
                .unwrap();
            assert_eq!(outcome.evicted_session, None);
            assert_eq!(outcome.capacity_millisats, 10);
        }

        #[test]
        fn unsupported_unit_is_rejected() {
            let payments = InMemoryRelayPayments::new();
            let err = payments
                .link_channel(session(1), &payment_json("chan", 0, Some(10), Some("usd")))
                .unwrap_err();
            assert_eq!(err, LinkError::UnsupportedUnit("usd".to_string()));
        }

        #[test]
        fn malformed_payload_is_rejected() {
            let payments = InMemoryRelayPayments::new();
            let err = payments.link_channel(session(1), "[]").unwrap_err();
            assert_eq!(
                err,
                LinkError::InvalidPayment("payment must be a JSON object".to_string())
            );
        }

        #[test]
        fn closed_channel_link_is_rejected() {
            let payments = InMemoryRelayPayments::new();
            let err = payments
                .link_channel(
                    session(1),
                    &payment_json_with_flag("chan", 0, Some(10), Some("msat"), "closed", true),
                )
                .unwrap_err();
            assert_eq!(err, LinkError::ChannelClosed);
        }

        #[test]
        fn payment_wrong_channel_is_rejected() {
            let payments = InMemoryRelayPayments::new();
            payments
                .link_channel(session(1), &payment_json("chan", 0, Some(10), Some("msat")))
                .unwrap();

            let err = payments
                .apply_channel_payment("other", &payment_json("chan", 1, None, None))
                .unwrap_err();
            assert_eq!(err, ChannelPaymentError::WrongChannel);
        }

        #[test]
        fn payment_no_new_funds_is_rejected() {
            let payments = InMemoryRelayPayments::new();
            payments
                .link_channel(session(1), &payment_json("chan", 0, Some(10), Some("msat")))
                .unwrap();
            payments
                .apply_channel_payment("chan", &payment_json("chan", 5, None, None))
                .unwrap();

            let err = payments
                .apply_channel_payment("chan", &payment_json("chan", 5, None, None))
                .unwrap_err();
            assert_eq!(err, ChannelPaymentError::NoNewFunds);
        }

        #[test]
        fn funding_bearing_channel_payment_is_rejected() {
            let payments = InMemoryRelayPayments::new();
            payments
                .link_channel(session(1), &payment_json("chan", 0, Some(10), Some("msat")))
                .unwrap();

            let err = payments
                .apply_channel_payment("chan", &payment_json_with_params("chan", 1))
                .unwrap_err();
            assert_eq!(
                err,
                ChannelPaymentError::InvalidPayment(
                    "channel payment must not include funding".to_string()
                )
            );
        }

        #[test]
        fn msat_payments_credit_raw_delta() {
            let payments = InMemoryRelayPayments::new();
            payments
                .link_channel(
                    session(1),
                    &payment_json("chan", 0, Some(100), Some("msat")),
                )
                .unwrap();

            let first = payments
                .apply_channel_payment("chan", &payment_json("chan", 1, None, None))
                .unwrap();
            let second = payments
                .apply_channel_payment("chan", &payment_json("chan", 5, None, None))
                .unwrap();
            let third = payments
                .apply_channel_payment("chan", &payment_json("chan", 100, None, None))
                .unwrap();

            assert_eq!(first.delta_millisats, 1);
            assert_eq!(second.delta_millisats, 4);
            assert_eq!(third.delta_millisats, 95);
        }

        #[test]
        fn sat_payments_credit_delta_times_one_thousand() {
            let payments = InMemoryRelayPayments::new();
            payments
                .link_channel(session(1), &payment_json("chan", 0, Some(100), Some("sat")))
                .unwrap();

            let first = payments
                .apply_channel_payment("chan", &payment_json("chan", 1, None, None))
                .unwrap();
            let second = payments
                .apply_channel_payment("chan", &payment_json("chan", 5, None, None))
                .unwrap();
            let third = payments
                .apply_channel_payment("chan", &payment_json("chan", 100, None, None))
                .unwrap();

            assert_eq!(first.delta_millisats, 1_000);
            assert_eq!(second.delta_millisats, 4_000);
            assert_eq!(third.delta_millisats, 95_000);
        }

        #[test]
        fn capacity_overflow_is_rejected() {
            let payments = InMemoryRelayPayments::new();
            let err = payments
                .link_channel(
                    session(1),
                    &payment_json("chan", 0, Some(u64::MAX), Some("sat")),
                )
                .unwrap_err();
            assert_eq!(
                err,
                LinkError::InvalidChannel("capacity overflow".to_string())
            );
        }

        #[test]
        fn delta_overflow_is_rejected() {
            let payments = InMemoryRelayPayments::new();
            payments
                .link_channel(
                    session(1),
                    &payment_json("chan", 0, Some(u64::MAX / 1000), Some("sat")),
                )
                .unwrap();
            let err = payments
                .apply_channel_payment("chan", &payment_json("chan", u64::MAX, None, None))
                .unwrap_err();
            assert_eq!(
                err,
                ChannelPaymentError::Internal("delta overflow".to_string())
            );
        }

        #[test]
        fn closed_channel_payment_is_rejected() {
            let payments = InMemoryRelayPayments::new();
            payments
                .link_channel(session(1), &payment_json("chan", 0, Some(10), Some("msat")))
                .unwrap();

            let err = payments
                .apply_channel_payment(
                    "chan",
                    &payment_json_with_flag("chan", 1, None, None, "closed", true),
                )
                .unwrap_err();
            assert_eq!(err, ChannelPaymentError::ChannelClosed);
        }
    }
}
