use crate::listener::SpilmanMintCache;
use cashu::nuts::{CurrencyUnit, Id, PublicKey, SecretKey};
use cdk_spilman::{
    compute_channel_secret_from_hex, sign_with_tweaked_key_util, BridgeError, ChannelFunding,
    ChannelPolicy, ChannelState, ClosingData, Payment, PaymentProof, SpilmanBridge, SpilmanHost,
};
use std::collections::HashMap;
use std::fmt;
use std::str::FromStr;
use std::sync::{Arc, Mutex};
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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ChannelUnit {
    Sat,
    Msat,
}

impl ChannelUnit {
    fn from_str(value: &str) -> Result<Self, LinkError> {
        match value {
            "sat" => Ok(Self::Sat),
            "msat" => Ok(Self::Msat),
            other => Err(LinkError::UnsupportedUnit(other.to_string())),
        }
    }

    fn from_str_bridge(value: &str) -> Result<Self, BridgeError> {
        match value {
            "sat" => Ok(Self::Sat),
            "msat" => Ok(Self::Msat),
            other => Err(BridgeError::UnsupportedUnit(other.to_string())),
        }
    }

    fn capacity_millisats(self, capacity_raw: u64) -> Result<u64, LinkError> {
        match self {
            Self::Msat => Ok(capacity_raw),
            Self::Sat => capacity_raw
                .checked_mul(1000)
                .ok_or_else(|| LinkError::InvalidChannel("capacity overflow".to_string())),
        }
    }

    fn delta_millisats(self, delta_raw: u64) -> Result<u64, ChannelPaymentError> {
        match self {
            Self::Msat => Ok(delta_raw),
            Self::Sat => delta_raw
                .checked_mul(1000)
                .ok_or_else(|| ChannelPaymentError::Internal("delta overflow".to_string())),
        }
    }
}

#[derive(Debug, Clone, Copy)]
enum PaymentContext {
    Payment,
}

#[derive(Debug, Clone)]
struct StoredChannel {
    funding: ChannelFunding,
    latest_payment: PaymentProof,
    state: ChannelState,
    closing_data: Option<ClosingData>,
    unit: ChannelUnit,
    owner: Option<[u8; 32]>,
}

#[derive(Debug, Default)]
struct StoredState {
    channels: HashMap<String, StoredChannel>,
}

#[derive(Debug, Clone)]
struct MonadHost {
    receiver_secret: SecretKey,
    mint_cache: SpilmanMintCache,
    state: Arc<Mutex<StoredState>>,
}

#[derive(Debug)]
pub struct SpilmanRelayPayments {
    bridge: SpilmanBridge<MonadHost, PaymentContext>,
    state: Arc<Mutex<StoredState>>,
}

impl SpilmanRelayPayments {
    pub fn new(receiver_secret: SecretKey, mint_cache: SpilmanMintCache) -> Self {
        let state = Arc::new(Mutex::new(StoredState::default()));
        let host = MonadHost {
            receiver_secret,
            mint_cache,
            state: state.clone(),
        };
        Self {
            bridge: SpilmanBridge::new(host),
            state,
        }
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

        let mut state = self
            .state
            .lock()
            .map_err(|_| LinkError::Internal("mutex poisoned".to_string()))?;
        let channel = state.channels.get_mut(&payment.channel_id).ok_or_else(|| {
            LinkError::Internal("linked channel missing after validation".to_string())
        })?;

        let evicted_session = match channel.owner {
            Some(owner) if owner != session_id => Some(owner),
            _ => None,
        };
        channel.owner = Some(session_id);

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
            let state = self
                .state
                .lock()
                .map_err(|_| ChannelPaymentError::Internal("mutex poisoned".to_string()))?;
            let channel = state
                .channels
                .get(expected_channel_id)
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
}

impl SpilmanHost<PaymentContext> for MonadHost {
    fn receiver_key_is_acceptable(&self, receiver_pubkey: &PublicKey) -> bool {
        *receiver_pubkey == self.receiver_secret.public_key()
    }

    fn mint_and_keyset_is_acceptable(&self, mint: &str, keyset_id: &Id) -> bool {
        self.mint_cache
            .keyset_info_json_by_mint
            .get(mint)
            .is_some_and(|by_id| by_id.contains_key(&keyset_id.to_string()))
    }

    fn get_funding(&self, channel_id: &str) -> Option<ChannelFunding> {
        self.state.lock().ok().and_then(|state| {
            state
                .channels
                .get(channel_id)
                .map(|channel| channel.funding.clone())
        })
    }

    fn save_funding(
        &self,
        channel_id: &str,
        funding: ChannelFunding,
        initial_payment: PaymentProof,
    ) {
        let metadata = parse_channel_metadata(&funding.params_json)
            .expect("validated channel params must contain supported unit and capacity");
        let mut state = self
            .state
            .lock()
            .expect("state mutex must not be poisoned while saving funding");
        state.channels.insert(
            channel_id.to_string(),
            StoredChannel {
                funding,
                latest_payment: initial_payment,
                state: ChannelState::Open,
                closing_data: None,
                unit: metadata.0,
                owner: None,
            },
        );
    }

    fn get_amount_due(&self, channel_id: &str, _context: Option<&PaymentContext>) -> u64 {
        self.state
            .lock()
            .ok()
            .and_then(|state| {
                state
                    .channels
                    .get(channel_id)
                    .map(|channel| channel.latest_payment.balance)
            })
            .unwrap_or(0)
    }

    fn record_payment(&self, channel_id: &str, payment: PaymentProof, _context: &PaymentContext) {
        if let Ok(mut state) = self.state.lock() {
            if let Some(channel) = state.channels.get_mut(channel_id) {
                channel.latest_payment = payment;
            }
        }
    }

    fn get_channel_state(&self, channel_id: &str) -> ChannelState {
        self.state
            .lock()
            .ok()
            .and_then(|state| state.channels.get(channel_id).map(|channel| channel.state))
            .unwrap_or(ChannelState::Open)
    }

    fn mark_channel_closing(
        &self,
        channel_id: &str,
        expiry_timestamp: u64,
        payment: PaymentProof,
    ) -> Result<(), String> {
        let mut state = self
            .state
            .lock()
            .map_err(|_| "state mutex poisoned".to_string())?;
        let channel = state
            .channels
            .get_mut(channel_id)
            .ok_or_else(|| format!("unknown channel: {channel_id}"))?;
        channel.state = ChannelState::Closing;
        channel.closing_data = Some(ClosingData {
            expiry_timestamp,
            balance: payment.balance,
            signature: payment.signature,
        });
        Ok(())
    }

    fn get_closing_data(&self, channel_id: &str) -> Option<ClosingData> {
        self.state.lock().ok().and_then(|state| {
            state
                .channels
                .get(channel_id)
                .and_then(|channel| channel.closing_data.clone())
        })
    }

    fn get_channel_policy(&self, unit: &str) -> Option<ChannelPolicy> {
        match unit {
            "sat" | "msat" => Some(ChannelPolicy {
                min_expiry_in_seconds: 0,
                min_capacity: 1,
                max_amount_per_output: None,
            }),
            _ => None,
        }
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
        self.state.lock().ok().and_then(|state| {
            state
                .channels
                .get(channel_id)
                .map(|channel| channel.latest_payment.clone())
        })
    }

    fn get_active_keyset_ids(&self, mint: &str, unit: &CurrencyUnit) -> Vec<Id> {
        self.mint_cache
            .advertised
            .get(mint)
            .and_then(|units| units.get(&unit.to_string()))
            .into_iter()
            .flatten()
            .filter_map(|id| Id::from_str(id).ok())
            .collect()
    }

    fn get_keyset_info(&self, mint: &str, keyset_id: &Id) -> Option<String> {
        self.mint_cache
            .keyset_info_json_by_mint
            .get(mint)
            .and_then(|by_id| by_id.get(&keyset_id.to_string()))
            .cloned()
    }

    fn mark_channel_closed(
        &self,
        channel_id: &str,
        _expiry_timestamp: u64,
        _balance: u64,
        _receiver_proofs_json: &str,
        _sender_proofs_json: &str,
        _receiver_sum: u64,
        _sender_sum: u64,
    ) -> Result<(), String> {
        let mut state = self
            .state
            .lock()
            .map_err(|_| "state mutex poisoned".to_string())?;
        let channel = state
            .channels
            .get_mut(channel_id)
            .ok_or_else(|| format!("unknown channel: {channel_id}"))?;
        channel.state = ChannelState::Closed;
        channel.closing_data = None;
        Ok(())
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

fn parse_channel_metadata(params_json: &str) -> Result<(ChannelUnit, u64), BridgeError> {
    let params: serde_json::Value =
        serde_json::from_str(params_json).map_err(|e| BridgeError::Internal(e.to_string()))?;
    let unit = params["unit"]
        .as_str()
        .ok_or_else(|| BridgeError::Internal("missing unit in stored params".to_string()))?;
    let capacity = params["capacity"]
        .as_u64()
        .ok_or_else(|| BridgeError::Internal("missing capacity in stored params".to_string()))?;
    Ok((ChannelUnit::from_str_bridge(unit)?, capacity))
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

pub mod testing {
    use super::{
        ChannelPaymentError, ChannelUnit, LinkError, LinkOutcome, PaymentOutcome, RelayPayments,
    };
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
    }

    #[derive(Debug)]
    struct ParsedPayment {
        channel_id: String,
        balance: u64,
        capacity: Option<u64>,
        unit: Option<String>,
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
