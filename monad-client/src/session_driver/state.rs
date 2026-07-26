use monad_common::protocol::{KeysetAdvertisement, LinkedChannelStatus};
use monad_common::proxy::CleartextByteCounters;
use monad_common::session::{RelayConnection, SessionPricing, SessionSpilmanInfo};
use std::collections::BTreeSet;
use std::io;
use std::sync::Arc;
use tokio::sync::oneshot;
use tokio::time::Instant;
use tracing::warn;

use crate::session_driver::PaymentPolicy;
use crate::wallet::{MonadWallet, RelayPaymentOffer};

#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct KeysetRefreshHint {
    pub(super) mint_url: String,
    pub(super) unit: String,
    pub(super) accepted_keyset_ids: Vec<String>,
}

impl KeysetRefreshHint {
    pub(super) fn from_offer(offer: &RelayPaymentOffer) -> Self {
        Self {
            mint_url: offer.mint_url.clone(),
            unit: offer.unit.clone(),
            accepted_keyset_ids: offer.accepted_keyset_ids.clone(),
        }
    }
}

#[derive(Clone)]
pub(super) struct SessionDriverConfig {
    pub(super) wallet: Arc<dyn MonadWallet>,
    pub(super) conn: RelayConnectionHandles,
    pub(super) hop_label: String,
    pub(super) payment_policy: PaymentPolicy,
}

#[derive(Clone)]
pub(super) struct RelayConnectionHandles {
    pub(super) session_id: [u8; 32],
    pub(super) pricing_handle: Arc<tokio::sync::RwLock<Option<SessionPricing>>>,
    pub(super) spilman_info_handle: Arc<tokio::sync::RwLock<Option<SessionSpilmanInfo>>>,
    pub(super) cashu_spilman_protocol_version_handle: Arc<tokio::sync::RwLock<Option<String>>>,
    pub(super) cleartext_byte_counters: CleartextByteCounters,
}

impl From<&RelayConnection> for RelayConnectionHandles {
    fn from(conn: &RelayConnection) -> Self {
        Self {
            session_id: *conn.session_id(),
            pricing_handle: conn.session_pricing_handle(),
            spilman_info_handle: conn.session_spilman_info_handle(),
            cashu_spilman_protocol_version_handle: conn.cashu_spilman_protocol_version_handle(),
            cleartext_byte_counters: conn.cleartext_byte_counters(),
        }
    }
}

// Latest control snapshot reported by the relay.
//
// This is relay-reported state, not a blanket trust boundary. The client uses
// some fields here as authoritative coordination state (for example pause state
// and the relay-reported linked channel), but it prioritizes its own local byte
// counters and locally authorized session-paid total when sizing payments.
//
// In particular, the client does not use relay `session_total_in` for payment
// math, because inbound bytes may legitimately be observed by the relay before
// the client has drained them locally. The field is still retained for
// diagnostics and relay-state visibility.
#[derive(Debug, Clone)]
pub(super) struct RelaySnapshot {
    pub(super) receiver_pubkey: String,
    pub(super) advertisements: Vec<KeysetAdvertisement>,
    pub(super) linked_channel: Option<LinkedChannelStatus>,
    pub(super) session_total_in: u64,
    pub(super) session_total_out: u64,
    pub(super) total_paid_millisats: u64,
    pub(super) remaining_milli_sats: i64,
    pub(super) paused: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) enum ControlOpInFlight {
    Link { channel_id: String },
    Payment { channel_id: String },
    RefreshKeysets(KeysetRefreshHint),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) enum FundingBlockedReason {
    ChannelAcquire,
    LinkRequestBuild,
    PaymentRequestBuild,
}

#[derive(Debug, Default)]
pub(super) struct DriverState {
    pub(super) relay_snapshot: Option<RelaySnapshot>,
    pub(super) established_pricing: Option<SessionPricing>,
    pub(super) cashu_spilman_protocol_version: Option<String>,
    pub(super) local_session_paid_msats: u64,
    pub(super) intended_channel_id: Option<String>,
    pub(super) intended_offer: Option<RelayPaymentOffer>,
    pub(super) session_excluded_channels: BTreeSet<String>,
    pub(super) control_op_in_flight: Option<ControlOpInFlight>,
    pub(super) last_keyset_refresh_hint: Option<KeysetRefreshHint>,
    pub(super) last_keyset_refresh_hint_at: Option<Instant>,
    pub(super) funding_blocked_reason: Option<FundingBlockedReason>,
    pub(super) ready_signaled: bool,
    pub(super) terminated: bool,
}

pub(super) fn relay_linked_channel_id(state: &DriverState) -> Option<&str> {
    state
        .relay_snapshot
        .as_ref()
        .and_then(|snapshot| snapshot.linked_channel.as_ref())
        .map(|channel| channel.channel_id.as_str())
}

pub(super) fn session_is_paused(state: &DriverState) -> bool {
    state
        .relay_snapshot
        .as_ref()
        .is_some_and(|snapshot| snapshot.paused)
}

pub(super) fn relay_confirms_intended_channel(state: &DriverState) -> bool {
    state.intended_channel_id.is_some()
        && state.intended_channel_id.as_deref() == relay_linked_channel_id(state)
}

pub(super) fn state_summary(state: &DriverState, counters: &CleartextByteCounters) -> String {
    let relay_linked = relay_linked_channel_id(state).unwrap_or("none");
    let intended = state.intended_channel_id.as_deref().unwrap_or("none");
    let paused = state
        .relay_snapshot
        .as_ref()
        .is_some_and(|snapshot| snapshot.paused);
    let remaining = state
        .relay_snapshot
        .as_ref()
        .map(|snapshot| snapshot.remaining_milli_sats.to_string())
        .unwrap_or_else(|| "unknown".to_string());
    let relay_in = state
        .relay_snapshot
        .as_ref()
        .map(|snapshot| snapshot.session_total_in.to_string())
        .unwrap_or_else(|| "unknown".to_string());
    let relay_out = state
        .relay_snapshot
        .as_ref()
        .map(|snapshot| snapshot.session_total_out.to_string())
        .unwrap_or_else(|| "unknown".to_string());
    let local_remaining = super::payment::compute_estimated_remaining(state, counters)
        .map(|remaining| remaining.to_string())
        .unwrap_or_else(|| "unknown".to_string());
    format!(
        "paused={} remaining={} local_remaining={} relay_in={} relay_out={} relay_linked={} intended={} op={:?} blocked={:?} ready={}",
        paused,
        remaining,
        local_remaining,
        relay_in,
        relay_out,
        relay_linked,
        intended,
        state.control_op_in_flight,
        state.funding_blocked_reason,
        state.ready_signaled,
    )
}

pub(super) fn current_spilman_info(state: &DriverState) -> Option<SessionSpilmanInfo> {
    let cashu_spilman_protocol_version = state.cashu_spilman_protocol_version.clone();
    if let Some(offer) = &state.intended_offer {
        return Some(SessionSpilmanInfo {
            receiver_pubkey: offer.receiver_pubkey.clone(),
            mint_url: offer.mint_url.clone(),
            unit: offer.unit.clone(),
            keyset_id: offer
                .accepted_keyset_ids
                .first()
                .cloned()
                .unwrap_or_default(),
            keyset_info_json: String::new(),
            cashu_spilman_protocol_version,
        });
    }

    let snapshot = state.relay_snapshot.as_ref()?;
    let advertisement = snapshot.advertisements.first()?;
    Some(SessionSpilmanInfo {
        receiver_pubkey: snapshot.receiver_pubkey.clone(),
        mint_url: advertisement.mint_url.clone(),
        unit: advertisement.unit.clone(),
        keyset_id: advertisement
            .keyset_ids
            .first()
            .cloned()
            .unwrap_or_default(),
        keyset_info_json: String::new(),
        cashu_spilman_protocol_version,
    })
}

pub(super) async fn publish_spilman_info(config: &SessionDriverConfig, state: &DriverState) {
    *config.conn.spilman_info_handle.write().await = current_spilman_info(state);
}

pub(super) async fn publish_pricing(config: &SessionDriverConfig, pricing: SessionPricing) {
    *config.conn.pricing_handle.write().await = Some(pricing);
}

fn clear_resolved_control_op_on_status(state: &mut DriverState) -> bool {
    let resolved_payment = matches!(
        state.control_op_in_flight,
        Some(ControlOpInFlight::Payment { .. })
    );
    if matches!(
        state.control_op_in_flight,
        Some(ControlOpInFlight::Link { .. })
            | Some(ControlOpInFlight::Payment { .. })
            | Some(ControlOpInFlight::RefreshKeysets(_))
    ) {
        state.control_op_in_flight = None;
    }
    resolved_payment
}

fn clear_refresh_hint_if_advertisement_changed(state: &mut DriverState, snapshot: &RelaySnapshot) {
    let Some(hint) = state.last_keyset_refresh_hint.as_ref() else {
        return;
    };
    let current_keyset_ids = snapshot
        .advertisements
        .iter()
        .find(|ad| ad.mint_url == hint.mint_url && ad.unit == hint.unit)
        .map(|ad| &ad.keyset_ids);
    if current_keyset_ids != Some(&hint.accepted_keyset_ids) {
        state.last_keyset_refresh_hint = None;
        state.last_keyset_refresh_hint_at = None;
    }
}

pub(super) fn clear_channel_control_op(state: &mut DriverState, channel_id: &str) {
    match &state.control_op_in_flight {
        Some(ControlOpInFlight::Link {
            channel_id: in_flight_channel,
        })
        | Some(ControlOpInFlight::Payment {
            channel_id: in_flight_channel,
        }) if in_flight_channel == channel_id => {
            state.control_op_in_flight = None;
        }
        _ => {}
    }
}

// ---------------------------------------------------------------------------
// Channel-state transition helpers
//
// These are the only places that should mutate intended-channel state,
// in-flight control operations, and the session-local excluded-channel set.
// Keep them small and explicit so callers cannot accidentally leave the driver
// in an inconsistent state.
// ---------------------------------------------------------------------------

pub(super) fn exclude_channel(state: &mut DriverState, channel_id: &str) {
    state
        .session_excluded_channels
        .insert(channel_id.to_owned());
}

pub(super) fn set_link_in_flight(
    state: &mut DriverState,
    channel_id: String,
    offer: RelayPaymentOffer,
) {
    state.intended_channel_id = Some(channel_id.clone());
    state.intended_offer = Some(offer);
    state.control_op_in_flight = Some(ControlOpInFlight::Link { channel_id });
}

pub(super) fn set_payment_in_flight(state: &mut DriverState, channel_id: String) {
    state.control_op_in_flight = Some(ControlOpInFlight::Payment { channel_id });
}

pub(super) fn set_keyset_refresh_in_flight(state: &mut DriverState, hint: KeysetRefreshHint) {
    state.last_keyset_refresh_hint = Some(hint.clone());
    state.last_keyset_refresh_hint_at = Some(Instant::now());
    state.control_op_in_flight = Some(ControlOpInFlight::RefreshKeysets(hint));
}

pub(super) fn clear_control_op(state: &mut DriverState) {
    state.control_op_in_flight = None;
}

/// Abandon the intended channel: detach it from the wallet, optionally exclude it
/// for the remainder of the session, clear intended/offer/in-flight state if it
/// still belongs to this channel, and republish Spilman info.
pub(super) async fn abandon_intended_channel(
    config: &SessionDriverConfig,
    state: &mut DriverState,
    channel_id: String,
    exclude_for_session: bool,
) {
    if exclude_for_session {
        state.session_excluded_channels.insert(channel_id.clone());
    }
    let _ = config
        .wallet
        .detach_channel_from_session(&channel_id, config.conn.session_id);
    if state.intended_channel_id.as_deref() == Some(channel_id.as_str()) {
        state.intended_channel_id = None;
        state.intended_offer = None;
    }
    clear_channel_control_op(state, &channel_id);
    publish_spilman_info(config, state).await;
}

/// Mark the session as terminated: detach any intended channel, clear all
/// channel/in-flight/blocked state, set the terminated flag, and republish
/// Spilman info.
pub(super) async fn terminate_session(config: &SessionDriverConfig, state: &mut DriverState) {
    if let Some(channel_id) = state.intended_channel_id.clone() {
        let _ = config
            .wallet
            .detach_channel_from_session(&channel_id, config.conn.session_id);
    }
    state.intended_channel_id = None;
    state.intended_offer = None;
    state.control_op_in_flight = None;
    state.last_keyset_refresh_hint = None;
    state.last_keyset_refresh_hint_at = None;
    state.funding_blocked_reason = None;
    state.terminated = true;
    publish_spilman_info(config, state).await;
}

pub(super) async fn signal_ready(
    state: &mut DriverState,
    ready_tx: &mut Option<oneshot::Sender<()>>,
) {
    if !state.ready_signaled {
        if let Some(tx) = ready_tx.take() {
            let _ = tx.send(());
        }
        state.ready_signaled = true;
    }
}

pub(super) fn set_blocked_reason(
    config: &SessionDriverConfig,
    state: &mut DriverState,
    reason: FundingBlockedReason,
    detail: &str,
) -> io::Result<()> {
    warn!(
        "{} funding blocked: {:?} ({detail})",
        config.hop_label, reason
    );
    state.funding_blocked_reason = Some(reason.clone());
    if !state.ready_signaled {
        return Err(io::Error::other(format!(
            "session funding blocked before readiness: {:?} ({detail})",
            reason,
        )));
    }
    Ok(())
}

#[cfg(test)]
pub(super) fn pre_ready_blocked_error(
    ready_tx: &Option<oneshot::Sender<()>>,
    previous_blocked_reason: Option<FundingBlockedReason>,
    next_state: &DriverState,
) -> Option<io::Error> {
    if ready_tx.is_none()
        || previous_blocked_reason == next_state.funding_blocked_reason
        || next_state.funding_blocked_reason.is_none()
    {
        return None;
    }

    let blocked_reason = next_state.funding_blocked_reason.as_ref().unwrap();
    Some(io::Error::other(format!(
        "session funding blocked before readiness: {:?}",
        blocked_reason,
    )))
}

// A `SessionStatus` both refreshes the relay-authoritative baseline and clears
// any link/payment operation that was waiting for the next status update.
pub(super) fn apply_session_status(state: &mut DriverState, snapshot: RelaySnapshot) -> bool {
    let resolved_payment = clear_resolved_control_op_on_status(state);
    clear_refresh_hint_if_advertisement_changed(state, &snapshot);
    state.relay_snapshot = Some(snapshot);
    resolved_payment
}
