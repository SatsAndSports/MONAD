use monad_common::protocol::{LinkedChannelStatus, PaymentOption};
use monad_common::proxy::CleartextByteCounters;
use monad_common::session::{RelayConnection, SessionPricing, SessionSpilmanInfo};
use std::collections::{BTreeMap, BTreeSet};
use std::io;
use std::sync::Arc;
use tokio::sync::oneshot;
use tokio::time::Instant;
use tracing::warn;

use crate::session_driver::PaymentPolicy;
use crate::wallet::{MonadWallet, RelayPaymentOffer, WalletChannel, WalletChannelAccounting};

#[derive(Clone)]
pub(super) struct SessionDriverConfig {
    pub(super) wallet: Arc<dyn MonadWallet>,
    pub(super) conn: RelayConnectionHandles,
    pub(super) hop_label: String,
    pub(super) payment_policy: PaymentPolicy,
    pub(super) management: Option<(
        Arc<crate::management::ClientManagement>,
        Arc<crate::management::HopManagement>,
    )>,
}

#[derive(Clone)]
pub(super) struct RelayConnectionHandles {
    pub(super) session_id: [u8; 32],
    pub(super) pricing_handle: Arc<tokio::sync::RwLock<Option<SessionPricing>>>,
    pub(super) spilman_info_handle: Arc<tokio::sync::RwLock<Option<SessionSpilmanInfo>>>,
    pub(super) cashu_spilman_protocol_version_handle: Arc<tokio::sync::RwLock<Option<String>>>,
    pub(super) cashu_spilman_keyset_versions_handle:
        Arc<tokio::sync::RwLock<Option<BTreeSet<String>>>>,
    pub(super) cleartext_byte_counters: CleartextByteCounters,
}

impl From<&RelayConnection> for RelayConnectionHandles {
    fn from(conn: &RelayConnection) -> Self {
        Self {
            session_id: *conn.session_id(),
            pricing_handle: conn.session_pricing_handle(),
            spilman_info_handle: conn.session_spilman_info_handle(),
            cashu_spilman_protocol_version_handle: conn.cashu_spilman_protocol_version_handle(),
            cashu_spilman_keyset_versions_handle: conn.cashu_spilman_keyset_versions_handle(),
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
// In particular, the client does not use relay `session_total_bytes_in` for payment
// math, because inbound bytes may legitimately be observed by the relay before
// the client has drained them locally. The field is still retained for
// diagnostics and relay-state visibility.
#[derive(Debug, Clone)]
pub(super) struct RelaySnapshot {
    pub(super) receiver_pubkey: String,
    pub(super) advertisements: Vec<PaymentOption>,
    pub(super) linked_channel: Option<LinkedChannelStatus>,
    pub(super) session_total_bytes_in: u64,
    pub(super) session_total_bytes_out: u64,
    pub(super) total_paid_millisats: u64,
    pub(super) remaining_milli_sats: i64,
    pub(super) paused: bool,
}

#[cfg(test)]
use monad_common::control_exchange::PendingRequest;

#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) enum FundingBlockedReason {
    ChannelAcquire,
    LinkRequestBuild,
    PaymentRequestBuild,
}

#[derive(Debug, Default)]
pub(super) struct DriverState {
    pub(super) exchange: super::reducer::ControlState,
    pub(super) relay_snapshot: Option<RelaySnapshot>,
    pub(super) established_pricing: Option<SessionPricing>,
    pub(super) cashu_spilman_protocol_version: Option<String>,
    pub(super) cashu_spilman_keyset_versions: Option<BTreeSet<String>>,
    pub(super) local_session_paid_msats: u64,
    pub(super) intended_channel_id: Option<String>,
    pub(super) intended_channel_keyset_id: Option<String>,
    pub(super) intended_offer: Option<RelayPaymentOffer>,
    pub(super) acquired: Option<(WalletChannel, RelayPaymentOffer)>,
    pub(super) previous_link: Option<PreviousChannel>,
    /// Wallet authority captured when this session reserves a channel. Relay
    /// statuses validate against this task-owned snapshot; they never load or
    /// populate authority from a relay-provided channel ID.
    pub(super) channel_authority: BTreeMap<String, WalletChannelAccounting>,
    pub(super) session_excluded_channels: BTreeSet<String>,
    /// Channels the relay has politely asked to retire. The client stops
    /// creating payments on them, awaits acknowledgement of any in-flight
    /// payment, then sends an ID-only `ChannelUnlink`.
    pub(super) release_requested_channels: BTreeSet<String>,
    pub(super) funding_retry_not_before: Option<Instant>,
    pub(super) funding_blocked_reason: Option<FundingBlockedReason>,
    pub(super) ready_signaled: bool,
    pub(super) terminated: bool,
}

#[derive(Debug)]
pub(super) struct PreviousChannel {
    pub channel_id: String,
    pub keyset_id: Option<String>,
    pub offer: Option<RelayPaymentOffer>,
    pub evicted: bool,
}

pub(super) fn relay_linked_channel_id(state: &DriverState) -> Option<&str> {
    state
        .relay_snapshot
        .as_ref()
        .and_then(|snapshot| snapshot.linked_channel.as_ref())
        .map(|channel| channel.channel_id.as_str())
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
        .map(|snapshot| snapshot.session_total_bytes_in.to_string())
        .unwrap_or_else(|| "unknown".to_string());
    let relay_out = state
        .relay_snapshot
        .as_ref()
        .map(|snapshot| snapshot.session_total_bytes_out.to_string())
        .unwrap_or_else(|| "unknown".to_string());
    let local_remaining = match super::payment::compute_estimated_remaining(state, counters) {
        Ok(Some(remaining)) => remaining.to_string(),
        Ok(None) => "unknown".to_string(),
        Err(_) => "out of range".to_string(),
    };
    format!(
        "paused={} remaining={} local_remaining={} relay_in={} relay_out={} relay_linked={} intended={} op={:?} blocked={:?} ready={}",
        paused,
        remaining,
        local_remaining,
        relay_in,
        relay_out,
        relay_linked,
        intended,
        state.exchange.pending(),
        state.funding_blocked_reason,
        state.ready_signaled,
    )
}

pub(super) fn current_spilman_info(state: &DriverState) -> Option<SessionSpilmanInfo> {
    let cashu_spilman_protocol_version = state.cashu_spilman_protocol_version.clone();
    let cashu_spilman_keyset_versions = state.cashu_spilman_keyset_versions.clone();
    if let Some(offer) = &state.intended_offer {
        return Some(SessionSpilmanInfo {
            receiver_pubkey: offer.receiver_pubkey.clone(),
            mint_url: offer.mint_url.clone(),
            unit: offer.unit.clone(),
            keyset_id: state.intended_channel_keyset_id.clone().unwrap_or_default(),
            keyset_info_json: String::new(),
            cashu_spilman_protocol_version,
            cashu_spilman_keyset_versions,
        });
    }

    let snapshot = state.relay_snapshot.as_ref()?;
    let advertisement = snapshot.advertisements.first()?;
    Some(SessionSpilmanInfo {
        receiver_pubkey: snapshot.receiver_pubkey.clone(),
        mint_url: advertisement.mint_url.clone(),
        unit: advertisement.unit.clone(),
        keyset_id: String::new(),
        keyset_info_json: String::new(),
        cashu_spilman_protocol_version,
        cashu_spilman_keyset_versions,
    })
}

pub(super) async fn publish_spilman_info(config: &SessionDriverConfig, state: &DriverState) {
    *config.conn.spilman_info_handle.write().await = current_spilman_info(state);
}

pub(super) async fn publish_pricing(config: &SessionDriverConfig, pricing: SessionPricing) {
    *config.conn.pricing_handle.write().await = Some(pricing);
}

// ---------------------------------------------------------------------------
// Channel-state transition helpers
//
// Executor-side cleanup/publication helpers. Ordinary-operation and replacement
// transitions live in reducer.rs. Cleanup must not consume a pending response.
// ---------------------------------------------------------------------------

pub(super) fn exclude_channel(state: &mut DriverState, channel_id: &str) {
    state
        .session_excluded_channels
        .insert(channel_id.to_owned());
}

#[cfg(test)]
pub(super) fn set_link_in_flight(
    state: &mut DriverState,
    channel_id: String,
    keyset_id: String,
    offer: RelayPaymentOffer,
) {
    state.intended_channel_id = Some(channel_id.clone());
    state.intended_channel_keyset_id = Some(keyset_id);
    state.intended_offer = Some(offer);
}

pub(super) fn clear_control_op(state: &mut DriverState) {
    // Responses have already been committed by the control reducer.
    debug_assert!(state.exchange.is_empty());
}

pub(super) fn request_channel_release(state: &mut DriverState, channel_id: &str) {
    state
        .release_requested_channels
        .insert(channel_id.to_owned());
}

pub(super) fn release_is_pending(state: &DriverState, channel_id: &str) -> bool {
    state.release_requested_channels.contains(channel_id)
}

pub(super) fn finish_channel_release(state: &mut DriverState, channel_id: &str) {
    state.release_requested_channels.remove(channel_id);
}

/// Abandon the intended channel: detach it from the wallet, optionally exclude it
/// for the remainder of the session, clear intended/offer state if it
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
    state.channel_authority.remove(&channel_id);
    if state.intended_channel_id.as_deref() == Some(channel_id.as_str()) {
        state.intended_channel_id = None;
        state.intended_channel_keyset_id = None;
        state.intended_offer = None;
    }
    publish_spilman_info(config, state).await;
}

/// Mark the session as terminated: detach any intended channel, clear all
/// channel/in-flight/blocked state, set the terminated flag, and republish
/// Spilman info.
pub(super) async fn terminate_session(config: &SessionDriverConfig, state: &mut DriverState) {
    let mut channel_ids = state
        .channel_authority
        .keys()
        .cloned()
        .collect::<BTreeSet<_>>();
    if let Some((channel, _)) = state.acquired.take() {
        channel_ids.insert(channel.channel_id);
    }
    if let Some(previous) = state.previous_link.take() {
        channel_ids.insert(previous.channel_id);
    }
    if let Some(channel_id) = state.intended_channel_id.clone() {
        channel_ids.insert(channel_id);
    }
    for channel_id in channel_ids {
        let _ = config
            .wallet
            .detach_channel_from_session(&channel_id, config.conn.session_id);
    }
    state.channel_authority.clear();
    state.intended_channel_id = None;
    state.intended_channel_keyset_id = None;
    state.intended_offer = None;
    let _ = state.exchange.step(super::reducer::Event::End);
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
    if let Some((owner, hop)) = &config.management {
        hop.blocked(owner, detail.to_owned());
    }
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

// Only called after ControlExchange validates and attributes the response.
pub(super) fn apply_session_status(state: &mut DriverState, snapshot: RelaySnapshot) {
    // Extra relay-reported credit can reduce future payments, never increase
    // them. A lower report cannot revoke locally recorded signed exposure.
    state.local_session_paid_msats = state
        .local_session_paid_msats
        .max(snapshot.total_paid_millisats);
    state.relay_snapshot = Some(snapshot);
}

#[cfg(test)]
mod acknowledgement_tests {
    use super::*;
    fn status(channel: &str, balance_raw: u64) -> RelaySnapshot {
        RelaySnapshot {
            receiver_pubkey: String::new(),
            advertisements: vec![],
            linked_channel: Some(LinkedChannelStatus {
                channel_id: channel.into(),
                balance_raw,
                capacity_raw: 30000,
                unit: "msat".into(),
            }),
            session_total_bytes_in: 0,
            session_total_bytes_out: 0,
            total_paid_millisats: balance_raw,
            remaining_milli_sats: -21,
            paused: true,
        }
    }

    fn unlinked_status(paid_millisats: u64) -> RelaySnapshot {
        RelaySnapshot {
            receiver_pubkey: String::new(),
            advertisements: vec![],
            linked_channel: None,
            session_total_bytes_in: 0,
            session_total_bytes_out: 0,
            total_paid_millisats: paid_millisats,
            remaining_milli_sats: -21,
            paused: true,
        }
    }

    #[test]
    fn storing_a_snapshot_cannot_heuristically_resolve_a_request() {
        let mut state = DriverState::default();
        state.exchange.ordinary =
            super::super::reducer::Ordinary::AwaitingResponse(PendingRequest::Payment {
                channel_id: "channel".into(),
                balance_raw: 1000,
                minimum_increment_msats: 1000,
            });
        apply_session_status(&mut state, status("channel", 1000));
        apply_session_status(&mut state, unlinked_status(1000));
        assert!(state.exchange.pending().is_some());
    }
}
