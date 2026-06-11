use bytes::Bytes;
use monad_common::h2stream::wait_for_send_capacity;
use monad_common::protocol::{
    ClientMessage, KeysetAdvertisement, LinkedChannelStatus, ServerErrorCode, ServerMessage,
};
use monad_common::proxy::CleartextByteCounters;
use monad_common::session::{RelayConnection, SessionPricing, SessionSpilmanInfo};
use std::collections::BTreeSet;
use std::io;
use std::sync::Arc;
use tokio::sync::oneshot;
use tokio::task::JoinHandle;
use tokio::time::{self, Duration, MissedTickBehavior};
use tracing::{info, warn};

use crate::wallet::{select_channel, MonadWallet, RelayPaymentOffer, WalletChannel, WalletError};

const DEFAULT_PROVISIONED_CHANNEL_CAPACITY_MSATS: u64 = 100_000_000;
const TARGET_TOPUP_BUFFER_MSATS: u64 = 10_000_000;

fn encode_client_message(message: &ClientMessage) -> io::Result<Bytes> {
    let bytes =
        serde_json::to_vec(message).map_err(|e| io::Error::other(format!("json error: {e}")))?;
    let mut frame = Vec::with_capacity(bytes.len() + 1);
    frame.extend_from_slice(&bytes);
    frame.push(b'\n');
    Ok(Bytes::from(frame))
}

async fn send_control_message(
    h2_send: &mut h2::SendStream<Bytes>,
    message: &ClientMessage,
) -> io::Result<()> {
    let frame = encode_client_message(message)?;
    h2_send.reserve_capacity(frame.len());
    wait_for_send_capacity(h2_send).await?;
    h2_send
        .send_data(frame, false)
        .map_err(|e| io::Error::other(format!("h2 send error: {e}")))
}

struct SessionDriverConfig {
    wallet: Arc<dyn MonadWallet>,
    conn: RelayConnectionProxy,
    hop_label: String,
}

pub async fn start_session_payment_driver(
    conn: &RelayConnection,
    wallet: Arc<dyn MonadWallet>,
    hop_label: &str,
) -> io::Result<(JoinHandle<()>, oneshot::Receiver<()>)> {
    let (control_send, control_recv) = conn.open_control().await?;
    let (ready_tx, ready_rx) = oneshot::channel();
    let config = SessionDriverConfig {
        wallet,
        conn: RelayConnectionProxy::from(conn),
        hop_label: hop_label.to_string(),
    };

    let handle = tokio::spawn(async move {
        if let Err(e) = run_session_driver(control_send, control_recv, ready_tx, config).await {
            warn!("session payment driver ended with error: {e}");
        }
    });

    Ok((handle, ready_rx))
}

struct RelayConnectionProxy {
    session_id: [u8; 32],
    pricing_handle: Arc<tokio::sync::RwLock<Option<SessionPricing>>>,
    spilman_info_handle: Arc<tokio::sync::RwLock<Option<SessionSpilmanInfo>>>,
    cleartext_byte_counters: CleartextByteCounters,
}

impl From<&RelayConnection> for RelayConnectionProxy {
    fn from(conn: &RelayConnection) -> Self {
        Self {
            session_id: *conn.session_id(),
            pricing_handle: conn.session_pricing_handle(),
            spilman_info_handle: conn.session_spilman_info_handle(),
            cleartext_byte_counters: conn.cleartext_byte_counters(),
        }
    }
}

#[derive(Debug, Clone)]
struct AuthoritativeSnapshot {
    receiver_pubkey: String,
    advertisements: Vec<KeysetAdvertisement>,
    linked_channel: Option<LinkedChannelStatus>,
    session_total_in: u64,
    session_total_out: u64,
    total_paid_millisats: u64,
    remaining_milli_sats: i64,
    paused: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum ControlOpInFlight {
    Link { channel_id: String },
    Payment { channel_id: String },
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum FundingBlockedReason {
    Acquire,
    LinkBuild,
    PaymentBuild,
}

#[derive(Debug, Default)]
struct DriverState {
    snapshot: Option<AuthoritativeSnapshot>,
    established_pricing: Option<SessionPricing>,
    intended_channel_id: Option<String>,
    intended_offer: Option<RelayPaymentOffer>,
    session_excluded_channels: BTreeSet<String>,
    control_op_in_flight: Option<ControlOpInFlight>,
    funding_blocked_reason: Option<FundingBlockedReason>,
    ready_signaled: bool,
    terminated: bool,
}

fn validate_session_pricing(
    established_pricing: &mut Option<SessionPricing>,
    candidate: SessionPricing,
) -> io::Result<()> {
    if let Some(previous) = established_pricing {
        if *previous != candidate {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!(
                    "protocol violation: relay changed active session pricing from in={} out={} to in={} out={}",
                    previous.in_bytes_per_millisat,
                    previous.out_bytes_per_millisat,
                    candidate.in_bytes_per_millisat,
                    candidate.out_bytes_per_millisat,
                ),
            ));
        }
    } else {
        *established_pricing = Some(candidate);
    }

    Ok(())
}

fn requested_delta_msats(remaining_milli_sats: i64) -> u64 {
    let target_remaining = TARGET_TOPUP_BUFFER_MSATS as i128;
    let delta = target_remaining - remaining_milli_sats as i128;
    if delta <= 0 {
        return 0;
    }
    delta.min(u64::MAX as i128) as u64
}

fn delta_msats_to_raw_units(unit: &str, delta_msats: u64) -> u64 {
    match unit {
        "msat" => delta_msats,
        "sat" => delta_msats.div_ceil(1000),
        _ => 0,
    }
}

fn exclude_on_wallet_error(error: &WalletError) -> bool {
    matches!(
        error,
        WalletError::NotFound
            | WalletError::NotOpen
            | WalletError::AttachedToDifferentSession { .. }
            | WalletError::InsufficientCapacity { .. }
            | WalletError::ChannelUnusable
            | WalletError::OfferMismatch(_)
    )
}

fn server_error_invalidates_channel(code: &ServerErrorCode) -> bool {
    matches!(
        code,
        ServerErrorCode::LinkInvalidChannel
            | ServerErrorCode::LinkReceiverMismatch
            | ServerErrorCode::LinkMintOrKeysetUnacceptable
            | ServerErrorCode::LinkUnsupportedUnit
            | ServerErrorCode::LinkNonZeroBalance
            | ServerErrorCode::ChannelExpired
            | ServerErrorCode::ChannelClosed
    )
}

fn server_error_rejects_intended_channel(code: &ServerErrorCode) -> bool {
    server_error_invalidates_channel(code)
}

fn relay_linked_channel_id(state: &DriverState) -> Option<&str> {
    state
        .snapshot
        .as_ref()
        .and_then(|snapshot| snapshot.linked_channel.as_ref())
        .map(|channel| channel.channel_id.as_str())
}

fn session_is_paused(state: &DriverState) -> bool {
    state
        .snapshot
        .as_ref()
        .is_some_and(|snapshot| snapshot.paused)
}

fn relay_confirms_intended_channel(state: &DriverState) -> bool {
    state.intended_channel_id.is_some()
        && state.intended_channel_id.as_deref() == relay_linked_channel_id(state)
}

fn compute_estimated_remaining(
    state: &DriverState,
    counters: &CleartextByteCounters,
) -> Option<i64> {
    let snapshot = state.snapshot.as_ref()?;
    let pricing = state.established_pricing?;
    let (local_inbound, local_outbound) = counters.snapshot();
    let estimated_total_in = snapshot
        .session_total_in
        .saturating_add(local_inbound.saturating_sub(snapshot.session_total_in));
    let estimated_total_out = snapshot
        .session_total_out
        .saturating_add(local_outbound.saturating_sub(snapshot.session_total_out));
    let estimated_due = pricing.amount_due_millisats(estimated_total_in, estimated_total_out);
    Some(
        (snapshot.total_paid_millisats as i128 - estimated_due as i128)
            .clamp(i64::MIN as i128, i64::MAX as i128) as i64,
    )
}

fn state_summary(state: &DriverState, counters: &CleartextByteCounters) -> String {
    let relay_linked = relay_linked_channel_id(state).unwrap_or("none");
    let intended = state.intended_channel_id.as_deref().unwrap_or("none");
    let paused = state
        .snapshot
        .as_ref()
        .is_some_and(|snapshot| snapshot.paused);
    let remaining = state
        .snapshot
        .as_ref()
        .map(|snapshot| snapshot.remaining_milli_sats.to_string())
        .unwrap_or_else(|| "unknown".to_string());
    let local_remaining = compute_estimated_remaining(state, counters)
        .map(|remaining| remaining.to_string())
        .unwrap_or_else(|| "unknown".to_string());
    format!(
        "paused={} remaining={} local_remaining={} relay_linked={} intended={} op={:?} blocked={:?} ready={}",
        paused,
        remaining,
        local_remaining,
        relay_linked,
        intended,
        state.control_op_in_flight,
        state.funding_blocked_reason,
        state.ready_signaled,
    )
}

fn current_spilman_info(state: &DriverState) -> Option<SessionSpilmanInfo> {
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
        });
    }

    let snapshot = state.snapshot.as_ref()?;
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
    })
}

async fn publish_spilman_info(config: &SessionDriverConfig, state: &DriverState) {
    *config.conn.spilman_info_handle.write().await = current_spilman_info(state);
}

async fn publish_pricing(config: &SessionDriverConfig, pricing: SessionPricing) {
    *config.conn.pricing_handle.write().await = Some(pricing);
}

fn clear_resolved_control_op_on_status(state: &mut DriverState) -> bool {
    let resolved_payment = matches!(
        state.control_op_in_flight,
        Some(ControlOpInFlight::Payment { .. })
    );
    if matches!(
        state.control_op_in_flight,
        Some(ControlOpInFlight::Link { .. }) | Some(ControlOpInFlight::Payment { .. })
    ) {
        state.control_op_in_flight = None;
    }
    resolved_payment
}

fn clear_channel_control_op(state: &mut DriverState, channel_id: &str) {
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

async fn signal_ready(state: &mut DriverState, ready_tx: &mut Option<oneshot::Sender<()>>) {
    if !state.ready_signaled {
        if let Some(tx) = ready_tx.take() {
            let _ = tx.send(());
        }
        state.ready_signaled = true;
    }
}

fn set_blocked_reason(
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
fn pre_ready_blocked_error(
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

async fn abandon_intended_channel(
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
    state.intended_channel_id = None;
    state.intended_offer = None;
    clear_channel_control_op(state, &channel_id);
    publish_spilman_info(config, state).await;
}

fn choose_channel_and_offer(
    wallet: &dyn MonadWallet,
    state: &DriverState,
    session_id: [u8; 32],
) -> Result<Option<(WalletChannel, RelayPaymentOffer)>, WalletError> {
    let Some(snapshot) = state.snapshot.as_ref() else {
        return Ok(None);
    };
    let channels = wallet
        .list_channels()?
        .into_iter()
        .filter(|channel| {
            !state
                .session_excluded_channels
                .contains(&channel.channel_id)
        })
        .collect::<Vec<_>>();
    for advertisement in &snapshot.advertisements {
        let offer =
            RelayPaymentOffer::from_advertisement(snapshot.receiver_pubkey.clone(), advertisement);
        if let Some(channel) = select_channel(&channels, &offer, session_id) {
            return Ok(Some((channel, offer)));
        }
    }
    Ok(None)
}

async fn send_channel_link(
    config: &SessionDriverConfig,
    state: &mut DriverState,
    h2_send: &mut h2::SendStream<Bytes>,
    channel_id: String,
    offer: RelayPaymentOffer,
    payment_json: String,
) -> io::Result<()> {
    info!(
        "{} sending ChannelLink for {} | {}",
        config.hop_label,
        channel_id,
        state_summary(state, &config.conn.cleartext_byte_counters)
    );
    send_control_message(h2_send, &ClientMessage::ChannelLink { payment_json }).await?;
    state.intended_channel_id = Some(channel_id.clone());
    state.intended_offer = Some(offer);
    state.control_op_in_flight = Some(ControlOpInFlight::Link { channel_id });
    publish_spilman_info(config, state).await;
    Ok(())
}

async fn try_link_channel(
    config: &SessionDriverConfig,
    state: &mut DriverState,
    h2_send: &mut h2::SendStream<Bytes>,
    channel: WalletChannel,
    offer: RelayPaymentOffer,
) -> io::Result<bool> {
    let channel_id = channel.channel_id.clone();
    if let Err(error) = config
        .wallet
        .attach_channel_to_session(&channel_id, config.conn.session_id)
    {
        if matches!(error, WalletError::Backend(_)) {
            set_blocked_reason(
                config,
                state,
                FundingBlockedReason::Acquire,
                &error.to_string(),
            )?;
            return Ok(false);
        }
        if exclude_on_wallet_error(&error) {
            state.session_excluded_channels.insert(channel_id.clone());
        }
        return Ok(true);
    }

    match config.wallet.build_link_request(&channel_id, &offer) {
        Ok(payment_json) => {
            send_channel_link(config, state, h2_send, channel_id, offer, payment_json).await?;
            Ok(false)
        }
        Err(error) => {
            let _ = config
                .wallet
                .detach_channel_from_session(&channel_id, config.conn.session_id);
            if matches!(error, WalletError::Backend(_)) {
                set_blocked_reason(
                    config,
                    state,
                    FundingBlockedReason::LinkBuild,
                    &error.to_string(),
                )?;
                return Ok(false);
            }
            if exclude_on_wallet_error(&error) {
                state.session_excluded_channels.insert(channel_id.clone());
            }
            Ok(true)
        }
    }
}

async fn maybe_ensure_linked_channel(
    config: &SessionDriverConfig,
    state: &mut DriverState,
    h2_send: &mut h2::SendStream<Bytes>,
) -> io::Result<()> {
    if state.terminated || state.funding_blocked_reason.is_some() || !session_is_paused(state) {
        return Ok(());
    }
    if matches!(
        state.control_op_in_flight,
        Some(ControlOpInFlight::Link { .. })
    ) || matches!(
        state.control_op_in_flight,
        Some(ControlOpInFlight::Payment { .. })
    ) {
        return Ok(());
    }
    if relay_confirms_intended_channel(state) {
        info!(
            "{} relay confirms intended channel {} | {}",
            config.hop_label,
            state.intended_channel_id.as_deref().unwrap_or("none"),
            state_summary(state, &config.conn.cleartext_byte_counters)
        );
        return Ok(());
    }

    if let Some(intended_channel_id) = state.intended_channel_id.as_deref() {
        let relay_linked = relay_linked_channel_id(state).unwrap_or("none");
        if relay_linked != "none" && relay_linked != intended_channel_id {
            info!(
                "{} relay linked channel mismatch: relay={} intended={} | {}",
                config.hop_label,
                relay_linked,
                intended_channel_id,
                state_summary(state, &config.conn.cleartext_byte_counters)
            );
        } else if relay_linked == "none" {
            info!(
                "{} relay reports no linked channel; keeping intended channel {} | {}",
                config.hop_label,
                intended_channel_id,
                state_summary(state, &config.conn.cleartext_byte_counters)
            );
        }
    }

    loop {
        if let (Some(channel_id), Some(offer)) = (
            state.intended_channel_id.clone(),
            state.intended_offer.clone(),
        ) {
            let channel = match config.wallet.get_channel(&channel_id) {
                Ok(channel) => channel,
                Err(error) => {
                    if matches!(error, WalletError::Backend(_)) {
                        set_blocked_reason(
                            config,
                            state,
                            FundingBlockedReason::Acquire,
                            &error.to_string(),
                        )?;
                        return Ok(());
                    }
                    abandon_intended_channel(config, state, channel_id, true).await;
                    continue;
                }
            };
            info!(
                "{} retrying ChannelLink for intended channel {} | {}",
                config.hop_label,
                channel.channel_id,
                state_summary(state, &config.conn.cleartext_byte_counters)
            );
            if !try_link_channel(config, state, h2_send, channel, offer).await? {
                return Ok(());
            }
            abandon_intended_channel(config, state, channel_id, false).await;
            continue;
        }

        match choose_channel_and_offer(config.wallet.as_ref(), state, config.conn.session_id) {
            Ok(Some((channel, offer))) => {
                info!(
                    "{} selected existing channel {} | {}",
                    config.hop_label,
                    channel.channel_id,
                    state_summary(state, &config.conn.cleartext_byte_counters)
                );
                if !try_link_channel(config, state, h2_send, channel, offer).await? {
                    return Ok(());
                }
            }
            Ok(None) => {
                let Some(snapshot) = state.snapshot.as_ref() else {
                    return Ok(());
                };
                let Some(advertisement) = snapshot.advertisements.first() else {
                    return Ok(());
                };
                info!(
                    "{} provisioning new channel from first advertisement | {}",
                    config.hop_label,
                    state_summary(state, &config.conn.cleartext_byte_counters)
                );
                let offer = RelayPaymentOffer::from_advertisement(
                    snapshot.receiver_pubkey.clone(),
                    advertisement,
                );
                let channel_id = match config
                    .wallet
                    .provision_channel(&offer, DEFAULT_PROVISIONED_CHANNEL_CAPACITY_MSATS)
                {
                    Ok(channel_id) => channel_id,
                    Err(error) => {
                        if matches!(error, WalletError::Backend(_)) {
                            set_blocked_reason(
                                config,
                                state,
                                FundingBlockedReason::Acquire,
                                &error.to_string(),
                            )?;
                        }
                        return Ok(());
                    }
                };
                let channel = match config.wallet.get_channel(&channel_id) {
                    Ok(channel) => channel,
                    Err(error) => {
                        if matches!(error, WalletError::Backend(_)) {
                            set_blocked_reason(
                                config,
                                state,
                                FundingBlockedReason::Acquire,
                                &error.to_string(),
                            )?;
                        }
                        return Ok(());
                    }
                };
                if !try_link_channel(config, state, h2_send, channel, offer).await? {
                    return Ok(());
                }
            }
            Err(error) => {
                if matches!(error, WalletError::Backend(_)) {
                    set_blocked_reason(
                        config,
                        state,
                        FundingBlockedReason::Acquire,
                        &error.to_string(),
                    )?;
                }
                return Ok(());
            }
        }
    }
}

async fn maybe_progress_payment(
    config: &SessionDriverConfig,
    state: &mut DriverState,
    h2_send: &mut h2::SendStream<Bytes>,
    skip_for_resolved_payment: bool,
) -> io::Result<()> {
    if skip_for_resolved_payment
        || state.terminated
        || state.funding_blocked_reason.is_some()
        || matches!(
            state.control_op_in_flight,
            Some(ControlOpInFlight::Payment { .. })
        )
    {
        return Ok(());
    }

    let Some(snapshot) = state.snapshot.as_ref() else {
        return Ok(());
    };
    let Some(linked_channel) = snapshot.linked_channel.as_ref() else {
        return Ok(());
    };
    let Some(intended_channel_id) = state.intended_channel_id.clone() else {
        return Ok(());
    };
    let Some(intended_offer) = state.intended_offer.clone() else {
        return Ok(());
    };
    let Some(estimated_remaining) =
        compute_estimated_remaining(state, &config.conn.cleartext_byte_counters)
    else {
        return Ok(());
    };
    let should_pay = snapshot.paused
        || snapshot.remaining_milli_sats <= 0
        || estimated_remaining < TARGET_TOPUP_BUFFER_MSATS as i64;
    if linked_channel.channel_id != intended_channel_id || !should_pay {
        if linked_channel.channel_id != intended_channel_id {
            info!(
                "{} payment skipped: relay linked channel {} does not match intended {} | {}",
                config.hop_label,
                linked_channel.channel_id,
                intended_channel_id,
                state_summary(state, &config.conn.cleartext_byte_counters)
            );
        }
        return Ok(());
    }

    let requested_delta_msats = requested_delta_msats(estimated_remaining);
    if requested_delta_msats == 0 {
        return Ok(());
    }
    let requested_delta_raw = delta_msats_to_raw_units(&linked_channel.unit, requested_delta_msats);
    let Some(next_balance_raw) = linked_channel.balance_raw.checked_add(requested_delta_raw) else {
        return Ok(());
    };

    if next_balance_raw > linked_channel.capacity_raw {
        warn!(
            "{} abandoning exhausted channel {}: next_balance_raw={} capacity_raw={} | {}",
            config.hop_label,
            intended_channel_id,
            next_balance_raw,
            linked_channel.capacity_raw,
            state_summary(state, &config.conn.cleartext_byte_counters)
        );
        abandon_intended_channel(config, state, intended_channel_id, true).await;
        return Ok(());
    }

    match config.wallet.build_channel_payment(
        &intended_channel_id,
        &intended_offer,
        linked_channel.balance_raw,
        next_balance_raw,
    ) {
        Ok(payment_json) => {
            info!(
                "{} sending ChannelPayment for {}: remaining={} target={} next_balance_raw={} | {}",
                config.hop_label,
                intended_channel_id,
                estimated_remaining,
                TARGET_TOPUP_BUFFER_MSATS,
                next_balance_raw,
                state_summary(state, &config.conn.cleartext_byte_counters)
            );
            send_control_message(h2_send, &ClientMessage::ChannelPayment { payment_json }).await?;
            state.control_op_in_flight = Some(ControlOpInFlight::Payment {
                channel_id: intended_channel_id,
            });
        }
        Err(error) => {
            if matches!(error, WalletError::Backend(_)) {
                set_blocked_reason(
                    config,
                    state,
                    FundingBlockedReason::PaymentBuild,
                    &error.to_string(),
                )?;
            } else if exclude_on_wallet_error(&error) {
                warn!(
                    "{} abandoning channel {} after payment build failure: {} | {}",
                    config.hop_label,
                    intended_channel_id,
                    error,
                    state_summary(state, &config.conn.cleartext_byte_counters)
                );
                abandon_intended_channel(config, state, intended_channel_id, true).await;
            }
        }
    }

    Ok(())
}

fn apply_session_status(state: &mut DriverState, snapshot: AuthoritativeSnapshot) -> bool {
    let resolved_payment = clear_resolved_control_op_on_status(state);
    state.snapshot = Some(snapshot);
    resolved_payment
}

async fn apply_channel_evicted(
    config: &SessionDriverConfig,
    state: &mut DriverState,
    channel_id: String,
) {
    clear_channel_control_op(state, &channel_id);
    state.session_excluded_channels.insert(channel_id.clone());
    if state.intended_channel_id.as_deref() == Some(channel_id.as_str()) {
        abandon_intended_channel(config, state, channel_id, false).await;
    }
    publish_spilman_info(config, state).await;
}

async fn apply_server_error(
    config: &SessionDriverConfig,
    state: &mut DriverState,
    code: ServerErrorCode,
) {
    if matches!(
        state.control_op_in_flight,
        Some(ControlOpInFlight::Link { .. }) | Some(ControlOpInFlight::Payment { .. })
    ) {
        state.control_op_in_flight = None;
    }

    if server_error_rejects_intended_channel(&code) {
        if let Some(channel_id) = state.intended_channel_id.clone() {
            if server_error_invalidates_channel(&code) {
                let _ = config.wallet.mark_channel_unusable(&channel_id);
            }
            abandon_intended_channel(config, state, channel_id, false).await;
        }
    }

    publish_spilman_info(config, state).await;
}

async fn handle_control_detached(config: &SessionDriverConfig, state: &mut DriverState) {
    if let Some(channel_id) = state.intended_channel_id.clone() {
        let _ = config
            .wallet
            .detach_channel_from_session(&channel_id, config.conn.session_id);
    }
    state.intended_channel_id = None;
    state.intended_offer = None;
    state.control_op_in_flight = None;
    state.funding_blocked_reason = None;
    state.terminated = true;
    publish_spilman_info(config, state).await;
}

async fn run_session_driver(
    mut h2_send: h2::SendStream<Bytes>,
    mut h2_recv: h2::RecvStream,
    ready_tx: oneshot::Sender<()>,
    config: SessionDriverConfig,
) -> io::Result<()> {
    let mut buf = Vec::new();
    let mut state = DriverState::default();
    let mut ready_tx = Some(ready_tx);

    let mut payment_tick = time::interval(Duration::from_millis(250));
    payment_tick.set_missed_tick_behavior(MissedTickBehavior::Skip);

    loop {
        tokio::select! {
            maybe_chunk = h2_recv.data() => {
                let Some(chunk) = maybe_chunk else {
                    break;
                };
                let data = chunk.map_err(|e| io::Error::other(format!("h2 recv error: {e}")))?;
                let len = data.len();
                let _ = h2_recv.flow_control().release_capacity(len);
                buf.extend_from_slice(&data);

                while let Some(newline_pos) = buf.iter().position(|&b| b == b'\n') {
                    let line: Vec<u8> = buf.drain(..=newline_pos).collect();
                    let line = line.trim_ascii();
                    if line.is_empty() {
                        continue;
                    }

                    let message: ServerMessage = serde_json::from_slice(line)
                        .map_err(|e| io::Error::other(format!("json error: {e}")))?;

                    let resolved_payment = match message {
                        ServerMessage::SessionStatus {
                            receiver_pubkey,
                            advertisements,
                            linked_channel,
                            active_in_rate,
                            active_out_rate,
                            session_total_in,
                            session_total_out,
                            total_paid_millisats,
                            remaining_milli_sats,
                            paused,
                            open_connects,
                            total_connects,
                        } => {
                            let pricing = SessionPricing::new(active_in_rate, active_out_rate);
                            validate_session_pricing(&mut state.established_pricing, pricing)?;
                            let due_now = pricing.amount_due_millisats(session_total_in, session_total_out);
                            info!(
                                "{} session status: open_connects={} total_connects={} paused={} balance={} paid={} due={} linked={:?} intended={} op={:?} blocked={:?} local_remaining={:?}",
                                config.hop_label,
                                open_connects,
                                total_connects,
                                paused,
                                remaining_milli_sats,
                                total_paid_millisats,
                                due_now,
                                linked_channel.as_ref().map(|channel| &channel.channel_id),
                                state.intended_channel_id.as_deref().unwrap_or("none"),
                                state.control_op_in_flight,
                                state.funding_blocked_reason,
                                compute_estimated_remaining(&state, &config.conn.cleartext_byte_counters),
                            );
                            let resolved = apply_session_status(
                                &mut state,
                                AuthoritativeSnapshot {
                                    receiver_pubkey,
                                    advertisements,
                                    linked_channel,
                                    session_total_in,
                                    session_total_out,
                                    total_paid_millisats,
                                    remaining_milli_sats,
                                    paused,
                                },
                            );
                            publish_pricing(&config, pricing).await;
                            publish_spilman_info(&config, &state).await;
                            if !paused {
                                signal_ready(&mut state, &mut ready_tx).await;
                            }
                            resolved
                        }
                        ServerMessage::ChannelEvicted { channel_id } => {
                            warn!(
                                "{} channel {channel_id} evicted from this session | {}",
                                config.hop_label,
                                state_summary(&state, &config.conn.cleartext_byte_counters)
                            );
                            apply_channel_evicted(&config, &mut state, channel_id).await;
                            false
                        }
                        ServerMessage::Error { code, message } => {
                            warn!(
                                "{} control error: code={:?} message={} | {}",
                                config.hop_label,
                                code,
                                message,
                                state_summary(&state, &config.conn.cleartext_byte_counters)
                            );
                            apply_server_error(&config, &mut state, code).await;
                            false
                        }
                    };

                    if state.terminated {
                        return Ok(());
                    }

                    maybe_ensure_linked_channel(&config, &mut state, &mut h2_send).await?;
                    maybe_progress_payment(&config, &mut state, &mut h2_send, resolved_payment).await?;
                    maybe_ensure_linked_channel(&config, &mut state, &mut h2_send).await?;
                }
            }
            _ = payment_tick.tick() => {
                if state.terminated {
                    return Ok(());
                }
                maybe_ensure_linked_channel(&config, &mut state, &mut h2_send).await?;
                maybe_progress_payment(&config, &mut state, &mut h2_send, false).await?;
                maybe_ensure_linked_channel(&config, &mut state, &mut h2_send).await?;
            }
        }
    }

    handle_control_detached(&config, &mut state).await;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{
        exclude_on_wallet_error, pre_ready_blocked_error, relay_confirms_intended_channel,
        requested_delta_msats, validate_session_pricing,
    };
    use super::{AuthoritativeSnapshot, DriverState, FundingBlockedReason};
    use crate::wallet::WalletError;
    use monad_common::protocol::{KeysetAdvertisement, LinkedChannelStatus, ServerErrorCode};
    use monad_common::proxy::CleartextByteCounters;
    use monad_common::session::SessionPricing;
    use std::io;
    use tokio::sync::oneshot;

    fn snapshot(paused: bool) -> AuthoritativeSnapshot {
        AuthoritativeSnapshot {
            receiver_pubkey: "receiver".to_string(),
            advertisements: vec![KeysetAdvertisement {
                mint_url: "https://mint".to_string(),
                unit: "msat".to_string(),
                keyset_ids: vec!["keyset-a".to_string()],
                in_bytes_per_millisat: 1,
                out_bytes_per_millisat: 1,
            }],
            linked_channel: None,
            session_total_in: 0,
            session_total_out: 0,
            total_paid_millisats: if paused { 0 } else { 10 },
            remaining_milli_sats: if paused { 0 } else { 10 },
            paused,
        }
    }

    #[test]
    fn relay_confirms_active_channel_matches_ids() {
        let state = DriverState {
            intended_channel_id: Some("chan-a".to_string()),
            snapshot: Some(AuthoritativeSnapshot {
                receiver_pubkey: "receiver".to_string(),
                advertisements: vec![],
                linked_channel: Some(LinkedChannelStatus {
                    channel_id: "chan-a".to_string(),
                    balance_raw: 0,
                    capacity_raw: 100,
                    unit: "msat".to_string(),
                }),
                session_total_in: 0,
                session_total_out: 0,
                total_paid_millisats: 0,
                remaining_milli_sats: 0,
                paused: true,
            }),
            ..DriverState::default()
        };

        assert!(relay_confirms_intended_channel(&state));
    }

    #[test]
    fn validate_session_pricing_allows_initial_and_matching_rates() {
        let mut established = None;
        let pricing = SessionPricing::new(1, 2);

        validate_session_pricing(&mut established, pricing).unwrap();
        validate_session_pricing(&mut established, pricing).unwrap();

        assert_eq!(established, Some(pricing));
    }

    #[test]
    fn validate_session_pricing_rejects_rate_change() {
        let mut established = Some(SessionPricing::new(1, 2));
        let err =
            validate_session_pricing(&mut established, SessionPricing::new(3, 2)).unwrap_err();

        assert_eq!(err.kind(), io::ErrorKind::InvalidData);
        assert!(err
            .to_string()
            .contains("protocol violation: relay changed active session pricing"));
    }

    #[test]
    fn validate_session_pricing_rejects_changed_rates_after_initial_baseline() {
        let mut established = None;

        validate_session_pricing(&mut established, SessionPricing::new(1, 1)).unwrap();
        let err = validate_session_pricing(&mut established, SessionPricing::new(2, 1))
            .expect_err("later pricing change should be rejected");

        assert_eq!(err.kind(), io::ErrorKind::InvalidData);
        assert!(err
            .to_string()
            .contains("protocol violation: relay changed active session pricing"));
    }

    #[test]
    fn requested_delta_targets_buffer_from_negative_remaining() {
        assert_eq!(
            requested_delta_msats(-5),
            super::TARGET_TOPUP_BUFFER_MSATS + 5
        );
    }

    #[test]
    fn estimated_remaining_uses_local_counter_deltas() {
        let counters = CleartextByteCounters::default();
        counters.note_inbound(4);
        counters.note_outbound(6);
        let state = DriverState {
            snapshot: Some(AuthoritativeSnapshot {
                session_total_in: 1,
                session_total_out: 2,
                total_paid_millisats: 20,
                ..snapshot(true)
            }),
            established_pricing: Some(SessionPricing::new(1, 1)),
            ..DriverState::default()
        };

        assert_eq!(
            super::compute_estimated_remaining(&state, &counters),
            Some(10)
        );
    }

    #[test]
    fn pre_ready_blocked_error_fires_when_session_newly_blocks_before_readiness() {
        let (ready_tx, _ready_rx) = oneshot::channel();
        let next_state = DriverState {
            funding_blocked_reason: Some(FundingBlockedReason::Acquire),
            ..DriverState::default()
        };

        let err = pre_ready_blocked_error(&Some(ready_tx), None, &next_state)
            .expect("pre-ready blocked session should fail fast");

        assert!(err
            .to_string()
            .contains("session funding blocked before readiness"));
        assert!(err.to_string().contains("Acquire"));
    }

    #[test]
    fn pre_ready_blocked_error_does_not_fire_after_readiness() {
        let next_state = DriverState {
            funding_blocked_reason: Some(FundingBlockedReason::PaymentBuild),
            ..DriverState::default()
        };

        let err = pre_ready_blocked_error(&None, None, &next_state);

        assert!(err.is_none());
    }

    #[test]
    fn exclude_on_wallet_error_marks_expected_errors() {
        assert!(exclude_on_wallet_error(&WalletError::NotFound));
        assert!(exclude_on_wallet_error(&WalletError::NotOpen));
        assert!(exclude_on_wallet_error(
            &WalletError::AttachedToDifferentSession { current: [1; 32] }
        ));
        assert!(exclude_on_wallet_error(
            &WalletError::InsufficientCapacity {
                requested: 1,
                capacity: 1
            }
        ));
        assert!(exclude_on_wallet_error(&WalletError::ChannelUnusable));
        assert!(exclude_on_wallet_error(&WalletError::OfferMismatch(
            "nope".to_string()
        )));
        assert!(!exclude_on_wallet_error(&WalletError::Backend(
            "boom".to_string()
        )));
    }

    #[test]
    fn unpaused_status_definition_is_authoritative() {
        let state = DriverState {
            snapshot: Some(snapshot(false)),
            ..DriverState::default()
        };
        assert!(!state.snapshot.as_ref().unwrap().paused);
    }

    #[test]
    fn payment_wrong_channel_keeps_intended_channel() {
        let code = ServerErrorCode::PaymentWrongChannel;
        assert!(!super::server_error_rejects_intended_channel(&code));
    }
}
