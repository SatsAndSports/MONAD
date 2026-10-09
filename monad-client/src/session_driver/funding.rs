use bytes::Bytes;
use monad_common::control_codec::send_json_line;
use monad_common::control_exchange::PendingRequest;
use monad_common::protocol::{ClientMessage, PaymentOption, ServerErrorCode};
use std::collections::BTreeSet;
use std::io;
use std::time::{SystemTime, UNIX_EPOCH};
use tokio::time::{Duration, Instant};
use tracing::{info, warn};

use crate::wallet::{select_channel, RelayPaymentOffer, WalletChannel, WalletError};

pub(super) const LINK_REFRESH_RETRY_COOLDOWN: Duration = Duration::from_secs(60);
pub(super) const LINK_REFRESH_BUSY_RETRY_DELAY: Duration = Duration::from_secs(1);
pub(super) const LOCAL_KEYSET_RETRY_COOLDOWN: Duration = Duration::from_secs(60);

use super::payment::{
    channel_signed_balance_raw, compute_estimated_remaining, exclude_on_wallet_error,
    plan_payment_topup, reconcile_payment_topup, server_error_invalidates_channel,
    server_error_rejects_intended_channel, PaymentTopupPlan,
};
use super::state::{
    abandon_intended_channel, clear_channel_control_op, clear_control_op, exclude_channel,
    finish_channel_release, publish_spilman_info, relay_confirms_intended_channel,
    relay_linked_channel_id, release_is_pending, request_channel_release, session_is_paused,
    set_blocked_reason, set_link_in_flight, set_payment_in_flight, set_unlink_in_flight,
    state_summary, terminate_session, ControlOpInFlight, DriverState, FundingBlockedReason,
    SessionDriverConfig,
};

pub(super) async fn send_control_message(
    h2_send: &mut h2::SendStream<Bytes>,
    message: &ClientMessage,
) -> io::Result<()> {
    tokio::time::timeout(
        super::runtime::HEARTBEAT_TIMEOUT,
        send_json_line(h2_send, message),
    )
    .await
    .map_err(|_| {
        io::Error::new(
            io::ErrorKind::TimedOut,
            "control send exceeded heartbeat timeout",
        )
    })?
}

fn choose_channel_and_offer(
    wallet: &dyn crate::wallet::MonadWallet,
    state: &DriverState,
    session_id: [u8; 32],
) -> Result<Option<(WalletChannel, RelayPaymentOffer)>, WalletError> {
    let Some(snapshot) = state.relay_snapshot.as_ref() else {
        return Ok(None);
    };
    let Some(versions) = state
        .cashu_spilman_keyset_versions
        .as_ref()
        .filter(|versions| !versions.is_empty())
    else {
        return Ok(None);
    };
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
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
        let offer = RelayPaymentOffer::from_advertisement(
            snapshot.receiver_pubkey.clone(),
            advertisement,
            versions,
        );
        if let Some(channel) = select_channel(&channels, &offer, session_id, now) {
            return Ok(Some((channel, offer)));
        }
    }
    Ok(None)
}

fn provisioning_offer_is_unavailable(error: &WalletError) -> bool {
    // These are the wallet's explicitly safe offer-local outcomes. Generic
    // backend failures can follow a reservation or ambiguous submission, so they
    // must stop traversal rather than funding a different offer.
    matches!(
        error,
        WalletError::NoCompatibleActiveKeyset { .. }
            | WalletError::InsufficientLooseProofFunds { .. }
            | WalletError::InputKeysetMetadataUnavailable { .. }
            | WalletError::TooManyInputProofs { .. }
            | WalletError::ProvisioningOfferUnavailable { .. }
            | WalletError::ProvisioningPreflight { .. }
    )
}

fn provision_from_advertisements<F>(
    receiver_pubkey: &str,
    advertisements: &[PaymentOption],
    versions: &BTreeSet<String>,
    mut provision: F,
) -> Result<Option<(String, RelayPaymentOffer)>, WalletError>
where
    F: FnMut(&RelayPaymentOffer) -> Result<String, WalletError>,
{
    let mut unavailable = None;
    for advertisement in advertisements {
        let offer = RelayPaymentOffer::from_advertisement(
            receiver_pubkey.to_string(),
            advertisement,
            versions,
        );
        match provision(&offer) {
            Ok(channel_id) => return Ok(Some((channel_id, offer))),
            Err(error) if provisioning_offer_is_unavailable(&error) => unavailable = Some(error),
            Err(error) => return Err(error),
        }
    }
    match unavailable {
        Some(error) => Err(error),
        None => Ok(None),
    }
}

async fn send_channel_link(
    config: &SessionDriverConfig,
    state: &mut DriverState,
    h2_send: &mut h2::SendStream<Bytes>,
    channel: WalletChannel,
    offer: RelayPaymentOffer,
    payment_json: String,
) -> io::Result<()> {
    let channel_id = channel.channel_id.clone();
    info!(
        "{} sending ChannelLink for {} | {}",
        config.hop_label,
        channel_id,
        state_summary(state, &config.conn.cleartext_byte_counters)
    );
    state.exchange.enqueue(PendingRequest::Link {
        channel_id: channel_id.clone(),
    })?;
    send_control_message(h2_send, &ClientMessage::ChannelLink { payment_json }).await?;
    set_link_in_flight(state, channel_id.clone(), channel.keyset_id, offer);
    if let Some((owner, hop)) = &config.management {
        hop.linking(owner, channel_id);
    }
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
                FundingBlockedReason::ChannelAcquire,
                &error.to_string(),
            )?;
            return Ok(false);
        }
        if exclude_on_wallet_error(&error) {
            exclude_channel(state, &channel_id);
        }
        return Ok(true);
    }

    match config.wallet.build_link_request(&channel_id, &offer) {
        Ok(payment_json) => {
            send_channel_link(config, state, h2_send, channel, offer, payment_json).await?;
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
                    FundingBlockedReason::LinkRequestBuild,
                    &error.to_string(),
                )?;
                return Ok(false);
            }
            if exclude_on_wallet_error(&error) {
                exclude_channel(state, &channel_id);
            }
            Ok(true)
        }
    }
}

pub(super) async fn maybe_ensure_linked_channel(
    config: &SessionDriverConfig,
    state: &mut DriverState,
    h2_send: &mut h2::SendStream<Bytes>,
) -> io::Result<()> {
    if state.terminated || state.funding_blocked_reason.is_some() {
        return Ok(());
    }
    if !session_is_paused(state)
        && compute_estimated_remaining(state, &config.conn.cleartext_byte_counters)?
            .is_none_or(|remaining| remaining > 0)
    {
        return Ok(());
    }
    let Some(versions) = state
        .cashu_spilman_keyset_versions
        .as_ref()
        .filter(|versions| !versions.is_empty())
        .cloned()
    else {
        return Ok(());
    };
    if state.control_op_in_flight.is_some() {
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
    if state
        .funding_retry_not_before
        .is_some_and(|deadline| Instant::now() < deadline)
    {
        return Ok(());
    }
    state.funding_retry_not_before = None;

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
                            FundingBlockedReason::ChannelAcquire,
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
                let Some((receiver_pubkey, advertisements)) =
                    state.relay_snapshot.as_ref().map(|snapshot| {
                        (
                            snapshot.receiver_pubkey.clone(),
                            snapshot.advertisements.clone(),
                        )
                    })
                else {
                    return Ok(());
                };
                if let Some((owner, hop)) = &config.management {
                    if !hop.begin_provisioning(owner) {
                        return Ok(());
                    }
                }
                let selected = provision_from_advertisements(
                    &receiver_pubkey,
                    &advertisements,
                    &versions,
                    |offer| {
                        info!(
                            "{} provisioning new channel for mint={} unit={} | {}",
                            config.hop_label,
                            offer.mint_url,
                            offer.unit,
                            state_summary(state, &config.conn.cleartext_byte_counters)
                        );
                        config.wallet.provision_channel(
                            offer,
                            config.payment_policy.channel_funding_token_target_msats,
                        )
                    },
                );
                if let Some((owner, hop)) = &config.management {
                    hop.provisioning_finished(owner);
                }
                let (channel_id, offer) = match selected {
                    Ok(Some(selected)) => selected,
                    Ok(None) => {
                        if let Some((owner, hop)) = &config.management {
                            if !owner.controls().automatic_provisioning {
                                hop.safe_provisioning_failure(owner);
                            }
                        }
                        return Ok(());
                    }
                    Err(error) if provisioning_offer_is_unavailable(&error) => {
                        if let Some((owner, hop)) = &config.management {
                            if !owner.controls().automatic_provisioning {
                                hop.safe_provisioning_failure(owner);
                                return Ok(());
                            }
                        }
                        if state.ready_signaled {
                            warn!(
                                "{} deferring funding after advertised offers were unavailable: {} | {}",
                                config.hop_label,
                                error,
                                state_summary(state, &config.conn.cleartext_byte_counters)
                            );
                            state.funding_retry_not_before =
                                Some(Instant::now() + LOCAL_KEYSET_RETRY_COOLDOWN);
                        } else {
                            set_blocked_reason(
                                config,
                                state,
                                FundingBlockedReason::ChannelAcquire,
                                &error.to_string(),
                            )?;
                        }
                        return Ok(());
                    }
                    Err(error) => {
                        if matches!(error, WalletError::Backend(_)) {
                            set_blocked_reason(
                                config,
                                state,
                                FundingBlockedReason::ChannelAcquire,
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
                                FundingBlockedReason::ChannelAcquire,
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
                        FundingBlockedReason::ChannelAcquire,
                        &error.to_string(),
                    )?;
                }
                return Ok(());
            }
        }
    }
}

/// The relay has politely asked to retire a linked channel. Stop creating new
/// payments on it, persist it as unusable for future funding, and unlink it as
/// soon as any in-flight payment is acknowledged. Remaining session credit
/// stays intact; the funding cycle may link a replacement afterward.
pub(super) async fn apply_channel_release_requested(
    config: &SessionDriverConfig,
    state: &mut DriverState,
    h2_send: &mut h2::SendStream<Bytes>,
    channel_id: String,
) -> io::Result<()> {
    info!(
        "{} relay requested channel release for {} | {}",
        config.hop_label,
        channel_id,
        state_summary(state, &config.conn.cleartext_byte_counters)
    );
    request_channel_release(state, &channel_id);
    // Persist that this channel must never be reused for future funding. The
    // channel records and refund recovery data remain intact; unusable does
    // not mean closed.
    if let Err(error) = config.wallet.mark_channel_unusable(&channel_id) {
        warn!(
            "{} failed to mark retiring channel {} unusable: {error}",
            config.hop_label, channel_id
        );
    }
    if let Some((owner, _hop)) = &config.management {
        owner.events.record(
            "channel_release_requested",
            serde_json::json!({
                "session_id": hex::encode(config.conn.session_id),
                "channel_id": channel_id,
            }),
        );
        owner.notify();
    }
    maybe_send_channel_unlink(config, state, h2_send).await
}

/// Send ID-only `ChannelUnlink` for a retirement-pending channel once no
/// payment or link operation on it is still in flight. The relay verifies
/// authoritative ownership using its stored state; the request carries no
/// final-balance claim.
pub(super) async fn maybe_send_channel_unlink(
    config: &SessionDriverConfig,
    state: &mut DriverState,
    h2_send: &mut h2::SendStream<Bytes>,
) -> io::Result<()> {
    if state.terminated || state.control_op_in_flight.is_some() {
        return Ok(());
    }
    let Some(intended) = state.intended_channel_id.clone() else {
        return Ok(());
    };
    if !release_is_pending(state, &intended) {
        return Ok(());
    }
    info!(
        "{} sending ChannelUnlink for {} | {}",
        config.hop_label,
        intended,
        state_summary(state, &config.conn.cleartext_byte_counters)
    );
    state.exchange.enqueue(PendingRequest::Unlink {
        channel_id: intended.clone(),
    })?;
    send_control_message(
        h2_send,
        &ClientMessage::ChannelUnlink {
            channel_id: intended.clone(),
        },
    )
    .await?;
    set_unlink_in_flight(state, intended);
    Ok(())
}

/// The authoritative unlink response status removed the pending channel. The
/// relay has released ownership; abandon the local intended channel state. The
/// session keeps its remaining credit and may link a replacement according to
/// provisioning policy.
pub(super) async fn apply_channel_unlinked(
    config: &SessionDriverConfig,
    state: &mut DriverState,
    channel_id: String,
) {
    info!(
        "{} relay confirmed unlink of channel {} | {}",
        config.hop_label,
        channel_id,
        state_summary(state, &config.conn.cleartext_byte_counters)
    );
    finish_channel_release(state, &channel_id);
    clear_channel_control_op(state, &channel_id);
    if let Some((owner, _hop)) = &config.management {
        owner.events.record(
            "channel_unlinked",
            serde_json::json!({
                "session_id": hex::encode(config.conn.session_id),
                "channel_id": channel_id,
            }),
        );
        owner.notify();
    }
    if state.intended_channel_id.as_deref() == Some(channel_id.as_str()) {
        abandon_intended_channel(config, state, channel_id, true).await;
    }
}

pub(super) async fn maybe_progress_payment(
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
            Some(ControlOpInFlight::Payment { .. }) | Some(ControlOpInFlight::Unlink { .. })
        )
    {
        return Ok(());
    }

    let Some(snapshot) = state.relay_snapshot.as_ref() else {
        return Ok(());
    };
    let Some(linked_channel) = snapshot.linked_channel.as_ref() else {
        return Ok(());
    };
    let Some(intended_channel_id) = state.intended_channel_id.clone() else {
        return Ok(());
    };
    // A channel whose release the relay has requested receives no new payments.
    // The unlink handshake runs through `maybe_send_channel_unlink` once the
    // in-flight operation is acknowledged.
    if release_is_pending(state, &intended_channel_id) {
        return Ok(());
    }
    let Some(intended_offer) = state.intended_offer.clone() else {
        return Ok(());
    };
    let Some(estimated_remaining) =
        compute_estimated_remaining(state, &config.conn.cleartext_byte_counters)?
    else {
        return Ok(());
    };
    let should_pay = snapshot.paused
        || snapshot.remaining_milli_sats <= 0
        || i128::from(estimated_remaining)
            < i128::from(config.payment_policy.target_topup_buffer_msats);
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

    let plan = match plan_payment_topup(
        estimated_remaining,
        config.payment_policy.target_topup_buffer_msats,
        config.payment_policy.minimum_topup_msats,
        linked_channel,
    ) {
        Ok(plan) => plan,
        Err(error) => {
            warn!(
                "{} abandoning channel {} after payment plan failure: {} | {}",
                config.hop_label,
                intended_channel_id,
                error,
                state_summary(state, &config.conn.cleartext_byte_counters)
            );
            abandon_intended_channel(config, state, intended_channel_id, true).await;
            return Ok(());
        }
    };

    let (_requested_delta_msats, planned_next_balance_raw, _reaches_capacity) = match plan {
        PaymentTopupPlan::NoPaymentNeeded => return Ok(()),
        PaymentTopupPlan::ExhaustedChannel if estimated_remaining > 0 => return Ok(()),
        PaymentTopupPlan::ExhaustedChannel => {
            warn!(
                "{} abandoning exhausted channel {}: balance_raw={} capacity_raw={} | {}",
                config.hop_label,
                intended_channel_id,
                linked_channel.balance_raw,
                linked_channel.capacity_raw,
                state_summary(state, &config.conn.cleartext_byte_counters)
            );
            let _ = config.wallet.mark_channel_unusable(&intended_channel_id);
            abandon_intended_channel(config, state, intended_channel_id, true).await;
            return Ok(());
        }
        PaymentTopupPlan::Pay {
            requested_delta_msats,
            next_balance_raw,
            reaches_capacity,
        } => (requested_delta_msats, next_balance_raw, reaches_capacity),
    };

    let signed_balance_raw = config
        .wallet
        .get_channel(&intended_channel_id)
        .and_then(|channel| channel_signed_balance_raw(&channel))
        .map_err(|e| io::Error::other(format!("wallet channel balance lookup failed: {e}")))?;
    let (next_balance_raw, authorized_delta_msats, reaches_capacity) =
        reconcile_payment_topup(planned_next_balance_raw, signed_balance_raw, linked_channel)
            .map_err(|e| io::Error::other(format!("payment delta conversion failed: {e}")))?;

    // This is a local numeric preflight, before the wallet signs/persists.
    let next_local_session_paid_msats = state
        .local_session_paid_msats
        .checked_add(authorized_delta_msats)
        .ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                "local session payment total exceeds u64 range",
            )
        })?;

    let minimum_increment_msats = monad_common::payment_units::raw_units_to_msats(
        &linked_channel.unit,
        next_balance_raw - signed_balance_raw,
    )?;
    match config.wallet.build_channel_payment(
        &intended_channel_id,
        &intended_offer,
        linked_channel.balance_raw,
        next_balance_raw,
    ) {
        Ok(payment_json) => {
            state.exchange.enqueue(PendingRequest::Payment {
                channel_id: intended_channel_id.clone(),
                balance_raw: next_balance_raw,
                minimum_increment_msats,
            })?;
            info!(
                "{} sending ChannelPayment for {}: remaining={} target={} reaches_capacity={} next_balance_raw={} | {}",
                config.hop_label,
                intended_channel_id,
                estimated_remaining,
                config.payment_policy.target_topup_buffer_msats,
                reaches_capacity,
                next_balance_raw,
                state_summary(state, &config.conn.cleartext_byte_counters)
            );
            send_control_message(h2_send, &ClientMessage::ChannelPayment { payment_json }).await?;
            state.local_session_paid_msats = next_local_session_paid_msats;
            set_payment_in_flight(state, intended_channel_id.clone(), next_balance_raw);
            if let Some((owner, hop)) = &config.management {
                hop.paying(owner, intended_channel_id);
            }
        }
        Err(error) => {
            if matches!(error, WalletError::Backend(_)) {
                set_blocked_reason(
                    config,
                    state,
                    FundingBlockedReason::PaymentRequestBuild,
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

/// Run one funding cycle: progress any pending cooperative unlink first, then
/// ensure a channel is linked, try to progress payment, then ensure a channel
/// is linked again in case payment planning abandoned the previous one.
pub(super) async fn run_funding_cycle(
    config: &SessionDriverConfig,
    state: &mut DriverState,
    h2_send: &mut h2::SendStream<Bytes>,
    skip_for_resolved_payment: bool,
) -> io::Result<()> {
    // Funding remains deliberately serialized; the shared exchange supports
    // the five-request window for pipelined callers without guessing replies.
    if !state.exchange.is_empty() {
        return Ok(());
    }
    maybe_send_channel_unlink(config, state, h2_send).await?;
    maybe_ensure_linked_channel(config, state, h2_send).await?;
    maybe_progress_payment(config, state, h2_send, skip_for_resolved_payment).await?;
    maybe_ensure_linked_channel(config, state, h2_send).await?;
    Ok(())
}

pub(super) async fn apply_channel_evicted(
    config: &SessionDriverConfig,
    state: &mut DriverState,
    channel_id: String,
) {
    exclude_channel(state, &channel_id);
    abandon_intended_channel(config, state, channel_id, false).await;
}

pub(super) async fn apply_server_error(
    config: &SessionDriverConfig,
    state: &mut DriverState,
    code: ServerErrorCode,
) {
    // Rejection does not revoke a signed payment. Retain the pessimistic local
    // payment record: the relay may still claim those funds. The runtime ends
    // the session after recording any channel-specific consequences below.
    clear_control_op(state);

    if code == ServerErrorCode::ChannelAdmissionDisabled {
        // Retain the funded channel and retry its link at a bounded cadence.
        // Admission policy never authorizes provisioning a replacement.
        state.funding_retry_not_before = Some(Instant::now() + crate::admission::RETRY_INTERVAL);
        if let Some((owner, hop)) = &config.management {
            hop.relay_admission_refused(owner);
        }
        publish_spilman_info(config, state).await;
        return;
    }

    if defer_link_after_refresh_error(state, &code, Instant::now()) {
        publish_spilman_info(config, state).await;
        return;
    }

    if code == ServerErrorCode::ChannelUnlinkRejected {
        // Unlink responses are ordered and nonfatal. The relay could not
        // commit this release under its ownership authority, so do not claim
        // success locally. Abandon the intended channel; if it is still
        // relay-owned, ordinary detach/reconnect cleanup can release it later.
        warn!(
            "{} channel unlink rejected | {}",
            config.hop_label,
            state_summary(state, &config.conn.cleartext_byte_counters)
        );
        if let Some(channel_id) = state.intended_channel_id.clone() {
            finish_channel_release(state, &channel_id);
            let _ = config.wallet.mark_channel_unusable(&channel_id);
            abandon_intended_channel(config, state, channel_id, true).await;
        }
        return;
    }

    if server_error_rejects_intended_channel(&code) {
        if let Some(channel_id) = state.intended_channel_id.clone() {
            if server_error_invalidates_channel(&code) {
                let _ = config.wallet.mark_channel_unusable(&channel_id);
            }
            let exclude_for_session = matches!(
                code,
                ServerErrorCode::LinkInvalidZeroBalanceSignature
                    | ServerErrorCode::ChannelEvictedFromSession
                    | ServerErrorCode::ChannelRetiredAtRelay
                    | ServerErrorCode::LinkChannelRetired
            );
            abandon_intended_channel(config, state, channel_id, exclude_for_session).await;
            return;
        }
    }

    // No intended channel was rejected, but we still need to republish Spilman
    // info because the in-flight operation was cleared above.
    publish_spilman_info(config, state).await;
}

pub(super) fn link_refresh_retry_delay(code: &ServerErrorCode) -> Option<Duration> {
    match code {
        ServerErrorCode::LinkKeysetRefreshRateLimited
        | ServerErrorCode::LinkKeysetRefreshFailed => Some(LINK_REFRESH_RETRY_COOLDOWN),
        ServerErrorCode::LinkKeysetRefreshBusy => Some(LINK_REFRESH_BUSY_RETRY_DELAY),
        _ => None,
    }
}

pub(super) fn defer_link_after_refresh_error(
    state: &mut DriverState,
    code: &ServerErrorCode,
    now: Instant,
) -> bool {
    let Some(delay) = link_refresh_retry_delay(code) else {
        return false;
    };
    state.funding_retry_not_before = Some(now + delay);
    true
}

pub(super) async fn handle_control_detached(config: &SessionDriverConfig, state: &mut DriverState) {
    terminate_session(config, state).await;
}

#[cfg(test)]
mod tests {
    use super::*;

    fn advertisement(mint_url: &str) -> PaymentOption {
        PaymentOption {
            funding_keyset_recovery_window_secs: 86_400,
            minimum_channel_lifetime_secs: 3600,
            mint_url: mint_url.to_string(),
            unit: "sat".to_string(),
            in_bytes_per_millisat: 1,
            out_bytes_per_millisat: 1,
        }
    }

    #[test]
    fn provisioning_tries_later_offer_after_preflight_insufficient_funds() {
        let advertisements = [
            advertisement("https://mint-a"),
            advertisement("https://mint-b"),
        ];
        let versions = BTreeSet::from(["v2".to_string()]);
        let mut attempted = Vec::new();

        let selected =
            provision_from_advertisements("receiver", &advertisements, &versions, |offer| {
                attempted.push(offer.mint_url.clone());
                if offer.mint_url == "https://mint-a" {
                    Err(WalletError::InsufficientLooseProofFunds {
                        mint_url: offer.mint_url.clone(),
                        unit: offer.unit.clone(),
                        requested_raw: 10,
                        available_raw: 5,
                    })
                } else {
                    Ok("channel-b".to_string())
                }
            })
            .unwrap()
            .unwrap();

        assert_eq!(attempted, ["https://mint-a", "https://mint-b"]);
        assert_eq!(selected.0, "channel-b");
        assert_eq!(selected.1.mint_url, "https://mint-b");
    }

    #[test]
    fn provisioning_does_not_try_later_offer_after_ambiguous_error() {
        let advertisements = [
            advertisement("https://mint-a"),
            advertisement("https://mint-b"),
        ];
        let versions = BTreeSet::from(["v2".to_string()]);
        let mut attempted = Vec::new();

        let error =
            provision_from_advertisements("receiver", &advertisements, &versions, |offer| {
                attempted.push(offer.mint_url.clone());
                Err(WalletError::Backend("input may be spent".to_string()))
            })
            .unwrap_err();

        assert_eq!(attempted, ["https://mint-a"]);
        assert_eq!(
            error,
            WalletError::Backend("input may be spent".to_string())
        );
    }

    #[test]
    fn provisioning_tries_later_offer_after_typed_preflight_error() {
        let advertisements = [
            advertisement("https://mint-a"),
            advertisement("https://mint-b"),
        ];
        let versions = BTreeSet::from(["v2".to_string()]);
        let mut attempted = Vec::new();

        let selected =
            provision_from_advertisements("receiver", &advertisements, &versions, |offer| {
                attempted.push(offer.mint_url.clone());
                if offer.mint_url == "https://mint-a" {
                    Err(WalletError::ProvisioningPreflight {
                        mint_url: offer.mint_url.clone(),
                        unit: offer.unit.clone(),
                        reason: "malformed cached input keyset metadata".to_string(),
                    })
                } else {
                    Ok("channel-b".to_string())
                }
            })
            .unwrap()
            .unwrap();

        assert_eq!(attempted, ["https://mint-a", "https://mint-b"]);
        assert_eq!(selected.0, "channel-b");
    }
}
