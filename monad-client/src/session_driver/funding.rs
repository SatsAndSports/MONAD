use bytes::Bytes;
use monad_common::control_codec::send_json_line;
use monad_common::protocol::{ClientMessage, ServerErrorCode};
use std::io;
use std::time::{SystemTime, UNIX_EPOCH};
use tracing::{info, warn};

use crate::wallet::{select_channel, RelayPaymentOffer, WalletChannel, WalletError};

use super::payment::{
    compute_estimated_remaining, exclude_on_wallet_error, plan_payment_topup, raw_amount_to_msats,
    server_error_invalidates_channel, server_error_rejects_intended_channel, PaymentTopupPlan,
};
use super::state::{
    abandon_intended_channel, clear_control_op, exclude_channel, publish_spilman_info,
    relay_confirms_intended_channel, relay_linked_channel_id, session_is_paused,
    set_blocked_reason, set_link_in_flight, set_payment_in_flight, state_summary,
    terminate_session, ControlOpInFlight, DriverState, FundingBlockedReason, SessionDriverConfig,
};

const DEFAULT_PROVISIONED_CHANNEL_INPUT_BUDGET_MSATS: u64 = 100_000_000;

pub(super) async fn send_control_message(
    h2_send: &mut h2::SendStream<Bytes>,
    message: &ClientMessage,
) -> io::Result<()> {
    send_json_line(h2_send, message).await
}

fn choose_channel_and_offer(
    wallet: &dyn crate::wallet::MonadWallet,
    state: &DriverState,
    session_id: [u8; 32],
) -> Result<Option<(WalletChannel, RelayPaymentOffer)>, WalletError> {
    let Some(snapshot) = state.relay_snapshot.as_ref() else {
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
        let offer =
            RelayPaymentOffer::from_advertisement(snapshot.receiver_pubkey.clone(), advertisement);
        if let Some(channel) = select_channel(&channels, &offer, session_id, now) {
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
    set_link_in_flight(state, channel_id, offer);
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
                let Some(snapshot) = state.relay_snapshot.as_ref() else {
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
                    .provision_channel(&offer, DEFAULT_PROVISIONED_CHANNEL_INPUT_BUDGET_MSATS)
                {
                    Ok(channel_id) => channel_id,
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
            Some(ControlOpInFlight::Payment { .. })
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
        || estimated_remaining < config.payment_policy.target_topup_buffer_msats as i64;
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

    let (_requested_delta_msats, next_balance_raw, reaches_capacity) = match plan {
        PaymentTopupPlan::NoPaymentNeeded => return Ok(()),
        PaymentTopupPlan::ExhaustedChannel => {
            warn!(
                "{} abandoning exhausted channel {}: balance_raw={} capacity_raw={} | {}",
                config.hop_label,
                intended_channel_id,
                linked_channel.balance_raw,
                linked_channel.capacity_raw,
                state_summary(state, &config.conn.cleartext_byte_counters)
            );
            abandon_intended_channel(config, state, intended_channel_id, true).await;
            return Ok(());
        }
        PaymentTopupPlan::Pay {
            requested_delta_msats,
            next_balance_raw,
            reaches_capacity,
        } => (requested_delta_msats, next_balance_raw, reaches_capacity),
    };

    match config.wallet.build_channel_payment(
        &intended_channel_id,
        &intended_offer,
        linked_channel.balance_raw,
        next_balance_raw,
    ) {
        Ok(payment_json) => {
            let authorized_delta_msats = raw_amount_to_msats(
                &linked_channel.unit,
                next_balance_raw.saturating_sub(linked_channel.balance_raw),
            )
            .map_err(|e| io::Error::other(format!("payment delta conversion failed: {e}")))?;
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
            state.local_session_paid_msats = state
                .local_session_paid_msats
                .saturating_add(authorized_delta_msats);
            set_payment_in_flight(state, intended_channel_id);
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

/// Run one funding cycle: ensure a channel is linked, try to progress payment,
/// then ensure a channel is linked again in case payment planning abandoned the
/// previous one.
pub(super) async fn run_funding_cycle(
    config: &SessionDriverConfig,
    state: &mut DriverState,
    h2_send: &mut h2::SendStream<Bytes>,
    skip_for_resolved_payment: bool,
) -> io::Result<()> {
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
    clear_control_op(state);

    if server_error_rejects_intended_channel(&code) {
        if let Some(channel_id) = state.intended_channel_id.clone() {
            if server_error_invalidates_channel(&code) {
                let _ = config.wallet.mark_channel_unusable(&channel_id);
            }
            abandon_intended_channel(config, state, channel_id, false).await;
            return;
        }
    }

    // No intended channel was rejected, but we still need to republish Spilman
    // info because the in-flight operation was cleared above.
    publish_spilman_info(config, state).await;
}

pub(super) async fn handle_control_detached(config: &SessionDriverConfig, state: &mut DriverState) {
    terminate_session(config, state).await;
}
