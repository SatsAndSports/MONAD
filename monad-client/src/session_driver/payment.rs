use monad_common::payment_units::{
    msats_to_raw_units as common_msats_to_raw_units,
    raw_units_to_msats as common_raw_units_to_msats,
};
use monad_common::protocol::{LinkedChannelStatus, ServerErrorCode};
use monad_common::proxy::CleartextByteCounters;
use monad_common::session::SessionPricing;
use std::io;

use crate::wallet::{MonadWallet, WalletChannel, WalletError};

use super::state::DriverState;

pub(super) fn validate_session_pricing(
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

#[cfg(test)]
pub(super) fn requested_delta_msats(
    remaining_milli_sats: i64,
    target_topup_buffer_msats: u64,
) -> u64 {
    let target_remaining = target_topup_buffer_msats as i128;
    let delta = target_remaining - remaining_milli_sats as i128;
    if delta <= 0 {
        return 0;
    }
    delta.min(u64::MAX as i128) as u64
}

fn delta_msats_to_raw_units(unit: &str, delta_msats: u64) -> Result<u64, WalletError> {
    common_msats_to_raw_units(unit, delta_msats)
        .map_err(|e| WalletError::OfferMismatch(e.to_string()))
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PaymentTopupPlan {
    NoPaymentNeeded,
    ExhaustedChannel,
    Pay {
        requested_delta_msats: u64,
        next_balance_raw: u64,
        reaches_capacity: bool,
    },
}

// Convert a local remaining-balance estimate into the next cumulative raw
// channel balance the wallet should sign.
pub(super) fn plan_payment_topup(
    estimated_remaining_msats: i64,
    target_remaining_msats: u64,
    minimum_topup_msats: u64,
    linked_channel: &LinkedChannelStatus,
) -> Result<PaymentTopupPlan, WalletError> {
    let base_delta_msats = {
        let delta = target_remaining_msats as i128 - estimated_remaining_msats as i128;
        if delta <= 0 {
            0
        } else {
            delta.min(u64::MAX as i128) as u64
        }
    };
    if base_delta_msats == 0 {
        return Ok(PaymentTopupPlan::NoPaymentNeeded);
    }

    let requested_delta_msats = base_delta_msats.max(minimum_topup_msats);
    let requested_delta_raw =
        delta_msats_to_raw_units(&linked_channel.unit, requested_delta_msats)?;
    let remaining_capacity_raw = linked_channel
        .capacity_raw
        .saturating_sub(linked_channel.balance_raw);

    if remaining_capacity_raw == 0 {
        return Ok(PaymentTopupPlan::ExhaustedChannel);
    }

    let actual_delta_raw = requested_delta_raw.min(remaining_capacity_raw);
    if actual_delta_raw == 0 {
        return Ok(PaymentTopupPlan::ExhaustedChannel);
    }

    let Some(next_balance_raw) = linked_channel.balance_raw.checked_add(actual_delta_raw) else {
        return Ok(PaymentTopupPlan::ExhaustedChannel);
    };

    let actual_delta_msats = common_raw_units_to_msats(&linked_channel.unit, actual_delta_raw)
        .map_err(|e| WalletError::OfferMismatch(e.to_string()))?;

    Ok(PaymentTopupPlan::Pay {
        requested_delta_msats: actual_delta_msats,
        next_balance_raw,
        reaches_capacity: actual_delta_raw == remaining_capacity_raw,
    })
}

pub(super) fn exclude_on_wallet_error(error: &WalletError) -> bool {
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

// Convert the locally stored signed balance into the channel's raw unit so it
// can be compared directly against relay-reported `linked_channel.balance_raw`.
pub(super) fn channel_signed_balance_raw(channel: &WalletChannel) -> Result<u64, WalletError> {
    match channel.unit.as_str() {
        "msat" => Ok(channel.current_signed_balance_msats),
        "sat" => Ok(channel.current_signed_balance_msats.div_ceil(1000)),
        other => Err(WalletError::OfferMismatch(format!(
            "unsupported unit: {other}"
        ))),
    }
}

pub(super) fn raw_amount_to_msats(unit: &str, amount_raw: u64) -> Result<u64, WalletError> {
    common_raw_units_to_msats(unit, amount_raw).map_err(|e| match e.kind() {
        io::ErrorKind::InvalidInput => WalletError::OfferMismatch(e.to_string()),
        _ => WalletError::Backend(e.to_string()),
    })
}

// The relay may report accepted linked-channel state, but it must never claim a
// raw balance above what the client has actually signed for that same channel.
pub(super) fn validate_linked_channel_balance_against_wallet(
    wallet: &dyn MonadWallet,
    state: &mut DriverState,
) -> io::Result<()> {
    let Some(intended_channel_id) = state.intended_channel_id.as_deref() else {
        return Ok(());
    };
    let Some(snapshot) = state.relay_snapshot.as_ref() else {
        return Ok(());
    };
    let Some(linked_channel) = snapshot.linked_channel.as_ref() else {
        return Ok(());
    };
    let linked_channel_id = linked_channel.channel_id.clone();
    let linked_balance_raw = linked_channel.balance_raw;
    if linked_channel_id != intended_channel_id {
        return Ok(());
    }

    let channel = wallet
        .get_channel(intended_channel_id)
        .map_err(|e| io::Error::other(format!("wallet channel lookup failed: {e}")))?;
    let local_signed_balance_raw = channel_signed_balance_raw(&channel)
        .map_err(|e| io::Error::other(format!("wallet channel balance conversion failed: {e}")))?;

    if linked_balance_raw > local_signed_balance_raw {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!(
                "protocol violation: relay reported linked balance_raw={} above client local signed balance_raw={} for channel {}",
                linked_balance_raw,
                local_signed_balance_raw,
                linked_channel_id,
            ),
        ));
    }

    Ok(())
}

pub(super) fn validate_session_status_baseline_against_local_counters(
    state: &DriverState,
    counters: &CleartextByteCounters,
) -> io::Result<()> {
    let Some(snapshot) = state.relay_snapshot.as_ref() else {
        return Ok(());
    };
    let (_local_inbound, local_outbound) = counters.snapshot();

    if snapshot.session_total_out > local_outbound {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!(
                "protocol violation: relay reported session_total_out={} above client local outbound total={}",
                snapshot.session_total_out, local_outbound,
            ),
        ));
    }

    if snapshot.total_paid_millisats > state.local_session_paid_msats {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!(
                "protocol violation: relay reported total_paid_millisats={} above client locally authorized total={}",
                snapshot.total_paid_millisats, state.local_session_paid_msats,
            ),
        ));
    }

    Ok(())
}

pub(super) fn compute_estimated_remaining(
    state: &DriverState,
    counters: &CleartextByteCounters,
) -> Option<i64> {
    let pricing = state.established_pricing?;
    let (local_inbound, local_outbound) = counters.snapshot();
    let estimated_due = pricing.amount_due_millisats(local_inbound, local_outbound);
    Some(
        (state.local_session_paid_msats as i128 - estimated_due as i128)
            .clamp(i64::MIN as i128, i64::MAX as i128) as i64,
    )
}

pub(super) fn server_error_invalidates_channel(code: &ServerErrorCode) -> bool {
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

pub(super) fn server_error_rejects_intended_channel(code: &ServerErrorCode) -> bool {
    server_error_invalidates_channel(code)
}
