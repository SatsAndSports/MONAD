use crate::wallet::{RelayPaymentOffer, WalletError};
use monad_common::protocol::{
    ClientMessage, KeysetAdvertisement, LinkedChannelStatus, ServerErrorCode,
};
use monad_common::session::{SessionPricing, SessionSpilmanInfo};
use std::collections::BTreeSet;

pub(crate) const DEFAULT_PROVISIONED_CHANNEL_CAPACITY_MSATS: u64 = 100_000_000;
pub(crate) const TARGET_TOPUP_BUFFER_MSATS: u64 = 10_000_000;

#[derive(Debug, Clone)]
pub(crate) struct SessionSnapshot {
    pub receiver_pubkey: String,
    pub advertisements: Vec<KeysetAdvertisement>,
    pub linked_channel: Option<LinkedChannelStatus>,
    pub remaining_milli_sats: i64,
    pub paused: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum ControlOpInFlight {
    Link { channel_id: String },
    Payment { channel_id: String },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum FundingBlockedReason {
    Acquire,
    LinkBuild,
    PaymentBuild,
}

#[derive(Debug, Clone)]
pub(crate) struct ClientSessionState {
    pub snapshot: Option<SessionSnapshot>,
    pub active_channel_id: Option<String>,
    pub active_offer: Option<RelayPaymentOffer>,
    pub session_excluded_channels: BTreeSet<String>,
    pub control_op_in_flight: Option<ControlOpInFlight>,
    pub funding_blocked_reason: Option<FundingBlockedReason>,
    pub terminated: bool,
}

impl ClientSessionState {
    pub(crate) fn new() -> Self {
        Self {
            snapshot: None,
            active_channel_id: None,
            active_offer: None,
            session_excluded_channels: BTreeSet::new(),
            control_op_in_flight: None,
            funding_blocked_reason: None,
            terminated: false,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum WalletOpKind {
    PreparePayment { channel_id: String },
}

#[derive(Debug, Clone)]
pub(crate) enum ClientSessionEvent {
    SessionStatusReceived {
        snapshot: SessionSnapshot,
        pricing: SessionPricing,
    },
    ChannelPaymentBuilt {
        payment_json: String,
    },
    WalletOperationFailed {
        kind: WalletOpKind,
        error: WalletError,
    },
    ChannelEvicted {
        channel_id: String,
    },
    ServerError {
        code: ServerErrorCode,
        message: String,
    },
    ControlDetached,
}

#[derive(Debug, Clone)]
pub(crate) enum ClientSessionEffect {
    UpdatePricingHandle(SessionPricing),
    UpdateSpilmanInfoHandle(Option<SessionSpilmanInfo>),
    BuildChannelPayment {
        channel_id: String,
        offer: RelayPaymentOffer,
        latest_server_balance_raw: u64,
        next_balance_raw: u64,
    },
    DetachChannel {
        channel_id: String,
    },
    MarkChannelUnusable {
        channel_id: String,
    },
    SendControl(ClientMessage),
    SignalUsable,
    EndSession,
}

pub(crate) fn step(
    mut state: ClientSessionState,
    event: ClientSessionEvent,
) -> (ClientSessionState, Vec<ClientSessionEffect>) {
    if state.terminated {
        return (state, Vec::new());
    }

    let effects = match event {
        ClientSessionEvent::SessionStatusReceived { snapshot, pricing } => {
            let resolved_control_op = clear_resolved_control_op_on_status(&mut state);
            let resolved_payment =
                matches!(resolved_control_op, Some(ControlOpInFlight::Payment { .. }));
            state.snapshot = Some(snapshot.clone());
            let mut effects = vec![ClientSessionEffect::UpdatePricingHandle(pricing)];
            if !snapshot.paused {
                effects.push(ClientSessionEffect::SignalUsable);
            }

            effects.push(ClientSessionEffect::UpdateSpilmanInfoHandle(
                spilman_info_for(snapshot_for(&state), state.active_offer.as_ref()),
            ));

            if let Some(linked_channel) = snapshot.linked_channel.clone() {
                if state.active_channel_id.as_deref() == Some(linked_channel.channel_id.as_str())
                    && state.active_offer.is_some()
                    && !resolved_payment
                {
                    effects.extend(payment_progress_effects(&mut state, linked_channel));
                }
            }

            effects
        }
        ClientSessionEvent::ChannelPaymentBuilt { payment_json } => {
            if let Some(channel_id) = state.active_channel_id.clone() {
                state.control_op_in_flight = Some(ControlOpInFlight::Payment { channel_id });
            }
            vec![ClientSessionEffect::SendControl(
                ClientMessage::ChannelPayment { payment_json },
            )]
        }
        ClientSessionEvent::WalletOperationFailed { kind, error } => {
            clear_failed_control_op(&mut state, &kind);
            match kind {
                WalletOpKind::PreparePayment { ref channel_id } => {
                    if exclude_on_wallet_error(&error) {
                        state.session_excluded_channels.insert(channel_id.clone());
                    }
                    if state.active_channel_id.as_deref() == Some(channel_id.as_str()) {
                        state.active_channel_id = None;
                        state.active_offer = None;
                    }
                }
            }

            if let Some(blocked_reason) = blocked_reason_for_wallet_failure(&kind, &error) {
                state.funding_blocked_reason = Some(blocked_reason);
            }

            let effects = vec![ClientSessionEffect::UpdateSpilmanInfoHandle(
                spilman_info_for(snapshot_for(&state), state.active_offer.as_ref()),
            )];
            effects
        }
        ClientSessionEvent::ChannelEvicted { channel_id } => {
            let mut effects = Vec::new();
            clear_channel_control_op(&mut state, &channel_id);
            state.session_excluded_channels.insert(channel_id.clone());
            if state.active_channel_id.as_deref() == Some(channel_id.as_str()) {
                state.active_channel_id = None;
                state.active_offer = None;
                effects.push(ClientSessionEffect::DetachChannel { channel_id });
            }
            effects.push(ClientSessionEffect::UpdateSpilmanInfoHandle(
                spilman_info_for(snapshot_for(&state), state.active_offer.as_ref()),
            ));
            effects
        }
        ClientSessionEvent::ServerError { code, message } => {
            let _ = &message;
            clear_resolved_control_op_on_error(&mut state);
            let mut effects = Vec::new();
            if should_abandon_active_channel_on_error(&code) {
                if let Some(active_channel_id) = state.active_channel_id.take() {
                    if is_channel_invalidating_error(&code) {
                        effects.push(ClientSessionEffect::MarkChannelUnusable {
                            channel_id: active_channel_id,
                        });
                    } else {
                        effects.push(ClientSessionEffect::DetachChannel {
                            channel_id: active_channel_id,
                        });
                    }
                    state.active_offer = None;
                }
            }
            effects.push(ClientSessionEffect::UpdateSpilmanInfoHandle(
                spilman_info_for(snapshot_for(&state), state.active_offer.as_ref()),
            ));
            effects
        }
        ClientSessionEvent::ControlDetached => {
            state.terminated = true;
            state.control_op_in_flight = None;
            state.funding_blocked_reason = None;
            let mut effects = Vec::new();
            if let Some(active_channel_id) = state.active_channel_id.take() {
                effects.push(ClientSessionEffect::DetachChannel {
                    channel_id: active_channel_id,
                });
            }
            state.active_offer = None;
            effects.push(ClientSessionEffect::EndSession);
            effects
        }
    };

    (state, effects)
}

fn payment_progress_effects(
    state: &mut ClientSessionState,
    linked_channel: LinkedChannelStatus,
) -> Vec<ClientSessionEffect> {
    if state.funding_blocked_reason.is_some()
        || matches!(
            state.control_op_in_flight,
            Some(ControlOpInFlight::Payment { .. })
        )
    {
        return Vec::new();
    }
    let Some(snapshot) = snapshot_for(state) else {
        return Vec::new();
    };
    let Some(active_channel_id) = state.active_channel_id.clone() else {
        return Vec::new();
    };
    let Some(active_offer) = state.active_offer.clone() else {
        return Vec::new();
    };
    if snapshot.remaining_milli_sats > 0 {
        return Vec::new();
    }

    let requested_delta_msats = requested_delta_msats(snapshot.remaining_milli_sats);
    if requested_delta_msats == 0 {
        return Vec::new();
    }

    let requested_delta_raw = delta_msats_to_raw_units(&linked_channel.unit, requested_delta_msats);
    let Some(next_balance_raw) = linked_channel.balance_raw.checked_add(requested_delta_raw) else {
        return Vec::new();
    };

    if next_balance_raw > linked_channel.capacity_raw {
        state
            .session_excluded_channels
            .insert(active_channel_id.clone());
        state.active_channel_id = None;
        state.active_offer = None;
        return vec![
            ClientSessionEffect::DetachChannel {
                channel_id: active_channel_id,
            },
            ClientSessionEffect::UpdateSpilmanInfoHandle(spilman_info_for(
                snapshot_for(state),
                state.active_offer.as_ref(),
            )),
        ];
    }

    vec![ClientSessionEffect::BuildChannelPayment {
        channel_id: active_channel_id,
        offer: active_offer,
        latest_server_balance_raw: linked_channel.balance_raw,
        next_balance_raw,
    }]
}

fn snapshot_for(state: &ClientSessionState) -> Option<&SessionSnapshot> {
    state.snapshot.as_ref()
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

fn spillman_info_from_offer(offer: &RelayPaymentOffer) -> SessionSpilmanInfo {
    SessionSpilmanInfo {
        receiver_pubkey: offer.receiver_pubkey.clone(),
        mint_url: offer.mint_url.clone(),
        unit: offer.unit.clone(),
        keyset_id: offer
            .accepted_keyset_ids
            .first()
            .cloned()
            .unwrap_or_default(),
        keyset_info_json: String::new(),
    }
}

fn spilman_info_for(
    snapshot: Option<&SessionSnapshot>,
    active_offer: Option<&RelayPaymentOffer>,
) -> Option<SessionSpilmanInfo> {
    if let Some(offer) = active_offer {
        return Some(spillman_info_from_offer(offer));
    }
    let snapshot = snapshot?;
    let advertisement = snapshot.advertisements.first()?;
    Some(spillman_info_from_offer(
        &RelayPaymentOffer::from_advertisement(snapshot.receiver_pubkey.clone(), advertisement),
    ))
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

fn clear_resolved_control_op_on_status(
    state: &mut ClientSessionState,
) -> Option<ControlOpInFlight> {
    match &state.control_op_in_flight {
        Some(ControlOpInFlight::Link { .. }) | Some(ControlOpInFlight::Payment { .. }) => {
            state.control_op_in_flight.take()
        }
        _ => None,
    }
}

fn clear_resolved_control_op_on_error(state: &mut ClientSessionState) {
    clear_resolved_control_op_on_status(state);
}

fn clear_failed_control_op(state: &mut ClientSessionState, kind: &WalletOpKind) {
    match kind {
        WalletOpKind::PreparePayment { channel_id } => {
            clear_channel_control_op(state, channel_id);
        }
    }
}

fn clear_channel_control_op(state: &mut ClientSessionState, channel_id: &str) {
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

fn blocked_reason_for_wallet_failure(
    kind: &WalletOpKind,
    error: &WalletError,
) -> Option<FundingBlockedReason> {
    if !matches!(error, WalletError::Backend(_)) {
        return None;
    }

    Some(match kind {
        WalletOpKind::PreparePayment { .. } => FundingBlockedReason::PaymentBuild,
    })
}

fn should_abandon_active_channel_on_error(code: &ServerErrorCode) -> bool {
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

pub(crate) fn is_channel_invalidating_error(code: &ServerErrorCode) -> bool {
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

#[cfg(test)]
mod tests {
    use super::{
        step, ClientSessionEffect, ClientSessionEvent, ClientSessionState, ControlOpInFlight,
        FundingBlockedReason, SessionSnapshot, WalletOpKind,
    };
    use crate::wallet::{RelayPaymentOffer, WalletError};
    use monad_common::protocol::{
        ClientMessage, KeysetAdvertisement, LinkedChannelStatus, ServerErrorCode,
    };
    use monad_common::session::SessionPricing;

    fn snapshot(paused: bool) -> SessionSnapshot {
        SessionSnapshot {
            receiver_pubkey: "receiver".to_string(),
            advertisements: vec![KeysetAdvertisement {
                mint_url: "https://mint".to_string(),
                unit: "msat".to_string(),
                keyset_ids: vec!["keyset-a".to_string()],
                in_bytes_per_millisat: 1,
                out_bytes_per_millisat: 1,
            }],
            linked_channel: None,
            remaining_milli_sats: if paused { 0 } else { 10 },
            paused,
        }
    }

    fn offer() -> RelayPaymentOffer {
        RelayPaymentOffer {
            receiver_pubkey: "receiver".to_string(),
            mint_url: "https://mint".to_string(),
            unit: "msat".to_string(),
            accepted_keyset_ids: vec!["keyset-a".to_string()],
            in_bytes_per_millisat: 1,
            out_bytes_per_millisat: 1,
        }
    }

    #[test]
    fn unpaused_status_signals_usable() {
        let (_state, effects) = step(
            ClientSessionState::new(),
            ClientSessionEvent::SessionStatusReceived {
                snapshot: snapshot(false),
                pricing: SessionPricing::new(1, 1),
            },
        );

        assert!(effects
            .iter()
            .any(|effect| matches!(effect, ClientSessionEffect::SignalUsable)));
    }

    #[test]
    fn channel_payment_built_sets_payment_in_flight() {
        let mut state = ClientSessionState::new();
        state.active_channel_id = Some("chan-a".to_string());

        let (state, effects) = step(
            state,
            ClientSessionEvent::ChannelPaymentBuilt {
                payment_json: "{}".to_string(),
            },
        );

        assert_eq!(
            state.control_op_in_flight,
            Some(ControlOpInFlight::Payment {
                channel_id: "chan-a".to_string(),
            })
        );
        assert!(matches!(
            effects.as_slice(),
            [ClientSessionEffect::SendControl(ClientMessage::ChannelPayment { payment_json })]
                if payment_json == "{}"
        ));
    }

    #[test]
    fn repeated_status_does_not_duplicate_payment_while_payment_in_flight() {
        let mut state = ClientSessionState::new();
        state.snapshot = Some(SessionSnapshot {
            linked_channel: Some(LinkedChannelStatus {
                channel_id: "chan-a".to_string(),
                balance_raw: 5,
                capacity_raw: 100,
                unit: "msat".to_string(),
            }),
            remaining_milli_sats: -5,
            paused: true,
            ..snapshot(true)
        });
        state.active_channel_id = Some("chan-a".to_string());
        state.active_offer = Some(offer());
        state.control_op_in_flight = Some(ControlOpInFlight::Payment {
            channel_id: "chan-a".to_string(),
        });

        let (_state, effects) = step(
            state,
            ClientSessionEvent::SessionStatusReceived {
                snapshot: SessionSnapshot {
                    linked_channel: Some(LinkedChannelStatus {
                        channel_id: "chan-a".to_string(),
                        balance_raw: 5,
                        capacity_raw: 100,
                        unit: "msat".to_string(),
                    }),
                    remaining_milli_sats: -5,
                    paused: true,
                    ..snapshot(true)
                },
                pricing: SessionPricing::new(1, 1),
            },
        );

        assert!(!effects
            .iter()
            .any(|effect| matches!(effect, ClientSessionEffect::BuildChannelPayment { .. })));
    }

    #[test]
    fn linked_matching_status_can_trigger_payment_progress() {
        let mut state = ClientSessionState::new();
        state.active_channel_id = Some("chan-a".to_string());
        state.active_offer = Some(offer());

        let (_state, effects) = step(
            state,
            ClientSessionEvent::SessionStatusReceived {
                snapshot: SessionSnapshot {
                    linked_channel: Some(LinkedChannelStatus {
                        channel_id: "chan-a".to_string(),
                        balance_raw: 0,
                        capacity_raw: 20_000_000,
                        unit: "msat".to_string(),
                    }),
                    remaining_milli_sats: -5,
                    paused: true,
                    ..snapshot(true)
                },
                pricing: SessionPricing::new(1, 1),
            },
        );

        assert!(effects
            .iter()
            .any(|effect| matches!(effect, ClientSessionEffect::BuildChannelPayment { .. })));
    }

    #[test]
    fn channel_evicted_detaches_and_excludes_channel() {
        let mut state = ClientSessionState::new();
        state.snapshot = Some(snapshot(true));
        state.active_channel_id = Some("chan-a".to_string());
        state.active_offer = Some(offer());
        state.control_op_in_flight = Some(ControlOpInFlight::Payment {
            channel_id: "chan-a".to_string(),
        });

        let (state, effects) = step(
            state,
            ClientSessionEvent::ChannelEvicted {
                channel_id: "chan-a".to_string(),
            },
        );

        assert_eq!(state.active_channel_id, None);
        assert_eq!(state.active_offer, None);
        assert_eq!(state.control_op_in_flight, None);
        assert!(state.session_excluded_channels.contains("chan-a"));
        assert!(matches!(
            effects.as_slice(),
            [ClientSessionEffect::DetachChannel { channel_id }, ClientSessionEffect::UpdateSpilmanInfoHandle(Some(_))]
                if channel_id == "chan-a"
        ));
    }

    #[test]
    fn invalidating_server_error_marks_channel_unusable() {
        let mut state = ClientSessionState::new();
        state.snapshot = Some(snapshot(true));
        state.active_channel_id = Some("chan-a".to_string());
        state.active_offer = Some(offer());
        state.control_op_in_flight = Some(ControlOpInFlight::Link {
            channel_id: "chan-a".to_string(),
        });

        let (state, effects) = step(
            state,
            ClientSessionEvent::ServerError {
                code: ServerErrorCode::ChannelClosed,
                message: "channel closed".to_string(),
            },
        );

        assert_eq!(state.active_channel_id, None);
        assert_eq!(state.active_offer, None);
        assert_eq!(state.control_op_in_flight, None);
        assert!(matches!(
            effects.as_slice(),
            [ClientSessionEffect::MarkChannelUnusable { channel_id }, ClientSessionEffect::UpdateSpilmanInfoHandle(Some(_))]
                if channel_id == "chan-a"
        ));
    }

    #[test]
    fn payment_wrong_channel_keeps_intended_channel() {
        let mut state = ClientSessionState::new();
        state.snapshot = Some(snapshot(true));
        state.active_channel_id = Some("chan-a".to_string());
        state.active_offer = Some(offer());
        state.control_op_in_flight = Some(ControlOpInFlight::Payment {
            channel_id: "chan-a".to_string(),
        });

        let (state, effects) = step(
            state,
            ClientSessionEvent::ServerError {
                code: ServerErrorCode::PaymentWrongChannel,
                message: "wrong channel".to_string(),
            },
        );

        assert_eq!(state.active_channel_id.as_deref(), Some("chan-a"));
        assert!(state.active_offer.is_some());
        assert_eq!(state.control_op_in_flight, None);
        assert!(matches!(
            effects.as_slice(),
            [ClientSessionEffect::UpdateSpilmanInfoHandle(Some(_))]
        ));
    }

    #[test]
    fn blocked_state_suppresses_payment_progress() {
        let mut state = ClientSessionState::new();
        state.snapshot = Some(SessionSnapshot {
            linked_channel: Some(LinkedChannelStatus {
                channel_id: "chan-a".to_string(),
                balance_raw: 5,
                capacity_raw: 100,
                unit: "msat".to_string(),
            }),
            remaining_milli_sats: -5,
            paused: true,
            ..snapshot(true)
        });
        state.active_channel_id = Some("chan-a".to_string());
        state.active_offer = Some(offer());
        state.funding_blocked_reason = Some(FundingBlockedReason::PaymentBuild);

        let (_state, effects) = step(
            state,
            ClientSessionEvent::SessionStatusReceived {
                snapshot: SessionSnapshot {
                    linked_channel: Some(LinkedChannelStatus {
                        channel_id: "chan-a".to_string(),
                        balance_raw: 5,
                        capacity_raw: 100,
                        unit: "msat".to_string(),
                    }),
                    remaining_milli_sats: -5,
                    paused: true,
                    ..snapshot(true)
                },
                pricing: SessionPricing::new(1, 1),
            },
        );

        assert!(!effects
            .iter()
            .any(|effect| matches!(effect, ClientSessionEffect::BuildChannelPayment { .. })));
    }

    #[test]
    fn wallet_payment_failure_clears_active_channel_and_blocks_on_backend() {
        let mut state = ClientSessionState::new();
        state.snapshot = Some(snapshot(true));
        state.active_channel_id = Some("chan-a".to_string());
        state.active_offer = Some(offer());
        let (state, effects) = step(
            state,
            ClientSessionEvent::WalletOperationFailed {
                kind: WalletOpKind::PreparePayment {
                    channel_id: "chan-a".to_string(),
                },
                error: WalletError::Backend("wallet down".to_string()),
            },
        );

        assert_eq!(state.active_channel_id, None);
        assert_eq!(state.active_offer, None);
        assert_eq!(
            state.funding_blocked_reason,
            Some(FundingBlockedReason::PaymentBuild)
        );
        assert!(matches!(
            effects.as_slice(),
            [ClientSessionEffect::UpdateSpilmanInfoHandle(Some(_))]
        ));
    }

    #[test]
    fn control_detached_ends_session() {
        let mut state = ClientSessionState::new();
        state.active_channel_id = Some("chan-a".to_string());
        state.control_op_in_flight = Some(ControlOpInFlight::Link {
            channel_id: "chan-a".to_string(),
        });
        state.funding_blocked_reason = Some(FundingBlockedReason::Acquire);

        let (state, effects) = step(state, ClientSessionEvent::ControlDetached);

        assert!(state.terminated);
        assert_eq!(state.control_op_in_flight, None);
        assert_eq!(state.funding_blocked_reason, None);
        assert!(matches!(
            effects.as_slice(),
            [ClientSessionEffect::DetachChannel { channel_id }, ClientSessionEffect::EndSession]
                if channel_id == "chan-a"
        ));
    }
}
