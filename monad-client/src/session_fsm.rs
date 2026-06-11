use crate::wallet::{RelayPaymentOffer, WalletError};
use monad_common::protocol::{KeysetAdvertisement, LinkedChannelStatus, ServerErrorCode};
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

#[derive(Debug, Clone)]
pub(crate) enum ClientSessionEvent {
    SessionStatusReceived {
        snapshot: SessionSnapshot,
        pricing: SessionPricing,
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
    DetachChannel { channel_id: String },
    MarkChannelUnusable { channel_id: String },
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
            let _resolved_payment =
                matches!(resolved_control_op, Some(ControlOpInFlight::Payment { .. }));
            state.snapshot = Some(snapshot.clone());
            let mut effects = vec![ClientSessionEffect::UpdatePricingHandle(pricing)];
            if !snapshot.paused {
                effects.push(ClientSessionEffect::SignalUsable);
            }

            effects.push(ClientSessionEffect::UpdateSpilmanInfoHandle(
                spilman_info_for(snapshot_for(&state), state.active_offer.as_ref()),
            ));

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

fn snapshot_for(state: &ClientSessionState) -> Option<&SessionSnapshot> {
    state.snapshot.as_ref()
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

pub(crate) fn exclude_on_wallet_error(error: &WalletError) -> bool {
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
        exclude_on_wallet_error, step, ClientSessionEffect, ClientSessionEvent, ClientSessionState,
        ControlOpInFlight, FundingBlockedReason, SessionSnapshot,
    };
    use crate::wallet::{RelayPaymentOffer, WalletError};
    use monad_common::protocol::{KeysetAdvertisement, ServerErrorCode};
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
    fn exclude_on_wallet_error_marks_expected_errors() {
        assert!(exclude_on_wallet_error(&WalletError::NotFound));
        assert!(exclude_on_wallet_error(&WalletError::NotOpen));
        assert!(exclude_on_wallet_error(
            &WalletError::AttachedToDifferentSession { current: [1; 32] }
        ));
        assert!(exclude_on_wallet_error(
            &WalletError::InsufficientCapacity {
                requested: 1,
                capacity: 1,
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
