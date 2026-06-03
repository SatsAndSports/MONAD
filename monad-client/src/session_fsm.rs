use crate::wallet::{RelayPaymentOffer, WalletChannel, WalletError};
use monad_common::protocol::{ClientMessage, KeysetAdvertisement, LinkedChannelStatus};
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

#[derive(Debug, Clone)]
pub(crate) struct ClientSessionState {
    pub snapshot: Option<SessionSnapshot>,
    pub active_channel_id: Option<String>,
    pub active_offer: Option<RelayPaymentOffer>,
    pub insufficient_channels: BTreeSet<String>,
    pub terminated: bool,
}

impl ClientSessionState {
    pub(crate) fn new() -> Self {
        Self {
            snapshot: None,
            active_channel_id: None,
            active_offer: None,
            insufficient_channels: BTreeSet::new(),
            terminated: false,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum WalletOpKind {
    ProvisionChannel,
    PrepareLink { channel_id: String },
    PreparePayment { channel_id: String },
}

#[derive(Debug, Clone)]
pub(crate) enum ClientSessionEvent {
    SessionStatusReceived {
        snapshot: SessionSnapshot,
        pricing: SessionPricing,
    },
    ChannelSelected {
        channel: WalletChannel,
        offer: RelayPaymentOffer,
    },
    NoSelectableChannel,
    ChannelProvisioned {
        channel: WalletChannel,
        offer: RelayPaymentOffer,
    },
    RelayLinkedChannelAdopted {
        linked_channel: LinkedChannelStatus,
        channel_id: String,
        offer: RelayPaymentOffer,
    },
    RelayLinkedChannelUnavailable {
        _linked_channel: LinkedChannelStatus,
    },
    LinkRequestBuilt {
        channel_id: String,
        payment_json: String,
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
        message: String,
    },
    ControlDetached,
}

#[derive(Debug, Clone)]
pub(crate) enum ClientSessionEffect {
    UpdatePricingHandle(SessionPricing),
    UpdateSpilmanInfoHandle(Option<SessionSpilmanInfo>),
    SelectChannel,
    ProvisionChannel {
        offer: RelayPaymentOffer,
        capacity_msats: u64,
    },
    PrepareLink {
        channel: WalletChannel,
        offer: RelayPaymentOffer,
    },
    InspectLinkedChannel {
        linked_channel: LinkedChannelStatus,
        receiver_pubkey: String,
        advertisements: Vec<KeysetAdvertisement>,
    },
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
            state.snapshot = Some(snapshot.clone());
            let mut effects = vec![ClientSessionEffect::UpdatePricingHandle(pricing)];
            if !snapshot.paused {
                effects.push(ClientSessionEffect::SignalUsable);
            }

            if let Some(linked_channel) = snapshot.linked_channel.clone() {
                if state.active_channel_id.as_deref() == Some(linked_channel.channel_id.as_str())
                    && state.active_offer.is_some()
                {
                    effects.push(ClientSessionEffect::UpdateSpilmanInfoHandle(
                        spilman_info_for(snapshot_for(&state), state.active_offer.as_ref()),
                    ));
                    effects.extend(payment_progress_effects(&mut state, linked_channel));
                } else {
                    if let Some(active_channel_id) = state.active_channel_id.take() {
                        effects.push(ClientSessionEffect::DetachChannel {
                            channel_id: active_channel_id,
                        });
                    }
                    state.active_offer = None;
                    effects.push(ClientSessionEffect::UpdateSpilmanInfoHandle(
                        spilman_info_for(snapshot_for(&state), state.active_offer.as_ref()),
                    ));
                    effects.push(ClientSessionEffect::InspectLinkedChannel {
                        linked_channel,
                        receiver_pubkey: snapshot.receiver_pubkey,
                        advertisements: snapshot.advertisements,
                    });
                }
            } else {
                if let Some(active_channel_id) = state.active_channel_id.take() {
                    effects.push(ClientSessionEffect::DetachChannel {
                        channel_id: active_channel_id,
                    });
                }
                state.active_offer = None;
                effects.push(ClientSessionEffect::UpdateSpilmanInfoHandle(
                    spilman_info_for(snapshot_for(&state), state.active_offer.as_ref()),
                ));
                if snapshot.paused {
                    effects.push(ClientSessionEffect::SelectChannel);
                }
            }

            effects
        }
        ClientSessionEvent::ChannelSelected { channel, offer }
        | ClientSessionEvent::ChannelProvisioned { channel, offer } => {
            state.active_channel_id = Some(channel.channel_id.clone());
            state.active_offer = Some(offer.clone());
            vec![
                ClientSessionEffect::UpdateSpilmanInfoHandle(spilman_info_for(
                    snapshot_for(&state),
                    state.active_offer.as_ref(),
                )),
                ClientSessionEffect::PrepareLink { channel, offer },
            ]
        }
        ClientSessionEvent::NoSelectableChannel => {
            match snapshot_for(&state).and_then(|snapshot| {
                snapshot
                    .advertisements
                    .first()
                    .map(|advertisement| (snapshot, advertisement))
            }) {
                Some((snapshot, advertisement)) => vec![ClientSessionEffect::ProvisionChannel {
                    offer: RelayPaymentOffer::from_advertisement(
                        snapshot.receiver_pubkey.clone(),
                        advertisement,
                    ),
                    capacity_msats: DEFAULT_PROVISIONED_CHANNEL_CAPACITY_MSATS,
                }],
                None => Vec::new(),
            }
        }
        ClientSessionEvent::RelayLinkedChannelAdopted {
            linked_channel,
            channel_id,
            offer,
        } => {
            state.active_channel_id = Some(channel_id);
            state.active_offer = Some(offer);
            let mut effects = vec![ClientSessionEffect::UpdateSpilmanInfoHandle(
                spilman_info_for(snapshot_for(&state), state.active_offer.as_ref()),
            )];
            effects.extend(payment_progress_effects(&mut state, linked_channel));
            effects
        }
        ClientSessionEvent::RelayLinkedChannelUnavailable { _linked_channel: _ } => {
            state.active_channel_id = None;
            state.active_offer = None;
            let mut effects = vec![ClientSessionEffect::UpdateSpilmanInfoHandle(
                spilman_info_for(snapshot_for(&state), state.active_offer.as_ref()),
            )];
            if snapshot_for(&state).is_some_and(|snapshot| snapshot.paused) {
                effects.push(ClientSessionEffect::SelectChannel);
            }
            effects
        }
        ClientSessionEvent::LinkRequestBuilt {
            channel_id,
            payment_json,
        } => {
            state.active_channel_id = Some(channel_id);
            vec![ClientSessionEffect::SendControl(
                ClientMessage::ChannelLink { payment_json },
            )]
        }
        ClientSessionEvent::ChannelPaymentBuilt { payment_json } => {
            vec![ClientSessionEffect::SendControl(
                ClientMessage::ChannelPayment { payment_json },
            )]
        }
        ClientSessionEvent::WalletOperationFailed { kind, error } => {
            match kind {
                WalletOpKind::ProvisionChannel => {}
                WalletOpKind::PrepareLink { channel_id }
                | WalletOpKind::PreparePayment { channel_id } => {
                    if exclude_on_wallet_error(&error) {
                        state.insufficient_channels.insert(channel_id.clone());
                    }
                    if state.active_channel_id.as_deref() == Some(channel_id.as_str()) {
                        state.active_channel_id = None;
                        state.active_offer = None;
                    }
                }
            }

            let mut effects = vec![ClientSessionEffect::UpdateSpilmanInfoHandle(
                spilman_info_for(snapshot_for(&state), state.active_offer.as_ref()),
            )];
            if snapshot_for(&state).is_some_and(|snapshot| snapshot.paused) {
                effects.push(ClientSessionEffect::SelectChannel);
            }
            effects
        }
        ClientSessionEvent::ChannelEvicted { channel_id } => {
            let mut effects = Vec::new();
            state.insufficient_channels.remove(&channel_id);
            if state.active_channel_id.as_deref() == Some(channel_id.as_str()) {
                state.active_channel_id = None;
                state.active_offer = None;
                effects.push(ClientSessionEffect::DetachChannel { channel_id });
            }
            effects.push(ClientSessionEffect::UpdateSpilmanInfoHandle(
                spilman_info_for(snapshot_for(&state), state.active_offer.as_ref()),
            ));
            if snapshot_for(&state).is_some_and(|snapshot| snapshot.paused) {
                effects.push(ClientSessionEffect::SelectChannel);
            }
            effects
        }
        ClientSessionEvent::ServerError { message } => {
            let mut effects = Vec::new();
            if let Some(active_channel_id) = state.active_channel_id.take() {
                if is_channel_invalidating_error(&message) {
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
            effects.push(ClientSessionEffect::UpdateSpilmanInfoHandle(
                spilman_info_for(snapshot_for(&state), state.active_offer.as_ref()),
            ));
            if snapshot_for(&state).is_some_and(|snapshot| snapshot.paused) {
                effects.push(ClientSessionEffect::SelectChannel);
            }
            effects
        }
        ClientSessionEvent::ControlDetached => {
            state.terminated = true;
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
            .insufficient_channels
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
            ClientSessionEffect::SelectChannel,
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

pub(crate) fn is_channel_invalidating_error(message: &str) -> bool {
    [
        "receiver key mismatch",
        "unsupported unit",
        "mint or keyset not acceptable",
        "link balance must be zero",
        "channel expired",
        "channel closed",
        "wrong receiver",
    ]
    .iter()
    .any(|needle| message.contains(needle))
}

#[cfg(test)]
mod tests {
    use super::{
        step, ClientSessionEffect, ClientSessionEvent, ClientSessionState, SessionSnapshot,
        WalletOpKind, DEFAULT_PROVISIONED_CHANNEL_CAPACITY_MSATS,
    };
    use crate::wallet::{RelayPaymentOffer, WalletChannel, WalletChannelState, WalletError};
    use monad_common::protocol::ClientMessage;
    use monad_common::protocol::{KeysetAdvertisement, LinkedChannelStatus};
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

    fn channel(id: &str) -> WalletChannel {
        WalletChannel {
            channel_id: id.to_string(),
            state: WalletChannelState::Open,
            receiver_pubkey: "receiver".to_string(),
            mint_url: "https://mint".to_string(),
            unit: "msat".to_string(),
            keyset_id: "keyset-a".to_string(),
            attached_session_id: None,
            capacity_msats: 100,
            current_signed_balance_msats: 0,
        }
    }

    #[test]
    fn initial_paused_status_selects_channel() {
        let (state, effects) = step(
            ClientSessionState::new(),
            ClientSessionEvent::SessionStatusReceived {
                snapshot: snapshot(true),
                pricing: SessionPricing::new(1, 1),
            },
        );

        assert_eq!(state.active_channel_id, None);
        assert!(matches!(
            effects.as_slice(),
            [
                ClientSessionEffect::UpdatePricingHandle(_),
                ClientSessionEffect::UpdateSpilmanInfoHandle(Some(_)),
                ClientSessionEffect::SelectChannel,
            ]
        ));
    }

    #[test]
    fn no_selectable_channel_provisions_from_first_advertisement() {
        let mut state = ClientSessionState::new();
        state.snapshot = Some(snapshot(true));
        let (_state, effects) = step(state, ClientSessionEvent::NoSelectableChannel);

        assert!(matches!(
            effects.as_slice(),
            [ClientSessionEffect::ProvisionChannel { capacity_msats, .. }]
                if *capacity_msats == DEFAULT_PROVISIONED_CHANNEL_CAPACITY_MSATS
        ));
    }

    #[test]
    fn selected_channel_prepares_link() {
        let mut state = ClientSessionState::new();
        state.snapshot = Some(snapshot(true));
        let (state, effects) = step(
            state,
            ClientSessionEvent::ChannelSelected {
                channel: channel("chan-a"),
                offer: offer(),
            },
        );

        assert_eq!(state.active_channel_id.as_deref(), Some("chan-a"));
        assert!(matches!(
            effects.as_slice(),
            [
                ClientSessionEffect::UpdateSpilmanInfoHandle(Some(_)),
                ClientSessionEffect::PrepareLink { channel, .. },
            ] if channel.channel_id == "chan-a"
        ));
    }

    #[test]
    fn link_request_built_sends_channel_link() {
        let (state, effects) = step(
            ClientSessionState::new(),
            ClientSessionEvent::LinkRequestBuilt {
                channel_id: "chan-a".to_string(),
                payment_json: "{}".to_string(),
            },
        );

        assert_eq!(state.active_channel_id.as_deref(), Some("chan-a"));
        assert!(matches!(
            effects.as_slice(),
            [ClientSessionEffect::SendControl(ClientMessage::ChannelLink { payment_json })]
                if payment_json == "{}"
        ));
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
    fn insufficient_capacity_detaches_and_reselects() {
        let mut state = ClientSessionState::new();
        state.snapshot = Some(SessionSnapshot {
            linked_channel: Some(LinkedChannelStatus {
                channel_id: "chan-a".to_string(),
                balance_raw: 95,
                capacity_raw: 100,
                unit: "msat".to_string(),
            }),
            remaining_milli_sats: -5,
            paused: true,
            ..snapshot(true)
        });
        state.active_channel_id = Some("chan-a".to_string());
        state.active_offer = Some(offer());

        let (state, effects) = step(
            state,
            ClientSessionEvent::RelayLinkedChannelAdopted {
                linked_channel: LinkedChannelStatus {
                    channel_id: "chan-a".to_string(),
                    balance_raw: 95,
                    capacity_raw: 100,
                    unit: "msat".to_string(),
                },
                channel_id: "chan-a".to_string(),
                offer: offer(),
            },
        );

        assert_eq!(state.active_channel_id, None);
        assert!(state.insufficient_channels.contains("chan-a"));
        assert!(matches!(
            effects.as_slice(),
            [
                ClientSessionEffect::UpdateSpilmanInfoHandle(Some(_)),
                ClientSessionEffect::DetachChannel { channel_id },
                ClientSessionEffect::UpdateSpilmanInfoHandle(Some(_)),
                ClientSessionEffect::SelectChannel,
            ] if channel_id == "chan-a"
        ));
    }

    #[test]
    fn channel_evicted_detaches_and_reselects() {
        let mut state = ClientSessionState::new();
        state.snapshot = Some(snapshot(true));
        state.active_channel_id = Some("chan-a".to_string());
        state.active_offer = Some(offer());

        let (state, effects) = step(
            state,
            ClientSessionEvent::ChannelEvicted {
                channel_id: "chan-a".to_string(),
            },
        );

        assert_eq!(state.active_channel_id, None);
        assert!(matches!(
            effects.as_slice(),
            [
                ClientSessionEffect::DetachChannel { channel_id },
                ClientSessionEffect::UpdateSpilmanInfoHandle(Some(_)),
                ClientSessionEffect::SelectChannel,
            ] if channel_id == "chan-a"
        ));
    }

    #[test]
    fn invalidating_server_error_marks_channel_unusable() {
        let mut state = ClientSessionState::new();
        state.snapshot = Some(snapshot(true));
        state.active_channel_id = Some("chan-a".to_string());
        state.active_offer = Some(offer());

        let (state, effects) = step(
            state,
            ClientSessionEvent::ServerError {
                message: "receiver key mismatch".to_string(),
            },
        );

        assert_eq!(state.active_channel_id, None);
        assert!(matches!(
            effects.as_slice(),
            [
                ClientSessionEffect::MarkChannelUnusable { channel_id },
                ClientSessionEffect::UpdateSpilmanInfoHandle(Some(_)),
                ClientSessionEffect::SelectChannel,
            ] if channel_id == "chan-a"
        ));
    }

    #[test]
    fn control_detached_ends_session() {
        let mut state = ClientSessionState::new();
        state.active_channel_id = Some("chan-a".to_string());

        let (state, effects) = step(state, ClientSessionEvent::ControlDetached);

        assert!(state.terminated);
        assert!(matches!(
            effects.as_slice(),
            [
                ClientSessionEffect::DetachChannel { channel_id },
                ClientSessionEffect::EndSession,
            ] if channel_id == "chan-a"
        ));
    }

    #[test]
    fn wallet_failure_reselects_when_paused() {
        let mut state = ClientSessionState::new();
        state.snapshot = Some(snapshot(true));
        state.active_channel_id = Some("chan-a".to_string());
        state.active_offer = Some(offer());

        let (state, effects) = step(
            state,
            ClientSessionEvent::WalletOperationFailed {
                kind: WalletOpKind::PrepareLink {
                    channel_id: "chan-a".to_string(),
                },
                error: WalletError::AttachedToDifferentSession { current: [1; 32] },
            },
        );

        assert!(state.active_channel_id.is_none());
        assert!(state.insufficient_channels.contains("chan-a"));
        assert!(matches!(
            effects.as_slice(),
            [
                ClientSessionEffect::UpdateSpilmanInfoHandle(Some(_)),
                ClientSessionEffect::SelectChannel,
            ]
        ));
    }
}
