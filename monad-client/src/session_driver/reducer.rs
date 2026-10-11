//! Serialized ordinary-control state. Heartbeat and tunnel I/O are independent.
//!
//! A response is classified without mutation, then committed only after wallet
//! and accounting validation. Unlike ControlExchange, this has no request FIFO.
use super::policy::{Intent, View};
use super::state::{DriverState, PreviousChannel};
use crate::wallet::{RelayPaymentOffer, WalletChannel};
use monad_common::control_exchange::{validate_response, Attribution, PendingRequest};
use monad_common::protocol::ServerMessage;
use std::io;

pub(super) enum ChannelEvent {
    Acquired(WalletChannel, RelayPaymentOffer),
    LinkSelected {
        channel_id: String,
        keyset_id: String,
        offer: RelayPaymentOffer,
    },
    LinkAccepted,
    LinkRejected,
    Evicted(String),
    ReleaseRequested(String),
}

#[cfg(test)]
mod tests {
    use super::*;
    use monad_common::protocol::{LinkedChannelStatus, ServerErrorCode};

    fn status(paid: u64, channel: Option<(&str, u64)>) -> ServerMessage {
        ServerMessage::SessionStatus {
            receiver_pubkey: "receiver".into(),
            advertisements: Default::default(),
            linked_channel: channel.map(|(id, balance)| LinkedChannelStatus {
                channel_id: id.into(),
                balance_raw: balance,
                capacity_raw: 100,
                unit: "msat".into(),
            }),
            active_in_rate: 1,
            active_out_rate: 1,
            session_total_bytes_in: 0,
            session_total_bytes_out: 0,
            total_paid_millisats: paid,
            remaining_milli_sats: paid as i64,
            paused: paid == 0,
            open_connects: 0,
            total_connects: 0,
            failed_connects: 0,
        }
    }

    fn initialized() -> ControlState {
        let mut state = ControlState::default();
        state.step(Event::Accept(status(0, None))).unwrap();
        state
    }

    fn view() -> View {
        View {
            acquired: false,
            linked: true,
            release_requested: false,
            paused: false,
            relay_remaining: 100,
            estimated_remaining: Some(100),
            exhausted: false,
            skip_payment: false,
            retry_eligible: true,
        }
    }

    #[test]
    fn ordinary_requests_are_serialized_but_notifications_are_independent() {
        for request in [
            PendingRequest::Link {
                channel_id: "A".into(),
            },
            PendingRequest::Payment {
                channel_id: "A".into(),
                balance_raw: 10,
                minimum_increment_msats: 10,
            },
            PendingRequest::Unlink {
                channel_id: "A".into(),
            },
            PendingRequest::Status,
        ] {
            let mut state = initialized();
            state.step(Event::Submit(request.clone())).unwrap();
            assert!(state.step(Event::Submit(PendingRequest::Status)).is_err());
            state.step(Event::Submitted).unwrap();
            for message in [
                ServerMessage::Pong {
                    nonce: "probe".into(),
                },
                ServerMessage::ChannelReleaseRequested {
                    channel_id: "A".into(),
                },
                ServerMessage::ChannelEvicted {
                    channel_id: "A".into(),
                    scope: monad_common::protocol::ChannelEvictionScope::Session,
                },
            ] {
                assert_eq!(state.classify(&message).unwrap(), Attribution::Notification);
                state.step(Event::Accept(message)).unwrap();
                assert_eq!(state.pending(), Some(&request));
            }
            assert_eq!(
                state
                    .funding_decided(
                        Intent::Pay {
                            requested_delta_msats: 1
                        },
                        &view()
                    )
                    .unwrap(),
                None
            );
            state
                .step(Event::Accept(ServerMessage::Error {
                    code: ServerErrorCode::LinkInvalidChannel,
                    message: "rejected".into(),
                }))
                .unwrap();
            assert!(state.is_empty());
            assert!(state
                .funding_decided(Intent::RequestStatus, &view())
                .unwrap()
                .is_some());
        }
    }

    #[test]
    fn response_validation_is_nonmutating_until_commit() {
        let mut state = initialized();
        let request = PendingRequest::Payment {
            channel_id: "A".into(),
            balance_raw: 10,
            minimum_increment_msats: 10,
        };
        state.step(Event::Submit(request.clone())).unwrap();
        state.step(Event::Submitted).unwrap();
        for invalid in [
            status(10, Some(("B", 10))),
            status(10, Some(("A", 9))),
            status(9, Some(("A", 10))),
        ] {
            assert!(state.classify(&invalid).is_err());
            assert_eq!(state.pending(), Some(&request));
        }
        let valid = status(10, Some(("A", 10)));
        state.classify(&valid).unwrap();
        // A subsequent wallet validation failure cannot consume the request.
        assert_eq!(state.pending(), Some(&request));
        assert_eq!(state.confirmed_paid, 0);
        state.step(Event::Accept(valid)).unwrap();
        assert!(state.is_empty());
        assert_eq!(state.confirmed_paid, 10);
        assert_eq!(
            state.classify(&status(10, Some(("A", 10)))).unwrap(),
            Attribution::Unsolicited
        );
    }

    #[test]
    fn reducer_does_not_encode_payment_thresholds() {
        let mut state = initialized();
        assert_eq!(
            state
                .funding_decided(
                    Intent::Pay {
                        requested_delta_msats: 7
                    },
                    &view()
                )
                .unwrap(),
            Some(FundingEffect::PreparePayment {
                requested_delta_msats: 7
            })
        );
        state.step(Event::WorkFinished).unwrap();
        let mut paused = view();
        paused.paused = true;
        paused.estimated_remaining = Some(-5);
        assert_eq!(state.funding_decided(Intent::Wait, &paused).unwrap(), None);
        paused.release_requested = true;
        assert_eq!(
            state
                .funding_decided(
                    Intent::Pay {
                        requested_delta_msats: 7
                    },
                    &paused
                )
                .unwrap(),
            None
        );
        assert_eq!(
            state.funding_decided(Intent::Unlink, &paused).unwrap(),
            Some(FundingEffect::RetireAndUnlink)
        );
    }

    fn offer() -> RelayPaymentOffer {
        RelayPaymentOffer {
            receiver_pubkey: "receiver".into(),
            mint_url: "https://mint".into(),
            unit: "msat".into(),
            negotiated_keyset_versions: ["v1".to_string()].into(),
            funding_keyset_recovery_window_secs: 86400,
            minimum_channel_lifetime_secs: 3600,
            in_bytes_per_millisat: 1,
            out_bytes_per_millisat: 1,
        }
    }

    fn replacing() -> DriverState {
        let mut state = DriverState {
            intended_channel_id: Some("A".into()),
            intended_offer: Some(offer()),
            ..Default::default()
        };
        state.relay_snapshot = Some(super::super::state::RelaySnapshot {
            receiver_pubkey: "receiver".into(),
            advertisements: vec![],
            linked_channel: Some(LinkedChannelStatus {
                channel_id: "A".into(),
                balance_raw: 1,
                capacity_raw: 100,
                unit: "msat".into(),
            }),
            session_total_bytes_in: 0,
            session_total_bytes_out: 0,
            total_paid_millisats: 1,
            remaining_milli_sats: 1,
            paused: false,
        });
        channel_step(
            &mut state,
            ChannelEvent::LinkSelected {
                channel_id: "B".into(),
                keyset_id: "key".into(),
                offer: offer(),
            },
        );
        assert_eq!(state.intended_channel_id.as_deref(), Some("B"));
        state
    }

    #[test]
    fn replacement_rejection_restores_previous_unless_evicted() {
        for evicted in [false, true] {
            let mut state = replacing();
            channel_step(&mut state, ChannelEvent::ReleaseRequested("A".into()));
            channel_step(
                &mut state,
                ChannelEvent::ReleaseRequested("unrelated".into()),
            );
            if evicted {
                channel_step(&mut state, ChannelEvent::Evicted("A".into()));
            }
            channel_step(&mut state, ChannelEvent::LinkRejected);
            assert_eq!(
                state.intended_channel_id.as_deref(),
                if evicted { None } else { Some("A") }
            );
            assert!(state.release_requested_channels.contains("A"));
            assert!(!state.release_requested_channels.contains("unrelated"));
        }
        let mut state = replacing();
        let effects = channel_step(&mut state, ChannelEvent::LinkAccepted);
        assert!(matches!(effects.as_slice(), [ChannelEffect::ReleaseReservation(id)] if id == "A"));
        assert_eq!(state.intended_channel_id.as_deref(), Some("B"));
        assert!(state.previous_link.is_none());
    }

    #[test]
    fn release_and_eviction_do_not_consume_payment_response() {
        let mut state = replacing();
        state.exchange = initialized();
        state
            .exchange
            .step(Event::Submit(PendingRequest::Payment {
                channel_id: "B".into(),
                balance_raw: 10,
                minimum_increment_msats: 10,
            }))
            .unwrap();
        state.exchange.step(Event::Submitted).unwrap();
        channel_step(&mut state, ChannelEvent::ReleaseRequested("B".into()));
        assert!(state.exchange.pending().is_some());
        channel_step(&mut state, ChannelEvent::Evicted("B".into()));
        assert!(state.exchange.pending().is_some());
        assert!(state.intended_channel_id.is_none());
        state.exchange.step(Event::End).unwrap();
        assert_eq!(state.exchange.phase, Phase::Ending);
        assert!(state
            .exchange
            .step(Event::Submit(PendingRequest::Status))
            .is_err());
        state.exchange.step(Event::CleanupFinished).unwrap();
        assert_eq!(state.exchange.phase, Phase::Ended);
    }
}

/// Local reservation cleanup is an effect, never I/O inside a transition.
pub(super) enum ChannelEffect {
    ReleaseReservation(String),
}

pub(super) fn channel_step(state: &mut DriverState, event: ChannelEvent) -> Vec<ChannelEffect> {
    match event {
        ChannelEvent::Acquired(channel, offer) => state.acquired = Some((channel, offer)),
        ChannelEvent::LinkSelected {
            channel_id,
            keyset_id,
            offer,
        } => {
            if super::state::relay_confirms_intended_channel(state)
                && state.intended_channel_id.as_deref() != Some(channel_id.as_str())
            {
                state.previous_link =
                    state
                        .intended_channel_id
                        .take()
                        .map(|channel_id| PreviousChannel {
                            channel_id,
                            keyset_id: state.intended_channel_keyset_id.take(),
                            offer: state.intended_offer.take(),
                            evicted: false,
                        });
            }
            state.intended_channel_id = Some(channel_id);
            state.intended_channel_keyset_id = Some(keyset_id);
            state.intended_offer = Some(offer);
        }
        ChannelEvent::LinkAccepted => {
            if let Some(previous) = state.previous_link.take() {
                state
                    .release_requested_channels
                    .remove(&previous.channel_id);
                return vec![ChannelEffect::ReleaseReservation(previous.channel_id)];
            }
        }
        ChannelEvent::LinkRejected => {
            if let Some(previous) = state.previous_link.take() {
                state.intended_channel_id = None;
                state.intended_channel_keyset_id = None;
                state.intended_offer = None;
                if !previous.evicted {
                    state.intended_channel_id = Some(previous.channel_id);
                    state.intended_channel_keyset_id = previous.keyset_id;
                    state.intended_offer = previous.offer;
                }
            }
        }
        ChannelEvent::Evicted(id) => {
            if let Some(previous) = state.previous_link.as_mut() {
                if previous.channel_id == id {
                    previous.evicted = true;
                }
            }
            if let Some(snapshot) = state.relay_snapshot.as_mut() {
                if snapshot
                    .linked_channel
                    .as_ref()
                    .is_some_and(|c| c.channel_id == id)
                {
                    snapshot.linked_channel = None;
                }
            }
            state.session_excluded_channels.insert(id.clone());
            if state.intended_channel_id.as_deref() == Some(id.as_str()) {
                state.intended_channel_id = None;
                state.intended_channel_keyset_id = None;
                state.intended_offer = None;
            }
            return vec![ChannelEffect::ReleaseReservation(id)];
        }
        ChannelEvent::ReleaseRequested(id) => {
            let relevant = state.intended_channel_id.as_deref() == Some(id.as_str())
                || state
                    .previous_link
                    .as_ref()
                    .is_some_and(|c| c.channel_id == id)
                || super::state::relay_linked_channel_id(state) == Some(id.as_str());
            if relevant {
                state.release_requested_channels.insert(id);
            }
        }
    }
    Vec::new()
}

/// Policy intents become effects only through this gate. Timing/amount choices
/// belong to the policy; authorization and ordinary-request serialization do not.
#[derive(Debug, PartialEq, Eq)]
pub(super) enum FundingEffect {
    AcquireChannel,
    PrepareLink,
    PreparePayment { requested_delta_msats: u64 },
    RetireAndUnlink,
    ReleaseAcquired,
    ReleaseExhausted,
    SubmitStatus,
}

#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub(super) enum Phase {
    #[default]
    AwaitingInitialStatus,
    Active,
    Ending,
    Ended,
}

#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub(super) enum Ordinary {
    #[default]
    Idle,
    Working,
    Submitting(PendingRequest),
    AwaitingResponse(PendingRequest),
}

#[derive(Debug, Default)]
pub(super) struct ControlState {
    pub phase: Phase,
    pub ordinary: Ordinary,
    confirmed_paid: u64,
}

pub(super) enum Event {
    BeginWork,
    WorkFinished,
    Submit(PendingRequest),
    Submitted,
    Accept(ServerMessage),
    End,
    CleanupFinished,
}

#[derive(Debug, PartialEq, Eq)]
pub(super) enum Effect {
    None,
    ResponseAccepted(Attribution),
    Cleanup,
}

fn invalid(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}

impl ControlState {
    pub fn funding_decided(
        &mut self,
        intent: Intent,
        view: &View,
    ) -> io::Result<Option<FundingEffect>> {
        if !self.is_initialized() || !self.is_empty() {
            return Ok(None);
        }
        let effect = match intent {
            Intent::Wait => return Ok(None),
            Intent::AcquireChannel if !view.acquired && view.retry_eligible => {
                FundingEffect::AcquireChannel
            }
            Intent::LinkAcquired if view.acquired && view.retry_eligible => {
                FundingEffect::PrepareLink
            }
            Intent::Pay {
                requested_delta_msats,
            } if view.linked && !view.release_requested => FundingEffect::PreparePayment {
                requested_delta_msats,
            },
            Intent::Unlink if view.linked || view.release_requested => {
                FundingEffect::RetireAndUnlink
            }
            Intent::ReleaseAcquired if view.acquired => FundingEffect::ReleaseAcquired,
            Intent::ReleaseExhausted if view.linked && view.exhausted => {
                FundingEffect::ReleaseExhausted
            }
            Intent::RequestStatus => FundingEffect::SubmitStatus,
            _ => return Ok(None),
        };
        self.step(Event::BeginWork)?;
        Ok(Some(effect))
    }
    pub fn is_initialized(&self) -> bool {
        self.phase == Phase::Active
    }

    pub fn is_empty(&self) -> bool {
        self.ordinary == Ordinary::Idle
    }

    pub fn pending(&self) -> Option<&PendingRequest> {
        match &self.ordinary {
            Ordinary::Submitting(request) | Ordinary::AwaitingResponse(request) => Some(request),
            _ => None,
        }
    }

    pub fn classify(&self, message: &ServerMessage) -> io::Result<Attribution> {
        if let ServerMessage::Error { code, .. } = message {
            if code.is_fatal() {
                return Err(invalid("fatal relay control error"));
            }
        }
        if matches!(self.phase, Phase::Ending | Phase::Ended) {
            return Err(invalid("response after session termination"));
        }
        if let ServerMessage::SessionStatus {
            active_in_rate,
            active_out_rate,
            ..
        } = message
        {
            if *active_in_rate == 0 || *active_out_rate == 0 {
                return Err(invalid("status pricing rates must be positive"));
            }
        }
        if self.phase == Phase::AwaitingInitialStatus {
            return match message {
                ServerMessage::ExtensionNotification(_) => Ok(Attribution::Notification),
                ServerMessage::SessionStatus { .. } => Ok(Attribution::InitialStatus),
                _ => Err(invalid("first relay control message must be SessionStatus")),
            };
        }
        match message {
            ServerMessage::SessionStatus { .. } | ServerMessage::Error { .. } => {
                let Ordinary::AwaitingResponse(request) = &self.ordinary else {
                    return Ok(Attribution::Unsolicited);
                };
                if matches!(message, ServerMessage::SessionStatus { .. }) {
                    validate_response(request, self.confirmed_paid, message)?;
                }
                Ok(Attribution::Response(request.clone()))
            }
            _ => Ok(Attribution::Notification),
        }
    }

    pub fn step(&mut self, event: Event) -> io::Result<Effect> {
        match event {
            Event::BeginWork => {
                if !self.is_initialized() || !self.is_empty() {
                    return Err(invalid(
                        "ordinary operation already busy or not initialized",
                    ));
                }
                self.ordinary = Ordinary::Working;
            }
            Event::WorkFinished => {
                if self.ordinary == Ordinary::Working {
                    self.ordinary = Ordinary::Idle;
                }
            }
            Event::Submit(request) => {
                if !self.is_initialized()
                    || !matches!(self.ordinary, Ordinary::Idle | Ordinary::Working)
                {
                    return Err(invalid(
                        "ordinary request while busy or before initial status",
                    ));
                }
                self.ordinary = Ordinary::Submitting(request);
            }
            Event::Submitted => {
                let Ordinary::Submitting(request) = &self.ordinary else {
                    return Err(invalid("submission completion without submitted request"));
                };
                self.ordinary = Ordinary::AwaitingResponse(request.clone());
            }
            Event::Accept(message) => {
                let attribution = self.classify(&message)?;
                if matches!(
                    attribution,
                    Attribution::InitialStatus | Attribution::Response(_)
                ) {
                    if let ServerMessage::SessionStatus {
                        total_paid_millisats,
                        ..
                    } = message
                    {
                        self.confirmed_paid = total_paid_millisats;
                    }
                    self.phase = Phase::Active;
                    self.ordinary = Ordinary::Idle;
                }
                return Ok(Effect::ResponseAccepted(attribution));
            }
            Event::End => {
                self.phase = Phase::Ending;
                self.ordinary = Ordinary::Idle;
                return Ok(Effect::Cleanup);
            }
            Event::CleanupFinished => {
                self.phase = Phase::Ended;
            }
        }
        Ok(Effect::None)
    }
}
