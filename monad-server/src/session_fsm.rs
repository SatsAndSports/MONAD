use crate::payments::{ChannelPaymentError, LinkError, LinkOutcome, PaymentOutcome};
use monad_common::protocol::ServerMessage;
use monad_common::session::SessionPricing;

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ServerSessionState {
    pub pricing: SessionPricing,
    pub session_total_in: u64,
    pub session_total_out: u64,
    pub total_paid_millisats: u64,
    pub paused: bool,
    pub linked_channel_id: Option<String>,
    pub terminated: bool,
}

#[derive(Debug, Clone)]
pub(crate) enum SessionEvent {
    ClientGetSessionStatus,
    ClientChannelLink { payment_json: String },
    LinkValidationFinished(Result<LinkOutcome, LinkError>),
    ClientChannelPayment { payment_json: String },
    PaymentValidationFinished(Result<PaymentOutcome, ChannelPaymentError>),
    ChannelEvicted { channel_id: String },
    ControlDetached,
}

#[derive(Debug, Clone)]
pub(crate) enum SessionEffect {
    SendControl(ServerMessage),
    SendStatus,
    RunLinkValidation {
        payment_json: String,
    },
    RunPaymentValidation {
        expected_channel_id: String,
        payment_json: String,
    },
    NotifySessionEvicted {
        target_session_id: [u8; 32],
        channel_id: String,
    },
    ReleaseLinkedChannelOwnership {
        channel_id: String,
    },
    UpdatePauseWatch(bool),
    EndSession,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ByteDirection {
    Inbound,
    Outbound,
}

pub(crate) fn step(
    mut state: ServerSessionState,
    event: SessionEvent,
) -> (ServerSessionState, Vec<SessionEffect>) {
    if state.terminated {
        return (state, Vec::new());
    }

    let effects = match event {
        SessionEvent::ClientGetSessionStatus => vec![SessionEffect::SendStatus],
        SessionEvent::ClientChannelLink { payment_json } => {
            vec![SessionEffect::RunLinkValidation { payment_json }]
        }
        SessionEvent::LinkValidationFinished(result) => match result {
            Ok(outcome) => {
                state.linked_channel_id = Some(outcome.channel_id.clone());
                let mut effects = vec![SessionEffect::SendControl(
                    ServerMessage::ChannelLinkAccepted {
                        channel_id: outcome.channel_id.clone(),
                        capacity: outcome.capacity_millisats,
                    },
                )];
                if let Some(evicted_session) = outcome.evicted_session {
                    effects.push(SessionEffect::NotifySessionEvicted {
                        target_session_id: evicted_session,
                        channel_id: outcome.channel_id,
                    });
                }
                effects.push(SessionEffect::SendStatus);
                effects
            }
            Err(err) => vec![SessionEffect::SendControl(ServerMessage::Error {
                message: err.to_string(),
            })],
        },
        SessionEvent::ClientChannelPayment { payment_json } => {
            if let Some(expected_channel_id) = state.linked_channel_id.clone() {
                vec![SessionEffect::RunPaymentValidation {
                    expected_channel_id,
                    payment_json,
                }]
            } else {
                vec![SessionEffect::SendControl(ServerMessage::Error {
                    message: ChannelPaymentError::WrongChannel.to_string(),
                })]
            }
        }
        SessionEvent::PaymentValidationFinished(result) => match result {
            Ok(outcome) => {
                state.total_paid_millisats = state
                    .total_paid_millisats
                    .saturating_add(outcome.delta_millisats);
                let pause_changed = refresh_pause_state(&mut state);
                let mut effects = Vec::new();
                if let Some(paused) = pause_changed {
                    effects.push(SessionEffect::UpdatePauseWatch(paused));
                }
                effects.push(SessionEffect::SendStatus);
                effects
            }
            Err(err) => vec![SessionEffect::SendControl(ServerMessage::Error {
                message: err.to_string(),
            })],
        },
        SessionEvent::ChannelEvicted { channel_id } => {
            if state.linked_channel_id.as_deref() == Some(channel_id.as_str()) {
                state.linked_channel_id = None;
            }
            vec![
                SessionEffect::SendControl(ServerMessage::ChannelEvicted { channel_id }),
                SessionEffect::SendStatus,
            ]
        }
        SessionEvent::ControlDetached => {
            state.terminated = true;
            let mut effects = Vec::new();
            if let Some(channel_id) = state.linked_channel_id.take() {
                effects.push(SessionEffect::ReleaseLinkedChannelOwnership { channel_id });
            }
            effects.push(SessionEffect::EndSession);
            effects
        }
    };

    (state, effects)
}

pub(crate) fn apply_accounted_bytes(
    mut state: ServerSessionState,
    direction: ByteDirection,
    bytes: usize,
) -> (ServerSessionState, Option<bool>) {
    match direction {
        ByteDirection::Inbound => {
            state.session_total_in = state.session_total_in.saturating_add(bytes as u64)
        }
        ByteDirection::Outbound => {
            state.session_total_out = state.session_total_out.saturating_add(bytes as u64)
        }
    }

    let pause_changed = refresh_pause_state(&mut state);
    (state, pause_changed)
}

fn refresh_pause_state(state: &mut ServerSessionState) -> Option<bool> {
    let was_paused = state.paused;
    state.paused = remaining_milli_sats(state) <= 0;
    (state.paused != was_paused).then_some(state.paused)
}

fn remaining_milli_sats(state: &ServerSessionState) -> i128 {
    let amount_due = state
        .pricing
        .amount_due_millisats(state.session_total_in, state.session_total_out);
    state.total_paid_millisats as i128 - amount_due as i128
}

#[cfg(test)]
mod tests {
    use super::{
        apply_accounted_bytes, step, ByteDirection, ServerSessionState, SessionEffect, SessionEvent,
    };
    use crate::payments::{ChannelPaymentError, LinkOutcome, PaymentOutcome};
    use monad_common::protocol::ServerMessage;
    use monad_common::session::SessionPricing;

    fn state() -> ServerSessionState {
        ServerSessionState {
            pricing: SessionPricing::new(0, 1, 1),
            session_total_in: 0,
            session_total_out: 0,
            total_paid_millisats: 0,
            paused: true,
            linked_channel_id: None,
            terminated: false,
        }
    }

    #[test]
    fn link_accept_updates_linked_channel_and_emits_status() {
        let (next, effects) = step(
            state(),
            SessionEvent::LinkValidationFinished(Ok(LinkOutcome {
                channel_id: "chan-a".to_string(),
                capacity_millisats: 123,
                evicted_session: None,
            })),
        );

        assert_eq!(next.linked_channel_id.as_deref(), Some("chan-a"));
        assert!(matches!(
            effects.as_slice(),
            [
                SessionEffect::SendControl(ServerMessage::ChannelLinkAccepted { channel_id, capacity }),
                SessionEffect::SendStatus,
            ] if channel_id == "chan-a" && *capacity == 123
        ));
    }

    #[test]
    fn payment_accept_unpauses_and_emits_status() {
        let mut current = state();
        current.linked_channel_id = Some("chan-a".to_string());

        let (next, effects) = step(
            current,
            SessionEvent::PaymentValidationFinished(Ok(PaymentOutcome {
                channel_id: "chan-a".to_string(),
                delta_millisats: 5,
            })),
        );

        assert_eq!(next.total_paid_millisats, 5);
        assert!(!next.paused);
        assert!(matches!(
            effects.as_slice(),
            [
                SessionEffect::UpdatePauseWatch(false),
                SessionEffect::SendStatus
            ]
        ));
    }

    #[test]
    fn payment_rejection_emits_error() {
        let (next, effects) = step(
            state(),
            SessionEvent::PaymentValidationFinished(Err(ChannelPaymentError::WrongChannel)),
        );

        assert_eq!(next, state());
        assert!(matches!(
            effects.as_slice(),
            [SessionEffect::SendControl(ServerMessage::Error { message })]
                if message == "wrong channel"
        ));
    }

    #[test]
    fn eviction_clears_link_and_emits_status() {
        let mut current = state();
        current.linked_channel_id = Some("chan-a".to_string());

        let (next, effects) = step(
            current,
            SessionEvent::ChannelEvicted {
                channel_id: "chan-a".to_string(),
            },
        );

        assert_eq!(next.linked_channel_id, None);
        assert!(matches!(
            effects.as_slice(),
            [
                SessionEffect::SendControl(ServerMessage::ChannelEvicted { channel_id }),
                SessionEffect::SendStatus,
            ] if channel_id == "chan-a"
        ));
    }

    #[test]
    fn control_detached_releases_linked_channel_and_ends_session() {
        let mut current = state();
        current.linked_channel_id = Some("chan-a".to_string());

        let (next, effects) = step(current, SessionEvent::ControlDetached);

        assert!(next.terminated);
        assert_eq!(next.linked_channel_id, None);
        assert!(matches!(
            effects.as_slice(),
            [
                SessionEffect::ReleaseLinkedChannelOwnership { channel_id },
                SessionEffect::EndSession,
            ] if channel_id == "chan-a"
        ));
    }

    #[test]
    fn byte_accounting_only_updates_pause_on_transition() {
        let mut current = state();
        current.total_paid_millisats = 10;
        current.paused = false;

        let (next, pause_changed) = apply_accounted_bytes(current, ByteDirection::Outbound, 4);
        assert_eq!(next.session_total_out, 4);
        assert_eq!(pause_changed, None);

        let (next, pause_changed) = apply_accounted_bytes(next, ByteDirection::Outbound, 6);
        assert_eq!(next.session_total_out, 10);
        assert_eq!(pause_changed, Some(true));
        assert!(next.paused);
    }
}
