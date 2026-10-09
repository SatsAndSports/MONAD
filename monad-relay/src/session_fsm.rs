use crate::payments::{ChannelPaymentError, LinkError, LinkOutcome, PaymentOutcome};
use monad_common::protocol::{ChannelEvictionScope, ServerErrorCode, ServerMessage};
use monad_common::session::SessionPricing;

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ServerSessionState {
    pub session_total_bytes_in: u64,
    pub session_total_bytes_out: u64,
    pub total_paid_millisats: u64,
    pub paused: bool,
    pub linked_channel_id: Option<String>,
    pub terminated: bool,
}

#[derive(Debug, Clone)]
pub(crate) enum SessionEvent {
    ClientChannelUnlink {
        channel_id: String,
    },
    UnlinkValidationFinished {
        result: Result<(), String>,
    },
    ClientGetSessionStatus,
    ClientPing {
        nonce: String,
    },
    ClientChannelLink {
        payment_json: String,
    },
    LinkValidationFinished(Result<LinkOutcome, LinkError>),
    ClientChannelPayment {
        payment_json: String,
    },
    PaymentValidationFinished(Result<PaymentOutcome, ChannelPaymentError>),
    ChannelEvicted {
        channel_id: String,
        scope: ChannelEvictionScope,
    },
    ControlDetached,
}

#[derive(Debug, Clone)]
pub(crate) enum SessionEffect {
    RunUnlinkValidation {
        channel_id: String,
    },
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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum SessionAccountingError {
    CounterOverflow,
    RemainingOutOfRange,
}

fn error_effects(
    state: &mut ServerSessionState,
    code: ServerErrorCode,
    mut message: String,
) -> Vec<SessionEffect> {
    let fatal = code.is_fatal();
    if code == ServerErrorCode::InternalError {
        message = "internal request processing error".into();
    }
    let mut effects = Vec::new();
    if fatal {
        state.terminated = true;
        if let Some(channel_id) = state.linked_channel_id.take() {
            effects.push(SessionEffect::ReleaseLinkedChannelOwnership { channel_id });
        }
    }
    effects.push(SessionEffect::SendControl(ServerMessage::Error {
        code,
        message,
    }));
    if fatal {
        effects.push(SessionEffect::EndSession);
    }
    effects
}

pub(crate) fn step(
    mut state: ServerSessionState,
    event: SessionEvent,
    pricing: SessionPricing,
) -> (ServerSessionState, Vec<SessionEffect>) {
    if state.terminated {
        return (state, Vec::new());
    }

    let effects = match event {
        SessionEvent::ClientChannelUnlink { channel_id } => {
            if state
                .linked_channel_id
                .as_ref()
                .is_some_and(|id| id != &channel_id)
            {
                vec![SessionEffect::SendControl(ServerMessage::Error {
                    code: monad_common::protocol::ServerErrorCode::ChannelUnlinkRejected,
                    message: "channel is not linked to this session".into(),
                })]
            } else {
                vec![SessionEffect::RunUnlinkValidation { channel_id }]
            }
        }
        SessionEvent::UnlinkValidationFinished { result, .. } => match result {
            Ok(()) => {
                state.linked_channel_id = None;
                vec![SessionEffect::SendStatus]
            }
            Err(_) => vec![SessionEffect::SendControl(ServerMessage::Error {
                code: monad_common::protocol::ServerErrorCode::ChannelUnlinkRejected,
                message: "channel unlink rejected: ownership mismatch".into(),
            })],
        },
        SessionEvent::ClientGetSessionStatus => vec![SessionEffect::SendStatus],
        SessionEvent::ClientPing { nonce } => {
            vec![SessionEffect::SendControl(ServerMessage::Pong { nonce })]
        }
        SessionEvent::ClientChannelLink { payment_json } => {
            vec![SessionEffect::RunLinkValidation { payment_json }]
        }
        SessionEvent::LinkValidationFinished(result) => match result {
            Ok(outcome) => {
                let previous_channel = state
                    .linked_channel_id
                    .replace(outcome.channel_id.clone())
                    .filter(|channel_id| channel_id != &outcome.channel_id);
                let mut effects = Vec::new();
                if let Some(channel_id) = previous_channel {
                    effects.push(SessionEffect::ReleaseLinkedChannelOwnership { channel_id });
                }
                if let Some(evicted_session) = outcome.evicted_session {
                    effects.push(SessionEffect::NotifySessionEvicted {
                        target_session_id: evicted_session,
                        channel_id: outcome.channel_id,
                    });
                }
                effects.push(SessionEffect::SendStatus);
                effects
            }
            Err(err) => error_effects(&mut state, err.code(), err.to_string()),
        },
        SessionEvent::ClientChannelPayment { payment_json } => {
            if let Some(expected_channel_id) = state.linked_channel_id.clone() {
                vec![SessionEffect::RunPaymentValidation {
                    expected_channel_id,
                    payment_json,
                }]
            } else {
                vec![SessionEffect::SendControl(ServerMessage::Error {
                    code: ChannelPaymentError::WrongChannel.code(),
                    message: ChannelPaymentError::WrongChannel.to_string(),
                })]
            }
        }
        SessionEvent::PaymentValidationFinished(result) => match result {
            Ok(outcome) => {
                let Some(total_paid_millisats) = state
                    .total_paid_millisats
                    .checked_add(outcome.delta_millisats)
                else {
                    state.terminated = true;
                    let effects = error_effects(
                        &mut state,
                        ServerErrorCode::InternalError,
                        "session accounting overflow".into(),
                    );
                    return (state, effects);
                };
                state.total_paid_millisats = total_paid_millisats;
                let pause_changed = refresh_pause_state(&mut state, pricing);
                let mut effects = Vec::new();
                if let Some(paused) = pause_changed {
                    effects.push(SessionEffect::UpdatePauseWatch(paused));
                }
                effects.push(SessionEffect::SendStatus);
                effects
            }
            Err(err) => error_effects(&mut state, err.code(), err.to_string()),
        },
        SessionEvent::ChannelEvicted { channel_id, scope } => {
            if state.linked_channel_id.as_deref() == Some(channel_id.as_str()) {
                state.linked_channel_id = None;
            }
            vec![SessionEffect::SendControl(ServerMessage::ChannelEvicted {
                channel_id,
                scope,
            })]
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
    pricing: SessionPricing,
    direction: ByteDirection,
    bytes: usize,
) -> Result<(ServerSessionState, Option<bool>), SessionAccountingError> {
    let bytes = u64::try_from(bytes).map_err(|_| SessionAccountingError::CounterOverflow)?;
    match direction {
        ByteDirection::Inbound => {
            state.session_total_bytes_in = state
                .session_total_bytes_in
                .checked_add(bytes)
                .ok_or(SessionAccountingError::CounterOverflow)?;
        }
        ByteDirection::Outbound => {
            state.session_total_bytes_out = state
                .session_total_bytes_out
                .checked_add(bytes)
                .ok_or(SessionAccountingError::CounterOverflow)?;
        }
    }

    if i64::try_from(remaining_milli_sats(&state, pricing)).is_err() {
        return Err(SessionAccountingError::RemainingOutOfRange);
    }
    let pause_changed = refresh_pause_state(&mut state, pricing);
    Ok((state, pause_changed))
}

fn refresh_pause_state(state: &mut ServerSessionState, pricing: SessionPricing) -> Option<bool> {
    let was_paused = state.paused;
    state.paused = remaining_milli_sats(state, pricing) <= 0;
    (state.paused != was_paused).then_some(state.paused)
}

pub(crate) fn remaining_milli_sats(state: &ServerSessionState, pricing: SessionPricing) -> i128 {
    pricing.remaining_milli_sats(
        state.total_paid_millisats,
        state.session_total_bytes_in,
        state.session_total_bytes_out,
    )
}

#[cfg(test)]
mod tests {
    use super::{
        apply_accounted_bytes, step, ByteDirection, ServerSessionState, SessionAccountingError,
        SessionEffect, SessionEvent,
    };
    use crate::payments::{ChannelPaymentError, LinkError, LinkOutcome, PaymentOutcome};
    use monad_common::protocol::{ChannelEvictionScope, ServerErrorCode, ServerMessage};
    use monad_common::session::SessionPricing;

    fn state() -> ServerSessionState {
        ServerSessionState {
            session_total_bytes_in: 0,
            session_total_bytes_out: 0,
            total_paid_millisats: 0,
            paused: true,
            linked_channel_id: None,
            terminated: false,
        }
    }

    #[test]
    fn ping_echoes_nonce_without_session_mutation() {
        let current = state();
        let (next, effects) = step(
            current.clone(),
            SessionEvent::ClientPing {
                nonce: "opaque-τ-17".to_string(),
            },
            SessionPricing::new(1, 1),
        );

        assert_eq!(next, current);
        assert!(matches!(
            effects.as_slice(),
            [SessionEffect::SendControl(ServerMessage::Pong { nonce })]
                if nonce == "opaque-τ-17"
        ));
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
            SessionPricing::new(1, 1),
        );

        assert_eq!(next.linked_channel_id.as_deref(), Some("chan-a"));
        assert!(matches!(effects.as_slice(), [SessionEffect::SendStatus]));
    }

    #[test]
    fn link_accept_releases_previous_channel_before_status() {
        let mut current = state();
        current.linked_channel_id = Some("chan-a".to_string());
        current.session_total_bytes_in = 11;
        current.session_total_bytes_out = 13;
        current.total_paid_millisats = 29;
        current.paused = false;
        let accounting = current.clone();

        let (next, effects) = step(
            current,
            SessionEvent::LinkValidationFinished(Ok(LinkOutcome {
                channel_id: "chan-b".to_string(),
                capacity_millisats: 123,
                evicted_session: None,
            })),
            SessionPricing::new(1, 1),
        );

        assert_eq!(next.linked_channel_id.as_deref(), Some("chan-b"));
        assert_eq!(
            next.session_total_bytes_in,
            accounting.session_total_bytes_in
        );
        assert_eq!(
            next.session_total_bytes_out,
            accounting.session_total_bytes_out
        );
        assert_eq!(next.total_paid_millisats, accounting.total_paid_millisats);
        assert_eq!(next.paused, accounting.paused);
        assert!(matches!(
            effects.as_slice(),
            [
                SessionEffect::ReleaseLinkedChannelOwnership { channel_id },
                SessionEffect::SendStatus,
            ] if channel_id == "chan-a"
        ));
    }

    #[test]
    fn same_channel_relink_keeps_ownership() {
        let mut current = state();
        current.linked_channel_id = Some("chan-a".to_string());

        let (next, effects) = step(
            current,
            SessionEvent::LinkValidationFinished(Ok(LinkOutcome {
                channel_id: "chan-a".to_string(),
                capacity_millisats: 123,
                evicted_session: None,
            })),
            SessionPricing::new(1, 1),
        );

        assert_eq!(next.linked_channel_id.as_deref(), Some("chan-a"));
        assert!(matches!(effects.as_slice(), [SessionEffect::SendStatus]));
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
            SessionPricing::new(1, 1),
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
            SessionPricing::new(1, 1),
        );

        assert_eq!(next, state());
        assert!(matches!(
            effects.as_slice(),
            [SessionEffect::SendControl(ServerMessage::Error { code, message })]
                if *code == monad_common::protocol::ServerErrorCode::PaymentWrongChannel
                    && message == "wrong channel"
        ));
    }

    #[test]
    fn payment_conflict_emits_dedicated_error_without_credit() {
        let current = state();
        let (next, effects) = step(
            current.clone(),
            SessionEvent::PaymentValidationFinished(Err(ChannelPaymentError::Conflict)),
            SessionPricing::new(1, 1),
        );

        assert_eq!(next, current);
        assert!(matches!(
            effects.as_slice(),
            [SessionEffect::SendControl(ServerMessage::Error { code, message })]
                if *code == monad_common::protocol::ServerErrorCode::PaymentConflict
                    && message == "payment state conflict"
        ));
    }

    #[test]
    fn internal_link_and_payment_failures_release_ownership_and_end_session() {
        for event in [
            SessionEvent::LinkValidationFinished(Err(LinkError::Internal("storage".into()))),
            SessionEvent::PaymentValidationFinished(Err(ChannelPaymentError::Internal(
                "storage".into(),
            ))),
        ] {
            let mut current = state();
            current.linked_channel_id = Some("chan-a".into());
            let (next, effects) = step(current, event, SessionPricing::new(1, 1));

            assert!(next.terminated);
            assert_eq!(next.linked_channel_id, None);
            assert!(matches!(
                effects.as_slice(),
                [
                    SessionEffect::ReleaseLinkedChannelOwnership { channel_id },
                    SessionEffect::SendControl(ServerMessage::Error { code, message }),
                    SessionEffect::EndSession,
                ] if channel_id == "chan-a"
                    && *code == ServerErrorCode::InternalError
                    && message == "internal request processing error"
            ));
        }
    }

    #[test]
    fn eviction_clears_link_and_emits_only_advisory() {
        let mut current = state();
        current.linked_channel_id = Some("chan-a".to_string());

        let (next, effects) = step(
            current,
            SessionEvent::ChannelEvicted {
                channel_id: "chan-a".to_string(),
                scope: ChannelEvictionScope::Session,
            },
            SessionPricing::new(1, 1),
        );

        assert_eq!(next.linked_channel_id, None);
        assert!(matches!(
            effects.as_slice(),
            [
                SessionEffect::SendControl(ServerMessage::ChannelEvicted { channel_id, scope }),
            ] if channel_id == "chan-a" && *scope == ChannelEvictionScope::Session
        ));
    }

    #[test]
    fn unlink_wrong_channel_rejected_without_clearing_link() {
        let mut current = state();
        current.linked_channel_id = Some("chan-a".to_string());

        let (next, effects) = step(
            current,
            SessionEvent::ClientChannelUnlink {
                channel_id: "chan-b".to_string(),
            },
            SessionPricing::new(1, 1),
        );

        assert_eq!(next.linked_channel_id.as_deref(), Some("chan-a"));
        assert!(matches!(
            effects.as_slice(),
            [SessionEffect::SendControl(ServerMessage::Error { code, .. })]
                if *code == monad_common::protocol::ServerErrorCode::ChannelUnlinkRejected
        ));
    }

    #[test]
    fn unlink_success_clears_link_and_confirms() {
        let mut current = state();
        current.linked_channel_id = Some("chan-a".to_string());
        current.session_total_bytes_in = 11;
        current.session_total_bytes_out = 13;
        current.total_paid_millisats = 29;
        current.paused = false;
        let accounting = current.clone();

        let (next, effects) = step(
            current,
            SessionEvent::UnlinkValidationFinished { result: Ok(()) },
            SessionPricing::new(1, 1),
        );

        assert_eq!(next.linked_channel_id, None);
        assert_eq!(
            next.session_total_bytes_in,
            accounting.session_total_bytes_in
        );
        assert_eq!(
            next.session_total_bytes_out,
            accounting.session_total_bytes_out
        );
        assert_eq!(next.total_paid_millisats, accounting.total_paid_millisats);
        assert_eq!(next.paused, accounting.paused);
        assert!(matches!(effects.as_slice(), [SessionEffect::SendStatus]));
    }

    #[test]
    fn unlink_validation_failure_keeps_link() {
        let mut current = state();
        current.linked_channel_id = Some("chan-a".to_string());

        let (next, effects) = step(
            current,
            SessionEvent::UnlinkValidationFinished {
                result: Err("channel is owned by another session".to_string()),
            },
            SessionPricing::new(1, 1),
        );

        assert_eq!(next.linked_channel_id.as_deref(), Some("chan-a"));
        assert!(matches!(
            effects.as_slice(),
            [SessionEffect::SendControl(ServerMessage::Error { code, .. })]
                if *code == monad_common::protocol::ServerErrorCode::ChannelUnlinkRejected
        ));
    }

    #[test]
    fn duplicate_or_stale_unlink_is_rejected_without_fabricating_success() {
        let current = state();

        let (next, effects) = step(
            current,
            SessionEvent::UnlinkValidationFinished {
                result: Err("channel is not owned by this session".to_string()),
            },
            SessionPricing::new(1, 1),
        );

        assert_eq!(next.linked_channel_id, None);
        assert!(matches!(
            effects.as_slice(),
            [SessionEffect::SendControl(ServerMessage::Error { code, .. })]
                if *code == monad_common::protocol::ServerErrorCode::ChannelUnlinkRejected
        ));
    }

    #[test]
    fn unlink_runs_validation_for_linked_channel() {
        let mut current = state();
        current.linked_channel_id = Some("chan-a".to_string());

        let (next, effects) = step(
            current.clone(),
            SessionEvent::ClientChannelUnlink {
                channel_id: "chan-a".to_string(),
            },
            SessionPricing::new(1, 1),
        );

        assert_eq!(next, current);
        assert!(matches!(
            effects.as_slice(),
            [SessionEffect::RunUnlinkValidation { channel_id }] if channel_id == "chan-a"
        ));
    }

    #[test]
    fn control_detached_releases_linked_channel_and_ends_session() {
        let mut current = state();
        current.linked_channel_id = Some("chan-a".to_string());

        let (next, effects) = step(
            current,
            SessionEvent::ControlDetached,
            SessionPricing::new(1, 1),
        );

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

        let (next, pause_changed) = apply_accounted_bytes(
            current,
            SessionPricing::new(1, 1),
            ByteDirection::Outbound,
            4,
        )
        .unwrap();
        assert_eq!(next.session_total_bytes_out, 4);
        assert_eq!(pause_changed, None);

        let (next, pause_changed) =
            apply_accounted_bytes(next, SessionPricing::new(1, 1), ByteDirection::Outbound, 6)
                .unwrap();
        assert_eq!(next.session_total_bytes_out, 10);
        assert_eq!(pause_changed, Some(true));
        assert!(next.paused);
    }

    #[test]
    fn byte_accounting_rejects_counter_overflow_without_mutation() {
        let mut current = state();
        current.session_total_bytes_out = u64::MAX;
        let error = apply_accounted_bytes(
            current.clone(),
            SessionPricing::new(1, 1),
            ByteDirection::Outbound,
            1,
        )
        .unwrap_err();
        assert_eq!(error, SessionAccountingError::CounterOverflow);
        assert_eq!(current.session_total_bytes_out, u64::MAX);
    }
}
