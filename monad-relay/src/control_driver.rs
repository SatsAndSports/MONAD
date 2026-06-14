//! Control-session effect interpreter.
//!
//! The driver takes the pure `SessionEffect` values produced by the relay-side
//! session reducer and performs the corresponding I/O and side effects. It does
//! not contain session-state policy; that lives in `session_fsm`.

use crate::session::{send_control_message, SessionState};
use crate::session_fsm::{SessionEffect, SessionEvent};
use bytes::Bytes;
use std::collections::VecDeque;
use std::io;

/// Interpreter for the side effects produced by the session reducer.
pub(crate) struct ControlDriver<'a> {
    state: &'a SessionState,
    h2_send: &'a mut h2::SendStream<Bytes>,
}

impl<'a> ControlDriver<'a> {
    pub(crate) fn new(state: &'a SessionState, h2_send: &'a mut h2::SendStream<Bytes>) -> Self {
        Self { state, h2_send }
    }

    /// Interpret one effect. Returns `true` if the session should end.
    /// May push follow-up events onto the pending queue.
    pub(crate) async fn interpret(
        &mut self,
        effect: SessionEffect,
        pending: &mut VecDeque<SessionEvent>,
    ) -> io::Result<bool> {
        match effect {
            SessionEffect::SendControl(message) => {
                send_control_message(self.h2_send, &message).await?;
            }
            SessionEffect::SendStatus => {
                let status = self.state.session_status_message().await;
                send_control_message(self.h2_send, &status).await?;
            }
            SessionEffect::RunLinkValidation { payment_json } => {
                pending.push_back(SessionEvent::LinkValidationFinished(
                    self.state.link_channel(&payment_json),
                ));
            }
            SessionEffect::RunPaymentValidation {
                expected_channel_id,
                payment_json,
            } => {
                pending.push_back(SessionEvent::PaymentValidationFinished(
                    self.state
                        .apply_channel_payment(&expected_channel_id, &payment_json),
                ));
            }
            SessionEffect::NotifySessionEvicted {
                target_session_id,
                channel_id,
            } => {
                self.state
                    .notify_session_evicted(&target_session_id, channel_id);
            }
            SessionEffect::ReleaseLinkedChannelOwnership { channel_id } => {
                self.state.release_channel_ownership(&channel_id);
            }
            SessionEffect::UpdatePauseWatch(paused) => {
                self.state.update_pause_watch(paused);
            }
            SessionEffect::EndSession => {
                self.state.terminate();
                return Ok(true);
            }
        }
        Ok(false)
    }
}
