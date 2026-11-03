//! Control-session effect interpreter.
//!
//! The driver takes the pure `SessionEffect` values produced by the relay-side
//! session reducer and performs the corresponding I/O and side effects. It does
//! not contain session-state policy; that lives in `session_fsm`.

use crate::session::{fail_status_construction, send_control_message, SessionState};
use crate::session_fsm::{SessionEffect, SessionEvent};
use bytes::Bytes;
use monad_common::protocol::ServerMessage;
use std::collections::VecDeque;
use std::io;

/// Interpreter for the side effects produced by the session reducer.
pub(crate) struct ControlDriver<'a> {
    state: &'a SessionState,
    h2_send: &'a mut h2::SendStream<Bytes>,
    accepted_payment: Option<(String, u64)>,
}

impl<'a> ControlDriver<'a> {
    pub(crate) fn new(state: &'a SessionState, h2_send: &'a mut h2::SendStream<Bytes>) -> Self {
        Self {
            state,
            h2_send,
            accepted_payment: None,
        }
    }

    /// Interpret one effect. Returns `true` if the session should end.
    /// May push follow-up events onto the pending queue.
    pub(crate) async fn interpret(
        &mut self,
        effect: SessionEffect,
        pending: &mut VecDeque<SessionEvent>,
    ) -> io::Result<bool> {
        match effect {
            SessionEffect::RunUnlinkValidation { channel_id } => {
                let result = self.state.unlink_channel(&channel_id);
                pending.push_back(SessionEvent::UnlinkValidationFinished { result });
            }
            SessionEffect::SendControl(message) => {
                if matches!(&message, ServerMessage::Error { code, .. } if code.is_fatal()) {
                    // Never let a reset or exhausted control window prevent EndSession.
                    let _ = tokio::time::timeout(
                        std::time::Duration::from_millis(250),
                        send_control_message(self.h2_send, &message),
                    )
                    .await;
                } else {
                    send_control_message(self.h2_send, &message).await?;
                }
            }
            SessionEffect::SendStatus => {
                let accepted_payment = self.accepted_payment.take();
                let Some(status) = self
                    .state
                    .session_status_message_for_payment(
                        accepted_payment
                            .as_ref()
                            .map(|(id, balance)| (id.as_str(), *balance)),
                    )
                    .await
                else {
                    fail_status_construction(self.state, self.h2_send).await;
                    return Ok(true);
                };
                send_control_message(self.h2_send, &status).await?;
            }
            SessionEffect::RunLinkValidation(request) => {
                pending.push_back(SessionEvent::LinkValidationFinished(
                    self.state.link_channel_with_keyset_refresh(&request).await,
                ));
            }
            SessionEffect::RunPaymentValidation {
                expected_channel_id,
                request,
            } => {
                let result = self
                    .state
                    .apply_channel_payment(&expected_channel_id, &request)
                    .await;
                if result.is_ok() {
                    self.accepted_payment = Some((request.channel_id.clone(), request.balance_raw));
                }
                pending.push_back(SessionEvent::PaymentValidationFinished(result));
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
