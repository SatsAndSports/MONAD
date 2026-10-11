use bytes::Bytes;
use monad_common::control_codec::try_decode_json_line;
use monad_common::control_exchange::{Attribution, PendingRequest};
use monad_common::h2stream::ensure_no_trailers;
use monad_common::protocol::{ClientMessage, ServerErrorCode, ServerMessage};
use monad_common::session::SessionPricing;
use std::io;
use tokio::sync::oneshot;
use tokio::time::{self, Duration, Instant, MissedTickBehavior};
use tracing::{info, warn};

use super::funding::{apply_channel_evicted, apply_channel_unlinked, apply_server_error};
use super::funding::{handle_control_detached, run_funding_cycle};
use super::payment::{
    compute_estimated_remaining, validate_linked_channel_against_session, validate_session_pricing,
    validate_session_status_baseline_against_local_counters,
};
use super::state::{
    apply_session_status, publish_pricing, publish_spilman_info, signal_ready, state_summary,
    DriverState, RelaySnapshot, SessionDriverConfig,
};

fn payment_conflict_error(code: &ServerErrorCode, hop_label: &str) -> Option<io::Error> {
    (*code == ServerErrorCode::PaymentConflict).then(|| {
        io::Error::other(format!(
            "{hop_label} payment state conflict; rebuilding session"
        ))
    })
}

fn funding_disabled_error(code: &ServerErrorCode, hop_label: &str) -> Option<io::Error> {
    (*code == ServerErrorCode::SessionFundingDisabled)
        .then(|| io::Error::other(format!("{hop_label} funding disabled for this session")))
}

const HEARTBEAT_INTERVAL: Duration = Duration::from_secs(5);
pub(super) const HEARTBEAT_TIMEOUT: Duration = Duration::from_secs(15);
const HEARTBEAT_TICK: Duration = Duration::from_secs(1);

#[derive(Debug)]
struct PendingPing {
    nonce: String,
    sent_at: Instant,
}

#[derive(Debug, Default)]
struct ControlHeartbeat {
    last_server_message_at: Option<Instant>,
    ping_to_submit: Option<String>,
    pending_ping: Option<PendingPing>,
    next_ping_sequence: u64,
}

#[derive(Debug, PartialEq, Eq)]
enum HeartbeatAction {
    None,
    SendPing { nonce: String },
    TimedOut,
}

impl ControlHeartbeat {
    fn observe_server_message(
        &mut self,
        now: Instant,
        attribution: &Attribution,
        message: &ServerMessage,
    ) -> HeartbeatAction {
        if *attribution == Attribution::Unsolicited {
            return HeartbeatAction::None;
        }

        self.last_server_message_at = Some(now);
        if let ServerMessage::Pong { nonce } = message {
            if let Some(pending) = &self.pending_ping {
                if pending.nonce == *nonce {
                    if now >= pending.sent_at + HEARTBEAT_TIMEOUT {
                        return HeartbeatAction::TimedOut;
                    }
                    self.pending_ping = None;
                }
            }
        }
        HeartbeatAction::None
    }

    fn ping_submitted(&mut self, now: Instant, nonce: String) {
        debug_assert_eq!(self.ping_to_submit.as_deref(), Some(nonce.as_str()));
        self.ping_to_submit = None;
        self.pending_ping = Some(PendingPing {
            nonce,
            sent_at: now,
        });
    }

    fn on_tick(&mut self, now: Instant, session_id: &[u8; 32]) -> HeartbeatAction {
        if let Some(pending) = &self.pending_ping {
            if now.duration_since(pending.sent_at) >= HEARTBEAT_TIMEOUT {
                return HeartbeatAction::TimedOut;
            }
            return HeartbeatAction::None;
        }
        if self.ping_to_submit.is_some() {
            return HeartbeatAction::None;
        }

        let Some(last_seen) = self.last_server_message_at else {
            return HeartbeatAction::None;
        };

        if now.duration_since(last_seen) >= HEARTBEAT_INTERVAL {
            let sequence = self.next_ping_sequence;
            let Some(next_sequence) = sequence.checked_add(1) else {
                return HeartbeatAction::TimedOut;
            };
            self.next_ping_sequence = next_sequence;
            let nonce = format!("monad:{}:{sequence}", hex::encode(session_id));
            self.ping_to_submit = Some(nonce.clone());
            return HeartbeatAction::SendPing { nonce };
        }

        HeartbeatAction::None
    }
}

async fn apply_driver_session_status(
    config: &SessionDriverConfig,
    state: &mut DriverState,
    snapshot: RelaySnapshot,
    attribution: Attribution,
) -> bool {
    let confirmed_unlink_channel = match &attribution {
        Attribution::Response(PendingRequest::Unlink { channel_id }) => Some(channel_id.clone()),
        _ => None,
    };
    let resolved_payment = matches!(
        attribution,
        Attribution::Response(PendingRequest::Payment { .. })
    );
    apply_session_status(state, snapshot);
    if let Some(channel_id) = confirmed_unlink_channel {
        apply_channel_unlinked(config, state, channel_id).await;
    }
    resolved_payment
}

pub(super) async fn run_session_driver(
    mut h2_send: h2::SendStream<Bytes>,
    mut h2_recv: h2::RecvStream,
    ready_tx: oneshot::Sender<()>,
    config: SessionDriverConfig,
) -> io::Result<()> {
    let mut buf = Vec::new();
    let mut state = DriverState {
        cashu_spilman_protocol_version: config
            .conn
            .cashu_spilman_protocol_version_handle
            .read()
            .await
            .clone(),
        cashu_spilman_keyset_versions: config
            .conn
            .cashu_spilman_keyset_versions_handle
            .read()
            .await
            .clone(),
        ..DriverState::default()
    };
    let mut ready_tx = Some(ready_tx);

    let mut payment_tick = time::interval(Duration::from_millis(250));
    payment_tick.set_missed_tick_behavior(MissedTickBehavior::Skip);
    let mut heartbeat_tick = time::interval(HEARTBEAT_TICK);
    heartbeat_tick.set_missed_tick_behavior(MissedTickBehavior::Skip);
    let mut heartbeat = ControlHeartbeat::default();
    let mut warned_unsolicited = false;

    let result = async {
        loop {
            tokio::select! {
            maybe_chunk = h2_recv.data() => {
                let Some(chunk) = maybe_chunk else {
                    ensure_no_trailers(&mut h2_recv).await?;
                    break;
                };
                let data = chunk.map_err(|e| io::Error::other(format!("h2 recv error: {e}")))?;
                let len = data.len();
                let _ = h2_recv.flow_control().release_capacity(len);
                buf.extend_from_slice(&data);

                loop {
                    let Some(message) = try_decode_json_line::<ServerMessage>(&mut buf)? else {
                        break;
                    };
                    let observed_at = Instant::now();
                    let attribution = state.exchange.classify(&message).map_err(|error| {
                        if let ServerMessage::Error { code, .. } = &message {
                            io::Error::new(
                                io::ErrorKind::InvalidData,
                                format!("fatal control error: {code:?}"),
                            )
                        } else { error }
                    })?;
                    if attribution == Attribution::Unsolicited {
                        if !warned_unsolicited {
                            warn!("discarding unsolicited control response with empty request FIFO");
                            warned_unsolicited = true;
                        }
                        continue;
                    }
                    if (state.exchange.is_initialized() || attribution == Attribution::InitialStatus)
                        && heartbeat.observe_server_message(observed_at, &attribution, &message)
                        == HeartbeatAction::TimedOut
                    {
                        return Err(heartbeat_timeout_error(&config.hop_label));
                    }

                    let accepted_message = message.clone();
                    let resolved_payment = match message {
                        ServerMessage::SessionStatus {
                            receiver_pubkey,
                            advertisements,
                            linked_channel,
                            active_in_rate,
                            active_out_rate,
                            session_total_bytes_in,
                            session_total_bytes_out,
                            total_paid_millisats,
                            remaining_milli_sats,
                            paused,
                            open_connects,
                            total_connects,
                            failed_connects,
                        } => {
                            if let Err(error) = validate_linked_channel_against_session(
                                &state,
                                config.conn.session_id,
                                &attribution,
                                linked_channel.as_ref(),
                            ) {
                                if let Some((owner, _)) = &config.management {
                                    let message = if error.kind() == io::ErrorKind::InvalidData {
                                        error.to_string()
                                    } else {
                                        "Unable to validate linked channel against local wallet".to_owned()
                                    };
                                    owner.events.record("session_payment_failed", serde_json::json!({
                                        "session_id": hex::encode(config.conn.session_id),
                                        "message": message,
                                    }));
                                }
                                return Err(error);
                            }
                            let previous_paid = state.relay_snapshot.as_ref().map(|s| s.total_paid_millisats).unwrap_or(0);
                            let pricing = SessionPricing::try_new(active_in_rate, active_out_rate)
                                .map_err(|error| io::Error::new(
                                    io::ErrorKind::InvalidData,
                                    format!("protocol violation: invalid relay session pricing: {error}"),
                                ))?;
                            validate_session_pricing(&mut state.established_pricing, pricing)?;
                            let due_now = pricing.amount_due_millisats(session_total_bytes_in, session_total_bytes_out);
                            info!(
                                "{} session status: open_connects={} total_connects={} failed_connects={} paused={} balance={} paid={} due={} linked={:?} intended={} op={:?} blocked={:?} local_remaining={:?}",
                                config.hop_label,
                                open_connects,
                                total_connects,
                                failed_connects,
                                paused,
                                remaining_milli_sats,
                                total_paid_millisats,
                                due_now,
                                linked_channel.as_ref().map(|channel| &channel.channel_id),
                                state.intended_channel_id.as_deref().unwrap_or("none"),
                                 state.exchange.pending(),
                                state.funding_blocked_reason,
                                compute_estimated_remaining(&state, &config.conn.cleartext_byte_counters),
                            );
                             let snapshot = RelaySnapshot {
                                    receiver_pubkey,
                                    advertisements: monad_common::protocol::advertisement_options(&advertisements, active_in_rate, active_out_rate),
                                    linked_channel,
                                    session_total_bytes_in,
                                    session_total_bytes_out,
                                    total_paid_millisats,
                                    remaining_milli_sats,
                                    paused,
                                 };
                            validate_session_status_baseline_against_local_counters(
                                &snapshot,
                                &config.conn.cleartext_byte_counters,
                            )?;
                             state.exchange.step(super::reducer::Event::Accept(accepted_message))?;
                             if matches!(attribution, Attribution::Response(PendingRequest::Link { .. })) {
                                 super::funding::finish_replacement(&config, &mut state, true).await?;
                             }
                               let resolved = apply_driver_session_status(&config, &mut state, snapshot, attribution).await;
                            publish_pricing(&config, pricing).await;
                            publish_spilman_info(&config, &state).await;
                            if let Some((owner, hop)) = &config.management {
                                if super::state::relay_confirms_intended_channel(&state) { hop.channel_admitted(owner); }
                                if total_paid_millisats > previous_paid {
                                    owner.events.record("payment_observed", serde_json::json!({
                                        "session_id": hex::encode(config.conn.session_id),
                                        "delta_msats": total_paid_millisats - previous_paid,
                                        "total_paid_msats": total_paid_millisats,
                                    }));
                                }
                                hop.status(owner, state.relay_snapshot.as_ref().and_then(|s| s.linked_channel.clone()), paused, total_paid_millisats, remaining_milli_sats);
                            }
                            if resolved && total_paid_millisats > 0 && !paused {
                                signal_ready(&mut state, &mut ready_tx).await;
                            }
                            resolved
                        }
                        ServerMessage::ChannelEvicted { channel_id, scope } => {
                            warn!(
                                "{} channel {channel_id} evicted with {scope:?} scope | {}",
                                config.hop_label,
                                state_summary(&state, &config.conn.cleartext_byte_counters)
                            );
                            apply_channel_evicted(&config, &mut state, channel_id).await;
                            false
                        }
                        ServerMessage::ChannelReleaseRequested { channel_id } => {
                            super::funding::apply_channel_release_requested(
                                &config,
                                &mut state,
                                &mut h2_send,
                                channel_id,
                            )
                            .await?;
                            false
                        }
                        ServerMessage::Pong { .. } => {
                            continue;
                        }
                        ServerMessage::ExtensionNotification(_) => {
                            continue;
                        }
                        ServerMessage::Error { code, message } => {
                            state.exchange.step(super::reducer::Event::Accept(accepted_message))?;
                            warn!(
                                "{} control error: code={:?} message={} | {}",
                                config.hop_label,
                                code,
                                message,
                                state_summary(&state, &config.conn.cleartext_byte_counters)
                            );
                            if code.is_fatal() {
                                return Err(io::Error::new(io::ErrorKind::InvalidData, message));
                            }
                            if let Some(error) = funding_disabled_error(&code, &config.hop_label) {
                                return Err(error);
                            }
                            if let Some(error) = payment_conflict_error(&code, &config.hop_label) {
                                return Err(error);
                            }
                            let payment_pending = matches!(
                                attribution,
                                Attribution::Response(PendingRequest::Payment { .. })
                            );
                            let link_pending = matches!(attribution, Attribution::Response(PendingRequest::Link { .. }));
                            let rejection_code = format!("{code:?}");
                            apply_server_error(&config, &mut state, code).await?;
                            if link_pending {
                                super::funding::finish_replacement(&config, &mut state, false).await?;
                            }
                            if payment_pending {
                                return Err(io::Error::other(format!(
                                    "{} payment rejected ({rejection_code}); signed payment retained",
                                    config.hop_label,
                                )));
                            }
                            false
                        }
                    };

                    if state.terminated {
                        return Ok(());
                    }

                    run_funding_cycle(&config, &mut state, &mut h2_send, resolved_payment).await?;
                }
            }
            _ = payment_tick.tick() => {
                if state.terminated {
                    return Ok(());
                }
                run_funding_cycle(&config, &mut state, &mut h2_send, false).await?;
            }
            _ = heartbeat_tick.tick() => {
                match heartbeat.on_tick(Instant::now(), &config.conn.session_id) {
                    HeartbeatAction::None => {}
                    HeartbeatAction::SendPing { nonce } => {
                        super::funding::send_control_message(
                            &mut h2_send,
                            &ClientMessage::Ping {
                                nonce: nonce.clone(),
                            },
                        )
                        .await?;
                        heartbeat.ping_submitted(Instant::now(), nonce);
                    }
                    HeartbeatAction::TimedOut => {
                        return Err(heartbeat_timeout_error(&config.hop_label));
                    }
                }
            }
            }
        }
        Ok(())
    }
    .await;

    handle_control_detached(&config, &mut state).await;
    state
        .exchange
        .step(super::reducer::Event::CleanupFinished)?;
    result
}

fn heartbeat_timeout_error(hop_label: &str) -> io::Error {
    io::Error::new(
        io::ErrorKind::TimedOut,
        format!(
            "{hop_label} control heartbeat timed out after {}ms",
            HEARTBEAT_TIMEOUT.as_millis()
        ),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn zero_window_control_send_obeys_heartbeat_deadline() {
        let (client, server) = tokio::io::duplex(4096);
        let (mut client, connection) = h2::client::handshake(client).await.unwrap();
        let mut tasks = tokio::task::JoinSet::new();
        tasks.spawn(async move {
            let _ = connection.await;
        });
        let (response, mut send) = client
            .send_request(
                http::Request::builder()
                    .method(http::Method::POST)
                    .uri("https://monad/control")
                    .body(())
                    .unwrap(),
                false,
            )
            .unwrap();
        let mut server = h2::server::Builder::new()
            .initial_window_size(0)
            .handshake::<_, Bytes>(server)
            .await
            .unwrap();
        let (_request, mut respond) = server.accept().await.unwrap().unwrap();
        let _send = respond
            .send_response(http::Response::new(()), false)
            .unwrap();
        tasks.spawn(async move { while server.accept().await.is_some() {} });
        let _response = response.await.unwrap();
        time::pause();
        let start = Instant::now();
        let error = super::super::funding::send_control_message(
            &mut send,
            &ClientMessage::Ping {
                nonce: "zero-window".to_string(),
            },
        )
        .await
        .unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::TimedOut);
        assert!(start.elapsed() >= HEARTBEAT_TIMEOUT);
        assert!(start.elapsed() <= HEARTBEAT_TIMEOUT + Duration::from_millis(2));
        tasks.shutdown().await;
    }

    #[test]
    fn payment_conflict_terminates_session_for_route_rebuild() {
        let error = payment_conflict_error(&ServerErrorCode::PaymentConflict, "hop 2/3")
            .expect("payment conflict policy must rebuild this session");
        assert_eq!(error.kind(), io::ErrorKind::Other);
        assert!(error.to_string().contains("rebuilding session"));
        assert!(payment_conflict_error(&ServerErrorCode::PaymentNoNewFunds, "hop 2/3").is_none());
    }

    #[test]
    fn funding_disabled_terminates_session_for_route_rebuild() {
        let error = funding_disabled_error(&ServerErrorCode::SessionFundingDisabled, "hop 2/3")
            .expect("funding-disabled policy must rebuild this session");
        assert_eq!(error.kind(), io::ErrorKind::Other);
        assert!(error.to_string().contains("funding disabled"));
        assert!(
            funding_disabled_error(&ServerErrorCode::ChannelAdmissionDisabled, "hop 2/3").is_none()
        );
    }

    fn heartbeat_session_id() -> [u8; 32] {
        [7; 32]
    }

    fn expected_nonce(sequence: u64) -> String {
        format!("monad:{}:{sequence}", hex::encode(heartbeat_session_id()))
    }

    #[test]
    fn heartbeat_waits_for_initial_server_message() {
        let session_id = heartbeat_session_id();
        let mut heartbeat = ControlHeartbeat::default();
        assert_eq!(
            heartbeat.on_tick(Instant::now() + HEARTBEAT_INTERVAL, &session_id),
            HeartbeatAction::None
        );
    }

    #[test]
    fn heartbeat_sends_correlated_ping_after_idle_interval() {
        let session_id = heartbeat_session_id();
        let now = Instant::now();
        let mut heartbeat = ControlHeartbeat {
            last_server_message_at: Some(now),
            ..Default::default()
        };

        assert_eq!(
            heartbeat.on_tick(
                now + HEARTBEAT_INTERVAL - Duration::from_millis(1),
                &session_id
            ),
            HeartbeatAction::None
        );
        assert_eq!(
            heartbeat.on_tick(now + HEARTBEAT_INTERVAL, &session_id),
            HeartbeatAction::SendPing {
                nonce: expected_nonce(0)
            }
        );
        heartbeat.ping_submitted(now + HEARTBEAT_INTERVAL, expected_nonce(0));
        assert_eq!(
            heartbeat.on_tick(
                now + HEARTBEAT_INTERVAL + Duration::from_secs(1),
                &session_id
            ),
            HeartbeatAction::None
        );
    }

    #[test]
    fn only_matching_pong_answers_pending_ping() {
        let session_id = heartbeat_session_id();
        let now = Instant::now();
        let mut heartbeat = ControlHeartbeat {
            last_server_message_at: Some(now),
            ..Default::default()
        };
        assert_eq!(
            heartbeat.on_tick(now + HEARTBEAT_INTERVAL, &session_id),
            HeartbeatAction::SendPing {
                nonce: expected_nonce(0)
            }
        );
        heartbeat.ping_submitted(now + HEARTBEAT_INTERVAL, expected_nonce(0));

        let unrelated_at = now + HEARTBEAT_INTERVAL + Duration::from_secs(1);
        assert_eq!(
            heartbeat.observe_server_message(
                unrelated_at,
                &Attribution::Notification,
                &ServerMessage::ChannelReleaseRequested {
                    channel_id: "channel".into(),
                },
            ),
            HeartbeatAction::None
        );
        let mismatched_at = now + HEARTBEAT_INTERVAL + Duration::from_secs(2);
        assert_eq!(
            heartbeat.observe_server_message(
                mismatched_at,
                &Attribution::Notification,
                &ServerMessage::Pong {
                    nonce: "different".into(),
                },
            ),
            HeartbeatAction::None
        );
        assert_eq!(
            heartbeat.on_tick(
                now + HEARTBEAT_INTERVAL + HEARTBEAT_TIMEOUT - Duration::from_millis(1),
                &session_id
            ),
            HeartbeatAction::None
        );

        let matched_at = now + HEARTBEAT_INTERVAL + Duration::from_secs(3);
        assert_eq!(
            heartbeat.observe_server_message(
                matched_at,
                &Attribution::Notification,
                &ServerMessage::Pong {
                    nonce: expected_nonce(0),
                },
            ),
            HeartbeatAction::None
        );
        assert_eq!(
            heartbeat.on_tick(
                matched_at + HEARTBEAT_INTERVAL - Duration::from_millis(1),
                &session_id
            ),
            HeartbeatAction::None
        );
        assert_eq!(
            heartbeat.on_tick(matched_at + HEARTBEAT_INTERVAL, &session_id),
            HeartbeatAction::SendPing {
                nonce: expected_nonce(1)
            }
        );
    }

    #[test]
    fn ordinary_traffic_and_mismatched_pong_do_not_prevent_ping_timeout() {
        let session_id = heartbeat_session_id();
        let now = Instant::now();
        let mut heartbeat = ControlHeartbeat {
            last_server_message_at: Some(now),
            ..Default::default()
        };
        assert_eq!(
            heartbeat.on_tick(now + HEARTBEAT_INTERVAL, &session_id),
            HeartbeatAction::SendPing {
                nonce: expected_nonce(0)
            }
        );
        heartbeat.ping_submitted(now + HEARTBEAT_INTERVAL, expected_nonce(0));

        assert_eq!(
            heartbeat.observe_server_message(
                now + HEARTBEAT_INTERVAL + Duration::from_secs(1),
                &Attribution::Notification,
                &ServerMessage::ChannelReleaseRequested {
                    channel_id: "channel".into(),
                },
            ),
            HeartbeatAction::None
        );
        assert_eq!(
            heartbeat.observe_server_message(
                now + HEARTBEAT_INTERVAL + Duration::from_secs(2),
                &Attribution::Notification,
                &ServerMessage::Pong {
                    nonce: "different".into(),
                },
            ),
            HeartbeatAction::None
        );
        assert_eq!(
            heartbeat.on_tick(
                now + HEARTBEAT_INTERVAL + HEARTBEAT_TIMEOUT - Duration::from_millis(1),
                &session_id
            ),
            HeartbeatAction::None
        );
        assert_eq!(
            heartbeat.on_tick(now + HEARTBEAT_INTERVAL + HEARTBEAT_TIMEOUT, &session_id),
            HeartbeatAction::TimedOut
        );
    }

    #[test]
    fn extensions_and_advisories_defer_an_unsent_ping() {
        let session_id = heartbeat_session_id();
        let now = Instant::now();

        for message in [
            ServerMessage::ExtensionNotification(monad_common::protocol::ExtensionNotification {
                name: "example.activity".into(),
                rest: Default::default(),
            }),
            ServerMessage::ChannelReleaseRequested {
                channel_id: "channel".into(),
            },
        ] {
            let mut heartbeat = ControlHeartbeat {
                last_server_message_at: Some(now),
                ..Default::default()
            };
            let observed_at = now + HEARTBEAT_INTERVAL;
            assert_eq!(
                heartbeat
                    .observe_server_message(observed_at, &Attribution::Notification, &message,),
                HeartbeatAction::None
            );
            assert_eq!(
                heartbeat.on_tick(
                    observed_at + HEARTBEAT_INTERVAL - Duration::from_millis(1),
                    &session_id,
                ),
                HeartbeatAction::None
            );
            assert!(matches!(
                heartbeat.on_tick(observed_at + HEARTBEAT_INTERVAL, &session_id),
                HeartbeatAction::SendPing { .. }
            ));
        }
    }

    #[test]
    fn discarded_unsolicited_response_does_not_defer_ping() {
        let session_id = heartbeat_session_id();
        let now = Instant::now();
        let mut heartbeat = ControlHeartbeat {
            last_server_message_at: Some(now),
            ..Default::default()
        };

        assert_eq!(
            heartbeat.observe_server_message(
                now + HEARTBEAT_INTERVAL - Duration::from_millis(1),
                &Attribution::Unsolicited,
                &ServerMessage::Error {
                    code: ServerErrorCode::PaymentNoNewFunds,
                    message: "discarded".into(),
                },
            ),
            HeartbeatAction::None
        );
        assert!(matches!(
            heartbeat.on_tick(now + HEARTBEAT_INTERVAL, &session_id),
            HeartbeatAction::SendPing { .. }
        ));
    }

    #[test]
    fn accepted_ordinary_response_defers_only_an_unsent_ping() {
        let session_id = heartbeat_session_id();
        let now = Instant::now();
        let response = ServerMessage::Error {
            code: ServerErrorCode::PaymentNoNewFunds,
            message: "accepted response".into(),
        };
        let attribution = Attribution::Response(PendingRequest::Status);

        let mut unsent = ControlHeartbeat {
            last_server_message_at: Some(now),
            ..Default::default()
        };
        let observed_at = now + HEARTBEAT_INTERVAL;
        assert_eq!(
            unsent.observe_server_message(observed_at, &attribution, &response),
            HeartbeatAction::None
        );
        assert_eq!(
            unsent.on_tick(
                observed_at + HEARTBEAT_INTERVAL - Duration::from_millis(1),
                &session_id,
            ),
            HeartbeatAction::None
        );

        let mut pending = ControlHeartbeat {
            last_server_message_at: Some(now),
            ..Default::default()
        };
        let sent_at = now + HEARTBEAT_INTERVAL;
        assert!(matches!(
            pending.on_tick(sent_at, &session_id),
            HeartbeatAction::SendPing { .. }
        ));
        pending.ping_submitted(sent_at, expected_nonce(0));
        assert_eq!(
            pending.observe_server_message(
                sent_at + Duration::from_secs(1),
                &attribution,
                &response,
            ),
            HeartbeatAction::None
        );
        assert_eq!(
            pending.on_tick(sent_at + HEARTBEAT_TIMEOUT, &session_id),
            HeartbeatAction::TimedOut
        );
    }

    #[test]
    fn extension_and_advisory_do_not_extend_pending_ping_deadline() {
        let session_id = heartbeat_session_id();
        let now = Instant::now();
        let sent_at = now + HEARTBEAT_INTERVAL;
        let mut heartbeat = ControlHeartbeat {
            last_server_message_at: Some(now),
            ..Default::default()
        };
        assert!(matches!(
            heartbeat.on_tick(sent_at, &session_id),
            HeartbeatAction::SendPing { .. }
        ));
        heartbeat.ping_submitted(sent_at, expected_nonce(0));

        for (offset, message) in [
            (
                Duration::from_secs(1),
                ServerMessage::ExtensionNotification(
                    monad_common::protocol::ExtensionNotification {
                        name: "example.activity".into(),
                        rest: Default::default(),
                    },
                ),
            ),
            (
                HEARTBEAT_TIMEOUT - Duration::from_millis(1),
                ServerMessage::ChannelReleaseRequested {
                    channel_id: "channel".into(),
                },
            ),
        ] {
            assert_eq!(
                heartbeat.observe_server_message(
                    sent_at + offset,
                    &Attribution::Notification,
                    &message,
                ),
                HeartbeatAction::None
            );
        }
        assert_eq!(
            heartbeat.on_tick(sent_at + HEARTBEAT_TIMEOUT, &session_id),
            HeartbeatAction::TimedOut
        );
    }

    #[test]
    fn matching_pong_at_deadline_is_too_late() {
        let session_id = heartbeat_session_id();
        let now = Instant::now();
        let sent_at = now + HEARTBEAT_INTERVAL;
        let mut heartbeat = ControlHeartbeat {
            last_server_message_at: Some(now),
            ..Default::default()
        };
        assert!(matches!(
            heartbeat.on_tick(sent_at, &session_id),
            HeartbeatAction::SendPing { .. }
        ));
        heartbeat.ping_submitted(sent_at, expected_nonce(0));

        assert_eq!(
            heartbeat.observe_server_message(
                sent_at + HEARTBEAT_TIMEOUT,
                &Attribution::Notification,
                &ServerMessage::Pong {
                    nonce: expected_nonce(0),
                },
            ),
            HeartbeatAction::TimedOut
        );
    }

    #[test]
    fn pong_deadline_starts_after_successful_ping_submission() {
        let session_id = heartbeat_session_id();
        let now = Instant::now();
        let selected_at = now + HEARTBEAT_INTERVAL;
        let submitted_at = selected_at + Duration::from_secs(2);
        let mut heartbeat = ControlHeartbeat {
            last_server_message_at: Some(now),
            ..Default::default()
        };
        assert!(matches!(
            heartbeat.on_tick(selected_at, &session_id),
            HeartbeatAction::SendPing { .. }
        ));
        heartbeat.ping_submitted(submitted_at, expected_nonce(0));

        assert_eq!(
            heartbeat.on_tick(
                submitted_at + HEARTBEAT_TIMEOUT - Duration::from_millis(1),
                &session_id,
            ),
            HeartbeatAction::None
        );
        assert_eq!(
            heartbeat.on_tick(submitted_at + HEARTBEAT_TIMEOUT, &session_id),
            HeartbeatAction::TimedOut
        );
    }
}
