use bytes::Bytes;
use monad_common::control_codec::try_decode_json_line;
use monad_common::protocol::{ClientMessage, ServerErrorCode, ServerMessage};
use monad_common::session::SessionPricing;
use std::io;
use tokio::sync::oneshot;
use tokio::time::{self, Duration, Instant, MissedTickBehavior};
use tracing::{info, warn};

use super::funding::{apply_channel_evicted, apply_channel_unlinked, apply_server_error};
use super::funding::{handle_control_detached, run_funding_cycle};
use super::payment::{
    compute_estimated_remaining, validate_linked_channel_balance_against_wallet,
    validate_session_pricing, validate_session_status_baseline_against_local_counters,
};
use super::state::{
    apply_session_status, publish_pricing, publish_spilman_info, signal_ready, state_summary,
    ControlOpInFlight, DriverState, RelaySnapshot, SessionDriverConfig,
};

fn payment_conflict_error(code: &ServerErrorCode, hop_label: &str) -> Option<io::Error> {
    (*code == ServerErrorCode::PaymentConflict).then(|| {
        io::Error::other(format!(
            "{hop_label} payment state conflict; rebuilding session"
        ))
    })
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
    fn observe_server_message(&mut self, now: Instant) {
        self.last_server_message_at = Some(now);
    }

    fn observe_pong(&mut self, now: Instant, nonce: &str) -> bool {
        self.observe_server_message(now);
        if self
            .pending_ping
            .as_ref()
            .is_some_and(|pending| pending.nonce == nonce)
        {
            self.pending_ping = None;
            return true;
        }
        false
    }

    fn on_tick(&mut self, now: Instant, session_id: &[u8; 32]) -> HeartbeatAction {
        if let Some(pending) = &self.pending_ping {
            if now.duration_since(pending.sent_at) >= HEARTBEAT_TIMEOUT {
                return HeartbeatAction::TimedOut;
            }
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
            self.pending_ping = Some(PendingPing {
                nonce: nonce.clone(),
                sent_at: now,
            });
            return HeartbeatAction::SendPing { nonce };
        }

        HeartbeatAction::None
    }
}

async fn apply_driver_session_status(
    config: &SessionDriverConfig,
    state: &mut DriverState,
    snapshot: RelaySnapshot,
) -> bool {
    let confirmed_unlink_channel = match (&state.control_op_in_flight, &snapshot.linked_channel) {
        (Some(ControlOpInFlight::Unlink { channel_id }), linked) if !matches!(linked, Some(linked) if linked.channel_id == *channel_id) => {
            Some(channel_id.clone())
        }
        _ => None,
    };
    let resolved_payment = apply_session_status(state, snapshot);
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

    let result = async {
        loop {
            tokio::select! {
            maybe_chunk = h2_recv.data() => {
                let Some(chunk) = maybe_chunk else {
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
                    if let ServerMessage::Pong { nonce } = &message {
                        heartbeat.observe_pong(observed_at, nonce);
                    } else {
                        heartbeat.observe_server_message(observed_at);
                    }

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
                                state.control_op_in_flight,
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
                             if super::state::session_status_is_stale(&state, &snapshot) {
                                 continue;
                             }
                              let resolved = apply_driver_session_status(&config, &mut state, snapshot).await;
                            publish_pricing(&config, pricing).await;
                            publish_spilman_info(&config, &state).await;
                             if let Err(error) = validate_linked_channel_balance_against_wallet(
                                 config.wallet.as_ref(),
                                 &mut state,
                             ) {
                                 if let Some((owner, _)) = &config.management {
                                     // Expose the numeric protocol mismatch, but not
                                     // arbitrary wallet/backend error contents.
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
                            validate_session_status_baseline_against_local_counters(
                                &state,
                                &config.conn.cleartext_byte_counters,
                            )?;
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
                            if !paused {
                                signal_ready(&mut state, &mut ready_tx).await;
                            }
                            resolved
                        }
                        ServerMessage::ChannelEvicted { channel_id } => {
                            warn!(
                                "{} channel {channel_id} evicted from this session | {}",
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
                        ServerMessage::Error { code, message } => {
                            warn!(
                                "{} control error: code={:?} message={} | {}",
                                config.hop_label,
                                code,
                                message,
                                state_summary(&state, &config.conn.cleartext_byte_counters)
                            );
                            if code == monad_common::protocol::ServerErrorCode::LinkKeysetVersionNotNegotiated {
                                return Err(io::Error::new(io::ErrorKind::InvalidData, message));
                            }
                            if let Some(error) = payment_conflict_error(&code, &config.hop_label) {
                                return Err(error);
                            }
                            apply_server_error(&config, &mut state, code).await;
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
                        super::funding::send_control_message(&mut h2_send, &ClientMessage::Ping { nonce }).await?;
                    }
                    HeartbeatAction::TimedOut => {
                    return Err(io::Error::new(
                            io::ErrorKind::TimedOut,
                            format!(
                                "{} control heartbeat timed out after {}ms",
                                config.hop_label,
                                HEARTBEAT_TIMEOUT.as_millis()
                            ),
                        ));
                    }
                }
            }
            }
        }
        Ok(())
    }
    .await;

    handle_control_detached(&config, &mut state).await;
    result
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
            .expect("payment conflict must be fatal to this session");
        assert_eq!(error.kind(), io::ErrorKind::Other);
        assert!(error.to_string().contains("rebuilding session"));
        assert!(payment_conflict_error(&ServerErrorCode::PaymentNoNewFunds, "hop 2/3").is_none());
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
        let mut heartbeat = ControlHeartbeat::default();
        heartbeat.observe_server_message(now);

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
        let mut heartbeat = ControlHeartbeat::default();
        heartbeat.observe_server_message(now);
        assert_eq!(
            heartbeat.on_tick(now + HEARTBEAT_INTERVAL, &session_id),
            HeartbeatAction::SendPing {
                nonce: expected_nonce(0)
            }
        );

        let unrelated_at = now + HEARTBEAT_INTERVAL + Duration::from_secs(1);
        heartbeat.observe_server_message(unrelated_at);
        let mismatched_at = now + HEARTBEAT_INTERVAL + Duration::from_secs(2);
        assert!(!heartbeat.observe_pong(mismatched_at, "different"));
        assert_eq!(
            heartbeat.on_tick(
                now + HEARTBEAT_INTERVAL + HEARTBEAT_TIMEOUT - Duration::from_millis(1),
                &session_id
            ),
            HeartbeatAction::None
        );

        let matched_at = now + HEARTBEAT_INTERVAL + Duration::from_secs(3);
        assert!(heartbeat.observe_pong(matched_at, &expected_nonce(0)));
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
        let mut heartbeat = ControlHeartbeat::default();
        heartbeat.observe_server_message(now);
        assert_eq!(
            heartbeat.on_tick(now + HEARTBEAT_INTERVAL, &session_id),
            HeartbeatAction::SendPing {
                nonce: expected_nonce(0)
            }
        );

        heartbeat.observe_server_message(now + HEARTBEAT_INTERVAL + Duration::from_secs(1));
        assert!(!heartbeat.observe_pong(
            now + HEARTBEAT_INTERVAL + Duration::from_secs(2),
            "different"
        ));
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
}
