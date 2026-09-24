use bytes::Bytes;
use monad_common::control_codec::try_decode_json_line;
use monad_common::protocol::{ClientMessage, ServerErrorCode, ServerMessage};
use monad_common::session::SessionPricing;
use std::io;
use tokio::sync::oneshot;
use tokio::time::{self, Duration, Instant, MissedTickBehavior};
use tracing::{info, warn};

use super::funding::{apply_channel_evicted, apply_server_error};
use super::funding::{handle_control_detached, run_funding_cycle};
use super::payment::{
    compute_estimated_remaining, validate_linked_channel_balance_against_wallet,
    validate_session_pricing, validate_session_status_baseline_against_local_counters,
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

const HEARTBEAT_INTERVAL: Duration = Duration::from_secs(5);
pub(super) const HEARTBEAT_TIMEOUT: Duration = Duration::from_secs(15);
const HEARTBEAT_TICK: Duration = Duration::from_secs(1);

#[derive(Debug, Default)]
struct ControlHeartbeat {
    last_server_message_at: Option<Instant>,
    heartbeat_sent_at: Option<Instant>,
}

#[derive(Debug, PartialEq, Eq)]
enum HeartbeatAction {
    None,
    SendStatusRequest,
    TimedOut,
}

impl ControlHeartbeat {
    fn observe_server_message(&mut self, now: Instant) {
        self.last_server_message_at = Some(now);
        self.heartbeat_sent_at = None;
    }

    fn on_tick(&mut self, now: Instant) -> HeartbeatAction {
        if let Some(sent_at) = self.heartbeat_sent_at {
            if now.duration_since(sent_at) >= HEARTBEAT_TIMEOUT {
                return HeartbeatAction::TimedOut;
            }
            return HeartbeatAction::None;
        }

        let Some(last_seen) = self.last_server_message_at else {
            return HeartbeatAction::None;
        };

        if now.duration_since(last_seen) >= HEARTBEAT_INTERVAL {
            self.heartbeat_sent_at = Some(now);
            return HeartbeatAction::SendStatusRequest;
        }

        HeartbeatAction::None
    }
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
                    heartbeat.observe_server_message(Instant::now());

                    let resolved_payment = match message {
                        ServerMessage::SessionStatus {
                            receiver_pubkey,
                            advertisements,
                            linked_channel,
                            active_in_rate,
                            active_out_rate,
                            session_total_in,
                            session_total_out,
                            total_paid_millisats,
                            remaining_milli_sats,
                            paused,
                            open_connects,
                            total_connects,
                        } => {
                            let previous_paid = state.relay_snapshot.as_ref().map(|s| s.total_paid_millisats).unwrap_or(0);
                            let pricing = SessionPricing::new(active_in_rate, active_out_rate);
                            validate_session_pricing(&mut state.established_pricing, pricing)?;
                            let due_now = pricing.amount_due_millisats(session_total_in, session_total_out);
                            info!(
                                "{} session status: open_connects={} total_connects={} paused={} balance={} paid={} due={} linked={:?} intended={} op={:?} blocked={:?} local_remaining={:?}",
                                config.hop_label,
                                open_connects,
                                total_connects,
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
                            let resolved = apply_session_status(
                                &mut state,
                                RelaySnapshot {
                                    receiver_pubkey,
                                    advertisements,
                                    linked_channel,
                                    session_total_in,
                                    session_total_out,
                                    total_paid_millisats,
                                    remaining_milli_sats,
                                    paused,
                                },
                            );
                            publish_pricing(&config, pricing).await;
                            publish_spilman_info(&config, &state).await;
                            validate_linked_channel_balance_against_wallet(
                                config.wallet.as_ref(),
                                &mut state,
                            )?;
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
                match heartbeat.on_tick(Instant::now()) {
                    HeartbeatAction::None => {}
                    HeartbeatAction::SendStatusRequest => {
                        super::funding::send_control_message(&mut h2_send, &ClientMessage::GetSessionStatus).await?;
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
            &ClientMessage::GetSessionStatus,
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

    #[test]
    fn heartbeat_waits_for_initial_server_message() {
        let mut heartbeat = ControlHeartbeat::default();
        assert_eq!(
            heartbeat.on_tick(Instant::now() + HEARTBEAT_INTERVAL),
            HeartbeatAction::None
        );
    }

    #[test]
    fn heartbeat_sends_status_request_after_idle_interval() {
        let now = Instant::now();
        let mut heartbeat = ControlHeartbeat::default();
        heartbeat.observe_server_message(now);

        assert_eq!(
            heartbeat.on_tick(now + HEARTBEAT_INTERVAL - Duration::from_millis(1)),
            HeartbeatAction::None
        );
        assert_eq!(
            heartbeat.on_tick(now + HEARTBEAT_INTERVAL),
            HeartbeatAction::SendStatusRequest
        );
        assert_eq!(
            heartbeat.on_tick(now + HEARTBEAT_INTERVAL + Duration::from_secs(1)),
            HeartbeatAction::None
        );
    }

    #[test]
    fn heartbeat_times_out_when_status_request_is_unanswered() {
        let now = Instant::now();
        let mut heartbeat = ControlHeartbeat::default();
        heartbeat.observe_server_message(now);
        assert_eq!(
            heartbeat.on_tick(now + HEARTBEAT_INTERVAL),
            HeartbeatAction::SendStatusRequest
        );
        assert_eq!(
            heartbeat
                .on_tick(now + HEARTBEAT_INTERVAL + HEARTBEAT_TIMEOUT - Duration::from_millis(1)),
            HeartbeatAction::None
        );
        assert_eq!(
            heartbeat.on_tick(now + HEARTBEAT_INTERVAL + HEARTBEAT_TIMEOUT),
            HeartbeatAction::TimedOut
        );
    }

    #[test]
    fn heartbeat_any_server_message_clears_outstanding_request() {
        let now = Instant::now();
        let mut heartbeat = ControlHeartbeat::default();
        heartbeat.observe_server_message(now);
        assert_eq!(
            heartbeat.on_tick(now + HEARTBEAT_INTERVAL),
            HeartbeatAction::SendStatusRequest
        );

        let response_at = now + HEARTBEAT_INTERVAL + Duration::from_secs(1);
        heartbeat.observe_server_message(response_at);
        assert_eq!(
            heartbeat.on_tick(response_at + HEARTBEAT_INTERVAL - Duration::from_millis(1)),
            HeartbeatAction::None
        );
        assert_eq!(
            heartbeat.on_tick(response_at + HEARTBEAT_INTERVAL),
            HeartbeatAction::SendStatusRequest
        );
    }
}
