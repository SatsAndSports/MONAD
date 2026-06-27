use bytes::Bytes;
use monad_common::control_codec::{send_json_line, try_decode_json_line};
use monad_common::protocol::{ClientMessage, ServerMessage};
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

const HEARTBEAT_INTERVAL: Duration = Duration::from_secs(5);
const HEARTBEAT_TIMEOUT: Duration = Duration::from_secs(15);
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
        ..DriverState::default()
    };
    let mut ready_tx = Some(ready_tx);

    let mut payment_tick = time::interval(Duration::from_millis(250));
    payment_tick.set_missed_tick_behavior(MissedTickBehavior::Skip);
    let mut heartbeat_tick = time::interval(HEARTBEAT_TICK);
    heartbeat_tick.set_missed_tick_behavior(MissedTickBehavior::Skip);
    let mut heartbeat = ControlHeartbeat::default();

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
                        send_json_line(&mut h2_send, &ClientMessage::GetSessionStatus).await?;
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

    handle_control_detached(&config, &mut state).await;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

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
