use bytes::Bytes;
use monad_common::control_codec::try_decode_json_line;
use monad_common::protocol::ServerMessage;
use monad_common::session::SessionPricing;
use std::io;
use tokio::sync::oneshot;
use tokio::time::{self, Duration, MissedTickBehavior};
use tracing::{info, warn};

use super::funding::{apply_channel_evicted, apply_server_error};
use super::funding::{
    handle_control_detached, maybe_ensure_linked_channel, maybe_progress_payment,
};
use super::payment::{
    compute_estimated_remaining, validate_linked_channel_balance_against_wallet,
    validate_session_pricing, validate_session_status_baseline_against_local_counters,
};
use super::state::{
    apply_session_status, publish_pricing, publish_spilman_info, signal_ready, state_summary,
    DriverState, RelaySnapshot, SessionDriverConfig,
};

pub(super) async fn run_session_driver(
    mut h2_send: h2::SendStream<Bytes>,
    mut h2_recv: h2::RecvStream,
    ready_tx: oneshot::Sender<()>,
    config: SessionDriverConfig,
) -> io::Result<()> {
    let mut buf = Vec::new();
    let mut state = DriverState::default();
    let mut ready_tx = Some(ready_tx);

    let mut payment_tick = time::interval(Duration::from_millis(250));
    payment_tick.set_missed_tick_behavior(MissedTickBehavior::Skip);

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

                    maybe_ensure_linked_channel(&config, &mut state, &mut h2_send).await?;
                    maybe_progress_payment(&config, &mut state, &mut h2_send, resolved_payment).await?;
                    maybe_ensure_linked_channel(&config, &mut state, &mut h2_send).await?;
                }
            }
            _ = payment_tick.tick() => {
                if state.terminated {
                    return Ok(());
                }
                maybe_ensure_linked_channel(&config, &mut state, &mut h2_send).await?;
                maybe_progress_payment(&config, &mut state, &mut h2_send, false).await?;
                maybe_ensure_linked_channel(&config, &mut state, &mut h2_send).await?;
            }
        }
    }

    handle_control_detached(&config, &mut state).await;
    Ok(())
}
