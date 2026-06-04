use bytes::Bytes;
use monad_common::h2stream::wait_for_send_capacity;
use monad_common::protocol::{LinkedChannelStatus, ServerMessage};
use monad_common::session::RelayConnection;
use std::collections::VecDeque;
use std::io;
use std::sync::Arc;
use tokio::sync::oneshot;
use tokio::task::JoinHandle;
use tracing::{info, warn};

use crate::session_fsm::{
    ClientSessionEffect, ClientSessionEvent, ClientSessionState, SessionSnapshot, WalletOpKind,
};
use crate::wallet::{select_channel, MonadWallet, RelayPaymentOffer, WalletError};

fn encode_client_message(message: &monad_common::protocol::ClientMessage) -> io::Result<Bytes> {
    let bytes =
        serde_json::to_vec(message).map_err(|e| io::Error::other(format!("json error: {e}")))?;
    let mut frame = Vec::with_capacity(bytes.len() + 1);
    frame.extend_from_slice(&bytes);
    frame.push(b'\n');
    Ok(Bytes::from(frame))
}

async fn send_control_message(
    h2_send: &mut h2::SendStream<Bytes>,
    message: &monad_common::protocol::ClientMessage,
) -> io::Result<()> {
    let frame = encode_client_message(message)?;
    h2_send.reserve_capacity(frame.len());
    wait_for_send_capacity(h2_send).await?;
    h2_send
        .send_data(frame, false)
        .map_err(|e| io::Error::other(format!("h2 send error: {e}")))
}

struct SessionDriverConfig {
    wallet: Arc<dyn MonadWallet>,
    conn: RelayConnectionProxy,
    hop_label: String,
}

pub async fn start_session_payment_driver(
    conn: &RelayConnection,
    wallet: Arc<dyn MonadWallet>,
    hop_label: &str,
) -> io::Result<(JoinHandle<()>, oneshot::Receiver<()>)> {
    let (control_send, control_recv) = conn.open_control().await?;
    let (ready_tx, ready_rx) = oneshot::channel();
    let config = SessionDriverConfig {
        wallet,
        conn: RelayConnectionProxy::from(conn),
        hop_label: hop_label.to_string(),
    };

    let handle = tokio::spawn(async move {
        if let Err(e) = run_session_driver(control_send, control_recv, ready_tx, config).await {
            warn!("session payment driver ended with error: {e}");
        }
    });

    Ok((handle, ready_rx))
}

struct RelayConnectionProxy {
    session_id: [u8; 32],
    pricing_handle:
        std::sync::Arc<tokio::sync::RwLock<Option<monad_common::session::SessionPricing>>>,
    spilman_info_handle:
        std::sync::Arc<tokio::sync::RwLock<Option<monad_common::session::SessionSpilmanInfo>>>,
}

impl From<&RelayConnection> for RelayConnectionProxy {
    fn from(conn: &RelayConnection) -> Self {
        Self {
            session_id: *conn.session_id(),
            pricing_handle: conn.session_pricing_handle(),
            spilman_info_handle: conn.session_spilman_info_handle(),
        }
    }
}

async fn run_session_driver(
    mut h2_send: h2::SendStream<Bytes>,
    mut h2_recv: h2::RecvStream,
    ready_tx: oneshot::Sender<()>,
    config: SessionDriverConfig,
) -> io::Result<()> {
    // Bootstrap stays outside the client reducer. Once the control stream is
    // open, the relay immediately sends the first SessionStatus and only then
    // do we start the reducer.
    let mut buf = Vec::new();
    let mut state = ClientSessionState::new();
    let mut ready_tx = Some(ready_tx);

    while let Some(chunk) = h2_recv.data().await {
        let data = chunk.map_err(|e| io::Error::other(format!("h2 recv error: {e}")))?;
        let len = data.len();
        let _ = h2_recv.flow_control().release_capacity(len);
        buf.extend_from_slice(&data);

        while let Some(newline_pos) = buf.iter().position(|&b| b == b'\n') {
            let line: Vec<u8> = buf.drain(..=newline_pos).collect();
            let line = line.trim_ascii();
            if line.is_empty() {
                continue;
            }

            let message: ServerMessage = serde_json::from_slice(line)
                .map_err(|e| io::Error::other(format!("json error: {e}")))?;
            let event = match message {
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
                } => {
                    let pricing =
                        monad_common::session::SessionPricing::new(active_in_rate, active_out_rate);
                    let due_now = pricing.amount_due_millisats(session_total_in, session_total_out);
                    info!(
                        "{} session status: paused={} balance={} paid={} due={} linked={:?}",
                        config.hop_label,
                        paused,
                        remaining_milli_sats,
                        total_paid_millisats,
                        due_now,
                        linked_channel.as_ref().map(|channel| &channel.channel_id),
                    );
                    ClientSessionEvent::SessionStatusReceived {
                        snapshot: SessionSnapshot {
                            receiver_pubkey,
                            advertisements,
                            linked_channel,
                            remaining_milli_sats,
                            paused,
                        },
                        pricing,
                    }
                }
                ServerMessage::ChannelEvicted { channel_id } => {
                    warn!(
                        "{} channel {channel_id} evicted from this session",
                        config.hop_label
                    );
                    ClientSessionEvent::ChannelEvicted { channel_id }
                }
                ServerMessage::Error { code, message } => {
                    warn!("{} control error: {message}", config.hop_label);
                    ClientSessionEvent::ServerError { code, message }
                }
            };

            let terminate =
                process_client_event(&config, &mut state, event, &mut h2_send, &mut ready_tx)
                    .await?;
            if terminate {
                return Ok(());
            }
        }
    }

    let _ = process_client_event(
        &config,
        &mut state,
        ClientSessionEvent::ControlDetached,
        &mut h2_send,
        &mut ready_tx,
    )
    .await?;

    Ok(())
}

async fn process_client_event(
    config: &SessionDriverConfig,
    state: &mut ClientSessionState,
    initial_event: ClientSessionEvent,
    h2_send: &mut h2::SendStream<Bytes>,
    ready_tx: &mut Option<oneshot::Sender<()>>,
) -> io::Result<bool> {
    // Run a small local event queue so wallet/build effects can feed their
    // result-events back into the same serialized reducer pass.
    let mut pending = VecDeque::from([initial_event]);
    let mut terminate = false;

    while let Some(event) = pending.pop_front() {
        let (next_state, effects) = crate::session_fsm::step(state.clone(), event);
        *state = next_state;

        for effect in effects {
            match effect {
                ClientSessionEffect::UpdatePricingHandle(pricing) => {
                    *config.conn.pricing_handle.write().await = Some(pricing);
                }
                ClientSessionEffect::UpdateSpilmanInfoHandle(info) => {
                    *config.conn.spilman_info_handle.write().await = info;
                }
                ClientSessionEffect::SelectChannel => {
                    match choose_channel_and_offer(
                        config.wallet.as_ref(),
                        state,
                        config.conn.session_id,
                    )
                    .map_err(io_wallet_error)?
                    {
                        Some((channel, offer)) => pending
                            .push_back(ClientSessionEvent::ChannelSelected { channel, offer }),
                        None => pending.push_back(ClientSessionEvent::NoSelectableChannel),
                    }
                }
                ClientSessionEffect::ProvisionChannel {
                    offer,
                    capacity_msats,
                } => match config.wallet.provision_channel(&offer, capacity_msats) {
                    Ok(channel_id) => match config.wallet.get_channel(&channel_id) {
                        Ok(channel) => pending
                            .push_back(ClientSessionEvent::ChannelProvisioned { channel, offer }),
                        Err(error) => {
                            pending.push_back(ClientSessionEvent::WalletOperationFailed {
                                kind: WalletOpKind::ProvisionChannel,
                                error,
                            })
                        }
                    },
                    Err(error) => pending.push_back(ClientSessionEvent::WalletOperationFailed {
                        kind: WalletOpKind::ProvisionChannel,
                        error,
                    }),
                },
                ClientSessionEffect::PrepareLink { channel, offer } => {
                    let channel_id = channel.channel_id.clone();
                    let result = config
                        .wallet
                        .attach_channel_to_session(&channel_id, config.conn.session_id)
                        .and_then(|_| config.wallet.build_link_request(&channel_id, &offer));
                    match result {
                        Ok(payment_json) => {
                            pending.push_back(ClientSessionEvent::LinkRequestBuilt {
                                channel_id,
                                payment_json,
                            })
                        }
                        Err(error) => {
                            let _ = config
                                .wallet
                                .detach_channel_from_session(&channel_id, config.conn.session_id);
                            pending.push_back(ClientSessionEvent::WalletOperationFailed {
                                kind: WalletOpKind::PrepareLink { channel_id },
                                error,
                            });
                        }
                    }
                }
                ClientSessionEffect::InspectLinkedChannel {
                    linked_channel,
                    receiver_pubkey,
                    advertisements,
                } => {
                    if let Some((channel_id, offer)) = inspect_and_adopt_linked_channel(
                        config.wallet.as_ref(),
                        config.conn.session_id,
                        &linked_channel,
                        &receiver_pubkey,
                        &advertisements,
                    ) {
                        pending.push_back(ClientSessionEvent::RelayLinkedChannelAdopted {
                            linked_channel,
                            channel_id,
                            offer,
                        });
                    } else {
                        pending.push_back(ClientSessionEvent::RelayLinkedChannelUnavailable {
                            _linked_channel: linked_channel,
                        });
                    }
                }
                ClientSessionEffect::BuildChannelPayment {
                    channel_id,
                    offer,
                    latest_server_balance_raw,
                    next_balance_raw,
                } => match config.wallet.build_channel_payment(
                    &channel_id,
                    &offer,
                    latest_server_balance_raw,
                    next_balance_raw,
                ) {
                    Ok(payment_json) => {
                        pending.push_back(ClientSessionEvent::ChannelPaymentBuilt { payment_json })
                    }
                    Err(error) => pending.push_back(ClientSessionEvent::WalletOperationFailed {
                        kind: WalletOpKind::PreparePayment { channel_id },
                        error,
                    }),
                },
                ClientSessionEffect::DetachChannel { channel_id } => {
                    let _ = config
                        .wallet
                        .detach_channel_from_session(&channel_id, config.conn.session_id);
                }
                ClientSessionEffect::MarkChannelUnusable { channel_id } => {
                    let _ = config.wallet.mark_channel_unusable(&channel_id);
                }
                ClientSessionEffect::SendControl(message) => {
                    send_control_message(h2_send, &message).await?;
                }
                ClientSessionEffect::SignalUsable => {
                    if let Some(tx) = ready_tx.take() {
                        let _ = tx.send(());
                    }
                }
                ClientSessionEffect::EndSession => {
                    terminate = true;
                }
            }
        }
    }

    Ok(terminate)
}

fn choose_channel_and_offer(
    wallet: &dyn MonadWallet,
    state: &ClientSessionState,
    session_id: [u8; 32],
) -> Result<Option<(crate::wallet::WalletChannel, RelayPaymentOffer)>, WalletError> {
    let Some(snapshot) = state.snapshot.as_ref() else {
        return Ok(None);
    };
    let channels = wallet
        .list_channels()?
        .into_iter()
        .filter(|channel| {
            !state
                .session_excluded_channels
                .contains(&channel.channel_id)
        })
        .collect::<Vec<_>>();
    for advertisement in &snapshot.advertisements {
        let offer =
            RelayPaymentOffer::from_advertisement(snapshot.receiver_pubkey.clone(), advertisement);
        if let Some(channel) = select_channel(&channels, &offer, session_id) {
            return Ok(Some((channel, offer)));
        }
    }
    Ok(None)
}

fn inspect_and_adopt_linked_channel(
    wallet: &dyn MonadWallet,
    session_id: [u8; 32],
    linked_channel: &LinkedChannelStatus,
    receiver_pubkey: &str,
    advertisements: &[monad_common::protocol::KeysetAdvertisement],
) -> Option<(String, RelayPaymentOffer)> {
    let channel = wallet.get_channel(&linked_channel.channel_id).ok()?;
    let offer = advertisements.iter().find_map(|advertisement| {
        let offer =
            RelayPaymentOffer::from_advertisement(receiver_pubkey.to_string(), advertisement);
        if channel.receiver_pubkey == offer.receiver_pubkey
            && channel.mint_url == offer.mint_url
            && channel.unit == offer.unit
            && offer
                .accepted_keyset_ids
                .iter()
                .any(|keyset| keyset == &channel.keyset_id)
        {
            Some(offer)
        } else {
            None
        }
    })?;

    wallet
        .attach_channel_to_session(&linked_channel.channel_id, session_id)
        .ok()?;
    Some((linked_channel.channel_id.clone(), offer))
}

fn io_wallet_error(err: WalletError) -> io::Error {
    io::Error::other(err.to_string())
}

#[cfg(test)]
mod tests {
    use super::inspect_and_adopt_linked_channel;
    use crate::wallet::{MockWallet, RelayPaymentOffer, WalletChannel, WalletChannelState};
    use monad_common::protocol::{KeysetAdvertisement, LinkedChannelStatus};

    fn channel(id: &str) -> WalletChannel {
        WalletChannel {
            channel_id: id.to_string(),
            state: WalletChannelState::Open,
            receiver_pubkey: "receiver".to_string(),
            mint_url: "https://mint".to_string(),
            unit: "msat".to_string(),
            keyset_id: "keyset-a".to_string(),
            attached_session_id: None,
            capacity_msats: 100,
            current_signed_balance_msats: 0,
        }
    }

    #[test]
    fn inspect_and_adopt_linked_channel_returns_matching_offer() {
        let wallet = MockWallet::new();
        wallet.insert_channel(channel("chan-a")).unwrap();

        let adopted = inspect_and_adopt_linked_channel(
            &wallet,
            [1; 32],
            &LinkedChannelStatus {
                channel_id: "chan-a".to_string(),
                balance_raw: 0,
                capacity_raw: 100,
                unit: "msat".to_string(),
            },
            "receiver",
            &[KeysetAdvertisement {
                mint_url: "https://mint".to_string(),
                unit: "msat".to_string(),
                keyset_ids: vec!["keyset-a".to_string()],
                in_bytes_per_millisat: 1,
                out_bytes_per_millisat: 1,
            }],
        )
        .unwrap();

        assert_eq!(adopted.0, "chan-a");
        assert_eq!(
            adopted.1,
            RelayPaymentOffer {
                receiver_pubkey: "receiver".to_string(),
                mint_url: "https://mint".to_string(),
                unit: "msat".to_string(),
                accepted_keyset_ids: vec!["keyset-a".to_string()],
                in_bytes_per_millisat: 1,
                out_bytes_per_millisat: 1,
            }
        );
    }
}
