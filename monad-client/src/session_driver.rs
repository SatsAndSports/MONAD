use bytes::Bytes;
use monad_common::h2stream::wait_for_send_capacity;
use monad_common::protocol::{
    ClientMessage, KeysetAdvertisement, LinkedChannelStatus, ServerMessage,
};
use monad_common::session::{RelayConnection, SessionPricing, SessionSpilmanInfo};
use std::collections::BTreeSet;
use std::io;
use std::sync::Arc;
use tokio::sync::{oneshot, RwLock};
use tokio::task::JoinHandle;
use tracing::{info, warn};

use crate::wallet::{select_channel, MonadWallet, RelayPaymentOffer, WalletChannel, WalletError};

const CLIENT_VERSION: u8 = 0;
const TARGET_TOPUP_BUFFER_MSATS: u64 = 10_000_000;

fn encode_client_message(message: &ClientMessage) -> io::Result<Bytes> {
    let bytes =
        serde_json::to_vec(message).map_err(|e| io::Error::other(format!("json error: {e}")))?;
    let mut frame = Vec::with_capacity(bytes.len() + 1);
    frame.extend_from_slice(&bytes);
    frame.push(b'\n');
    Ok(Bytes::from(frame))
}

async fn send_control_message(
    h2_send: &mut h2::SendStream<Bytes>,
    message: &ClientMessage,
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
    pricing_handle: Arc<RwLock<Option<SessionPricing>>>,
    spilman_info_handle: Arc<RwLock<Option<SessionSpilmanInfo>>>,
    session_id: [u8; 32],
    hop_label: String,
}

#[derive(Debug, Clone)]
struct SessionSnapshot {
    receiver_pubkey: String,
    advertisements: Vec<KeysetAdvertisement>,
    linked_channel: Option<LinkedChannelStatus>,
    remaining_milli_sats: i64,
    paused: bool,
}

struct SessionDriverState {
    snapshot: Option<SessionSnapshot>,
    active_channel_id: Option<String>,
    active_offer: Option<RelayPaymentOffer>,
    insufficient_channels: BTreeSet<String>,
    ready_tx: Option<oneshot::Sender<()>>,
}

impl SessionDriverState {
    fn new(ready_tx: oneshot::Sender<()>) -> Self {
        Self {
            snapshot: None,
            active_channel_id: None,
            active_offer: None,
            insufficient_channels: BTreeSet::new(),
            ready_tx: Some(ready_tx),
        }
    }
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
        pricing_handle: conn.session_pricing_handle(),
        spilman_info_handle: conn.session_spilman_info_handle(),
        session_id: *conn.session_id(),
        hop_label: hop_label.to_string(),
    };

    let handle = tokio::spawn(async move {
        if let Err(e) = run_session_driver(control_send, control_recv, ready_tx, config).await {
            warn!("session payment driver ended with error: {e}");
        }
    });

    Ok((handle, ready_rx))
}

async fn run_session_driver(
    mut h2_send: h2::SendStream<Bytes>,
    mut h2_recv: h2::RecvStream,
    ready_tx: oneshot::Sender<()>,
    config: SessionDriverConfig,
) -> io::Result<()> {
    let mut buf = Vec::new();
    let mut state = SessionDriverState::new(ready_tx);

    send_control_message(
        &mut h2_send,
        &ClientMessage::Hello {
            version: CLIENT_VERSION,
        },
    )
    .await?;

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
            match message {
                ServerMessage::SessionStatus {
                    version,
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
                    let pricing = SessionPricing::new(version, active_in_rate, active_out_rate);
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
                    *config.pricing_handle.write().await = Some(pricing);

                    state.snapshot = Some(SessionSnapshot {
                        receiver_pubkey,
                        advertisements,
                        linked_channel,
                        remaining_milli_sats,
                        paused,
                    });
                    refresh_spilman_info(&config, &state).await;

                    if let Some(snapshot) = &state.snapshot {
                        if !snapshot.paused {
                            if let Some(tx) = state.ready_tx.take() {
                                let _ = tx.send(());
                            }
                        }
                    }

                    maybe_progress_session(&config, &mut state, &mut h2_send).await?;
                }
                ServerMessage::ChannelEvicted { channel_id } => {
                    warn!(
                        "{} channel {channel_id} evicted from this session",
                        config.hop_label
                    );
                    if state.active_channel_id.as_deref() == Some(channel_id.as_str()) {
                        config
                            .wallet
                            .detach_channel_from_session(&channel_id, config.session_id)
                            .map_err(io_wallet_error)?;
                        state.insufficient_channels.remove(&channel_id);
                        state.active_channel_id = None;
                        state.active_offer = None;
                    }
                    maybe_progress_session(&config, &mut state, &mut h2_send).await?;
                }
                ServerMessage::ChannelLinkAccepted {
                    channel_id,
                    capacity,
                } => {
                    info!(
                        "{} channel {channel_id} linked successfully (capacity={capacity})",
                        config.hop_label
                    );
                    state.active_channel_id = Some(channel_id);
                }
                ServerMessage::Error { message } => {
                    warn!("{} control error: {message}", config.hop_label);
                    handle_control_error(&config, &mut state, &message).await?;
                    maybe_progress_session(&config, &mut state, &mut h2_send).await?;
                }
            }
        }
    }

    if let Some(channel_id) = state.active_channel_id.as_deref() {
        let _ = config
            .wallet
            .detach_channel_from_session(channel_id, config.session_id);
    }

    Ok(())
}

async fn maybe_progress_session(
    config: &SessionDriverConfig,
    state: &mut SessionDriverState,
    h2_send: &mut h2::SendStream<Bytes>,
) -> io::Result<()> {
    loop {
        let Some(snapshot) = state.snapshot.clone() else {
            return Ok(());
        };

        if !snapshot.paused {
            return Ok(());
        }

        if state.active_channel_id.is_none() {
            let Some((channel, offer)) = choose_channel_and_offer(
                config.wallet.as_ref(),
                &snapshot,
                config.session_id,
                &state.insufficient_channels,
            )
            .map_err(io_wallet_error)?
            else {
                warn!(
                    "{} no selectable channel matched relay advertisements; session stays paused",
                    config.hop_label
                );
                return Ok(());
            };

            config
                .wallet
                .attach_channel_to_session(&channel.channel_id, config.session_id)
                .map_err(io_wallet_error)?;
            match config
                .wallet
                .build_link_request(&channel.channel_id, &offer)
            {
                Ok(payment_json) => {
                    state.active_channel_id = Some(channel.channel_id.clone());
                    state.active_offer = Some(offer);
                    return send_control_message(
                        h2_send,
                        &ClientMessage::ChannelLink { payment_json },
                    )
                    .await;
                }
                Err(err) => {
                    config
                        .wallet
                        .detach_channel_from_session(&channel.channel_id, config.session_id)
                        .map_err(io_wallet_error)?;
                    return Err(io_wallet_error(err));
                }
            }
        }

        let Some(active_channel_id) = state.active_channel_id.clone() else {
            continue;
        };
        let Some(active_offer) = state.active_offer.clone() else {
            continue;
        };
        let Some(linked_channel) = sync_active_channel_from_snapshot(config, state, &snapshot)?
        else {
            continue;
        };
        if snapshot.remaining_milli_sats > 0 {
            return Ok(());
        }

        let requested_delta_msats = requested_delta_msats(snapshot.remaining_milli_sats)?;
        if requested_delta_msats == 0 {
            return Ok(());
        }
        let requested_delta_raw =
            delta_msats_to_raw_units(&linked_channel.unit, requested_delta_msats)
                .map_err(io_wallet_error)?;
        let next_balance_raw = linked_channel
            .balance_raw
            .checked_add(requested_delta_raw)
            .ok_or_else(|| io::Error::other("next linked-channel balance overflow"))?;
        if next_balance_raw > linked_channel.capacity_raw {
            state
                .insufficient_channels
                .insert(active_channel_id.clone());
            config
                .wallet
                .detach_channel_from_session(&active_channel_id, config.session_id)
                .map_err(io_wallet_error)?;
            state.active_channel_id = None;
            state.active_offer = None;
            continue;
        }

        let payment_json = match config.wallet.build_channel_payment(
            &active_channel_id,
            &active_offer,
            linked_channel.balance_raw,
            next_balance_raw,
        ) {
            Ok(payment_json) => payment_json,
            Err(WalletError::NoNewFunds) => return Ok(()),
            Err(WalletError::InsufficientCapacity { .. }) => {
                state
                    .insufficient_channels
                    .insert(active_channel_id.clone());
                config
                    .wallet
                    .detach_channel_from_session(&active_channel_id, config.session_id)
                    .map_err(io_wallet_error)?;
                state.active_channel_id = None;
                state.active_offer = None;
                continue;
            }
            Err(err) => return Err(io_wallet_error(err)),
        };

        return send_control_message(h2_send, &ClientMessage::ChannelPayment { payment_json })
            .await;
    }
}

fn choose_channel_and_offer(
    wallet: &dyn MonadWallet,
    snapshot: &SessionSnapshot,
    session_id: [u8; 32],
    excluded_channels: &BTreeSet<String>,
) -> Result<Option<(WalletChannel, RelayPaymentOffer)>, WalletError> {
    let channels = wallet
        .list_channels()?
        .into_iter()
        .filter(|channel| !excluded_channels.contains(&channel.channel_id))
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

async fn refresh_spilman_info(config: &SessionDriverConfig, state: &SessionDriverState) {
    let Some(snapshot) = &state.snapshot else {
        return;
    };
    let offer = if let Some(active_offer) = &state.active_offer {
        Some(active_offer.clone())
    } else {
        snapshot.advertisements.first().map(|advertisement| {
            RelayPaymentOffer::from_advertisement(snapshot.receiver_pubkey.clone(), advertisement)
        })
    };
    if let Some(offer) = offer {
        *config.spilman_info_handle.write().await = Some(SessionSpilmanInfo {
            receiver_pubkey: offer.receiver_pubkey,
            mint_url: offer.mint_url,
            unit: offer.unit,
            keyset_id: offer
                .accepted_keyset_ids
                .first()
                .cloned()
                .unwrap_or_default(),
            keyset_info_json: String::new(),
        });
    }
}

async fn handle_control_error(
    config: &SessionDriverConfig,
    state: &mut SessionDriverState,
    message: &str,
) -> io::Result<()> {
    let Some(active_channel_id) = state.active_channel_id.clone() else {
        return Ok(());
    };

    if is_channel_invalidating_error(message) {
        config
            .wallet
            .mark_channel_unusable(&active_channel_id)
            .map_err(io_wallet_error)?;
    } else {
        config
            .wallet
            .detach_channel_from_session(&active_channel_id, config.session_id)
            .map_err(io_wallet_error)?;
    }

    state.active_channel_id = None;
    state.active_offer = None;
    Ok(())
}

fn sync_active_channel_from_snapshot(
    config: &SessionDriverConfig,
    state: &mut SessionDriverState,
    snapshot: &SessionSnapshot,
) -> io::Result<Option<LinkedChannelStatus>> {
    match (&state.active_channel_id, &snapshot.linked_channel) {
        (Some(active_channel_id), Some(linked_channel))
            if linked_channel.channel_id == *active_channel_id =>
        {
            Ok(Some(linked_channel.clone()))
        }
        (Some(active_channel_id), Some(linked_channel)) => {
            config
                .wallet
                .detach_channel_from_session(active_channel_id, config.session_id)
                .map_err(io_wallet_error)?;
            state.active_channel_id = None;
            state.active_offer = None;

            if let Ok(channel) = config.wallet.get_channel(&linked_channel.channel_id) {
                let offer = snapshot.advertisements.iter().find_map(|advertisement| {
                    let offer = RelayPaymentOffer::from_advertisement(
                        snapshot.receiver_pubkey.clone(),
                        advertisement,
                    );
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
                });
                if let Some(offer) = offer {
                    if config
                        .wallet
                        .attach_channel_to_session(&linked_channel.channel_id, config.session_id)
                        .is_err()
                    {
                        return Ok(None);
                    }
                    state.active_channel_id = Some(linked_channel.channel_id.clone());
                    state.active_offer = Some(offer);
                    return Ok(Some(linked_channel.clone()));
                }
            }
            Ok(None)
        }
        (Some(active_channel_id), None) => {
            config
                .wallet
                .detach_channel_from_session(active_channel_id, config.session_id)
                .map_err(io_wallet_error)?;
            state.active_channel_id = None;
            state.active_offer = None;
            Ok(None)
        }
        (None, Some(linked_channel)) => {
            if let Ok(channel) = config.wallet.get_channel(&linked_channel.channel_id) {
                let offer = snapshot.advertisements.iter().find_map(|advertisement| {
                    let offer = RelayPaymentOffer::from_advertisement(
                        snapshot.receiver_pubkey.clone(),
                        advertisement,
                    );
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
                });
                if let Some(offer) = offer {
                    if config
                        .wallet
                        .attach_channel_to_session(&linked_channel.channel_id, config.session_id)
                        .is_err()
                    {
                        return Ok(None);
                    }
                    state.active_channel_id = Some(linked_channel.channel_id.clone());
                    state.active_offer = Some(offer);
                    return Ok(Some(linked_channel.clone()));
                }
            }
            Ok(None)
        }
        (None, None) => Ok(None),
    }
}

fn requested_delta_msats(remaining_milli_sats: i64) -> Result<u64, io::Error> {
    let target_remaining = TARGET_TOPUP_BUFFER_MSATS as i128;
    let delta = target_remaining - remaining_milli_sats as i128;
    if delta <= 0 {
        return Ok(0);
    }
    u64::try_from(delta).map_err(|_| io::Error::other("requested delta overflow"))
}

fn delta_msats_to_raw_units(unit: &str, delta_msats: u64) -> Result<u64, WalletError> {
    match unit {
        "msat" => Ok(delta_msats),
        "sat" => Ok(delta_msats.div_ceil(1000)),
        other => Err(WalletError::OfferMismatch(format!(
            "unsupported unit: {other}"
        ))),
    }
}

fn is_channel_invalidating_error(message: &str) -> bool {
    [
        "receiver key mismatch",
        "unsupported unit",
        "mint or keyset not acceptable",
        "link balance must be zero",
        "channel expired",
        "channel closed",
        "wrong receiver",
    ]
    .iter()
    .any(|needle| message.contains(needle))
}

fn io_wallet_error(err: WalletError) -> io::Error {
    io::Error::other(err.to_string())
}

#[cfg(test)]
mod tests {
    use super::is_channel_invalidating_error;

    #[test]
    fn invalidating_error_strings_are_classified() {
        assert!(is_channel_invalidating_error("receiver key mismatch"));
        assert!(is_channel_invalidating_error("unsupported unit: usd"));
        assert!(is_channel_invalidating_error("channel closed"));
        assert!(!is_channel_invalidating_error("wrong channel"));
        assert!(!is_channel_invalidating_error("no new funds"));
    }
}
