use bytes::Bytes;
use monad_common::h2stream::wait_for_send_capacity;
use monad_common::protocol::{ClientMessage, ServerMessage};
use monad_common::session::{
    RelayConnection, SessionPricing, SessionSpilmanInfo,
};
use std::io;
use std::sync::Arc;
use tokio::sync::{oneshot, RwLock};
use tokio::task::JoinHandle;
use tracing::{info, warn};

const CLIENT_VERSION: u8 = 0;

fn encode_client_message(message: &ClientMessage) -> io::Result<Bytes> {
    let bytes = serde_json::to_vec(message)
        .map_err(|e| io::Error::new(io::ErrorKind::Other, format!("json error: {e}")))?;
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
        .map_err(|e| io::Error::new(io::ErrorKind::Other, format!("h2 send error: {e}")))
}

async fn run_control_task(
    mut h2_send: h2::SendStream<Bytes>,
    mut h2_recv: h2::RecvStream,
    fake_payment_millisats: u64,
    _session_id: [u8; 32],
    _hop_label: String,
    ready_tx: oneshot::Sender<()>,
    pricing_handle: Arc<RwLock<Option<SessionPricing>>>,
    spilman_info_handle: Arc<RwLock<Option<SessionSpilmanInfo>>>,
) -> io::Result<()> {
    let mut buf = Vec::new();
    let mut ready_tx = Some(ready_tx);

    // Send Hello as the first message on the control stream.
    send_control_message(&mut h2_send, &ClientMessage::Hello { version: CLIENT_VERSION }).await?;

    while let Some(chunk) = h2_recv.data().await {
        let data = chunk
            .map_err(|e| io::Error::new(io::ErrorKind::Other, format!("h2 recv error: {e}")))?;
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
                .map_err(|e| io::Error::new(io::ErrorKind::Other, format!("json error: {e}")))?;
            match message {
                ServerMessage::SessionStatus {
                    version,
                    receiver_pubkey,
                    advertisements,
                    linked_channel_id,
                    active_in_rate,
                    active_out_rate,
                    session_total_in,
                    session_total_out,
                    total_paid_millisats,
                    remaining_milli_sats,
                    paused,
                } => {
                    let pricing = SessionPricing::new(
                        version,
                        active_in_rate,
                        active_out_rate,
                    );
                    info!(
                        "session status: paused={} balance={} paid={} in={} out={} linked={:?}",
                        paused,
                        remaining_milli_sats,
                        total_paid_millisats,
                        session_total_in,
                        session_total_out,
                        linked_channel_id,
                    );
                    *pricing_handle.write().await = Some(pricing);

                    // Update session Spilman info handle if we have enough info.
                    // For now we just pick the first advertisement to store.
                    if let Some(adv) = advertisements.first() {
                        *spilman_info_handle.write().await = Some(SessionSpilmanInfo {
                            receiver_pubkey,
                            mint_url: adv.mint_url.clone(),
                            unit: adv.unit.clone(),
                            keyset_id: adv.keyset_ids.first().cloned().unwrap_or_default(),
                            keyset_info_json: String::new(), // not yet fetched
                        });
                    }

                    if paused && remaining_milli_sats <= 0 {
                        // Always use FakePayment for now.
                        info!(
                            "session paused; sending fake payment of {} millisats",
                            fake_payment_millisats
                        );
                        send_control_message(
                            &mut h2_send,
                            &ClientMessage::FakePayment {
                                milli_sats: fake_payment_millisats,
                            },
                        )
                        .await?;
                    } else if !paused {
                        if let Some(tx) = ready_tx.take() {
                            let _ = tx.send(());
                        }
                    }
                }
                ServerMessage::ChannelEvicted { channel_id } => {
                    warn!("channel {channel_id} evicted from this session");
                }
                ServerMessage::ChannelLinkAccepted { channel_id, capacity } => {
                    info!("channel {channel_id} linked successfully (capacity={capacity})");
                }
                ServerMessage::Error { message } => {
                    warn!("control error: {message}");
                }
            }
        }
    }

    Ok(())
}

/// Start a control task for a session.
pub async fn start_control_task(
    conn: &RelayConnection,
    fake_payment_millisats: u64,
    hop_label: &str,
) -> io::Result<(JoinHandle<()>, oneshot::Receiver<()>)> {
    let (control_send, control_recv) = conn.open_control().await?;
    let (ready_tx, ready_rx) = oneshot::channel();
    let session_id = *conn.session_id();
    let hop_label = hop_label.to_string();
    let pricing_handle = conn.session_pricing_handle();
    let spilman_info_handle = conn.session_spilman_info_handle();

    let handle = tokio::spawn(async move {
        if let Err(e) = run_control_task(
            control_send,
            control_recv,
            fake_payment_millisats,
            session_id,
            hop_label,
            ready_tx,
            pricing_handle,
            spilman_info_handle,
        )
        .await
        {
            warn!("control task ended with error: {e}");
        }
    });

    Ok((handle, ready_rx))
}

/// Start a control task that only uses `FakePayment`.
pub async fn start_fake_payment_controller(
    conn: &RelayConnection,
    fake_payment_millisats: u64,
    hop_label: &str,
) -> io::Result<(JoinHandle<()>, oneshot::Receiver<()>)> {
    start_control_task(conn, fake_payment_millisats, hop_label).await
}
