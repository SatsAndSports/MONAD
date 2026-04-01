use bytes::Bytes;
use monad_common::h2stream::wait_for_send_capacity;
use monad_common::protocol::{ClientMessage, ServerMessage};
use monad_common::session::RelayConnection;
use std::io;
use tokio::sync::oneshot;
use tokio::task::JoinHandle;
use tracing::{info, warn};

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
    ready_tx: oneshot::Sender<()>,
) -> io::Result<()> {
    let mut buf = Vec::new();
    let mut ready_tx = Some(ready_tx);

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
                ServerMessage::Pong => {
                    info!("control: pong");
                }
                ServerMessage::Error { message } => {
                    warn!("control error: {message}");
                }
                ServerMessage::SessionStatus {
                    session_total_in,
                    session_total_out,
                    remaining_milli_sats,
                    paused,
                } => {
                    info!(
                        "session status: paused={} balance={} in={} out={}",
                        paused,
                        remaining_milli_sats,
                        session_total_in,
                        session_total_out
                    );

                    if paused && remaining_milli_sats <= 0 {
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
            }
        }
    }

    Ok(())
}

pub async fn start_fake_payment_controller(
    conn: &RelayConnection,
    fake_payment_millisats: u64,
) -> io::Result<(JoinHandle<()>, oneshot::Receiver<()>)> {
    let (control_send, control_recv) = conn.open_control().await?;
    let (ready_tx, ready_rx) = oneshot::channel();

    let handle = tokio::spawn(async move {
        if let Err(e) = run_control_task(control_send, control_recv, fake_payment_millisats, ready_tx).await {
            warn!("control task ended with error: {e}");
        }
    });

    Ok((handle, ready_rx))
}
