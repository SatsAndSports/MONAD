//! Server-side proxy helpers.

use crate::session::SessionState;
use bytes::Bytes;
use h2::{RecvStream, SendStream};
use monad_common::h2stream::wait_for_send_capacity;
use std::io;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::sync::watch;
use tokio_util::sync::CancellationToken;
use tracing::{debug, info};

pub use monad_common::proxy::proxy_bidirectional;

async fn wait_until_unpaused_or_terminated(
    paused_rx: &mut watch::Receiver<bool>,
    termination: &CancellationToken,
) -> io::Result<()> {
    loop {
        if !*paused_rx.borrow() {
            return Ok(());
        }

        tokio::select! {
            _ = termination.cancelled() => {
                return Err(io::Error::new(
                    io::ErrorKind::ConnectionAborted,
                    "session terminated",
                ));
            }
            changed = paused_rx.changed() => {
                changed.map_err(|_| {
                    io::Error::new(
                        io::ErrorKind::BrokenPipe,
                        "session pause channel closed unexpectedly",
                    )
                })?;
            }
        }
    }
}

/// Proxy bytes bidirectionally while enforcing per-session payment pauses.
pub(crate) async fn proxy_bidirectional_accounted<T>(
    mut h2_send: SendStream<Bytes>,
    mut h2_recv: RecvStream,
    target: T,
    label: &str,
    state: SessionState,
) -> io::Result<()>
where
    T: AsyncRead + AsyncWrite + Unpin + Send,
{
    let (mut target_read, mut target_write) = tokio::io::split(target);
    let mut paused_rx_a = state.pause_receiver();
    let mut paused_rx_b = state.pause_receiver();
    let termination_a = state.termination_token();
    let termination_b = state.termination_token();

    let h2_to_target = async {
        let mut tunnel_outbound = 0u64;
        loop {
            wait_until_unpaused_or_terminated(&mut paused_rx_a, &termination_a).await?;

            match tokio::select! {
                _ = termination_a.cancelled() => None,
                item = h2_recv.data() => item,
            } {
                Some(Ok(data)) => {
                    let len = data.len();
                    let _ = h2_recv.flow_control().release_capacity(len);

                    target_write.write_all(&data).await?;
                    tunnel_outbound = tunnel_outbound.saturating_add(len as u64);

                    let paused = state.note_outbound_bytes(len).await;
                    if paused {
                        state.push_status().await;
                    }
                }
                Some(Err(e)) => {
                    return Err(io::Error::other(format!("h2 recv error: {e}")));
                }
                None => {
                    debug!("h2 recv stream ended");
                    break;
                }
            }
        }

        let _ = target_write.shutdown().await;
        Ok::<u64, io::Error>(tunnel_outbound)
    };

    let target_to_h2 = async {
        let mut buf = vec![0u8; 16384];
        let mut tunnel_inbound = 0u64;
        loop {
            wait_until_unpaused_or_terminated(&mut paused_rx_b, &termination_b).await?;

            match tokio::select! {
                _ = termination_b.cancelled() => Ok(0),
                read = target_read.read(&mut buf) => read,
            } {
                Ok(0) => {
                    debug!("target read EOF");
                    break;
                }
                Ok(n) => {
                    let data = Bytes::copy_from_slice(&buf[..n]);

                    h2_send.reserve_capacity(data.len());
                    wait_for_send_capacity(&mut h2_send).await?;
                    h2_send
                        .send_data(data, false)
                        .map_err(|e| io::Error::other(format!("h2 send error: {e}")))?;
                    tunnel_inbound = tunnel_inbound.saturating_add(n as u64);

                    let paused = state.note_inbound_bytes(n).await;
                    if paused {
                        state.push_status().await;
                    }
                }
                Err(e) => {
                    return Err(e);
                }
            }
        }

        let _ = h2_send.send_data(Bytes::new(), true);
        Ok::<u64, io::Error>(tunnel_inbound)
    };

    let (left, right) = tokio::join!(h2_to_target, target_to_h2);
    let tunnel_outbound = left.as_ref().ok().copied().unwrap_or(0);
    let tunnel_inbound = right.as_ref().ok().copied().unwrap_or(0);
    if let Err(e) = left {
        debug!("proxy {label} h2->target ended with error: {e}");
    }
    if let Err(e) = right {
        debug!("proxy {label} target->h2 ended with error: {e}");
    }

    info!(
        "tunnel closed: {label} | outbound={} inbound={} total={}",
        tunnel_outbound,
        tunnel_inbound,
        tunnel_outbound + tunnel_inbound
    );

    Ok(())
}
