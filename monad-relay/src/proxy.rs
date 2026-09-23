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

struct TunnelAccounting<'a> {
    state: &'a SessionState,
    label: &'a str,
    outbound: u64,
    inbound: u64,
}

impl Drop for TunnelAccounting<'_> {
    fn drop(&mut self) {
        let (open_connects, total_connects) = self.state.connect_closed();
        info!(
            "tunnel closed: {} | session_id={} open_connects={} total_connects={} outbound={} inbound={} total={}",
            self.label, hex::encode(self.state.session_id()), open_connects, total_connects,
            self.outbound, self.inbound, self.outbound.saturating_add(self.inbound)
        );
    }
}

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
///
/// Byte accounting stays on the fast path here rather than flowing through the
/// main control/session reducer so the active data path can update counters as
/// soon as possible.
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
    let termination = state.termination_token();
    let mut accounting = TunnelAccounting {
        state: &state,
        label,
        outbound: 0,
        inbound: 0,
    };

    let h2_to_target = async {
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
                    accounting.outbound = accounting.outbound.saturating_add(len as u64);

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
        Ok::<(), io::Error>(())
    };

    let target_to_h2 = async {
        let mut buf = vec![0u8; 16384];
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
                    accounting.inbound = accounting.inbound.saturating_add(n as u64);

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
        Ok::<(), io::Error>(())
    };

    // Cancellation covers writes, shutdown, and H2 capacity as well as reads.
    // Normal EOF still waits for the other direction (TCP half-close).
    let (left, right) = tokio::select! {
        biased;
        _ = termination.cancelled() => return Ok(()),
        results = async { tokio::join!(h2_to_target, target_to_h2) } => results,
    };
    if let Err(e) = left {
        debug!("proxy {label} h2->target ended with error: {e}");
    }
    if let Err(e) = right {
        debug!("proxy {label} target->h2 ended with error: {e}");
    }

    Ok(())
}
