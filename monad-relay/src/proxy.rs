//! Server-side proxy helpers.

use crate::session::SessionState;
use crate::session_fsm::ByteDirection;
use bytes::Bytes;
use h2::{RecvStream, SendStream};
use monad_common::h2stream::wait_for_send_capacity;
use std::{future::poll_fn, io, pin::Pin, task::Poll};
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
        let Some((open_connects, total_connects)) = self.state.connect_closed() else {
            self.state.terminate();
            return;
        };
        info!(
            "tunnel closed: {} | session_id={} open_connects={} total_connects={} outbound={} inbound={} total={}",
            self.label, hex::encode(self.state.session_id()), open_connects, total_connects,
            self.outbound, self.inbound, self.outbound as u128 + self.inbound as u128
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
                return Err(io::Error::new(io::ErrorKind::ConnectionAborted, "session terminated"));
            }
            changed = paused_rx.changed() => {
                changed.map_err(|_| io::Error::new(
                    io::ErrorKind::BrokenPipe, "session pause channel closed unexpectedly",
                ))?;
            }
        }
    }
}

/// Proxy with exact accounting and chunk-boundary payment pauses.
///
/// An operation started with positive credit may finish and take credit negative.
/// The successful write count commits in the same synchronous poll, before task
/// cancellation/drop can intervene. No billing lock is held while polling the
/// transport and no prepaid bytes are reserved.
/// This is in-memory accounting, not a process-crash-durable traffic journal.
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
            let data = match h2_recv.data().await {
                Some(Ok(data)) => data,
                Some(Err(error)) => {
                    return Err(io::Error::other(format!("h2 recv error: {error}")))
                }
                None => break,
            };
            // Restore the original stream-capacity timing: consumption by this
            // proxy releases the frame before the target write. At most one
            // bounded DATA frame is held here, including on a slow target.
            let _ = h2_recv.flow_control().release_capacity(data.len());
            let mut written = 0;
            while written < data.len() {
                let (n, _) = poll_fn(|cx| {
                    state.poll_accounted_forward(
                        ByteDirection::Outbound,
                        data.len() - written,
                        || Pin::new(&mut target_write).poll_write(cx, &data[written..]),
                    )
                })
                .await?;
                if n == 0 {
                    return Err(io::Error::new(
                        io::ErrorKind::WriteZero,
                        "target write returned zero",
                    ));
                }
                written += n;
                // A tunnel total is bounded by the corresponding checked
                // session total. These additions cannot overflow.
                accounting.outbound += n as u64;
            }
        }
        target_write.shutdown().await?;
        Ok::<(), io::Error>(())
    };

    let target_to_h2 = async {
        let mut buf = vec![0u8; 16384];
        loop {
            wait_until_unpaused_or_terminated(&mut paused_rx_b, &termination_b).await?;
            let n = target_read.read(&mut buf).await?;
            if n == 0 {
                break;
            }
            let data = Bytes::copy_from_slice(&buf[..n]);
            h2_send.reserve_capacity(n);
            wait_for_send_capacity(&mut h2_send).await?;
            // send_data is synchronous and all-or-nothing. The enqueue and byte
            // accounting have no intervening suspension.
            let result = state.poll_accounted_forward(ByteDirection::Inbound, n, || {
                Poll::Ready(
                    h2_send
                        .send_data(data, false)
                        .map(|()| n)
                        .map_err(|error| io::Error::other(format!("h2 send error: {error}"))),
                )
            });
            let Poll::Ready(result) = result else {
                unreachable!("H2 send_data is synchronous")
            };
            let _ = result?;
            accounting.inbound += n as u64;
        }
        h2_send
            .send_data(Bytes::new(), true)
            .map_err(|error| io::Error::other(format!("h2 send error: {error}")))?;
        Ok::<(), io::Error>(())
    };

    // Completed writes are already counted even when this drops a direction
    // mid-operation. Normal EOF still preserves the other half of the tunnel.
    let result = tokio::select! {
        biased;
        _ = termination.cancelled() => return Ok(()),
        result = async { tokio::try_join!(h2_to_target, target_to_h2) } => result,
    };
    if let Err(error) = &result {
        debug!("proxy {label} ended with error: {error}");
    }
    result.map(|_| ())
}
