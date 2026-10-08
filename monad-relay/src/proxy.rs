//! Server-side proxy helpers.

use crate::session::SessionState;
use crate::session_fsm::ByteDirection;
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
        let Some((open_connects, total_connects)) = self.state.connect_closed() else {
            self.state.terminate();
            return;
        };
        info!(
            "tunnel closed: {} | session_id={} open_connects={} total_connects={} outbound={} inbound={} total={}",
            self.label,
            hex::encode(self.state.session_id()),
            open_connects,
            total_connects,
            self.outbound,
            self.inbound,
            self.outbound as u128 + self.inbound as u128
        );
    }
}

struct ByteReservation {
    state: SessionState,
    direction: ByteDirection,
    granted_bytes: usize,
}

impl ByteReservation {
    async fn commit(mut self, actual_bytes: usize) -> io::Result<bool> {
        let result = self
            .state
            .commit_reserved_bytes(self.direction, self.granted_bytes, actual_bytes)
            .await;
        self.granted_bytes = 0;
        result.map_err(|error| {
            io::Error::new(
                io::ErrorKind::QuotaExceeded,
                format!("session accounting limit exceeded: {error:?}"),
            )
        })
    }
}

impl Drop for ByteReservation {
    fn drop(&mut self) {
        if self.granted_bytes != 0 {
            self.state
                .release_reserved_bytes(self.direction, self.granted_bytes);
        }
    }
}

async fn wait_until_unpaused_or_terminated(
    paused_rx: &mut watch::Receiver<bool>,
    termination: &CancellationToken,
    proxy_cancel: &CancellationToken,
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
            _ = proxy_cancel.cancelled() => {
                return Err(io::Error::new(
                    io::ErrorKind::ConnectionAborted,
                    "proxy direction ended",
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

async fn reserve_forwarding_bytes(
    state: &SessionState,
    direction: ByteDirection,
    requested_bytes: usize,
    paused_rx: &mut watch::Receiver<bool>,
    billing_version_rx: &mut watch::Receiver<u64>,
    termination: &CancellationToken,
    proxy_cancel: &CancellationToken,
) -> io::Result<ByteReservation> {
    loop {
        wait_until_unpaused_or_terminated(paused_rx, termination, proxy_cancel).await?;
        let granted_bytes = state.reserve_bytes(direction, requested_bytes).await;
        if granted_bytes != 0 {
            return Ok(ByteReservation {
                state: state.clone(),
                direction,
                granted_bytes,
            });
        }

        tokio::select! {
            _ = termination.cancelled() => {
                return Err(io::Error::new(
                    io::ErrorKind::ConnectionAborted,
                    "session terminated",
                ));
            }
            _ = proxy_cancel.cancelled() => {
                return Err(io::Error::new(
                    io::ErrorKind::ConnectionAborted,
                    "proxy direction ended",
                ));
            }
            changed = billing_version_rx.changed() => {
                changed.map_err(|_| {
                    io::Error::new(
                        io::ErrorKind::BrokenPipe,
                        "session billing channel closed unexpectedly",
                    )
                })?;
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
/// main control/session reducer. Each bounded forwarding operation reserves
/// exact billing headroom first, so simultaneous tunnels cannot spend the same
/// remaining credit. Reservations release on every error and cancellation path.
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
    let mut billing_version_rx_a = state.billing_version_receiver();
    let mut billing_version_rx_b = state.billing_version_receiver();
    let termination_a = state.termination_token();
    let termination_b = state.termination_token();
    let proxy_cancel_a = CancellationToken::new();
    let proxy_cancel_b = proxy_cancel_a.clone();
    let mut accounting = TunnelAccounting {
        state: &state,
        label,
        outbound: 0,
        inbound: 0,
    };

    let h2_to_target = async {
        let result: io::Result<()> = async {
            let mut pending: Option<Bytes> = None;
            loop {
                if pending.is_none() {
                    wait_until_unpaused_or_terminated(
                        &mut paused_rx_a,
                        &termination_a,
                        &proxy_cancel_a,
                    )
                    .await?;

                    match tokio::select! {
                        _ = termination_a.cancelled() => None,
                        _ = proxy_cancel_a.cancelled() => None,
                        item = h2_recv.data() => item,
                    } {
                        Some(Ok(data)) if data.is_empty() => {
                            let _ = h2_recv.flow_control().release_capacity(0);
                            continue;
                        }
                        Some(Ok(data)) => pending = Some(data),
                        Some(Err(e)) => {
                            return Err(io::Error::other(format!("h2 recv error: {e}")));
                        }
                        None => {
                            debug!("h2 recv stream ended");
                            break;
                        }
                    }
                }

                let pending_len = pending.as_ref().expect("pending data").len();
                let reservation = reserve_forwarding_bytes(
                    &state,
                    ByteDirection::Outbound,
                    pending_len,
                    &mut paused_rx_a,
                    &mut billing_version_rx_a,
                    &termination_a,
                    &proxy_cancel_a,
                )
                .await?;
                let granted_bytes = reservation.granted_bytes;
                let mut written = 0;
                let mut write_result = Ok(());

                while written < granted_bytes {
                    let buf = pending.as_ref().expect("pending data");
                    let write = target_write.write(&buf[written..granted_bytes]);
                    tokio::select! {
                        biased;
                        _ = termination_a.cancelled() => {
                            write_result = Err(io::Error::new(
                                io::ErrorKind::ConnectionAborted,
                                "session terminated",
                            ));
                            break;
                        }
                        _ = proxy_cancel_a.cancelled() => {
                            write_result = Err(io::Error::new(
                                io::ErrorKind::ConnectionAborted,
                                "proxy direction ended",
                            ));
                            break;
                        }
                        result = write => {
                            match result {
                                Ok(0) => {
                                    write_result = Err(io::Error::new(
                                        io::ErrorKind::WriteZero,
                                        "target write returned zero",
                                    ));
                                    break;
                                }
                                Ok(n) => written += n,
                                Err(e) => {
                                    write_result = Err(e);
                                    break;
                                }
                            }
                        }
                    }
                }

                let commit_result = reservation.commit(written).await;
                if written != 0 {
                    let _ = h2_recv.flow_control().release_capacity(written);
                }
                let mut remainder = pending.take().expect("pending data");
                if written != 0 {
                    let _ = remainder.split_to(written);
                }
                if !remainder.is_empty() {
                    pending = Some(remainder);
                }
                accounting.outbound =
                    accounting
                        .outbound
                        .checked_add(written as u64)
                        .ok_or_else(|| {
                            io::Error::new(
                                io::ErrorKind::QuotaExceeded,
                                "tunnel outbound counter overflow",
                            )
                        })?;
                let paused = commit_result?;
                if paused {
                    state.push_status().await;
                }
                write_result?;
            }

            tokio::select! {
                _ = termination_a.cancelled() => Err(io::Error::new(
                    io::ErrorKind::ConnectionAborted,
                    "session terminated",
                )),
                _ = proxy_cancel_a.cancelled() => Err(io::Error::new(
                    io::ErrorKind::ConnectionAborted,
                    "proxy direction ended",
                )),
                result = target_write.shutdown() => result,
            }
        }
        .await;
        if result.is_err() {
            proxy_cancel_a.cancel();
        }
        result
    };

    let target_to_h2 = async {
        let result: io::Result<()> = async {
            let mut buf = vec![0u8; 16384];
            let mut pending = Bytes::new();
            loop {
                if pending.is_empty() {
                    wait_until_unpaused_or_terminated(
                        &mut paused_rx_b,
                        &termination_b,
                        &proxy_cancel_b,
                    )
                    .await?;

                    match tokio::select! {
                        _ = termination_b.cancelled() => Ok(0),
                        _ = proxy_cancel_b.cancelled() => Ok(0),
                        read = target_read.read(&mut buf) => read,
                    } {
                        Ok(0) => {
                            debug!("target read EOF");
                            break;
                        }
                        Ok(n) => pending = Bytes::copy_from_slice(&buf[..n]),
                        Err(e) => return Err(e),
                    }
                }

                let reservation = reserve_forwarding_bytes(
                    &state,
                    ByteDirection::Inbound,
                    pending.len(),
                    &mut paused_rx_b,
                    &mut billing_version_rx_b,
                    &termination_b,
                    &proxy_cancel_b,
                )
                .await?;
                let granted_bytes = reservation.granted_bytes;
                let data = pending.split_to(granted_bytes);

                h2_send.reserve_capacity(data.len());
                tokio::select! {
                    _ = termination_b.cancelled() => {
                        return Err(io::Error::new(
                            io::ErrorKind::ConnectionAborted,
                            "session terminated",
                        ));
                    }
                    _ = proxy_cancel_b.cancelled() => {
                        return Err(io::Error::new(
                            io::ErrorKind::ConnectionAborted,
                            "proxy direction ended",
                        ));
                    }
                    result = wait_for_send_capacity(&mut h2_send) => {
                        result?;
                    }
                }
                h2_send
                    .send_data(data, false)
                    .map_err(|e| io::Error::other(format!("h2 send error: {e}")))?;
                let paused = reservation.commit(granted_bytes).await?;
                accounting.inbound = accounting
                    .inbound
                    .checked_add(granted_bytes as u64)
                    .ok_or_else(|| {
                        io::Error::new(
                            io::ErrorKind::QuotaExceeded,
                            "tunnel inbound counter overflow",
                        )
                    })?;
                if paused {
                    state.push_status().await;
                }
            }

            h2_send
                .send_data(Bytes::new(), true)
                .map_err(|e| io::Error::other(format!("h2 send error: {e}")))?;
            Ok(())
        }
        .await;
        if result.is_err() {
            proxy_cancel_b.cancel();
        }
        result
    };

    // Join rather than try_join so an error in one direction cancels the other
    // direction's operation but still lets that direction release reservations
    // and commit any already-delivered write prefix before returning.
    let (outbound_result, inbound_result) = tokio::join!(h2_to_target, target_to_h2);
    let is_session_termination = |error: &io::Error| {
        error.kind() == io::ErrorKind::ConnectionAborted
            && error.to_string() == "session terminated"
    };
    let result = match (outbound_result, inbound_result) {
        (Err(error), other) | (other, Err(error)) if is_session_termination(&error) => {
            drop(other);
            Ok(())
        }
        (outbound_result, inbound_result) => outbound_result.and(inbound_result),
    };
    if let Err(e) = &result {
        debug!("proxy {label} ended with error: {e}");
    }

    result
}
