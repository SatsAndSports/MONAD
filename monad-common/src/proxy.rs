//! Bidirectional proxy between an H2 stream pair and a transport.
//!
//! This is the shared copy loop used by both the relay (proxying CONNECT
//! tunnels to external targets) and the client (proxying local SOCKS5
//! connections through H2 tunnels).

use crate::h2stream::wait_for_send_capacity;
use bytes::Bytes;
use h2::RecvStream;
use h2::SendStream;
use std::io;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tracing::{debug, info};

/// Passive per-session cleartext byte counters for a MONAD relay session.
///
/// Semantics mirror the relay-side `session_total_in` / `session_total_out`
/// accounting used for billing:
/// - `outbound`: cleartext CONNECT payload bytes sent from the client side of
///   the session toward the target
/// - `inbound`: cleartext CONNECT payload bytes sent from the target back
///   toward the client
///
/// These counters intentionally exclude control-stream traffic and all H2 /
/// Noise framing overhead.
#[derive(Clone, Debug, Default)]
pub struct CleartextByteCounters {
    inbound: Arc<AtomicU64>,
    outbound: Arc<AtomicU64>,
}

impl CleartextByteCounters {
    /// Record cleartext bytes received from the target side of the relay session.
    pub fn note_inbound(&self, bytes: usize) {
        self.inbound.fetch_add(bytes as u64, Ordering::Relaxed);
    }

    /// Record cleartext bytes sent toward the target side of the relay session.
    pub fn note_outbound(&self, bytes: usize) {
        self.outbound.fetch_add(bytes as u64, Ordering::Relaxed);
    }

    pub fn inbound(&self) -> u64 {
        self.inbound.load(Ordering::Relaxed)
    }

    pub fn outbound(&self) -> u64 {
        self.outbound.load(Ordering::Relaxed)
    }

    pub fn snapshot(&self) -> (u64, u64) {
        (self.inbound(), self.outbound())
    }
}

/// Proxy bytes bidirectionally between an H2 send/recv stream pair and a
/// transport.
///
/// The target can be any type that implements `AsyncRead + AsyncWrite` (e.g.,
/// a `TcpStream`, `&mut TcpStream`, or a QUIC bidirectional stream).
///
/// `label` identifies this tunnel for logging (typically the CONNECT authority,
/// e.g., "example.com:443").
///
/// On completion, logs the total proxied bytes in each direction.
pub async fn proxy_bidirectional<T>(
    mut h2_send: SendStream<Bytes>,
    mut h2_recv: RecvStream,
    target: T,
    label: &str,
    accounting: Option<CleartextByteCounters>,
) -> io::Result<()>
where
    T: AsyncRead + AsyncWrite + Unpin + Send,
{
    let (mut target_read, mut target_write) = tokio::io::split(target);

    // Byte counters shared between the two directions
    let bytes_to_target = Arc::new(AtomicU64::new(0));
    let bytes_from_target = Arc::new(AtomicU64::new(0));

    let bytes_to_target_ref = bytes_to_target.clone();
    let bytes_from_target_ref = bytes_from_target.clone();
    let accounting_to_target = accounting.clone();
    let accounting_from_target = accounting;

    // H2 recv -> target write (data from H2 peer going to the target)
    let h2_to_target = async {
        loop {
            match h2_recv.data().await {
                Some(Ok(data)) => {
                    // Release H2 flow control capacity
                    let len = data.len();
                    let _ = h2_recv.flow_control().release_capacity(len);

                    bytes_to_target_ref.fetch_add(len as u64, Ordering::Relaxed);
                    if let Some(accounting) = &accounting_to_target {
                        accounting.note_outbound(len);
                    }

                    if let Err(e) = target_write.write_all(&data).await {
                        debug!("target write error: {e}");
                        break;
                    }
                }
                Some(Err(e)) => {
                    debug!("h2 recv error: {e}");
                    break;
                }
                None => {
                    // H2 stream closed (peer done sending)
                    debug!("h2 recv stream ended");
                    break;
                }
            }
        }
        let _ = target_write.shutdown().await;
    };

    // Target read -> H2 send (data from target going to H2 peer)
    let target_to_h2 = async {
        let mut buf = vec![0u8; 16384];
        loop {
            match target_read.read(&mut buf).await {
                Ok(0) => {
                    debug!("target read EOF");
                    break;
                }
                Ok(n) => {
                    bytes_from_target_ref.fetch_add(n as u64, Ordering::Relaxed);
                    if let Some(accounting) = &accounting_from_target {
                        accounting.note_inbound(n);
                    }

                    let data = Bytes::copy_from_slice(&buf[..n]);

                    // Wait for H2 flow control capacity (sleeps until
                    // the peer sends a WINDOW_UPDATE — no busy-looping)
                    h2_send.reserve_capacity(data.len());
                    if let Err(e) = wait_for_send_capacity(&mut h2_send).await {
                        debug!("{e}");
                        break;
                    }

                    if let Err(e) = h2_send.send_data(data, false) {
                        debug!("h2 send error: {e}");
                        break;
                    }
                }
                Err(e) => {
                    debug!("target read error: {e}");
                    break;
                }
            }
        }
        // Send empty frame with END_STREAM to signal we're done
        let _ = h2_send.send_data(Bytes::new(), true);
    };

    // Run both directions to completion. We use join (not select) because
    // when one side finishes sending, we still need the other to drain.
    // The shutdown of the write half causes the peer to see EOF, which
    // eventually causes the other direction to complete naturally.
    tokio::join!(h2_to_target, target_to_h2);

    let outbound = bytes_to_target.load(Ordering::Relaxed);
    let inbound = bytes_from_target.load(Ordering::Relaxed);
    info!(
        "tunnel closed: {label} | outbound={outbound} inbound={inbound} total={}",
        outbound + inbound
    );

    Ok(())
}
