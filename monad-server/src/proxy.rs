//! Bidirectional proxy between an H2 stream and an external connection.
//!
//! When the server receives a CONNECT request, it opens a connection to the
//! target (TCP or QUIC stream) and then copies bytes bidirectionally between
//! the H2 stream and the external transport.

use bytes::Bytes;
use h2::RecvStream;
use h2::SendStream;
use monad_common::h2stream::wait_for_send_capacity;
use std::io;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tracing::{debug, info};

/// Proxy bytes bidirectionally between an H2 send/recv stream pair and an
/// external connection.
///
/// The target can be any type that implements `AsyncRead + AsyncWrite` (e.g.,
/// a `TcpStream` or a QUIC bidirectional stream).
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
) -> io::Result<()>
where
    T: AsyncRead + AsyncWrite + Unpin + Send,
{
    let (mut tcp_read, mut tcp_write) = tokio::io::split(target);

    // Byte counters shared between the two directions
    let bytes_to_target = Arc::new(AtomicU64::new(0));
    let bytes_from_target = Arc::new(AtomicU64::new(0));

    let bytes_to_target_ref = bytes_to_target.clone();
    let bytes_from_target_ref = bytes_from_target.clone();

    // H2 recv -> TCP write (data from client going to external target)
    let h2_to_tcp = async {
        loop {
            match h2_recv.data().await {
                Some(Ok(data)) => {
                    // Release H2 flow control capacity
                    let len = data.len();
                    let _ = h2_recv.flow_control().release_capacity(len);

                    bytes_to_target_ref.fetch_add(len as u64, Ordering::Relaxed);

                    if let Err(e) = tcp_write.write_all(&data).await {
                        debug!("tcp write error: {e}");
                        break;
                    }
                }
                Some(Err(e)) => {
                    debug!("h2 recv error: {e}");
                    break;
                }
                None => {
                    // H2 stream closed (client done sending)
                    debug!("h2 recv stream ended");
                    break;
                }
            }
        }
        let _ = tcp_write.shutdown().await;
    };

    // TCP read -> H2 send (data from external target going to client)
    let tcp_to_h2 = async {
        let mut buf = vec![0u8; 16384];
        loop {
            match tcp_read.read(&mut buf).await {
                Ok(0) => {
                    debug!("tcp read EOF");
                    break;
                }
                Ok(n) => {
                    bytes_from_target_ref.fetch_add(n as u64, Ordering::Relaxed);

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
                    debug!("tcp read error: {e}");
                    break;
                }
            }
        }
        // Send empty frame with END_STREAM to signal we're done
        let _ = h2_send.send_data(Bytes::new(), true);
    };

    // Run both directions to completion. We use join (not select) because
    // when the client finishes sending (h2_to_tcp completes), we still need
    // tcp_to_h2 to read the response from the external target and send it back.
    // h2_to_tcp shuts down the TCP write side, causing the target to see EOF,
    // which eventually causes tcp_to_h2 to see EOF and complete naturally.
    tokio::join!(h2_to_tcp, tcp_to_h2);

    let outbound = bytes_to_target.load(Ordering::Relaxed);
    let inbound = bytes_from_target.load(Ordering::Relaxed);
    info!(
        "tunnel closed: {label} | outbound={outbound} inbound={inbound} total={}",
        outbound + inbound
    );

    Ok(())
}
