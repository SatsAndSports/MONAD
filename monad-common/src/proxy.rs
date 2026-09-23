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

/// Per-session cleartext byte counters for a MONAD relay session.
///
/// Semantics mirror the relay-side `session_total_in` / `session_total_out`
/// accounting used for billing:
/// - `outbound`: cleartext CONNECT payload bytes sent from the client side of
///   the session toward the target
/// - `inbound`: cleartext CONNECT payload bytes sent from the target back
///   toward the client
///
/// These counters intentionally exclude control-stream traffic and all H2 /
/// Noise framing overhead. On the client side they are also read by the
/// session driver to estimate local spend between authoritative relay status
/// updates and to size proactive payments.
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
    proxy_bidirectional_inner(&mut h2_send, &mut h2_recv, target, label, accounting, false).await
}

/// Client-side variant where `target` is the local application socket rather
/// than the remote CONNECT destination.
pub async fn proxy_bidirectional_from_client<T>(
    mut h2_send: SendStream<Bytes>,
    mut h2_recv: RecvStream,
    target: T,
    label: &str,
    accounting: Option<CleartextByteCounters>,
) -> io::Result<()>
where
    T: AsyncRead + AsyncWrite + Unpin + Send,
{
    proxy_bidirectional_inner(&mut h2_send, &mut h2_recv, target, label, accounting, true).await
}

async fn proxy_bidirectional_inner<T>(
    h2_send: &mut SendStream<Bytes>,
    h2_recv: &mut RecvStream,
    target: T,
    label: &str,
    accounting: Option<CleartextByteCounters>,
    target_is_client: bool,
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
    let (recv_done_tx, recv_done_rx) = tokio::sync::oneshot::channel();

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
                        if target_is_client {
                            accounting.note_inbound(len);
                        } else {
                            accounting.note_outbound(len);
                        }
                    }

                    if let Err(e) = target_write.write_all(&data).await {
                        debug!("target write error: {e}");
                        return Err(e);
                    }
                }
                Some(Err(e)) => {
                    debug!("h2 recv error: {e}");
                    return Err(io::Error::other(format!("h2 recv error: {e}")));
                }
                None => {
                    // H2 stream closed (peer done sending)
                    debug!("h2 recv stream ended");
                    break;
                }
            }
        }
        target_write.shutdown().await?;
        let _ = recv_done_tx.send(());
        Ok::<(), io::Error>(())
    };

    // Target read -> H2 send (data from target going to H2 peer)
    let target_to_h2 = async {
        let mut buf = vec![0u8; 16384];
        loop {
            // RecvStream is not polled while target_write is blocked. Observe
            // reset/connection failure independently through the send handle.
            // H2 capacity waits below already observe those failures themselves.
            match tokio::select! {
                biased;
                error = wait_for_h2_reset(h2_send) => return Err(error),
                read = target_read.read(&mut buf) => read,
            } {
                Ok(0) => {
                    debug!("target read EOF");
                    break;
                }
                Ok(n) => {
                    bytes_from_target_ref.fetch_add(n as u64, Ordering::Relaxed);
                    if let Some(accounting) = &accounting_from_target {
                        if target_is_client {
                            accounting.note_outbound(n);
                        } else {
                            accounting.note_inbound(n);
                        }
                    }

                    let data = Bytes::copy_from_slice(&buf[..n]);

                    // Wait for H2 flow control capacity (sleeps until
                    // the peer sends a WINDOW_UPDATE — no busy-looping)
                    h2_send.reserve_capacity(data.len());
                    if let Err(e) = wait_for_send_capacity(h2_send).await {
                        debug!("{e}");
                        return Err(e);
                    }

                    if let Err(e) = h2_send.send_data(data, false) {
                        debug!("h2 send error: {e}");
                        return Err(io::Error::other(format!("h2 send error: {e}")));
                    }
                }
                Err(e) => {
                    debug!("target read error: {e}");
                    return Err(e);
                }
            }
        }
        // Send empty frame with END_STREAM to signal we're done
        h2_send
            .send_data(Bytes::new(), true)
            .map_err(|e| io::Error::other(format!("h2 send error: {e}")))?;
        // Local EOF must not disable reset observation while the other half is
        // still draining to the application. Ordinary EOF never cancels that drain.
        tokio::select! {
            biased;
            error = wait_for_h2_reset(h2_send) => Err(error),
            _ = recv_done_rx => Ok::<(), io::Error>(()),
        }
    };

    // EOF preserves half-close; a hard error cancels the other direction rather
    // than retaining a stalled application socket forever after H2 reset.
    let result = tokio::try_join!(h2_to_target, target_to_h2);

    let (outbound, inbound) = if target_is_client {
        (
            bytes_from_target.load(Ordering::Relaxed),
            bytes_to_target.load(Ordering::Relaxed),
        )
    } else {
        (
            bytes_to_target.load(Ordering::Relaxed),
            bytes_from_target.load(Ordering::Relaxed),
        )
    };
    info!(
        "tunnel closed: {label} | outbound={outbound} inbound={inbound} total={}",
        outbound + inbound
    );

    result.map(|_| ())
}

async fn wait_for_h2_reset(send: &mut SendStream<Bytes>) -> io::Error {
    match std::future::poll_fn(|cx| send.poll_reset(cx)).await {
        Ok(reason) => io::Error::new(
            io::ErrorKind::ConnectionReset,
            format!("h2 stream reset: {reason}"),
        ),
        Err(error) => io::Error::other(format!("h2 connection error: {error}")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct WriteGate {
        io: tokio::io::DuplexStream,
        blocked: Option<tokio::sync::oneshot::Sender<()>>,
        dropped: Arc<std::sync::atomic::AtomicBool>,
    }

    impl Drop for WriteGate {
        fn drop(&mut self) {
            self.dropped.store(true, Ordering::SeqCst);
        }
    }

    impl AsyncRead for WriteGate {
        fn poll_read(
            mut self: std::pin::Pin<&mut Self>,
            cx: &mut std::task::Context<'_>,
            buf: &mut tokio::io::ReadBuf<'_>,
        ) -> std::task::Poll<io::Result<()>> {
            std::pin::Pin::new(&mut self.io).poll_read(cx, buf)
        }
    }

    impl AsyncWrite for WriteGate {
        fn poll_write(
            mut self: std::pin::Pin<&mut Self>,
            cx: &mut std::task::Context<'_>,
            buf: &[u8],
        ) -> std::task::Poll<io::Result<usize>> {
            let result = std::pin::Pin::new(&mut self.io).poll_write(cx, buf);
            if result.is_pending() {
                if let Some(blocked) = self.blocked.take() {
                    let _ = blocked.send(());
                }
            }
            result
        }

        fn poll_flush(
            mut self: std::pin::Pin<&mut Self>,
            cx: &mut std::task::Context<'_>,
        ) -> std::task::Poll<io::Result<()>> {
            std::pin::Pin::new(&mut self.io).poll_flush(cx)
        }

        fn poll_shutdown(
            mut self: std::pin::Pin<&mut Self>,
            cx: &mut std::task::Context<'_>,
        ) -> std::task::Poll<io::Result<()>> {
            std::pin::Pin::new(&mut self.io).poll_shutdown(cx)
        }
    }

    #[tokio::test]
    async fn blocked_target_write_observes_reset_and_connection_loss() {
        use std::time::Duration;
        use tokio::time::timeout;

        for (finish, local_eof) in [
            ("reset", false),
            ("peer loss", false),
            ("route close", false),
            ("reset", true),
            ("peer loss", true),
            ("route close", true),
            ("normal EOF", true),
        ] {
            let (client, server) = tokio::io::duplex(4096);
            let (mut client, driver) = h2::client::handshake(client).await.unwrap();
            let mut tasks = tokio::task::JoinSet::new();
            let client_driver = tasks.spawn(async move {
                let _ = driver.await;
            });
            let (response, send) = client
                .send_request(
                    http::Request::builder()
                        .method("CONNECT")
                        .uri("target:80")
                        .body(())
                        .unwrap(),
                    false,
                )
                .unwrap();
            let mut server = h2::server::handshake(server).await.unwrap();
            let (request, mut respond) = server.accept().await.unwrap().unwrap();
            let mut server_recv = request.into_body();
            let mut server_send = respond
                .send_response(http::Response::new(()), false)
                .unwrap();
            let server_driver =
                tasks.spawn(async move { while server.accept().await.is_some() {} });
            let recv = response.await.unwrap().into_body();
            let (io, mut app) = tokio::io::duplex(8);
            let (blocked, blocked_rx) = tokio::sync::oneshot::channel();
            let dropped = Arc::new(std::sync::atomic::AtomicBool::new(false));
            let target = WriteGate {
                io,
                blocked: Some(blocked),
                dropped: dropped.clone(),
            };
            if local_eof {
                app.shutdown().await.unwrap();
            }
            let payload = Bytes::from(vec![42; 64]);
            server_send.send_data(payload.clone(), false).unwrap();
            let mut proxy = Box::pin(proxy_bidirectional_from_client(
                send, recv, target, "blocked", None,
            ));
            timeout(Duration::from_secs(2), async {
                tokio::select! {
                    result = &mut proxy => panic!("proxy ended before blocked write: {result:?}"),
                    result = blocked_rx => result.unwrap(),
                }
            })
            .await
            .unwrap();
            if local_eof {
                // Keep driving the proxy until its outbound half has sent EOF.
                timeout(Duration::from_secs(2), async {
                    tokio::select! {
                        result = &mut proxy => panic!("proxy ended before reset: {result:?}"),
                        data = server_recv.data() => assert!(data.is_none() || data.unwrap().unwrap().is_empty()),
                    }
                }).await.unwrap();
            }
            match finish {
                "reset" => server_send.send_reset(h2::Reason::CANCEL),
                "peer loss" => server_driver.abort(),
                "route close" => client_driver.abort(),
                "normal EOF" => server_send.send_data(Bytes::new(), true).unwrap(),
                _ => unreachable!(),
            }
            if finish == "normal EOF" {
                let drain = async {
                    let mut received = Vec::new();
                    app.read_to_end(&mut received).await.unwrap();
                    assert_eq!(received, payload);
                };
                let (result, ()) =
                    timeout(Duration::from_secs(2), async { tokio::join!(proxy, drain) })
                        .await
                        .unwrap();
                result.unwrap();
            } else {
                let result = timeout(Duration::from_secs(2), proxy)
                    .await
                    .unwrap_or_else(|_| {
                        panic!("{finish}, local_eof={local_eof}: reset was hidden by blocked write")
                    });
                assert!(result.is_err());
            }
            assert!(dropped.load(Ordering::SeqCst));
            tasks.shutdown().await;
        }
    }

    #[tokio::test]
    async fn fatal_reset_cancels_other_direction_but_eof_preserves_reply() {
        use std::future::Future;
        use std::task::Poll;
        for reset in [true, false] {
            let (client, server) = tokio::io::duplex(4096);
            let (mut client, driver) = h2::client::handshake(client).await.unwrap();
            let mut tasks = tokio::task::JoinSet::new();
            tasks.spawn(async move {
                let _ = driver.await;
            });
            let (response, send) = client
                .send_request(
                    http::Request::builder()
                        .method("CONNECT")
                        .uri("target:80")
                        .body(())
                        .unwrap(),
                    false,
                )
                .unwrap();
            let mut server = h2::server::handshake(server).await.unwrap();
            let (request, mut respond) = server.accept().await.unwrap().unwrap();
            let mut server_recv = request.into_body();
            let mut server_send = respond
                .send_response(http::Response::new(()), false)
                .unwrap();
            tasks.spawn(async move { while server.accept().await.is_some() {} });
            let recv = response.await.unwrap().into_body();
            let (target, mut app) = tokio::io::duplex(64);
            let mut proxy = Box::pin(proxy_bidirectional_from_client(
                send, recv, target, "test", None,
            ));
            if reset {
                std::future::poll_fn(|cx| {
                    assert!(proxy.as_mut().poll(cx).is_pending());
                    Poll::Ready(())
                })
                .await;
                server_send.send_reset(h2::Reason::CANCEL);
                assert!(
                    tokio::time::timeout(std::time::Duration::from_secs(2), proxy)
                        .await
                        .unwrap()
                        .is_err()
                );
            } else {
                let remote = async {
                    let mut request = Vec::new();
                    while let Some(chunk) = server_recv.data().await {
                        request.extend_from_slice(&chunk.unwrap());
                    }
                    assert_eq!(request, b"request");
                    server_send
                        .send_data(Bytes::from_static(b"reply after EOF"), true)
                        .unwrap();
                };
                let local = async {
                    app.write_all(b"request").await.unwrap();
                    app.shutdown().await.unwrap();
                    let mut reply = Vec::new();
                    app.read_to_end(&mut reply).await.unwrap();
                    assert_eq!(reply, b"reply after EOF");
                };
                let (result, (), ()) =
                    tokio::time::timeout(std::time::Duration::from_secs(2), async {
                        tokio::join!(proxy, remote, local)
                    })
                    .await
                    .unwrap();
                result.unwrap();
            }
            tasks.shutdown().await;
        }
    }
}
