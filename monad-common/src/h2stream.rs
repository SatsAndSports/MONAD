//! H2ConnectStream — wraps an H2 CONNECT stream (SendStream + RecvStream)
//! as a single AsyncRead + AsyncWrite type.
//!
//! This is the key abstraction for nesting / onion routing: it makes an H2
//! CONNECT tunnel look like a plain TCP socket, so that another Noise + H2
//! session can run on top of it.

use crate::proxy::CleartextByteCounters;
use bytes::{Buf, Bytes, BytesMut};
use h2::{RecvStream, SendStream};
use std::io;
use std::pin::Pin;
use std::task::{Context, Poll};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

/// Maximum uncompressed size of one MONAD H2 header list, including the
/// per-field overhead defined by HTTP/2.
pub const MAX_H2_HEADER_LIST_SIZE: u32 = 32 * 1024;

const TRAILERS_NOT_PERMITTED: &str = "H2 trailers are not permitted by MONAD";

/// Complete an H2 receive body while rejecting any trailing HEADERS block.
pub async fn ensure_no_trailers(recv: &mut RecvStream) -> io::Result<()> {
    match recv
        .trailers()
        .await
        .map_err(|e| io::Error::other(format!("h2 trailer receive error: {e}")))?
    {
        Some(_) => Err(io::Error::new(
            io::ErrorKind::InvalidData,
            TRAILERS_NOT_PERMITTED,
        )),
        None => Ok(()),
    }
}

/// An H2 CONNECT stream wrapped as AsyncRead + AsyncWrite.
///
/// This allows an H2 data channel to be used as the underlying transport
/// for another Noise + H2 connection, enabling nested tunneling.
pub struct H2ConnectStream {
    send: SendStream<Bytes>,
    recv: RecvStream,
    accounting: Option<CleartextByteCounters>,

    // Read side: buffered data from H2 data frames not yet consumed by the caller.
    read_buf: BytesMut,

    // Track whether we've received end-of-stream on the read side.
    recv_done: bool,
}

/// Wait for H2 flow control capacity on a send stream.
///
/// This is the async counterpart to calling `poll_capacity` directly in a
/// `poll_*` method: it sleeps until the peer sends a WINDOW_UPDATE instead of
/// busy-looping.
pub async fn wait_for_send_capacity(send: &mut SendStream<Bytes>) -> io::Result<usize> {
    match std::future::poll_fn(|cx| send.poll_capacity(cx)).await {
        Some(Ok(capacity)) => Ok(capacity),
        Some(Err(e)) => Err(io::Error::other(format!("h2 capacity error: {e}"))),
        None => Err(io::Error::new(
            io::ErrorKind::BrokenPipe,
            "h2 send stream closed",
        )),
    }
}

impl H2ConnectStream {
    /// Create a new `H2ConnectStream` from an H2 send/recv stream pair.
    ///
    /// These are typically obtained from an H2 CONNECT request:
    /// - `send` from `h2_client.send_request(connect_request, false)`
    /// - `recv` from `response.into_body()`
    pub fn new(
        send: SendStream<Bytes>,
        recv: RecvStream,
        accounting: Option<CleartextByteCounters>,
    ) -> Self {
        Self {
            send,
            recv,
            accounting,
            read_buf: BytesMut::new(),
            recv_done: false,
        }
    }
}

impl Unpin for H2ConnectStream {}

impl AsyncRead for H2ConnectStream {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let me = self.get_mut();

        // Return buffered data first
        if !me.read_buf.is_empty() {
            let to_copy = std::cmp::min(buf.remaining(), me.read_buf.len());
            buf.put_slice(&me.read_buf[..to_copy]);
            me.read_buf.advance(to_copy);
            if let Some(accounting) = &me.accounting {
                accounting.note_inbound(to_copy);
            }
            return Poll::Ready(Ok(()));
        }

        // If we already saw end-of-stream, return EOF
        if me.recv_done {
            return Poll::Ready(Ok(()));
        }

        // Poll the H2 recv stream for the next data frame.
        // RecvStream::poll_data returns Poll<Option<Result<Bytes>>>.
        match me.recv.poll_data(cx) {
            Poll::Ready(Some(Ok(data))) => {
                // Release H2 flow control capacity
                let len = data.len();
                let _ = me.recv.flow_control().release_capacity(len);

                // Copy what we can into the caller's buffer, buffer the rest
                let to_copy = std::cmp::min(buf.remaining(), data.len());
                buf.put_slice(&data[..to_copy]);
                if let Some(accounting) = &me.accounting {
                    accounting.note_inbound(to_copy);
                }
                if to_copy < data.len() {
                    me.read_buf.extend_from_slice(&data[to_copy..]);
                }
                Poll::Ready(Ok(()))
            }
            Poll::Ready(Some(Err(e))) => {
                Poll::Ready(Err(io::Error::other(format!("h2 recv error: {e}"))))
            }
            Poll::Ready(None) => match me.recv.poll_trailers(cx) {
                Poll::Ready(Ok(Some(_))) => Poll::Ready(Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    TRAILERS_NOT_PERMITTED,
                ))),
                Poll::Ready(Ok(None)) => {
                    me.recv_done = true;
                    Poll::Ready(Ok(()))
                }
                Poll::Ready(Err(e)) => Poll::Ready(Err(io::Error::other(format!(
                    "h2 trailer receive error: {e}"
                )))),
                Poll::Pending => Poll::Pending,
            },
            Poll::Pending => Poll::Pending,
        }
    }
}

impl AsyncWrite for H2ConnectStream {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let me = self.get_mut();

        if buf.is_empty() {
            return Poll::Ready(Ok(0));
        }

        // Reserve capacity for the write
        me.send.reserve_capacity(buf.len());

        // Wait for flow control capacity (proper waker-based, no spinning)
        match me.send.poll_capacity(cx) {
            Poll::Ready(Some(Ok(capacity))) => {
                // Send up to `capacity` bytes
                let to_send = std::cmp::min(buf.len(), capacity);
                let data = Bytes::copy_from_slice(&buf[..to_send]);
                me.send
                    .send_data(data, false)
                    .map_err(|e| io::Error::other(format!("h2 send error: {e}")))?;
                if let Some(accounting) = &me.accounting {
                    accounting.note_outbound(to_send);
                }
                Poll::Ready(Ok(to_send))
            }
            Poll::Ready(Some(Err(e))) => {
                Poll::Ready(Err(io::Error::other(format!("h2 capacity error: {e}"))))
            }
            Poll::Ready(None) => Poll::Ready(Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "h2 send stream closed",
            ))),
            Poll::Pending => Poll::Pending,
        }
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        // H2 frames are sent immediately when send_data is called.
        // The actual flushing to the wire is handled by the H2 connection driver.
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let me = self.get_mut();
        // Send an empty frame with end_of_stream=true
        let _ = me.send.send_data(Bytes::new(), true);
        Poll::Ready(Ok(()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use http::{HeaderMap, HeaderValue, Request, Response};
    use tokio::io::AsyncReadExt;
    use tokio::time::{timeout, Duration};

    #[tokio::test]
    async fn connect_stream_rejects_trailers() {
        let (client_io, server_io) = tokio::io::duplex(4096);
        let (mut client, client_conn) = h2::client::handshake(client_io).await.unwrap();
        let client_driver = tokio::spawn(async move {
            let _ = client_conn.await;
        });
        let (response, send) = client
            .send_request(
                Request::builder()
                    .method("CONNECT")
                    .uri("target:80")
                    .body(())
                    .unwrap(),
                false,
            )
            .unwrap();

        let mut server = h2::server::handshake(server_io).await.unwrap();
        let (_request, mut respond) = server.accept().await.unwrap().unwrap();
        let mut server_send = respond.send_response(Response::new(()), false).unwrap();
        let server_driver = tokio::spawn(async move { while server.accept().await.is_some() {} });
        let recv = response.await.unwrap().into_body();
        let mut stream = H2ConnectStream::new(send, recv, None);

        server_send.send_trailers(HeaderMap::new()).unwrap();
        let error = timeout(Duration::from_secs(2), async {
            let mut bytes = Vec::new();
            stream.read_to_end(&mut bytes).await.unwrap_err()
        })
        .await
        .unwrap();
        assert_eq!(error.kind(), io::ErrorKind::InvalidData);
        assert_eq!(error.to_string(), TRAILERS_NOT_PERMITTED);

        client_driver.abort();
        server_driver.abort();
    }

    #[tokio::test]
    async fn client_header_limit_rejects_oversized_response() {
        let (client_io, server_io) = tokio::io::duplex(128 * 1024);
        let (mut client, client_conn) = h2::client::Builder::new()
            .max_header_list_size(MAX_H2_HEADER_LIST_SIZE)
            .handshake::<_, Bytes>(client_io)
            .await
            .unwrap();
        let client_driver = tokio::spawn(async move {
            let _ = client_conn.await;
        });
        let (response, _send) = client.send_request(Request::new(()), true).unwrap();

        let mut server = h2::server::handshake(server_io).await.unwrap();
        let (_request, mut respond) = server.accept().await.unwrap().unwrap();
        let oversized = HeaderValue::from_bytes(&vec![b'x'; 40 * 1024]).unwrap();
        let response_headers = Response::builder()
            .header("x-oversized", oversized)
            .body(())
            .unwrap();
        respond.send_response(response_headers, true).unwrap();
        let server_driver = tokio::spawn(async move { while server.accept().await.is_some() {} });

        assert!(timeout(Duration::from_secs(2), response)
            .await
            .unwrap()
            .is_err());
        client_driver.abort();
        server_driver.abort();
    }

    #[tokio::test]
    async fn server_header_limit_rejects_oversized_request_before_dispatch() {
        use std::sync::atomic::{AtomicBool, Ordering};
        use std::sync::Arc;

        let (client_io, server_io) = tokio::io::duplex(128 * 1024);
        let (mut client, client_conn) = h2::client::handshake(client_io).await.unwrap();
        let client_driver = tokio::spawn(async move {
            let _ = client_conn.await;
        });
        let mut server = h2::server::Builder::new()
            .max_header_list_size(MAX_H2_HEADER_LIST_SIZE)
            .handshake::<_, Bytes>(server_io)
            .await
            .unwrap();
        let dispatched = Arc::new(AtomicBool::new(false));
        let server_dispatched = dispatched.clone();
        let server_driver = tokio::spawn(async move {
            if matches!(server.accept().await, Some(Ok(_))) {
                server_dispatched.store(true, Ordering::SeqCst);
            }
        });

        let oversized = HeaderValue::from_bytes(&vec![b'x'; 40 * 1024]).unwrap();
        let request = Request::builder()
            .header("x-oversized", oversized)
            .body(())
            .unwrap();
        if let Ok((response, _send)) = client.send_request(request, true) {
            if let Ok(response) = timeout(Duration::from_secs(2), response).await.unwrap() {
                assert_eq!(
                    response.status(),
                    http::StatusCode::REQUEST_HEADER_FIELDS_TOO_LARGE
                );
            }
        }
        tokio::task::yield_now().await;
        assert!(!dispatched.load(Ordering::SeqCst));
        client_driver.abort();
        server_driver.abort();
    }
}
