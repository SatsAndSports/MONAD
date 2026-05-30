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
            Poll::Ready(None) => {
                // End of stream
                me.recv_done = true;
                Poll::Ready(Ok(()))
            }
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
