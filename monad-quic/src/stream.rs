//! `QuicStream` — wraps a quinn bidirectional stream as `AsyncRead + AsyncWrite`.
//!
//! This allows a QUIC bidirectional stream to be used anywhere a `TcpStream` is
//! used today, including as the transport for `NoiseStream<QuicStream>`.

use std::io;
use std::pin::Pin;
use std::task::{Context, Poll};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

/// A bidirectional QUIC stream that implements `AsyncRead + AsyncWrite`.
///
/// Wraps a quinn `SendStream` + `RecvStream` pair into a single type that
/// can be used interchangeably with `TcpStream` as a transport for Noise+H2.
pub struct QuicStream {
    send: quinn::SendStream,
    recv: quinn::RecvStream,
}

impl QuicStream {
    /// Create a new `QuicStream` from a quinn bidirectional stream pair.
    pub fn new(send: quinn::SendStream, recv: quinn::RecvStream) -> Self {
        Self { send, recv }
    }
}

impl AsyncRead for QuicStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        // quinn::RecvStream implements AsyncRead
        Pin::new(&mut self.recv).poll_read(cx, buf)
    }
}

impl AsyncWrite for QuicStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        // quinn::SendStream implements AsyncWrite
        <quinn::SendStream as AsyncWrite>::poll_write(Pin::new(&mut self.send), cx, buf)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        <quinn::SendStream as AsyncWrite>::poll_flush(Pin::new(&mut self.send), cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        <quinn::SendStream as AsyncWrite>::poll_shutdown(Pin::new(&mut self.send), cx)
    }
}
