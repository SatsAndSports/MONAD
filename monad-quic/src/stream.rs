//! `QuicStream` — wraps a quinn bidirectional stream as `AsyncRead + AsyncWrite`.
//!
//! This allows a QUIC bidirectional stream to be used anywhere a `TcpStream` is
//! used today, including as the transport for secp Noise + H2.

use std::io;
use std::pin::Pin;
use std::task::{Context, Poll};
use tokio::io::AsyncWriteExt;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

pub const STREAM_KIND_SECP_NOISE: u8 = 0x02;
pub const STREAM_KIND_TWEAKED_NOISE: u8 = 0x03;

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

pub async fn open_monad_stream_with_kind(
    conn: &quinn::Connection,
    kind: u8,
) -> io::Result<QuicStream> {
    let (mut send, recv) = conn
        .open_bi()
        .await
        .map_err(|e| io::Error::other(format!("failed to open QUIC stream: {e}")))?;
    send.write_all(&[kind])
        .await
        .map_err(|e| io::Error::other(format!("failed to write QUIC stream preamble: {e}")))?;
    send.flush()
        .await
        .map_err(|e| io::Error::other(format!("failed to flush QUIC stream preamble: {e}")))?;
    Ok(QuicStream::new(send, recv))
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
