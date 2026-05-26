//! `QuicStream` — wraps a quinn bidirectional stream as `AsyncRead + AsyncWrite`.
//!
//! This allows a QUIC bidirectional stream to be used anywhere a `TcpStream` is
//! used today, including as the transport for `NoiseStream<QuicStream>`.

use std::io;
use std::pin::Pin;
use std::task::{Context, Poll};
use tokio::io::AsyncWriteExt;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

pub const STREAM_KIND_PLAIN_NOISE: u8 = 0x00;
pub const STREAM_ERROR_UNKNOWN_KIND: u64 = 0x01;

fn stream_error_code(code: u64) -> quinn::VarInt {
    quinn::VarInt::from_u64(code).expect("valid QUIC application error code")
}

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

/// Open a QUIC bidirectional stream carrying a MONAD session.
pub async fn open_monad_stream(conn: &quinn::Connection) -> io::Result<QuicStream> {
    let (mut send, recv) = conn
        .open_bi()
        .await
        .map_err(|e| io::Error::other(format!("failed to open QUIC stream: {e}")))?;
    send.write_all(&[STREAM_KIND_PLAIN_NOISE])
        .await
        .map_err(|e| io::Error::other(format!("failed to write QUIC stream preamble: {e}")))?;
    send.flush()
        .await
        .map_err(|e| io::Error::other(format!("failed to flush QUIC stream preamble: {e}")))?;
    Ok(QuicStream::new(send, recv))
}

/// Accept a QUIC bidirectional stream carrying a MONAD session.
pub async fn accept_monad_stream(
    mut send: quinn::SendStream,
    mut recv: quinn::RecvStream,
) -> io::Result<QuicStream> {
    let mut kind = [0u8; 1];
    if let Err(e) = recv.read_exact(&mut kind).await {
        let code = stream_error_code(STREAM_ERROR_UNKNOWN_KIND);
        let _ = recv.stop(code);
        let _ = send.reset(code);
        return Err(io::Error::other(format!(
            "failed to read QUIC stream kind preamble: {e}"
        )));
    }

    if kind[0] != STREAM_KIND_PLAIN_NOISE {
        let code = stream_error_code(STREAM_ERROR_UNKNOWN_KIND);
        let _ = recv.stop(code);
        let _ = send.reset(code);
        return Err(io::Error::other(format!(
            "unsupported QUIC stream kind: {}",
            kind[0]
        )));
    }

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
