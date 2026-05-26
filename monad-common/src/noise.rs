//! NoiseStream — AsyncRead/AsyncWrite wrapper over Noise NK transport.
//!
//! Wire format per Noise message:
//!   [2-byte big-endian length] [encrypted payload + 16-byte auth tag]
//!
//! The Noise NK pattern provides:
//!   - Server authentication (client knows server's static public key)
//!   - Forward secrecy (via ephemeral DH)
//!   - No client authentication (ephemeral clients)

use bytes::{Buf, BufMut, BytesMut};
use snow::{Builder, TransportState};
use std::io;
use std::pin::Pin;
use std::task::{Context, Poll};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

/// The Noise protocol pattern string.
/// NK: client knows server's static key, client has no static key.
/// 25519: X25519 DH
/// ChaChaPoly: ChaCha20-Poly1305 AEAD
/// BLAKE2s: hash function for key derivation
const NOISE_PATTERN: &str = "Noise_NK_25519_ChaChaPoly_BLAKE2s";

/// Maximum Noise transport message size (spec limit).
const NOISE_MAX_MSG_LEN: usize = 65535;

/// Maximum plaintext per Noise message (minus 16-byte AEAD tag).
const NOISE_MAX_PLAINTEXT_LEN: usize = NOISE_MAX_MSG_LEN - 16;

/// Length prefix size (2 bytes, big-endian).
const LEN_PREFIX_SIZE: usize = 2;

/// Generate a new Noise static keypair for the server.
/// Returns (private_key, public_key) as raw 32-byte arrays.
pub fn generate_keypair() -> (Vec<u8>, Vec<u8>) {
    let builder = Builder::new(NOISE_PATTERN.parse().unwrap());
    let keypair = builder.generate_keypair().unwrap();
    (keypair.private, keypair.public)
}

/// Perform the Noise NK handshake as the initiator (client).
///
/// The client must know the server's static public key in advance.
/// Returns an encrypted transport ready for use with `NoiseStream`.
pub async fn handshake_initiator<T>(
    stream: &mut T,
    server_pubkey: &[u8],
) -> io::Result<(TransportState, [u8; 32])>
where
    T: AsyncRead + AsyncWrite + Unpin,
{
    let builder = Builder::new(NOISE_PATTERN.parse().map_err(noise_err)?);
    let mut noise = builder
        .remote_public_key(server_pubkey)
        .build_initiator()
        .map_err(noise_err)?;

    let mut buf = vec![0u8; NOISE_MAX_MSG_LEN];

    // -> e, es: client sends ephemeral key, performs DH with server's static key
    let len = noise.write_message(&[], &mut buf).map_err(noise_err)?;
    write_noise_msg(stream, &buf[..len]).await?;

    // <- e, ee: server sends ephemeral key, performs DH
    let msg = read_noise_msg(stream).await?;
    noise.read_message(&msg, &mut buf).map_err(noise_err)?;

    let handshake_hash: [u8; 32] = noise.get_handshake_hash().try_into().map_err(|_| {
        noise_err(snow::Error::State(
            snow::error::StateProblem::HandshakeNotFinished,
        ))
    })?;
    let transport = noise.into_transport_mode().map_err(noise_err)?;
    Ok((transport, handshake_hash))
}

/// Perform the Noise NK handshake as the responder (server).
///
/// The server uses its static private key.
/// Returns an encrypted transport ready for use with `NoiseStream`.
pub async fn handshake_responder<T>(
    stream: &mut T,
    server_privkey: &[u8],
) -> io::Result<(TransportState, [u8; 32])>
where
    T: AsyncRead + AsyncWrite + Unpin,
{
    let builder = Builder::new(NOISE_PATTERN.parse().map_err(noise_err)?);
    let mut noise = builder
        .local_private_key(server_privkey)
        .build_responder()
        .map_err(noise_err)?;

    let mut buf = vec![0u8; NOISE_MAX_MSG_LEN];

    // <- e, es: read client's ephemeral key
    let msg = read_noise_msg(stream).await?;
    noise.read_message(&msg, &mut buf).map_err(noise_err)?;

    // -> e, ee: send server's ephemeral key
    let len = noise.write_message(&[], &mut buf).map_err(noise_err)?;
    write_noise_msg(stream, &buf[..len]).await?;

    let handshake_hash: [u8; 32] = noise.get_handshake_hash().try_into().map_err(|_| {
        noise_err(snow::Error::State(
            snow::error::StateProblem::HandshakeNotFinished,
        ))
    })?;
    let transport = noise.into_transport_mode().map_err(noise_err)?;
    Ok((transport, handshake_hash))
}

/// Write a length-prefixed message to the stream.
async fn write_noise_msg<T: AsyncWrite + Unpin>(stream: &mut T, msg: &[u8]) -> io::Result<()> {
    use tokio::io::AsyncWriteExt;

    let len = msg.len() as u16;
    stream.write_all(&len.to_be_bytes()).await?;
    stream.write_all(msg).await?;
    stream.flush().await?;
    Ok(())
}

/// Read a length-prefixed message from the stream.
async fn read_noise_msg<T: AsyncRead + Unpin>(stream: &mut T) -> io::Result<Vec<u8>> {
    use tokio::io::AsyncReadExt;

    let mut len_buf = [0u8; LEN_PREFIX_SIZE];
    stream.read_exact(&mut len_buf).await?;
    let len = u16::from_be_bytes(len_buf) as usize;

    if len > NOISE_MAX_MSG_LEN {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("noise message too large: {len}"),
        ));
    }

    let mut msg = vec![0u8; len];
    stream.read_exact(&mut msg).await?;
    Ok(msg)
}

fn noise_err(e: snow::Error) -> io::Error {
    io::Error::new(io::ErrorKind::Other, format!("noise error: {e}"))
}

// ---------------------------------------------------------------------------
// NoiseStream: AsyncRead + AsyncWrite over Noise transport
// ---------------------------------------------------------------------------

/// An encrypted bidirectional stream over a Noise NK transport.
///
/// Wraps an inner `AsyncRead + AsyncWrite + Unpin` stream (typically a `TcpStream`)
/// and transparently encrypts/decrypts all data using the Noise transport state.
///
/// Tracks total wire bytes (encrypted) read and written. On drop, logs the totals
/// via `tracing::debug!` for debugging and bandwidth accounting.
pub struct NoiseStream<T> {
    inner: T,
    transport: TransportState,

    /// Noise handshake hash — identical on both sides, unique per session.
    session_id: [u8; 32],

    // Read side: buffer for decrypted plaintext not yet consumed by the caller
    read_plaintext: BytesMut,
    // Read side: buffer for accumulating an incoming encrypted message (len-prefixed)
    read_ciphertext: BytesMut,
    // Expected length of the current incoming message (None = reading len prefix)
    read_expected_len: Option<usize>,

    // Write side: buffer for encrypted data not yet flushed to inner stream
    write_ciphertext: BytesMut,

    // Wire byte counters (encrypted bytes on the underlying transport)
    wire_bytes_read: u64,
    wire_bytes_written: u64,

    // Human-readable label for logging (e.g., "127.0.0.1:9050 <-> 127.0.0.1:43210")
    label: String,
}

// NoiseStream is Unpin as long as T is Unpin (which we require).
impl<T: Unpin> Unpin for NoiseStream<T> {}

impl<T> NoiseStream<T> {
    /// Create a new `NoiseStream` from an inner stream, an established Noise
    /// transport, and a label for logging.
    ///
    /// The label typically describes the connection endpoints, e.g.,
    /// `"127.0.0.1:9050 <-> 127.0.0.1:43210"` or `"tunnel to 1.2.3.4:9050"`.
    pub fn new(
        inner: T,
        transport: TransportState,
        session_id: [u8; 32],
        label: impl Into<String>,
    ) -> Self {
        Self {
            inner,
            transport,
            session_id,
            read_plaintext: BytesMut::new(),
            read_ciphertext: BytesMut::new(),
            read_expected_len: None,
            write_ciphertext: BytesMut::new(),
            wire_bytes_read: 0,
            wire_bytes_written: 0,
            label: label.into(),
        }
    }

    /// The Noise handshake hash, used as a unique session identifier.
    ///
    /// Identical on both sides of the connection. Derived from the Noise
    /// transcript (ephemeral keys + DH results), so it's unique per session
    /// and unpredictable to non-participants.
    pub fn session_id(&self) -> &[u8; 32] {
        &self.session_id
    }
}

impl<T> Drop for NoiseStream<T> {
    fn drop(&mut self) {
        tracing::debug!(
            label = %self.label,
            wire_read = self.wire_bytes_read,
            wire_written = self.wire_bytes_written,
            wire_total = self.wire_bytes_read + self.wire_bytes_written,
            "NoiseStream closed"
        );
    }
}

impl<T: AsyncRead + AsyncWrite + Unpin> AsyncRead for NoiseStream<T> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let me = self.get_mut();

        // If we have decrypted plaintext buffered, return it immediately
        if !me.read_plaintext.is_empty() {
            let to_copy = std::cmp::min(buf.remaining(), me.read_plaintext.len());
            buf.put_slice(&me.read_plaintext[..to_copy]);
            me.read_plaintext.advance(to_copy);
            return Poll::Ready(Ok(()));
        }

        // We need to read and decrypt a new Noise message from the inner stream.
        // Noise messages are framed as: [2-byte big-endian length] [encrypted payload]
        loop {
            match me.read_expected_len {
                None => {
                    // We need to read the 2-byte length prefix
                    if me.read_ciphertext.len() >= LEN_PREFIX_SIZE {
                        let len = u16::from_be_bytes([me.read_ciphertext[0], me.read_ciphertext[1]])
                            as usize;
                        me.read_ciphertext.advance(LEN_PREFIX_SIZE);
                        if len > NOISE_MAX_MSG_LEN {
                            return Poll::Ready(Err(io::Error::new(
                                io::ErrorKind::InvalidData,
                                format!("noise message too large: {len}"),
                            )));
                        }
                        me.read_expected_len = Some(len);
                        continue;
                    }

                    // Need more data for the length prefix
                    me.read_ciphertext.reserve(LEN_PREFIX_SIZE);
                    let mut tmp_buf = [0u8; 256];
                    let mut tmp_read_buf = ReadBuf::new(&mut tmp_buf);
                    match Pin::new(&mut me.inner).poll_read(cx, &mut tmp_read_buf) {
                        Poll::Ready(Ok(())) => {
                            let n = tmp_read_buf.filled().len();
                            if n == 0 {
                                // EOF
                                return Poll::Ready(Ok(()));
                            }
                            me.wire_bytes_read += n as u64;
                            me.read_ciphertext.extend_from_slice(tmp_read_buf.filled());
                            continue;
                        }
                        Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                        Poll::Pending => return Poll::Pending,
                    }
                }
                Some(expected) => {
                    let expected = expected;
                    if me.read_ciphertext.len() >= expected {
                        // We have the full encrypted message — decrypt it
                        let encrypted = &me.read_ciphertext[..expected];
                        let mut plaintext = vec![0u8; expected];
                        let len = me
                            .transport
                            .read_message(encrypted, &mut plaintext)
                            .map_err(noise_err)?;
                        me.read_ciphertext.advance(expected);
                        me.read_expected_len = None;

                        // Buffer the plaintext and return what we can
                        me.read_plaintext.extend_from_slice(&plaintext[..len]);
                        let to_copy = std::cmp::min(buf.remaining(), me.read_plaintext.len());
                        buf.put_slice(&me.read_plaintext[..to_copy]);
                        me.read_plaintext.advance(to_copy);
                        return Poll::Ready(Ok(()));
                    }

                    // Need more data for the encrypted message body
                    me.read_ciphertext
                        .reserve(expected - me.read_ciphertext.len());
                    let mut tmp_buf = vec![0u8; std::cmp::min(expected * 2, 65536)];
                    let mut tmp_read_buf = ReadBuf::new(&mut tmp_buf);
                    match Pin::new(&mut me.inner).poll_read(cx, &mut tmp_read_buf) {
                        Poll::Ready(Ok(())) => {
                            let n = tmp_read_buf.filled().len();
                            if n == 0 {
                                return Poll::Ready(Err(io::Error::new(
                                    io::ErrorKind::UnexpectedEof,
                                    "connection closed mid-noise-message",
                                )));
                            }
                            me.wire_bytes_read += n as u64;
                            me.read_ciphertext.extend_from_slice(tmp_read_buf.filled());
                            continue;
                        }
                        Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                        Poll::Pending => return Poll::Pending,
                    }
                }
            }
        }
    }
}

impl<T: AsyncRead + AsyncWrite + Unpin> AsyncWrite for NoiseStream<T> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let me = self.get_mut();

        // First, try to flush any pending ciphertext
        while !me.write_ciphertext.is_empty() {
            match Pin::new(&mut me.inner).poll_write(cx, &me.write_ciphertext) {
                Poll::Ready(Ok(n)) => {
                    me.wire_bytes_written += n as u64;
                    me.write_ciphertext.advance(n);
                }
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                Poll::Pending => return Poll::Pending,
            }
        }

        if buf.is_empty() {
            return Poll::Ready(Ok(0));
        }

        // Encrypt up to NOISE_MAX_PLAINTEXT_LEN bytes
        let to_encrypt = std::cmp::min(buf.len(), NOISE_MAX_PLAINTEXT_LEN);
        let mut encrypted = vec![0u8; to_encrypt + 16]; // +16 for AEAD tag
        let encrypted_len = me
            .transport
            .write_message(&buf[..to_encrypt], &mut encrypted)
            .map_err(noise_err)?;

        // Frame it: 2-byte length prefix + encrypted payload
        let len_prefix = (encrypted_len as u16).to_be_bytes();
        me.write_ciphertext.reserve(LEN_PREFIX_SIZE + encrypted_len);
        me.write_ciphertext.put_slice(&len_prefix);
        me.write_ciphertext.put_slice(&encrypted[..encrypted_len]);

        // Try to write as much of the ciphertext as possible
        while !me.write_ciphertext.is_empty() {
            match Pin::new(&mut me.inner).poll_write(cx, &me.write_ciphertext) {
                Poll::Ready(Ok(n)) => {
                    me.wire_bytes_written += n as u64;
                    me.write_ciphertext.advance(n);
                }
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                Poll::Pending => {
                    // We accepted the plaintext even though we couldn't flush all ciphertext.
                    // That's fine — flush will handle it.
                    break;
                }
            }
        }

        Poll::Ready(Ok(to_encrypt))
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let me = self.get_mut();

        // Flush any buffered ciphertext
        while !me.write_ciphertext.is_empty() {
            match Pin::new(&mut me.inner).poll_write(cx, &me.write_ciphertext) {
                Poll::Ready(Ok(n)) => {
                    if n == 0 {
                        return Poll::Ready(Err(io::Error::new(
                            io::ErrorKind::WriteZero,
                            "write returned 0",
                        )));
                    }
                    me.wire_bytes_written += n as u64;
                    me.write_ciphertext.advance(n);
                }
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                Poll::Pending => return Poll::Pending,
            }
        }

        Pin::new(&mut me.inner).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let me = self.get_mut();

        // Flush remaining ciphertext first
        while !me.write_ciphertext.is_empty() {
            match Pin::new(&mut me.inner).poll_write(cx, &me.write_ciphertext) {
                Poll::Ready(Ok(n)) => {
                    if n == 0 {
                        return Poll::Ready(Err(io::Error::new(
                            io::ErrorKind::WriteZero,
                            "write returned 0",
                        )));
                    }
                    me.wire_bytes_written += n as u64;
                    me.write_ciphertext.advance(n);
                }
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                Poll::Pending => return Poll::Pending,
            }
        }

        Pin::new(&mut me.inner).poll_shutdown(cx)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::{TcpListener, TcpStream};

    #[tokio::test]
    async fn test_noise_handshake_and_transport() {
        let (privkey, pubkey) = generate_keypair();

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        let server_handle = tokio::spawn({
            let privkey = privkey.clone();
            async move {
                let (mut stream, _) = listener.accept().await.unwrap();
                let (transport, session_id) =
                    handshake_responder(&mut stream, &privkey).await.unwrap();
                let mut noise_stream =
                    NoiseStream::new(stream, transport, session_id, "test-server");

                let mut buf = vec![0u8; 1024];
                let n = noise_stream.read(&mut buf).await.unwrap();
                assert_eq!(&buf[..n], b"hello from client");

                noise_stream.write_all(b"hello from server").await.unwrap();
                noise_stream.flush().await.unwrap();
            }
        });

        let client_handle = tokio::spawn(async move {
            let mut stream = TcpStream::connect(addr).await.unwrap();
            let (transport, session_id) = handshake_initiator(&mut stream, &pubkey).await.unwrap();
            let mut noise_stream = NoiseStream::new(stream, transport, session_id, "test-client");

            noise_stream.write_all(b"hello from client").await.unwrap();
            noise_stream.flush().await.unwrap();

            let mut buf = vec![0u8; 1024];
            let n = noise_stream.read(&mut buf).await.unwrap();
            assert_eq!(&buf[..n], b"hello from server");
        });

        server_handle.await.unwrap();
        client_handle.await.unwrap();
    }

    #[tokio::test]
    async fn test_large_payload() {
        let (privkey, pubkey) = generate_keypair();

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        // Send a payload larger than NOISE_MAX_PLAINTEXT_LEN to test chunking
        let large_data: Vec<u8> = (0..200_000).map(|i| (i % 256) as u8).collect();

        let server_handle = tokio::spawn({
            let privkey = privkey.clone();
            let expected = large_data.clone();
            async move {
                let (mut stream, _) = listener.accept().await.unwrap();
                let (transport, session_id) =
                    handshake_responder(&mut stream, &privkey).await.unwrap();
                let mut noise_stream =
                    NoiseStream::new(stream, transport, session_id, "test-server-large");

                let mut received = Vec::new();
                let mut buf = vec![0u8; 8192];
                while received.len() < expected.len() {
                    let n = noise_stream.read(&mut buf).await.unwrap();
                    if n == 0 {
                        break;
                    }
                    received.extend_from_slice(&buf[..n]);
                }

                assert_eq!(received.len(), expected.len());
                assert_eq!(received, expected);
            }
        });

        let client_handle = tokio::spawn(async move {
            let mut stream = TcpStream::connect(addr).await.unwrap();
            let (transport, session_id) = handshake_initiator(&mut stream, &pubkey).await.unwrap();
            let mut noise_stream =
                NoiseStream::new(stream, transport, session_id, "test-client-large");

            noise_stream.write_all(&large_data).await.unwrap();
            noise_stream.flush().await.unwrap();
            noise_stream.shutdown().await.unwrap();
        });

        server_handle.await.unwrap();
        client_handle.await.unwrap();
    }

    #[tokio::test]
    async fn test_session_id_matches_on_both_sides() {
        let (privkey, pubkey) = generate_keypair();

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        let server_handle = tokio::spawn({
            let privkey = privkey.clone();
            async move {
                let (mut stream, _) = listener.accept().await.unwrap();
                let (_, session_id) = handshake_responder(&mut stream, &privkey).await.unwrap();
                session_id
            }
        });

        let client_handle = tokio::spawn(async move {
            let mut stream = TcpStream::connect(addr).await.unwrap();
            let (_, session_id) = handshake_initiator(&mut stream, &pubkey).await.unwrap();
            session_id
        });

        let server_session_id = server_handle.await.unwrap();
        let client_session_id = client_handle.await.unwrap();

        assert_eq!(server_session_id, client_session_id);
        assert_ne!(server_session_id, [0u8; 32]);
    }
}
