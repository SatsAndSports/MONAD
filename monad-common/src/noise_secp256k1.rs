use bytes::{Buf, BufMut, BytesMut};
use k256::elliptic_curve::sec1::ToEncodedPoint;
use k256::{ecdh, PublicKey, SecretKey};
use noise_protocol::patterns;
use noise_protocol::{CipherState, HandshakeState, U8Array};
use noise_rust_crypto::{Blake2s, ChaCha20Poly1305};
use std::io;
use std::pin::Pin;
use std::task::{Context, Poll};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};

use crate::bootstrap::{
    decode_client_hello, decode_server_response, decode_v1_client_hello, decode_v1_server_accept,
    encode_client_hello, encode_server_response, highest_supported_version, initial_client_hello,
    initial_server_accept, initial_server_accept_v1, supported_bootstrap_versions,
    validate_v1_client_hello, BootstrapServerResponse, BOOTSTRAP_VERSION,
};
use crate::secp_identity::{Secp256k1Pubkey, SecpTransportKeypair};

const PROLOGUE: &[u8] = b"monad-noise-secp256k1-v1";
const MAX_MSG_LEN: usize = 65535;
const LEN_PREFIX_SIZE: usize = 2;
const MAX_PLAINTEXT_LEN: usize = MAX_MSG_LEN - 16;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SecpPublicKeyBytes([u8; 33]);

impl U8Array for SecpPublicKeyBytes {
    fn new() -> Self {
        Self([0u8; 33])
    }

    fn new_with(x: u8) -> Self {
        Self([x; 33])
    }

    fn from_slice(data: &[u8]) -> Self {
        let mut out = [0u8; 33];
        out.copy_from_slice(data);
        Self(out)
    }

    fn len() -> usize {
        33
    }

    fn as_slice(&self) -> &[u8] {
        &self.0
    }

    fn as_mut(&mut self) -> &mut [u8] {
        &mut self.0
    }
}

pub struct Secp256k1Dh;

impl noise_protocol::DH for Secp256k1Dh {
    type Key = [u8; 32];
    type Pubkey = SecpPublicKeyBytes;
    type Output = [u8; 32];

    fn name() -> &'static str {
        "secp256k1"
    }

    fn genkey() -> Self::Key {
        SecpTransportKeypair::generate().normalized_secret_bytes()
    }

    fn pubkey(key: &Self::Key) -> Self::Pubkey {
        let secret_key = SecretKey::from_slice(key).expect("valid secp256k1 secret key bytes");
        let public_key = secret_key.public_key();
        let encoded = public_key.to_encoded_point(true);
        SecpPublicKeyBytes::from_slice(encoded.as_bytes())
    }

    fn dh(key: &Self::Key, pubkey: &Self::Pubkey) -> Result<Self::Output, ()> {
        let secret_key = SecretKey::from_slice(key).map_err(|_| ())?;
        let public_key = PublicKey::from_sec1_bytes(pubkey.as_slice()).map_err(|_| ())?;
        let shared = ecdh::diffie_hellman(secret_key.to_nonzero_scalar(), public_key.as_affine());
        Ok((*shared.raw_secret_bytes()).into())
    }
}

type SecpHandshake = HandshakeState<Secp256k1Dh, ChaCha20Poly1305, Blake2s>;

pub struct SecpNoiseStream<T> {
    inner: T,
    send_cipher: CipherState<ChaCha20Poly1305>,
    recv_cipher: CipherState<ChaCha20Poly1305>,
    session_id: [u8; 32],
    read_plaintext: BytesMut,
    read_ciphertext: BytesMut,
    read_expected_len: Option<usize>,
    write_ciphertext: BytesMut,
    wire_bytes_read: u64,
    wire_bytes_written: u64,
    label: String,
}

impl<T> SecpNoiseStream<T> {
    pub fn new(
        inner: T,
        send_cipher: CipherState<ChaCha20Poly1305>,
        recv_cipher: CipherState<ChaCha20Poly1305>,
        session_id: [u8; 32],
        label: impl Into<String>,
    ) -> Self {
        Self {
            inner,
            send_cipher,
            recv_cipher,
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

    pub fn session_id(&self) -> &[u8; 32] {
        &self.session_id
    }

    fn poll_flush_pending_ciphertext(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>>
    where
        T: AsyncWrite + Unpin,
    {
        while !self.write_ciphertext.is_empty() {
            match Pin::new(&mut self.inner).poll_write(cx, &self.write_ciphertext) {
                Poll::Ready(Ok(0)) => {
                    return Poll::Ready(Err(io::Error::new(
                        io::ErrorKind::WriteZero,
                        "write returned 0",
                    )));
                }
                Poll::Ready(Ok(n)) => {
                    self.wire_bytes_written += n as u64;
                    self.write_ciphertext.advance(n);
                }
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                Poll::Pending => return Poll::Pending,
            }
        }

        Poll::Ready(Ok(()))
    }
}

impl<T> Drop for SecpNoiseStream<T> {
    fn drop(&mut self) {
        tracing::debug!(
            label = %self.label,
            wire_read = self.wire_bytes_read,
            wire_written = self.wire_bytes_written,
            wire_total = self.wire_bytes_read + self.wire_bytes_written,
            "SecpNoiseStream closed"
        );
    }
}

impl<T: Unpin> Unpin for SecpNoiseStream<T> {}

impl<T: AsyncRead + AsyncWrite + Unpin> AsyncRead for SecpNoiseStream<T> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let me = self.get_mut();

        if !me.read_plaintext.is_empty() {
            let to_copy = std::cmp::min(buf.remaining(), me.read_plaintext.len());
            buf.put_slice(&me.read_plaintext[..to_copy]);
            me.read_plaintext.advance(to_copy);
            return Poll::Ready(Ok(()));
        }

        loop {
            match me.read_expected_len {
                None => {
                    if me.read_ciphertext.len() >= LEN_PREFIX_SIZE {
                        let len = u16::from_be_bytes([me.read_ciphertext[0], me.read_ciphertext[1]])
                            as usize;
                        me.read_ciphertext.advance(LEN_PREFIX_SIZE);
                        if len > MAX_MSG_LEN {
                            return Poll::Ready(Err(io::Error::new(
                                io::ErrorKind::InvalidData,
                                format!("noise message too large: {len}"),
                            )));
                        }
                        me.read_expected_len = Some(len);
                        continue;
                    }

                    let mut tmp = [0u8; 256];
                    let mut tmp_read_buf = ReadBuf::new(&mut tmp);
                    match Pin::new(&mut me.inner).poll_read(cx, &mut tmp_read_buf) {
                        Poll::Ready(Ok(())) => {
                            let n = tmp_read_buf.filled().len();
                            if n == 0 {
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
                    if me.read_ciphertext.len() >= expected {
                        let encrypted = me.read_ciphertext.split_to(expected).freeze();
                        me.read_expected_len = None;
                        let plaintext = me.recv_cipher.decrypt_vec(&encrypted).map_err(|_| {
                            io::Error::new(io::ErrorKind::InvalidData, "noise decrypt failed")
                        })?;
                        me.read_plaintext.extend_from_slice(&plaintext);
                        let to_copy = std::cmp::min(buf.remaining(), me.read_plaintext.len());
                        buf.put_slice(&me.read_plaintext[..to_copy]);
                        me.read_plaintext.advance(to_copy);
                        return Poll::Ready(Ok(()));
                    }

                    let mut tmp = vec![0u8; std::cmp::min(expected * 2, 65536)];
                    let mut tmp_read_buf = ReadBuf::new(&mut tmp);
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

impl<T: AsyncRead + AsyncWrite + Unpin> AsyncWrite for SecpNoiseStream<T> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let me = self.get_mut();

        match me.poll_flush_pending_ciphertext(cx) {
            Poll::Ready(Ok(())) => {}
            Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
            Poll::Pending => return Poll::Pending,
        }

        if buf.is_empty() {
            return Poll::Ready(Ok(0));
        }

        let plaintext_len = std::cmp::min(buf.len(), MAX_PLAINTEXT_LEN);
        let encrypted = me.send_cipher.encrypt_vec(&buf[..plaintext_len]);
        let len = encrypted.len() as u16;
        me.write_ciphertext
            .reserve(LEN_PREFIX_SIZE + encrypted.len());
        me.write_ciphertext.put_slice(&len.to_be_bytes());
        me.write_ciphertext.put_slice(&encrypted);

        match me.poll_flush_pending_ciphertext(cx) {
            Poll::Ready(Ok(())) => Poll::Ready(Ok(plaintext_len)),
            Poll::Ready(Err(e)) => Poll::Ready(Err(e)),
            Poll::Pending => Poll::Ready(Ok(plaintext_len)),
        }
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let me = self.as_mut().get_mut();

        match me.poll_flush_pending_ciphertext(cx) {
            Poll::Ready(Ok(())) => Pin::new(&mut me.inner).poll_flush(cx),
            Poll::Ready(Err(e)) => Poll::Ready(Err(e)),
            Poll::Pending => Poll::Pending,
        }
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let me = self.as_mut().get_mut();

        match me.poll_flush_pending_ciphertext(cx) {
            Poll::Ready(Ok(())) => Pin::new(&mut me.inner).poll_shutdown(cx),
            Poll::Ready(Err(e)) => Poll::Ready(Err(e)),
            Poll::Pending => Poll::Pending,
        }
    }
}

async fn write_handshake_msg<T: AsyncWrite + Unpin>(stream: &mut T, msg: &[u8]) -> io::Result<()> {
    let len = msg.len() as u16;
    stream.write_all(&len.to_be_bytes()).await?;
    stream.write_all(msg).await?;
    stream.flush().await?;
    Ok(())
}

async fn read_handshake_msg<T: AsyncRead + Unpin>(stream: &mut T) -> io::Result<Vec<u8>> {
    let mut len_buf = [0u8; LEN_PREFIX_SIZE];
    stream.read_exact(&mut len_buf).await?;
    let len = u16::from_be_bytes(len_buf) as usize;
    let mut msg = vec![0u8; len];
    stream.read_exact(&mut msg).await?;
    Ok(msg)
}

pub async fn handshake_initiator<T: AsyncRead + AsyncWrite + Unpin>(
    stream: &mut T,
    server_pubkey: &Secp256k1Pubkey,
) -> io::Result<(
    CipherState<ChaCha20Poly1305>,
    CipherState<ChaCha20Poly1305>,
    [u8; 32],
)> {
    handshake_initiator_with_pubkey(stream, server_pubkey.to_compressed_bytes()).await
}

pub async fn handshake_initiator_with_pubkey<T: AsyncRead + AsyncWrite + Unpin>(
    stream: &mut T,
    server_pubkey: [u8; 33],
) -> io::Result<(
    CipherState<ChaCha20Poly1305>,
    CipherState<ChaCha20Poly1305>,
    [u8; 32],
)> {
    let client_payload = encode_client_hello(&initial_client_hello())?;
    let (send, recv, session_id, server_payload) =
        handshake_initiator_with_pubkey_and_payload(stream, server_pubkey, &client_payload).await?;
    let response = decode_server_response(&server_payload)?;
    match response {
        BootstrapServerResponse::Accept {
            selected_version,
            response,
        } => {
            if selected_version != BOOTSTRAP_VERSION {
                return Err(io::Error::other(format!(
                    "relay selected unsupported bootstrap version: {selected_version}"
                )));
            }
            let accept = decode_v1_server_accept(response)?;
            if accept != initial_server_accept_v1() {
                return Err(io::Error::other(
                    "relay bootstrap accept did not match the hardcoded expected v1 response",
                ));
            }
        }
        BootstrapServerResponse::Reject { reason, .. } => {
            return Err(io::Error::new(
                io::ErrorKind::ConnectionRefused,
                format!("relay bootstrap rejected session: {reason}"),
            ));
        }
    }
    Ok((send, recv, session_id))
}

pub async fn handshake_initiator_with_pubkey_and_payload<T: AsyncRead + AsyncWrite + Unpin>(
    stream: &mut T,
    server_pubkey: [u8; 33],
    payload: &[u8],
) -> io::Result<(
    CipherState<ChaCha20Poly1305>,
    CipherState<ChaCha20Poly1305>,
    [u8; 32],
    Vec<u8>,
)> {
    let rs = SecpPublicKeyBytes::from_slice(&server_pubkey);
    let mut hs = SecpHandshake::new(
        patterns::noise_nk(),
        true,
        PROLOGUE,
        None,
        None,
        Some(rs),
        None,
    );
    let msg1 = hs
        .write_message_vec(payload)
        .map_err(|_| io::Error::other("initiator failed to write first handshake message"))?;
    write_handshake_msg(stream, &msg1).await?;

    let msg2 = read_handshake_msg(stream).await?;
    let server_payload = hs
        .read_message_vec(&msg2)
        .map_err(|_| io::Error::other("initiator failed to read second handshake message"))?;

    let mut session_id = [0u8; 32];
    session_id.copy_from_slice(hs.get_hash());
    let (send, recv) = hs.get_ciphers();
    Ok((send, recv, session_id, server_payload))
}

pub async fn handshake_responder<T: AsyncRead + AsyncWrite + Unpin>(
    stream: &mut T,
    server_key: &SecpTransportKeypair,
) -> io::Result<(
    CipherState<ChaCha20Poly1305>,
    CipherState<ChaCha20Poly1305>,
    [u8; 32],
)> {
    handshake_responder_with_secret_key_bytes(stream, server_key.normalized_secret_bytes()).await
}

pub async fn handshake_responder_with_secret_key_bytes<T: AsyncRead + AsyncWrite + Unpin>(
    stream: &mut T,
    server_key: [u8; 32],
) -> io::Result<(
    CipherState<ChaCha20Poly1305>,
    CipherState<ChaCha20Poly1305>,
    [u8; 32],
)> {
    handshake_responder_with_secret_key_bytes_and_payload_decider(
        stream,
        server_key,
        |client_payload| {
            let (response, accepted) = match decode_client_hello(&client_payload) {
                Ok(client_hello) => match highest_supported_version(&client_hello) {
                    Some(BOOTSTRAP_VERSION) => match decode_v1_client_hello(&client_hello)
                        .and_then(|hello| validate_v1_client_hello(&hello).map(|_| hello))
                    {
                        Ok(_) => (initial_server_accept(), true),
                        Err(reason) => (
                            BootstrapServerResponse::Reject {
                                supported_versions: supported_bootstrap_versions(),
                                reason,
                            },
                            false,
                        ),
                    },
                    Some(other) => (
                        BootstrapServerResponse::Reject {
                            supported_versions: supported_bootstrap_versions(),
                            reason: format!("selected bootstrap version is unsupported: {other}"),
                        },
                        false,
                    ),
                    None => (
                        BootstrapServerResponse::Reject {
                            supported_versions: supported_bootstrap_versions(),
                            reason: "no supported bootstrap version".to_string(),
                        },
                        false,
                    ),
                },
                Err(err) => (
                    BootstrapServerResponse::Reject {
                        supported_versions: supported_bootstrap_versions(),
                        reason: format!("invalid client bootstrap: {err}"),
                    },
                    false,
                ),
            };
            encode_server_response(&response).map(|payload| (payload, accepted))
        },
    )
    .await
}

pub async fn handshake_responder_with_secret_key_bytes_and_payload_decider<
    T: AsyncRead + AsyncWrite + Unpin,
    F,
>(
    stream: &mut T,
    server_key: [u8; 32],
    decide_payload: F,
) -> io::Result<(
    CipherState<ChaCha20Poly1305>,
    CipherState<ChaCha20Poly1305>,
    [u8; 32],
)>
where
    F: FnOnce(Vec<u8>) -> io::Result<(Vec<u8>, bool)>,
{
    let mut hs = SecpHandshake::new(
        patterns::noise_nk(),
        false,
        PROLOGUE,
        Some(server_key),
        None,
        None,
        None,
    );
    let msg1 = read_handshake_msg(stream).await?;
    let client_payload = hs
        .read_message_vec(&msg1)
        .map_err(|_| io::Error::other("responder failed to read first handshake message"))?;
    let (response_payload, accepted) = decide_payload(client_payload)?;
    let msg2 = hs
        .write_message_vec(&response_payload)
        .map_err(|_| io::Error::other("responder failed to write second handshake message"))?;
    write_handshake_msg(stream, &msg2).await?;

    if !accepted {
        return Err(io::Error::new(
            io::ErrorKind::ConnectionRefused,
            "client bootstrap was rejected",
        ));
    }

    let mut session_id = [0u8; 32];
    session_id.copy_from_slice(hs.get_hash());
    let (initiator_to_responder, responder_to_initiator) = hs.get_ciphers();
    Ok((responder_to_initiator, initiator_to_responder, session_id))
}

#[cfg(test)]
mod tests {
    use super::*;
    use k256::schnorr::SigningKey;
    use std::pin::Pin;
    use std::task::{Context, Poll};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    struct LimitedWrite<T> {
        inner: T,
        max_write: usize,
    }

    impl<T> LimitedWrite<T> {
        fn new(inner: T, max_write: usize) -> Self {
            Self { inner, max_write }
        }
    }

    impl<T: AsyncRead + Unpin> AsyncRead for LimitedWrite<T> {
        fn poll_read(
            mut self: Pin<&mut Self>,
            cx: &mut Context<'_>,
            buf: &mut ReadBuf<'_>,
        ) -> Poll<io::Result<()>> {
            Pin::new(&mut self.inner).poll_read(cx, buf)
        }
    }

    impl<T: AsyncWrite + Unpin> AsyncWrite for LimitedWrite<T> {
        fn poll_write(
            mut self: Pin<&mut Self>,
            cx: &mut Context<'_>,
            buf: &[u8],
        ) -> Poll<io::Result<usize>> {
            let limit = std::cmp::min(self.max_write, buf.len());
            Pin::new(&mut self.inner).poll_write(cx, &buf[..limit])
        }

        fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            Pin::new(&mut self.inner).poll_flush(cx)
        }

        fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            Pin::new(&mut self.inner).poll_shutdown(cx)
        }
    }

    #[tokio::test]
    async fn test_secp_noise_handshake_and_transport_roundtrip() {
        let server_key = SecpTransportKeypair::generate();
        let server_pubkey = server_key.pubkey();
        let (mut a, mut b) = tokio::io::duplex(1 << 20);
        let server_key_clone = server_key.clone();
        let responder = tokio::spawn(async move {
            let (send, recv, session_id) = handshake_responder(&mut b, &server_key_clone)
                .await
                .unwrap();
            SecpNoiseStream::new(b, send, recv, session_id, "test-secp-server")
        });
        let initiator = tokio::spawn(async move {
            let (send, recv, session_id) =
                handshake_initiator(&mut a, &server_pubkey).await.unwrap();
            SecpNoiseStream::new(a, send, recv, session_id, "test-secp-client")
        });

        let mut responder = responder.await.unwrap();
        let mut initiator = initiator.await.unwrap();

        let server = tokio::spawn(async move {
            let mut buf = [0u8; 64];
            let n = responder.read(&mut buf).await.unwrap();
            assert_eq!(&buf[..n], b"hello over secp noise");
            responder.write_all(b"hello back").await.unwrap();
            responder.flush().await.unwrap();
        });

        initiator.write_all(b"hello over secp noise").await.unwrap();
        initiator.flush().await.unwrap();
        let mut buf = [0u8; 64];
        let n = initiator.read(&mut buf).await.unwrap();
        assert_eq!(&buf[..n], b"hello back");
        server.await.unwrap();
    }

    #[tokio::test]
    async fn test_secp_noise_stream_handles_partial_writes() {
        let server_key = SecpTransportKeypair::generate();
        let server_pubkey = server_key.pubkey();
        let (mut a, mut b) = tokio::io::duplex(1 << 20);
        let server_key_clone = server_key.clone();

        let responder = tokio::spawn(async move {
            let (send, recv, session_id) = handshake_responder(&mut b, &server_key_clone)
                .await
                .unwrap();
            let limited = LimitedWrite::new(b, 3);
            SecpNoiseStream::new(limited, send, recv, session_id, "partial-write-server")
        });
        let initiator = tokio::spawn(async move {
            let (send, recv, session_id) =
                handshake_initiator(&mut a, &server_pubkey).await.unwrap();
            let limited = LimitedWrite::new(a, 3);
            SecpNoiseStream::new(limited, send, recv, session_id, "partial-write-client")
        });

        let mut responder = responder.await.unwrap();
        let mut initiator = initiator.await.unwrap();
        let payload = vec![0x5a; MAX_PLAINTEXT_LEN * 2 + 137];
        let expected = payload.clone();

        let server = tokio::spawn(async move {
            let mut received = vec![0u8; expected.len()];
            responder.read_exact(&mut received).await.unwrap();
            assert_eq!(received, expected);
        });

        initiator.write_all(&payload).await.unwrap();
        initiator.flush().await.unwrap();
        server.await.unwrap();
    }

    #[tokio::test]
    async fn test_secp_noise_shutdown_flushes_buffered_ciphertext() {
        let server_key = SecpTransportKeypair::generate();
        let server_pubkey = server_key.pubkey();
        let (mut a, mut b) = tokio::io::duplex(1 << 20);
        let server_key_clone = server_key.clone();

        let responder = tokio::spawn(async move {
            let (send, recv, session_id) = handshake_responder(&mut b, &server_key_clone)
                .await
                .unwrap();
            SecpNoiseStream::new(b, send, recv, session_id, "shutdown-server")
        });
        let initiator = tokio::spawn(async move {
            let (send, recv, session_id) =
                handshake_initiator(&mut a, &server_pubkey).await.unwrap();
            let limited = LimitedWrite::new(a, 1);
            SecpNoiseStream::new(limited, send, recv, session_id, "shutdown-client")
        });

        let mut responder = responder.await.unwrap();
        let mut initiator = initiator.await.unwrap();
        let payload = b"buffered shutdown payload".to_vec();
        let expected = payload.clone();

        let server = tokio::spawn(async move {
            let mut buf = vec![0u8; expected.len()];
            responder.read_exact(&mut buf).await.unwrap();
            assert_eq!(buf, expected);
        });

        initiator.write_all(&payload).await.unwrap();
        initiator.shutdown().await.unwrap();
        server.await.unwrap();
    }

    #[tokio::test]
    async fn test_secp_noise_handshake_with_odd_form_imported_secret() {
        let canonical = SecpTransportKeypair::generate();
        let odd_form_bytes: [u8; 32] =
            (-*SigningKey::from_bytes(&canonical.normalized_secret_bytes())
                .unwrap()
                .as_nonzero_scalar()
                .as_ref())
            .to_bytes()
            .into();
        let imported = SecpTransportKeypair::from_secret_bytes(&odd_form_bytes).unwrap();
        let server_pubkey = canonical.pubkey();
        let (mut a, mut b) = tokio::io::duplex(1 << 20);

        let responder =
            tokio::spawn(async move { handshake_responder(&mut b, &imported).await.unwrap() });
        let initiator =
            tokio::spawn(async move { handshake_initiator(&mut a, &server_pubkey).await.unwrap() });

        let (responder_send, responder_recv, responder_session_id) = responder.await.unwrap();
        let (initiator_send, initiator_recv, initiator_session_id) = initiator.await.unwrap();

        assert_eq!(canonical.pubkey(), server_pubkey);
        assert_eq!(responder_session_id, initiator_session_id);
        drop((
            responder_send,
            responder_recv,
            initiator_send,
            initiator_recv,
        ));
    }
}
