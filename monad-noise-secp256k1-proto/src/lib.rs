use bytes::{Buf, BytesMut};
use k256::elliptic_curve::sec1::ToEncodedPoint;
use k256::schnorr::SigningKey;
use k256::{ecdh, PublicKey};
use monad_secp256k1_identity::{compressed_public_key_bytes_from_npub, TransportKeypair};
use noise_protocol::patterns;
use noise_protocol::{CipherState, HandshakeState, U8Array};
use noise_rust_crypto::{Blake2s, ChaCha20Poly1305};
use std::io;
use std::pin::Pin;
use std::task::{Context, Poll};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};

const PROLOGUE: &[u8] = b"monad-noise-secp256k1-proto-v1";
const MAX_MSG_LEN: usize = 65535;
const LEN_PREFIX_SIZE: usize = 2;

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
        TransportKeypair::generate().secret_bytes()
    }

    fn pubkey(key: &Self::Key) -> Self::Pubkey {
        let signing_key = SigningKey::from_bytes(key).expect("valid secp256k1 secret key bytes");
        let public_key = PublicKey::from(*signing_key.verifying_key());
        let encoded = public_key.to_encoded_point(true);
        SecpPublicKeyBytes::from_slice(encoded.as_bytes())
    }

    fn dh(key: &Self::Key, pubkey: &Self::Pubkey) -> Result<Self::Output, ()> {
        let signing_key = SigningKey::from_bytes(key).map_err(|_| ())?;
        let public_key = PublicKey::from_sec1_bytes(pubkey.as_slice()).map_err(|_| ())?;
        let shared = ecdh::diffie_hellman(signing_key.as_nonzero_scalar(), public_key.as_affine());
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
}

impl<T> SecpNoiseStream<T> {
    pub fn new(
        inner: T,
        send_cipher: CipherState<ChaCha20Poly1305>,
        recv_cipher: CipherState<ChaCha20Poly1305>,
        session_id: [u8; 32],
    ) -> Self {
        Self {
            inner,
            send_cipher,
            recv_cipher,
            session_id,
            read_plaintext: BytesMut::new(),
            read_ciphertext: BytesMut::new(),
            read_expected_len: None,
        }
    }

    pub fn session_id(&self) -> &[u8; 32] {
        &self.session_id
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
                                return Poll::Ready(Ok(()));
                            }
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
        if buf.is_empty() {
            return Poll::Ready(Ok(0));
        }
        let plaintext_len = std::cmp::min(buf.len(), MAX_MSG_LEN - 16);
        let encrypted = me.send_cipher.encrypt_vec(&buf[..plaintext_len]);
        let len = encrypted.len() as u16;
        let mut frame = Vec::with_capacity(LEN_PREFIX_SIZE + encrypted.len());
        frame.extend_from_slice(&len.to_be_bytes());
        frame.extend_from_slice(&encrypted);

        match Pin::new(&mut me.inner).poll_write(cx, &frame) {
            Poll::Ready(Ok(n)) => {
                if n == frame.len() {
                    Poll::Ready(Ok(plaintext_len))
                } else {
                    Poll::Ready(Err(io::Error::new(
                        io::ErrorKind::WriteZero,
                        "partial SecpNoise frame write",
                    )))
                }
            }
            Poll::Ready(Err(e)) => Poll::Ready(Err(e)),
            Poll::Pending => Poll::Pending,
        }
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
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
    server_npub: &str,
) -> io::Result<(
    CipherState<ChaCha20Poly1305>,
    CipherState<ChaCha20Poly1305>,
    [u8; 32],
)> {
    let rs = SecpPublicKeyBytes::from_slice(
        &compressed_public_key_bytes_from_npub(server_npub).map_err(|e| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("invalid server npub: {e}"),
            )
        })?,
    );
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
        .write_message_vec(&[])
        .map_err(|_| io::Error::other("initiator failed to write first handshake message"))?;
    write_handshake_msg(stream, &msg1).await?;

    let msg2 = read_handshake_msg(stream).await?;
    hs.read_message_vec(&msg2)
        .map_err(|_| io::Error::other("initiator failed to read second handshake message"))?;

    let mut session_id = [0u8; 32];
    session_id.copy_from_slice(hs.get_hash());
    let (send, recv) = hs.get_ciphers();
    Ok((send, recv, session_id))
}

pub async fn handshake_responder<T: AsyncRead + AsyncWrite + Unpin>(
    stream: &mut T,
    server_key: &TransportKeypair,
) -> io::Result<(
    CipherState<ChaCha20Poly1305>,
    CipherState<ChaCha20Poly1305>,
    [u8; 32],
)> {
    let mut hs = SecpHandshake::new(
        patterns::noise_nk(),
        false,
        PROLOGUE,
        Some(server_key.secret_bytes()),
        None,
        None,
        None,
    );
    let msg1 = read_handshake_msg(stream).await?;
    hs.read_message_vec(&msg1)
        .map_err(|_| io::Error::other("responder failed to read first handshake message"))?;
    let msg2 = hs
        .write_message_vec(&[])
        .map_err(|_| io::Error::other("responder failed to write second handshake message"))?;
    write_handshake_msg(stream, &msg2).await?;

    let mut session_id = [0u8; 32];
    session_id.copy_from_slice(hs.get_hash());
    let (initiator_to_responder, responder_to_initiator) = hs.get_ciphers();
    Ok((responder_to_initiator, initiator_to_responder, session_id))
}

pub async fn secp_noise_stream_pair(
    server_key: &TransportKeypair,
) -> io::Result<(
    SecpNoiseStream<tokio::io::DuplexStream>,
    SecpNoiseStream<tokio::io::DuplexStream>,
)> {
    let (mut a, mut b) = tokio::io::duplex(1 << 20);
    let npub = server_key.npub();
    let server = server_key.clone();

    let initiator = tokio::spawn(async move {
        let (send, recv, session_id) = handshake_initiator(&mut a, &npub).await?;
        Ok::<_, io::Error>(SecpNoiseStream::new(a, send, recv, session_id))
    });
    let responder = tokio::spawn(async move {
        let (send, recv, session_id) = handshake_responder(&mut b, &server).await?;
        Ok::<_, io::Error>(SecpNoiseStream::new(b, send, recv, session_id))
    });

    Ok((initiator.await.unwrap()?, responder.await.unwrap()?))
}

#[cfg(test)]
mod tests {
    use super::*;
    use bytes::Bytes;
    use h2::{client, server};
    use http::{Method, Request, Response, StatusCode};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::time::{timeout, Duration};

    #[tokio::test]
    async fn test_secp_noise_handshake_and_transport_roundtrip() {
        let server_key = TransportKeypair::generate();
        let (mut initiator, mut responder) = secp_noise_stream_pair(&server_key).await.unwrap();

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
    async fn test_secp_noise_wrong_npub_fails() {
        let server_key = TransportKeypair::generate();
        let wrong_npub = TransportKeypair::generate().npub();
        let (mut a, mut b) = tokio::io::duplex(1 << 20);
        let server = server_key.clone();

        let initiator = tokio::spawn(async move { handshake_initiator(&mut a, &wrong_npub).await });
        let responder = tokio::spawn(async move { handshake_responder(&mut b, &server).await });

        let initiator_result = initiator.await.unwrap();
        let responder_result = responder.await.unwrap();
        assert!(initiator_result.is_err() || responder_result.is_err());
    }

    #[tokio::test]
    async fn test_h2_over_secp_noise_supports_control_and_connect_like_stream() {
        let server_key = TransportKeypair::generate();
        let (initiator, responder) = secp_noise_stream_pair(&server_key).await.unwrap();

        let server_task = tokio::spawn(async move {
            let mut conn = server::handshake(responder).await.unwrap();
            while let Some(result) = conn.accept().await {
                let (request, mut respond) = result.unwrap();
                match (request.method().clone(), request.uri().path()) {
                    (Method::POST, "/control") => {
                        let resp = Response::builder().status(StatusCode::OK).body(()).unwrap();
                        let mut send = respond.send_response(resp, false).unwrap();
                        send.send_data(Bytes::from_static(b"pong"), true).unwrap();
                    }
                    (Method::POST, "/echo") => {
                        let (_, mut recv) = request.into_parts();
                        let mut body = Vec::new();
                        while let Some(chunk) = recv.data().await {
                            body.extend_from_slice(&chunk.unwrap());
                        }
                        let resp = Response::builder().status(StatusCode::OK).body(()).unwrap();
                        let mut send = respond.send_response(resp, false).unwrap();
                        send.send_data(Bytes::from(body), true).unwrap();
                    }
                    _ => {
                        let resp = Response::builder()
                            .status(StatusCode::NOT_FOUND)
                            .body(())
                            .unwrap();
                        let _ = respond.send_response(resp, true);
                    }
                }
            }
        });

        let (mut client, h2_conn) = client::handshake(initiator).await.unwrap();
        let client_driver = tokio::spawn(async move {
            h2_conn.await.unwrap();
        });

        let control_request = Request::builder()
            .method(Method::POST)
            .uri("http://monad/control")
            .body(())
            .unwrap();
        let (control_response_future, _control_send) =
            client.send_request(control_request, true).unwrap();
        let control_response = timeout(Duration::from_secs(5), control_response_future)
            .await
            .unwrap()
            .unwrap();
        let mut control_recv = control_response.into_body();
        let mut control_buf = Vec::new();
        while let Some(chunk) = timeout(Duration::from_secs(5), control_recv.data())
            .await
            .unwrap()
        {
            control_buf.extend_from_slice(&chunk.unwrap());
        }
        assert_eq!(control_buf, b"pong");

        let connect_request = Request::builder()
            .method(Method::POST)
            .uri("/echo")
            .body(())
            .unwrap();
        let (connect_response_future, mut connect_send) =
            client.send_request(connect_request, false).unwrap();
        connect_send
            .send_data(Bytes::from_static(b"hello h2 over secp noise"), true)
            .unwrap();
        let connect_response = timeout(Duration::from_secs(5), connect_response_future)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(connect_response.status(), StatusCode::OK);

        let mut connect_recv = connect_response.into_body();
        let mut echoed = Vec::new();
        while let Some(chunk) = timeout(Duration::from_secs(5), connect_recv.data())
            .await
            .unwrap()
        {
            echoed.extend_from_slice(&chunk.unwrap());
        }
        assert_eq!(echoed, b"hello h2 over secp noise");

        drop(client);
        client_driver.abort();
        server_task.abort();
    }
}
