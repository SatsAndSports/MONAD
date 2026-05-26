use std::net::SocketAddr;
use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc, Once,
};

use anyhow::{anyhow, Context, Result};
use monad_quic::keygen;
use monad_secp256k1_identity::{
    transport_auth_digest, verify_digest, verifying_key_from_npub, TransportKeypair,
};
use quinn::Endpoint;
use rand_core::RngCore;
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::DigitallySignedStruct;
use tokio::io::AsyncWriteExt;

pub const AUTH_STREAM_KIND: u8 = 0x01;
pub const ECHO_STREAM_KIND: u8 = 0x02;
pub const STREAM_ERROR_UNKNOWN_KIND: u64 = 0x21;
pub const STREAM_ERROR_AUTH_REQUIRED: u64 = 0x22;
pub const STREAM_ERROR_BAD_AUTH: u64 = 0x23;
pub const EXPORTER_LABEL: &[u8] = b"monad-quic-npub-auth-v1";
pub const EXPORTER_LEN: usize = 32;

static CRYPTO_PROVIDER: Once = Once::new();

fn stream_error_code(code: u64) -> quinn::VarInt {
    quinn::VarInt::from_u64(code).expect("valid QUIC application error code")
}

fn reject_stream(send: &mut quinn::SendStream, recv: &mut quinn::RecvStream, code: u64) {
    let code = stream_error_code(code);
    let _ = recv.stop(code);
    let _ = send.reset(code);
}

fn ensure_crypto_provider() {
    CRYPTO_PROVIDER.call_once(|| {
        let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
    });
}

#[derive(Debug)]
struct PermissiveVerifier;

impl ServerCertVerifier for PermissiveVerifier {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> std::result::Result<ServerCertVerified, rustls::Error> {
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> std::result::Result<HandshakeSignatureValid, rustls::Error> {
        Err(rustls::Error::General(
            "TLS 1.2 is not supported for QUIC".into(),
        ))
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> std::result::Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(
            message,
            cert,
            dss,
            &rustls::crypto::ring::default_provider().signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        rustls::crypto::ring::default_provider()
            .signature_verification_algorithms
            .supported_schemes()
    }
}

pub fn build_permissive_client_config() -> Result<quinn::ClientConfig> {
    ensure_crypto_provider();
    let mut tls_config = rustls::ClientConfig::builder()
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(PermissiveVerifier))
        .with_no_client_auth();
    tls_config.alpn_protocols = vec![b"monad-relay/0".to_vec()];
    tls_config.enable_early_data = false;

    let mut client_config = quinn::ClientConfig::new(Arc::new(
        quinn::crypto::rustls::QuicClientConfig::try_from(tls_config)?,
    ));
    let mut transport = quinn::TransportConfig::default();
    transport.keep_alive_interval(Some(std::time::Duration::from_secs(15)));
    client_config.transport_config(Arc::new(transport));
    Ok(client_config)
}

fn export_binding(conn: &quinn::Connection) -> Result<[u8; EXPORTER_LEN]> {
    let mut exporter = [0u8; EXPORTER_LEN];
    conn.export_keying_material(&mut exporter, EXPORTER_LABEL, b"")
        .map_err(|e| anyhow!("failed to export QUIC keying material: {e:?}"))?;
    Ok(exporter)
}

pub async fn request_attestation_signature(
    conn: &quinn::Connection,
    challenge: [u8; 32],
) -> Result<[u8; 64]> {
    let (mut send, mut recv) = conn.open_bi().await.context("failed to open auth stream")?;
    send.write_all(&[AUTH_STREAM_KIND]).await?;
    send.write_all(&challenge).await?;
    send.flush().await?;

    let mut signature = [0u8; 64];
    recv.read_exact(&mut signature)
        .await
        .context("failed to read attestation signature")?;
    Ok(signature)
}

pub async fn authenticate_connection(conn: &quinn::Connection, expected_npub: &str) -> Result<()> {
    let mut challenge = [0u8; 32];
    rand_core::OsRng.fill_bytes(&mut challenge);
    let signature = request_attestation_signature(conn, challenge).await?;
    let exporter = export_binding(conn)?;
    let digest = transport_auth_digest(EXPORTER_LABEL, &challenge, &exporter);
    let verifying_key = verifying_key_from_npub(expected_npub)?;
    verify_digest(&verifying_key, &digest, &signature)
        .map_err(|e| anyhow!("npub attestation verification failed: {e}"))
}

pub async fn open_echo_stream(conn: &quinn::Connection, payload: &[u8]) -> Result<Vec<u8>> {
    let (mut send, mut recv) = conn.open_bi().await.context("failed to open echo stream")?;
    send.write_all(&[ECHO_STREAM_KIND]).await?;
    send.write_all(payload).await?;
    send.finish()?;
    recv.read_to_end(payload.len() + 1)
        .await
        .context("failed to read echo")
}

async fn handle_auth_stream(
    conn: &quinn::Connection,
    transport_key: &TransportKeypair,
    authenticated: &AtomicBool,
    send: &mut quinn::SendStream,
    recv: &mut quinn::RecvStream,
) {
    let mut challenge = [0u8; 32];
    if recv.read_exact(&mut challenge).await.is_err() {
        reject_stream(send, recv, STREAM_ERROR_BAD_AUTH);
        return;
    }

    let exporter = match export_binding(conn) {
        Ok(bytes) => bytes,
        Err(_) => {
            reject_stream(send, recv, STREAM_ERROR_BAD_AUTH);
            return;
        }
    };
    let digest = transport_auth_digest(EXPORTER_LABEL, &challenge, &exporter);
    let signature = transport_key.sign_digest(&digest);
    if send.write_all(&signature).await.is_err() {
        return;
    }
    let _ = send.finish();
    authenticated.store(true, Ordering::Release);
}

async fn handle_echo_stream(
    authenticated: &AtomicBool,
    send: &mut quinn::SendStream,
    recv: &mut quinn::RecvStream,
) {
    if !authenticated.load(Ordering::Acquire) {
        reject_stream(send, recv, STREAM_ERROR_AUTH_REQUIRED);
        return;
    }

    let mut buf = vec![0u8; 64 * 1024];
    while let Ok(Some(n)) = recv.read(&mut buf).await {
        if send.write_all(&buf[..n]).await.is_err() {
            return;
        }
    }
    let _ = send.finish();
}

async fn handle_proto_stream(
    conn: &quinn::Connection,
    transport_key: &TransportKeypair,
    authenticated: &AtomicBool,
    mut send: quinn::SendStream,
    mut recv: quinn::RecvStream,
) {
    let mut kind = [0u8; 1];
    if recv.read_exact(&mut kind).await.is_err() {
        return;
    }

    match kind[0] {
        AUTH_STREAM_KIND => {
            handle_auth_stream(conn, transport_key, authenticated, &mut send, &mut recv).await;
        }
        ECHO_STREAM_KIND => {
            handle_echo_stream(authenticated, &mut send, &mut recv).await;
        }
        _ => {
            reject_stream(&mut send, &mut recv, STREAM_ERROR_UNKNOWN_KIND);
        }
    }
}

async fn handle_connection(conn: quinn::Connection, transport_key: Arc<TransportKeypair>) {
    let authenticated = Arc::new(AtomicBool::new(false));

    while let Ok((send, recv)) = conn.accept_bi().await {
        let transport_key = transport_key.clone();
        let authenticated = authenticated.clone();
        let conn = conn.clone();
        tokio::spawn(async move {
            handle_proto_stream(&conn, &transport_key, &authenticated, send, recv).await;
        });
    }
}

pub async fn start_server() -> Result<(Endpoint, SocketAddr, String)> {
    ensure_crypto_provider();
    let transport_key = Arc::new(TransportKeypair::generate());
    let npub = transport_key.npub();
    let km = keygen::generate()?;
    let server_config = monad_quic::server::build_server_config(&km.cert_pem, &km.key_pem)?;
    let endpoint = Endpoint::server(server_config, "127.0.0.1:0".parse()?)?;
    let addr = endpoint.local_addr()?;

    let ep = endpoint.clone();
    tokio::spawn(async move {
        while let Some(incoming) = ep.accept().await {
            let transport_key = transport_key.clone();
            tokio::spawn(async move {
                let conn = match incoming.await {
                    Ok(conn) => conn,
                    Err(_) => return,
                };
                handle_connection(conn, transport_key).await;
            });
        }
    });

    Ok((endpoint, addr, npub))
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::time::{timeout, Duration};

    async fn connect(addr: SocketAddr) -> quinn::Connection {
        let client_config = build_permissive_client_config().unwrap();
        let mut endpoint = Endpoint::client("0.0.0.0:0".parse().unwrap()).unwrap();
        endpoint.set_default_client_config(client_config);
        endpoint
            .connect(addr, "monad-relay")
            .unwrap()
            .await
            .unwrap()
    }

    #[tokio::test]
    async fn test_quic_npub_auth_succeeds_and_many_streams_work() {
        let (_server, addr, npub) = start_server().await.unwrap();
        let conn = connect(addr).await;

        authenticate_connection(&conn, &npub).await.unwrap();

        let mut handles = Vec::new();
        for i in 0..32 {
            let conn = conn.clone();
            handles.push(tokio::spawn(async move {
                let payload = format!("authenticated stream {i}").into_bytes();
                let echoed = open_echo_stream(&conn, &payload).await.unwrap();
                assert_eq!(echoed, payload);
            }));
        }

        for handle in handles {
            handle.await.unwrap();
        }
    }

    #[tokio::test]
    async fn test_quic_npub_auth_wrong_key_fails() {
        let (_server, addr, _npub) = start_server().await.unwrap();
        let wrong_npub = TransportKeypair::generate().npub();
        let conn = connect(addr).await;

        assert!(authenticate_connection(&conn, &wrong_npub).await.is_err());
    }

    #[tokio::test]
    async fn test_echo_stream_before_auth_is_rejected() {
        let (_server, addr, _npub) = start_server().await.unwrap();
        let conn = connect(addr).await;

        let result = timeout(
            Duration::from_secs(1),
            open_echo_stream(&conn, b"unauthenticated"),
        )
        .await;
        assert!(
            result.is_ok(),
            "server did not reject unauthenticated echo promptly"
        );
        assert!(
            result.unwrap().is_err(),
            "echo unexpectedly succeeded before auth"
        );
    }

    #[tokio::test]
    async fn test_attestation_signature_is_bound_to_connection_exporter() {
        let (_server, addr, npub) = start_server().await.unwrap();
        let conn_a = connect(addr).await;
        let conn_b = connect(addr).await;
        let challenge = [42u8; 32];

        let signature = request_attestation_signature(&conn_a, challenge)
            .await
            .unwrap();
        let verifying_key = verifying_key_from_npub(&npub).unwrap();

        let exporter_a = export_binding(&conn_a).unwrap();
        let digest_a = transport_auth_digest(EXPORTER_LABEL, &challenge, &exporter_a);
        verify_digest(&verifying_key, &digest_a, &signature).unwrap();

        let exporter_b = export_binding(&conn_b).unwrap();
        let digest_b = transport_auth_digest(EXPORTER_LABEL, &challenge, &exporter_b);
        assert!(verify_digest(&verifying_key, &digest_b, &signature).is_err());
    }
}
