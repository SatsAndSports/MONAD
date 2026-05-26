use crate::auth::authenticate_connection;
use monad_common::secp_identity::Secp256k1Pubkey;
use std::net::SocketAddr;
use std::sync::{Arc, Once};

use anyhow::{Context, Result};
use quinn::Endpoint;
use rand::RngCore;
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::DigitallySignedStruct;
use tracing::{error, info};

static CRYPTO_PROVIDER: Once = Once::new();

fn ensure_crypto_provider() {
    CRYPTO_PROVIDER.call_once(|| {
        let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
    });
}

/// Run the QUIC client.
///
/// Connects to the server, verifying that its certificate matches the
/// pinned public key. Opens `streams` bidirectional streams and sends
/// `bytes_per_stream` random bytes on each, reading them back and
/// verifying the echo.
pub async fn run_client(
    connect: SocketAddr,
    pin_hex: &str,
    streams: usize,
    bytes_per_stream: usize,
) -> Result<()> {
    let pinned_spki = hex::decode(pin_hex).context("invalid hex for pinned public key")?;

    let client_config = build_client_config(pinned_spki)?;

    let mut endpoint = Endpoint::client("0.0.0.0:0".parse()?)?;
    endpoint.set_default_client_config(client_config);

    info!(%connect, "connecting to QUIC server");

    // Use "monad-relay" as the server name — matches the self-signed cert's SAN
    let conn = endpoint
        .connect(connect, "monad-relay")?
        .await
        .context("failed to connect")?;

    info!(
        remote = %conn.remote_address(),
        "connection established, opening {streams} streams"
    );

    let mut handles = Vec::with_capacity(streams);
    for i in 0..streams {
        let conn = conn.clone();
        let handle = tokio::spawn(async move { run_stream(conn, i, bytes_per_stream).await });
        handles.push(handle);
    }

    let mut ok_count = 0usize;
    let mut err_count = 0usize;
    for handle in handles {
        match handle.await? {
            Ok(()) => ok_count += 1,
            Err(e) => {
                error!(error = %e, "stream failed");
                err_count += 1;
            }
        }
    }

    info!(ok_count, err_count, "all streams finished");

    // Gracefully close the connection
    conn.close(0u32.into(), b"done");
    endpoint.wait_idle().await;

    if err_count > 0 {
        anyhow::bail!("{err_count} stream(s) failed");
    }

    Ok(())
}

async fn run_stream(conn: quinn::Connection, index: usize, bytes_per_stream: usize) -> Result<()> {
    let (mut send, mut recv) = conn.open_bi().await.context("failed to open stream")?;
    let stream_id = send.id();
    info!(
        index,
        ?stream_id,
        bytes = bytes_per_stream,
        "stream opened, sending data"
    );

    // Generate random payload
    let mut payload = vec![0u8; bytes_per_stream];
    rand::rng().fill_bytes(&mut payload);

    // Send all data, then finish the send side
    send.write_all(&payload).await?;
    send.finish()?;

    // Read the echo back
    let echoed = recv
        .read_to_end(bytes_per_stream + 1)
        .await
        .context("failed to read echo")?;

    if echoed.len() != payload.len() {
        anyhow::bail!(
            "stream {index}: echo length mismatch: sent {} but received {}",
            payload.len(),
            echoed.len()
        );
    }

    if echoed != payload {
        anyhow::bail!("stream {index}: echo data mismatch");
    }

    info!(
        index,
        ?stream_id,
        bytes = bytes_per_stream,
        "stream echo verified OK"
    );
    Ok(())
}

pub fn build_client_config(pinned_spki: Vec<u8>) -> Result<quinn::ClientConfig> {
    build_client_config_for_auth(ClientAuthMode::PinnedSpki(pinned_spki))
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ClientAuthMode {
    PinnedSpki(Vec<u8>),
    Secp256k1(Secp256k1Pubkey),
}

pub fn build_client_config_for_auth(auth: ClientAuthMode) -> Result<quinn::ClientConfig> {
    ensure_crypto_provider();
    let verifier: Arc<dyn ServerCertVerifier> = match auth {
        ClientAuthMode::PinnedSpki(pinned_spki) => Arc::new(PinnedKeyVerifier {
            pinned_spki: pinned_spki.into(),
        }),
        ClientAuthMode::Secp256k1(_) => Arc::new(PermissiveVerifier),
    };

    let mut tls_config = rustls::ClientConfig::builder()
        .dangerous()
        .with_custom_certificate_verifier(verifier)
        .with_no_client_auth();

    // Match ALPN
    tls_config.alpn_protocols = vec![b"monad-relay/0".to_vec()];

    // Disable 0-RTT
    tls_config.enable_early_data = false;

    let mut client_config = quinn::ClientConfig::new(Arc::new(
        quinn::crypto::rustls::QuicClientConfig::try_from(tls_config)?,
    ));

    // Transport configuration — match server-side flow-control windows
    let mut transport = quinn::TransportConfig::default();
    transport.stream_receive_window(8_000_000u32.into());
    transport.receive_window(16_000_000u32.into());
    // Send QUIC PINGs every 15 seconds to keep idle connections alive.
    // Without this, Quinn's default 30-second idle timeout would close
    // connections that have no active data flow.
    transport.keep_alive_interval(Some(std::time::Duration::from_secs(15)));
    client_config.transport_config(Arc::new(transport));

    Ok(client_config)
}

pub async fn connect_with_auth(
    endpoint: &Endpoint,
    connect: SocketAddr,
    auth: ClientAuthMode,
) -> Result<quinn::Connection> {
    let conn = endpoint
        .connect(connect, "monad-relay")?
        .await
        .context("failed to connect")?;

    if let ClientAuthMode::Secp256k1(pubkey) = auth {
        authenticate_connection(&conn, &pubkey).await?;
    }

    Ok(conn)
}

/// Custom TLS certificate verifier that checks the server's certificate
/// contains the expected pinned SubjectPublicKeyInfo (SPKI) DER bytes.
///
/// This provides server authentication without requiring a CA trust chain.
/// The client only needs to know the server's public key in advance.
#[derive(Debug)]
struct PinnedKeyVerifier {
    pinned_spki: Arc<[u8]>,
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

impl ServerCertVerifier for PinnedKeyVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> std::result::Result<ServerCertVerified, rustls::Error> {
        // Parse the end-entity certificate to extract its SPKI
        let cert = rustls::pki_types::CertificateDer::from(end_entity.to_vec());

        // Use webpki to parse and extract the SPKI
        // For simplicity, we do a raw DER parse to find the SPKI field.
        // The certificate DER structure is:
        //   SEQUENCE { tbsCertificate, signatureAlgorithm, signatureValue }
        //   tbsCertificate = SEQUENCE { version, serialNumber, signature,
        //                               issuer, validity, subject,
        //                               subjectPublicKeyInfo, ... }
        // We extract subjectPublicKeyInfo directly.
        let spki = extract_spki_from_cert_der(cert.as_ref()).map_err(|e| {
            rustls::Error::General(format!("failed to extract SPKI from certificate: {e}"))
        })?;

        if spki == self.pinned_spki.as_ref() {
            Ok(ServerCertVerified::assertion())
        } else {
            Err(rustls::Error::General(format!(
                "server public key does not match pinned key: got {}, expected {}",
                hex::encode(spki),
                hex::encode(self.pinned_spki.as_ref()),
            )))
        }
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> std::result::Result<HandshakeSignatureValid, rustls::Error> {
        // QUIC requires TLS 1.3, so this should never be called
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
        // Delegate to the default webpki signature verification
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

/// Extract the SubjectPublicKeyInfo (SPKI) DER bytes from a DER-encoded
/// X.509 certificate.
///
/// This does minimal ASN.1 DER parsing — just enough to find the 7th
/// field in the TBSCertificate SEQUENCE, which is the SPKI.
fn extract_spki_from_cert_der(cert_der: &[u8]) -> Result<Vec<u8>> {
    let mut reader = DerReader::new(cert_der);

    // Outer SEQUENCE (Certificate)
    let cert_seq = reader.read_sequence()?;
    let mut cert_inner = DerReader::new(cert_seq);

    // TBSCertificate SEQUENCE
    let tbs = cert_inner.read_sequence()?;
    let mut tbs_inner = DerReader::new(tbs);

    // Field 0: version [0] EXPLICIT (context tag 0xa0)
    tbs_inner.read_tlv()?; // version

    // Field 1: serialNumber
    tbs_inner.read_tlv()?;

    // Field 2: signature (AlgorithmIdentifier)
    tbs_inner.read_tlv()?;

    // Field 3: issuer
    tbs_inner.read_tlv()?;

    // Field 4: validity
    tbs_inner.read_tlv()?;

    // Field 5: subject
    tbs_inner.read_tlv()?;

    // Field 6: subjectPublicKeyInfo — this is what we want (full TLV)
    let spki = tbs_inner.read_tlv_raw()?;

    Ok(spki.to_vec())
}

/// Minimal DER reader for extracting TLV fields from ASN.1 DER data.
struct DerReader<'a> {
    data: &'a [u8],
    pos: usize,
}

impl<'a> DerReader<'a> {
    fn new(data: &'a [u8]) -> Self {
        Self { data, pos: 0 }
    }

    /// Read a SEQUENCE and return its contents.
    fn read_sequence(&mut self) -> Result<&'a [u8]> {
        let tag = self.read_byte()?;
        if tag != 0x30 {
            anyhow::bail!("expected SEQUENCE tag (0x30), got 0x{tag:02x}");
        }
        let len = self.read_length()?;
        let content = self.read_bytes(len)?;
        Ok(content)
    }

    /// Read a complete TLV (tag + length + value) and skip it,
    /// returning just the value.
    fn read_tlv(&mut self) -> Result<&'a [u8]> {
        let _tag = self.read_byte()?;
        let len = self.read_length()?;
        let value = self.read_bytes(len)?;
        Ok(value)
    }

    /// Read a complete TLV and return the raw bytes (tag + length + value).
    fn read_tlv_raw(&mut self) -> Result<&'a [u8]> {
        let start = self.pos;
        let _tag = self.read_byte()?;
        let len = self.read_length()?;
        let _value = self.read_bytes(len)?;
        Ok(&self.data[start..self.pos])
    }

    fn read_byte(&mut self) -> Result<u8> {
        if self.pos >= self.data.len() {
            anyhow::bail!("unexpected end of DER data at pos {}", self.pos);
        }
        let b = self.data[self.pos];
        self.pos += 1;
        Ok(b)
    }

    fn read_length(&mut self) -> Result<usize> {
        let first = self.read_byte()?;
        if first < 0x80 {
            Ok(first as usize)
        } else {
            let num_bytes = (first & 0x7f) as usize;
            if num_bytes == 0 || num_bytes > 4 {
                anyhow::bail!("unsupported DER length encoding: {num_bytes} bytes");
            }
            let mut len = 0usize;
            for _ in 0..num_bytes {
                len = (len << 8) | (self.read_byte()? as usize);
            }
            Ok(len)
        }
    }

    fn read_bytes(&mut self, len: usize) -> Result<&'a [u8]> {
        if self.pos + len > self.data.len() {
            anyhow::bail!(
                "DER data too short: need {} bytes at pos {}, have {}",
                len,
                self.pos,
                self.data.len() - self.pos
            );
        }
        let bytes = &self.data[self.pos..self.pos + len];
        self.pos += len;
        Ok(bytes)
    }
}
