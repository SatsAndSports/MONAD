use std::net::SocketAddr;
use std::sync::{Arc, Once};

use anyhow::{Context, Result};
use quinn::Endpoint;
use tracing::{error, info};

static CRYPTO_PROVIDER: Once = Once::new();

fn ensure_crypto_provider() {
    CRYPTO_PROVIDER.call_once(|| {
        let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
    });
}

/// Run the QUIC echo server.
///
/// Accepts connections, accepts bidirectional streams, and echoes
/// all received data back on the same stream.
pub async fn run_server(listen: SocketAddr, cert_pem: &str, key_pem: &str) -> Result<()> {
    let server_config = build_server_config(cert_pem, key_pem)?;

    let endpoint = Endpoint::server(server_config, listen)?;
    info!(%listen, "QUIC server listening");

    while let Some(incoming) = endpoint.accept().await {
        let remote = incoming.remote_address();
        info!(%remote, "incoming connection");
        tokio::spawn(async move {
            if let Err(e) = handle_connection(incoming).await {
                error!(%remote, error = %e, "connection failed");
            }
        });
    }

    Ok(())
}

async fn handle_connection(incoming: quinn::Incoming) -> Result<()> {
    let conn = incoming.await?;
    let remote = conn.remote_address();
    info!(%remote, "connection established");

    loop {
        let stream = conn.accept_bi().await;
        match stream {
            Ok((send, recv)) => {
                let stream_id = send.id();
                info!(%remote, ?stream_id, "accepted bidirectional stream");
                tokio::spawn(async move {
                    if let Err(e) = handle_stream(send, recv).await {
                        error!(?stream_id, error = %e, "stream failed");
                    }
                });
            }
            Err(quinn::ConnectionError::ApplicationClosed(_)) => {
                info!(%remote, "connection closed by peer");
                break;
            }
            Err(e) => {
                error!(%remote, error = %e, "failed to accept stream");
                break;
            }
        }
    }

    Ok(())
}

async fn handle_stream(mut send: quinn::SendStream, mut recv: quinn::RecvStream) -> Result<()> {
    let stream_id = send.id();

    // Read all data and echo it back
    let mut total = 0u64;
    let mut buf = vec![0u8; 64 * 1024];
    while let Some(n) = recv.read(&mut buf).await? {
        send.write_all(&buf[..n]).await?;
        total += n as u64;
    }

    send.finish()?;
    info!(?stream_id, total, "stream echo complete");
    Ok(())
}

pub fn build_server_config(cert_pem: &str, key_pem: &str) -> Result<quinn::ServerConfig> {
    ensure_crypto_provider();
    // Parse certificate chain
    let certs: Vec<rustls::pki_types::CertificateDer<'static>> =
        rustls_pemfile::certs(&mut cert_pem.as_bytes())
            .collect::<std::result::Result<Vec<_>, _>>()
            .context("failed to parse certificate PEM")?;

    if certs.is_empty() {
        anyhow::bail!("no certificates found in PEM");
    }

    // Parse private key
    let key = rustls_pemfile::private_key(&mut key_pem.as_bytes())
        .context("failed to parse private key PEM")?
        .context("no private key found in PEM")?;

    // Build rustls server config — no client auth (one-way authentication)
    let mut tls_config = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(certs, key)?;

    // Disable 0-RTT per architecture doc constraints
    tls_config.max_early_data_size = 0;

    // ALPN protocol — use a custom identifier for MONAD relay links
    tls_config.alpn_protocols = vec![b"monad-relay/0".to_vec()];

    let mut server_config = quinn::ServerConfig::with_crypto(Arc::new(
        quinn::crypto::rustls::QuicServerConfig::try_from(tls_config)?,
    ));

    // Transport configuration
    let mut transport = quinn::TransportConfig::default();
    transport.max_concurrent_bidi_streams(2048u32.into());
    transport.max_concurrent_uni_streams(0u32.into()); // only bidi for now
                                                       // Increase flow-control windows to support large payloads per stream
    transport.stream_receive_window(8_000_000u32.into());
    transport.receive_window(16_000_000u32.into());
    server_config.transport_config(Arc::new(transport));

    Ok(server_config)
}
