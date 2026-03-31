//! Establishes a connection to the PaidTor server: TCP -> Noise NK handshake -> H2 client.

use h2::client;
use paidtor_common::noise::{self, NoiseStream};
use std::io;
use tokio::net::TcpStream;
use tracing::info;

/// An established connection to a PaidTor server, ready to open H2 streams.
pub struct ServerConnection {
    /// The H2 client send handle — use this to open new streams (CONNECT, etc.)
    pub h2_client: client::SendRequest<bytes::Bytes>,
}

/// Connect to a PaidTor server, perform Noise handshake, and establish an H2 connection.
///
/// Returns a `ServerConnection` and spawns a background task to drive the H2 connection.
pub async fn connect(
    server_addr: &str,
    server_pubkey: &[u8],
) -> io::Result<ServerConnection> {
    // TCP connect
    info!("connecting to {server_addr}");
    let mut tcp_stream = TcpStream::connect(server_addr).await?;
    info!("TCP connected");

    // Noise NK handshake (client is initiator)
    let transport = noise::handshake_initiator(&mut tcp_stream, server_pubkey).await?;
    info!("Noise handshake complete");

    let noise_stream = NoiseStream::new(tcp_stream, transport);

    // H2 client handshake
    let (h2_client, h2_conn) = client::handshake(noise_stream)
        .await
        .map_err(|e| io::Error::new(io::ErrorKind::Other, format!("h2 handshake error: {e}")))?;
    info!("H2 connection established");

    // Spawn background task to drive the H2 connection
    tokio::spawn(async move {
        if let Err(e) = h2_conn.await {
            tracing::error!("H2 connection error: {e}");
        }
    });

    Ok(ServerConnection { h2_client })
}
