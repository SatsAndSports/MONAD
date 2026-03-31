//! TCP listener that accepts connections and performs the Noise NK handshake.

use crate::session;
use paidtor_common::noise;
use paidtor_common::noise::NoiseStream;
use std::io;
use std::sync::Arc;
use tokio::net::TcpListener;
use tracing::{error, info};

/// Server configuration.
pub struct ServerConfig {
    /// Server's Noise static private key (32 bytes).
    pub private_key: Vec<u8>,
}

/// Run the server: listen for TCP connections, perform Noise handshake, handle H2 sessions.
pub async fn run(listener: TcpListener, config: Arc<ServerConfig>) -> io::Result<()> {
    let local_addr = listener.local_addr()?;
    info!("listening on {local_addr}");

    loop {
        let (mut tcp_stream, peer_addr) = listener.accept().await?;
        info!("accepted connection from {peer_addr}");

        let config = config.clone();

        tokio::spawn(async move {
            // Noise NK handshake (server is responder)
            let transport =
                match noise::handshake_responder(&mut tcp_stream, &config.private_key).await {
                    Ok(t) => {
                        info!("noise handshake complete with {peer_addr}");
                        t
                    }
                    Err(e) => {
                        error!("noise handshake failed with {peer_addr}: {e}");
                        return;
                    }
                };

            let noise_stream = NoiseStream::new(tcp_stream, transport);

            // Run the H2 session
            if let Err(e) = session::handle_session(noise_stream).await {
                error!("session error with {peer_addr}: {e}");
            }

            info!("connection with {peer_addr} closed");
        });
    }
}
