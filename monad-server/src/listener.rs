//! TCP listener that accepts connections and performs the Noise NK handshake.

use crate::session;
use monad_common::noise;
use monad_common::noise::NoiseStream;
use std::io;
use std::sync::Arc;
use tokio::net::TcpListener;
use tokio::task::JoinSet;
use tracing::{error, info};

/// Server configuration.
pub struct ServerConfig {
    /// Server's Noise static private key (32 bytes).
    pub private_key: Vec<u8>,
}

/// Run the server: listen for TCP connections, perform Noise handshake, handle H2 sessions.
///
/// Handles Ctrl+C gracefully: stops accepting new connections, waits for active
/// sessions to finish (up to a timeout), then exits. This ensures NoiseStream
/// Drop impls run and wire byte counters are logged.
pub async fn run(listener: TcpListener, config: Arc<ServerConfig>) -> io::Result<()> {
    let local_addr = listener.local_addr()?;
    info!("listening on {local_addr}");

    let mut sessions = JoinSet::new();

    // Accept loop — runs until Ctrl+C
    loop {
        tokio::select! {
            result = listener.accept() => {
                let (mut tcp_stream, peer_addr) = result?;
                info!("accepted connection from {peer_addr}");

                let config = config.clone();

                sessions.spawn(async move {
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

                    let label = format!("{local_addr} <-> {peer_addr}");
                    let noise_stream = NoiseStream::new(tcp_stream, transport, label);

                    // Run the H2 session
                    if let Err(e) = session::handle_session(noise_stream).await {
                        error!("session error with {peer_addr}: {e}");
                    }

                    info!("connection with {peer_addr} closed");
                });

                // Reap any finished sessions (non-blocking)
                while let Some(result) = sessions.try_join_next() {
                    if let Err(e) = result {
                        error!("session task panicked: {e}");
                    }
                }
            }
            _ = tokio::signal::ctrl_c() => {
                info!("shutting down (Ctrl+C)...");
                break;
            }
        }
    }

    // Graceful shutdown: wait for active sessions to finish.
    // When the client disconnects cleanly, the server's H2 session ends,
    // which drops the NoiseStream, triggering the wire byte logging.
    let active = sessions.len();
    if active > 0 {
        info!("waiting for {active} active session(s) to finish...");

        // Give sessions up to 5 seconds to finish
        let timeout = tokio::time::sleep(std::time::Duration::from_secs(5));
        tokio::pin!(timeout);

        loop {
            tokio::select! {
                result = sessions.join_next() => {
                    match result {
                        Some(Ok(())) => {}
                        Some(Err(e)) => error!("session task panicked: {e}"),
                        None => {
                            info!("all sessions finished");
                            break;
                        }
                    }
                }
                _ = &mut timeout => {
                    let remaining = sessions.len();
                    info!("shutdown timeout, aborting {remaining} remaining session(s)");
                    sessions.abort_all();
                    break;
                }
            }
        }
    }

    info!("server shut down");
    Ok(())
}
