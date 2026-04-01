//! TCP and QUIC listener that accepts connections and performs the Noise NK handshake.

use crate::quic_pool::QuicPool;
use crate::session::RelaySession;
use monad_common::identity::ServerIdentity;
use monad_common::noise;
use monad_common::noise::NoiseStream;
use monad_quic::stream::QuicStream;
use std::io;
use std::sync::Arc;
use tokio::net::TcpListener;
use tokio::task::JoinSet;
use tracing::{error, info};

/// Server configuration.
pub struct ServerConfig {
    /// The server's unified identity (Ed25519 seed + derived keys).
    pub identity: ServerIdentity,
}

/// Run the server: listen for TCP and optionally QUIC connections, perform Noise
/// handshake, handle H2 sessions.
///
/// Both TCP and QUIC connections are fed into the same Noise+H2 session handler.
/// The server treats them identically after the transport is established.
///
/// Handles Ctrl+C gracefully: stops accepting new connections, waits for active
/// sessions to finish (up to a timeout), then exits. This ensures NoiseStream
/// Drop impls run and wire byte counters are logged.
pub async fn run(
    listener: TcpListener,
    quic_endpoint: Option<quinn::Endpoint>,
    config: Arc<ServerConfig>,
) -> io::Result<()> {
    let local_addr = listener.local_addr()?;
    info!("listening on {local_addr}");

    let mut sessions = JoinSet::new();

    // Create the QUIC connection pool for outbound CONNECT quic: forwarding.
    // This is separate from the QUIC endpoint (which handles inbound connections).
    let quic_pool = QuicPool::new().ok();

    // Accept loop — runs until Ctrl+C
    loop {
        tokio::select! {
            result = listener.accept() => {
                let (mut tcp_stream, peer_addr) = result?;
                info!("accepted TCP connection from {peer_addr}");

                let config = config.clone();
                let quic_pool = quic_pool.clone();

                sessions.spawn(async move {
                    // Noise NK handshake (server is responder)
                    let transport =
                        match noise::handshake_responder(&mut tcp_stream, config.identity.x25519_private()).await {
                            Ok(t) => {
                                info!("noise handshake complete with {peer_addr} (TCP)");
                                t
                            }
                            Err(e) => {
                                error!("noise handshake failed with {peer_addr}: {e}");
                                return;
                            }
                        };

                    let label = format!("{local_addr} <-> {peer_addr} (TCP)");
                    let noise_stream = NoiseStream::new(tcp_stream, transport, label);

                    // Run the H2 session
                    match RelaySession::from_noise_stream(noise_stream, quic_pool).await {
                        Ok(session) => {
                            if let Err(e) = session.run().await {
                                error!("session error with {peer_addr}: {e}");
                            }
                        }
                        Err(e) => {
                            error!("H2 handshake failed with {peer_addr}: {e}");
                        }
                    }

                    info!("connection with {peer_addr} closed (TCP)");
                });

                // Reap any finished sessions (non-blocking)
                while let Some(result) = sessions.try_join_next() {
                    if let Err(e) = result {
                        error!("session task panicked: {e}");
                    }
                }
            }
            Some(incoming) = async {
                match &quic_endpoint {
                    Some(ep) => ep.accept().await,
                    None => std::future::pending().await,
                }
            } => {
                let config = config.clone();
                let quic_pool = quic_pool.clone();

                sessions.spawn(async move {
                    // Complete the QUIC connection handshake
                    let conn = match incoming.await {
                        Ok(c) => c,
                        Err(e) => {
                            error!("QUIC connection handshake failed: {e}");
                            return;
                        }
                    };
                    let remote = conn.remote_address();
                    info!("accepted QUIC connection from {remote}");

                    // Accept bidirectional streams from this QUIC connection.
                    // Each stream is an independent Noise+H2 session.
                    loop {
                        match conn.accept_bi().await {
                            Ok((send, recv)) => {
                                let stream_id = send.id();
                                info!(%remote, ?stream_id, "accepted QUIC stream");

                                let config = config.clone();
                                let quic_pool = quic_pool.clone();
                                tokio::spawn(async move {
                                    let mut quic_stream = QuicStream::new(send, recv);

                                    let transport = match noise::handshake_responder(
                                        &mut quic_stream,
                                        config.identity.x25519_private(),
                                    )
                                    .await
                                    {
                                        Ok(t) => {
                                            info!("noise handshake complete with {remote} (QUIC {stream_id:?})");
                                            t
                                        }
                                        Err(e) => {
                                            error!("noise handshake failed with {remote} (QUIC {stream_id:?}): {e}");
                                            return;
                                        }
                                    };

                                    let label =
                                        format!("{} <-> {remote} (QUIC {stream_id:?})", "quic");
                                    let noise_stream =
                                        NoiseStream::new(quic_stream, transport, label);

                                    match RelaySession::from_noise_stream(noise_stream, quic_pool).await {
                                        Ok(session) => {
                                            if let Err(e) = session.run().await {
                                                error!("session error with {remote} (QUIC {stream_id:?}): {e}");
                                            }
                                        }
                                        Err(e) => {
                                            error!("H2 handshake failed with {remote} (QUIC {stream_id:?}): {e}");
                                        }
                                    }

                                    info!("QUIC stream {stream_id:?} from {remote} closed");
                                });
                            }
                            Err(quinn::ConnectionError::ApplicationClosed(_)) => {
                                info!(%remote, "QUIC connection closed by peer");
                                break;
                            }
                            Err(e) => {
                                error!(%remote, error = %e, "QUIC accept_bi failed");
                                break;
                            }
                        }
                    }
                });

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
    let active = sessions.len();
    if active > 0 {
        info!("waiting for {active} active session(s) to finish...");

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

    if let Some(ep) = quic_endpoint {
        ep.close(0u32.into(), b"shutdown");
    }

    info!("server shut down");
    Ok(())
}
