//! QUIC connection pool for relay-to-relay transport.
//!
//! Maintains shared QUIC connections keyed by `(host, port)`. When the server
//! receives `CONNECT quic:host:port,<pin>`, it either reuses an existing QUIC
//! connection to that target or establishes a new one, then opens a new
//! bidirectional stream inside it.

use monad_quic::stream::QuicStream;
use std::collections::HashMap;
use std::io;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::sync::Mutex;
use tracing::info;

/// A pool of shared QUIC connections keyed by target address string.
///
/// Each entry is a `quinn::Connection` that may carry many concurrent streams.
/// The pool is shared across all sessions on the server via `Arc`.
#[derive(Clone)]
pub struct QuicPool {
    inner: Arc<Mutex<HashMap<String, quinn::Connection>>>,
    endpoint: Arc<quinn::Endpoint>,
}

impl QuicPool {
    /// Create a new empty QUIC connection pool.
    ///
    /// The endpoint is used to dial new outbound QUIC connections when no
    /// cached connection exists for a target.
    pub fn new() -> io::Result<Self> {
        let endpoint = quinn::Endpoint::client("0.0.0.0:0".parse().unwrap())
            .map_err(|e| io::Error::new(io::ErrorKind::Other, format!("QUIC endpoint error: {e}")))?;

        Ok(Self {
            inner: Arc::new(Mutex::new(HashMap::new())),
            endpoint: Arc::new(endpoint),
        })
    }

    /// Open a QUIC bidirectional stream to `target_addr`, reusing an existing
    /// connection if one is available, or establishing a new one using the
    /// provided pinned SPKI for server authentication.
    pub async fn open_stream(
        &self,
        target_addr: &str,
        pinned_spki: Vec<u8>,
    ) -> io::Result<QuicStream> {
        let mut pool = self.inner.lock().await;

        // Check for an existing connection that's still alive
        if let Some(conn) = pool.get(target_addr) {
            match conn.open_bi().await {
                Ok((send, recv)) => {
                    info!("reusing QUIC connection to {target_addr}");
                    return Ok(QuicStream::new(send, recv));
                }
                Err(e) => {
                    // Connection is dead, remove it and fall through to reconnect
                    info!("cached QUIC connection to {target_addr} is dead ({e}), reconnecting");
                    pool.remove(target_addr);
                }
            }
        }

        // Resolve the target address
        let socket_addr: SocketAddr = tokio::net::lookup_host(target_addr)
            .await
            .map_err(|e| {
                io::Error::new(
                    io::ErrorKind::Other,
                    format!("failed to resolve {target_addr}: {e}"),
                )
            })?
            .next()
            .ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::Other,
                    format!("no addresses found for {target_addr}"),
                )
            })?;

        // Build client config with pinned key verification for this specific target
        let client_config = monad_quic::client::build_client_config(pinned_spki).map_err(|e| {
            io::Error::new(
                io::ErrorKind::Other,
                format!("failed to build QUIC client config: {e}"),
            )
        })?;

        // Establish a new QUIC connection using per-connection config
        info!("establishing new QUIC connection to {target_addr} ({socket_addr})");
        let conn = self
            .endpoint
            .connect_with(client_config, socket_addr, "monad-relay")
            .map_err(|e| {
                io::Error::new(
                    io::ErrorKind::Other,
                    format!("QUIC connect error to {target_addr}: {e}"),
                )
            })?
            .await
            .map_err(|e| {
                io::Error::new(
                    io::ErrorKind::ConnectionRefused,
                    format!("QUIC handshake failed with {target_addr}: {e}"),
                )
            })?;

        // Open the first stream
        let (send, recv) = conn.open_bi().await.map_err(|e| {
            io::Error::new(
                io::ErrorKind::Other,
                format!("failed to open QUIC stream to {target_addr}: {e}"),
            )
        })?;

        // Cache the connection for future reuse
        pool.insert(target_addr.to_string(), conn);

        info!("QUIC connection to {target_addr} established and cached");
        Ok(QuicStream::new(send, recv))
    }
}
