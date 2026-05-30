//! QUIC connection pool for relay-to-relay transport.
//!
//! Maintains shared QUIC connections keyed by `(host, port)`. When the relay
//! receives a CONNECT request with a `quic-secp256k1-pubkey` header, it either
//! reuses an existing QUIC connection to that target or establishes a new one, then
//! opens a new bidirectional stream inside it.
//!
//! The pool uses per-key pending state so that:
//! - only one QUIC handshake runs per target at a time
//! - concurrent callers to the same target wait on the in-progress handshake
//!   rather than blocking the entire pool
//! - callers to different targets are never blocked by each other
//! - failed handshakes clean up the placeholder so the next caller retries

use monad_common::secp_identity::Secp256k1Pubkey;
use monad_quic::auth::authenticate_connection;
use monad_quic::client::{build_client_config_for_auth, ClientAuthMode};
use monad_quic::stream::{open_monad_stream_with_kind, QuicStream, STREAM_KIND_SECP_NOISE};
use std::collections::HashMap;
use std::io;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::sync::{watch, Mutex};
use tracing::info;

/// Result of a QUIC connection attempt, shared with waiters via a watch channel.
type ConnResult = Option<Result<quinn::Connection, String>>;

#[derive(Debug, Clone, PartialEq, Eq)]
enum QuicAuthKey {
    Secp256k1(Secp256k1Pubkey),
}

impl From<ClientAuthMode> for QuicAuthKey {
    fn from(value: ClientAuthMode) -> Self {
        match value {
            ClientAuthMode::PinnedSpki(_) => {
                panic!("legacy pinned-SPKI MONAD transport is no longer supported")
            }
            ClientAuthMode::Secp256k1(pubkey) => Self::Secp256k1(pubkey),
        }
    }
}

/// State of a pool entry for a given target.
enum PoolEntry {
    /// A QUIC handshake is in progress. Waiters clone the receiver and watch
    /// for the result. The sender is held by the task performing the handshake.
    Pending {
        auth: QuicAuthKey,
        rx: watch::Receiver<ConnResult>,
    },
    /// An established QUIC connection ready for opening new streams.
    Ready {
        auth: QuicAuthKey,
        conn: quinn::Connection,
    },
}

/// A pool of shared QUIC connections keyed by target address string.
///
/// Each entry is either a pending handshake or an established connection.
/// The pool lock is held only briefly (map lookup + insert/remove), never
/// across network operations.
#[derive(Clone)]
pub struct QuicPool {
    inner: Arc<Mutex<HashMap<String, PoolEntry>>>,
    endpoint: Arc<quinn::Endpoint>,
}

impl QuicPool {
    fn auth_mismatch_error(target_addr: &str) -> io::Error {
        io::Error::new(
            io::ErrorKind::PermissionDenied,
            format!(
                "cached QUIC connection for {target_addr} uses a different transport auth mode"
            ),
        )
    }

    /// Create a new empty QUIC connection pool.
    pub fn new() -> io::Result<Self> {
        let endpoint = quinn::Endpoint::client("[::]:0".parse().unwrap())
            .or_else(|_| quinn::Endpoint::client("0.0.0.0:0".parse().unwrap()))
            .map_err(|e| io::Error::other(format!("QUIC endpoint error: {e}")))?;

        Ok(Self {
            inner: Arc::new(Mutex::new(HashMap::new())),
            endpoint: Arc::new(endpoint),
        })
    }

    /// Open a secp-authenticated QUIC bidirectional stream to `target_addr`.
    pub async fn open_stream(
        &self,
        target_addr: &str,
        auth: ClientAuthMode,
    ) -> io::Result<QuicStream> {
        self.open_stream_with_kind(target_addr, auth, STREAM_KIND_SECP_NOISE)
            .await
    }

    pub async fn open_stream_with_kind(
        &self,
        target_addr: &str,
        auth: ClientAuthMode,
        stream_kind: u8,
    ) -> io::Result<QuicStream> {
        loop {
            let auth_key = QuicAuthKey::from(auth.clone());
            let action = {
                let mut pool = self.inner.lock().await;

                match pool.get(target_addr) {
                    Some(PoolEntry::Ready {
                        auth: cached_auth,
                        conn,
                    }) => {
                        if cached_auth != &auth_key {
                            return Err(Self::auth_mismatch_error(target_addr));
                        }
                        // Try to open a stream on the cached connection.
                        // Clone the connection handle (cheap Arc clone) so we
                        // can release the lock before the async open_bi call.
                        Action::UseExisting(conn.clone())
                    }
                    Some(PoolEntry::Pending {
                        auth: cached_auth,
                        rx,
                    }) => {
                        if cached_auth != &auth_key {
                            return Err(Self::auth_mismatch_error(target_addr));
                        }
                        // Another task is connecting — wait on its result.
                        Action::Wait(rx.clone())
                    }
                    None => {
                        // No entry — we are the one to establish the connection.
                        // Insert a Pending entry and release the lock.
                        let (tx, rx) = watch::channel(None);
                        pool.insert(
                            target_addr.to_string(),
                            PoolEntry::Pending {
                                auth: auth_key.clone(),
                                rx,
                            },
                        );
                        Action::Connect(tx)
                    }
                }
            };
            // Lock is released here.

            match action {
                Action::UseExisting(conn) => {
                    match open_monad_stream_with_kind(&conn, stream_kind).await {
                        Ok(stream) => {
                            info!("reusing QUIC connection to {target_addr}");
                            return Ok(stream);
                        }
                        Err(e) => {
                            // Connection is dead — remove it and retry.
                            info!(
                                "cached QUIC connection to {target_addr} is dead ({e}), \
                                 removing and retrying"
                            );
                            let mut pool = self.inner.lock().await;
                            // Only remove if it's still the same Ready entry (not
                            // replaced by a new Pending from another task).
                            if matches!(pool.get(target_addr), Some(PoolEntry::Ready { .. })) {
                                pool.remove(target_addr);
                            }
                            // Loop back to retry — will either find a new Pending
                            // from another task or create our own.
                            continue;
                        }
                    }
                }

                Action::Wait(mut rx) => {
                    // Wait for the in-progress handshake to complete.
                    loop {
                        rx.changed().await.map_err(|_| {
                            io::Error::new(
                                io::ErrorKind::ConnectionReset,
                                format!(
                                    "QUIC connection task to {target_addr} dropped without result"
                                ),
                            )
                        })?;

                        let result = rx.borrow().clone();
                        match result {
                            None => {
                                // Still pending, keep waiting.
                                continue;
                            }
                            Some(Ok(_conn)) => {
                                // Connection established by another task. It should now
                                // be in the pool as Ready. Loop back to UseExisting.
                                break;
                            }
                            Some(Err(e)) => {
                                // The connecting task failed and cleaned up. Retry
                                // from scratch — we might become the next connector.
                                info!(
                                    "waited for QUIC connection to {target_addr}, \
                                     but it failed: {e} — retrying"
                                );
                                break;
                            }
                        }
                    }
                    // Loop back to check the pool again.
                    continue;
                }

                Action::Connect(tx) => {
                    // We are responsible for establishing the connection.
                    match self.establish_connection(target_addr, auth.clone()).await {
                        Ok(conn) => {
                            // Open the first stream.
                            let stream_result =
                                open_monad_stream_with_kind(&conn, stream_kind).await;

                            // Promote to Ready in the pool, notify waiters.
                            {
                                let mut pool = self.inner.lock().await;
                                pool.insert(
                                    target_addr.to_string(),
                                    PoolEntry::Ready {
                                        auth: auth_key.clone(),
                                        conn: conn.clone(),
                                    },
                                );
                            }
                            let _ = tx.send(Some(Ok(conn)));

                            info!("QUIC connection to {target_addr} established and cached");
                            return stream_result;
                        }
                        Err(e) => {
                            // Remove the Pending placeholder, notify waiters of failure.
                            {
                                let mut pool = self.inner.lock().await;
                                pool.remove(target_addr);
                            }
                            let _ = tx.send(Some(Err(e.to_string())));
                            return Err(e);
                        }
                    }
                }
            }
        }
    }

    /// Establish a new QUIC connection (DNS resolution + handshake).
    /// Called without any lock held.
    async fn establish_connection(
        &self,
        target_addr: &str,
        auth: ClientAuthMode,
    ) -> io::Result<quinn::Connection> {
        // Resolve the target address
        let socket_addr: SocketAddr = tokio::net::lookup_host(target_addr)
            .await
            .map_err(|e| io::Error::other(format!("failed to resolve {target_addr}: {e}")))?
            .next()
            .ok_or_else(|| io::Error::other(format!("no addresses found for {target_addr}")))?;

        // Build client config with pinned key verification
        let client_config = build_client_config_for_auth(auth.clone())
            .map_err(|e| io::Error::other(format!("failed to build QUIC client config: {e}")))?;

        info!("establishing new QUIC connection to {target_addr} ({socket_addr})");

        let conn = self
            .endpoint
            .connect_with(client_config, socket_addr, "monad-relay")
            .map_err(|e| io::Error::other(format!("QUIC connect error to {target_addr}: {e}")))?
            .await
            .map_err(|e| {
                io::Error::new(
                    io::ErrorKind::ConnectionRefused,
                    format!("QUIC handshake failed with {target_addr}: {e}"),
                )
            })?;

        let pubkey = match auth {
            ClientAuthMode::Secp256k1(pubkey) => pubkey,
            ClientAuthMode::PinnedSpki(_) => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "legacy pinned-SPKI MONAD transport is no longer supported",
                ));
            }
        };
        authenticate_connection(&conn, &pubkey).await.map_err(|e| {
            io::Error::new(
                io::ErrorKind::PermissionDenied,
                format!("QUIC secp256k1 auth failed with {target_addr}: {e}"),
            )
        })?;

        Ok(conn)
    }
}

/// Internal action determined under the pool lock, executed after releasing it.
enum Action {
    /// Found a Ready connection — try to open a stream on it.
    UseExisting(quinn::Connection),
    /// Found a Pending entry — wait on this watch receiver for the result.
    Wait(watch::Receiver<ConnResult>),
    /// No entry — we establish the connection and signal via this sender.
    Connect(watch::Sender<ConnResult>),
}
