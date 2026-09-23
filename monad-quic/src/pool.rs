use crate::auth::authenticate_connection;
use crate::client::{build_client_config_for_auth, ClientAuthMode};
use crate::stream::{open_monad_stream_with_kind, QuicStream, STREAM_KIND_SECP_NOISE};
use monad_common::network_endpoint::validate_network_endpoint;
use monad_common::secp_identity::Secp256k1Pubkey;
use std::collections::HashMap;
use std::io;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::sync::{watch, Mutex};
use tracing::info;

type ConnResult = Option<Result<quinn::Connection, String>>;

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
enum PoolAuthKey {
    Secp256k1(Secp256k1Pubkey),
}

impl TryFrom<&ClientAuthMode> for PoolAuthKey {
    type Error = io::Error;

    fn try_from(value: &ClientAuthMode) -> Result<Self, Self::Error> {
        match value {
            ClientAuthMode::PinnedSpki(_) => Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "legacy pinned-SPKI MONAD transport is no longer supported",
            )),
            ClientAuthMode::Secp256k1(pubkey) => Ok(Self::Secp256k1(*pubkey)),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct PoolKey {
    target_addr: String,
    auth: PoolAuthKey,
}

enum PoolEntry {
    Pending { rx: watch::Receiver<ConnResult> },
    Ready { conn: quinn::Connection },
}

impl PoolEntry {
    fn is_pending_channel(&self, rx: &watch::Receiver<ConnResult>) -> bool {
        matches!(self, Self::Pending { rx: current } if current.same_channel(rx))
    }
}

#[derive(Clone)]
pub struct QuicPool {
    inner: Arc<Mutex<HashMap<PoolKey, PoolEntry>>>,
    endpoint: Arc<quinn::Endpoint>,
}

impl QuicPool {
    pub fn new() -> io::Result<Self> {
        let endpoint = quinn::Endpoint::client("[::]:0".parse().unwrap())
            .or_else(|_| quinn::Endpoint::client("0.0.0.0:0".parse().unwrap()))
            .map_err(|e| io::Error::other(format!("QUIC endpoint error: {e}")))?;

        Ok(Self {
            inner: Arc::new(Mutex::new(HashMap::new())),
            endpoint: Arc::new(endpoint),
        })
    }

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
        validate_network_endpoint(target_addr)?;
        loop {
            let key = PoolKey {
                target_addr: target_addr.to_string(),
                auth: PoolAuthKey::try_from(&auth)?,
            };
            let action = {
                let mut pool = self.inner.lock().await;
                match pool.get(&key) {
                    Some(PoolEntry::Ready { conn }) => Action::UseExisting(conn.clone()),
                    Some(PoolEntry::Pending { rx }) => Action::Wait {
                        key: key.clone(),
                        rx: rx.clone(),
                    },
                    None => {
                        let (tx, rx) = watch::channel(None);
                        pool.insert(key.clone(), PoolEntry::Pending { rx });
                        Action::Connect {
                            key: key.clone(),
                            tx,
                        }
                    }
                }
            };

            match action {
                Action::UseExisting(conn) => {
                    match open_monad_stream_with_kind(&conn, stream_kind).await {
                        Ok(stream) => {
                            info!("reusing QUIC connection to {target_addr}");
                            return Ok(stream);
                        }
                        Err(e) => {
                            info!(
                            "cached QUIC connection to {target_addr} is dead ({e}), removing and retrying"
                        );
                            self.remove_failed_connection(&key, &conn).await;
                            continue;
                        }
                    }
                }
                Action::Wait { key, mut rx } => {
                    loop {
                        if rx.changed().await.is_err() {
                            info!(
                                "QUIC connection task to {target_addr} dropped without result, removing and retrying"
                            );
                            let mut pool = self.inner.lock().await;
                            if pool
                                .get(&key)
                                .is_some_and(|entry| entry.is_pending_channel(&rx))
                            {
                                pool.remove(&key);
                            }
                            break;
                        }

                        match rx.borrow().clone() {
                            None => continue,
                            Some(Ok(_)) | Some(Err(_)) => break,
                        }
                    }
                    continue;
                }
                Action::Connect { key, tx } => {
                    match self.establish_connection(target_addr, auth.clone()).await {
                        Ok(conn) => {
                            let stream_result =
                                open_monad_stream_with_kind(&conn, stream_kind).await;
                            {
                                let mut pool = self.inner.lock().await;
                                pool.insert(key, PoolEntry::Ready { conn: conn.clone() });
                            }
                            let _ = tx.send(Some(Ok(conn)));
                            info!("QUIC connection to {target_addr} established and cached");
                            return stream_result;
                        }
                        Err(e) => {
                            {
                                let mut pool = self.inner.lock().await;
                                pool.remove(&key);
                            }
                            let _ = tx.send(Some(Err(e.to_string())));
                            return Err(e);
                        }
                    }
                }
            }
        }
    }

    async fn establish_connection(
        &self,
        target_addr: &str,
        auth: ClientAuthMode,
    ) -> io::Result<quinn::Connection> {
        let socket_addr: SocketAddr = tokio::net::lookup_host(target_addr)
            .await
            .map_err(|e| io::Error::other(format!("failed to resolve {target_addr}: {e}")))?
            .next()
            .ok_or_else(|| io::Error::other(format!("no addresses found for {target_addr}")))?;

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

    async fn remove_failed_connection(&self, key: &PoolKey, failed: &quinn::Connection) {
        let mut pool = self.inner.lock().await;
        if matches!(pool.get(key), Some(PoolEntry::Ready { conn }) if conn.stable_id() == failed.stable_id())
        {
            pool.remove(key);
        }
    }
}

enum Action {
    UseExisting(quinn::Connection),
    Wait {
        key: PoolKey,
        rx: watch::Receiver<ConnResult>,
    },
    Connect {
        key: PoolKey,
        tx: watch::Sender<ConnResult>,
    },
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn stale_ready_failure_cannot_evict_real_replacement_connection() {
        let km = crate::keygen::generate().unwrap();
        let endpoint = quinn::Endpoint::server(
            crate::server::build_server_config(&km.cert_pem, &km.key_pem).unwrap(),
            "127.0.0.1:0".parse().unwrap(),
        )
        .unwrap();
        let pool = QuicPool::new().unwrap();
        let client_config =
            crate::client::build_client_config(hex::decode(km.pin_hex).unwrap()).unwrap();
        let addr = endpoint.local_addr().unwrap();
        let mut pairs = Vec::new();
        for _ in 0..2 {
            let client = pool
                .endpoint
                .connect_with(client_config.clone(), addr, "monad-relay")
                .unwrap();
            let (client, server) =
                tokio::join!(client, async { endpoint.accept().await.unwrap().await });
            pairs.push((client.unwrap(), server.unwrap()));
        }
        let key = PoolKey {
            target_addr: addr.to_string(),
            auth: PoolAuthKey::Secp256k1(
                monad_common::secp_identity::SecpTransportKeypair::generate().pubkey(),
            ),
        };
        let old = pairs[0].0.clone();
        let replacement = pairs[1].0.clone();
        // Hold the stale caller's connection across replacement, then complete
        // its failed open and run the exact production eviction path.
        pool.inner.lock().await.insert(
            key.clone(),
            PoolEntry::Ready {
                conn: replacement.clone(),
            },
        );
        old.close(0u32.into(), b"old generation");
        assert!(open_monad_stream_with_kind(&old, STREAM_KIND_SECP_NOISE)
            .await
            .is_err());
        pool.remove_failed_connection(&key, &old).await;
        assert!(
            matches!(pool.inner.lock().await.get(&key), Some(PoolEntry::Ready { conn }) if conn.stable_id() == replacement.stable_id())
        );
        pool.remove_failed_connection(&key, &replacement).await;
        assert!(!pool.inner.lock().await.contains_key(&key));
        endpoint.close(0u32.into(), b"done");
        pool.endpoint.close(0u32.into(), b"done");
        endpoint.wait_idle().await;
        pool.endpoint.wait_idle().await;
    }

    #[test]
    fn stale_pending_waiter_does_not_match_replacement() {
        let (old_tx, old_rx) = watch::channel(None);
        let (_new_tx, new_rx) = watch::channel(None);
        let original = PoolEntry::Pending { rx: old_rx.clone() };
        assert!(original.is_pending_channel(&old_rx));
        drop(old_tx);
        let replacement = PoolEntry::Pending { rx: new_rx };
        assert!(!replacement.is_pending_channel(&old_rx));
    }
}
