use crate::auth::authenticate_connection;
use crate::client::{build_client_config_for_auth, ClientAuthMode};
use crate::stream::{open_monad_stream_with_kind, QuicStream, STREAM_KIND_SECP_NOISE};
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
        loop {
            let key = PoolKey {
                target_addr: target_addr.to_string(),
                auth: PoolAuthKey::try_from(&auth)?,
            };
            let action = {
                let mut pool = self.inner.lock().await;
                match pool.get(&key) {
                    Some(PoolEntry::Ready { conn }) => Action::UseExisting(conn.clone()),
                    Some(PoolEntry::Pending { rx }) => Action::Wait(rx.clone()),
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
                            let mut pool = self.inner.lock().await;
                            if matches!(pool.get(&key), Some(PoolEntry::Ready { .. })) {
                                pool.remove(&key);
                            }
                            continue;
                        }
                    }
                }
                Action::Wait(mut rx) => {
                    loop {
                        rx.changed().await.map_err(|_| {
                            io::Error::new(
                                io::ErrorKind::ConnectionReset,
                                format!(
                                    "QUIC connection task to {target_addr} dropped without result"
                                ),
                            )
                        })?;

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
}

enum Action {
    UseExisting(quinn::Connection),
    Wait(watch::Receiver<ConnResult>),
    Connect {
        key: PoolKey,
        tx: watch::Sender<ConnResult>,
    },
}
