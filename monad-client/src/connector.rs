//! Establishes a connection to a MONAD relay, optionally through a chain
//! of intermediate hops (onion routing / nested tunneling).
//!
//! Single hop:   TCP → Noise(S) → H2
//! Two hops:     TCP → Noise(T) → H2 → CONNECT(S) → Noise(S) → H2
//! N hops:       Each hop wraps the previous one via H2ConnectStream.

use crate::session_driver;
use crate::wallet::{MockWallet, MonadWallet};
use monad_common::noise_secp256k1;
use monad_common::secp_identity::Secp256k1Pubkey;
use monad_common::session::RelayConnection;
use monad_quic::client::ClientAuthMode;
use monad_quic::pool::QuicPool;
use std::io;
use std::sync::Arc;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::TcpStream;
use tracing::info;

#[derive(Clone)]
pub struct ConnectorRuntime {
    wallet: Option<Arc<dyn MonadWallet>>,
    first_hop_quic_pool: Arc<QuicPool>,
}

impl ConnectorRuntime {
    pub fn new(wallet: Option<Arc<dyn MonadWallet>>) -> io::Result<Self> {
        Ok(Self {
            wallet,
            first_hop_quic_pool: Arc::new(QuicPool::new()?),
        })
    }

    pub fn with_mock_wallet() -> io::Result<Self> {
        Self::new(Some(Arc::new(MockWallet::new())))
    }
}

/// A hop identity for transport authentication.
#[derive(Debug, Clone)]
pub enum HopIdentity {
    Secp256k1(Secp256k1Pubkey),
}

impl HopIdentity {
    pub fn describe(&self) -> &'static str {
        match self {
            Self::Secp256k1(_) => "secp256k1",
        }
    }
}

/// A hop in the tunnel chain: relay address and its transport identity.
///
/// MONAD transport now uses secp256k1 identities for both plain TCP and QUIC.
///
/// If `use_quic` is true, the previous relay in the chain will connect to this
/// hop via QUIC instead of TCP.
#[derive(Debug, Clone)]
pub struct Hop {
    pub addr: String,
    /// Transport identity for this hop.
    pub identity: HopIdentity,
    /// Whether the previous relay should connect to this hop via QUIC.
    pub use_quic: bool,
}

/// Connect to a MONAD relay directly (single hop).
///
/// Equivalent to `connect_through_chain(&[hop])`.
#[allow(dead_code)]
pub async fn connect(
    relay_addr: &str,
    relay_pubkey: Secp256k1Pubkey,
) -> io::Result<RelayConnection> {
    connect_through_chain(&[Hop {
        addr: relay_addr.to_string(),
        identity: HopIdentity::Secp256k1(relay_pubkey),
        use_quic: false,
    }])
    .await
}

/// Connect to a chain of MONAD relays.
///
/// `hops` must have at least one entry. The first hop is connected to via TCP.
/// Each subsequent hop is reached by opening an H2 CONNECT tunnel through the
/// previous hop. The returned `RelayConnection` is for the *last* hop in the chain.
///
/// Example with 2 hops [T, S]:
///   TCP → Noise(T) → H2 → CONNECT(S:port) → Noise(S) → H2 → (returned client)
///
/// T only sees encrypted Noise bytes. It has no idea that inside those bytes
/// is another MONAD session asking S to proxy onward.
pub async fn connect_through_chain(hops: &[Hop]) -> io::Result<RelayConnection> {
    let runtime = ConnectorRuntime::with_mock_wallet()?;
    connect_through_chain_internal(hops, runtime, false).await
}

/// Connect to a chain of MONAD relays, optionally funding every hop with the
/// provided wallet.
///
/// When `wallet` is `Some`, every hop in the chain, including the final hop,
/// is funded through the shared session payment driver before this function
/// returns. When `wallet` is `None`, no funding is started automatically.
pub async fn connect_through_chain_with_wallet(
    hops: &[Hop],
    wallet: Option<Arc<dyn MonadWallet>>,
) -> io::Result<RelayConnection> {
    let runtime = ConnectorRuntime::new(wallet)?;
    connect_through_chain_internal(hops, runtime, true).await
}

pub async fn connect_through_chain_with_runtime(
    hops: &[Hop],
    runtime: &ConnectorRuntime,
) -> io::Result<RelayConnection> {
    connect_through_chain_internal(hops, runtime.clone(), true).await
}

async fn connect_through_chain_internal(
    hops: &[Hop],
    runtime: ConnectorRuntime,
    fund_last_hop: bool,
) -> io::Result<RelayConnection> {
    if hops.is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "at least one hop is required",
        ));
    }

    let first = &hops[0];

    if first.use_quic {
        // Connect to the first hop via QUIC
        info!("connecting to first hop via QUIC: {}", first.addr);
        let auth = match &first.identity {
            HopIdentity::Secp256k1(pubkey) => ClientAuthMode::Secp256k1(*pubkey),
        };
        let quic_stream = runtime
            .first_hop_quic_pool
            .open_stream(&first.addr, auth)
            .await?;
        info!("QUIC connected to {}", first.addr);

        chain_from_stream(quic_stream, hops, 0, runtime, fund_last_hop).await
    } else {
        // Connect to the first hop via TCP
        info!("connecting to first hop: {}", first.addr);
        let tcp_stream = TcpStream::connect(&first.addr).await?;
        info!("TCP connected to {}", first.addr);

        chain_from_stream(tcp_stream, hops, 0, runtime, fund_last_hop).await
    }
}

async fn optionally_fund_session(
    mut conn: RelayConnection,
    wallet: Option<Arc<dyn MonadWallet>>,
    hop_label: &str,
) -> io::Result<RelayConnection> {
    let Some(wallet) = wallet else {
        return Ok(conn);
    };

    info!("{hop_label}: opening funded control session");
    let (control_task, ready_rx) =
        session_driver::start_session_payment_driver(&conn, wallet, hop_label).await?;
    info!("{hop_label}: waiting for funded session readiness");
    ready_rx.await.map_err(|_| {
        io::Error::new(
            io::ErrorKind::BrokenPipe,
            format!("control task exited before {hop_label} was funded"),
        )
    })?;
    info!("{hop_label}: session funded and usable");
    conn.add_task(control_task);
    Ok(conn)
}

/// Recursively build the tunnel chain starting from a given stream and hop index.
///
/// This function performs the Noise handshake and H2 setup for `hops[hop_idx]`,
/// then if there are more hops, opens a CONNECT tunnel and recurses.
///
/// The returned future is boxed to allow async recursion with different stream types
/// at each nesting level.
fn chain_from_stream<S>(
    mut stream: S,
    hops: &[Hop],
    hop_idx: usize,
    runtime: ConnectorRuntime,
    fund_last_hop: bool,
) -> std::pin::Pin<Box<dyn std::future::Future<Output = io::Result<RelayConnection>> + Send>>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    // Clone what we need since we're moving into a boxed future
    let hops = hops.to_vec();
    let runtime = runtime.clone();

    Box::pin(async move {
        let hop = &hops[hop_idx];

        info!(
            "hop {}/{}: Noise handshake with {}",
            hop_idx + 1,
            hops.len(),
            hop.addr
        );

        let label = format!("client hop {}/{} to {}", hop_idx + 1, hops.len(), hop.addr);
        let (mut conn, driver) = match &hop.identity {
            HopIdentity::Secp256k1(pubkey) => {
                let (send_cipher, recv_cipher, session_id) =
                    noise_secp256k1::handshake_initiator(&mut stream, pubkey).await?;
                let secp_stream = noise_secp256k1::SecpNoiseStream::new(
                    stream,
                    send_cipher,
                    recv_cipher,
                    session_id,
                    label,
                );
                RelayConnection::from_transport_stream(secp_stream, session_id).await?
            }
        };
        conn.add_driver(driver);

        info!(
            "hop {}/{}: H2 connection established",
            hop_idx + 1,
            hops.len()
        );

        let hop_label = format!("hop {}/{} to {}", hop_idx + 1, hops.len(), hop.addr);
        let should_fund = runtime.wallet.is_some() && (hop_idx < hops.len() - 1 || fund_last_hop);
        conn = optionally_fund_session(
            conn,
            if should_fund {
                runtime.wallet.clone()
            } else {
                None
            },
            &hop_label,
        )
        .await?;

        if hop_idx < hops.len() - 1 {
            // Not the last hop — open a CONNECT tunnel to the next hop
            let next = &hops[hop_idx + 1];
            info!(
                "hop {}/{}: opening CONNECT tunnel to next hop {}",
                hop_idx + 1,
                hops.len(),
                next.addr
            );

            // Open the CONNECT tunnel, with QUIC pin if the next hop uses QUIC
            let h2_connect_stream = if next.use_quic {
                match &next.identity {
                    HopIdentity::Secp256k1(pubkey) => {
                        conn.open_tunnel_quic_secp256k1(&next.addr, &pubkey.to_hex())
                            .await?
                    }
                }
            } else {
                conn.open_tunnel(&next.addr).await?
            };

            // Recurse: perform Noise + H2 over this tunnel for the next hop.
            // Attach this hop's driver to the final connection.
            let mut conn = conn;
            let mut next_conn = chain_from_stream(
                h2_connect_stream,
                &hops,
                hop_idx + 1,
                runtime.clone(),
                fund_last_hop,
            )
            .await?;
            next_conn.absorb_handles_from(&mut conn);
            Ok(next_conn)
        } else {
            // Last hop — return for actual use.
            info!("tunnel chain established ({} hops)", hops.len());
            Ok(conn)
        }
    }) // close Box::pin(async move { ... })
}
