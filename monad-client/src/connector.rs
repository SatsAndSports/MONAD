//! Establishes a connection to a MONAD relay, optionally through a route of
//! intermediate hops.
//!
//! Single hop:   TCP/QUIC -> Noise(S) -> H2
//! Two hops:     TCP/QUIC -> Noise(T) -> H2 -> CONNECT(S) -> Noise(S) -> H2
//! N hops:       Each hop wraps the previous one via `H2ConnectStream`.

use crate::route::{Route, RouteHop};
use crate::session_driver;
use crate::session_driver::PaymentPolicy;
use crate::wallet::{MockWallet, MonadWallet};
use monad_common::blinded_connect::BlindedConnectRequest;
use monad_common::bootstrap::BootstrapCapabilities;
use monad_common::noise_secp256k1;
use monad_common::secp_identity::Secp256k1Pubkey;
use monad_common::session::RelayConnection;
use monad_quic::client::ClientAuthMode;
use monad_quic::pool::QuicPool;
use std::io;
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::TcpStream;
use tokio::task::JoinSet;
use tracing::info;

#[derive(Clone)]
pub struct ConnectorRuntime {
    wallet: Option<Arc<dyn MonadWallet>>,
    first_hop_quic_pool: Arc<QuicPool>,
    payment_policy: PaymentPolicy,
}

impl ConnectorRuntime {
    pub fn new(wallet: Option<Arc<dyn MonadWallet>>) -> io::Result<Self> {
        Self::with_payment_policy(wallet, PaymentPolicy::default())
    }

    pub fn with_payment_policy(
        wallet: Option<Arc<dyn MonadWallet>>,
        payment_policy: PaymentPolicy,
    ) -> io::Result<Self> {
        Ok(Self {
            wallet,
            first_hop_quic_pool: Arc::new(QuicPool::new()?),
            payment_policy,
        })
    }

    pub fn with_mock_wallet() -> io::Result<Self> {
        Self::new(Some(Arc::new(MockWallet::new())))
    }

    pub fn reset_first_hop_quic_pool(&mut self) -> io::Result<()> {
        self.first_hop_quic_pool = Arc::new(QuicPool::new()?);
        Ok(())
    }
}

#[derive(Debug, Clone)]
pub struct RouteHopConnection {
    pub hop_idx: usize,
    pub label: String,
    pub session_id: [u8; 32],
    pub funded: bool,
}

const CASCADED_ROUTE_FAILURE_DEBOUNCE: Duration = Duration::from_millis(100);

/// Short window for collecting downstream failures caused by one upstream hop
/// dropping, so rebuilds start from the earliest failed hop.
pub fn cascaded_route_failure_debounce() -> Duration {
    CASCADED_ROUTE_FAILURE_DEBOUNCE
}

/// Owns every established hop in a route, not only the final hop.
///
/// Keeping prefix connections alive lets configured clients rebuild a failed
/// suffix without tearing down unaffected prefix sessions or their channels.
pub struct RouteConnection {
    final_conn: Arc<RelayConnection>,
    prefix_conns: Vec<Arc<RelayConnection>>,
    hops: Vec<RouteHopConnection>,
}

impl RouteConnection {
    fn from_funded(funded: FundedConnection) -> Self {
        Self {
            final_conn: Arc::new(funded.conn),
            prefix_conns: funded.prefix_conns.into_iter().map(Arc::new).collect(),
            hops: funded.hops,
        }
    }

    pub fn final_connection(&self) -> &RelayConnection {
        &self.final_conn
    }

    pub fn final_connection_arc(&self) -> Arc<RelayConnection> {
        self.final_conn.clone()
    }

    pub fn hops(&self) -> &[RouteHopConnection] {
        &self.hops
    }

    pub fn hop_count(&self) -> usize {
        self.hops.len()
    }

    pub fn connection_for_hop(&self, hop_idx: usize) -> Option<Arc<RelayConnection>> {
        if hop_idx >= self.hops.len() {
            return None;
        }
        if hop_idx + 1 == self.hops.len() {
            Some(self.final_conn.clone())
        } else {
            self.prefix_conns.get(hop_idx).cloned()
        }
    }

    pub fn prefix_tail_connection(&self, start_hop_idx: usize) -> Option<Arc<RelayConnection>> {
        start_hop_idx
            .checked_sub(1)
            .and_then(|hop_idx| self.connection_for_hop(hop_idx))
    }

    pub fn suffix_session_ids_from(&self, start_hop_idx: usize) -> Vec<[u8; 32]> {
        self.hops
            .iter()
            .filter(|hop| hop.hop_idx >= start_hop_idx)
            .map(|hop| hop.session_id)
            .collect()
    }

    pub async fn close_suffix_from(&self, start_hop_idx: usize) {
        for hop_idx in start_hop_idx..self.hops.len() {
            if let Some(conn) = self.connection_for_hop(hop_idx) {
                conn.close().await;
            }
        }
    }

    pub async fn wait_for_failure(&self) -> Option<usize> {
        self.wait_for_failure_owned().await
    }

    pub fn wait_for_failure_owned(
        &self,
    ) -> impl std::future::Future<Output = Option<usize>> + Send + 'static {
        let conns = self
            .prefix_conns
            .iter()
            .chain(std::iter::once(&self.final_conn))
            .filter(|conn| conn.has_failure_watchers())
            .cloned()
            .collect::<Vec<_>>();

        async move {
            if conns.is_empty() {
                return None;
            }

            let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel::<usize>();
            let mut tasks = JoinSet::new();
            for conn in conns {
                let tx = tx.clone();
                tasks.spawn(async move {
                    if let Some(hop_idx) = conn.wait_for_failure().await {
                        let _ = tx.send(hop_idx);
                    }
                });
            }

            let mut min_hop = rx.recv().await?;

            // A middle-hop failure often cascades into downstream session
            // failures. Debounce briefly and rebuild from the lowest failed hop.
            let deadline = tokio::time::Instant::now() + CASCADED_ROUTE_FAILURE_DEBOUNCE;
            loop {
                let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
                if remaining.is_zero() {
                    break;
                }
                match tokio::time::timeout(remaining, rx.recv()).await {
                    Ok(Some(hop_idx)) => {
                        if hop_idx < min_hop {
                            min_hop = hop_idx;
                        }
                    }
                    Ok(None) | Err(_) => break,
                }
            }

            // The remaining watcher tasks are aborted when the JoinSet drops.
            drop(tasks);
            Some(min_hop)
        }
    }

    pub async fn close(&self) {
        self.final_conn.close().await;
        for prefix_conn in &self.prefix_conns {
            prefix_conn.close().await;
        }
    }
}

pub async fn connect(
    relay_addr: &str,
    relay_pubkey: Secp256k1Pubkey,
) -> io::Result<RouteConnection> {
    let route = Route::new(vec![RouteHop::Cleartext {
        addr: relay_addr.to_string(),
        pubkey: relay_pubkey,
        use_quic: false,
    }])?;
    let runtime = ConnectorRuntime::with_mock_wallet()?;
    connect_route_internal(&route, runtime, false).await
}

pub async fn connect_route(route: &Route) -> io::Result<RouteConnection> {
    let runtime = ConnectorRuntime::with_mock_wallet()?;
    connect_route_internal(route, runtime, false).await
}

pub async fn connect_route_with_wallet(
    route: &Route,
    wallet: Option<Arc<dyn MonadWallet>>,
) -> io::Result<RouteConnection> {
    let runtime = ConnectorRuntime::new(wallet)?;
    connect_route_internal(route, runtime, true).await
}

pub async fn connect_route_with_runtime(
    route: &Route,
    runtime: &ConnectorRuntime,
) -> io::Result<RouteConnection> {
    connect_route_internal(route, runtime.clone(), true).await
}

/// Build a route, optionally preserving the prefix before `start_hop_idx` from
/// `old_route` and rebuilding only the suffix from that hop onward.
pub async fn rebuild_route_from_with_runtime(
    route: &Route,
    runtime: &ConnectorRuntime,
    old_route: Option<RouteConnection>,
    start_hop_idx: usize,
) -> io::Result<RouteConnection> {
    // Rebuilding from hop 0 is equivalent to a normal full-route reconnect.
    if start_hop_idx == 0 {
        if let Some(old_route) = old_route {
            old_route.close().await;
        }
        return connect_route_internal(route, runtime.clone(), true).await;
    }

    if start_hop_idx >= route.hops().len() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!(
                "cannot rebuild route from hop {} of {}",
                start_hop_idx + 1,
                route.hops().len()
            ),
        ));
    }

    let old_route = old_route.ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            "suffix rebuild requires an existing route",
        )
    })?;

    // Suffix rebuild only applies when the route shape is unchanged. Route
    // config changes should use a full reconnect so hop metadata cannot drift.
    if old_route.hop_count() != route.hops().len() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!(
                "cannot rebuild route suffix: old route has {} hops but target route has {}",
                old_route.hop_count(),
                route.hops().len()
            ),
        ));
    }

    let prefix_tail = old_route
        .prefix_tail_connection(start_hop_idx)
        .ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("missing preserved prefix for hop {}", start_hop_idx + 1),
            )
        })?;
    let next_hop = route.hops().get(start_hop_idx).ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("missing route hop {}", start_hop_idx + 1),
        )
    })?;

    let RouteConnection {
        final_conn: old_final_conn,
        prefix_conns: old_prefix_conns,
        hops: old_hops,
    } = old_route;

    let mut preserved_prefix_conns = Vec::new();
    let mut old_suffix_conns = Vec::new();
    for (hop_idx, conn) in old_prefix_conns.into_iter().enumerate() {
        if hop_idx < start_hop_idx {
            preserved_prefix_conns.push(conn);
        } else {
            old_suffix_conns.push(conn);
        }
    }
    old_suffix_conns.push(old_final_conn);
    for conn in old_suffix_conns {
        conn.close().await;
    }

    let preserved_hops = old_hops.into_iter().take(start_hop_idx).collect::<Vec<_>>();
    let h2_connect_stream = match open_next_hop_tunnel(&prefix_tail, next_hop).await {
        Ok(stream) => stream,
        Err(err) => {
            for conn in &preserved_prefix_conns {
                conn.close().await;
            }
            return Err(err);
        }
    };
    let mut rebuilt_suffix = match chain_from_stream(
        h2_connect_stream,
        route.clone(),
        start_hop_idx,
        runtime.clone(),
        true,
    )
    .await
    {
        Ok(rebuilt_suffix) => rebuilt_suffix,
        Err(err) => {
            for conn in &preserved_prefix_conns {
                conn.close().await;
            }
            return Err(err);
        }
    };

    let mut hops = preserved_hops;
    hops.append(&mut rebuilt_suffix.hops);
    let mut prefix_conns = preserved_prefix_conns;
    prefix_conns.extend(rebuilt_suffix.prefix_conns.into_iter().map(Arc::new));

    Ok(RouteConnection {
        final_conn: Arc::new(rebuilt_suffix.conn),
        prefix_conns,
        hops,
    })
}

async fn connect_route_internal(
    route: &Route,
    runtime: ConnectorRuntime,
    fund_last_hop: bool,
) -> io::Result<RouteConnection> {
    let first = route.hops().first().ok_or_else(|| {
        io::Error::new(io::ErrorKind::InvalidInput, "at least one hop is required")
    })?;

    let RouteHop::Cleartext {
        addr,
        pubkey,
        use_quic,
    } = first
    else {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "the first hop must be cleartext",
        ));
    };

    let funded = if *use_quic {
        info!("connecting to first hop via QUIC: {addr}");
        let quic_stream = runtime
            .first_hop_quic_pool
            .open_stream(addr, ClientAuthMode::Secp256k1(*pubkey))
            .await?;
        info!("QUIC connected to {addr}");
        chain_from_stream(quic_stream, route.clone(), 0, runtime, fund_last_hop).await?
    } else {
        info!("connecting to first hop: {addr}");
        let tcp_stream = TcpStream::connect(addr).await?;
        info!("TCP connected to {addr}");
        chain_from_stream(tcp_stream, route.clone(), 0, runtime, fund_last_hop).await?
    };
    Ok(RouteConnection::from_funded(funded))
}

pub struct FundedConnection {
    pub conn: RelayConnection,
    pub prefix_conns: Vec<RelayConnection>,
    pub failure_rx: Option<tokio::sync::watch::Receiver<bool>>,
    pub hops: Vec<RouteHopConnection>,
}

async fn optionally_fund_session(
    conn: RelayConnection,
    wallet: Option<Arc<dyn MonadWallet>>,
    hop_label: &str,
    payment_policy: PaymentPolicy,
) -> io::Result<FundedConnection> {
    let Some(wallet) = wallet else {
        return Ok(FundedConnection {
            conn,
            prefix_conns: Vec::new(),
            failure_rx: None,
            hops: Vec::new(),
        });
    };

    info!("{hop_label}: opening funded control session");
    let (control_task, ready_rx, failure_rx) =
        session_driver::start_session_payment_driver(&conn, wallet, hop_label, payment_policy)
            .await?;
    info!("{hop_label}: waiting for funded session readiness");
    ready_rx.await.map_err(|_| {
        io::Error::new(
            io::ErrorKind::BrokenPipe,
            format!("control task exited before {hop_label} was funded"),
        )
    })?;
    info!("{hop_label}: session funded and usable");
    conn.add_task(control_task);
    Ok(FundedConnection {
        conn,
        prefix_conns: Vec::new(),
        failure_rx: Some(failure_rx),
        hops: Vec::new(),
    })
}

fn hop_display_label(hop: &RouteHop) -> String {
    match hop {
        RouteHop::Cleartext { addr, use_quic, .. } => {
            if *use_quic {
                format!("quic:{addr}")
            } else {
                addr.clone()
            }
        }
        RouteHop::Blinded { descriptor } => {
            format!("blinded:{}", descriptor.tweaked_pubkey.to_hex())
        }
    }
}

fn ensure_next_hop_capabilities(
    route: &Route,
    hop_idx: usize,
    capabilities: &BootstrapCapabilities,
) -> io::Result<()> {
    let Some(next_hop) = route.hops().get(hop_idx + 1) else {
        return Ok(());
    };

    let requirements = next_hop.previous_hop_capability_requirements();
    if requirements.is_satisfied_by(capabilities) {
        return Ok(());
    }

    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        format!(
            "hop {}/{} cannot forward to {}: relay capabilities {:?} do not satisfy {:?}",
            hop_idx + 1,
            route.hops().len(),
            hop_display_label(next_hop),
            capabilities,
            requirements,
        ),
    ))
}

async fn open_next_hop_tunnel(
    conn: &RelayConnection,
    next_hop: &RouteHop,
) -> io::Result<monad_common::h2stream::H2ConnectStream> {
    match next_hop {
        RouteHop::Cleartext {
            addr,
            pubkey,
            use_quic,
        } => {
            if *use_quic {
                conn.open_tunnel_quic_secp256k1(addr, &pubkey.to_hex())
                    .await
            } else {
                conn.open_tunnel(addr).await
            }
        }
        RouteHop::Blinded { descriptor } => {
            let request = BlindedConnectRequest::from_descriptor(descriptor);
            conn.open_tunnel_blinded_hop(&request).await
        }
    }
}

fn chain_from_stream<S>(
    mut stream: S,
    route: Route,
    hop_idx: usize,
    runtime: ConnectorRuntime,
    fund_last_hop: bool,
) -> std::pin::Pin<Box<dyn std::future::Future<Output = io::Result<FundedConnection>> + Send>>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let runtime = runtime.clone();

    Box::pin(async move {
        let hop = &route.hops()[hop_idx];
        let hop_label = hop_display_label(hop);

        info!(
            "hop {}/{}: Noise handshake with {}",
            hop_idx + 1,
            route.hops().len(),
            hop_label
        );

        let (send_cipher, recv_cipher, session_id, server_accept) =
            noise_secp256k1::handshake_initiator_with_pubkey_and_server_accept(
                &mut stream,
                hop.handshake_pubkey().to_compressed_bytes(),
            )
            .await?;
        let capabilities = server_accept.capabilities.clone();

        let noise_stream = noise_secp256k1::SecpNoiseStream::new(
            stream,
            send_cipher,
            recv_cipher,
            session_id,
            format!(
                "client hop {}/{} to {}",
                hop_idx + 1,
                route.hops().len(),
                hop_label
            ),
        );
        let (mut conn, driver) =
            RelayConnection::from_transport_stream(noise_stream, session_id).await?;
        conn.add_driver(driver);
        conn.set_cashu_spilman_protocol_version(
            server_accept.cashu_spilman_protocol_version.clone(),
        )
        .await;

        info!(
            "hop {}/{}: H2 connection established",
            hop_idx + 1,
            route.hops().len()
        );

        let funding_label = format!(
            "hop {}/{} to {}",
            hop_idx + 1,
            route.hops().len(),
            hop_label
        );
        let should_fund =
            runtime.wallet.is_some() && (hop_idx < route.hops().len() - 1 || fund_last_hop);
        let funded = optionally_fund_session(
            conn,
            if should_fund {
                runtime.wallet.clone()
            } else {
                None
            },
            &funding_label,
            runtime.payment_policy,
        )
        .await?;
        let mut conn = funded.conn;
        let funded_hop = funded.failure_rx.is_some();
        if let Some(failure_rx) = funded.failure_rx {
            conn.add_failure_watcher(hop_idx, failure_rx);
        }
        let mut hops = vec![RouteHopConnection {
            hop_idx,
            label: hop_label,
            session_id: *conn.session_id(),
            funded: funded_hop,
        }];

        if hop_idx < route.hops().len() - 1 {
            let next_hop = &route.hops()[hop_idx + 1];
            ensure_next_hop_capabilities(&route, hop_idx, &capabilities)?;

            info!(
                "hop {}/{}: opening CONNECT tunnel to next hop {}",
                hop_idx + 1,
                route.hops().len(),
                hop_display_label(next_hop)
            );

            let h2_connect_stream = open_next_hop_tunnel(&conn, next_hop).await?;

            let mut next_funded = chain_from_stream(
                h2_connect_stream,
                route.clone(),
                hop_idx + 1,
                runtime.clone(),
                fund_last_hop,
            )
            .await?;
            let mut prefix_conns = vec![conn];
            prefix_conns.append(&mut next_funded.prefix_conns);
            next_funded.prefix_conns = prefix_conns;
            hops.append(&mut next_funded.hops);
            next_funded.hops = hops;
            Ok(next_funded)
        } else {
            info!("tunnel route established ({} hops)", route.hops().len());
            Ok(FundedConnection {
                conn,
                prefix_conns: Vec::new(),
                failure_rx: None,
                hops,
            })
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use monad_common::blinded_hop::BlindedHopDescriptor;
    use monad_common::blinded_hop::BlindedHopMessage;
    use monad_common::bootstrap::initial_server_capabilities;
    use monad_common::secp_identity::SecpTransportKeypair;
    use std::time::Duration;
    use tokio::sync::watch;
    use tokio::time::{sleep, timeout};

    fn sample_pubkey(seed: u8) -> Secp256k1Pubkey {
        SecpTransportKeypair::from_secret_bytes(&[seed; 32])
            .unwrap()
            .pubkey()
    }

    fn sample_blinded_descriptor() -> BlindedHopDescriptor {
        BlindedHopDescriptor {
            tweaked_pubkey: sample_pubkey(9),
            message: BlindedHopMessage {
                ephemeral_pubkey: sample_pubkey(10).to_compressed_bytes(),
                ciphertext: vec![1, 2, 3],
            },
        }
    }

    async fn test_relay_connection(session_seed: u8) -> RelayConnection {
        let (client_io, server_io) = tokio::io::duplex(4096);
        let server_handle = tokio::spawn(async move {
            let Ok(mut h2) = h2::server::handshake(server_io).await else {
                return;
            };
            while let Some(result) = h2.accept().await {
                if result.is_err() {
                    break;
                }
            }
        });
        let (mut conn, driver) =
            RelayConnection::from_transport_stream(client_io, [session_seed; 32])
                .await
                .unwrap();
        conn.add_driver(driver);
        conn.add_task(server_handle);
        conn
    }

    async fn test_route_with_connections(conns: Vec<RelayConnection>) -> RouteConnection {
        let hop_count = conns.len();
        let mut conns = conns.into_iter().map(Arc::new).collect::<Vec<_>>();
        let final_conn = conns.pop().expect("test route requires at least one hop");
        let hops = (0..hop_count)
            .map(|hop_idx| RouteHopConnection {
                hop_idx,
                label: format!("test hop {hop_idx}"),
                session_id: [hop_idx as u8; 32],
                funded: true,
            })
            .collect();
        RouteConnection {
            final_conn,
            prefix_conns: conns,
            hops,
        }
    }

    #[tokio::test]
    async fn capability_check_hard_fails_when_next_hop_requires_missing_flag() {
        let route = Route::new(vec![
            RouteHop::Cleartext {
                addr: "127.0.0.1:9000".to_string(),
                pubkey: sample_pubkey(1),
                use_quic: true,
            },
            RouteHop::Blinded {
                descriptor: sample_blinded_descriptor(),
            },
        ])
        .unwrap();
        let mut capabilities = initial_server_capabilities();
        capabilities.blinded_connect_v1 = false;

        let err = ensure_next_hop_capabilities(&route, 0, &capabilities).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::Unsupported);
        assert!(err.to_string().contains("cannot forward"));
    }

    #[tokio::test]
    async fn wait_for_failure_returns_none_with_no_watchers() {
        let route = test_route_with_connections(vec![test_relay_connection(1).await]).await;

        let failed_hop = timeout(Duration::from_secs(1), route.wait_for_failure_owned())
            .await
            .unwrap();

        assert_eq!(failed_hop, None);
        route.close().await;
    }

    #[tokio::test]
    async fn wait_for_failure_reports_single_failed_hop() {
        let mut hop0 = test_relay_connection(1).await;
        let mut hop1 = test_relay_connection(2).await;
        let (_hop0_tx, hop0_rx) = watch::channel(false);
        let (hop1_tx, hop1_rx) = watch::channel(false);
        hop0.add_failure_watcher(0, hop0_rx);
        hop1.add_failure_watcher(1, hop1_rx);
        let route = test_route_with_connections(vec![hop0, hop1]).await;

        tokio::spawn(async move {
            sleep(Duration::from_millis(10)).await;
            let _ = hop1_tx.send(true);
        });

        let failed_hop = timeout(Duration::from_secs(1), route.wait_for_failure_owned())
            .await
            .unwrap();

        assert_eq!(failed_hop, Some(1));
        route.close().await;
    }

    #[tokio::test]
    async fn wait_for_failure_debounces_and_reports_lowest_failed_hop() {
        let mut hop0 = test_relay_connection(1).await;
        let mut hop1 = test_relay_connection(2).await;
        let (hop0_tx, hop0_rx) = watch::channel(false);
        let (hop1_tx, hop1_rx) = watch::channel(false);
        hop0.add_failure_watcher(0, hop0_rx);
        hop1.add_failure_watcher(1, hop1_rx);
        let route = test_route_with_connections(vec![hop0, hop1]).await;

        tokio::spawn(async move {
            sleep(Duration::from_millis(10)).await;
            let _ = hop1_tx.send(true);
            sleep(Duration::from_millis(10)).await;
            let _ = hop0_tx.send(true);
        });

        let failed_hop = timeout(Duration::from_secs(1), route.wait_for_failure_owned())
            .await
            .unwrap();

        assert_eq!(failed_hop, Some(0));
        route.close().await;
    }
}
