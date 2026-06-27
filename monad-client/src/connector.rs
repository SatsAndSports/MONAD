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
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::TcpStream;
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

pub struct RouteConnection {
    final_conn: RelayConnection,
    prefix_conns: Vec<RelayConnection>,
    hops: Vec<RouteHopConnection>,
}

impl RouteConnection {
    pub fn final_connection(&self) -> &RelayConnection {
        &self.final_conn
    }

    pub fn into_final_connection(self) -> RelayConnection {
        let mut final_conn = self.final_conn;
        for mut prefix_conn in self.prefix_conns {
            final_conn.absorb_handles_from(&mut prefix_conn);
        }
        final_conn
    }

    pub fn hops(&self) -> &[RouteHopConnection] {
        &self.hops
    }
}

pub async fn connect(
    relay_addr: &str,
    relay_pubkey: Secp256k1Pubkey,
) -> io::Result<RelayConnection> {
    let route = Route::new(vec![RouteHop::Cleartext {
        addr: relay_addr.to_string(),
        pubkey: relay_pubkey,
        use_quic: false,
    }])?;
    let runtime = ConnectorRuntime::with_mock_wallet()?;
    connect_route_internal(&route, runtime, false)
        .await
        .map(RouteConnection::into_final_connection)
}

pub async fn connect_route(route: &Route) -> io::Result<RelayConnection> {
    let runtime = ConnectorRuntime::with_mock_wallet()?;
    connect_route_internal(route, runtime, false)
        .await
        .map(RouteConnection::into_final_connection)
}

pub async fn connect_route_with_wallet(
    route: &Route,
    wallet: Option<Arc<dyn MonadWallet>>,
) -> io::Result<RelayConnection> {
    let runtime = ConnectorRuntime::new(wallet)?;
    connect_route_internal(route, runtime, true)
        .await
        .map(RouteConnection::into_final_connection)
}

pub async fn connect_route_with_runtime(
    route: &Route,
    runtime: &ConnectorRuntime,
) -> io::Result<RelayConnection> {
    connect_route_connection_with_runtime(route, runtime)
        .await
        .map(RouteConnection::into_final_connection)
}

pub async fn connect_route_connection_with_runtime(
    route: &Route,
    runtime: &ConnectorRuntime,
) -> io::Result<RouteConnection> {
    connect_route_internal(route, runtime.clone(), true).await
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
    Ok(RouteConnection {
        final_conn: funded.conn,
        prefix_conns: funded.prefix_conns,
        hops: funded.hops,
    })
}

pub struct FundedConnection {
    pub conn: RelayConnection,
    pub prefix_conns: Vec<RelayConnection>,
    pub failure_rx: Option<tokio::sync::watch::Receiver<bool>>,
    pub hops: Vec<RouteHopConnection>,
}

async fn optionally_fund_session(
    mut conn: RelayConnection,
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

    #[test]
    fn capability_check_hard_fails_when_next_hop_requires_missing_flag() {
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
}
