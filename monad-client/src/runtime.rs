use crate::config_runtime::route_from_client_config;
use crate::connector::{connect_route_with_runtime, ConnectorRuntime};
use crate::loose_proof_wallet::LooseProofWallet;
use crate::session_driver::PaymentPolicy;
use crate::sqlite_client_wallet::SqliteClientWallet;
use crate::wallet::{MonadWallet, WalletChannelState};
use crate::{socks, tunnel};
use monad_common::config::MonadConfig;
use monad_common::session::RelayConnection;
use std::future::Future;
use std::sync::Arc;
use std::time::Duration;
use tokio::net::TcpListener;
use tokio::sync::watch;
use tracing::{info, warn};

const MAX_RECONNECT_ATTEMPTS: u32 = 5;
const INITIAL_RECONNECT_BACKOFF_MS: u64 = 250;
const MAX_RECONNECT_BACKOFF_MS: u64 = 5_000;
const ROUTE_CONNECT_TIMEOUT_MS: u64 = 5_000;

/// Run a configured client until the shutdown signal fires or the route cannot
/// be rebuilt after the maximum number of reconnect attempts.
pub async fn run_configured_client_until_shutdown<S>(
    config: MonadConfig,
    client_name: Option<&str>,
    shutdown: S,
) -> anyhow::Result<()>
where
    S: Future<Output = ()> + Send,
{
    tokio::pin!(shutdown);

    let client = config.select_client(client_name)?;
    let client_wallet = config
        .wallets
        .client
        .as_ref()
        .ok_or_else(|| anyhow::anyhow!("wallets.client is required to run a client"))?;

    let loose_wallet =
        LooseProofWallet::open(&client_wallet.loose_db_path, &client_wallet.wallet_name)?;
    let wallet = SqliteClientWallet::open(
        loose_wallet,
        &client_wallet.channel_db_path,
        &client_wallet.sender_secret_hex,
    )?;
    let wallet: Arc<dyn MonadWallet> = Arc::new(wallet);
    let runtime = ConnectorRuntime::with_payment_policy(
        Some(wallet.clone()),
        PaymentPolicy {
            channel_input_budget_msats: client_wallet.channel_input_budget_msats,
            ..PaymentPolicy::default()
        },
    )?;
    let route = route_from_client_config(client)?;

    info!(
        client = %client.name,
        socks = %client.socks,
        hops = route.hops().len(),
        "connecting configured QUIC route"
    );

    let listener = TcpListener::bind(&client.socks).await?;
    info!(client = %client.name, socks = %client.socks, "SOCKS5 listener ready");

    let (conn_tx, conn_rx) = watch::channel::<Option<Arc<RelayConnection>>>(None);
    let (socks_shutdown_tx, socks_shutdown_rx) = watch::channel(false);
    let socks_task = tokio::spawn(run_socks_listener(listener, conn_rx, socks_shutdown_rx));

    let result =
        connection_manager_loop(&route, runtime, wallet, conn_tx.clone(), &mut shutdown).await;

    // Stop accepting SOCKS connections before tearing down tasks.
    let _ = conn_tx.send(None);
    let _ = socks_shutdown_tx.send(true);
    if let Err(err) = socks_task.await {
        warn!("SOCKS listener task failed: {err}");
    }
    result
}

async fn connection_manager_loop<S>(
    route: &crate::route::Route,
    mut runtime: ConnectorRuntime,
    wallet: Arc<dyn MonadWallet>,
    conn_tx: watch::Sender<Option<Arc<RelayConnection>>>,
    shutdown: &mut S,
) -> anyhow::Result<()>
where
    S: Future<Output = ()> + Send + Unpin,
{
    let mut attempt = 0u32;
    let mut backoff_ms = INITIAL_RECONNECT_BACKOFF_MS;

    loop {
        if attempt > 0 {
            info!("route reconnect attempt {attempt}/{MAX_RECONNECT_ATTEMPTS}");
            if let Err(err) = runtime.reset_first_hop_quic_pool() {
                warn!("failed to reset QUIC pool before reconnect: {err}");
            }
            // Detach any channels still linked to a previous session so the
            // next session can re-link or provision fresh channels.
            detach_all_channels(&wallet);
        }

        match tokio::time::timeout(
            Duration::from_millis(ROUTE_CONNECT_TIMEOUT_MS),
            connect_route_with_runtime(route, &runtime),
        )
        .await
        {
            Err(_) => {
                warn!("timed out connecting route after {ROUTE_CONNECT_TIMEOUT_MS}ms");
            }
            Ok(Err(err)) => {
                warn!("failed to connect route: {err}");
            }
            Ok(Ok(conn)) => {
                attempt = 0;
                backoff_ms = INITIAL_RECONNECT_BACKOFF_MS;
                let conn = Arc::new(conn);
                let _ = conn_tx.send(Some(conn.clone()));
                info!("route connected; SOCKS active");

                let failure_fut = conn.wait_for_failure();
                tokio::pin!(failure_fut);
                tokio::select! {
                    biased;
                    _ = &mut *shutdown => {
                        info!("shutting down configured client");
                        let _ = conn_tx.send(None);
                        conn.close().await;
                        return Ok(());
                    }
                    _ = &mut failure_fut => {
                        warn!("route failed; rebuilding");
                        let _ = conn_tx.send(None);
                        conn.close().await;
                    }
                }
            }
        }

        attempt += 1;
        if attempt > MAX_RECONNECT_ATTEMPTS {
            return Err(anyhow::anyhow!(
                "route failed and max reconnect attempts ({MAX_RECONNECT_ATTEMPTS}) exceeded"
            ));
        }

        info!("reconnecting in {backoff_ms}ms");
        tokio::select! {
            biased;
            _ = &mut *shutdown => {
                info!("shutting down configured client during reconnect backoff");
                return Ok(());
            }
            _ = tokio::time::sleep(Duration::from_millis(backoff_ms)) => {}
        }
        backoff_ms = (backoff_ms * 2).min(MAX_RECONNECT_BACKOFF_MS);
    }
}

fn detach_all_channels(wallet: &Arc<dyn MonadWallet>) {
    match wallet.list_channels() {
        Ok(channels) => {
            for channel in channels {
                if channel.state == WalletChannelState::Open
                    && channel.attached_session_id.is_some()
                {
                    if let Err(err) = wallet.force_detach_channel(&channel.channel_id) {
                        warn!(
                            channel_id = %channel.channel_id,
                            "failed to detach channel from previous session: {err}"
                        );
                    }
                }
            }
        }
        Err(err) => {
            warn!("failed to list channels for detach: {err}");
        }
    }
}

pub async fn run_socks_listener(
    listener: TcpListener,
    mut conn_rx: watch::Receiver<Option<Arc<RelayConnection>>>,
    mut shutdown_rx: watch::Receiver<bool>,
) -> std::io::Result<()> {
    loop {
        // Wait for either an incoming SOCKS connection or an explicit shutdown
        // signal so the listener task can exit promptly.
        tokio::select! {
            accept_result = listener.accept() => {
                let (mut stream, peer_addr) = accept_result?;

                // If there is no active route (reconnecting), fail the SOCKS request
                // immediately so the application can retry.
                let conn = match conn_rx.borrow_and_update().clone() {
                    Some(conn) => conn,
                    None => {
                        tokio::spawn(async move {
                            let _ = socks::reject_socks5_connect_unavailable(&mut stream).await;
                            warn!(
                                "SOCKS client {peer_addr} rejected: route is reconnecting"
                            );
                        });
                        continue;
                    }
                };

                tokio::spawn(async move {
                    let result = async {
                        let target = socks::socks5_handshake(&mut stream).await?;
                        tunnel::open_tunnel(&conn, &target.authority, &mut stream).await
                    }
                    .await;
                    if let Err(err) = result {
                        warn!("SOCKS client {peer_addr} failed: {err}");
                    }
                });
            }
            changed = shutdown_rx.changed() => {
                if changed.is_err() || *shutdown_rx.borrow() {
                    // Sender dropped or explicit shutdown.
                    return Ok(());
                }
            }
        }
    }
}
