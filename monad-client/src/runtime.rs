use crate::client_wallet_manager::ClientWalletManager;
use crate::config_runtime::route_from_client_config;
use crate::connector::{
    cascaded_route_failure_debounce, connect_route_with_runtime, rebuild_route_from_with_runtime,
    ConnectorRuntime,
};
use crate::session_driver::PaymentPolicy;
use crate::wallet::{MonadWallet, WalletChannelState};
use crate::{socks, tunnel};
use futures_util::{future::BoxFuture, stream::FuturesUnordered, FutureExt, StreamExt};
use monad_common::config::{ClientConfig, MonadConfig};
use monad_common::session::RelayConnection;
use std::future::Future;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use tokio::net::TcpListener;
use tokio::sync::watch;
use tokio::task::JoinSet;
use tracing::{info, warn};

const MAX_STARTUP_CONNECT_ATTEMPTS: u32 = 5;
const INITIAL_RECONNECT_BACKOFF_MS: u64 = 250;
const MAX_RECONNECT_BACKOFF_MS: u64 = 5_000;
const ROUTE_CONNECT_TIMEOUT_MS: u64 = 5_000;
const SOCKS_ROUTE_WAIT_TIMEOUT_MS: u64 = 10_000;
pub const CONFIGURED_CLIENT_WALLET_NAME: &str = "default";

#[derive(Debug, Clone, Copy)]
pub struct ConfiguredClientRuntimeOptions {
    pub route_setup_timeout: Duration,
}

impl Default for ConfiguredClientRuntimeOptions {
    fn default() -> Self {
        Self {
            route_setup_timeout: Duration::from_millis(ROUTE_CONNECT_TIMEOUT_MS),
        }
    }
}

#[derive(Debug, Default)]
struct ChannelDetachStats {
    scanned: usize,
    matched: usize,
    detached: usize,
    failed: usize,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct RouteRuntimeStatsSnapshot {
    pub route_connect_attempts_total: u64,
    pub route_connected_total: u64,
    pub route_failures_total: u64,
    pub failure_watchers_unavailable_total: u64,
    pub full_reconnects_total: u64,
    pub suffix_rebuild_attempts_total: u64,
    pub suffix_rebuild_successes_total: u64,
    pub suffix_rebuild_failures_total: u64,
    pub suffix_rebuild_fallbacks_total: u64,
}

#[derive(Debug, Clone, Default)]
pub struct SharedRouteRuntimeStats {
    inner: Arc<Mutex<RouteRuntimeStatsSnapshot>>,
}

impl SharedRouteRuntimeStats {
    pub fn snapshot(&self) -> RouteRuntimeStatsSnapshot {
        *self
            .inner
            .lock()
            .expect("route runtime stats lock poisoned")
    }

    fn record_route_connect_attempt(&self) -> RouteRuntimeStatsSnapshot {
        self.update(|stats| stats.route_connect_attempts_total += 1)
    }

    fn record_route_connected(&self) -> RouteRuntimeStatsSnapshot {
        self.update(|stats| stats.route_connected_total += 1)
    }

    fn record_failure_watcher_unavailable(&self) -> RouteRuntimeStatsSnapshot {
        self.update(|stats| {
            stats.failure_watchers_unavailable_total += 1;
            stats.full_reconnects_total += 1;
        })
    }

    fn record_failed_hop(&self, hop_idx: usize) -> (RouteFailurePath, RouteRuntimeStatsSnapshot) {
        let path = if hop_idx == 0 {
            RouteFailurePath::FullReconnect
        } else {
            RouteFailurePath::SuffixRebuild
        };
        let snapshot = self.update(|stats| {
            stats.route_failures_total += 1;
            if path == RouteFailurePath::FullReconnect {
                stats.full_reconnects_total += 1;
            }
        });
        (path, snapshot)
    }

    fn record_suffix_rebuild_attempt(&self) -> RouteRuntimeStatsSnapshot {
        self.update(|stats| stats.suffix_rebuild_attempts_total += 1)
    }

    fn record_suffix_rebuild_success(&self) -> RouteRuntimeStatsSnapshot {
        self.update(|stats| stats.suffix_rebuild_successes_total += 1)
    }

    fn record_suffix_rebuild_failure_with_fallback(&self) -> RouteRuntimeStatsSnapshot {
        self.update(|stats| {
            stats.suffix_rebuild_failures_total += 1;
            stats.suffix_rebuild_fallbacks_total += 1;
            stats.full_reconnects_total += 1;
        })
    }

    fn update(&self, f: impl FnOnce(&mut RouteRuntimeStatsSnapshot)) -> RouteRuntimeStatsSnapshot {
        let mut stats = self
            .inner
            .lock()
            .expect("route runtime stats lock poisoned");
        f(&mut stats);
        *stats
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RouteFailurePath {
    FullReconnect,
    SuffixRebuild,
}

impl RouteFailurePath {
    fn as_str(self) -> &'static str {
        match self {
            Self::FullReconnect => "full_reconnect",
            Self::SuffixRebuild => "suffix_rebuild",
        }
    }
}

/// Run all configured clients, or one selected client, until shutdown.
pub async fn run_configured_client_until_shutdown<S>(
    config: MonadConfig,
    client_name: Option<&str>,
    shutdown: S,
) -> anyhow::Result<()>
where
    S: Future<Output = ()> + Send,
{
    run_configured_client_until_shutdown_with_stats(
        config,
        client_name,
        SharedRouteRuntimeStats::default(),
        shutdown,
    )
    .await
}

/// Run a configured client with an observable in-memory stats handle.
pub async fn run_configured_client_until_shutdown_with_stats<S>(
    config: MonadConfig,
    client_name: Option<&str>,
    stats: SharedRouteRuntimeStats,
    shutdown: S,
) -> anyhow::Result<()>
where
    S: Future<Output = ()> + Send,
{
    run_configured_client_until_shutdown_with_options(
        config,
        client_name,
        stats,
        ConfiguredClientRuntimeOptions::default(),
        shutdown,
    )
    .await
}

/// Run with instance-local setup timing, without process-wide environment overrides.
pub async fn run_configured_client_until_shutdown_with_options<S>(
    config: MonadConfig,
    client_name: Option<&str>,
    stats: SharedRouteRuntimeStats,
    options: ConfiguredClientRuntimeOptions,
    shutdown: S,
) -> anyhow::Result<()>
where
    S: Future<Output = ()> + Send,
{
    run_configured_client_managed(
        config,
        client_name,
        stats,
        options,
        Default::default(),
        shutdown,
    )
    .await
}

pub async fn run_configured_client_managed<S>(
    config: MonadConfig,
    client_name: Option<&str>,
    stats: SharedRouteRuntimeStats,
    options: ConfiguredClientRuntimeOptions,
    management: std::collections::BTreeMap<String, Arc<crate::management::ClientManagement>>,
    shutdown: S,
) -> anyhow::Result<()>
where
    S: Future<Output = ()> + Send,
{
    tokio::pin!(shutdown);
    let clients = selected_clients(&config, client_name)?;
    let client_wallet = config
        .client_wallet
        .as_ref()
        .ok_or_else(|| anyhow::anyhow!("client_wallet is required to run a client"))?;
    let policy = PaymentPolicy {
        channel_funding_token_target_msats: client_wallet.channel_funding_token_target_msats,
        target_topup_buffer_msats: client_wallet.target_topup_buffer_msats,
        minimum_topup_msats: client_wallet.minimum_topup_msats,
    };
    let mut prepared_clients = Vec::with_capacity(clients.len());
    for client in clients {
        let route = route_from_client_config(&client)?;
        let listener = TcpListener::bind(&client.socks).await.map_err(|error| {
            anyhow::anyhow!("bind client '{}' at {}: {error}", client.name, client.socks)
        })?;
        prepared_clients.push(PreparedConfiguredClient {
            client,
            route,
            listener,
        });
    }
    let (manager, recovered) = ClientWalletManager::open(client_wallet)?;
    if !recovered.is_empty() {
        info!(
            recovered = recovered.recovered_channel_ids.len(),
            cancelled = recovered.cancelled_attempt_ids.len(),
            externally_spent = recovered.externally_spent_attempt_ids.len(),
            unresolved = recovered.unresolved.len(),
            "channel opening recovery outcomes"
        );
    }

    let (shutdown_tx, shutdown_rx) = watch::channel(false);
    let mut tasks = JoinSet::new();
    for prepared in prepared_clients {
        let controls = management
            .get(&prepared.client.name)
            .cloned()
            .unwrap_or_default();
        let wallet = manager.wallet();
        let stats = stats.clone();
        let shutdown_rx = shutdown_rx.clone();
        tasks.spawn(async move {
            let name = prepared.client.name.clone();
            run_configured_client_leaf(
                prepared,
                wallet,
                policy,
                stats,
                options,
                shutdown_rx,
                controls,
            )
            .await
            .map_err(|error| anyhow::anyhow!("client '{name}' failed: {error}"))
        });
    }

    let mut result = Ok(());
    tokio::select! {
        _ = &mut shutdown => {}
        joined = tasks.join_next() => {
            result = match joined {
                Some(Ok(Ok(()))) => Err(anyhow::anyhow!("configured client exited before shutdown")),
                Some(Ok(Err(error))) => Err(error),
                Some(Err(error)) => Err(anyhow::anyhow!("configured client task failed: {error}")),
                None => Err(anyhow::anyhow!("no configured client tasks were started")),
            };
        }
    }
    let _ = shutdown_tx.send(true);
    while let Some(joined) = tasks.join_next().await {
        match joined {
            Ok(Ok(())) => {}
            Ok(Err(error)) if result.is_ok() => result = Err(error),
            Err(error) if result.is_ok() => {
                result = Err(anyhow::anyhow!("configured client task failed: {error}"))
            }
            _ => {}
        }
    }
    drop(manager);
    result
}

fn selected_clients(
    config: &MonadConfig,
    client_name: Option<&str>,
) -> anyhow::Result<Vec<ClientConfig>> {
    match client_name {
        Some(name) => Ok(vec![config.select_client(Some(name))?.clone()]),
        None if config.clients.is_empty() => anyhow::bail!("config contains no clients"),
        None => Ok(config.clients.clone()),
    }
}

struct PreparedConfiguredClient {
    client: ClientConfig,
    route: crate::route::Route,
    listener: TcpListener,
}

async fn run_configured_client_leaf(
    prepared: PreparedConfiguredClient,
    wallet: Arc<dyn MonadWallet>,
    policy: PaymentPolicy,
    stats: SharedRouteRuntimeStats,
    options: ConfiguredClientRuntimeOptions,
    shutdown_rx: watch::Receiver<bool>,
    controls: Arc<crate::management::ClientManagement>,
) -> anyhow::Result<()> {
    let PreparedConfiguredClient {
        client,
        route,
        listener,
    } = prepared;
    let listener = Arc::new(listener);
    let mut process_shutdown = shutdown_rx.clone();
    let mut control_changes = controls.subscribe();
    loop {
        if *process_shutdown.borrow() {
            return Ok(());
        }
        if !controls.begin_run() {
            tokio::select! {
                result = listener.accept() => { drop(result?); }
                result = process_shutdown.changed() => { if result.is_err() { return Ok(()); } }
                _ = control_changes.changed() => {}
            }
            continue;
        }
        let runtime = ConnectorRuntime::with_payment_policy(Some(wallet.clone()), policy)?
            .with_setup_timeout(options.route_setup_timeout)
            .with_management(controls.clone());
        info!(client = %client.name, socks = %client.socks, hops = route.hops().len(), "connecting configured route");
        info!(client = %client.name, socks = %client.socks, "SOCKS5 listener ready");

        let (conn_tx, conn_rx) = watch::channel::<Option<Arc<RelayConnection>>>(None);
        let (leaf_shutdown_tx, leaf_shutdown_rx) = watch::channel(false);
        let mut disabled = controls.subscribe();
        let process_stop = shutdown_signal(shutdown_rx.clone(), leaf_shutdown_rx.clone());
        let mut manager_shutdown = Box::pin(async move {
            tokio::select! {
                _ = process_stop => {},
                _ = async {
                    loop {
                        if !disabled.borrow_and_update().enabled { break; }
                        if disabled.changed().await.is_err() { break; }
                    }
                } => {},
            }
        });
        let manager = connection_manager_loop(
            &route,
            runtime,
            wallet.clone(),
            conn_tx.clone(),
            stats.clone(),
            &mut manager_shutdown,
        );
        let listener = run_socks_listener_shared(listener.clone(), conn_rx, leaf_shutdown_rx);
        tokio::pin!(manager);
        tokio::pin!(listener);

        let result = tokio::select! {
            result = &mut manager => {
                let _ = conn_tx.send(None);
                let _ = leaf_shutdown_tx.send(true);
                let listener_result = listener.await;
                result.and(listener_result.map_err(Into::into))
            }
            listener_result = &mut listener => {
                let _ = conn_tx.send(None);
                let _ = leaf_shutdown_tx.send(true);
                let manager_result = manager.await;
                listener_result.map_err(anyhow::Error::from).and(manager_result)
            }
        };
        controls.finish_run();
        result?;
    }
}

async fn shutdown_signal(
    mut process_shutdown_rx: watch::Receiver<bool>,
    mut leaf_shutdown_rx: watch::Receiver<bool>,
) {
    loop {
        if *process_shutdown_rx.borrow() || *leaf_shutdown_rx.borrow() {
            return;
        }
        tokio::select! {
            changed = process_shutdown_rx.changed() => {
                if changed.is_err() {
                    return;
                }
            }
            changed = leaf_shutdown_rx.changed() => {
                if changed.is_err() {
                    return;
                }
            }
        }
    }
}

async fn connection_manager_loop<S>(
    route: &crate::route::Route,
    mut runtime: ConnectorRuntime,
    wallet: Arc<dyn MonadWallet>,
    conn_tx: watch::Sender<Option<Arc<RelayConnection>>>,
    stats: SharedRouteRuntimeStats,
    shutdown: &mut S,
) -> anyhow::Result<()>
where
    S: Future<Output = ()> + Send + Unpin,
{
    let mut attempt = 0u32;
    let mut backoff_ms = INITIAL_RECONNECT_BACKOFF_MS;
    // Startup connects fail fast after a bounded number of attempts so a
    // misconfigured route is loud. Once a route has connected at least once,
    // retry forever with capped backoff: transient correlated failures (e.g.
    // relay restarts, wallet top-ups) should never permanently kill the SOCKS
    // listener.
    let mut route_has_connected = false;
    let mut owned_session_ids = Vec::new();

    loop {
        if attempt > 0 {
            info!(
                attempt,
                route_has_connected,
                hops = route.hops().len(),
                backoff_ms,
                "route reconnect attempt"
            );
            if let Err(err) = runtime.reset_first_hop_quic_pool() {
                warn!("failed to reset QUIC pool before reconnect: {err}");
            } else {
                info!(attempt, "reset first-hop QUIC pool before reconnect");
            }
            // Detach only this leaf's previous route sessions. Other client
            // leaves share the wallet and may still be actively using theirs.
            let detach_stats = detach_channels_for_sessions(&wallet, &owned_session_ids);
            info!(
                attempt,
                scanned = detach_stats.scanned,
                matched = detach_stats.matched,
                detached = detach_stats.detached,
                failed = detach_stats.failed,
                "detached channels before full route reconnect"
            );
        }

        let snapshot = stats.record_route_connect_attempt();
        info!(
            attempt,
            hops = route.hops().len(),
            route_connect_attempts_total = snapshot.route_connect_attempts_total,
            full_reconnects_total = snapshot.full_reconnects_total,
            "connecting route"
        );

        let connected = tokio::select! {
            biased;
            _ = &mut *shutdown => None,
            result = connect_route_with_runtime(route, &runtime) => Some(result),
        };
        let Some(connected) = connected else {
            runtime.wait_for_setup_cleanup().await;
            return Ok(());
        };
        match connected {
            Err(err) => {
                warn!("failed to connect route: {err}");
            }
            Ok(route_conn) => {
                attempt = 0;
                backoff_ms = INITIAL_RECONNECT_BACKOFF_MS;
                route_has_connected = true;
                let mut active_route = route_conn;

                loop {
                    owned_session_ids = active_route.suffix_session_ids_from(0);
                    let hop_count = active_route.hops().len();
                    let funded_hop_count =
                        active_route.hops().iter().filter(|hop| hop.funded).count();
                    let conn = active_route.final_connection_arc();
                    let _ = conn_tx.send(Some(conn.clone()));
                    let snapshot = stats.record_route_connected();
                    info!(
                        hops = hop_count,
                        funded_hops = funded_hop_count,
                        route_connected_total = snapshot.route_connected_total,
                        "route connected; SOCKS active"
                    );

                    let failure_fut = active_route.wait_for_failure_owned();
                    tokio::pin!(failure_fut);
                    let failed_hop_idx = tokio::select! {
                        biased;
                        _ = &mut *shutdown => {
                            info!("shutting down configured client");
                            let _ = conn_tx.send(None);
                            active_route.close().await;
                            return Ok(());
                        }
                        failed_hop_idx = &mut failure_fut => failed_hop_idx,
                    };

                    let Some(hop_idx) = failed_hop_idx else {
                        let snapshot = stats.record_failure_watcher_unavailable();
                        warn!(
                            failure_watchers_unavailable_total =
                                snapshot.failure_watchers_unavailable_total,
                            full_reconnects_total = snapshot.full_reconnects_total,
                            "route failure watcher unavailable; rebuilding full route"
                        );
                        let _ = conn_tx.send(None);
                        active_route.close().await;
                        break;
                    };

                    let (failure_path, snapshot) = stats.record_failed_hop(hop_idx);
                    warn!(
                        hop = hop_idx + 1,
                        hops = hop_count,
                        funded_hops = funded_hop_count,
                        debounce_ms = cascaded_route_failure_debounce().as_millis(),
                        path = failure_path.as_str(),
                        route_failures_total = snapshot.route_failures_total,
                        full_reconnects_total = snapshot.full_reconnects_total,
                        suffix_rebuild_attempts_total = snapshot.suffix_rebuild_attempts_total,
                        suffix_rebuild_successes_total = snapshot.suffix_rebuild_successes_total,
                        suffix_rebuild_failures_total = snapshot.suffix_rebuild_failures_total,
                        "route failed at funded hop"
                    );
                    let _ = conn_tx.send(None);

                    if hop_idx == 0 {
                        warn!(
                            hop = hop_idx + 1,
                            full_reconnects_total = snapshot.full_reconnects_total,
                            "first-hop failure requires full route reconnect"
                        );
                        active_route.close().await;
                        break;
                    }

                    // Prefix sessions stay active across a suffix rebuild, so
                    // only detach channels linked to sessions that will close.
                    let preserved_hops = hop_idx;
                    let suffix_hops = hop_count - hop_idx;
                    let suffix_session_ids = active_route.suffix_session_ids_from(hop_idx);
                    let snapshot = stats.record_suffix_rebuild_attempt();
                    info!(
                        hop = hop_idx + 1,
                        preserved_hops,
                        suffix_hops,
                        suffix_sessions = suffix_session_ids.len(),
                        suffix_rebuild_attempts_total = snapshot.suffix_rebuild_attempts_total,
                        "starting route suffix rebuild"
                    );
                    active_route.close_suffix_from(hop_idx).await;
                    let detach_stats = detach_channels_for_sessions(&wallet, &suffix_session_ids);
                    info!(
                        hop = hop_idx + 1,
                        scanned = detach_stats.scanned,
                        matched = detach_stats.matched,
                        detached = detach_stats.detached,
                        failed = detach_stats.failed,
                        suffix_sessions = suffix_session_ids.len(),
                        "detached suffix channels before route rebuild"
                    );
                    let rebuild_started = Instant::now();
                    let rebuilt = tokio::select! {
                        biased;
                        _ = &mut *shutdown => None,
                        result = rebuild_route_from_with_runtime(
                        route,
                        &runtime,
                        Some(active_route),
                        hop_idx,
                        ) => Some(result),
                    };
                    let Some(rebuilt) = rebuilt else {
                        runtime.wait_for_setup_cleanup().await;
                        return Ok(());
                    };
                    match rebuilt {
                        Ok(rebuilt_route) => {
                            let snapshot = stats.record_suffix_rebuild_success();
                            info!(
                                hop = hop_idx + 1,
                                preserved_hops,
                                rebuilt_hops = suffix_hops,
                                elapsed_ms = rebuild_started.elapsed().as_millis(),
                                suffix_rebuild_attempts_total =
                                    snapshot.suffix_rebuild_attempts_total,
                                suffix_rebuild_successes_total =
                                    snapshot.suffix_rebuild_successes_total,
                                "route suffix rebuilt"
                            );
                            active_route = rebuilt_route;
                            continue;
                        }
                        Err(err) => {
                            let snapshot = stats.record_suffix_rebuild_failure_with_fallback();
                            warn!(
                                hop = hop_idx + 1,
                                preserved_hops,
                                suffix_hops,
                                elapsed_ms = rebuild_started.elapsed().as_millis(),
                                suffix_rebuild_attempts_total =
                                    snapshot.suffix_rebuild_attempts_total,
                                suffix_rebuild_failures_total =
                                    snapshot.suffix_rebuild_failures_total,
                                suffix_rebuild_fallbacks_total =
                                    snapshot.suffix_rebuild_fallbacks_total,
                                full_reconnects_total = snapshot.full_reconnects_total,
                                "route suffix rebuild failed; falling back to full route rebuild: {err}"
                            );
                            break;
                        }
                    }
                }
            }
        }

        attempt += 1;
        if !route_has_connected && attempt > MAX_STARTUP_CONNECT_ATTEMPTS {
            return Err(anyhow::anyhow!(
                "route failed before first successful connect: max startup attempts ({MAX_STARTUP_CONNECT_ATTEMPTS}) exceeded"
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

fn detach_channels_for_sessions(
    wallet: &Arc<dyn MonadWallet>,
    session_ids: &[[u8; 32]],
) -> ChannelDetachStats {
    if session_ids.is_empty() {
        return ChannelDetachStats::default();
    }

    let mut stats = ChannelDetachStats::default();
    match wallet.list_channels() {
        Ok(channels) => {
            stats.scanned = channels.len();
            for channel in channels {
                if channel.state == WalletChannelState::Open
                    && channel
                        .attached_session_id
                        .is_some_and(|session_id| session_ids.contains(&session_id))
                {
                    stats.matched += 1;
                    if let Err(err) = wallet.detach_channel_from_session(
                        &channel.channel_id,
                        channel.attached_session_id.expect("matched session"),
                    ) {
                        stats.failed += 1;
                        warn!(
                            channel_id = %channel.channel_id,
                            "failed to detach suffix channel from previous session: {err}"
                        );
                    } else {
                        stats.detached += 1;
                    }
                }
            }
        }
        Err(err) => {
            warn!("failed to list channels for suffix detach: {err}");
        }
    }
    stats
}

pub async fn run_socks_listener(
    listener: TcpListener,
    conn_rx: watch::Receiver<Option<Arc<RelayConnection>>>,
    shutdown_rx: watch::Receiver<bool>,
) -> std::io::Result<()> {
    run_socks_listener_shared(Arc::new(listener), conn_rx, shutdown_rx).await
}

async fn run_socks_listener_shared(
    listener: Arc<TcpListener>,
    conn_rx: watch::Receiver<Option<Arc<RelayConnection>>>,
    mut shutdown_rx: watch::Receiver<bool>,
) -> std::io::Result<()> {
    let mut connections: FuturesUnordered<BoxFuture<'static, std::thread::Result<()>>> =
        FuturesUnordered::new();
    let result = loop {
        if *shutdown_rx.borrow() {
            break Ok(());
        }
        // Wait for either an incoming SOCKS connection or an explicit shutdown
        // signal so the listener task can exit promptly.
        tokio::select! {
            accept_result = listener.accept() => {
                let (mut stream, peer_addr) = match accept_result {
                    Ok(accepted) => accepted,
                    Err(error) => break Err(error),
                };
                let conn_rx = conn_rx.clone();
                let shutdown_rx = shutdown_rx.clone();

                connections.push(std::panic::AssertUnwindSafe(async move {
                    let result = async {
                        // A stalled handshake must not pin a route generation.
                        let target = socks::socks5_handshake(&mut stream).await?;
                        let conn = match wait_for_active_route(conn_rx, shutdown_rx).await {
                            Some(conn) => conn,
                            None => {
                                socks::send_reply(&mut stream, 0x05, "0.0.0.0", 0).await?;
                                warn!(
                                    "SOCKS client {peer_addr} rejected: route is reconnecting"
                                );
                                return Ok(());
                            }
                        };
                        tunnel::open_tunnel(&conn, &target.authority, &mut stream).await
                    }
                    .await;
                    if let Err(err) = result {
                        warn!("SOCKS client {peer_addr} failed: {err}");
                    }
                }).catch_unwind().boxed());
            }
            Some(result) = connections.next(), if !connections.is_empty() => {
                if result.is_err() {
                    warn!("SOCKS connection future panicked");
                }
            }
            changed = shutdown_rx.changed() => {
                if changed.is_err() || *shutdown_rx.borrow() {
                    break Ok(());
                }
            }
        }
    };
    drop(connections);
    result
}

async fn wait_for_active_route(
    mut conn_rx: watch::Receiver<Option<Arc<RelayConnection>>>,
    mut shutdown_rx: watch::Receiver<bool>,
) -> Option<Arc<RelayConnection>> {
    let timeout = tokio::time::sleep(Duration::from_millis(SOCKS_ROUTE_WAIT_TIMEOUT_MS));
    tokio::pin!(timeout);

    loop {
        if *shutdown_rx.borrow() {
            return None;
        }
        if let Some(conn) = conn_rx.borrow_and_update().clone() {
            return Some(conn);
        }

        tokio::select! {
            biased;
            _ = &mut timeout => return None,
            changed = shutdown_rx.changed() => {
                if changed.is_err() || *shutdown_rx.borrow() {
                    return None;
                }
            }
            changed = conn_rx.changed() => {
                if changed.is_err() {
                    return None;
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::wallet::{MockWallet, WalletChannel};

    #[tokio::test]
    async fn stalled_socks_handshake_does_not_pin_route_and_drops_with_listener() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let (io, _peer) = tokio::io::duplex(4096);
        let (mut conn, driver) = RelayConnection::from_transport_stream(io, [1; 32])
            .await
            .unwrap();
        conn.add_driver(driver);
        let conn = Arc::new(conn);
        let (_route_tx, route_rx) = watch::channel(Some(conn.clone()));
        let (_stop_tx, stop_rx) = watch::channel(false);
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let mut socket = tokio::net::TcpStream::connect(listener.local_addr().unwrap())
            .await
            .unwrap();
        let root = tokio::spawn(run_socks_listener(listener, route_rx, stop_rx));
        socket.write_all(&[5, 1, 0]).await.unwrap();
        let mut reply = [0; 2];
        socket.read_exact(&mut reply).await.unwrap();
        assert_eq!(reply, [5, 0]);
        assert_eq!(
            Arc::strong_count(&conn),
            2,
            "stalled handshake retained route"
        );
        root.abort();
        assert!(root.await.unwrap_err().is_cancelled());
        assert_eq!(
            tokio::time::timeout(Duration::from_secs(2), socket.read(&mut reply))
                .await
                .unwrap()
                .unwrap(),
            0
        );
        conn.close().await;
    }

    #[test]
    fn route_runtime_stats_start_at_zero() {
        assert_eq!(
            SharedRouteRuntimeStats::default().snapshot(),
            RouteRuntimeStatsSnapshot::default()
        );
    }

    #[test]
    fn route_runtime_stats_record_connect_attempts() {
        let stats = SharedRouteRuntimeStats::default();

        stats.record_route_connect_attempt();
        let snapshot = stats.record_route_connect_attempt();

        assert_eq!(snapshot.route_connect_attempts_total, 2);
        assert_eq!(snapshot.full_reconnects_total, 0);
    }

    #[test]
    fn route_runtime_stats_first_hop_failure_counts_full_reconnect() {
        let stats = SharedRouteRuntimeStats::default();

        let (path, snapshot) = stats.record_failed_hop(0);

        assert_eq!(path, RouteFailurePath::FullReconnect);
        assert_eq!(snapshot.route_failures_total, 1);
        assert_eq!(snapshot.full_reconnects_total, 1);
        assert_eq!(snapshot.suffix_rebuild_attempts_total, 0);
    }

    #[test]
    fn route_runtime_stats_later_hop_failure_selects_suffix_rebuild() {
        let stats = SharedRouteRuntimeStats::default();

        let (path, snapshot) = stats.record_failed_hop(2);

        assert_eq!(path, RouteFailurePath::SuffixRebuild);
        assert_eq!(snapshot.route_failures_total, 1);
        assert_eq!(snapshot.full_reconnects_total, 0);
        assert_eq!(snapshot.suffix_rebuild_attempts_total, 0);
    }

    #[test]
    fn route_runtime_stats_suffix_rebuild_success_flow() {
        let stats = SharedRouteRuntimeStats::default();

        let (path, _) = stats.record_failed_hop(1);
        assert_eq!(path, RouteFailurePath::SuffixRebuild);
        stats.record_suffix_rebuild_attempt();
        let snapshot = stats.record_suffix_rebuild_success();

        assert_eq!(snapshot.route_failures_total, 1);
        assert_eq!(snapshot.suffix_rebuild_attempts_total, 1);
        assert_eq!(snapshot.suffix_rebuild_successes_total, 1);
        assert_eq!(snapshot.suffix_rebuild_failures_total, 0);
        assert_eq!(snapshot.full_reconnects_total, 0);
    }

    #[test]
    fn route_runtime_stats_suffix_rebuild_failure_counts_fallback() {
        let stats = SharedRouteRuntimeStats::default();

        stats.record_failed_hop(1);
        stats.record_suffix_rebuild_attempt();
        let snapshot = stats.record_suffix_rebuild_failure_with_fallback();

        assert_eq!(snapshot.route_failures_total, 1);
        assert_eq!(snapshot.suffix_rebuild_attempts_total, 1);
        assert_eq!(snapshot.suffix_rebuild_successes_total, 0);
        assert_eq!(snapshot.suffix_rebuild_failures_total, 1);
        assert_eq!(snapshot.suffix_rebuild_fallbacks_total, 1);
        assert_eq!(snapshot.full_reconnects_total, 1);
    }

    #[test]
    fn route_runtime_stats_failure_watcher_unavailable_counts_full_reconnect() {
        let stats = SharedRouteRuntimeStats::default();

        let snapshot = stats.record_failure_watcher_unavailable();

        assert_eq!(snapshot.failure_watchers_unavailable_total, 1);
        assert_eq!(snapshot.full_reconnects_total, 1);
        assert_eq!(snapshot.route_failures_total, 0);
    }

    #[test]
    fn full_reconnect_detaches_only_sessions_owned_by_that_client_leaf() {
        let wallet = Arc::new(MockWallet::new());
        for (channel_id, session_id) in [("first", [1; 32]), ("sibling", [2; 32])] {
            wallet
                .insert_channel(WalletChannel {
                    channel_id: channel_id.to_string(),
                    state: WalletChannelState::Open,
                    receiver_pubkey: "receiver".to_string(),
                    mint_url: "https://mint".to_string(),
                    unit: "msat".to_string(),
                    keyset_id: "keyset".to_string(),
                    attached_session_id: Some(session_id),
                    capacity_msats: 1_000,
                    current_signed_balance_msats: 0,
                    expiry_timestamp: u64::MAX,
                })
                .unwrap();
        }
        let shared: Arc<dyn MonadWallet> = wallet.clone();

        let stats = detach_channels_for_sessions(&shared, &[[1; 32]]);

        assert_eq!(stats.detached, 1);
        let channels = wallet.list_channels().unwrap();
        assert_eq!(
            channels
                .iter()
                .find(|channel| channel.channel_id == "first")
                .unwrap()
                .attached_session_id,
            None
        );
        assert_eq!(
            channels
                .iter()
                .find(|channel| channel.channel_id == "sibling")
                .unwrap()
                .attached_session_id,
            Some([2; 32])
        );
    }

    #[test]
    fn omitted_selector_preserves_all_clients_in_yaml_order() {
        let config = test_config_with_clients(&["first", "second"]);
        let selected = selected_clients(&config, None).unwrap();
        assert_eq!(
            selected
                .iter()
                .map(|client| client.name.as_str())
                .collect::<Vec<_>>(),
            vec!["first", "second"]
        );
    }

    #[test]
    fn selector_runs_one_named_client() {
        let config = test_config_with_clients(&["first", "second"]);
        let selected = selected_clients(&config, Some("second")).unwrap();
        assert_eq!(selected.len(), 1);
        assert_eq!(selected[0].name, "second");
    }

    #[tokio::test]
    async fn managed_disable_interrupts_setup_and_can_restart_same_listener() {
        use crate::management::ClientManagement;
        use crate::route::{Route, RouteHop};
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        use tokio::time::timeout;
        let blackhole = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let socks = listener.local_addr().unwrap();
        let management = Arc::new(ClientManagement::default());
        let route = Route::new(vec![RouteHop::Cleartext {
            addr: blackhole.local_addr().unwrap().to_string(),
            pubkey: monad_common::secp_identity::SecpTransportKeypair::generate().pubkey(),
            use_quic: false,
        }])
        .unwrap();
        let prepared = PreparedConfiguredClient {
            client: ClientConfig {
                name: "managed".into(),
                socks: socks.to_string(),
                route: vec![],
            },
            route,
            listener,
        };
        let (stop, stopped) = watch::channel(false);
        let task = tokio::spawn(run_configured_client_leaf(
            prepared,
            Arc::new(MockWallet::new()),
            PaymentPolicy::default(),
            SharedRouteRuntimeStats::default(),
            ConfiguredClientRuntimeOptions {
                route_setup_timeout: Duration::from_secs(60),
            },
            stopped,
            management.clone(),
        ));
        let (mut pending, _) = timeout(Duration::from_secs(2), blackhole.accept())
            .await
            .unwrap()
            .unwrap();
        // Consume the first Noise byte: setup has entered the real handshake.
        pending.read_exact(&mut [0]).await.unwrap();
        let mut socks_peer = tokio::net::TcpStream::connect(socks).await.unwrap();
        socks_peer.write_all(&[5, 1, 0]).await.unwrap();
        let mut greeting = [0; 2];
        timeout(Duration::from_secs(2), socks_peer.read_exact(&mut greeting))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(greeting, [5, 0]);
        management.set_enabled(false).unwrap();
        let mut changed = management.changes();
        timeout(Duration::from_secs(2), async {
            loop {
                changed.borrow_and_update();
                if !management.is_running() {
                    break;
                }
                changed.changed().await.unwrap();
            }
        })
        .await
        .unwrap();
        timeout(Duration::from_secs(2), pending.read_to_end(&mut Vec::new()))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(
            timeout(Duration::from_secs(2), socks_peer.read(&mut [0]))
                .await
                .unwrap()
                .unwrap(),
            0
        );
        management.set_enabled(true).unwrap();
        let (_new, _) = timeout(Duration::from_secs(2), blackhole.accept())
            .await
            .unwrap()
            .unwrap();
        stop.send(true).unwrap();
        timeout(Duration::from_secs(2), task)
            .await
            .unwrap()
            .unwrap()
            .unwrap();
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn multi_client_supervisor_propagates_listener_failure() {
        let occupied = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let occupied_addr = occupied.local_addr().unwrap();
        let dir = tempfile::tempdir().unwrap();
        let loose_db = dir.path().join("loose.db");
        let channel_db = dir.path().join("channels.db");
        let mut config = test_config_with_clients(&["first", "second"]);
        config.clients[1].socks = occupied_addr.to_string();
        config.client_wallet = Some(monad_common::config::ClientWalletConfig {
            funding_keyset_recovery_window_secs: 86_400,
            loose_db_path: loose_db.display().to_string(),
            channel_db_path: channel_db.display().to_string(),
            sender_secret_hex: hex::encode([9u8; 32]),
            channel_funding_token_target_msats: 1_000,
            target_topup_buffer_msats: 1_000,
            minimum_topup_msats: 1,
        });

        let result = tokio::time::timeout(
            Duration::from_secs(5),
            run_configured_client_until_shutdown_with_options(
                config,
                None,
                SharedRouteRuntimeStats::default(),
                ConfiguredClientRuntimeOptions {
                    route_setup_timeout: Duration::from_millis(100),
                },
                std::future::pending(),
            ),
        )
        .await
        .expect("supervisor should not hang")
        .unwrap_err();
        assert!(result.to_string().contains("bind client 'second'"));
        assert!(!loose_db.exists());
        assert!(!channel_db.exists());
    }

    fn test_config_with_clients(names: &[&str]) -> MonadConfig {
        let secret = monad_common::secp_identity::SecpTransportKeypair::from_secret_bytes(&[7; 32])
            .unwrap()
            .pubkey()
            .to_hex();
        let clients = names
            .iter()
            .map(|name| ClientConfig {
                name: (*name).to_string(),
                socks: "127.0.0.1:0".to_string(),
                route: vec![format!("{secret}::127.0.0.1:1").parse().unwrap()],
            })
            .collect();
        MonadConfig {
            relay_wallet: None,
            client_wallet: None,
            management: None,
            relays: Vec::new(),
            clients,
        }
    }
}
