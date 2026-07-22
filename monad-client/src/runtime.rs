use crate::config_runtime::route_from_client_config;
use crate::connector::{
    cascaded_route_failure_debounce, connect_route_with_runtime, rebuild_route_from_with_runtime,
    ConnectorRuntime,
};
use crate::loose_proof_wallet::LooseProofWallet;
use crate::session_driver::PaymentPolicy;
use crate::sqlite_client_wallet::SqliteClientWallet;
use crate::wallet::{MonadWallet, WalletChannelState};
use crate::{socks, tunnel};
use monad_common::config::MonadConfig;
use monad_common::session::RelayConnection;
use std::future::Future;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use tokio::net::TcpListener;
use tokio::sync::watch;
use tracing::{info, warn};

const MAX_STARTUP_CONNECT_ATTEMPTS: u32 = 5;
const INITIAL_RECONNECT_BACKOFF_MS: u64 = 250;
const MAX_RECONNECT_BACKOFF_MS: u64 = 5_000;
const ROUTE_CONNECT_TIMEOUT_MS: u64 = 5_000;
pub const CONFIGURED_CLIENT_WALLET_NAME: &str = "default";

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
    tokio::pin!(shutdown);

    let client = config.select_client(client_name)?;
    let client_wallet = config
        .client_wallet
        .as_ref()
        .ok_or_else(|| anyhow::anyhow!("client_wallet is required to run a client"))?;

    let loose_wallet =
        LooseProofWallet::open(&client_wallet.loose_db_path, CONFIGURED_CLIENT_WALLET_NAME)?;
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
            target_topup_buffer_msats: client_wallet.target_topup_buffer_msats,
            minimum_topup_msats: client_wallet.minimum_topup_msats,
        },
    )?;
    let route = route_from_client_config(client)?;

    info!(
        client = %client.name,
        socks = %client.socks,
        hops = route.hops().len(),
        "connecting configured route"
    );

    let listener = TcpListener::bind(&client.socks).await?;
    info!(client = %client.name, socks = %client.socks, "SOCKS5 listener ready");

    let (conn_tx, conn_rx) = watch::channel::<Option<Arc<RelayConnection>>>(None);
    let (socks_shutdown_tx, socks_shutdown_rx) = watch::channel(false);
    let socks_task = tokio::spawn(run_socks_listener(listener, conn_rx, socks_shutdown_rx));

    let result = connection_manager_loop(
        &route,
        runtime,
        wallet,
        conn_tx.clone(),
        stats,
        &mut shutdown,
    )
    .await;

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
            // Detach any channels still linked to a previous session so the
            // next session can re-link or provision fresh channels.
            let detach_stats = detach_all_channels(&wallet);
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
            timeout_ms = ROUTE_CONNECT_TIMEOUT_MS,
            route_connect_attempts_total = snapshot.route_connect_attempts_total,
            full_reconnects_total = snapshot.full_reconnects_total,
            "connecting route"
        );

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
            Ok(Ok(route_conn)) => {
                attempt = 0;
                backoff_ms = INITIAL_RECONNECT_BACKOFF_MS;
                route_has_connected = true;
                let mut active_route = route_conn;

                loop {
                    let hop_count = active_route.hops().len();
                    let funded_hop_count =
                        active_route.hops().iter().filter(|hop| hop.funded).count();
                    let conn = active_route.final_connection_arc();
                    let _ = conn_tx.send(Some(conn.clone()));
                    info!(
                        hops = hop_count,
                        funded_hops = funded_hop_count,
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
                    match rebuild_route_from_with_runtime(
                        route,
                        &runtime,
                        Some(active_route),
                        hop_idx,
                    )
                    .await
                    {
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

fn detach_all_channels(wallet: &Arc<dyn MonadWallet>) -> ChannelDetachStats {
    let mut stats = ChannelDetachStats::default();
    match wallet.list_channels() {
        Ok(channels) => {
            stats.scanned = channels.len();
            for channel in channels {
                if channel.state == WalletChannelState::Open
                    && channel.attached_session_id.is_some()
                {
                    stats.matched += 1;
                    if let Err(err) = wallet.force_detach_channel(&channel.channel_id) {
                        stats.failed += 1;
                        warn!(
                            channel_id = %channel.channel_id,
                            "failed to detach channel from previous session: {err}"
                        );
                    } else {
                        stats.detached += 1;
                    }
                }
            }
        }
        Err(err) => {
            warn!("failed to list channels for detach: {err}");
        }
    }
    stats
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
                    if let Err(err) = wallet.force_detach_channel(&channel.channel_id) {
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

#[cfg(test)]
mod tests {
    use super::*;

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
}
