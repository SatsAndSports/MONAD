//! TCP and QUIC listener that accepts connections and performs the Noise NK handshake.

use crate::keyset_refresh::RelayKeysetRefreshCoordinator;
use crate::payments::RelayPayments;
use crate::quic_pool::QuicPool;
use crate::session::{relay_session_from_transport_stream, RelaySessionConfig};
use crate::session_registry::SessionRegistry;
use crate::wallet_manager::{cache_relay_keysets, CloseExpiringChannelsResult, RelayWalletManager};
use cashu::nuts::Id;
use cdk_spilman::configurable_host::SpilmanStorage;
use cdk_spilman::configurable_networking::{build_keyset_info_json, fetch_all_keysets_from_mint};
use monad_common::blinded_hop::derive_tweaked_responder_secret;
use monad_common::bootstrap::{
    initial_server_accept_v1, select_cashu_spilman_protocol_version, select_pricing_policy,
    BootstrapCapabilities, BootstrapV1ClientHello, BootstrapV1ServerAccept,
};
use monad_common::config::RelayChannelPolicyConfig;
use monad_common::noise_secp256k1;
use monad_common::protocol::MintUnitKeysets;
use monad_common::quic_cert_identity::QuicCertIdentity;
use monad_common::secp_identity::SecpTransportKeypair;
use monad_quic::auth::{
    reject_stream, serve_attestation_stream, AUTH_STREAM_KIND, STREAM_ERROR_AUTH_REQUIRED,
    STREAM_ERROR_UNKNOWN_KIND,
};
use monad_quic::stream::{QuicStream, STREAM_KIND_SECP_NOISE, STREAM_KIND_TWEAKED_NOISE};
use std::collections::{BTreeMap, BTreeSet};
use std::future::Future;
use std::io;
use std::str::FromStr;
use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc, RwLock,
};
use tokio::net::TcpListener;
use tokio::sync::watch;
use tokio::task::JoinSet;
use tokio::time::{Duration, Instant};
use tracing::{error, info, warn};

#[derive(Clone)]
struct QuicSessionRuntime {
    quic_pool: Option<QuicPool>,
    config: Arc<ServerConfig>,
    transport_key: SecpTransportKeypair,
    discovered_spilman_mint_cache: SharedSpilmanMintCache,
    payments: Arc<dyn RelayPayments>,
    session_registry: Arc<SessionRegistry>,
    keyset_refresh: Option<Arc<RelayKeysetRefreshCoordinator>>,
}

async fn run_quic_noise_session(
    quic_stream: QuicStream,
    responder_secret_key: [u8; 32],
    remote: std::net::SocketAddr,
    stream_id: quinn::StreamId,
    label_suffix: &str,
    runtime: QuicSessionRuntime,
) {
    let mut quic_stream = quic_stream;
    let (send_cipher, recv_cipher, session_id, bootstrap_accept) =
        match noise_secp256k1::handshake_responder_with_secret_key_bytes_and_accept_builder(
            &mut quic_stream,
            responder_secret_key,
            |hello| runtime.config.bootstrap_accept_v1(hello),
        )
        .await
        {
            Ok(v) => {
                info!("secp noise handshake complete with {remote} (QUIC {stream_id:?} {label_suffix})");
                v
            }
            Err(e) => {
                error!("secp noise handshake failed with {remote} (QUIC {stream_id:?} {label_suffix}): {e}");
                return;
            }
        };
    let secp_stream = noise_secp256k1::SecpNoiseStream::new(
        quic_stream,
        send_cipher,
        recv_cipher,
        session_id,
        format!(
            "{} <-> {remote} (QUIC {stream_id:?} {label_suffix})",
            "quic"
        ),
    );

    match relay_session_from_transport_stream(
        secp_stream,
        session_id,
        runtime.quic_pool,
        RelaySessionConfig {
            payments: runtime.payments,
            session_registry: runtime.session_registry,
            transport_key: runtime.transport_key,
            receiver_pubkey_hex: runtime.config.receiver_pubkey_hex.clone(),
            spilman_mint_cache: runtime.discovered_spilman_mint_cache,
            trusted_mint_units: runtime.config.trusted_mint_units.clone(),
            keyset_refresh: runtime.keyset_refresh,
            cashu_spilman_protocol_version: bootstrap_accept.cashu_spilman_protocol_version,
            in_bytes_per_millisat: runtime.config.in_bytes_per_millisat,
            out_bytes_per_millisat: runtime.config.out_bytes_per_millisat,
        },
    )
    .await
    {
        Ok(session) => {
            if let Err(e) = session.run().await {
                error!("session error with {remote} (QUIC {stream_id:?} {label_suffix}): {e}");
            }
        }
        Err(e) => {
            error!("H2 handshake failed with {remote} (QUIC {stream_id:?} {label_suffix}): {e}");
        }
    }
}

/// Configured trusted mint policy: mint URL -> allowed units.
pub type TrustedMintUnits = BTreeMap<String, BTreeSet<String>>;

/// Cached details for a single mint keyset.
#[derive(Debug, Clone)]
pub struct CachedKeyset {
    pub unit: String,
    pub active: bool,
    pub input_fee_ppk: u64,
    pub info_json: String,
}

/// Relay-side cached view of known mint keysets.
///
/// This is a mirror of the mint's current keyset response: it stores every
/// unit and every keyset the mint reports, active or inactive. Trusted-unit
/// and active filtering happens on demand at read sites.
#[derive(Debug, Clone, Default)]
pub struct SpilmanMintCache {
    /// Mint URL -> unit -> all known keyset IDs (active and inactive).
    pub advertised: MintUnitKeysets,
    /// Mint URL -> keyset ID -> cached keyset details.
    pub keysets: BTreeMap<String, BTreeMap<String, CachedKeyset>>,
}

impl SpilmanMintCache {
    /// All known keyset ID strings for one `(mint, unit)`.
    pub fn keyset_ids(&self, mint: &str, unit: &str) -> Vec<String> {
        self.advertised
            .get(mint)
            .and_then(|units| units.get(unit))
            .into_iter()
            .flatten()
            .cloned()
            .collect()
    }

    /// Active keyset IDs for one `(mint, unit)`.
    pub fn active_keyset_ids(&self, mint: &str, unit: &str) -> Vec<Id> {
        self.keysets
            .get(mint)
            .into_iter()
            .flatten()
            .filter(|(_, ks)| ks.unit == unit && ks.active)
            .map(|(id, _)| Id::from_str(id))
            .filter_map(Result::ok)
            .collect()
    }

    /// Keyset info JSON lookup.
    pub fn keyset_info_json(&self, mint: &str, keyset_id: &Id) -> Option<String> {
        self.keysets
            .get(mint)
            .and_then(|by_id| by_id.get(&keyset_id.to_string()))
            .map(|ks| ks.info_json.clone())
    }

    /// True if the keyset is known and belongs to a trusted unit for that mint.
    pub fn is_acceptable(
        &self,
        mint: &str,
        keyset_id: &Id,
        trusted_units: &BTreeSet<String>,
    ) -> bool {
        self.keysets
            .get(mint)
            .and_then(|by_id| by_id.get(&keyset_id.to_string()))
            .is_some_and(|ks| trusted_units.contains(&ks.unit))
    }
}

pub type SharedSpilmanMintCache = Arc<RwLock<SpilmanMintCache>>;

pub fn shared_spilman_mint_cache(cache: SpilmanMintCache) -> SharedSpilmanMintCache {
    Arc::new(RwLock::new(cache))
}

#[derive(Clone)]
pub struct RelayRuntimeServices {
    pub session_registry: Arc<SessionRegistry>,
    pub keyset_refresh: Option<Arc<RelayKeysetRefreshCoordinator>>,
}

impl RelayRuntimeServices {
    pub fn new(session_registry: Arc<SessionRegistry>) -> Self {
        Self {
            session_registry,
            keyset_refresh: None,
        }
    }
}

/// Relay configuration.
pub struct ServerConfig {
    /// The relay's Ed25519 QUIC certificate identity.
    pub identity: QuicCertIdentity,
    /// Optional shared secp256k1 transport identity for secp-authenticated transports.
    pub transport_key: Option<SecpTransportKeypair>,
    /// Receiver secp256k1 pubkey advertised in SessionStatus.
    pub receiver_pubkey_hex: String,
    /// Configured trusted mint policy.
    pub trusted_mint_units: TrustedMintUnits,
    /// Default inbound bytes per millisat for sessions on this relay.
    pub in_bytes_per_millisat: u64,
    /// Default outbound bytes per millisat for sessions on this relay.
    pub out_bytes_per_millisat: u64,
    /// Optional bootstrap capability override, primarily for tests.
    pub bootstrap_capabilities: Option<BootstrapCapabilities>,
    /// Wallet-manager relay identity name used to look up the receiver key and
    /// shared persistent payment state.
    pub relay_wallet_name: String,
    /// Path to the SQLite database used for persistent Spilman channel state.
    pub spilman_storage_path: String,
    /// Relay-side channel acceptance and expiry-maintenance policy.
    pub channel_policy: RelayChannelPolicyConfig,
}

impl ServerConfig {
    fn bootstrap_accept_v1(&self, hello: &BootstrapV1ClientHello) -> BootstrapV1ServerAccept {
        let mut accept = match &self.bootstrap_capabilities {
            Some(capabilities) => BootstrapV1ServerAccept {
                session_protocol: initial_server_accept_v1().session_protocol,
                capabilities: capabilities.clone(),
                cashu_spilman_protocol_version: None,
                pricing_policy: None,
            },
            None => initial_server_accept_v1(),
        };
        accept.cashu_spilman_protocol_version =
            select_cashu_spilman_protocol_version(&hello.cashu_spilman_protocol_versions);
        accept.pricing_policy = select_pricing_policy(&hello.pricing_policies);
        accept
    }
}

/// Discover all keyset IDs (active and inactive) for configured mints and cache
/// their keyset info JSON.
pub async fn discover_spilman_mint_cache(
    trusted_mint_units: &TrustedMintUnits,
) -> io::Result<SpilmanMintCache> {
    discover_spilman_mint_cache_with_storage(trusted_mint_units, None).await
}

/// Discover mint keysets and optionally persist the fetched keysets.
///
/// This is intended for relay startup/configured mint discovery, not per-session
/// refreshes. Normal sessions use the in-memory [`SpilmanMintCache`] created at
/// startup. All units returned by the mint are cached; trusted-unit filtering
/// happens on demand at read sites.
pub async fn discover_spilman_mint_cache_with_storage(
    trusted_mint_units: &TrustedMintUnits,
    storage: Option<&dyn SpilmanStorage>,
) -> io::Result<SpilmanMintCache> {
    let mut cache = SpilmanMintCache::default();

    for mint_url in trusted_mint_units.keys() {
        let keysets = fetch_all_keysets_from_mint(mint_url)
            .await
            .map_err(|e| io::Error::other(format!("discover keysets from {mint_url}: {e}")))?;
        if let Some(storage) = storage {
            cache_relay_keysets(storage, mint_url, &keysets)
                .map_err(|e| io::Error::other(format!("cache keysets from {mint_url}: {e}")))?;
        }

        let mut by_unit = BTreeMap::<String, Vec<String>>::new();
        let mut by_id = BTreeMap::<String, CachedKeyset>::new();
        for keyset in keysets {
            let unit = keyset.unit.to_string();
            let id = keyset.id.to_string();
            by_unit.entry(unit.clone()).or_default().push(id.clone());
            by_id.insert(
                id,
                CachedKeyset {
                    unit,
                    active: keyset.active,
                    input_fee_ppk: keyset.input_fee_ppk,
                    info_json: build_keyset_info_json(
                        &keyset.id,
                        &keyset.unit,
                        &keyset.keys,
                        keyset.input_fee_ppk,
                    ),
                },
            );
        }

        for ids in by_unit.values_mut() {
            ids.sort();
            ids.dedup();
        }

        info!(mint = %mint_url, units = ?by_unit.keys().collect::<Vec<_>>(), "discovered mint keysets");
        cache.advertised.insert(mint_url.clone(), by_unit);
        cache.keysets.insert(mint_url.clone(), by_id);
    }

    Ok(cache)
}

/// Run the relay: listen for TCP and QUIC connections, perform secp
/// Noise handshake, and handle H2 sessions.
///
/// Both TCP and QUIC connections are fed into the same H2 session handler.
/// The relay treats them identically after the secp transport is established.
///
/// Handles Ctrl+C gracefully: stops accepting new connections, waits for active
/// sessions to finish (up to a timeout), then exits. This ensures
/// `SecpNoiseStream` drop logging runs and wire byte counters are logged.
pub async fn run(
    listener: TcpListener,
    quic_endpoint: Option<quinn::Endpoint>,
    config: Arc<ServerConfig>,
) -> io::Result<()> {
    let wallet_manager = Arc::new(RelayWalletManager::open(&config.spilman_storage_path)?);
    wallet_manager
        .refresh_trusted_mint_cache(&config.trusted_mint_units)
        .await
        .map_err(io::Error::other)?;
    run_with_wallet_manager(listener, quic_endpoint, config, wallet_manager).await
}

pub async fn run_with_wallet_manager(
    listener: TcpListener,
    quic_endpoint: Option<quinn::Endpoint>,
    config: Arc<ServerConfig>,
    wallet_manager: Arc<RelayWalletManager>,
) -> io::Result<()> {
    run_with_wallet_manager_and_shutdown(listener, quic_endpoint, config, wallet_manager, async {
        let _ = tokio::signal::ctrl_c().await;
    })
    .await
}

pub async fn run_with_wallet_manager_and_shutdown<S>(
    listener: TcpListener,
    quic_endpoint: Option<quinn::Endpoint>,
    config: Arc<ServerConfig>,
    wallet_manager: Arc<RelayWalletManager>,
    shutdown: S,
) -> io::Result<()>
where
    S: Future<Output = ()> + Send,
{
    let discovered_spilman_mint_cache = wallet_manager.keyset_cache();
    let keyset_refresh = Some(Arc::new(RelayKeysetRefreshCoordinator::new(
        wallet_manager.clone(),
        config.trusted_mint_units.clone(),
    )));
    let receiver_pubkey_hex = wallet_manager.receiver_pubkey_hex(&config.relay_wallet_name)?;
    let payments = wallet_manager
        .payments_for_with_policy(&config.relay_wallet_name, config.channel_policy.clone())?;
    let config = Arc::new(ServerConfig {
        identity: QuicCertIdentity::from_seed(*config.identity.seed())
            .map_err(|e| io::Error::other(format!("clone relay identity: {e}")))?,
        transport_key: config.transport_key.clone(),
        receiver_pubkey_hex,
        trusted_mint_units: config.trusted_mint_units.clone(),
        in_bytes_per_millisat: config.in_bytes_per_millisat,
        out_bytes_per_millisat: config.out_bytes_per_millisat,
        bootstrap_capabilities: config.bootstrap_capabilities.clone(),
        relay_wallet_name: config.relay_wallet_name.clone(),
        spilman_storage_path: config.spilman_storage_path.clone(),
        channel_policy: config.channel_policy.clone(),
    });
    let auto_close_worker = spawn_expiring_channel_auto_close_worker(
        wallet_manager,
        config.relay_wallet_name.clone(),
        config
            .channel_policy
            .expiring_channels
            .close_before_expiry_secs,
        config.channel_policy.expiring_channels.auto_close.enabled,
        config
            .channel_policy
            .expiring_channels
            .auto_close
            .interval_secs,
    );

    let result = run_with_payments_and_registry_and_shutdown(
        listener,
        quic_endpoint,
        config,
        payments,
        discovered_spilman_mint_cache,
        RelayRuntimeServices {
            session_registry: Arc::new(SessionRegistry::new()),
            keyset_refresh,
        },
        shutdown,
    )
    .await;

    stop_expiring_channel_auto_close_worker(auto_close_worker).await;
    result
}

fn spawn_expiring_channel_auto_close_worker(
    wallet_manager: Arc<RelayWalletManager>,
    relay_name: String,
    close_before_expiry_secs: u64,
    enabled: bool,
    interval_secs: u64,
) -> Option<(watch::Sender<bool>, tokio::task::JoinHandle<()>)> {
    if !enabled {
        return None;
    }
    let (shutdown_tx, shutdown_rx) = watch::channel(false);
    let handle = tokio::spawn(run_expiring_channel_auto_close_worker(
        wallet_manager,
        relay_name,
        close_before_expiry_secs,
        interval_secs,
        shutdown_rx,
    ));
    Some((shutdown_tx, handle))
}

async fn stop_expiring_channel_auto_close_worker(
    worker: Option<(watch::Sender<bool>, tokio::task::JoinHandle<()>)>,
) {
    let Some((shutdown_tx, mut handle)) = worker else {
        return;
    };
    let _ = shutdown_tx.send(true);
    match tokio::time::timeout(Duration::from_secs(5), &mut handle).await {
        Ok(Ok(())) => {}
        Ok(Err(e)) => error!(error = %e, "expiring-channel auto-close worker panicked"),
        Err(_) => {
            error!("timed out waiting for expiring-channel auto-close worker to stop");
            handle.abort();
        }
    }
}

async fn run_expiring_channel_auto_close_worker(
    wallet_manager: Arc<RelayWalletManager>,
    relay_name: String,
    close_before_expiry_secs: u64,
    interval_secs: u64,
    mut shutdown: watch::Receiver<bool>,
) {
    info!(
        relay = %relay_name,
        close_before_expiry_secs,
        interval_secs,
        "expiring-channel auto-close worker started"
    );
    loop {
        if *shutdown.borrow() {
            break;
        }

        let started = Instant::now();
        match wallet_manager
            .close_expiring_channels(Some(&relay_name), now_seconds(), close_before_expiry_secs)
            .await
        {
            Ok(result) => log_expiring_channel_auto_close_result(&result, started.elapsed()),
            Err(e) => {
                error!(relay = %relay_name, error = %e, "expiring-channel auto-close sweep failed")
            }
        }

        let sleep = tokio::time::sleep(Duration::from_secs(interval_secs));
        tokio::pin!(sleep);
        tokio::select! {
            _ = &mut sleep => {}
            changed = shutdown.changed() => {
                if changed.is_err() || *shutdown.borrow() {
                    break;
                }
            }
        }
    }
    info!(relay = %relay_name, "expiring-channel auto-close worker stopped");
}

fn log_expiring_channel_auto_close_result(result: &CloseExpiringChannelsResult, elapsed: Duration) {
    for failure in &result.failures {
        warn!(
            channel_id = %failure.channel.channel_id,
            relay = %failure.channel.relay_name,
            mint = %failure.channel.mint_url,
            unit = %failure.channel.unit,
            seconds_until_expiry = failure.channel.seconds_until_expiry,
            error = %failure.error,
            "expiring-channel auto-close failed for channel"
        );
    }
    info!(
        candidates = result.candidate_count,
        closed = result.closed.len(),
        failed = result.failures.len(),
        close_before_expiry_secs = result.close_before_expiry_secs,
        elapsed_ms = elapsed.as_millis(),
        "expiring-channel auto-close sweep finished"
    );
}

fn now_seconds() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .unwrap_or(0)
}

pub async fn run_with_payments(
    listener: TcpListener,
    quic_endpoint: Option<quinn::Endpoint>,
    config: Arc<ServerConfig>,
    payments: Arc<dyn RelayPayments>,
    discovered_spilman_mint_cache: SharedSpilmanMintCache,
) -> io::Result<()> {
    run_with_payments_and_registry(
        listener,
        quic_endpoint,
        config,
        payments,
        discovered_spilman_mint_cache,
        Arc::new(SessionRegistry::new()),
    )
    .await
}

pub async fn run_with_payments_and_registry(
    listener: TcpListener,
    quic_endpoint: Option<quinn::Endpoint>,
    config: Arc<ServerConfig>,
    payments: Arc<dyn RelayPayments>,
    discovered_spilman_mint_cache: SharedSpilmanMintCache,
    session_registry: Arc<SessionRegistry>,
) -> io::Result<()> {
    run_with_payments_and_registry_and_shutdown(
        listener,
        quic_endpoint,
        config,
        payments,
        discovered_spilman_mint_cache,
        RelayRuntimeServices::new(session_registry),
        async {
            let _ = tokio::signal::ctrl_c().await;
        },
    )
    .await
}

pub async fn run_with_payments_and_registry_and_shutdown<S>(
    listener: TcpListener,
    quic_endpoint: Option<quinn::Endpoint>,
    config: Arc<ServerConfig>,
    payments: Arc<dyn RelayPayments>,
    discovered_spilman_mint_cache: SharedSpilmanMintCache,
    services: RelayRuntimeServices,
    shutdown: S,
) -> io::Result<()>
where
    S: Future<Output = ()> + Send,
{
    let mut shutdown = std::pin::pin!(shutdown);
    let transport_key = config.transport_key.clone().ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            "relay transport_key is required for secp-authenticated transport",
        )
    })?;
    let local_addr = listener.local_addr()?;
    info!("listening on {local_addr}");

    let mut sessions = JoinSet::new();

    // Create the QUIC connection pool for outbound CONNECT quic: forwarding.
    // This is separate from the QUIC endpoint (which handles inbound connections).
    let quic_pool = QuicPool::new().ok();
    // Accept loop — runs until shutdown signal
    loop {
        tokio::select! {
            result = listener.accept() => {
                let (mut tcp_stream, peer_addr) = result?;
                info!("accepted TCP connection from {peer_addr}");

                let config = config.clone();
                let transport_key = transport_key.clone();
                let quic_pool = quic_pool.clone();
                let discovered_spilman_mint_cache = discovered_spilman_mint_cache.clone();
                let payments = payments.clone();
                let services = services.clone();

                sessions.spawn(async move {
                    let (send_cipher, recv_cipher, session_id, bootstrap_accept) =
                        match noise_secp256k1::handshake_responder_with_secret_key_bytes_and_accept_builder(
                            &mut tcp_stream,
                            transport_key.normalized_secret_bytes(),
                            |hello| config.bootstrap_accept_v1(hello),
                        )
                        .await {
                            Ok(v) => {
                                info!("secp noise handshake complete with {peer_addr} (TCP)");
                                v
                            }
                            Err(e) => {
                                error!("secp noise handshake failed with {peer_addr}: {e}");
                                return;
                            }
                        };

                    let label = format!("{local_addr} <-> {peer_addr} (TCP)");
                    let secp_stream = noise_secp256k1::SecpNoiseStream::new(
                        tcp_stream,
                        send_cipher,
                        recv_cipher,
                        session_id,
                        label,
                    );

                    // Run the H2 session
                    match relay_session_from_transport_stream(
                        secp_stream,
                        session_id,
                        quic_pool,
                        RelaySessionConfig {
                            payments,
                            session_registry: services.session_registry,
                            transport_key: transport_key.clone(),
                            receiver_pubkey_hex: config.receiver_pubkey_hex.clone(),
                            spilman_mint_cache: discovered_spilman_mint_cache,
                            trusted_mint_units: config.trusted_mint_units.clone(),
                            keyset_refresh: services.keyset_refresh,
                            cashu_spilman_protocol_version: bootstrap_accept
                                .cashu_spilman_protocol_version,
                            in_bytes_per_millisat: config.in_bytes_per_millisat,
                            out_bytes_per_millisat: config.out_bytes_per_millisat,
                        },
                    )
                    .await {
                        Ok(session) => {
                            if let Err(e) = session.run().await {
                                error!("session error with {peer_addr}: {e}");
                            }
                        }
                        Err(e) => {
                            error!("H2 handshake failed with {peer_addr}: {e}");
                        }
                    }

                    info!("connection with {peer_addr} closed (TCP)");
                });

                // Reap any finished sessions (non-blocking)
                while let Some(result) = sessions.try_join_next() {
                    if let Err(e) = result {
                        error!("session task panicked: {e}");
                    }
                }
            }
            Some(incoming) = async {
                match &quic_endpoint {
                    Some(ep) => ep.accept().await,
                    None => std::future::pending().await,
                }
            } => {
                let config = config.clone();
                let transport_key = transport_key.clone();
                let quic_pool = quic_pool.clone();
                let discovered_spilman_mint_cache = discovered_spilman_mint_cache.clone();
                let payments = payments.clone();
                let services = services.clone();

                sessions.spawn(async move {
                    // Complete the QUIC connection handshake
                    let conn = match incoming.await {
                        Ok(c) => c,
                        Err(e) => {
                            error!("QUIC connection handshake failed: {e}");
                            return;
                        }
                    };
                    let remote = conn.remote_address();
                    info!("accepted QUIC connection from {remote}");
                    let authenticated = Arc::new(AtomicBool::new(false));

                    // Accept bidirectional streams from this QUIC connection.
                    // Each stream is an independent secp Noise+H2 session.
                    // Stream tasks are tracked in a per-connection JoinSet so
                    // cancelling this task (shutdown, abrupt kill) also cancels
                    // its stream sessions: JoinSet aborts on drop. Detached
                    // stream tasks would leak connections and hold the endpoint
                    // socket open.
                    let mut stream_tasks = JoinSet::new();
                    loop {
                        tokio::select! {
                            accept_result = conn.accept_bi() => {
                                match accept_result {
                                    Ok((send, recv)) => {
                                        let stream_id = send.id();
                                        info!(%remote, ?stream_id, "accepted QUIC stream");

                                let config = config.clone();
                                let transport_key = transport_key.clone();
                                let quic_pool = quic_pool.clone();
                                let discovered_spilman_mint_cache = discovered_spilman_mint_cache.clone();
                                let payments = payments.clone();
                                let services = services.clone();
                                let authenticated = authenticated.clone();
                                let conn = conn.clone();
                                stream_tasks.spawn(async move {
                                    let mut send = send;
                                    let mut recv = recv;
                                    let mut kind = [0u8; 1];
                                    if recv.read_exact(&mut kind).await.is_err() {
                                        return;
                                    }

                                    if kind[0] == AUTH_STREAM_KIND {
                                        if let Err(e) = serve_attestation_stream(
                                            &conn,
                                            &transport_key,
                                            &authenticated,
                                            &mut send,
                                            &mut recv,
                                        )
                                        .await
                                        {
                                            error!("QUIC secp256k1 auth failed with {remote} ({stream_id:?}): {e}");
                                        }
                                        return;
                                    }

                                    if kind[0] != STREAM_KIND_SECP_NOISE
                                        && kind[0] != STREAM_KIND_TWEAKED_NOISE
                                    {
                                        reject_stream(&mut send, &mut recv, STREAM_ERROR_UNKNOWN_KIND);
                                        return;
                                    }

                                    match kind[0] {
                                        STREAM_KIND_SECP_NOISE => {
                                            if !authenticated.load(Ordering::Acquire) {
                                                reject_stream(&mut send, &mut recv, STREAM_ERROR_AUTH_REQUIRED);
                                                return;
                                            }
                                            let runtime = QuicSessionRuntime {
                                                quic_pool,
                                                config,
                                                transport_key,
                                                 discovered_spilman_mint_cache,
                                                 payments,
                                                 session_registry: services.session_registry,
                                                 keyset_refresh: services.keyset_refresh,
                                             };
                                            run_quic_noise_session(
                                                QuicStream::new(send, recv),
                                                runtime.transport_key.normalized_secret_bytes(),
                                                remote,
                                                stream_id,
                                                "secp",
                                                runtime,
                                            )
                                            .await;
                                        }
                                        STREAM_KIND_TWEAKED_NOISE => {
                                            if !authenticated.load(Ordering::Acquire) {
                                                reject_stream(&mut send, &mut recv, STREAM_ERROR_AUTH_REQUIRED);
                                                return;
                                            }

                                            let mut tweak = [0u8; 32];
                                            if let Err(e) = recv.read_exact(&mut tweak).await {
                                                error!("failed to read tweaked QUIC preamble with {remote} ({stream_id:?}): {e}");
                                                return;
                                            }

                                            let responder_secret_key = match derive_tweaked_responder_secret(
                                                &transport_key,
                                                tweak,
                                            ) {
                                                Ok(secret) => secret,
                                                Err(e) => {
                                                    error!("failed to derive tweaked responder key with {remote} (QUIC {stream_id:?}): {e}");
                                                    return;
                                                }
                                            };

                                            let runtime = QuicSessionRuntime {
                                                quic_pool,
                                                config,
                                                transport_key,
                                                 discovered_spilman_mint_cache,
                                                 payments,
                                                 session_registry: services.session_registry,
                                                 keyset_refresh: services.keyset_refresh,
                                             };

                                            run_quic_noise_session(
                                                QuicStream::new(send, recv),
                                                responder_secret_key,
                                                remote,
                                                stream_id,
                                                "tweaked secp",
                                                runtime,
                                            )
                                            .await;
                                        }
                                        _ => unreachable!(),
                                    }

                                    info!("QUIC stream {stream_id:?} from {remote} closed");
                                });
                            }
                            Err(quinn::ConnectionError::ApplicationClosed(_))
                            | Err(quinn::ConnectionError::ConnectionClosed(_))
                            | Err(quinn::ConnectionError::LocallyClosed) => {
                                info!(%remote, "QUIC connection closed");
                                break;
                            }
                            Err(quinn::ConnectionError::TimedOut) => {
                                warn!(%remote, "QUIC accept_bi timed out");
                                break;
                            }
                            Err(e) => {
                                error!(%remote, error = %e, "QUIC accept_bi failed");
                                break;
                            }
                                }
                        }
                        Some(result) = stream_tasks.join_next(), if !stream_tasks.is_empty() => {
                            if let Err(e) = result {
                                error!(%remote, "QUIC stream task panicked: {e}");
                            }
                        }
                    }
                }
                });

                while let Some(result) = sessions.try_join_next() {
                    if let Err(e) = result {
                        error!("session task panicked: {e}");
                    }
                }
            }
            _ = &mut shutdown => {
                info!("shutting down (signal)...");
                break;
            }
        }
    }

    // Graceful shutdown: wait for active sessions to finish.
    let active = sessions.len();
    if active > 0 {
        info!("waiting for {active} active session(s) to finish...");

        let timeout = tokio::time::sleep(std::time::Duration::from_secs(5));
        tokio::pin!(timeout);

        loop {
            tokio::select! {
                result = sessions.join_next() => {
                    match result {
                        Some(Ok(())) => {}
                        Some(Err(e)) => error!("session task panicked: {e}"),
                        None => {
                            info!("all sessions finished");
                            break;
                        }
                    }
                }
                _ = &mut timeout => {
                    let remaining = sessions.len();
                    info!("shutdown timeout, aborting {remaining} remaining session(s)");
                    sessions.abort_all();
                    break;
                }
            }
        }
    }

    if let Some(ep) = quic_endpoint {
        ep.close(0u32.into(), b"shutdown");
    }

    info!("relay shut down");
    Ok(())
}
