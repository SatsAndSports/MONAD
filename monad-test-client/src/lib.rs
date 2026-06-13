use anyhow::{anyhow, Result};
use monad_client::socks;
use monad_client::wallet::{MockWallet, MonadWallet, RelayPaymentOffer, WalletError};
use monad_common::control_codec::{send_json_line, try_decode_json_line};
use monad_common::noise_secp256k1;
use monad_common::protocol::{ClientMessage, ServerErrorCode, ServerMessage};
use monad_common::quic_cert_identity::QuicCertIdentity;
use monad_common::secp_identity::{Secp256k1Pubkey, SecpTransportKeypair};
use monad_common::session::{RelayConnection, SessionPricing, SessionSpilmanInfo};
use monad_quic::client::ClientAuthMode;
use monad_quic::pool::QuicPool;
use monad_relay::listener::{run_with_payments_and_registry, ServerConfig, SpilmanMintCache};
use monad_relay::payments::testing::InMemoryRelayPayments;
use monad_relay::session_registry::SessionRegistry;
use std::collections::BTreeMap;
use std::io;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{mpsc, oneshot, RwLock};
use tokio::task::JoinHandle;
use tokio::time::{self, Duration, Instant};
use tracing::{info, warn};

pub const MAX_SHARED_BIND_RETRIES: usize = 32;
pub const SYNTHETIC_TEST_MINT_URL: &str = "https://test-mint.invalid";
pub const SYNTHETIC_TEST_MINT_UNIT: &str = "msat";
pub const SYNTHETIC_TEST_KEYSET_ID: &str = "00testkeyset0000";
pub const DEFAULT_MOCK_CHANNEL_CAPACITY_MSATS: u64 = 1_000_000_000_000;
pub const DEFAULT_BYTES_PER_MILLISAT: u64 = 1024 * 1024;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RelaySpec {
    pub addr: String,
    pub pubkey: Secp256k1Pubkey,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HopFailure {
    pub hop_idx: usize,
    pub epoch: u64,
    pub reason: String,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RebuildAfterFailureOutcome {
    Rebuilt,
    Stale,
    InvalidHop,
}

#[derive(Clone, Debug)]
pub struct CircuitConfig {
    pub status_interval: Option<Duration>,
    pub status_timeout: Duration,
    pub mock_channel_capacity_msats: u64,
}

impl Default for CircuitConfig {
    fn default() -> Self {
        Self {
            status_interval: Some(Duration::from_secs(5)),
            status_timeout: Duration::from_secs(15),
            mock_channel_capacity_msats: DEFAULT_MOCK_CHANNEL_CAPACITY_MSATS,
        }
    }
}

pub struct HopSlot {
    pub spec: RelaySpec,
    pub epoch: u64,
    pub conn: Option<Arc<RelayConnection>>,
}

pub struct Circuit {
    hops: Vec<HopSlot>,
    first_hop_quic_pool: QuicPool,
    config: CircuitConfig,
    active_final_conn: Arc<RwLock<Option<Arc<RelayConnection>>>>,
    failure_tx: mpsc::UnboundedSender<HopFailure>,
}

struct HopFundingState {
    offer: Option<RelayPaymentOffer>,
    channel_id: Option<String>,
    phase: HopFundingPhase,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum HopFundingPhase {
    NeedChannel,
    AwaitingLinkedStatus,
    NeedTopUp,
    Funded,
}

impl HopFundingState {
    fn new() -> Self {
        Self {
            offer: None,
            channel_id: None,
            phase: HopFundingPhase::NeedChannel,
        }
    }

    fn reset(&mut self) {
        self.offer = None;
        self.channel_id = None;
        self.phase = HopFundingPhase::NeedChannel;
    }

    fn needs_channel(&self) -> bool {
        self.offer.is_none()
            || self.channel_id.is_none()
            || matches!(self.phase, HopFundingPhase::NeedChannel)
    }

    fn set_active_channel(&mut self, offer: RelayPaymentOffer, channel_id: String) {
        self.offer = Some(offer);
        self.channel_id = Some(channel_id);
        self.phase = HopFundingPhase::AwaitingLinkedStatus;
    }

    fn active_offer(&self) -> Option<&RelayPaymentOffer> {
        self.offer.as_ref()
    }

    fn active_channel_id(&self) -> Option<&str> {
        self.channel_id.as_deref()
    }

    fn mark_needs_topup(&mut self) {
        self.phase = HopFundingPhase::NeedTopUp;
    }

    fn mark_awaiting_linked_status(&mut self) {
        self.phase = HopFundingPhase::AwaitingLinkedStatus;
    }

    fn mark_funded(&mut self) {
        self.phase = HopFundingPhase::Funded;
    }

    fn needs_topup(&self) -> bool {
        matches!(
            self.phase,
            HopFundingPhase::AwaitingLinkedStatus | HopFundingPhase::NeedTopUp
        )
    }

    fn is_funded(&self) -> bool {
        matches!(self.phase, HopFundingPhase::Funded)
    }

    fn has_active_channel(&self) -> bool {
        self.offer.is_some() && self.channel_id.is_some()
    }
}

impl Circuit {
    pub fn new(
        specs: Vec<RelaySpec>,
        config: CircuitConfig,
    ) -> io::Result<(Self, mpsc::UnboundedReceiver<HopFailure>)> {
        let (failure_tx, failure_rx) = mpsc::unbounded_channel();
        let hops = specs
            .into_iter()
            .map(|spec| HopSlot {
                spec,
                epoch: 1,
                conn: None,
            })
            .collect();
        Ok((
            Self {
                hops,
                first_hop_quic_pool: QuicPool::new()?,
                config,
                active_final_conn: Arc::new(RwLock::new(None)),
                failure_tx,
            },
            failure_rx,
        ))
    }

    pub fn active_final_conn_handle(&self) -> Arc<RwLock<Option<Arc<RelayConnection>>>> {
        self.active_final_conn.clone()
    }

    pub fn hop_count(&self) -> usize {
        self.hops.len()
    }

    pub fn hop_epoch(&self, hop_idx: usize) -> Option<u64> {
        self.hops.get(hop_idx).map(|slot| slot.epoch)
    }

    pub fn set_hop_spec(&mut self, hop_idx: usize, spec: RelaySpec) -> Result<()> {
        let slot = self
            .hops
            .get_mut(hop_idx)
            .ok_or_else(|| anyhow!("invalid hop index {hop_idx}"))?;
        slot.spec = spec;
        Ok(())
    }

    pub fn hop_session_id(&self, hop_idx: usize) -> Option<[u8; 32]> {
        self.hops
            .get(hop_idx)
            .and_then(|slot| slot.conn.as_ref().map(|conn| *conn.session_id()))
    }

    pub fn has_conn(&self, hop_idx: usize) -> bool {
        self.hops
            .get(hop_idx)
            .and_then(|slot| slot.conn.as_ref())
            .is_some()
    }

    pub fn connected_hop_prefix_len(&self) -> usize {
        self.hops
            .iter()
            .take_while(|slot| slot.conn.is_some())
            .count()
    }

    pub fn session_ids(&self) -> Vec<Option<[u8; 32]>> {
        self.hops
            .iter()
            .map(|slot| slot.conn.as_ref().map(|conn| *conn.session_id()))
            .collect()
    }

    pub fn final_conn(&self) -> Option<Arc<RelayConnection>> {
        self.hops.last().and_then(|slot| slot.conn.clone())
    }

    pub async fn active_final_conn_is_set(&self) -> bool {
        self.active_final_conn.read().await.is_some()
    }

    pub fn is_complete(&self) -> bool {
        self.hops.iter().all(|slot| slot.conn.is_some())
    }

    pub fn first_incomplete_hop(&self) -> Option<usize> {
        self.hops.iter().position(|slot| slot.conn.is_none())
    }

    #[cfg(test)]
    fn failure_is_current(&self, failure: &HopFailure) -> bool {
        self.hops
            .get(failure.hop_idx)
            .map(|slot| slot.epoch == failure.epoch)
            .unwrap_or(false)
    }

    pub async fn build_full(&mut self) -> Result<()> {
        self.rebuild_from(0).await
    }

    pub async fn invalidate_from(&mut self, hop_idx: usize) {
        if hop_idx >= self.hops.len() {
            return;
        }

        info!(
            "circuit final hop unavailable while rebuilding suffix from hop {}/{}",
            hop_idx + 1,
            self.hops.len()
        );
        *self.active_final_conn.write().await = None;

        for slot in &mut self.hops[hop_idx..] {
            slot.epoch = slot.epoch.saturating_add(1);
            if let Some(conn) = slot.conn.take() {
                conn.close().await;
            }
        }
    }

    pub async fn rebuild_from(&mut self, hop_idx: usize) -> Result<()> {
        if hop_idx >= self.hops.len() {
            return Err(anyhow!("invalid hop index {hop_idx}"));
        }

        info!(
            "starting circuit suffix rebuild from hop {}/{}",
            hop_idx + 1,
            self.hops.len()
        );
        self.invalidate_from(hop_idx).await;

        for idx in hop_idx..self.hops.len() {
            info!(
                "reconnecting hop {}/{} via {}",
                idx + 1,
                self.hops.len(),
                self.hops[idx].spec.addr
            );
            let conn = if idx == 0 {
                let stream = self
                    .first_hop_quic_pool
                    .open_stream(
                        &self.hops[idx].spec.addr,
                        ClientAuthMode::Secp256k1(self.hops[idx].spec.pubkey),
                    )
                    .await?;
                establish_hop(
                    stream,
                    &self.hops[idx].spec,
                    idx,
                    self.hops.len(),
                    self.hops[idx].epoch,
                    self.config.clone(),
                    self.failure_tx.clone(),
                )
                .await?
            } else {
                let parent = self.hops[idx - 1]
                    .conn
                    .clone()
                    .ok_or_else(|| anyhow!("missing parent hop {} for rebuild", idx - 1))?;
                let stream = parent
                    .open_tunnel_quic_secp256k1(
                        &self.hops[idx].spec.addr,
                        &self.hops[idx].spec.pubkey.to_hex(),
                    )
                    .await?;
                establish_hop(
                    stream,
                    &self.hops[idx].spec,
                    idx,
                    self.hops.len(),
                    self.hops[idx].epoch,
                    self.config.clone(),
                    self.failure_tx.clone(),
                )
                .await?
            };

            self.hops[idx].conn = Some(conn);
            info!(
                "reconnected hop {}/{} via {}",
                idx + 1,
                self.hops.len(),
                self.hops[idx].spec.addr
            );
        }

        *self.active_final_conn.write().await = self.final_conn();
        info!(
            "circuit final hop restored after rebuild from hop {}/{}",
            hop_idx + 1,
            self.hops.len()
        );
        Ok(())
    }

    pub async fn rebuild_after_failure(
        &mut self,
        failure: HopFailure,
    ) -> Result<RebuildAfterFailureOutcome> {
        let Some(slot) = self.hops.get(failure.hop_idx) else {
            return Ok(RebuildAfterFailureOutcome::InvalidHop);
        };
        if slot.epoch != failure.epoch {
            return Ok(RebuildAfterFailureOutcome::Stale);
        }
        self.rebuild_from(failure.hop_idx).await?;
        Ok(RebuildAfterFailureOutcome::Rebuilt)
    }
}

pub struct TestRelayHandle {
    bind_addr: SocketAddr,
    quic_seed: [u8; 32],
    transport_key: SecpTransportKeypair,
    pub spec: RelaySpec,
    session_registry: Arc<SessionRegistry>,
    task: Option<JoinHandle<io::Result<()>>>,
}

impl TestRelayHandle {
    pub async fn start_ephemeral() -> Result<Self> {
        let identity = QuicCertIdentity::generate()?;
        let transport_key = SecpTransportKeypair::generate();
        Self::start_with_identity("127.0.0.1:0".parse().unwrap(), identity, transport_key).await
    }

    pub async fn start_at(bind_addr: SocketAddr) -> Result<Self> {
        let identity = QuicCertIdentity::generate()?;
        let transport_key = SecpTransportKeypair::generate();
        Self::start_with_identity(bind_addr, identity, transport_key).await
    }

    async fn start_with_identity(
        bind_addr: SocketAddr,
        identity: QuicCertIdentity,
        transport_key: SecpTransportKeypair,
    ) -> Result<Self> {
        let pubkey = transport_key.pubkey();
        let (task, addr, session_registry) =
            spawn_relay_task(bind_addr, &identity, &transport_key).await?;
        Ok(Self {
            bind_addr: addr,
            quic_seed: *identity.seed(),
            transport_key,
            spec: RelaySpec {
                addr: addr.to_string(),
                pubkey,
            },
            session_registry,
            task: Some(task),
        })
    }

    pub fn addr(&self) -> SocketAddr {
        self.bind_addr
    }

    pub async fn stop(&mut self) {
        if let Some(task) = self.task.take() {
            task.abort();
            let _ = task.await;
        }
    }

    pub async fn restart(&mut self) -> Result<()> {
        self.stop().await;
        let identity = QuicCertIdentity::from_seed(self.quic_seed)?;
        let mut last_err = None;
        for _ in 0..50 {
            match spawn_relay_task(self.bind_addr, &identity, &self.transport_key).await {
                Ok((task, addr, session_registry)) => {
                    self.bind_addr = addr;
                    self.spec.addr = addr.to_string();
                    self.session_registry = session_registry;
                    self.task = Some(task);
                    return Ok(());
                }
                Err(err) => {
                    last_err = Some(err);
                    time::sleep(Duration::from_millis(50)).await;
                }
            }
        }
        Err(last_err.unwrap_or_else(|| anyhow!("relay restart failed")))
    }

    pub fn terminate_session(&self, session_id: &[u8; 32]) -> bool {
        self.session_registry.terminate(session_id)
    }

    pub fn notify_session(&self, session_id: &[u8; 32], msg: ServerMessage) -> bool {
        self.session_registry.notify(session_id, msg)
    }
}

impl Drop for TestRelayHandle {
    fn drop(&mut self) {
        if let Some(task) = self.task.take() {
            task.abort();
        }
    }
}

pub async fn start_local_relays(count: usize) -> Result<Vec<TestRelayHandle>> {
    let mut relays = Vec::with_capacity(count);
    for _ in 0..count {
        relays.push(TestRelayHandle::start_ephemeral().await?);
    }
    Ok(relays)
}

pub async fn run_socks_listener(
    listener: TcpListener,
    active_final_conn: Arc<RwLock<Option<Arc<RelayConnection>>>>,
) -> io::Result<()> {
    loop {
        let (mut stream, peer_addr) = listener.accept().await?;
        let active_final_conn = active_final_conn.clone();
        tokio::spawn(async move {
            let result = async {
                let target = socks::socks5_handshake(&mut stream).await?;
                let final_conn = active_final_conn.read().await.clone();
                let Some(final_conn) = final_conn else {
                    let _ = socks::send_reply(&mut stream, 0x01, "0.0.0.0", 0).await;
                    return Err(io::Error::other("circuit final hop unavailable"));
                };
                open_tunnel_via_connection(final_conn.as_ref(), &target.authority, &mut stream)
                    .await
            }
            .await;
            if let Err(err) = result {
                warn!("SOCKS client {peer_addr} failed: {err}");
            }
        });
    }
}

pub async fn run_fd_logger(interval: Option<Duration>) {
    let Some(interval_duration) = interval else {
        return;
    };

    let mut interval = time::interval(interval_duration);
    interval.set_missed_tick_behavior(time::MissedTickBehavior::Skip);

    loop {
        interval.tick().await;
        let fd_count = tokio::task::spawn_blocking(|| -> io::Result<usize> {
            Ok(std::fs::read_dir("/proc/self/fd")?.count())
        })
        .await;

        match fd_count {
            Ok(Ok(count)) => info!("fds | open={count}"),
            Ok(Err(err)) => warn!("failed to count open file descriptors: {err}"),
            Err(err) => {
                warn!("fd logger task failed: {err}");
                return;
            }
        }
    }
}

pub async fn open_tunnel_via_connection(
    conn: &RelayConnection,
    target_authority: &str,
    local_stream: &mut TcpStream,
) -> io::Result<()> {
    monad_client::tunnel::open_tunnel(conn, target_authority, local_stream).await
}

async fn spawn_relay_task(
    bind_addr: SocketAddr,
    identity: &QuicCertIdentity,
    transport_key: &SecpTransportKeypair,
) -> Result<(JoinHandle<io::Result<()>>, SocketAddr, Arc<SessionRegistry>)> {
    let quic_km = monad_quic::keygen::generate_from_seed(identity.seed())?;
    let quic_server_config =
        monad_quic::server::build_server_config(&quic_km.cert_pem, &quic_km.key_pem)?;
    let (listener, quic_endpoint, addr) =
        bind_tcp_and_quic_on_same_port(bind_addr, quic_server_config).await?;

    let config = Arc::new(ServerConfig {
        identity: QuicCertIdentity::from_seed(*identity.seed())?,
        transport_key: Some(transport_key.clone()),
        payment_receiver_secret: cashu::nuts::SecretKey::generate(),
        trusted_mint_units: BTreeMap::new(),
        default_in_bytes_per_millisat: DEFAULT_BYTES_PER_MILLISAT,
        default_out_bytes_per_millisat: DEFAULT_BYTES_PER_MILLISAT,
    });
    let payments = Arc::new(InMemoryRelayPayments::new());
    let synthetic_mint_cache = Arc::new(synthetic_test_mint_cache());
    let session_registry = Arc::new(SessionRegistry::new());

    Ok((
        tokio::spawn(run_with_payments_and_registry(
            listener,
            Some(quic_endpoint),
            config,
            payments,
            synthetic_mint_cache,
            session_registry.clone(),
        )),
        addr,
        session_registry,
    ))
}

fn synthetic_test_mint_cache() -> SpilmanMintCache {
    let mut advertised = BTreeMap::new();
    advertised.insert(
        SYNTHETIC_TEST_MINT_URL.to_string(),
        BTreeMap::from([(
            SYNTHETIC_TEST_MINT_UNIT.to_string(),
            vec![SYNTHETIC_TEST_KEYSET_ID.to_string()],
        )]),
    );
    SpilmanMintCache {
        advertised,
        keyset_info_json_by_mint: BTreeMap::new(),
    }
}

async fn bind_tcp_and_quic_on_same_port(
    bind_addr: SocketAddr,
    quic_server_config: quinn::ServerConfig,
) -> io::Result<(TcpListener, quinn::Endpoint, SocketAddr)> {
    let mut last_addr_in_use: Option<io::Error> = None;

    for _ in 0..MAX_SHARED_BIND_RETRIES {
        let listener = match TcpListener::bind(bind_addr).await {
            Ok(listener) => listener,
            Err(err) if err.kind() == io::ErrorKind::AddrInUse => {
                last_addr_in_use = Some(err);
                continue;
            }
            Err(err) => return Err(err),
        };

        let addr = listener.local_addr()?;
        match quinn::Endpoint::server(quic_server_config.clone(), addr) {
            Ok(quic_endpoint) => return Ok((listener, quic_endpoint, addr)),
            Err(err) if err.kind() == io::ErrorKind::AddrInUse => {
                last_addr_in_use = Some(err);
                drop(listener);
            }
            Err(err) => return Err(err),
        }
    }

    Err(last_addr_in_use.unwrap_or_else(|| {
        io::Error::other(format!(
            "failed to bind shared TCP/QUIC relay after {MAX_SHARED_BIND_RETRIES} retries"
        ))
    }))
}

async fn establish_hop<S>(
    mut stream: S,
    relay: &RelaySpec,
    hop_idx: usize,
    total_hops: usize,
    epoch: u64,
    config: CircuitConfig,
    failure_tx: mpsc::UnboundedSender<HopFailure>,
) -> Result<Arc<RelayConnection>>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let label = format!(
        "test-client hop {}/{} to {}",
        hop_idx + 1,
        total_hops,
        relay.addr
    );
    let (send_cipher, recv_cipher, session_id) =
        noise_secp256k1::handshake_initiator(&mut stream, &relay.pubkey).await?;
    let secp_stream =
        noise_secp256k1::SecpNoiseStream::new(stream, send_cipher, recv_cipher, session_id, label);
    let (mut conn, driver) =
        RelayConnection::from_transport_stream(secp_stream, session_id).await?;
    conn.add_driver(driver);
    let hop_label = format!("hop {}/{} to {}", hop_idx + 1, total_hops, relay.addr);
    let (control_task, ready_rx) =
        start_auto_control(&conn, hop_idx, epoch, hop_label.clone(), config, failure_tx).await?;
    ready_rx
        .await
        .map_err(|_| anyhow!("auto control task exited before {hop_label} became usable"))?;
    conn.add_task(control_task);
    Ok(Arc::new(conn))
}

async fn start_auto_control(
    conn: &RelayConnection,
    hop_idx: usize,
    epoch: u64,
    hop_label: String,
    config: CircuitConfig,
    failure_tx: mpsc::UnboundedSender<HopFailure>,
) -> io::Result<(JoinHandle<()>, oneshot::Receiver<()>)> {
    let (mut h2_send, mut h2_recv) = conn.open_control().await?;
    let session_id = *conn.session_id();
    let pricing_handle = conn.session_pricing_handle();
    let spilman_info_handle = conn.session_spilman_info_handle();
    let wallet = Arc::new(MockWallet::new());
    let (ready_tx, ready_rx) = oneshot::channel();

    let handle = tokio::spawn(async move {
        let mut buf = Vec::new();
        let mut ready_tx = Some(ready_tx);
        let mut funding = HopFundingState::new();
        let mut last_status_received_at = Instant::now();
        let mut last_status_requested_at: Option<Instant> = None;
        let mut was_usable = false;
        let mut status_request_in_flight = false;
        // This polling path is primarily for health checks and observability.
        // Unlike the main client, the test harness still sends periodic
        // `GetSessionStatus` requests so it can detect stalled control channels
        // and log fresh authoritative hop state while circuits stay alive.
        let mut interval = config.status_interval.map(time::interval);
        if let Some(interval) = interval.as_mut() {
            interval.set_missed_tick_behavior(time::MissedTickBehavior::Skip);
        }

        loop {
            let maybe_message = if let Some(interval) = interval.as_mut() {
                tokio::select! {
                    _ = interval.tick() => {
                        if status_request_in_flight && last_status_received_at.elapsed() >= config.status_timeout {
                            report_hop_failure(
                                &failure_tx,
                                hop_idx,
                                epoch,
                                format!("control channel timed out after {:?}", config.status_timeout),
                            );
                            break;
                        }
                        if status_request_in_flight {
                            continue;
                        }
                        info!(
                            "{hop_label}: sending health check status poll (timeout {:?})",
                            config.status_timeout
                        );
                        if let Err(err) = send_control_message(&mut h2_send, &ClientMessage::GetSessionStatus).await {
                            report_hop_failure(
                                &failure_tx,
                                hop_idx,
                                epoch,
                                format!("failed to request session status: {err}"),
                            );
                            break;
                        }
                        last_status_requested_at = Some(Instant::now());
                        status_request_in_flight = true;
                        continue;
                    }
                    result = read_control_message(&mut h2_recv, &mut buf) => result,
                }
            } else {
                read_control_message(&mut h2_recv, &mut buf).await
            };

            let message = match maybe_message {
                Ok(Some(message)) => message,
                Ok(None) => {
                    report_hop_failure(&failure_tx, hop_idx, epoch, "control stream closed");
                    break;
                }
                Err(err) => {
                    report_hop_failure(
                        &failure_tx,
                        hop_idx,
                        epoch,
                        format!("control stream error: {err}"),
                    );
                    break;
                }
            };

            match message {
                ServerMessage::SessionStatus {
                    receiver_pubkey,
                    advertisements,
                    linked_channel,
                    active_in_rate,
                    active_out_rate,
                    session_total_in,
                    session_total_out,
                    total_paid_millisats,
                    remaining_milli_sats,
                    paused,
                    open_connects,
                    total_connects,
                    ..
                } => {
                    last_status_received_at = Instant::now();
                    let pricing = SessionPricing::new(active_in_rate, active_out_rate);
                    *pricing_handle.write().await = Some(pricing);

                    if status_request_in_flight {
                        let due_now =
                            pricing.amount_due_millisats(session_total_in, session_total_out);
                        let linked_summary = linked_channel
                            .as_ref()
                            .map(|channel| {
                                format!(
                                    "{} balance_raw={} capacity_raw={} unit={}",
                                    channel.channel_id,
                                    channel.balance_raw,
                                    channel.capacity_raw,
                                    channel.unit
                                )
                            })
                            .unwrap_or_else(|| "none".to_string());
                        info!(
                            "{hop_label} | open_connects={} total_connects={} paused={paused} remaining={}msat paid={}msat due={}msat totals(in={}, out={}) linked={}",
                            open_connects,
                            total_connects,
                            remaining_milli_sats,
                            total_paid_millisats,
                            due_now,
                            session_total_in,
                            session_total_out,
                            linked_summary,
                        );
                        if let Some(started_at) = last_status_requested_at.take() {
                            info!(
                                "{hop_label}: health check status poll completed in {:?}",
                                started_at.elapsed()
                            );
                        }
                        status_request_in_flight = false;
                    }

                    if funding.needs_channel() {
                        let Some(advertisement) = advertisements.first() else {
                            warn!("{hop_label}: relay advertised no payment offers yet");
                            continue;
                        };
                        let relay_offer = RelayPaymentOffer::from_advertisement(
                            receiver_pubkey.clone(),
                            advertisement,
                        );
                        let new_channel_id = match wallet
                            .provision_channel(&relay_offer, config.mock_channel_capacity_msats)
                        {
                            Ok(id) => id,
                            Err(err) => {
                                warn!("{hop_label}: failed to provision mock channel: {err}");
                                continue;
                            }
                        };
                        if let Err(err) =
                            wallet.attach_channel_to_session(&new_channel_id, session_id)
                        {
                            warn!("{hop_label}: failed to attach mock channel: {err}");
                            continue;
                        }
                        let payment_json =
                            match wallet.build_link_request(&new_channel_id, &relay_offer) {
                                Ok(payload) => payload,
                                Err(err) => {
                                    warn!("{hop_label}: failed to build link request: {err}");
                                    continue;
                                }
                            };
                        if let Err(err) = send_control_message(
                            &mut h2_send,
                            &ClientMessage::ChannelLink { payment_json },
                        )
                        .await
                        {
                            report_hop_failure(
                                &failure_tx,
                                hop_idx,
                                epoch,
                                format!("failed to send channel link: {err}"),
                            );
                            break;
                        }
                        info!("{hop_label}: sent channel link request for new mock channel");
                        *spilman_info_handle.write().await = Some(SessionSpilmanInfo {
                            receiver_pubkey: relay_offer.receiver_pubkey.clone(),
                            mint_url: relay_offer.mint_url.clone(),
                            unit: relay_offer.unit.clone(),
                            keyset_id: relay_offer
                                .accepted_keyset_ids
                                .first()
                                .cloned()
                                .unwrap_or_default(),
                            keyset_info_json: String::new(),
                        });
                        funding.set_active_channel(relay_offer, new_channel_id);
                        continue;
                    }

                    let Some(current_offer) = funding.active_offer().cloned() else {
                        continue;
                    };
                    let Some(current_channel_id) = funding.active_channel_id().map(str::to_owned)
                    else {
                        continue;
                    };

                    if let Some(linked) = linked_channel {
                        if linked.channel_id == current_channel_id && !paused {
                            funding.mark_funded();
                        }
                        if linked.channel_id == current_channel_id && funding.needs_topup() {
                            funding.mark_needs_topup();
                            let mut payment_complete = false;
                            match build_payment_to_capacity(
                                &wallet,
                                &current_channel_id,
                                &current_offer,
                                &linked,
                            ) {
                                Ok(Some(payment_json)) => {
                                    if let Err(err) = send_control_message(
                                        &mut h2_send,
                                        &ClientMessage::ChannelPayment { payment_json },
                                    )
                                    .await
                                    {
                                        report_hop_failure(
                                            &failure_tx,
                                            hop_idx,
                                            epoch,
                                            format!("failed to send channel payment: {err}"),
                                        );
                                        break;
                                    }
                                    info!(
                                        "{hop_label}: sent channel payment to restore session balance"
                                    );
                                    funding.mark_awaiting_linked_status();
                                }
                                Ok(None) => {
                                    if paused {
                                        warn!(
                                            "{hop_label}: active channel reached capacity while session remains paused; reprovisioning"
                                        );
                                        funding.reset();
                                    } else {
                                        payment_complete = true;
                                    }
                                }
                                Err(err) => {
                                    warn!("{hop_label}: failed to build funding payment: {err}");
                                    if matches!(
                                        err,
                                        WalletError::NoNewFunds
                                            | WalletError::InsufficientCapacity { .. }
                                    ) && paused
                                    {
                                        funding.reset();
                                    }
                                }
                            }
                            if payment_complete && funding.has_active_channel() {
                                funding.mark_funded();
                            }
                        }
                    }

                    let is_usable = funding.is_funded() && !paused;
                    if is_usable && !was_usable {
                        info!("{hop_label}: hop is healthy and funded");
                    }
                    was_usable = is_usable;

                    if is_usable {
                        if let Some(tx) = ready_tx.take() {
                            let _ = tx.send(());
                        }
                    }
                }
                ServerMessage::ChannelEvicted {
                    channel_id: evicted_channel_id,
                } => {
                    warn!(
                        "{hop_label}: linked channel evicted: {evicted_channel_id}; recovering in-session"
                    );
                    funding.reset();
                }
                ServerMessage::Error { code, message } => {
                    if is_recoverable_funding_error(&code) {
                        warn!(
                            "{hop_label}: recoverable relay control error: {message}; staying on session"
                        );
                        if is_channel_resetting_error(&code) {
                            funding.reset();
                        }
                        continue;
                    }
                    report_hop_failure(
                        &failure_tx,
                        hop_idx,
                        epoch,
                        format!("relay control error: {message}"),
                    );
                    break;
                }
            }
        }

        if let Some(tx) = ready_tx.take() {
            drop(tx);
        }
    });

    Ok((handle, ready_rx))
}

fn is_channel_resetting_error(code: &ServerErrorCode) -> bool {
    matches!(
        code,
        ServerErrorCode::PaymentNoNewFunds
            | ServerErrorCode::PaymentWrongChannel
            | ServerErrorCode::PaymentUnknownChannel
            | ServerErrorCode::ChannelExpired
            | ServerErrorCode::ChannelClosed
            | ServerErrorCode::LinkReceiverMismatch
            | ServerErrorCode::LinkUnsupportedUnit
            | ServerErrorCode::LinkMintOrKeysetUnacceptable
            | ServerErrorCode::LinkNonZeroBalance
    )
}

fn is_recoverable_funding_error(code: &ServerErrorCode) -> bool {
    is_channel_resetting_error(code)
}

fn report_hop_failure(
    failure_tx: &mpsc::UnboundedSender<HopFailure>,
    hop_idx: usize,
    epoch: u64,
    reason: impl Into<String>,
) {
    let _ = failure_tx.send(HopFailure {
        hop_idx,
        epoch,
        reason: reason.into(),
    });
}

fn build_payment_to_capacity(
    wallet: &MockWallet,
    channel_id: &str,
    offer: &RelayPaymentOffer,
    linked_channel: &monad_common::protocol::LinkedChannelStatus,
) -> Result<Option<String>, WalletError> {
    if linked_channel.balance_raw >= linked_channel.capacity_raw {
        return Ok(None);
    }
    wallet
        .build_channel_payment(
            channel_id,
            offer,
            linked_channel.balance_raw,
            linked_channel.capacity_raw,
        )
        .map(Some)
}

async fn send_control_message(
    h2_send: &mut h2::SendStream<bytes::Bytes>,
    message: &ClientMessage,
) -> io::Result<()> {
    send_json_line(h2_send, message).await
}

async fn read_control_message(
    h2_recv: &mut h2::RecvStream,
    buf: &mut Vec<u8>,
) -> io::Result<Option<ServerMessage>> {
    loop {
        if let Some(message) = try_decode_json_line::<ServerMessage>(buf)? {
            return Ok(Some(message));
        }

        match h2_recv.data().await {
            Some(Ok(data)) => {
                let len = data.len();
                let _ = h2_recv.flow_control().release_capacity(len);
                buf.extend_from_slice(&data);
            }
            Some(Err(e)) => return Err(io::Error::other(format!("h2 recv error: {e}"))),
            None => return Ok(None),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn invalidate_from_bumps_epochs_and_clears_suffix_shape() {
        let relays = start_local_relays(3).await.unwrap();
        let specs = vec![
            relays[0].spec.clone(),
            relays[1].spec.clone(),
            relays[2].spec.clone(),
        ];
        let (mut circuit, _) = Circuit::new(specs, CircuitConfig::default()).unwrap();
        circuit.build_full().await.unwrap();

        let epochs_before = (0..circuit.hop_count())
            .map(|idx| circuit.hop_epoch(idx).unwrap())
            .collect::<Vec<_>>();

        circuit.invalidate_from(1).await;

        assert_eq!(circuit.hop_epoch(0), Some(epochs_before[0]));
        assert_eq!(circuit.hop_epoch(1), Some(epochs_before[1] + 1));
        assert_eq!(circuit.hop_epoch(2), Some(epochs_before[2] + 1));
        assert!(circuit.has_conn(0));
        assert!(!circuit.has_conn(1));
        assert!(!circuit.has_conn(2));
        assert_eq!(circuit.connected_hop_prefix_len(), 1);
        assert!(!circuit.is_complete());
        assert_eq!(circuit.first_incomplete_hop(), Some(1));
        assert!(circuit.final_conn().is_none());
        assert!(!circuit.active_final_conn_is_set().await);
    }

    #[tokio::test]
    async fn stale_failure_is_rejected_by_epoch() {
        let specs = vec![RelaySpec {
            addr: "127.0.0.1:1".to_string(),
            pubkey: SecpTransportKeypair::generate().pubkey(),
        }];
        let (mut circuit, _) = Circuit::new(specs, CircuitConfig::default()).unwrap();
        let original_epoch = circuit.hop_epoch(0).unwrap();
        circuit.invalidate_from(0).await;

        assert!(!circuit.failure_is_current(&HopFailure {
            hop_idx: 0,
            epoch: original_epoch,
            reason: "old".to_string(),
        }));
        assert!(circuit.failure_is_current(&HopFailure {
            hop_idx: 0,
            epoch: original_epoch + 1,
            reason: "current".to_string(),
        }));
    }

    #[tokio::test]
    async fn rebuild_after_failure_returns_stale_for_stale_epoch() {
        let relay = TestRelayHandle::start_ephemeral().await.unwrap();
        let (mut circuit, _) =
            Circuit::new(vec![relay.spec.clone()], CircuitConfig::default()).unwrap();
        circuit.build_full().await.unwrap();

        let original_epoch = circuit.hop_epoch(0).unwrap();
        let original_session_id = circuit.hop_session_id(0).unwrap();

        circuit.invalidate_from(0).await;

        let rebuilt = circuit
            .rebuild_after_failure(HopFailure {
                hop_idx: 0,
                epoch: original_epoch,
                reason: "stale".to_string(),
            })
            .await
            .unwrap();

        assert_eq!(rebuilt, RebuildAfterFailureOutcome::Stale);
        assert_eq!(circuit.hop_epoch(0), Some(original_epoch + 1));
        assert_eq!(circuit.hop_session_id(0), None);
        assert_eq!(circuit.connected_hop_prefix_len(), 0);
        assert_ne!(circuit.hop_session_id(0), Some(original_session_id));
    }

    #[tokio::test]
    async fn rebuild_after_failure_returns_rebuilt_for_current_epoch() {
        let relay = TestRelayHandle::start_ephemeral().await.unwrap();
        let (mut circuit, _) =
            Circuit::new(vec![relay.spec.clone()], CircuitConfig::default()).unwrap();
        circuit.build_full().await.unwrap();

        let original_epoch = circuit.hop_epoch(0).unwrap();
        let original_session_id = circuit.hop_session_id(0).unwrap();

        let rebuilt = circuit
            .rebuild_after_failure(HopFailure {
                hop_idx: 0,
                epoch: original_epoch,
                reason: "current".to_string(),
            })
            .await
            .unwrap();

        assert_eq!(rebuilt, RebuildAfterFailureOutcome::Rebuilt);
        assert_eq!(circuit.hop_epoch(0), Some(original_epoch + 1));
        assert!(circuit.is_complete());
        assert_eq!(circuit.connected_hop_prefix_len(), 1);
        assert!(circuit.active_final_conn_is_set().await);
        assert_ne!(circuit.hop_session_id(0), Some(original_session_id));
    }

    #[tokio::test]
    async fn rebuild_after_failure_returns_invalid_hop_for_out_of_range_failure() {
        let relay = TestRelayHandle::start_ephemeral().await.unwrap();
        let (mut circuit, _) =
            Circuit::new(vec![relay.spec.clone()], CircuitConfig::default()).unwrap();
        circuit.build_full().await.unwrap();

        let outcome = circuit
            .rebuild_after_failure(HopFailure {
                hop_idx: 1,
                epoch: 1,
                reason: "bad-hop".to_string(),
            })
            .await
            .unwrap();

        assert_eq!(outcome, RebuildAfterFailureOutcome::InvalidHop);
        assert!(circuit.is_complete());
        assert_eq!(circuit.connected_hop_prefix_len(), 1);
    }

    #[tokio::test]
    async fn rebuild_from_invalid_index_errors() {
        let specs = vec![RelaySpec {
            addr: "127.0.0.1:1".to_string(),
            pubkey: SecpTransportKeypair::generate().pubkey(),
        }];
        let (mut circuit, _) = Circuit::new(specs, CircuitConfig::default()).unwrap();

        let err = circuit.rebuild_from(1).await.unwrap_err();
        assert!(err.to_string().contains("invalid hop index 1"));
    }
}
