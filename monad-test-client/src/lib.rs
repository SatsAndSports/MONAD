use anyhow::{anyhow, Result};
use monad_client::socks;
use monad_client::wallet::{MockWallet, MonadWallet, RelayPaymentOffer};
use monad_common::noise_secp256k1;
use monad_common::protocol::{ClientMessage, ServerMessage};
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

    pub fn session_ids(&self) -> Vec<Option<[u8; 32]>> {
        self.hops
            .iter()
            .map(|slot| slot.conn.as_ref().map(|conn| *conn.session_id()))
            .collect()
    }

    pub fn final_conn(&self) -> Option<Arc<RelayConnection>> {
        self.hops.last().and_then(|slot| slot.conn.clone())
    }

    pub fn is_complete(&self) -> bool {
        self.hops.iter().all(|slot| slot.conn.is_some())
    }

    pub fn first_incomplete_hop(&self) -> Option<usize> {
        self.hops.iter().position(|slot| slot.conn.is_none())
    }

    pub fn failure_is_current(&self, failure: &HopFailure) -> bool {
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

        self.invalidate_from(hop_idx).await;

        for idx in hop_idx..self.hops.len() {
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
        }

        *self.active_final_conn.write().await = self.final_conn();
        Ok(())
    }

    pub async fn rebuild_after_failure(&mut self, failure: HopFailure) -> Result<bool> {
        if !self.failure_is_current(&failure) {
            return Ok(false);
        }
        self.rebuild_from(failure.hop_idx).await?;
        Ok(true)
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
        let mut offer: Option<RelayPaymentOffer> = None;
        let mut channel_id: Option<String> = None;
        let mut funded_to_capacity = false;
        let mut last_status_received_at = Instant::now();
        let mut status_request_in_flight = false;
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
                        if let Err(err) = send_control_message(&mut h2_send, &ClientMessage::GetSessionStatus).await {
                            report_hop_failure(
                                &failure_tx,
                                hop_idx,
                                epoch,
                                format!("failed to request session status: {err}"),
                            );
                            break;
                        }
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
                    version,
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
                    ..
                } => {
                    last_status_received_at = Instant::now();
                    let pricing = SessionPricing::new(version, active_in_rate, active_out_rate);
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
                            "{hop_label} | paused={paused} remaining={}msat paid={}msat due={}msat totals(in={}, out={}) linked={}",
                            remaining_milli_sats,
                            total_paid_millisats,
                            due_now,
                            session_total_in,
                            session_total_out,
                            linked_summary,
                        );
                        status_request_in_flight = false;
                    }

                    if offer.is_none() {
                        let Some(advertisement) = advertisements.first() else {
                            report_hop_failure(
                                &failure_tx,
                                hop_idx,
                                epoch,
                                "relay advertised no payment offers",
                            );
                            break;
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
                                report_hop_failure(
                                    &failure_tx,
                                    hop_idx,
                                    epoch,
                                    format!("failed to provision mock channel: {err}"),
                                );
                                break;
                            }
                        };
                        if let Err(err) =
                            wallet.attach_channel_to_session(&new_channel_id, session_id)
                        {
                            report_hop_failure(
                                &failure_tx,
                                hop_idx,
                                epoch,
                                format!("failed to attach mock channel: {err}"),
                            );
                            break;
                        }
                        let payment_json =
                            match wallet.build_link_request(&new_channel_id, &relay_offer) {
                                Ok(payload) => payload,
                                Err(err) => {
                                    report_hop_failure(
                                        &failure_tx,
                                        hop_idx,
                                        epoch,
                                        format!("failed to build link request: {err}"),
                                    );
                                    break;
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
                        offer = Some(relay_offer);
                        channel_id = Some(new_channel_id);
                        continue;
                    }

                    let Some(current_offer) = offer.as_ref() else {
                        continue;
                    };
                    let Some(current_channel_id) = channel_id.as_ref() else {
                        continue;
                    };

                    if let Some(linked) = linked_channel {
                        if linked.channel_id == *current_channel_id && !funded_to_capacity {
                            if let Err(err) = send_payment_to_capacity(
                                &wallet,
                                current_channel_id,
                                current_offer,
                                &linked,
                                &mut h2_send,
                            )
                            .await
                            {
                                report_hop_failure(
                                    &failure_tx,
                                    hop_idx,
                                    epoch,
                                    format!("failed to fund session to capacity: {err}"),
                                );
                                break;
                            }
                            funded_to_capacity = true;
                        }
                    }

                    if funded_to_capacity && !paused {
                        if let Some(tx) = ready_tx.take() {
                            let _ = tx.send(());
                        }
                    }
                }
                ServerMessage::ChannelLinkAccepted {
                    channel_id,
                    capacity,
                } => {
                    info!("{hop_label}: linked mock channel {channel_id} (capacity={capacity})");
                }
                ServerMessage::ChannelEvicted { channel_id } => {
                    report_hop_failure(
                        &failure_tx,
                        hop_idx,
                        epoch,
                        format!("linked channel evicted: {channel_id}"),
                    );
                    break;
                }
                ServerMessage::Error { message } => {
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

async fn send_payment_to_capacity(
    wallet: &MockWallet,
    channel_id: &str,
    offer: &RelayPaymentOffer,
    linked_channel: &monad_common::protocol::LinkedChannelStatus,
    h2_send: &mut h2::SendStream<bytes::Bytes>,
) -> io::Result<()> {
    if linked_channel.balance_raw >= linked_channel.capacity_raw {
        return Ok(());
    }
    let payment_json = wallet
        .build_channel_payment(
            channel_id,
            offer,
            linked_channel.balance_raw,
            linked_channel.capacity_raw,
        )
        .map_err(|e| io::Error::other(format!("failed to build mock top-up payment: {e}")))?;
    send_control_message(h2_send, &ClientMessage::ChannelPayment { payment_json }).await
}

async fn send_control_message(
    h2_send: &mut h2::SendStream<bytes::Bytes>,
    message: &ClientMessage,
) -> io::Result<()> {
    let bytes =
        serde_json::to_vec(message).map_err(|e| io::Error::other(format!("json error: {e}")))?;
    let mut frame = Vec::with_capacity(bytes.len() + 1);
    frame.extend_from_slice(&bytes);
    frame.push(b'\n');
    h2_send.reserve_capacity(frame.len());
    monad_common::h2stream::wait_for_send_capacity(h2_send).await?;
    h2_send
        .send_data(bytes::Bytes::from(frame), false)
        .map_err(|e| io::Error::other(format!("h2 send error: {e}")))
}

async fn read_control_message(
    h2_recv: &mut h2::RecvStream,
    buf: &mut Vec<u8>,
) -> io::Result<Option<ServerMessage>> {
    loop {
        if let Some(newline_pos) = buf.iter().position(|&b| b == b'\n') {
            let line: Vec<u8> = buf.drain(..=newline_pos).collect();
            let line = line.trim_ascii();
            if line.is_empty() {
                continue;
            }
            let msg = serde_json::from_slice::<ServerMessage>(line).map_err(|e| {
                io::Error::new(io::ErrorKind::InvalidData, format!("invalid message: {e}"))
            })?;
            return Ok(Some(msg));
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
        let specs = vec![
            RelaySpec {
                addr: "127.0.0.1:1".to_string(),
                pubkey: SecpTransportKeypair::generate().pubkey(),
            },
            RelaySpec {
                addr: "127.0.0.1:2".to_string(),
                pubkey: SecpTransportKeypair::generate().pubkey(),
            },
            RelaySpec {
                addr: "127.0.0.1:3".to_string(),
                pubkey: SecpTransportKeypair::generate().pubkey(),
            },
        ];
        let (mut circuit, _) = Circuit::new(specs, CircuitConfig::default()).unwrap();

        let epochs_before = (0..circuit.hop_count())
            .map(|idx| circuit.hop_epoch(idx).unwrap())
            .collect::<Vec<_>>();

        circuit.invalidate_from(1).await;

        assert_eq!(circuit.hop_epoch(0), Some(epochs_before[0]));
        assert_eq!(circuit.hop_epoch(1), Some(epochs_before[1] + 1));
        assert_eq!(circuit.hop_epoch(2), Some(epochs_before[2] + 1));
        assert_eq!(circuit.session_ids(), vec![None, None, None]);
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
}
