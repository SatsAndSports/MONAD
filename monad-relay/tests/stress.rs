use monad_client::route::RouteHop;
use monad_client::wallet::{MockWallet, MonadWallet, RelayPaymentOffer};
use monad_common::control_codec::{send_json_line, try_decode_json_line};
use monad_common::noise_secp256k1;
use monad_common::payment_units::msats_to_raw_units;
use monad_common::protocol::{ClientMessage, ServerErrorCode, ServerMessage};
use monad_common::quic_cert_identity::QuicCertIdentity;
use monad_common::secp_identity::{Secp256k1Pubkey, SecpTransportKeypair};
use monad_common::session::RelayConnection;
use monad_quic::client::ClientAuthMode;
use monad_quic::pool::QuicPool;
use monad_relay::listener::{
    run_with_payments, shared_spilman_mint_cache, CachedKeyset, ServerConfig, SpilmanMintCache,
};
use monad_relay::payments::testing::InMemoryRelayPayments;
use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::env;
use std::io;
use std::io::Write;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::Arc;
use std::sync::OnceLock;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio::sync::oneshot;
use tokio::task::JoinSet;
use tokio::time::Duration;
use tokio::time::Instant;

const MAX_SHARED_BIND_RETRIES: usize = 32;
const SYNTHETIC_TEST_MINT_URL: &str = "https://test-mint.invalid";
const SYNTHETIC_TEST_MINT_UNIT: &str = "msat";
const SYNTHETIC_TEST_KEYSET_ID: &str = "00testkeyset0000";
const STRESS_CHANNEL_CAPACITY_MSATS: u64 = 1_000_000_000_000;
const DEFAULT_PAYMENT_STATUS_POLL_MS: u64 = 100;
const DEFAULT_INITIAL_PAYMENT_MSATS: u64 = 100_000;
const DEFAULT_PAYMENT_CHUNK_MSATS: u64 = 100_000;
const DEFAULT_TARGET_BUFFER_MSATS: u64 = 20_000;

fn hop_label(hop: &RouteHop) -> &str {
    match hop {
        RouteHop::Cleartext { addr, .. } => addr,
        RouteHop::Blinded { .. } => "blinded",
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum StressPaymentMode {
    Transport,
    Buffered,
    RelinkBuffered,
}

impl StressPaymentMode {
    fn from_env() -> Self {
        match env::var("MONAD_STRESS_PAYMENT_MODE")
            .ok()
            .as_deref()
            .unwrap_or("transport")
        {
            "transport" => Self::Transport,
            "buffered" => Self::Buffered,
            "relink-buffered" => Self::RelinkBuffered,
            other => panic!("unsupported MONAD_STRESS_PAYMENT_MODE={other}"),
        }
    }

    fn as_str(self) -> &'static str {
        match self {
            Self::Transport => "transport",
            Self::Buffered => "buffered",
            Self::RelinkBuffered => "relink-buffered",
        }
    }
}

#[derive(Debug, Clone, Copy)]
struct StressPaymentConfig {
    mode: StressPaymentMode,
    channel_capacity_msats: u64,
    initial_payment_msats: u64,
    payment_chunk_msats: u64,
    target_buffer_msats: u64,
    status_poll_interval: Duration,
}

impl StressPaymentConfig {
    fn from_env() -> Self {
        Self {
            mode: StressPaymentMode::from_env(),
            channel_capacity_msats: read_env_u64(
                "MONAD_STRESS_CHANNEL_CAPACITY_MSATS",
                STRESS_CHANNEL_CAPACITY_MSATS,
            ),
            initial_payment_msats: read_env_u64(
                "MONAD_STRESS_INITIAL_PAYMENT_MSATS",
                DEFAULT_INITIAL_PAYMENT_MSATS,
            ),
            payment_chunk_msats: read_env_u64(
                "MONAD_STRESS_PAYMENT_CHUNK_MSATS",
                DEFAULT_PAYMENT_CHUNK_MSATS,
            ),
            target_buffer_msats: read_env_u64(
                "MONAD_STRESS_TARGET_BUFFER_MSATS",
                DEFAULT_TARGET_BUFFER_MSATS,
            ),
            status_poll_interval: Duration::from_millis(read_env_u64(
                "MONAD_STRESS_PAYMENT_STATUS_POLL_MS",
                DEFAULT_PAYMENT_STATUS_POLL_MS,
            )),
        }
    }
}

#[derive(Default)]
struct PaymentStats {
    sessions_linked: AtomicU64,
    channel_links_total: AtomicU64,
    channel_relinks_total: AtomicU64,
    sessions_relinked_once: AtomicU64,
    max_links_on_one_session: AtomicU64,
    channel_link_failures: AtomicU64,
    initial_payments: AtomicU64,
    topups_total: AtomicU64,
    topups_proactive: AtomicU64,
    topups_reactive: AtomicU64,
    sessions_paused_once: AtomicU64,
    pause_events: AtomicU64,
    startup_unpauses: AtomicU64,
    recovery_unpause_events: AtomicU64,
    status_polls_sent: AtomicU64,
    status_updates_seen: AtomicU64,
    payment_no_new_funds: AtomicU64,
    control_errors: AtomicU64,
    channels_abandoned_due_to_capacity: AtomicU64,
    channels_abandoned_not_at_capacity: AtomicU64,
}

#[derive(Debug, Default, Clone, Copy)]
struct PaymentStatsSnapshot {
    sessions_linked: u64,
    channel_links_total: u64,
    channel_relinks_total: u64,
    sessions_relinked_once: u64,
    max_links_on_one_session: u64,
    channel_link_failures: u64,
    initial_payments: u64,
    topups_total: u64,
    topups_proactive: u64,
    topups_reactive: u64,
    sessions_paused_once: u64,
    pause_events: u64,
    startup_unpauses: u64,
    recovery_unpause_events: u64,
    status_polls_sent: u64,
    status_updates_seen: u64,
    payment_no_new_funds: u64,
    control_errors: u64,
    channels_abandoned_due_to_capacity: u64,
    channels_abandoned_not_at_capacity: u64,
}

impl PaymentStats {
    fn snapshot(&self) -> PaymentStatsSnapshot {
        PaymentStatsSnapshot {
            sessions_linked: self.sessions_linked.load(Ordering::Relaxed),
            channel_links_total: self.channel_links_total.load(Ordering::Relaxed),
            channel_relinks_total: self.channel_relinks_total.load(Ordering::Relaxed),
            sessions_relinked_once: self.sessions_relinked_once.load(Ordering::Relaxed),
            max_links_on_one_session: self.max_links_on_one_session.load(Ordering::Relaxed),
            channel_link_failures: self.channel_link_failures.load(Ordering::Relaxed),
            initial_payments: self.initial_payments.load(Ordering::Relaxed),
            topups_total: self.topups_total.load(Ordering::Relaxed),
            topups_proactive: self.topups_proactive.load(Ordering::Relaxed),
            topups_reactive: self.topups_reactive.load(Ordering::Relaxed),
            sessions_paused_once: self.sessions_paused_once.load(Ordering::Relaxed),
            pause_events: self.pause_events.load(Ordering::Relaxed),
            startup_unpauses: self.startup_unpauses.load(Ordering::Relaxed),
            recovery_unpause_events: self.recovery_unpause_events.load(Ordering::Relaxed),
            status_polls_sent: self.status_polls_sent.load(Ordering::Relaxed),
            status_updates_seen: self.status_updates_seen.load(Ordering::Relaxed),
            payment_no_new_funds: self.payment_no_new_funds.load(Ordering::Relaxed),
            control_errors: self.control_errors.load(Ordering::Relaxed),
            channels_abandoned_due_to_capacity: self
                .channels_abandoned_due_to_capacity
                .load(Ordering::Relaxed),
            channels_abandoned_not_at_capacity: self
                .channels_abandoned_not_at_capacity
                .load(Ordering::Relaxed),
        }
    }
}

#[derive(Debug, Default, Clone, Copy)]
struct ChannelAttemptState {
    last_confirmed_balance_raw: u64,
    last_confirmed_capacity_raw: u64,
    last_attempted_balance_raw: Option<u64>,
    initial_payment_sent: bool,
}

static TRACING_INIT: OnceLock<()> = OnceLock::new();
const STRESS_PATH_SEED: u64 = 0x4d4f_4e41_445f_5354;

#[derive(Debug, Clone, Copy)]
struct StressConfig {
    relays: usize,
    circuits: usize,
    hops_per_circuit: usize,
    streams_per_circuit: usize,
    max_in_flight_per_circuit: usize,
    targets: usize,
    payload_bytes: usize,
    payment: StressPaymentConfig,
}

impl StressConfig {
    fn from_env(default: Self) -> Self {
        Self {
            relays: read_env_usize("MONAD_STRESS_RELAYS", default.relays),
            circuits: read_env_usize("MONAD_STRESS_CIRCUITS", default.circuits),
            hops_per_circuit: read_env_usize("MONAD_STRESS_HOPS", default.hops_per_circuit),
            streams_per_circuit: read_env_usize(
                "MONAD_STRESS_STREAMS",
                default.streams_per_circuit,
            ),
            max_in_flight_per_circuit: read_env_usize(
                "MONAD_STRESS_MAX_IN_FLIGHT_PER_CIRCUIT",
                default.max_in_flight_per_circuit,
            ),
            targets: read_env_usize("MONAD_STRESS_TARGETS", default.targets),
            payload_bytes: read_env_usize("MONAD_STRESS_PAYLOAD_BYTES", default.payload_bytes),
            payment: StressPaymentConfig::from_env(),
        }
    }

    fn verbose(self) -> bool {
        self.circuits <= 5
    }
}

#[derive(Debug, Default, Clone, Copy)]
struct CircuitStats {
    setup_micros: u128,
    data_micros: u128,
    sent_bytes: u64,
    recv_bytes: u64,
    streams_ok: usize,
}

#[derive(Clone)]
struct CircuitRunConfig {
    targets: Arc<Vec<String>>,
    streams_per_circuit: usize,
    max_in_flight_per_circuit: usize,
    payload_bytes: usize,
    verbose: bool,
    progress: ProgressTracker,
    payment: StressPaymentConfig,
    payment_stats: Arc<PaymentStats>,
}

#[derive(Clone)]
struct ProgressTracker {
    enabled: bool,
    total_streams: usize,
    completed_streams: Arc<AtomicUsize>,
}

impl ProgressTracker {
    fn new(enabled: bool, total_streams: usize) -> Self {
        Self {
            enabled,
            total_streams,
            completed_streams: Arc::new(AtomicUsize::new(0)),
        }
    }

    fn record_stream_completed(&self) {
        if !self.enabled {
            return;
        }

        let completed = self.completed_streams.fetch_add(1, Ordering::Relaxed) + 1;
        print!(".");
        let _ = std::io::stdout().flush();

        if completed.is_multiple_of(50) || completed == self.total_streams {
            println!(
                " progress: {completed}/{} streams complete",
                self.total_streams
            );
        }
    }

    fn finish_line(&self) {
        if self.enabled {
            println!();
        }
    }
}

async fn run_echo_server(listener: TcpListener) {
    loop {
        let (mut stream, peer_addr) = match listener.accept().await {
            Ok(conn) => conn,
            Err(err) => {
                eprintln!("stress echo server accept error: {err}");
                tracing::error!("stress echo server accept error: {err}");
                break;
            }
        };

        tokio::spawn(async move {
            let mut buf = vec![0u8; 16 * 1024];
            loop {
                match stream.read(&mut buf).await {
                    Ok(0) => break,
                    Ok(n) => {
                        if stream.write_all(&buf[..n]).await.is_err() {
                            tracing::debug!("stress echo server write failed for {peer_addr}");
                            break;
                        }
                    }
                    Err(err) => {
                        tracing::debug!("stress echo server read failed for {peer_addr}: {err}");
                        break;
                    }
                }
            }
        });
    }
}

fn stress_target_bind_addr(index: usize) -> io::Result<SocketAddr> {
    const TARGETS_PER_OCTET: usize = 254;
    const MAX_TARGETS: usize = 256 * TARGETS_PER_OCTET;

    if index >= MAX_TARGETS {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("too many stress targets requested: {index} (max {MAX_TARGETS})"),
        ));
    }

    let third = (index / TARGETS_PER_OCTET) as u8;
    let fourth = (index % TARGETS_PER_OCTET + 1) as u8;
    Ok(SocketAddr::from(([127, 127, third, fourth], 0)))
}

async fn start_echo_targets(targets: usize) -> io::Result<Vec<String>> {
    let mut addrs = Vec::with_capacity(targets);
    for idx in 0..targets {
        let bind_addr = stress_target_bind_addr(idx)?;
        let listener = TcpListener::bind(bind_addr).await?;
        let addr = listener.local_addr()?;
        tokio::spawn(run_echo_server(listener));
        addrs.push(addr.to_string());
    }
    Ok(addrs)
}

fn pick_target(
    circuit_id: usize,
    stream_idx: usize,
    streams_per_circuit: usize,
    targets: &[String],
) -> &str {
    let global_stream_idx = circuit_id
        .saturating_mul(streams_per_circuit)
        .saturating_add(stream_idx);
    &targets[global_stream_idx % targets.len()]
}

fn next_balance_raw_for_delta(
    current_balance_raw: u64,
    capacity_raw: u64,
    unit: &str,
    delta_msats: u64,
) -> u64 {
    current_balance_raw
        .saturating_add(msats_to_raw_units(unit, delta_msats).unwrap_or(0))
        .min(capacity_raw)
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
            "failed to bind shared TCP/QUIC test server after {MAX_SHARED_BIND_RETRIES} retries"
        ))
    }))
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
    let mut keysets = BTreeMap::new();
    keysets.insert(
        SYNTHETIC_TEST_MINT_URL.to_string(),
        BTreeMap::from([(
            SYNTHETIC_TEST_KEYSET_ID.to_string(),
            CachedKeyset {
                unit: SYNTHETIC_TEST_MINT_UNIT.to_string(),
                active: true,
                info_json:
                    r#"{"keysetId":"00testkeyset0000","unit":"msat","keys":{},"inputFeePpk":0}"#
                        .to_string(),
            },
        )]),
    );
    SpilmanMintCache {
        advertised,
        keysets,
    }
}

fn synthetic_trusted_mint_units() -> BTreeMap<String, BTreeSet<String>> {
    BTreeMap::from([(
        SYNTHETIC_TEST_MINT_URL.to_string(),
        BTreeSet::from([SYNTHETIC_TEST_MINT_UNIT.to_string()]),
    )])
}

async fn start_monad_relay() -> (SocketAddr, Secp256k1Pubkey) {
    let identity = QuicCertIdentity::generate().unwrap();
    let transport_key = SecpTransportKeypair::generate();
    let pubkey = transport_key.pubkey();
    let quic_km = monad_quic::keygen::generate_from_seed(identity.seed()).unwrap();
    let quic_server_config =
        monad_quic::server::build_server_config(&quic_km.cert_pem, &quic_km.key_pem).unwrap();
    let (listener, quic_endpoint, addr) =
        bind_tcp_and_quic_on_same_port("127.0.0.1:0".parse().unwrap(), quic_server_config)
            .await
            .unwrap();

    let config = Arc::new(ServerConfig {
        identity,
        transport_key: Some(transport_key),
        receiver_pubkey_hex: cashu::nuts::SecretKey::generate().public_key().to_hex(),
        trusted_mint_units: synthetic_trusted_mint_units(),
        in_bytes_per_millisat: 1,
        out_bytes_per_millisat: 1,
        bootstrap_capabilities: None,
        relay_wallet_name: "test-relay".to_string(),
        spilman_storage_path: tempfile::NamedTempFile::new()
            .unwrap()
            .path()
            .to_str()
            .unwrap()
            .to_string(),
    });
    let payments = Arc::new(InMemoryRelayPayments::new());
    let synthetic_mint_cache = shared_spilman_mint_cache(synthetic_test_mint_cache());

    tokio::spawn(run_with_payments(
        listener,
        Some(quic_endpoint),
        config,
        payments,
        synthetic_mint_cache,
    ));

    (addr, pubkey)
}

fn sample_relay_indices(relays: usize, hops: usize, circuit_id: usize) -> Vec<usize> {
    let mut state = STRESS_PATH_SEED ^ ((circuit_id as u64).wrapping_mul(0x9e37_79b9_7f4a_7c15));
    let mut indices = Vec::with_capacity(hops);
    for _ in 0..hops {
        state ^= state << 13;
        state ^= state >> 7;
        state ^= state << 17;
        indices.push((state as usize) % relays);
    }
    indices
}

async fn run_stream_echo(
    tunnel: monad_common::h2stream::H2ConnectStream,
    total_bytes: usize,
    pattern: u8,
) -> io::Result<(u64, u64)> {
    let chunk = vec![pattern; 8 * 1024];
    let (mut reader, mut writer) = tokio::io::split(tunnel);

    let write_task = tokio::spawn(async move {
        let mut sent = 0usize;
        while sent < total_bytes {
            let remaining = total_bytes - sent;
            let take = remaining.min(chunk.len());
            writer.write_all(&chunk[..take]).await?;
            sent += take;
        }
        writer.shutdown().await?;
        Ok::<u64, io::Error>(sent as u64)
    });

    let read_task = tokio::spawn(async move {
        let mut buf = vec![0u8; 16 * 1024];
        let mut received = 0u64;
        loop {
            let n = reader.read(&mut buf).await?;
            if n == 0 {
                break;
            }
            if buf[..n].iter().any(|b| *b != pattern) {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "echoed payload pattern mismatch",
                ));
            }
            received = received.saturating_add(n as u64);
        }
        Ok::<u64, io::Error>(received)
    });

    let sent = write_task
        .await
        .map_err(|e| io::Error::other(format!("writer task failed: {e}")))??;
    let received = read_task
        .await
        .map_err(|e| io::Error::other(format!("reader task failed: {e}")))??;

    if received != total_bytes as u64 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("echoed byte count mismatch: sent={sent} received={received}"),
        ));
    }

    Ok((sent, received))
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

async fn provision_and_send_link(
    wallet: &MockWallet,
    session_id: [u8; 32],
    offer: &RelayPaymentOffer,
    channel_capacity_msats: u64,
    h2_send: &mut h2::SendStream<bytes::Bytes>,
) -> io::Result<String> {
    let channel_id = wallet
        .provision_channel(offer, channel_capacity_msats)
        .map_err(|e| io::Error::other(format!("failed to provision stress channel: {e}")))?;
    wallet
        .attach_channel_to_session(&channel_id, session_id)
        .map_err(|e| io::Error::other(format!("failed to attach stress channel: {e}")))?;
    let payment_json = wallet
        .build_link_request(&channel_id, offer)
        .map_err(|e| io::Error::other(format!("failed to build stress link request: {e}")))?;
    send_control_message(h2_send, &ClientMessage::ChannelLink { payment_json }).await?;
    Ok(channel_id)
}

async fn start_huge_funding_control(
    conn: &RelayConnection,
    hop_label: &str,
    payment: StressPaymentConfig,
    payment_stats: Arc<PaymentStats>,
) -> io::Result<(tokio::task::JoinHandle<()>, oneshot::Receiver<()>)> {
    let (mut h2_send, mut h2_recv) = conn.open_control().await?;
    let session_id = *conn.session_id();
    let wallet = Arc::new(MockWallet::new());
    let (ready_tx, ready_rx) = oneshot::channel();
    let hop_label = hop_label.to_string();

    let handle = tokio::spawn(async move {
        let mut buf = Vec::new();
        let mut ready_tx = Some(ready_tx);
        let mut offer: Option<RelayPaymentOffer> = None;
        let mut active_channel_id: Option<String> = None;
        let mut link_in_flight: Option<String> = None;
        let mut channel_states = HashMap::<String, ChannelAttemptState>::new();
        let mut session_became_usable = false;
        let mut last_paused: Option<bool> = None;
        let mut saw_pause_once = false;
        let mut successful_links = 0u64;
        let mut counted_relinked_session = false;
        let mut status_interval = tokio::time::interval(payment.status_poll_interval);
        status_interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

        loop {
            let maybe_message = tokio::select! {
                _ = status_interval.tick(), if payment.mode != StressPaymentMode::Transport => {
                    payment_stats.status_polls_sent.fetch_add(1, Ordering::Relaxed);
                    if let Err(err) = send_control_message(&mut h2_send, &ClientMessage::GetSessionStatus).await {
                        payment_stats.control_errors.fetch_add(1, Ordering::Relaxed);
                        println!("{hop_label}: failed to request stress SessionStatus: {err}");
                        break;
                    }
                    continue;
                }
                result = read_control_message(&mut h2_recv, &mut buf) => result,
            };

            let message = match maybe_message {
                Ok(Some(message)) => message,
                Ok(None) => break,
                Err(err) => {
                    payment_stats.control_errors.fetch_add(1, Ordering::Relaxed);
                    println!("{hop_label}: control stream error during stress prefund: {err}");
                    break;
                }
            };

            match message {
                ServerMessage::SessionStatus {
                    receiver_pubkey,
                    advertisements,
                    linked_channel,
                    remaining_milli_sats,
                    paused,
                    ..
                } => {
                    payment_stats
                        .status_updates_seen
                        .fetch_add(1, Ordering::Relaxed);
                    if let Some(previous_paused) = last_paused {
                        if !previous_paused && paused {
                            payment_stats.pause_events.fetch_add(1, Ordering::Relaxed);
                            if !saw_pause_once {
                                saw_pause_once = true;
                                payment_stats
                                    .sessions_paused_once
                                    .fetch_add(1, Ordering::Relaxed);
                            }
                        } else if previous_paused && !paused && saw_pause_once {
                            payment_stats
                                .recovery_unpause_events
                                .fetch_add(1, Ordering::Relaxed);
                        }
                    }
                    last_paused = Some(paused);

                    if offer.is_none() {
                        let Some(advertisement) = advertisements.first() else {
                            payment_stats.control_errors.fetch_add(1, Ordering::Relaxed);
                            println!("{hop_label}: relay advertised no payment offers");
                            break;
                        };
                        offer = Some(RelayPaymentOffer::from_advertisement(
                            receiver_pubkey.clone(),
                            advertisement,
                        ));
                    }

                    let Some(current_offer) = offer.as_ref() else {
                        continue;
                    };

                    if active_channel_id.is_none() && link_in_flight.is_none() {
                        match provision_and_send_link(
                            wallet.as_ref(),
                            session_id,
                            current_offer,
                            payment.channel_capacity_msats,
                            &mut h2_send,
                        )
                        .await
                        {
                            Ok(new_channel_id) => {
                                channel_states.entry(new_channel_id.clone()).or_default();
                                link_in_flight = Some(new_channel_id);
                                continue;
                            }
                            Err(err) => {
                                payment_stats
                                    .channel_link_failures
                                    .fetch_add(1, Ordering::Relaxed);
                                payment_stats.control_errors.fetch_add(1, Ordering::Relaxed);
                                println!("{hop_label}: {err}");
                                break;
                            }
                        }
                    }

                    if let Some(linked) = linked_channel {
                        let previous_active_channel_id = active_channel_id.clone();
                        if link_in_flight.as_deref() == Some(linked.channel_id.as_str()) {
                            successful_links = successful_links.saturating_add(1);
                            payment_stats
                                .channel_links_total
                                .fetch_add(1, Ordering::Relaxed);
                            payment_stats
                                .max_links_on_one_session
                                .fetch_max(successful_links, Ordering::Relaxed);
                            if successful_links == 1 {
                                payment_stats
                                    .sessions_linked
                                    .fetch_add(1, Ordering::Relaxed);
                            } else {
                                payment_stats
                                    .channel_relinks_total
                                    .fetch_add(1, Ordering::Relaxed);
                                if !counted_relinked_session {
                                    counted_relinked_session = true;
                                    payment_stats
                                        .sessions_relinked_once
                                        .fetch_add(1, Ordering::Relaxed);
                                }
                            }
                            active_channel_id = Some(linked.channel_id.clone());
                            link_in_flight = None;
                        } else if active_channel_id.as_deref() != Some(linked.channel_id.as_str()) {
                            active_channel_id = Some(linked.channel_id.clone());
                        }

                        if let (Some(previous_channel_id), Some(current_channel_id)) = (
                            previous_active_channel_id.as_ref(),
                            active_channel_id.as_ref(),
                        ) {
                            if previous_channel_id != current_channel_id {
                                if let Some(previous_state) =
                                    channel_states.get(previous_channel_id)
                                {
                                    if previous_state.last_confirmed_balance_raw
                                        >= previous_state.last_confirmed_capacity_raw
                                    {
                                        payment_stats
                                            .channels_abandoned_due_to_capacity
                                            .fetch_add(1, Ordering::Relaxed);
                                    } else {
                                        payment_stats
                                            .channels_abandoned_not_at_capacity
                                            .fetch_add(1, Ordering::Relaxed);
                                    }
                                }
                            }
                        }

                        let Some(current_channel_id) = active_channel_id.as_ref() else {
                            continue;
                        };

                        if active_channel_id.as_deref() == Some(linked.channel_id.as_str()) {
                            let channel_state =
                                channel_states.entry(linked.channel_id.clone()).or_default();
                            channel_state.last_confirmed_balance_raw = linked.balance_raw;
                            channel_state.last_confirmed_capacity_raw = linked.capacity_raw;
                            if channel_state
                                .last_attempted_balance_raw
                                .is_some_and(|target| linked.balance_raw >= target)
                            {
                                channel_state.last_attempted_balance_raw = None;
                            }

                            let base_balance_raw = channel_state
                                .last_attempted_balance_raw
                                .unwrap_or(channel_state.last_confirmed_balance_raw)
                                .max(channel_state.last_confirmed_balance_raw);
                            let needs_reactive_topup = paused || remaining_milli_sats <= 0;
                            let needs_proactive_topup = matches!(
                                payment.mode,
                                StressPaymentMode::Buffered | StressPaymentMode::RelinkBuffered
                            ) && remaining_milli_sats
                                <= payment.target_buffer_msats as i64;
                            let is_initial_payment = !channel_state.initial_payment_sent;

                            let next_target_raw = if is_initial_payment {
                                channel_state.initial_payment_sent = true;
                                Some(match payment.mode {
                                    StressPaymentMode::Transport => linked.capacity_raw,
                                    StressPaymentMode::Buffered
                                    | StressPaymentMode::RelinkBuffered => {
                                        next_balance_raw_for_delta(
                                            base_balance_raw,
                                            linked.capacity_raw,
                                            &linked.unit,
                                            payment.initial_payment_msats,
                                        )
                                    }
                                })
                            } else if channel_state.last_attempted_balance_raw.is_some() {
                                None
                            } else if needs_reactive_topup || needs_proactive_topup {
                                let desired_next_balance_raw = base_balance_raw.saturating_add(
                                    msats_to_raw_units(&linked.unit, payment.payment_chunk_msats)
                                        .unwrap_or(0),
                                );
                                if payment.mode == StressPaymentMode::RelinkBuffered
                                    && desired_next_balance_raw > linked.capacity_raw
                                {
                                    if link_in_flight.is_none() {
                                        match provision_and_send_link(
                                            wallet.as_ref(),
                                            session_id,
                                            current_offer,
                                            payment.channel_capacity_msats,
                                            &mut h2_send,
                                        )
                                        .await
                                        {
                                            Ok(new_channel_id) => {
                                                channel_states
                                                    .entry(new_channel_id.clone())
                                                    .or_default();
                                                link_in_flight = Some(new_channel_id);
                                                continue;
                                            }
                                            Err(err) => {
                                                payment_stats
                                                    .channel_link_failures
                                                    .fetch_add(1, Ordering::Relaxed);
                                                payment_stats
                                                    .control_errors
                                                    .fetch_add(1, Ordering::Relaxed);
                                                println!("{hop_label}: {err}");
                                                break;
                                            }
                                        }
                                    }
                                    None
                                } else {
                                    Some(next_balance_raw_for_delta(
                                        base_balance_raw,
                                        linked.capacity_raw,
                                        &linked.unit,
                                        payment.payment_chunk_msats,
                                    ))
                                }
                            } else {
                                None
                            };

                            if let Some(next_target_raw) = next_target_raw {
                                if next_target_raw > base_balance_raw {
                                    let payment_json = match wallet.build_channel_payment(
                                        current_channel_id,
                                        current_offer,
                                        base_balance_raw,
                                        next_target_raw,
                                    ) {
                                        Ok(payment_json) => payment_json,
                                        Err(err) => {
                                            if err.to_string() == "no new funds" {
                                                payment_stats
                                                    .payment_no_new_funds
                                                    .fetch_add(1, Ordering::Relaxed);
                                                channel_state.last_attempted_balance_raw = None;
                                                continue;
                                            }
                                            payment_stats
                                                .control_errors
                                                .fetch_add(1, Ordering::Relaxed);
                                            println!(
                                                "{hop_label}: failed to build stress channel payment: {err}"
                                            );
                                            break;
                                        }
                                    };
                                    if let Err(err) = send_control_message(
                                        &mut h2_send,
                                        &ClientMessage::ChannelPayment { payment_json },
                                    )
                                    .await
                                    {
                                        payment_stats
                                            .control_errors
                                            .fetch_add(1, Ordering::Relaxed);
                                        println!(
                                            "{hop_label}: failed to send stress payment: {err}"
                                        );
                                        break;
                                    }
                                    if is_initial_payment {
                                        payment_stats
                                            .initial_payments
                                            .fetch_add(1, Ordering::Relaxed);
                                    } else {
                                        payment_stats.topups_total.fetch_add(1, Ordering::Relaxed);
                                        if needs_reactive_topup {
                                            payment_stats
                                                .topups_reactive
                                                .fetch_add(1, Ordering::Relaxed);
                                        } else if needs_proactive_topup {
                                            payment_stats
                                                .topups_proactive
                                                .fetch_add(1, Ordering::Relaxed);
                                        }
                                    }
                                    channel_state.last_attempted_balance_raw =
                                        Some(next_target_raw);
                                    continue;
                                }
                            }
                        }
                    }

                    if active_channel_id
                        .as_ref()
                        .and_then(|id| channel_states.get(id))
                        .is_some_and(|state| state.initial_payment_sent)
                        && !paused
                    {
                        if !session_became_usable {
                            session_became_usable = true;
                            payment_stats
                                .startup_unpauses
                                .fetch_add(1, Ordering::Relaxed);
                        }
                        if let Some(tx) = ready_tx.take() {
                            let _ = tx.send(());
                        }
                    }
                }
                ServerMessage::ChannelEvicted { channel_id } => {
                    payment_stats.control_errors.fetch_add(1, Ordering::Relaxed);
                    println!("{hop_label}: stress funding channel evicted: {channel_id}");
                    break;
                }
                ServerMessage::Error { code, message } => {
                    if matches!(code, ServerErrorCode::PaymentNoNewFunds) {
                        payment_stats
                            .payment_no_new_funds
                            .fetch_add(1, Ordering::Relaxed);
                        if let Some(current_channel_id) = active_channel_id.as_ref() {
                            if let Some(channel_state) = channel_states.get_mut(current_channel_id)
                            {
                                channel_state.last_attempted_balance_raw = None;
                            }
                        }
                        continue;
                    }
                    if link_in_flight.is_some() {
                        payment_stats
                            .channel_link_failures
                            .fetch_add(1, Ordering::Relaxed);
                    }
                    payment_stats.control_errors.fetch_add(1, Ordering::Relaxed);
                    println!("{hop_label}: stress funding control error: {message}");
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

async fn fund_session_huge(
    mut conn: RelayConnection,
    hop_label: &str,
    payment: StressPaymentConfig,
    payment_stats: Arc<PaymentStats>,
) -> io::Result<RelayConnection> {
    let (control_task, ready_rx) =
        start_huge_funding_control(&conn, hop_label, payment, payment_stats).await?;
    ready_rx.await.map_err(|_| {
        io::Error::new(
            io::ErrorKind::BrokenPipe,
            format!("control task exited before {hop_label} was prefunded"),
        )
    })?;
    conn.add_task(control_task);
    Ok(conn)
}

fn connect_through_chain_prefunded(
    mut stream: impl AsyncRead + AsyncWrite + Unpin + Send + 'static,
    hops: &[RouteHop],
    hop_idx: usize,
    payment: StressPaymentConfig,
    payment_stats: Arc<PaymentStats>,
) -> std::pin::Pin<Box<dyn std::future::Future<Output = io::Result<RelayConnection>> + Send>> {
    let hops = hops.to_vec();

    Box::pin(async move {
        let hop = &hops[hop_idx];
        let label = format!(
            "stress hop {}/{} to {}",
            hop_idx + 1,
            hops.len(),
            hop_label(hop)
        );
        let (mut conn, driver) = match hop {
            RouteHop::Cleartext { pubkey, .. } => {
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
            RouteHop::Blinded { .. } => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "stress harness does not support blinded hops yet",
                ));
            }
        };
        conn.add_driver(driver);

        let funding_label = format!("hop {}/{} to {}", hop_idx + 1, hops.len(), hop_label(hop));
        conn = fund_session_huge(conn, &funding_label, payment, payment_stats.clone()).await?;

        if hop_idx < hops.len() - 1 {
            let next = &hops[hop_idx + 1];
            let h2_connect_stream = match next {
                RouteHop::Cleartext {
                    addr,
                    pubkey,
                    use_quic,
                } => {
                    if *use_quic {
                        conn.open_tunnel_quic_secp256k1(addr, &pubkey.to_hex())
                            .await?
                    } else {
                        conn.open_tunnel(addr).await?
                    }
                }
                RouteHop::Blinded { .. } => {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidInput,
                        "stress harness does not support blinded hops yet",
                    ));
                }
            };

            let mut conn = conn;
            let mut next_conn = connect_through_chain_prefunded(
                h2_connect_stream,
                &hops,
                hop_idx + 1,
                payment,
                payment_stats,
            )
            .await?;
            next_conn.absorb_handles_from(&mut conn);
            Ok(next_conn)
        } else {
            Ok(conn)
        }
    })
}

async fn connect_quic_chain_prefunded(
    first_hop_pool: &QuicPool,
    hops: &[RouteHop],
    payment: StressPaymentConfig,
    payment_stats: Arc<PaymentStats>,
) -> io::Result<RelayConnection> {
    if hops.is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "at least one hop is required",
        ));
    }

    let first = &hops[0];
    let RouteHop::Cleartext {
        addr,
        pubkey,
        use_quic,
    } = first
    else {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "stress harness expects a cleartext first hop",
        ));
    };
    if !use_quic {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "stress harness expects QUIC first hop",
        ));
    }
    let stream = first_hop_pool
        .open_stream(addr, ClientAuthMode::Secp256k1(*pubkey))
        .await?;

    connect_through_chain_prefunded(stream, hops, 0, payment, payment_stats).await
}

async fn run_circuit(
    circuit_id: usize,
    first_hop_pool: Arc<QuicPool>,
    hops: Vec<RouteHop>,
    config: CircuitRunConfig,
) -> io::Result<CircuitStats> {
    if config.verbose {
        let hop_path = hops.iter().map(hop_label).collect::<Vec<_>>().join(" -> ");
        println!(
            "circuit {circuit_id}: building {}-hop QUIC chain via [{hop_path}]",
            hops.len(),
        );
        println!(
            "circuit {circuit_id}: payment_mode={} channel_capacity_msats={} initial_payment_msats={} payment_chunk_msats={} target_buffer_msats={} poll_ms={}",
            config.payment.mode.as_str(),
            config.payment.channel_capacity_msats,
            config.payment.initial_payment_msats,
            config.payment.payment_chunk_msats,
            config.payment.target_buffer_msats,
            config.payment.status_poll_interval.as_millis(),
        );
    }
    let setup_start = Instant::now();
    let conn = connect_quic_chain_prefunded(
        first_hop_pool.as_ref(),
        &hops,
        config.payment,
        config.payment_stats.clone(),
    )
    .await?;
    if config.verbose {
        println!("circuit {circuit_id}: chain established and all hop payment drivers ready");
    }
    let setup_elapsed = setup_start.elapsed();

    let conn = Arc::new(conn);
    let data_start = Instant::now();
    let mut stream_tasks = JoinSet::new();
    let max_in_flight = config
        .max_in_flight_per_circuit
        .max(1)
        .min(config.streams_per_circuit.max(1));

    let mut stats = CircuitStats {
        setup_micros: setup_elapsed.as_micros(),
        ..CircuitStats::default()
    };

    if config.verbose {
        println!(
            "circuit {circuit_id}: starting {} stream(s) with {} byte payloads across {} target(s) (max_in_flight={max_in_flight})",
            config.streams_per_circuit,
            config.payload_bytes,
            config.targets.len(),
        );
    }

    for stream_idx in 0..config.streams_per_circuit {
        while stream_tasks.len() >= max_in_flight {
            let (sent, received) = match stream_tasks.join_next().await {
                Some(Ok(Ok((sent, received)))) => (sent, received),
                Some(Ok(Err(err))) => {
                    stream_tasks.abort_all();
                    return Err(err);
                }
                Some(Err(err)) => {
                    stream_tasks.abort_all();
                    return Err(io::Error::other(format!("stream task join error: {err}")));
                }
                None => break,
            };

            stats.sent_bytes = stats.sent_bytes.saturating_add(sent);
            stats.recv_bytes = stats.recv_bytes.saturating_add(received);
            stats.streams_ok += 1;
        }

        let conn = Arc::clone(&conn);
        let target = pick_target(
            circuit_id,
            stream_idx,
            config.streams_per_circuit,
            config.targets.as_ref(),
        )
        .to_string();
        let pattern = ((circuit_id + stream_idx) % 251) as u8;
        let progress = config.progress.clone();
        let verbose = config.verbose;
        let payload_bytes = config.payload_bytes;
        stream_tasks.spawn(async move {
            if verbose {
                println!("circuit {circuit_id} stream {stream_idx}: open");
            }
            let tunnel = conn.open_tunnel(&target).await?;
            let result = run_stream_echo(tunnel, payload_bytes, pattern).await;
            if verbose {
                match &result {
                    Ok((sent, received)) => println!(
                        "circuit {circuit_id} stream {stream_idx}: done sent={sent} received={received}"
                    ),
                    Err(err) => println!(
                        "circuit {circuit_id} stream {stream_idx}: failed err={err}"
                    ),
                }
            }
            if result.is_ok() {
                progress.record_stream_completed();
            }
            match result {
                Ok((sent, received)) => Ok((sent, received)),
                Err(err) => Err(io::Error::new(
                    err.kind(),
                    format!(
                        "circuit {circuit_id} stream {stream_idx} target {target} failed: {err}"
                    ),
                )),
            }
        });
    }

    while let Some(result) = stream_tasks.join_next().await {
        let (sent, received) = match result {
            Ok(Ok((sent, received))) => (sent, received),
            Ok(Err(err)) => {
                stream_tasks.abort_all();
                return Err(err);
            }
            Err(err) => {
                stream_tasks.abort_all();
                return Err(io::Error::other(format!("stream task join error: {err}")));
            }
        };
        stats.sent_bytes = stats.sent_bytes.saturating_add(sent);
        stats.recv_bytes = stats.recv_bytes.saturating_add(received);
        stats.streams_ok += 1;
    }

    stats.data_micros = data_start.elapsed().as_micros();

    if config.verbose {
        println!(
            "circuit {circuit_id}: complete setup_ms={:.2} data_ms={:.2} sent_bytes={} recv_bytes={} streams_ok={}",
            stats.setup_micros as f64 / 1000.0,
            stats.data_micros as f64 / 1000.0,
            stats.sent_bytes,
            stats.recv_bytes,
            stats.streams_ok,
        );
    }

    let conn = match Arc::try_unwrap(conn) {
        Ok(conn) => conn,
        Err(_) => {
            return Err(io::Error::other(
                "circuit connection still had outstanding references at shutdown",
            ));
        }
    };
    conn.shutdown().await;
    Ok(stats)
}

async fn run_stress_scenario(config: StressConfig) {
    init_stress_tracing();
    assert!(
        config.hops_per_circuit >= 1,
        "need at least 1 hop per circuit"
    );
    assert!(config.relays >= 1, "need at least 1 relay");

    println!(
        "stress start relays={} circuits={} hops={} streams_per_circuit={} max_in_flight_per_circuit={} targets={} payload_bytes={} payment_mode={} initial_payment_msats={} payment_chunk_msats={} target_buffer_msats={} poll_ms={}",
        config.relays,
        config.circuits,
        config.hops_per_circuit,
        config.streams_per_circuit,
        config.max_in_flight_per_circuit,
        config.targets,
        config.payload_bytes,
        config.payment.mode.as_str(),
        config.payment.initial_payment_msats,
        config.payment.payment_chunk_msats,
        config.payment.target_buffer_msats,
        config.payment.status_poll_interval.as_millis(),
    );

    let targets = Arc::new(start_echo_targets(config.targets).await.unwrap());
    let sample_targets = targets.iter().take(3).cloned().collect::<Vec<_>>();
    println!(
        "stress echo targets={} sample={sample_targets:?}",
        targets.len()
    );

    let mut relays = Vec::with_capacity(config.relays);
    for relay_idx in 0..config.relays {
        let relay = start_monad_relay().await;
        println!(
            "stress relay {relay_idx}: addr={} pubkey={}",
            relay.0, relay.1
        );
        relays.push(relay);
    }
    let first_hop_pool =
        Arc::new(QuicPool::new().expect("stress first-hop QUIC pool should construct"));
    let total_streams = config.circuits * config.streams_per_circuit;
    let progress = ProgressTracker::new(!config.verbose(), total_streams);
    let payment_stats = Arc::new(PaymentStats::default());

    let total_start = Instant::now();
    let mut handles = Vec::with_capacity(config.circuits);
    for circuit_id in 0..config.circuits {
        let indices = sample_relay_indices(config.relays, config.hops_per_circuit, circuit_id);
        let hops = indices
            .into_iter()
            .map(|relay_idx| RouteHop::Cleartext {
                addr: relays[relay_idx].0.to_string(),
                pubkey: relays[relay_idx].1,
                use_quic: true,
            })
            .collect::<Vec<_>>();
        let circuit_config = CircuitRunConfig {
            targets: targets.clone(),
            streams_per_circuit: config.streams_per_circuit,
            max_in_flight_per_circuit: config.max_in_flight_per_circuit,
            payload_bytes: config.payload_bytes,
            verbose: config.verbose(),
            progress: progress.clone(),
            payment: config.payment,
            payment_stats: payment_stats.clone(),
        };
        handles.push(tokio::spawn(run_circuit(
            circuit_id,
            first_hop_pool.clone(),
            hops,
            circuit_config,
        )));
    }

    let mut successes = 0usize;
    let mut failures = 0usize;
    let mut streams_ok = 0usize;
    let mut sent_bytes = 0u64;
    let mut recv_bytes = 0u64;
    let mut setup_micros_total = 0u128;
    let mut data_micros_total = 0u128;
    let mut first_error = None::<String>;

    for handle in handles {
        match handle.await {
            Ok(Ok(stats)) => {
                successes += 1;
                streams_ok += stats.streams_ok;
                sent_bytes = sent_bytes.saturating_add(stats.sent_bytes);
                recv_bytes = recv_bytes.saturating_add(stats.recv_bytes);
                setup_micros_total = setup_micros_total.saturating_add(stats.setup_micros);
                data_micros_total = data_micros_total.saturating_add(stats.data_micros);
            }
            Ok(Err(err)) => {
                failures += 1;
                println!("stress circuit failure: {err}");
                if first_error.is_none() {
                    first_error = Some(err.to_string());
                }
            }
            Err(err) => {
                failures += 1;
                println!("stress circuit join failure: {err}");
                if first_error.is_none() {
                    first_error = Some(format!("join error: {err}"));
                }
            }
        }
    }

    let total_elapsed = total_start.elapsed();
    progress.finish_line();
    let total_sessions = config.circuits * config.hops_per_circuit;
    let total_bytes = sent_bytes.saturating_add(recv_bytes);
    let payment_snapshot = payment_stats.snapshot();
    let throughput_mib_per_s = if total_elapsed.as_secs_f64() > 0.0 {
        total_bytes as f64 / (1024.0 * 1024.0) / total_elapsed.as_secs_f64()
    } else {
        0.0
    };

    println!(
        "stress summary relays={} circuits={} sessions={} streams={} payload_bytes={} successes={} failures={} streams_ok={} sent_bytes={} recv_bytes={} total_bytes={} avg_setup_ms={:.2} avg_data_ms={:.2} total_elapsed_s={:.3} throughput_mib_per_s={:.2} sessions_linked={} channel_links_total={} channel_relinks_total={} sessions_relinked_once={} max_links_on_one_session={} channel_link_failures={} initial_payments={} topups_total={} topups_proactive={} topups_reactive={} sessions_paused_once={} pause_events={} startup_unpauses={} recovery_unpause_events={} status_polls_sent={} status_updates_seen={} payment_no_new_funds={} control_errors={} channels_abandoned_due_to_capacity={} channels_abandoned_not_at_capacity={}",
        config.relays,
        config.circuits,
        total_sessions,
        total_streams,
        config.payload_bytes,
        successes,
        failures,
        streams_ok,
        sent_bytes,
        recv_bytes,
        total_bytes,
        (setup_micros_total as f64 / successes.max(1) as f64) / 1000.0,
        (data_micros_total as f64 / successes.max(1) as f64) / 1000.0,
        total_elapsed.as_secs_f64(),
        throughput_mib_per_s,
        payment_snapshot.sessions_linked,
        payment_snapshot.channel_links_total,
        payment_snapshot.channel_relinks_total,
        payment_snapshot.sessions_relinked_once,
        payment_snapshot.max_links_on_one_session,
        payment_snapshot.channel_link_failures,
        payment_snapshot.initial_payments,
        payment_snapshot.topups_total,
        payment_snapshot.topups_proactive,
        payment_snapshot.topups_reactive,
        payment_snapshot.sessions_paused_once,
        payment_snapshot.pause_events,
        payment_snapshot.startup_unpauses,
        payment_snapshot.recovery_unpause_events,
        payment_snapshot.status_polls_sent,
        payment_snapshot.status_updates_seen,
        payment_snapshot.payment_no_new_funds,
        payment_snapshot.control_errors,
        payment_snapshot.channels_abandoned_due_to_capacity,
        payment_snapshot.channels_abandoned_not_at_capacity,
    );

    if let Some(ref first_error) = first_error {
        println!("first_error={first_error}");
    }

    assert_eq!(
        failures, 0,
        "stress scenario had circuit failures; first_error={:?}",
        first_error
    );
    assert_eq!(
        streams_ok, total_streams,
        "expected all streams to complete successfully"
    );
}

fn read_env_usize(name: &str, default: usize) -> usize {
    env::var(name)
        .ok()
        .and_then(|value| value.parse::<usize>().ok())
        .unwrap_or(default)
}

fn read_env_u64(name: &str, default: u64) -> u64 {
    env::var(name)
        .ok()
        .and_then(|value| value.parse::<u64>().ok())
        .unwrap_or(default)
}

fn init_stress_tracing() {
    let _ = TRACING_INIT.get_or_init(|| {
        let filter = tracing_subscriber::EnvFilter::try_from_default_env()
            .unwrap_or_else(|_| "info,quinn=warn,h2=warn".into());
        let _ = tracing_subscriber::fmt().with_env_filter(filter).try_init();
    });
}

#[tokio::test(flavor = "multi_thread")]
#[ignore = "manual stress test"]
async fn stress_three_hop_quic_tiny() {
    run_stress_scenario(StressConfig {
        relays: 3,
        circuits: 1,
        hops_per_circuit: 3,
        streams_per_circuit: 2,
        max_in_flight_per_circuit: 2,
        targets: 1,
        payload_bytes: 4 * 1024,
        payment: StressPaymentConfig::from_env(),
    })
    .await;
}

#[tokio::test(flavor = "multi_thread")]
#[ignore = "manual stress test"]
async fn stress_three_hop_quic_small() {
    run_stress_scenario(StressConfig {
        relays: 10,
        circuits: 20,
        hops_per_circuit: 3,
        streams_per_circuit: 10,
        max_in_flight_per_circuit: 10,
        targets: 1,
        payload_bytes: 32 * 1024,
        payment: StressPaymentConfig::from_env(),
    })
    .await;
}

#[tokio::test(flavor = "multi_thread")]
#[ignore = "manual stress test"]
async fn stress_three_hop_quic_medium() {
    run_stress_scenario(StressConfig {
        relays: 10,
        circuits: 100,
        hops_per_circuit: 3,
        streams_per_circuit: 10,
        max_in_flight_per_circuit: 10,
        targets: 1,
        payload_bytes: 64 * 1024,
        payment: StressPaymentConfig::from_env(),
    })
    .await;
}

#[tokio::test(flavor = "multi_thread")]
#[ignore = "manual stress test"]
async fn stress_three_hop_quic_configurable() {
    run_stress_scenario(StressConfig::from_env(StressConfig {
        relays: 10,
        circuits: 100,
        hops_per_circuit: 3,
        streams_per_circuit: 10,
        max_in_flight_per_circuit: 10,
        targets: 1,
        payload_bytes: 64 * 1024,
        payment: StressPaymentConfig::from_env(),
    }))
    .await;
}
