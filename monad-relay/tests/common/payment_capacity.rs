//! Manual single-relay capacity experiment. No production instrumentation.
use super::*;
use monad_relay::payments::{ChannelPaymentError, PaymentOutcome};
use serde::{Deserialize, Serialize};
use std::time::Instant;
use tokio::io::{AsyncBufReadExt, BufReader};
use tokio::net::{UnixListener, UnixStream};

const MINT: &str = "https://capacity-mint.invalid";

#[derive(Clone, Debug, Serialize, Deserialize)]
struct Config {
    sessions: usize,
    duration: u64,
    payment_interval: u64,
    bytes_per_sec: u64,
    traffic_tick_ms: u64,
    warmup: u64,
    setup_concurrency: usize,
    setup_timeout: u64,
    io_timeout: u64,
    client_workers: usize,
    relay_workers: usize,
    seed: u64,
}

impl Config {
    fn from_env() -> anyhow::Result<Self> {
        fn number(name: &str, default: u64) -> anyhow::Result<u64> {
            match env::var(format!("MONAD_CAPACITY_{name}")) {
                Ok(value) => Ok(value.parse()?),
                Err(env::VarError::NotPresent) => Ok(default),
                Err(error) => Err(error.into()),
            }
        }
        let payment_interval = number("PAYMENT_INTERVAL_SECS", 10)?;
        let config = Self {
            sessions: usize::try_from(number("SESSIONS", 25)?)?,
            duration: number("DURATION_SECS", 30)?,
            payment_interval,
            bytes_per_sec: number("BYTES_PER_SEC", 1000)?,
            traffic_tick_ms: number("TRAFFIC_TICK_MS", 1000)?,
            warmup: number("WARMUP_SECS", payment_interval.saturating_add(2))?,
            setup_concurrency: usize::try_from(number("SETUP_CONCURRENCY", 8)?)?,
            setup_timeout: number("SETUP_TIMEOUT_SECS", 300)?,
            io_timeout: number("IO_TIMEOUT_SECS", 10)?,
            client_workers: usize::try_from(number("CLIENT_WORKERS", 2)?)?,
            relay_workers: usize::try_from(number("RELAY_WORKERS", 2)?)?,
            seed: number("SEED", 1)?,
        };
        config.validate()?;
        Ok(config)
    }

    fn validate(&self) -> anyhow::Result<()> {
        anyhow::ensure!(
            (1..=100_000).contains(&self.sessions),
            "sessions must be 1..100000"
        );
        anyhow::ensure!(
            (1..=300).contains(&self.payment_interval),
            "payment interval must be 1..300 seconds"
        );
        anyhow::ensure!(
            self.duration >= 2 * self.payment_interval && self.duration <= 3600,
            "measurement must cover at least two payment intervals, at most one hour"
        );
        anyhow::ensure!(
            self.warmup >= self.payment_interval && self.warmup <= 600,
            "warmup must cover the stagger interval, at most 600 seconds"
        );
        anyhow::ensure!(
            (10..=655_360).contains(&self.bytes_per_sec) && self.bytes_per_sec.is_multiple_of(10),
            "bytes/sec must be divisible by 10 and in 10..655360"
        );
        anyhow::ensure!(
            (100..=1000).contains(&self.traffic_tick_ms),
            "traffic tick must be 100..1000 ms"
        );
        anyhow::ensure!(
            (self.bytes_per_sec * self.traffic_tick_ms).is_multiple_of(1000)
                && self.bytes_per_sec * self.traffic_tick_ms / 1000 <= 65536,
            "traffic rate/tick must yield a whole-byte payload no larger than 64 KiB"
        );
        anyhow::ensure!(
            self.duration * 1000 >= 10 * self.traffic_tick_ms,
            "measurement must cover at least ten traffic ticks"
        );
        anyhow::ensure!(
            (1..=512).contains(&self.setup_concurrency),
            "setup concurrency must be 1..512"
        );
        anyhow::ensure!(
            (1..=64).contains(&self.client_workers) && (1..=64).contains(&self.relay_workers),
            "worker counts must be 1..64"
        );
        anyhow::ensure!(
            (1..=3600).contains(&self.setup_timeout) && (1..=60).contains(&self.io_timeout),
            "invalid setup or I/O timeout"
        );
        anyhow::ensure!(
            self.duration >= 2 * self.minimum_topup().div_ceil(2 * self.bytes_per_sec),
            "measurement must cover two payment intervals after SAT rounding"
        );
        Ok(())
    }

    fn minimum_topup(&self) -> u64 {
        // SAT channels: round the desired payment up to a whole satoshi.
        (2 * self.bytes_per_sec * self.payment_interval).div_ceil(1000) * 1000
    }

    fn capacity_sats(&self) -> u64 {
        (2 * self.bytes_per_sec * (self.duration + self.warmup + 60) + 8 * self.minimum_topup())
            .div_ceil(1000)
    }

    fn phase_ms(&self, id: usize) -> u64 {
        let mut x = self.seed ^ (id as u64).wrapping_mul(0x9e3779b97f4a7c15);
        x ^= x >> 30;
        x = x.wrapping_mul(0xbf58476d1ce4e5b9);
        x ^= x >> 27;
        x % (self.payment_interval * 1000)
    }
}

#[derive(Serialize, Deserialize)]
struct Init {
    config: Config,
    db: String,
    keyset_id: String,
    keyset_info: String,
}

#[derive(Serialize, Deserialize)]
struct Ready {
    addr: SocketAddr,
    pubkey: String,
    receiver: String,
}

#[derive(Clone, Default, Serialize, Deserialize)]
struct Snapshot {
    elapsed_secs: f64,
    accepted: u64,
    rejected: u64,
    links: u64,
    unlinks: u64,
    latency_us_sum: u64,
    latency_us_max: u64,
    latency_buckets: Vec<u64>,
    gap_count: u64,
    gap_sum_us: u64,
    gap_max_us: u64,
    per_channel: Vec<u64>,
    resources: Resources,
}

impl Snapshot {
    fn percentile_upper_us(&self, percent: u64) -> u64 {
        let target = (self.accepted * percent).div_ceil(100);
        if target == 0 {
            return 0;
        }
        let mut count = 0;
        for (bucket, value) in self.latency_buckets.iter().enumerate() {
            count += value;
            if count >= target {
                return 1u64.checked_shl(bucket as u32).unwrap_or(u64::MAX);
            }
        }
        self.latency_us_max
    }
}

#[derive(Default)]
struct Measurement {
    start: Option<Instant>,
    counts: BTreeMap<String, u64>,
    last_payment: BTreeMap<String, Instant>,
    snapshot: Snapshot,
}

impl Measurement {
    fn begin(&mut self) {
        self.snapshot = Snapshot {
            latency_buckets: vec![0; 64],
            ..Default::default()
        };
        self.counts.values_mut().for_each(|count| *count = 0);
        self.last_payment.clear();
        self.start = Some(Instant::now());
    }

    fn record(&mut self, begin: Instant, elapsed: u64, id: &str, accepted: bool) {
        // Exclude requests already executing when measurement started. Stop
        // takes the same lock, so records arriving after it are excluded too.
        if self.start.is_none_or(|start| begin < start) {
            return;
        }
        if !accepted {
            self.snapshot.rejected += 1;
            return;
        }
        self.snapshot.accepted += 1;
        self.snapshot.latency_us_sum += elapsed;
        self.snapshot.latency_us_max = self.snapshot.latency_us_max.max(elapsed);
        let bucket = (64 - elapsed.saturating_sub(1).leading_zeros()) as usize;
        self.snapshot.latency_buckets[bucket.min(63)] += 1;
        *self.counts.entry(id.to_owned()).or_default() += 1;
        if let Some(previous) = self.last_payment.insert(id.to_owned(), Instant::now()) {
            let gap = previous.elapsed().as_micros() as u64;
            self.snapshot.gap_count += 1;
            self.snapshot.gap_sum_us += gap;
            self.snapshot.gap_max_us = self.snapshot.gap_max_us.max(gap);
        }
    }
}

struct MeteredPayments {
    real: Arc<SpilmanRelayPayments>,
    measurement: Mutex<Measurement>,
}

impl RelayPayments for MeteredPayments {
    fn session_mode_policy(&self) -> monad_common::commitment_modes::SessionModePolicy {
        self.real.session_mode_policy()
    }
    fn mint_mode_cache(&self) -> Option<Arc<monad_common::commitment_modes::MintModeCache>> {
        self.real.mint_mode_cache()
    }
    fn retained_mode_mints(&self) -> Result<BTreeSet<String>, String> {
        self.real.retained_mode_mints()
    }
    fn validate_channel_mode(
        &self,
        request: &ChannelLinkRequest,
        policy: &monad_common::commitment_modes::SessionModePolicy,
        versions: &BTreeSet<String>,
    ) -> Result<(), LinkError> {
        self.real.validate_channel_mode(request, policy, versions)
    }
    fn retire_channel(&self, id: &str, require_unowned: bool) -> Result<Option<[u8; 32]>, String> {
        self.real.retire_channel(id, require_unowned)
    }
    fn is_retired(&self, id: &str) -> Result<bool, String> {
        self.real.is_retired(id)
    }
    fn minimum_channel_lifetime_secs(&self) -> u64 {
        self.real.minimum_channel_lifetime_secs()
    }
    fn funding_keyset_recovery_window_secs(&self) -> u64 {
        self.real.funding_keyset_recovery_window_secs()
    }
    fn link_channel(
        &self,
        versions: &BTreeSet<String>,
        session: [u8; 32],
        request: &ChannelLinkRequest,
    ) -> Result<monad_relay::payments::LinkOutcome, LinkError> {
        let result = self.real.link_channel(versions, session, request);
        let mut m = self.measurement.lock().unwrap();
        if m.start.is_some() {
            m.snapshot.links += 1;
        }
        if result.is_ok() {
            m.counts.entry(request.channel_id.clone()).or_default();
        }
        result
    }
    fn unlink_channel(&self, session: [u8; 32], id: &str) -> Result<(), String> {
        let mut m = self.measurement.lock().unwrap();
        if m.start.is_some() {
            m.snapshot.unlinks += 1;
        }
        drop(m);
        self.real.unlink_channel(session, id)
    }
    fn apply_channel_payment_with_limit(
        &self,
        session: [u8; 32],
        id: &str,
        request: &ChannelPaymentRequest,
        limit: u64,
    ) -> Result<PaymentOutcome, ChannelPaymentError> {
        let begin = Instant::now();
        let result = self
            .real
            .apply_channel_payment_with_limit(session, id, request, limit);
        let elapsed = begin.elapsed().as_micros().min(u64::MAX as u128) as u64;
        self.measurement
            .lock()
            .unwrap()
            .record(begin, elapsed, id, result.is_ok());
        result
    }
    fn linked_channel_status(
        &self,
        id: &str,
    ) -> Option<monad_common::protocol::LinkedChannelStatus> {
        self.real.linked_channel_status(id)
    }
    fn release_channel_ownership(&self, session: [u8; 32], id: &str) {
        self.real.release_channel_ownership(session, id);
    }
    fn channel_state(&self, id: &str) -> Result<Option<ChannelState>, String> {
        self.real.channel_state(id)
    }
}

// Linux process-level observations; missing fields stay null on other systems.
// CPU is in OS clock ticks, not a guessed percentage. VmHWM is process-lifetime.
#[derive(Clone, Default, Serialize, Deserialize, Debug)]
struct Resources {
    cpu_ticks: Option<u64>,
    rss_kib: Option<u64>,
    lifetime_hwm_kib: Option<u64>,
}

fn resources() -> Resources {
    let stat = std::fs::read_to_string("/proc/self/stat").unwrap_or_default();
    let fields: Vec<_> = stat
        .rsplit_once(") ")
        .map(|(_, rest)| rest.split_whitespace().collect())
        .unwrap_or_default();
    let cpu_ticks = fields
        .get(11)
        .and_then(|v| v.parse::<u64>().ok())
        .zip(fields.get(12).and_then(|v| v.parse::<u64>().ok()))
        .map(|(u, s)| u + s);
    let status = std::fs::read_to_string("/proc/self/status").unwrap_or_default();
    let value = |name| {
        status
            .lines()
            .find(|l| l.starts_with(name))
            .and_then(|l| l.split_whitespace().nth(1))
            .and_then(|s| s.parse().ok())
    };
    Resources {
        cpu_ticks,
        rss_kib: value("VmRSS:"),
        lifetime_hwm_kib: value("VmHWM:"),
    }
}

async fn send<T: Serialize>(stream: &mut BufReader<UnixStream>, message: &T) -> anyhow::Result<()> {
    let mut bytes = serde_json::to_vec(message)?;
    bytes.push(b'\n');
    stream.get_mut().write_all(&bytes).await?;
    Ok(())
}

async fn receive<T: serde::de::DeserializeOwned>(
    stream: &mut BufReader<UnixStream>,
) -> anyhow::Result<T> {
    timeout(Duration::from_secs(30), read_json(stream)).await?
}

async fn read_json<T: serde::de::DeserializeOwned>(
    stream: &mut BufReader<UnixStream>,
) -> anyhow::Result<T> {
    let mut line = String::new();
    anyhow::ensure!(stream.read_line(&mut line).await? > 0, "relay IPC closed");
    Ok(serde_json::from_str(&line)?)
}

async fn command(stream: &mut BufReader<UnixStream>, command: &str) -> anyhow::Result<Snapshot> {
    send(stream, &command).await?;
    receive(stream).await
}

#[test]
#[ignore = "internal worker for the manual payment-capacity test"]
fn payment_capacity_relay_worker() -> anyhow::Result<()> {
    let Ok(socket) = env::var("MONAD_CAPACITY_WORKER_SOCKET") else {
        return Ok(());
    };
    let workers: usize = env::var("MONAD_CAPACITY_RELAY_WORKERS")?.parse()?;
    tokio::runtime::Builder::new_multi_thread()
        .worker_threads(workers)
        .enable_all()
        .build()?
        .block_on(async {
            init_test_tracing();
            let mut ipc = BufReader::new(UnixStream::connect(socket).await?);
            let init: Init = receive(&mut ipc).await?;
            init.config.validate()?;
            let manager = Arc::new(RelayWalletManager::open(&init.db)?);
            let receiver = cashu::nuts::SecretKey::generate();
            manager.register_identity("capacity-relay", receiver.clone())?;
            manager.install_keyset_cache(mint_cache_with_keyset(
                MINT,
                "sat",
                &init.keyset_id,
                &init.keyset_info,
                true,
            ));
            let trusted = BTreeMap::from([(MINT.to_owned(), BTreeSet::from(["sat".into()]))]);
            manager.set_trusted_mint_units(trusted.clone());
            // This capacity recipe uses pre-created ordinary signing-wallet
            // fixtures; optional mint discovery is not part of its workload.
            let channel_policy = monad_common::config::RelayChannelPolicyConfig {
                commitment_modes: Default::default(),
                ..Default::default()
            };
            let payments = Arc::new(MeteredPayments {
                real: manager.spilman_payments_for_live_with_policy(
                    "capacity-relay",
                    channel_policy.clone(),
                )?,
                measurement: Mutex::new(Measurement::default()),
            });
            let identity = QuicCertIdentity::generate()?;
            let key = SecpTransportKeypair::generate();
            let km = monad_quic::keygen::generate_from_seed(identity.seed())?;
            let (listener, endpoint, addr) = bind_tcp_and_quic_on_same_port(
                "127.0.0.1:0".parse()?,
                monad_quic::server::build_server_config(&km.cert_pem, &km.key_pem)?,
            )
            .await?;
            let ready = Ready {
                addr,
                pubkey: key.pubkey().to_hex(),
                receiver: receiver.public_key().to_hex(),
            };
            let mut limits = monad_common::config::RelayConnectLimitsConfig::default();
            limits.max_open_per_relay = limits.max_open_per_relay.max(init.config.sessions as u32);
            let config = Arc::new(ServerConfig {
                identity,
                transport_key: Some(key),
                receiver_pubkey_hex: ready.receiver.clone(),
                trusted_mint_units: trusted,
                in_bytes_per_millisat: 1,
                out_bytes_per_millisat: 1,
                bootstrap_capabilities: None,
                relay_wallet_name: "capacity-relay".into(),
                spilman_storage_path: init.db,
                channel_policy,
                connect_limits: limits,
            });
            let (stop_tx, stop_rx) = tokio::sync::oneshot::channel();
            let task = tokio::spawn(run_with_payments_and_registry_and_shutdown(
                listener,
                Some(endpoint),
                config,
                payments.clone(),
                manager.keyset_cache(),
                RelayRuntimeServices {
                    session_registry: Arc::new(SessionRegistry::new()),
                    keyset_refresh: None,
                },
                async {
                    let _ = stop_rx.await;
                },
            ));
            send(&mut ipc, &ready).await?;
            loop {
                let op: String = read_json(&mut ipc).await?;
                if op == "shutdown" {
                    break;
                }
                let snapshot = {
                    let mut m = payments.measurement.lock().unwrap();
                    if op == "start" {
                        m.begin();
                    }
                    anyhow::ensure!(
                        matches!(op.as_str(), "start" | "snapshot" | "stop"),
                        "invalid worker command"
                    );
                    m.snapshot.elapsed_secs = m
                        .start
                        .map(|start| start.elapsed().as_secs_f64())
                        .unwrap_or_default();
                    m.snapshot.per_channel = m.counts.values().copied().collect();
                    m.snapshot.resources = resources();
                    let snapshot = m.snapshot.clone();
                    if op == "stop" {
                        m.start = None;
                    }
                    snapshot
                };
                send(&mut ipc, &snapshot).await?;
            }
            let _ = stop_tx.send(());
            timeout(Duration::from_secs(10), task).await???;
            send(&mut ipc, &Snapshot::default()).await?;
            Ok(())
        })
}

struct ChildGuard(std::process::Child);
impl Drop for ChildGuard {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

struct Client {
    id: usize,
    runtime: connector::ConnectorRuntime,
    route: connector::RouteConnection,
    tunnel: monad_common::h2stream::H2ConnectStream,
}

async fn traffic(
    client: Client,
    cfg: Config,
    bytes: Arc<Vec<AtomicU64>>,
    mut stop: tokio::sync::watch::Receiver<bool>,
) -> anyhow::Result<()> {
    let Client {
        id,
        runtime,
        route,
        mut tunnel,
    } = client;
    let result = async {
        tokio::select! {
            _ = stop.changed() => return Ok(()),
            _ = tokio::time::sleep(Duration::from_millis(cfg.phase_ms(id))) => {}
        }
        let payload = vec![(id % 251) as u8; (cfg.bytes_per_sec * cfg.traffic_tick_ms / 1000) as usize];
        let mut echo = vec![0; payload.len()];
        let mut tick = tokio::time::interval(Duration::from_millis(cfg.traffic_tick_ms));
        tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        loop {
            tokio::select! {
                _ = stop.changed() => break,
                _ = route.wait_for_failure() => anyhow::bail!("client {id}: payment/transport task failed"),
                _ = tick.tick() => {
                    timeout(Duration::from_secs(cfg.io_timeout), async {
                        tunnel.write_all(&payload).await?;
                        tunnel.read_exact(&mut echo).await?;
                        Ok::<_, io::Error>(())
                    }).await??;
                    anyhow::ensure!(echo == payload, "client {id}: corrupt echo");
                    bytes[id].fetch_add(payload.len() as u64, Ordering::Relaxed);
                }
            }
        }
        Ok(())
    }.await;
    drop(tunnel);
    route.close().await;
    runtime.wait_for_setup_cleanup().await;
    result
}

async fn echo_server(
    listener: TcpListener,
    mut stop: tokio::sync::watch::Receiver<bool>,
) -> io::Result<()> {
    let mut tasks = JoinSet::new();
    loop {
        tokio::select! {
            _ = stop.changed() => break,
            accepted = listener.accept() => {
                let (mut stream, _) = accepted.map_err(|error| io::Error::new(
                    error.kind(), format!("capacity echo listener accept failed: {error}"),
                ))?;
                tasks.spawn(async move {
                    let mut buf = [0; 16384];
                    loop {
                        let len = stream.read(&mut buf).await?;
                        if len == 0 { return Ok::<_, io::Error>(()); }
                        stream.write_all(&buf[..len]).await?;
                    }
                });
            }
            Some(_) = tasks.join_next(), if !tasks.is_empty() => {}
        }
    }
    tasks.abort_all();
    while tasks.join_next().await.is_some() {}
    Ok(())
}

async fn monitor_echo<T>(
    tasks: &mut JoinSet<io::Result<()>>,
    work: impl Future<Output = anyhow::Result<T>>,
) -> anyhow::Result<T> {
    tokio::select! {
        // Prefer the originating listener error over a consequent CONNECT
        // refusal when both become ready together.
        biased;
        ended = tasks.join_next() => match ended {
            Some(Ok(Err(error))) => Err(error.into()),
            Some(Err(error)) => Err(anyhow::anyhow!("capacity echo task failed: {error}")),
            _ => Err(anyhow::anyhow!("capacity echo server stopped unexpectedly")),
        },
        result = work => result,
    }
}

#[test]
#[ignore = "manual capacity test; real signatures/SQLite, one relay subprocess"]
fn single_relay_payment_capacity() -> anyhow::Result<()> {
    let cfg = Config::from_env()?;
    println!("capacity config {}", serde_json::to_string(&cfg)?);
    let clock_ticks = std::process::Command::new("getconf")
        .arg("CLK_TCK")
        .output()
        .ok()
        .filter(|o| o.status.success())
        .and_then(|o| String::from_utf8(o.stdout).ok())
        .and_then(|s| s.trim().parse::<u64>().ok());
    println!(
        "capacity debug_assertions={} cpu_ticks_per_second={clock_ticks:?}",
        cfg!(debug_assertions)
    );
    println!("capacity minimum_topup_msats={} channel_capacity_sats={} relay_open_limit={} latency_scope=payment_backend_call_including_signature_and_storage", cfg.minimum_topup(), cfg.capacity_sats(), cfg.sessions.max(1024));
    tokio::runtime::Builder::new_multi_thread()
        .worker_threads(cfg.client_workers)
        .enable_all()
        .build()?
        .block_on(run(cfg))
}

async fn run(cfg: Config) -> anyhow::Result<()> {
    init_test_tracing();
    let directory = tempfile::tempdir()?;
    let socket = directory.path().join("control.sock");
    let ipc_listener = UnixListener::bind(&socket)?;
    let mint = Arc::new(TestMintHelper::new().await?);
    let mut child = ChildGuard(
        std::process::Command::new(std::env::current_exe()?)
            .args([
                "--ignored",
                "--exact",
                "payment_capacity::payment_capacity_relay_worker",
                "--nocapture",
            ])
            .env("MONAD_CAPACITY_WORKER_SOCKET", &socket)
            .env(
                "MONAD_CAPACITY_RELAY_WORKERS",
                cfg.relay_workers.to_string(),
            )
            .env(
                "RUST_LOG",
                env::var("RUST_LOG").unwrap_or_else(|_| "error".into()),
            )
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::null())
            .spawn()?,
    );
    let (stream, _) = timeout(Duration::from_secs(30), ipc_listener.accept()).await??;
    let mut ipc = BufReader::new(stream);
    send(
        &mut ipc,
        &Init {
            config: cfg.clone(),
            db: directory
                .path()
                .join("relay.sqlite")
                .to_string_lossy()
                .into_owned(),
            keyset_id: mint.keyset_id().to_string(),
            keyset_info: mint.keyset_info_json()?,
        },
    )
    .await?;
    let ready: Ready = receive(&mut ipc).await?;
    let pubkey = Secp256k1Pubkey::from_hex(&ready.pubkey)?;
    println!(
        "capacity relay_pid={} generator_pid={}",
        child.0.id(),
        std::process::id()
    );
    let echo = TcpListener::bind("127.0.0.1:0").await?;
    let target = echo.local_addr()?.to_string();
    let mut echo_tasks = JoinSet::new();
    let (echo_stop, echo_stopped) = tokio::sync::watch::channel(false);
    echo_tasks.spawn(echo_server(echo, echo_stopped));
    let mut setup_tasks = JoinSet::new();
    let mut clients = JoinSet::new();
    let bytes = Arc::new(
        (0..cfg.sessions)
            .map(|_| AtomicU64::new(0))
            .collect::<Vec<_>>(),
    );
    let (stop_tx, stop_rx) = tokio::sync::watch::channel(false);
    // Retain setup supervisors independently of their tasks so cancellation
    // cannot discard the handle needed to await production connector cleanup.
    let runtimes = Arc::new(Mutex::new(Vec::new()));
    let mut established = Vec::with_capacity(cfg.sessions);
    let result = monitor_echo(&mut echo_tasks, async {
        let setup_start = Instant::now();
        timeout(Duration::from_secs(cfg.setup_timeout), async {
        for id in 0..cfg.sessions {
            if setup_tasks.len() >= cfg.setup_concurrency {
                established.push(setup_tasks.join_next().await.unwrap()??);
            }
            let mint = mint.clone();
            let receiver = ready.receiver.clone();
            let target = target.clone();
            let cfg = cfg.clone();
            let runtimes = runtimes.clone();
            let addr = ready.addr;
            setup_tasks.spawn(async move {
                let wallet = Arc::new(TestSigningWallet::new(mint.mint(), receiver, MINT.into(), mint.keyset_id().to_string(), mint.keyset_info_json()?).await);
                timeout(Duration::from_secs(cfg.setup_timeout), wallet.pre_create_channel(cfg.capacity_sats())).await?.map_err(anyhow::Error::msg)?;
                let runtime = connector::ConnectorRuntime::with_payment_policy(Some(wallet), PaymentPolicy { channel_funding_token_target_msats: cfg.capacity_sats() * 1000, target_topup_buffer_msats: (cfg.minimum_topup() / 4).max(1000), minimum_topup_msats: cfg.minimum_topup() })?;
                runtimes.lock().unwrap().push(runtime.clone());
                let specification = Route::new(vec![cleartext_route_hop(addr.to_string(), pubkey, true)])?;
                let connected = timeout(Duration::from_secs(cfg.setup_timeout), connector::connect_route_with_runtime(&specification, &runtime)).await;
                runtime.wait_for_setup_cleanup().await;
                let route = connected??;
                let opened = timeout(Duration::from_secs(cfg.io_timeout), route.final_connection_arc().open_tunnel(&target)).await;
                let tunnel = match opened {
                    Ok(Ok(tunnel)) => tunnel,
                    Ok(Err(error)) => { route.close().await; return Err(error.into()); }
                    Err(error) => { route.close().await; return Err(error.into()); }
                };
                Ok::<_, anyhow::Error>(Client { id, runtime, route, tunnel })
            });
        }
        while let Some(result) = setup_tasks.join_next().await { established.push(result??); }
        Ok::<_, anyhow::Error>(())
        }).await??;
        println!("capacity ready sessions={} setup_secs={:.3}", established.len(), setup_start.elapsed().as_secs_f64());
        for client in established.drain(..) { clients.spawn(traffic(client, cfg.clone(), bytes.clone(), stop_rx.clone())); }
        tokio::select! {
            _ = tokio::time::sleep(Duration::from_secs(cfg.warmup)) => {},
            result = clients.join_next() => anyhow::bail!("client exited during warmup: {result:?}"),
        }
        let generator_before = resources();
        let relay_before = command(&mut ipc, "start").await?;
        let before: Vec<_> = bytes.iter().map(|v| v.load(Ordering::Relaxed)).collect();
        let deadline = tokio::time::Instant::now() + Duration::from_secs(cfg.duration);
        let mut report = tokio::time::interval(Duration::from_secs(5));
        report.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        report.tick().await;
        loop {
            tokio::select! {
                _ = tokio::time::sleep_until(deadline) => break,
                result = clients.join_next() => anyhow::bail!("client exited during measurement: {result:?}"),
                _ = report.tick() => {
                    let s = command(&mut ipc, "snapshot").await?;
                    println!("capacity progress elapsed_s={:.1} accepted={} payments_per_sec={:.2} rejected={} relay_rss_kib={:?}", s.elapsed_secs, s.accepted, s.accepted as f64 / s.elapsed_secs, s.rejected, s.resources.rss_kib);
                }
            }
        }
        let snapshot = command(&mut ipc, "stop").await?;
        let delivered: Vec<_> = bytes.iter().zip(&before).map(|(value, before)| value.load(Ordering::Relaxed) - before).collect();
        let minimum_bytes = *delivered.iter().min().unwrap();
        println!("capacity summary sessions={} elapsed_s={:.3} accepted={} payments_per_sec={:.2} rejected={} links={} unlinks={} min_payments_per_channel={} max_payments_per_channel={} processing_p50_upper_us={} processing_p95_upper_us={} processing_p99_upper_us={} processing_max_us={} min_echo_bytes={} total_echo_bytes={}", cfg.sessions, snapshot.elapsed_secs, snapshot.accepted, snapshot.accepted as f64 / snapshot.elapsed_secs, snapshot.rejected, snapshot.links, snapshot.unlinks, snapshot.per_channel.iter().min().unwrap_or(&0), snapshot.per_channel.iter().max().unwrap_or(&0), snapshot.percentile_upper_us(50), snapshot.percentile_upper_us(95), snapshot.percentile_upper_us(99), snapshot.latency_us_max, minimum_bytes, delivered.iter().sum::<u64>());
        println!("capacity resources relay_cpu_ticks_delta={:?} relay={:?} generator_cpu_ticks_delta={:?} generator={:?}", snapshot.resources.cpu_ticks.zip(relay_before.resources.cpu_ticks).map(|(after,before)| after-before), snapshot.resources, resources().cpu_ticks.zip(generator_before.cpu_ticks).map(|(after,before)| after-before), resources());
        println!("capacity cadence observed_gaps={} mean_gap_s={:.3} max_gap_s={:.3}", snapshot.gap_count, snapshot.gap_sum_us as f64 / snapshot.gap_count.max(1) as f64 / 1e6, snapshot.gap_max_us as f64 / 1e6);
        anyhow::ensure!(snapshot.rejected == 0 && snapshot.links == 0 && snapshot.unlinks == 0, "payment errors or channel churn during measurement");
        anyhow::ensure!(snapshot.per_channel.len() == cfg.sessions && snapshot.per_channel.iter().all(|&n| n > 0), "not every session made a measured payment");
        anyhow::ensure!(minimum_bytes as f64 >= cfg.bytes_per_sec as f64 * snapshot.elapsed_secs * 0.90, "at least one client delivered less than 90% of offered traffic");
        Ok::<_, anyhow::Error>(())
    }).await;
    // Cleanup also runs on an ordinary experiment failure. JoinSet drops abort
    // remaining setup/echo tasks; the subprocess guard always kills and reaps.
    let _ = stop_tx.send(true);
    setup_tasks.abort_all();
    while let Some(result) = setup_tasks.join_next().await {
        if let Ok(Ok(client)) = result {
            established.push(client);
        }
    }
    for Client {
        runtime,
        route,
        tunnel,
        ..
    } in established
    {
        drop(tunnel);
        route.close().await;
        runtime.wait_for_setup_cleanup().await;
    }
    let cleanup = timeout(Duration::from_secs(15), async {
        while let Some(result) = clients.join_next().await {
            result??;
        }
        Ok::<_, anyhow::Error>(())
    })
    .await;
    clients.abort_all();
    while clients.join_next().await.is_some() {}
    let runtimes = std::mem::take(&mut *runtimes.lock().unwrap());
    for runtime in runtimes {
        runtime.wait_for_setup_cleanup().await;
    }
    let _ = echo_stop.send(true);
    let mut echo_result = Ok(());
    while let Some(result) = echo_tasks.join_next().await {
        if let Err(error) = result
            .map_err(anyhow::Error::from)
            .and_then(|r| r.map_err(anyhow::Error::from))
        {
            echo_result = Err(error);
        }
    }
    let shutdown = command(&mut ipc, "shutdown").await;
    echo_result?;
    result?;
    cleanup??;
    shutdown?;
    anyhow::ensure!(child.0.wait()?.success(), "relay worker failed");
    Ok(())
}

#[test]
fn capacity_histogram_and_bounds() {
    let s = Snapshot {
        accepted: 4,
        latency_buckets: vec![1, 1, 0, 2],
        ..Default::default()
    };
    assert_eq!(s.percentile_upper_us(50), 2);
    assert_eq!(s.percentile_upper_us(95), 8);
    let mut cfg = Config {
        sessions: 25,
        duration: 30,
        payment_interval: 10,
        bytes_per_sec: 1000,
        traffic_tick_ms: 1000,
        warmup: 12,
        setup_concurrency: 8,
        setup_timeout: 300,
        io_timeout: 10,
        client_workers: 2,
        relay_workers: 2,
        seed: 1,
    };
    assert!(cfg.validate().is_ok());
    assert_eq!(cfg.minimum_topup(), 20_000);
    assert!(cfg.capacity_sats() * 1000 > 2 * cfg.bytes_per_sec * (cfg.duration + cfg.warmup));
    cfg.duration = 1;
    assert!(cfg.validate().is_err());
}

#[tokio::test]
async fn capacity_echo_failure_interrupts_work_and_preserves_original_error() {
    for secondary_failure in [false, true] {
        let mut tasks = JoinSet::new();
        let (ready, received) = tokio::sync::oneshot::channel();
        tasks.spawn(async move {
            let _ = ready.send(());
            Err(io::Error::other("injected echo accept failure"))
        });
        received.await.unwrap();
        let work = async {
            if secondary_failure {
                anyhow::bail!("secondary TCP connection refused");
            }
            std::future::pending::<anyhow::Result<()>>().await
        };
        let error = timeout(Duration::from_secs(1), monitor_echo(&mut tasks, work))
            .await
            .unwrap()
            .unwrap_err();
        assert!(error.to_string().contains("injected echo accept failure"));
        assert!(tasks.is_empty());
    }
}

#[test]
fn capacity_measurement_excludes_setup_and_teardown_and_keeps_idle_sessions() {
    let mut m = Measurement::default();
    m.counts.insert("idle".into(), 3);
    let setup = Instant::now() - Duration::from_secs(1);
    m.record(setup, 999, "setup", true);
    m.begin();
    m.record(setup, 999, "cross-boundary", true);
    m.record(Instant::now(), 7, "active", true);
    m.record(Instant::now(), 17, "active", true);
    m.record(Instant::now(), 99, "rejected", false);
    m.start = None;
    m.record(Instant::now(), 999, "teardown", true);
    assert_eq!(
        m.counts,
        BTreeMap::from([("active".into(), 2), ("idle".into(), 0)])
    );
    assert_eq!(m.snapshot.accepted, 2);
    assert_eq!(m.snapshot.rejected, 1);
    assert_eq!(m.snapshot.gap_count, 1);
    assert_eq!(m.snapshot.latency_us_sum, 24);
    assert_eq!(m.snapshot.percentile_upper_us(95), 32);
}
