use monad_client::connector::{self, ConnectorRuntime, Hop, HopIdentity};
use monad_client::wallet::{MockWallet, MonadWallet};
use monad_common::quic_cert_identity::QuicCertIdentity;
use monad_common::secp_identity::{Secp256k1Pubkey, SecpTransportKeypair};
use monad_relay::listener::{run_with_payments, ServerConfig, SpilmanMintCache};
use monad_relay::payments::testing::InMemoryRelayPayments;
use std::collections::BTreeMap;
use std::env;
use std::io;
use std::io::Write;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::sync::OnceLock;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio::time::Instant;

const MAX_SHARED_BIND_RETRIES: usize = 32;
const SYNTHETIC_TEST_MINT_URL: &str = "https://test-mint.invalid";
const SYNTHETIC_TEST_MINT_UNIT: &str = "msat";
const SYNTHETIC_TEST_KEYSET_ID: &str = "00testkeyset0000";

static TRACING_INIT: OnceLock<()> = OnceLock::new();
const STRESS_PATH_SEED: u64 = 0x4d4f_4e41_445f_5354;

#[derive(Debug, Clone, Copy)]
struct StressConfig {
    relays: usize,
    circuits: usize,
    hops_per_circuit: usize,
    streams_per_circuit: usize,
    payload_bytes: usize,
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
            payload_bytes: read_env_usize("MONAD_STRESS_PAYLOAD_BYTES", default.payload_bytes),
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
    target: String,
    streams_per_circuit: usize,
    payload_bytes: usize,
    verbose: bool,
    progress: ProgressTracker,
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
    SpilmanMintCache {
        advertised,
        keyset_info_json_by_mint: BTreeMap::new(),
    }
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
        payment_receiver_secret: cashu::nuts::SecretKey::generate(),
        trusted_mint_units: BTreeMap::new(),
    });
    let payments = Arc::new(InMemoryRelayPayments::new());
    let synthetic_mint_cache = Arc::new(synthetic_test_mint_cache());

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

async fn run_circuit(
    circuit_id: usize,
    runtime: ConnectorRuntime,
    hops: Vec<Hop>,
    config: CircuitRunConfig,
) -> io::Result<CircuitStats> {
    if config.verbose {
        let hop_path = hops
            .iter()
            .map(|hop| hop.addr.as_str())
            .collect::<Vec<_>>()
            .join(" -> ");
        println!(
            "circuit {circuit_id}: building {}-hop QUIC chain via [{hop_path}]",
            hops.len(),
        );
        println!("circuit {circuit_id}: connector will fund all hops via shared MockWallet");
    }
    let setup_start = Instant::now();
    let conn = connector::connect_through_chain_with_runtime(&hops, &runtime).await?;
    if config.verbose {
        println!("circuit {circuit_id}: chain established and all hops funded");
    }
    let setup_elapsed = setup_start.elapsed();

    let conn = Arc::new(conn);
    let data_start = Instant::now();
    let mut handles = Vec::with_capacity(config.streams_per_circuit);

    if config.verbose {
        println!(
            "circuit {circuit_id}: starting {} stream(s) with {} byte payloads to {}",
            config.streams_per_circuit, config.payload_bytes, config.target
        );
    }

    for stream_idx in 0..config.streams_per_circuit {
        let conn = Arc::clone(&conn);
        let target = config.target.clone();
        let pattern = ((circuit_id + stream_idx) % 251) as u8;
        let progress = config.progress.clone();
        let verbose = config.verbose;
        let payload_bytes = config.payload_bytes;
        handles.push(tokio::spawn(async move {
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
            result
        }));
    }

    let mut stats = CircuitStats {
        setup_micros: setup_elapsed.as_micros(),
        ..CircuitStats::default()
    };

    for handle in handles {
        let (sent, received) = handle
            .await
            .map_err(|e| io::Error::other(format!("stream task join error: {e}")))??;
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
        "stress start relays={} circuits={} hops={} streams_per_circuit={} payload_bytes={}",
        config.relays,
        config.circuits,
        config.hops_per_circuit,
        config.streams_per_circuit,
        config.payload_bytes,
    );

    let echo_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let echo_addr = echo_listener.local_addr().unwrap();
    println!("stress echo target listening on {echo_addr}");
    tokio::spawn(run_echo_server(echo_listener));

    let mut relays = Vec::with_capacity(config.relays);
    for relay_idx in 0..config.relays {
        let relay = start_monad_relay().await;
        println!(
            "stress relay {relay_idx}: addr={} pubkey={}",
            relay.0, relay.1
        );
        relays.push(relay);
    }
    let runtime = ConnectorRuntime::new(Some(Arc::new(MockWallet::new()) as Arc<dyn MonadWallet>))
        .expect("stress runtime should construct a shared first-hop QUIC pool");
    let total_streams = config.circuits * config.streams_per_circuit;
    let progress = ProgressTracker::new(!config.verbose(), total_streams);

    let total_start = Instant::now();
    let mut handles = Vec::with_capacity(config.circuits);
    for circuit_id in 0..config.circuits {
        let indices = sample_relay_indices(config.relays, config.hops_per_circuit, circuit_id);
        let hops = indices
            .into_iter()
            .map(|relay_idx| Hop {
                addr: relays[relay_idx].0.to_string(),
                identity: HopIdentity::Secp256k1(relays[relay_idx].1),
                use_quic: true,
            })
            .collect::<Vec<_>>();
        let circuit_config = CircuitRunConfig {
            target: echo_addr.to_string(),
            streams_per_circuit: config.streams_per_circuit,
            payload_bytes: config.payload_bytes,
            verbose: config.verbose(),
            progress: progress.clone(),
        };
        handles.push(tokio::spawn(run_circuit(
            circuit_id,
            runtime.clone(),
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
    let throughput_mib_per_s = if total_elapsed.as_secs_f64() > 0.0 {
        total_bytes as f64 / (1024.0 * 1024.0) / total_elapsed.as_secs_f64()
    } else {
        0.0
    };

    println!(
        "stress summary relays={} circuits={} sessions={} streams={} payload_bytes={} successes={} failures={} streams_ok={} sent_bytes={} recv_bytes={} total_bytes={} avg_setup_ms={:.2} avg_data_ms={:.2} total_elapsed_s={:.3} throughput_mib_per_s={:.2}",
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
        payload_bytes: 4 * 1024,
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
        payload_bytes: 32 * 1024,
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
        payload_bytes: 64 * 1024,
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
        payload_bytes: 64 * 1024,
    }))
    .await;
}
