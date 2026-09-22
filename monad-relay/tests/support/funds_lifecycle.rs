use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use axum::{
    body::{to_bytes, Body},
    extract::Request,
    middleware::Next,
};
use cashu::nuts::{CheckStateRequest, Proof, RestoreRequest, State, SwapRequest, SwapResponse};
use cdk_spilman_test_mint::{build_router, rotate_sat_keyset, TestMintHelper};
use monad_client::loose_proof_wallet::{LooseProofWallet, NewLooseProof};
use monad_client::runtime::CONFIGURED_CLIENT_WALLET_NAME;
use monad_common::secp_identity::SecpTransportKeypair;
use rusqlite::{Connection, OpenFlags};
use serde_json::Value;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{Notify, Semaphore};
use tokio::task::JoinSet;

const DEADLINE: Duration = Duration::from_secs(45);
const INITIAL: u64 = 16_384;

pub async fn persistent_mint_worker() {
    use std::os::unix::fs::OpenOptionsExt;
    let Ok(root) = std::env::var("MONAD_TEST_MINT_ROOT") else {
        return;
    };
    let root = PathBuf::from(root);
    let port = std::env::var("MONAD_TEST_MINT_PORT")
        .unwrap()
        .parse()
        .unwrap();
    let config = cdk_spilman_test_mint::TestMintConfig {
        base_url: std::env::var("MONAD_TEST_MINT_URL").unwrap(),
        default_input_fee_ppk: 100,
        ..cdk_spilman_test_mint::TestMintConfig::for_port(port)
    };
    let mint = Arc::new(
        cdk_spilman_test_mint::build_persistent_test_mint(&config, &root.join("mint.db"))
            .await
            .unwrap(),
    );
    let bootstrap = root.join("initial-proofs.json");
    if !bootstrap.exists() {
        let proofs = cdk_spilman_test_mint::mint_test_proofs(&mint, INITIAL)
            .await
            .unwrap();
        let file = std::fs::OpenOptions::new()
            .create_new(true)
            .write(true)
            .mode(0o600)
            .open(bootstrap)
            .unwrap();
        serde_json::to_writer(&file, &proofs).unwrap();
        file.sync_all().unwrap();
    }
    cdk_spilman_test_mint::serve_existing_mint_with_shutdown(mint, config, std::future::pending())
        .await
        .unwrap();
}

async fn start_mint_child(root: &Path, port: u16, url: &str) -> Process {
    let mut command = Command::new(std::env::current_exe().unwrap());
    command
        .args(["--exact", "persistent_mint_worker", "--nocapture"])
        .env("MONAD_TEST_MINT_ROOT", root)
        .env("MONAD_TEST_MINT_PORT", port.to_string())
        .env("MONAD_TEST_MINT_URL", url)
        .env("RUST_LOG", "off")
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    for unit in ["SAT", "MSAT", "USD"] {
        command.env_remove(format!("TEST_MINT_FEE_PPK_{unit}"));
        command.env_remove(format!("CDK_MINTD_INPUT_FEE_PPK_{unit}"));
    }
    let mut child = Process(command.spawn().unwrap());
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(1))
        .no_proxy()
        .build()
        .unwrap();
    tokio::time::timeout(DEADLINE, async {
        loop {
            assert!(
                child.0.try_wait().unwrap().is_none(),
                "persistent mint worker exited"
            );
            if client
                .get(format!("http://127.0.0.1:{port}/v1/keysets"))
                .send()
                .await
                .is_ok_and(|r| r.status().is_success())
            {
                break;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    })
    .await
    .expect("persistent mint readiness");
    child
}

// Never derive Debug: requests contain bearer secrets and signing witnesses.
#[derive(Default)]
struct Ledger {
    swaps: BTreeMap<Vec<String>, (SwapRequest, SwapResponse)>,
    requests: usize,
    attempts: Vec<SwapRequest>,
    hold_success: bool,
    hold_request: bool,
    discard_request: bool,
    offline: bool,
    http_requests: usize,
    rejections: usize,
    inactive_rejections: usize,
    race_barrier: Option<Arc<tokio::sync::Barrier>>,
    raced_requests: usize,
}

struct Process(Child);

struct GateFinished(Arc<Notify>);

impl Drop for GateFinished {
    fn drop(&mut self) {
        self.0.notify_one();
    }
}

impl Process {
    fn spawn(binary: &Path, args: &[&str], config: &Path) -> Self {
        Self::spawn_with_env(binary, args, config, &[])
    }

    fn spawn_with_env(binary: &Path, args: &[&str], config: &Path, env: &[(&str, &str)]) -> Self {
        eprintln!(
            "funds process {} {}",
            binary.file_name().unwrap().to_string_lossy(),
            args[..args.len().min(2)].join(" ")
        );
        Self(
            Command::new(binary)
                .arg(args[0])
                .arg("--config")
                .arg(config)
                .args(&args[1..])
                .env("RUST_LOG", "off")
                .env("NO_PROXY", "*")
                .env_remove("MONAD_FUNDS_BOUNDARY")
                .env_remove("MONAD_FUNDS_IPC")
                .env_remove("MONAD_FUNDS_LIFETIME")
                .envs(env.iter().copied())
                .stdin(Stdio::null())
                .stdout(if args.contains(&"--json") {
                    Stdio::piped()
                } else {
                    Stdio::null()
                })
                .stderr(
                    std::fs::File::create(config.parent().unwrap().join("last-process.stderr"))
                        .unwrap(),
                )
                .spawn()
                .expect("spawn production CLI"),
        )
    }

    async fn status(mut self) -> std::process::ExitStatus {
        tokio::time::timeout(DEADLINE, async {
            loop {
                if let Some(status) = self.0.try_wait().unwrap() {
                    break status;
                }
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
        })
        .await
        .expect("maintenance CLI deadline")
    }

    async fn success(self) {
        let status = self.status().await;
        assert!(
            status.success(),
            "maintenance CLI failed: {status}; output suppressed to protect secrets"
        );
    }

    async fn json_status(mut self) -> (std::process::ExitStatus, Option<Value>) {
        let mut pipe = self.0.stdout.take().expect("JSON process stdout");
        let reader = tokio::task::spawn_blocking(move || {
            let mut bytes = Vec::new();
            std::io::Read::read_to_end(&mut pipe, &mut bytes).unwrap();
            bytes
        });
        let status = self.status().await;
        let bytes = reader.await.unwrap();
        let json = if bytes.is_empty() {
            None
        } else {
            Some(serde_json::from_slice(&bytes).expect("JSON CLI result"))
        };
        (status, json)
    }

    async fn json(self) -> Value {
        let (status, json) = self.json_status().await;
        assert!(
            status.success(),
            "JSON maintenance CLI failed: {status}; output redacted"
        );
        json.expect("JSON CLI result")
    }
}

impl Drop for Process {
    fn drop(&mut self) {
        if self.0.try_wait().ok().flatten().is_none() {
            let _ = self.0.kill();
            // Reap, including on assertion failure. No subprocess can retain a DB lock.
            let _ = self.0.wait();
        }
    }
}

pub struct Fixture {
    dir: Option<tempfile::TempDir>,
    config: PathBuf,
    client_bin: PathBuf,
    relay_bin: PathBuf,
    mint: Option<TestMintHelper>,
    mint_process: Option<Process>,
    mint_port: Option<u16>,
    mint_url: String,
    external_url: Option<String>,
    socks: std::net::SocketAddr,
    target: std::net::SocketAddr,
    ledger: Arc<Mutex<Ledger>>,
    committed: Arc<Notify>,
    gate_finished: Arc<Notify>,
    release: Arc<Semaphore>,
    tasks: JoinSet<()>,
    cycle: usize,
}

impl Fixture {
    pub async fn start() -> Self {
        Self::start_with_persistent_mint(false).await
    }

    pub async fn start_with_persistent_mint(persistent: bool) -> Self {
        Self::start_mint(persistent, None).await
    }

    #[allow(dead_code)] // Used only by the separate opt-in external characterization target.
    pub async fn start_external(url: String, proofs: PathBuf) -> Self {
        assert!(
            url.starts_with("http://127.0.0.1:"),
            "disposable loopback mint only"
        );
        Self::start_mint(false, Some((url, proofs))).await
    }

    async fn start_mint(persistent: bool, external: Option<(String, PathBuf)>) -> Self {
        let client_bin = PathBuf::from(
            std::env::var("MONAD_FUNDS_CLIENT_BIN").expect("set MONAD_FUNDS_CLIENT_BIN via Make"),
        );
        let relay_bin = PathBuf::from(
            std::env::var("MONAD_FUNDS_RELAY_BIN").expect("set MONAD_FUNDS_RELAY_BIN via Make"),
        );
        assert!(
            client_bin.is_file() && relay_bin.is_file(),
            "build both production binaries first"
        );
        let dir = tempfile::Builder::new()
            .prefix("monad-funds-secret-")
            .tempdir()
            .unwrap();
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let mint_url = format!("http://{}", listener.local_addr().unwrap());
        let (mint, mint_process, mint_port, router) = if let Some((url, proofs)) = &external {
            std::fs::copy(proofs, dir.path().join("initial-proofs.json")).unwrap();
            let url = url.clone();
            let client = reqwest::Client::builder()
                .timeout(DEADLINE)
                .no_proxy()
                .build()
                .unwrap();
            let router = axum::Router::new().fallback(move |request: Request| {
                let client = client.clone();
                let url = url.clone();
                async move {
                    let (parts, body) = request.into_parts();
                    let bytes = to_bytes(body, 4 * 1024 * 1024).await.unwrap();
                    let checked_swap = if parts.uri.path() == "/v1/swap" {
                        let swap = serde_json::from_slice::<SwapRequest>(&bytes).expect("swap body redacted");
                        let states: cashu::nuts::CheckStateResponse = client.post(format!("{url}/v1/checkstate"))
                            .json(&CheckStateRequest { ys: swap.inputs().iter().map(|p| p.y().unwrap()).collect() })
                            .send().await.unwrap().error_for_status().unwrap().json().await.unwrap();
                        let restored: cashu::nuts::RestoreResponse = client.post(format!("{url}/v1/restore"))
                            .json(&RestoreRequest { outputs: swap.outputs().to_vec() })
                            .send().await.unwrap().error_for_status().unwrap().json().await.unwrap();
                        Some((swap, states, restored))
                    } else { None };
                    let response = client.request(parts.method, format!("{url}{}", parts.uri))
                        .header("content-type", "application/json").body(bytes).send().await.unwrap();
                    let status = response.status();
                    let bytes = response.bytes().await.unwrap();
                    if !status.is_success() {
                        if let Some((swap, before_states, before_restore)) = checked_swap {
                            let states: cashu::nuts::CheckStateResponse = client.post(format!("{url}/v1/checkstate"))
                                .json(&CheckStateRequest { ys: swap.inputs().iter().map(|p| p.y().unwrap()).collect() })
                                .send().await.unwrap().error_for_status().unwrap().json().await.unwrap();
                            assert_eq!(states.states.len(), swap.inputs().len());
                            assert!(serde_json::to_value(&states).unwrap() == serde_json::to_value(&before_states).unwrap(),
                                "rejection changed input states (proofs redacted)");
                            let restored: cashu::nuts::RestoreResponse = client.post(format!("{url}/v1/restore"))
                                .json(&RestoreRequest { outputs: swap.outputs().to_vec() })
                                .send().await.unwrap().error_for_status().unwrap().json().await.unwrap();
                            assert!(serde_json::to_value(&restored).unwrap() == serde_json::to_value(&before_restore).unwrap(),
                                "rejection changed restore outputs (proofs redacted)");
                            let error: Value = serde_json::from_slice(&bytes).expect("error body redacted");
                            if matches!(error["code"].as_u64(), Some(12001 | 12002)) {
                                assert!(states.states.iter().all(|s| s.state == State::Unspent));
                                assert!(restored.outputs.is_empty() && restored.signatures.is_empty());
                                eprintln!("external rejection status={} code={} all_inputs_unspent={} restore_outputs=0",
                                    status.as_u16(), error["code"], states.states.len());
                            }
                        }
                    }
                    axum::response::Response::builder().status(status)
                        .header("content-type", "application/json").body(Body::from(bytes)).unwrap()
                }
            });
            (None, None, None, router)
        } else if persistent {
            let reservation = TcpListener::bind("127.0.0.1:0").await.unwrap();
            let port = reservation.local_addr().unwrap().port();
            drop(reservation);
            let child = start_mint_child(dir.path(), port, &mint_url).await;
            let client = reqwest::Client::builder()
                .timeout(DEADLINE)
                .no_proxy()
                .build()
                .unwrap();
            let router = axum::Router::new().fallback(move |request: Request| {
                let client = client.clone();
                async move {
                    let (parts, body) = request.into_parts();
                    let bytes = to_bytes(body, 4 * 1024 * 1024).await.unwrap();
                    // No parent response cache: every request reaches the current child.
                    let response = client
                        .request(
                            parts.method,
                            format!("http://127.0.0.1:{port}{}", parts.uri),
                        )
                        .header("content-type", "application/json")
                        .body(bytes)
                        .send()
                        .await
                        .expect("mint child HTTP");
                    let status = response.status();
                    let bytes = response.bytes().await.unwrap();
                    axum::response::Response::builder()
                        .status(status)
                        .header("content-type", "application/json")
                        .body(Body::from(bytes))
                        .unwrap()
                }
            });
            (None, Some(child), Some(port), router)
        } else {
            let mint = TestMintHelper::new().await.unwrap();
            rotate_sat_keyset(&mint.mint(), 100).await.unwrap();
            let router = build_router(mint.mint()).await.unwrap();
            (Some(mint), None, None, router)
        };
        let ledger = Arc::new(Mutex::new(Ledger::default()));
        let committed = Arc::new(Notify::new());
        let gate_finished = Arc::new(Notify::new());
        let release = Arc::new(Semaphore::new(0));
        let router = router.layer(axum::middleware::from_fn({
            let ledger = ledger.clone();
            let committed = committed.clone();
            let gate_finished = gate_finished.clone();
            let release = release.clone();
            move |request: Request, next: Next| {
                let ledger = ledger.clone();
                let committed = committed.clone();
                let gate_finished = gate_finished.clone();
                let release = release.clone();
                async move {
                    let offline = {
                        let mut ledger = ledger.lock().unwrap();
                        ledger.http_requests += 1;
                        ledger.offline
                    };
                    if offline {
                        return axum::response::Response::builder()
                            .status(503)
                            .body(Body::empty())
                            .unwrap();
                    }
                    if request.uri().path() != "/v1/swap" {
                        return next.run(request).await;
                    }
                    let (parts, body) = request.into_parts();
                    let bytes = to_bytes(body, 4 * 1024 * 1024).await.unwrap();
                    let swap: SwapRequest = serde_json::from_slice(&bytes)
                        .expect("decode swap request (body redacted)");
                    {
                        let mut ledger = ledger.lock().unwrap();
                        ledger.requests += 1;
                        ledger.attempts.push(swap.clone());
                    }
                    let hold = std::mem::take(&mut ledger.lock().unwrap().hold_request);
                    if hold {
                        let _finished = GateFinished(gate_finished.clone());
                        committed.notify_one();
                        let permit = tokio::time::timeout(DEADLINE, release.acquire())
                            .await
                            .expect("request gate deadline")
                            .unwrap();
                        permit.forget();
                        if std::mem::take(&mut ledger.lock().unwrap().discard_request) {
                            return axum::response::Response::builder()
                                .status(503)
                                .body(Body::empty())
                                .unwrap();
                        }
                    }
                    let barrier = {
                        let mut ledger = ledger.lock().unwrap();
                        let barrier = ledger.race_barrier.clone();
                        if barrier.is_some() {
                            ledger.raced_requests += 1;
                        }
                        barrier
                    };
                    if let Some(barrier) = barrier {
                        tokio::time::timeout(DEADLINE, barrier.wait())
                            .await
                            .expect("both race swaps must reach mint");
                    }
                    let response = next
                        .run(Request::from_parts(parts, Body::from(bytes)))
                        .await;
                    if !response.status().is_success() {
                        ledger.lock().unwrap().rejections += 1;
                        let (parts, body) = response.into_parts();
                        let bytes = to_bytes(body, 4 * 1024 * 1024).await.unwrap();
                        let error: Value = serde_json::from_slice(&bytes).unwrap();
                        if error["code"].as_u64() == Some(12002) {
                            ledger.lock().unwrap().inactive_rejections += 1;
                        }
                        return axum::response::Response::from_parts(parts, Body::from(bytes));
                    }
                    let (parts, body) = response.into_parts();
                    let bytes = to_bytes(body, 4 * 1024 * 1024).await.unwrap();
                    let result: SwapResponse = serde_json::from_slice(&bytes)
                        .expect("decode swap response (body redacted)");
                    let mut ys = swap
                        .inputs()
                        .iter()
                        .map(|p| p.y().unwrap().to_string())
                        .collect::<Vec<_>>();
                    ys.sort();
                    let hold = {
                        let mut ledger = ledger.lock().unwrap();
                        // A cached successful replay is not another mint transaction.
                        ledger.swaps.entry(ys).or_insert((swap, result));
                        std::mem::take(&mut ledger.hold_success)
                    };
                    if hold {
                        let _finished = GateFinished(gate_finished.clone());
                        committed.notify_one();
                        let permit = tokio::time::timeout(DEADLINE, release.acquire())
                            .await
                            .expect("HTTP crash gate deadline")
                            .unwrap();
                        permit.forget();
                    }
                    axum::response::Response::from_parts(parts, Body::from(bytes))
                }
            }
        }));
        let mut tasks = JoinSet::new();
        tasks.spawn(async move {
            axum::serve(listener, router).await.unwrap();
        });
        let target_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let target = target_listener.local_addr().unwrap();
        tasks.spawn(async move {
            let mut connections = JoinSet::new();
            loop {
                tokio::select! {
                    accepted = target_listener.accept() => {
                        let (mut stream, _) = accepted.unwrap();
                        connections.spawn(async move {
                            let (mut read, mut write) = stream.split();
                            let _ = tokio::io::copy(&mut read, &mut write).await;
                        });
                    }
                    _ = connections.join_next(), if !connections.is_empty() => {}
                }
            }
        });
        let socks_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let socks = socks_listener.local_addr().unwrap();
        let relay_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let relay = relay_listener.local_addr().unwrap();
        let key = SecpTransportKeypair::generate();
        let config = dir.path().join("monad.yaml");
        std::fs::write(
            &config,
            format!(
                r#"relay_wallet:
  db_path: {root}/relay.db
client_wallet:
  loose_db_path: {root}/loose.db
  channel_db_path: {root}/channel.db
  sender_secret_hex: "{sender}"
  channel_funding_token_target_msats: 1024000
  target_topup_buffer_msats: 100000
relays:
  - name: funds
    receiver_secret_hex: "{receiver}"
    quic_cert_seed: "{cert}"
    transport_key: "{transport}"
    listen: {relay}
    channel_policy:
      min_expiry: 1s
    trusted_mints:
      - url: {mint_url}
        units: [sat]
    pricing:
      in_bytes_per_millisat: 1000000
      out_bytes_per_millisat: 1000000
clients:
  - name: funds
    socks: {socks}
    route:
      - addr: {relay}
        pubkey: "{pubkey}"
"#,
                root = dir.path().display(),
                sender = "01".repeat(32),
                receiver = "02".repeat(32),
                cert = "03".repeat(32),
                transport = hex::encode(key.normalized_secret_bytes()),
                pubkey = key.pubkey().to_hex()
            ),
        )
        .unwrap();
        // Only initial funding. Later cycles must live on recovered change/refunds.
        let proofs: Vec<Proof> = if let Some(mint) = &mint {
            tokio::time::timeout(DEADLINE, mint.mint_proofs(INITIAL))
                .await
                .unwrap()
                .unwrap()
        } else {
            serde_json::from_slice(&std::fs::read(dir.path().join("initial-proofs.json")).unwrap())
                .expect("bootstrap proofs (redacted)")
        };
        let wallet =
            LooseProofWallet::open(dir.path().join("loose.db"), CONFIGURED_CLIENT_WALLET_NAME)
                .unwrap();
        wallet
            .import_proofs(
                &proofs
                    .iter()
                    .map(|p| NewLooseProof {
                        proof_id: p.y().unwrap().to_string(),
                        mint_url: mint_url.clone(),
                        unit: "sat".into(),
                        keyset_id: p.keyset_id.to_string(),
                        amount_raw: u64::from(p.amount),
                        proof_json: serde_json::to_string(p).unwrap(),
                        source_quote_id: None,
                        source_batch_id: None,
                    })
                    .collect::<Vec<_>>(),
            )
            .unwrap();
        drop(wallet);
        drop(socks_listener);
        drop(relay_listener);
        Self {
            dir: Some(dir),
            config,
            client_bin,
            relay_bin,
            mint,
            mint_process,
            mint_port,
            mint_url,
            external_url: external.map(|(url, _)| url),
            socks,
            target,
            ledger,
            committed,
            gate_finished,
            release,
            tasks,
            cycle: 0,
        }
    }

    fn client(&self, args: &[&str]) -> Process {
        Process::spawn(&self.client_bin, args, &self.config)
    }

    fn memory_mint(&self) -> Arc<cdk::Mint> {
        self.mint
            .as_ref()
            .expect("rotation scenarios use memory fixture")
            .mint()
    }

    async fn mint_post<T: serde::de::DeserializeOwned>(
        &self,
        path: &str,
        body: &impl serde::Serialize,
    ) -> T {
        reqwest::Client::builder()
            .timeout(DEADLINE)
            .no_proxy()
            .build()
            .unwrap()
            .post(format!("{}{path}", self.mint_url))
            .json(body)
            .send()
            .await
            .unwrap()
            .error_for_status()
            .unwrap()
            .json()
            .await
            .expect("mint response (redacted)")
    }

    pub async fn persistent_mint_restart(&mut self) {
        self.cycle += 1;
        assert!(self.mint.is_none(), "no parent in-memory mint allowed");
        let relay = self.relay(&["run"]);
        let client = self.client(&["run"]);
        self.roundtrip().await;
        drop(client);
        drop(relay);
        let channel = self.active_channel();
        self.ledger.lock().unwrap().hold_success = true;
        let close = self.relay(&["wallet", "close", "--channel-id", &channel]);
        tokio::time::timeout(DEADLINE, self.committed.notified())
            .await
            .expect("committed close response gate");
        // The gate has consumed the child's complete successful HTTP response.
        // Killing and reaping removes its in-memory HTTP cache as well as the mint.
        assert_eq!(self.ledger.lock().unwrap().swaps.len(), 2);
        drop(close);
        drop(self.mint_process.take());
        self.release_gate().await;
        self.mint_process = Some(
            start_mint_child(
                self.dir.as_ref().unwrap().path(),
                self.mint_port.unwrap(),
                &self.mint_url,
            )
            .await,
        );
        let before = self.ledger.lock().unwrap().requests;
        let result = self
            .relay(&["wallet", "--json", "close", "--channel-id", &channel])
            .json()
            .await;
        assert_eq!(result["outcome"], "Closed");
        assert_eq!(
            self.ledger.lock().unwrap().requests,
            before,
            "restart recovery must restore, not resubmit"
        );
        self.settle(&channel, false).await;
    }

    async fn release_gate(&self) {
        self.release.add_permits(1);
        tokio::time::timeout(DEADLINE, self.gate_finished.notified())
            .await
            .expect("HTTP gate did not finish or cancel");
        // Cancellation may precede permit consumption. Never leak that permit
        // into the next crash boundary, which must block independently.
        self.release.forget_permits(usize::MAX);
    }
    fn relay(&self, args: &[&str]) -> Process {
        let mut selected = vec![args[0], "--relay", "funds"];
        selected.extend_from_slice(&args[1..]);
        Process::spawn(&self.relay_bin, &selected, &self.config)
    }
    fn db(&self, name: &str) -> Connection {
        Connection::open_with_flags(
            self.dir.as_ref().unwrap().path().join(name),
            OpenFlags::SQLITE_OPEN_READ_ONLY,
        )
        .unwrap()
    }

    async fn roundtrip(&self) {
        tokio::time::timeout(DEADLINE, async {
            loop {
                let attempt = tokio::time::timeout(Duration::from_secs(2), async {
                    let mut stream = TcpStream::connect(self.socks).await?;
                    stream.write_all(&[5, 1, 0]).await?;
                    let mut greeting = [0; 2];
                    stream.read_exact(&mut greeting).await?;
                    if greeting != [5, 0] {
                        return Err(std::io::Error::other("SOCKS greeting"));
                    }
                    let mut connect = vec![5, 1, 0, 1, 127, 0, 0, 1];
                    connect.extend_from_slice(&self.target.port().to_be_bytes());
                    stream.write_all(&connect).await?;
                    let mut reply = [0; 10];
                    stream.read_exact(&mut reply).await?;
                    if reply[1] != 0 {
                        return Err(std::io::Error::other("SOCKS CONNECT"));
                    }
                    let payload = [42; 4096];
                    stream.write_all(&payload).await?;
                    let mut received = [0; 4096];
                    stream.read_exact(&mut received).await?;
                    assert!(payload == received, "tunnel data mismatch");
                    Ok::<_, std::io::Error>(())
                })
                .await;
                if matches!(attempt, Ok(Ok(()))) {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(100)).await;
            }
        })
        .await
        .expect("production QUIC/SOCKS route did not become ready");
    }

    pub async fn cycle(&mut self, crash_opening: bool) {
        self.cycle += 1;
        eprintln!(
            "funds event cycle={} opening={}",
            self.cycle,
            if crash_opening {
                "commit-kill"
            } else {
                "clean"
            }
        );
        let relay = self.relay(&["run"]);
        self.ledger.lock().unwrap().hold_success = crash_opening;
        let mut client = self.client(&["run"]);
        if crash_opening {
            tokio::time::timeout(DEADLINE, self.committed.notified())
                .await
                .expect("opening commit gate not reached");
            drop(client); // SIGKILL and wait, before any recovery opens the same files.
            self.release_gate().await;
            let submitted = self.ledger.lock().unwrap().requests;
            self.client(&["wallet", "recover-openings"]).success().await;
            self.client(&["wallet", "recover-openings"]).success().await;
            assert_eq!(
                self.ledger.lock().unwrap().requests,
                submitted,
                "restore-only recovery submitted a swap"
            );
            client = self.client(&["run"]);
        }
        self.roundtrip().await;
        drop(client);
        drop(relay);
        let channels = self
            .db("channel.db")
            .prepare("SELECT channel_id FROM monad_client_channels WHERE state != 'closed'")
            .unwrap()
            .query_map([], |r| r.get::<_, String>(0))
            .unwrap()
            .collect::<Result<Vec<_>, _>>()
            .unwrap();
        assert_eq!(
            channels.len(),
            1,
            "exactly one established channel per cycle"
        );
        for channel in channels {
            self.relay(&["wallet", "close", "--channel-id", &channel])
                .success()
                .await;
            self.client(&["wallet", "recover-channel", "--channel-id", &channel])
                .success()
                .await;
            let before = self.ledger.lock().unwrap().requests;
            self.client(&["wallet", "recover-channel", "--channel-id", &channel])
                .success()
                .await;
            assert_eq!(
                self.ledger.lock().unwrap().requests,
                before,
                "repeat recovery submitted a swap"
            );
        }
        self.relay(&[
            "wallet",
            "drain",
            "--mint-url",
            &self.mint_url,
            "--unit",
            "sat",
        ])
        .success()
        .await;
        self.audit().await;
    }

    fn active_channel(&self) -> String {
        let channels = self
            .db("channel.db")
            .prepare("SELECT channel_id FROM monad_client_channels WHERE state != 'closed'")
            .unwrap()
            .query_map([], |r| r.get::<_, String>(0))
            .unwrap()
            .collect::<Result<Vec<_>, _>>()
            .unwrap();
        assert_eq!(channels.len(), 1);
        channels.into_iter().next().unwrap()
    }

    async fn boundary_kill(&self, args: &[&str], boundary: &str) {
        self.binary_boundary_kill(&self.client_bin, args, boundary)
            .await;
    }

    async fn binary_boundary_kill(&self, binary: &Path, args: &[&str], boundary: &str) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap().to_string();
        let child = Process::spawn_with_env(
            binary,
            args,
            &self.config,
            &[
                ("MONAD_FUNDS_BOUNDARY", boundary),
                ("MONAD_FUNDS_IPC", &addr),
            ],
        );
        let mut stream = tokio::time::timeout(DEADLINE, async {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut name = vec![0; boundary.len() + 1];
            stream.read_exact(&mut name).await.unwrap();
            assert!(
                name == format!("{boundary}\n").as_bytes(),
                "wrong durable boundary"
            );
            stream
        })
        .await
        .expect("durable boundary not reached");
        drop(child);
        // The child was reaped before the blocked boundary could continue.
        let _ = stream.write_all(&[1]).await;
    }

    async fn offline_recover(&self, args: &[&str]) {
        let before = {
            let mut ledger = self.ledger.lock().unwrap();
            ledger.offline = true;
            ledger.http_requests
        };
        self.client(args).success().await;
        self.client(args).success().await;
        let mut ledger = self.ledger.lock().unwrap();
        assert_eq!(
            ledger.http_requests, before,
            "local finalization attempted mint IO"
        );
        ledger.offline = false;
    }

    async fn settle(&self, channel: &str, refund: bool) {
        if !refund {
            self.relay(&["wallet", "close", "--channel-id", channel])
                .success()
                .await;
        }
        self.client(&["wallet", "recover-channel", "--channel-id", channel])
            .success()
            .await;
        let before = self.ledger.lock().unwrap().requests;
        self.client(&["wallet", "recover-channel", "--channel-id", channel])
            .success()
            .await;
        assert_eq!(before, self.ledger.lock().unwrap().requests);
        if !refund {
            self.relay(&[
                "wallet",
                "drain",
                "--mint-url",
                &self.mint_url,
                "--unit",
                "sat",
            ])
            .success()
            .await;
        }
        if refund {
            let args = ["wallet", "--json", "close", "--channel-id", channel];
            let result = self.relay(&args).json().await;
            assert_eq!(result["outcome"], "SenderRefundedAfterExpiry");
            let before = {
                let mut ledger = self.ledger.lock().unwrap();
                ledger.offline = true;
                ledger.http_requests
            };
            for _ in 0..2 {
                assert_eq!(
                    self.relay(&args).json().await["outcome"],
                    "SenderRefundedAfterExpiry"
                );
            }
            let batch = self
                .relay(&["wallet", "--json", "close-expiring-channels"])
                .json()
                .await;
            assert_eq!(batch["candidate_count"], 0);
            assert!(!self
                .relay(&[
                    "wallet",
                    "drain",
                    "--mint-url",
                    &self.mint_url,
                    "--unit",
                    "sat"
                ])
                .status()
                .await
                .success());
            let mut ledger = self.ledger.lock().unwrap();
            assert_eq!(
                ledger.http_requests, before,
                "terminal operations performed mint IO"
            );
            ledger.offline = false;
        }
        self.audit().await;
    }

    pub async fn opening_boundary(&mut self, boundary: &str) {
        self.cycle += 1;
        eprintln!("funds boundary={boundary}");
        let relay = self.relay(&["run"]);
        self.boundary_kill(&["run"], boundary).await;
        self.offline_recover(&["wallet", "recover-openings"]).await;
        let client = self.client(&["run"]);
        self.roundtrip().await;
        drop(client);
        drop(relay);
        self.settle(&self.active_channel(), false).await;
    }

    pub async fn relay_close_case(
        &mut self,
        boundary: Option<&str>,
        rotate: bool,
        lost_response: bool,
    ) {
        self.cycle += 1;
        eprintln!(
            "funds relay close boundary={boundary:?} rotate={rotate} lost_response={lost_response}"
        );
        let relay = self.relay(&["run"]);
        let client = self.client(&["run"]);
        self.roundtrip().await;
        drop(client);
        drop(relay);
        let channel = self.active_channel();
        let args = ["wallet", "close", "--channel-id", &channel];
        if let Some(boundary) = boundary {
            let selected = [
                "wallet",
                "--relay",
                "funds",
                "close",
                "--channel-id",
                &channel,
            ];
            if rotate {
                self.ledger.lock().unwrap().hold_request = true;
                let rotation = async {
                    tokio::time::timeout(DEADLINE, self.committed.notified())
                        .await
                        .expect("close rejection request gate");
                    self.rotate(250).await;
                    self.release_gate().await;
                };
                tokio::join!(
                    self.binary_boundary_kill(&self.relay_bin, &selected, boundary),
                    rotation
                );
            } else {
                self.binary_boundary_kill(&self.relay_bin, &selected, boundary)
                    .await;
            }
            if matches!(boundary, "close-finalizing" | "close-completed") {
                let before = {
                    let mut ledger = self.ledger.lock().unwrap();
                    ledger.offline = true;
                    ledger.http_requests
                };
                self.relay(&args).success().await;
                self.relay(&args).success().await;
                let mut ledger = self.ledger.lock().unwrap();
                assert_eq!(
                    ledger.http_requests, before,
                    "offline close finalization contacted mint"
                );
                ledger.offline = false;
            }
        } else {
            self.ledger.lock().unwrap().hold_request = rotate;
            self.ledger.lock().unwrap().hold_success = lost_response;
            let child = self.relay(&args);
            if rotate {
                tokio::time::timeout(DEADLINE, self.committed.notified())
                    .await
                    .expect("close request gate");
                self.rotate(250).await;
                self.release_gate().await;
            }
            if lost_response {
                tokio::time::timeout(DEADLINE, self.committed.notified())
                    .await
                    .expect("close response gate");
                drop(child);
                self.release_gate().await;
                self.rotate(300).await;
            } else {
                child.success().await;
            }
        }
        self.settle(&channel, false).await;
    }

    pub async fn refund_case(&mut self, boundary: Option<&str>, rotate: bool, lost_response: bool) {
        self.cycle += 1;
        eprintln!(
            "funds refund boundary={boundary:?} rotate={rotate} lost_response={lost_response}"
        );
        let channel = self.open_expired().await;
        let args = ["wallet", "recover-channel", "--channel-id", &channel];
        if let Some(boundary) = boundary {
            self.boundary_kill(&args, boundary).await;
            self.offline_recover(&args).await;
        } else {
            let before = self.ledger.lock().unwrap().requests;
            let rejections = self.ledger.lock().unwrap().inactive_rejections;
            self.ledger.lock().unwrap().hold_request = rotate;
            self.ledger.lock().unwrap().hold_success = lost_response;
            let child = self.client(&args);
            if rotate {
                tokio::time::timeout(DEADLINE, self.committed.notified())
                    .await
                    .expect("refund request gate");
                self.rotate(250).await;
                self.release_gate().await;
            }
            if lost_response {
                tokio::time::timeout(DEADLINE, self.committed.notified())
                    .await
                    .expect("refund commit gate");
                drop(child);
                self.release_gate().await;
                if self.external_url.is_some() {
                    self.rotate(300).await;
                }
                let submitted = self.ledger.lock().unwrap().requests;
                self.client(&args).success().await;
                assert_eq!(
                    submitted,
                    self.ledger.lock().unwrap().requests,
                    "restore recovery resubmitted refund"
                );
            } else {
                child.success().await;
            }
            if rotate {
                let ledger = self.ledger.lock().unwrap();
                assert_eq!(
                    ledger.inactive_rejections,
                    rejections + 1,
                    "expected one direct 12002"
                );
                assert_eq!(
                    ledger.requests,
                    before + 2,
                    "expected exactly one successor"
                );
            }
        }
        self.settle(&channel, true).await;
    }

    pub async fn relay_drain_case(
        &mut self,
        boundary: Option<&str>,
        rotate: bool,
        lost_response: bool,
    ) {
        self.cycle += 1;
        eprintln!(
            "funds relay drain boundary={boundary:?} rotate={rotate} lost_response={lost_response}"
        );
        let relay = self.relay(&["run"]);
        let client = self.client(&["run"]);
        self.roundtrip().await;
        drop(client);
        drop(relay);
        let channel = self.active_channel();
        self.relay(&["wallet", "close", "--channel-id", &channel])
            .success()
            .await;
        self.client(&["wallet", "recover-channel", "--channel-id", &channel])
            .success()
            .await;
        let args = [
            "wallet",
            "drain",
            "--mint-url",
            &self.mint_url,
            "--unit",
            "sat",
        ];
        if let Some(boundary) = boundary {
            let selected = [
                "wallet",
                "--relay",
                "funds",
                "drain",
                "--mint-url",
                &self.mint_url,
                "--unit",
                "sat",
            ];
            if rotate {
                self.ledger.lock().unwrap().hold_request = true;
                let rotation = async {
                    tokio::time::timeout(DEADLINE, self.committed.notified())
                        .await
                        .expect("drain rejection request gate");
                    self.rotate(200).await;
                    self.release_gate().await;
                };
                tokio::join!(
                    self.binary_boundary_kill(&self.relay_bin, &selected, boundary),
                    rotation
                );
            } else {
                self.binary_boundary_kill(&self.relay_bin, &selected, boundary)
                    .await;
            }
        } else {
            self.ledger.lock().unwrap().hold_request = rotate;
            self.ledger.lock().unwrap().hold_success = lost_response;
            let child = self.relay(&args);
            if rotate {
                tokio::time::timeout(DEADLINE, self.committed.notified())
                    .await
                    .expect("drain request gate");
                self.rotate(200).await;
                self.release_gate().await;
            }
            if lost_response {
                tokio::time::timeout(DEADLINE, self.committed.notified())
                    .await
                    .expect("drain response gate");
                drop(child);
                self.release_gate().await;
                self.rotate(350).await;
            } else {
                child.success().await;
            }
        }
        let id: String = self
            .db("relay.db")
            .query_row(
                "SELECT drain_id FROM monad_relay_drained_channels WHERE channel_id=?1",
                [&channel],
                |row| row.get(0),
            )
            .unwrap();
        let recovery = ["wallet", "recover-drain", "--drain-id", &id];
        let offline = matches!(boundary, Some("drain-finalizing" | "drain-completed"));
        let before = {
            let mut ledger = self.ledger.lock().unwrap();
            ledger.offline = offline;
            ledger.http_requests
        };
        self.relay(&recovery).success().await;
        let first_requests = self.ledger.lock().unwrap().http_requests;
        self.relay(&recovery).success().await;
        {
            let mut ledger = self.ledger.lock().unwrap();
            assert_eq!(
                ledger.http_requests, first_requests,
                "completed drain recovery attempted HTTP"
            );
            if offline {
                assert_eq!(
                    ledger.http_requests, before,
                    "offline drain finalization attempted HTTP"
                );
            }
            ledger.offline = false;
        }
        self.audit().await;
    }

    async fn open_expired(&self) -> String {
        let relay = self.relay(&["run"]);
        let client = Process::spawn_with_env(
            &self.client_bin,
            &["run"],
            &self.config,
            &[("MONAD_FUNDS_LIFETIME", "8")],
        );
        self.roundtrip().await;
        drop(client);
        drop(relay);
        let channel = self.active_channel();
        let expiry: u64 = self
            .db("channel.db")
            .query_row(
                "SELECT expiry_timestamp FROM monad_client_channels WHERE channel_id = ?1",
                [&channel],
                |r| r.get(0),
            )
            .unwrap();
        tokio::time::timeout(Duration::from_secs(12), async {
            while std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs()
                <= expiry
            {
                tokio::time::sleep(Duration::from_millis(100)).await;
            }
        })
        .await
        .expect("signed channel did not expire on wall clock");
        channel
    }

    pub async fn opening_request(&mut self, rotate: bool, kill_before: bool) {
        self.cycle += 1;
        let relay = self.relay(&["run"]);
        let before = self.ledger.lock().unwrap().requests;
        let rejected = self.ledger.lock().unwrap().inactive_rejections;
        self.ledger.lock().unwrap().hold_request = true;
        self.ledger.lock().unwrap().hold_success = true;
        let mut client = Some(self.client(&["run"]));
        tokio::time::timeout(DEADLINE, self.committed.notified())
            .await
            .expect("opening request gate");
        if kill_before {
            drop(client.take());
            self.ledger.lock().unwrap().discard_request = true;
            self.release_gate().await;
            self.client(&["wallet", "recover-openings"]).success().await;
            self.client(&["wallet", "recover-openings"]).success().await;
            assert_eq!(
                self.ledger.lock().unwrap().requests,
                before + 1,
                "pending recovery submitted"
            );
            assert!(
                self.ledger.lock().unwrap().swaps.is_empty(),
                "discarded opening executed"
            );
            let reserved: u64 = self
                .db("loose.db")
                .query_row(
                    "SELECT COUNT(*) FROM monad_client_loose_proofs WHERE state = 'reserved'",
                    [],
                    |r| r.get(0),
                )
                .unwrap();
            assert!(reserved > 0, "ambiguous input reservation released");
            drop(relay);
            self.audit_custody(true).await;
            return;
        }
        if rotate {
            assert!(!kill_before, "direct rejection must reach live client");
            self.rotate(350).await;
        }
        self.release_gate().await;
        tokio::time::timeout(DEADLINE, self.committed.notified())
            .await
            .expect("opening commit gate");
        drop(client);
        self.release_gate().await;
        if self.external_url.is_some() {
            self.rotate(400).await;
        }
        let submitted = self.ledger.lock().unwrap().requests;
        self.client(&["wallet", "recover-openings"]).success().await;
        self.client(&["wallet", "recover-openings"]).success().await;
        assert_eq!(submitted, self.ledger.lock().unwrap().requests);
        if rotate {
            assert_eq!(submitted, before + 2);
            assert_eq!(
                self.ledger.lock().unwrap().inactive_rejections,
                rejected + 1
            );
        }
        let client = self.client(&["run"]);
        self.roundtrip().await;
        drop(client);
        drop(relay);
        self.settle(&self.active_channel(), false).await;
    }

    pub async fn race(&mut self, refund_wins: Option<bool>) {
        self.cycle += 1;
        eprintln!("funds race controlled_refund_winner={refund_wins:?}");
        let channel = self.open_expired().await;
        let before = self.ledger.lock().unwrap().swaps.len();
        let refund_args = ["wallet", "recover-channel", "--channel-id", &channel];
        let close_args = ["wallet", "--json", "close", "--channel-id", &channel];
        let (close, refund) = if let Some(refund_first) = refund_wins {
            self.ledger.lock().unwrap().hold_success = true;
            let first = if refund_first {
                self.client(&refund_args)
            } else {
                self.relay(&close_args)
            };
            tokio::time::timeout(DEADLINE, self.committed.notified())
                .await
                .expect("winner commit gate");
            let second = if refund_first {
                self.relay(&close_args)
            } else {
                self.client(&refund_args)
            };
            self.release_gate().await;
            if refund_first {
                (second, first)
            } else {
                (first, second)
            }
        } else {
            self.ledger.lock().unwrap().race_barrier = Some(Arc::new(tokio::sync::Barrier::new(2)));
            (self.relay(&close_args), self.client(&refund_args))
        };
        let (close_status, close_result) = close.json_status().await;
        refund.success().await;
        if refund_wins.is_none() {
            let mut ledger = self.ledger.lock().unwrap();
            ledger.race_barrier = None;
            assert_eq!(
                ledger.raced_requests, 2,
                "race did not overlap at mint execution"
            );
        }
        // Pending is valid during concurrent mint execution. Only after both
        // processes finish can a fresh bounded recovery classify the winner.
        let close_result = if close_status.success() {
            close_result.unwrap()
        } else {
            self.relay(&close_args).json().await
        };
        let sender_refunded = match close_result["outcome"].as_str().unwrap() {
            "Closed" => false,
            "SenderRefundedAfterExpiry" => true,
            _ => panic!("race did not resolve a typed terminal outcome"),
        };
        assert_eq!(
            self.ledger.lock().unwrap().swaps.len(),
            before + 1,
            "race must commit one spend"
        );
        if let Some(refund_first) = refund_wins {
            assert_eq!(sender_refunded, refund_first, "wrong controlled winner");
        }
        self.settle(&channel, sender_refunded).await;
    }

    pub async fn close_winner_response_loss(&mut self) {
        self.cycle += 1;
        let channel = self.open_expired().await;
        let before = self.ledger.lock().unwrap().swaps.len();
        self.ledger.lock().unwrap().hold_success = true;
        let close = self.relay(&["wallet", "close", "--channel-id", &channel]);
        tokio::time::timeout(DEADLINE, self.committed.notified())
            .await
            .expect("close winner response gate");
        let refund = self.client(&["wallet", "recover-channel", "--channel-id", &channel]);
        drop(close);
        self.release_gate().await;
        refund.success().await;
        self.relay(&["wallet", "close", "--channel-id", &channel])
            .success()
            .await;
        assert_eq!(
            self.ledger.lock().unwrap().swaps.len(),
            before + 1,
            "lost close response caused another funding spend"
        );
        self.settle(&channel, false).await;
    }

    pub async fn rotate(&self, ppk: u64) {
        if let Some(url) = &self.external_url {
            // External adapters deliberately keep fees at zero; the CDK process
            // baseline separately covers fee changes and purse conservation.
            reqwest::Client::builder()
                .timeout(DEADLINE)
                .no_proxy()
                .build()
                .unwrap()
                .post(format!("{url}/_test/rotate"))
                .json(&serde_json::json!({}))
                .send()
                .await
                .unwrap()
                .error_for_status()
                .unwrap();
        } else {
            rotate_sat_keyset(&self.memory_mint(), ppk).await.unwrap();
        }
    }

    pub async fn refund_request_crash(&mut self) {
        self.cycle += 1;
        let channel = self.open_expired().await;
        let args = ["wallet", "recover-channel", "--channel-id", &channel];
        let before = self.ledger.lock().unwrap().swaps.len();
        let attempt_index = self.ledger.lock().unwrap().requests;
        self.ledger.lock().unwrap().hold_request = true;
        let child = self.client(&args);
        tokio::time::timeout(DEADLINE, self.committed.notified())
            .await
            .expect("refund request gate");
        drop(child);
        self.ledger.lock().unwrap().discard_request = true;
        self.release_gate().await;
        self.client(&args).success().await;
        assert_eq!(self.ledger.lock().unwrap().swaps.len(), before + 1);
        {
            let ledger = self.ledger.lock().unwrap();
            assert_eq!(ledger.attempts.len(), attempt_index + 2);
            let original = &ledger.attempts[attempt_index];
            let resumed = &ledger.attempts[attempt_index + 1];
            assert!(
                original.outputs() == resumed.outputs(),
                "refund replay changed prepared outputs"
            );
            let inputs = |swap: &SwapRequest| {
                swap.inputs()
                    .iter()
                    .map(|p| (p.y().unwrap(), p.keyset_id, p.amount))
                    .collect::<Vec<_>>()
            };
            assert!(
                inputs(original) == inputs(resumed),
                "refund replay changed inputs"
            );
        }
        self.settle(&channel, true).await;
    }

    pub async fn refund_rotation_before_prepare(&mut self) {
        self.cycle += 1;
        let channel = self.open_expired().await;
        let output_keyset = rotate_sat_keyset(&self.memory_mint(), 450).await.unwrap();
        self.settle(&channel, true).await;
        let ledger = self.ledger.lock().unwrap();
        assert!(
            ledger.swaps.values().any(|(swap, _)| {
                swap.outputs().iter().all(|p| p.keyset_id == output_keyset)
                    && swap.inputs().iter().all(|p| p.keyset_id != output_keyset)
            }),
            "refund must use new output keys with old input fee keys"
        );
    }

    pub async fn stress(&mut self, seed: u64, cycles: usize) {
        assert!((1..=1000).contains(&cycles));
        let mut random = seed;
        for step in 0..cycles {
            // Reserve a conservative capacity/fee margin; never top up the purse.
            let balance: u64 = self.db("loose.db").query_row("SELECT COALESCE(SUM(amount_raw), 0) FROM monad_client_loose_proofs WHERE state = 'available'", [], |r| r.get(0)).unwrap();
            if balance < 2048 {
                eprintln!("funds stress seed={seed} stopped=capacity_fee_margin step={step} balance={balance}");
                break;
            }
            random = random
                .wrapping_mul(6364136223846793005)
                .wrapping_add(1442695040888963407);
            let choice = (random >> 32) % 10;
            eprintln!("funds stress seed={seed} step={step} choice={choice}");
            match choice {
                0 => self.cycle(false).await,
                1 => self.cycle(true).await,
                2 => self.opening_boundary("opening-change").await,
                3 => self.refund_case(None, false, true).await,
                4 => self.opening_request(true, false).await,
                5 => {
                    self.rotate(100 + (random % 400)).await;
                    self.cycle(false).await;
                }
                6 => {
                    self.relay_close_case(Some("close-finalizing"), false, false)
                        .await
                }
                7 => self.relay_close_case(None, true, true).await,
                8 => {
                    self.relay_drain_case(Some("drain-prepared"), false, false)
                        .await
                }
                _ => self.relay_drain_case(None, true, true).await,
            }
        }
        self.audit().await;
    }

    async fn audit(&self) {
        self.audit_custody(false).await;
    }

    async fn audit_custody(&self, include_reserved: bool) {
        let wallet = LooseProofWallet::open(
            self.dir.as_ref().unwrap().path().join("loose.db"),
            CONFIGURED_CLIENT_WALLET_NAME,
        )
        .unwrap();
        let mut proofs = wallet
            .list_available_proofs(&self.mint_url, "sat", &[])
            .unwrap()
            .into_iter()
            .map(|p| serde_json::from_str::<Proof>(&p.proof_json).unwrap())
            .collect::<Vec<_>>();
        drop(wallet);
        if include_reserved {
            let conn = self.db("loose.db");
            let mut stmt = conn
                .prepare(
                    "SELECT proof_json FROM monad_client_loose_proofs WHERE state = 'reserved'",
                )
                .unwrap();
            for row in stmt.query_map([], |r| r.get::<_, String>(0)).unwrap() {
                proofs.push(serde_json::from_str(&row.unwrap()).unwrap());
            }
        }
        let client_value: u64 = proofs.iter().map(|p| u64::from(p.amount)).sum();
        let conn = self.db("relay.db");
        let mut stmt = conn
            .prepare("SELECT output_proofs_json FROM monad_relay_drains WHERE state = 'Completed'")
            .unwrap();
        for row in stmt.query_map([], |r| r.get::<_, String>(0)).unwrap() {
            proofs.extend(serde_json::from_str::<Vec<Proof>>(&row.unwrap()).unwrap());
        }
        let ys = proofs.iter().map(|p| p.y().unwrap()).collect::<Vec<_>>();
        assert_eq!(
            ys.iter().collect::<BTreeSet<_>>().len(),
            proofs.len(),
            "duplicate final custody"
        );
        let states: cashu::nuts::CheckStateResponse = self
            .mint_post("/v1/checkstate", &CheckStateRequest { ys })
            .await;
        assert_eq!(states.states.len(), proofs.len());
        assert!(
            states.states.iter().all(|s| s.state == State::Unspent),
            "final custody includes spent/unknown proofs"
        );
        for proof in &proofs {
            let keys: cashu::nuts::KeysResponse = reqwest::Client::new()
                .get(format!("{}/v1/keys/{}", self.mint_url, proof.keyset_id))
                .send()
                .await
                .unwrap()
                .error_for_status()
                .unwrap()
                .json()
                .await
                .unwrap();
            proof
                .verify_dleq(*keys.keysets[0].keys.get(&proof.amount).unwrap())
                .expect("final proof DLEQ invalid");
        }
        let metadata: Value = reqwest::Client::new()
            .get(format!("{}/v1/keysets", self.mint_url))
            .send()
            .await
            .unwrap()
            .json()
            .await
            .unwrap();
        let fees = metadata["keysets"]
            .as_array()
            .unwrap()
            .iter()
            .map(|k| {
                (
                    k["id"].as_str().unwrap().to_string(),
                    k["input_fee_ppk"].as_u64().unwrap_or(0),
                )
            })
            .collect::<BTreeMap<_, _>>();
        let mut total_fee = 0;
        let swaps = self.ledger.lock().unwrap().swaps.clone();
        for (swap, response) in swaps.values() {
            let restored: cashu::nuts::RestoreResponse = self
                .mint_post(
                    "/v1/restore",
                    &RestoreRequest {
                        outputs: swap.outputs().to_vec(),
                    },
                )
                .await;
            assert!(
                restored.signatures == response.signatures,
                "accepted output restore mismatch"
            );
            let states: cashu::nuts::CheckStateResponse = self
                .mint_post(
                    "/v1/checkstate",
                    &CheckStateRequest {
                        ys: swap.inputs().iter().map(|p| p.y().unwrap()).collect(),
                    },
                )
                .await;
            assert_eq!(states.states.len(), swap.inputs().len());
            assert!(
                states.states.iter().all(|s| s.state == State::Spent),
                "accepted inputs not spent"
            );
            let fee = swap
                .inputs()
                .iter()
                .map(|p| fees[&p.keyset_id.to_string()])
                .sum::<u64>()
                .div_ceil(1000);
            let input: u64 = swap.inputs().iter().map(|p| u64::from(p.amount)).sum();
            let output: u64 = response
                .signatures
                .iter()
                .map(|p| u64::from(p.amount))
                .sum();
            assert_eq!(
                input,
                output + fee,
                "accepted transaction fee oracle mismatch"
            );
            total_fee += fee;
        }
        let final_value: u64 = proofs.iter().map(|p| u64::from(p.amount)).sum();
        assert_eq!(
            INITIAL,
            final_value + total_fee,
            "strict final funds conservation"
        );
        eprintln!("funds ledger cycle={} initial={INITIAL} client={client_value} relay={} fees={total_fee} accepted_unique={}", self.cycle, final_value-client_value, swaps.len());
    }

    pub async fn finish(mut self) {
        self.tasks.shutdown().await;
        drop(self.mint_process.take());
        self.dir.take().unwrap().close().unwrap();
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        drop(self.mint_process.take());
        if let Some(dir) = self.dir.take() {
            if self.mint_port.is_some() {
                self.tasks.abort_all();
                drop(dir);
                return;
            }
            eprintln!(
                "SECRET wallet artifacts preserved after failure: {} (do not publish)",
                dir.keep().display()
            );
        }
    }
}
