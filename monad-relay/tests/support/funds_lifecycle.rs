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

// Never derive Debug: requests contain bearer secrets and signing witnesses.
#[derive(Default)]
struct Ledger {
    swaps: BTreeMap<Vec<String>, (SwapRequest, SwapResponse)>,
    requests: usize,
    hold_success: bool,
    hold_request: bool,
    offline: bool,
    http_requests: usize,
    rejections: usize,
    inactive_rejections: usize,
}

struct Process(Child);

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
                .stdout(Stdio::null())
                .stderr(
                    std::fs::File::create(config.parent().unwrap().join("last-process.stderr"))
                        .unwrap(),
                )
                .spawn()
                .expect("spawn production CLI"),
        )
    }

    async fn success(mut self) {
        let status = tokio::time::timeout(DEADLINE, async {
            loop {
                if let Some(status) = self.0.try_wait().unwrap() {
                    break status;
                }
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
        })
        .await
        .expect("maintenance CLI deadline");
        assert!(
            status.success(),
            "maintenance CLI failed: {status}; output suppressed to protect secrets"
        );
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
    mint: TestMintHelper,
    mint_url: String,
    socks: std::net::SocketAddr,
    target: std::net::SocketAddr,
    ledger: Arc<Mutex<Ledger>>,
    committed: Arc<Notify>,
    release: Arc<Semaphore>,
    tasks: JoinSet<()>,
    cycle: usize,
}

impl Fixture {
    pub async fn start() -> Self {
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
        let mint = TestMintHelper::new().await.unwrap();
        rotate_sat_keyset(&mint.mint(), 100).await.unwrap();
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let mint_url = format!("http://{}", listener.local_addr().unwrap());
        let ledger = Arc::new(Mutex::new(Ledger::default()));
        let committed = Arc::new(Notify::new());
        let release = Arc::new(Semaphore::new(0));
        let router = build_router(mint.mint())
            .await
            .unwrap()
            .layer(axum::middleware::from_fn({
                let ledger = ledger.clone();
                let committed = committed.clone();
                let release = release.clone();
                move |request: Request, next: Next| {
                    let ledger = ledger.clone();
                    let committed = committed.clone();
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
                        ledger.lock().unwrap().requests += 1;
                        let hold = std::mem::take(&mut ledger.lock().unwrap().hold_request);
                        if hold {
                            committed.notify_one();
                            let permit = tokio::time::timeout(DEADLINE, release.acquire())
                                .await
                                .expect("request gate deadline")
                                .unwrap();
                            permit.forget();
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
        let proofs = tokio::time::timeout(DEADLINE, mint.mint_proofs(INITIAL))
            .await
            .unwrap()
            .unwrap();
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
            mint_url,
            socks,
            target,
            ledger,
            committed,
            release,
            tasks,
            cycle: 0,
        }
    }

    fn client(&self, args: &[&str]) -> Process {
        Process::spawn(&self.client_bin, args, &self.config)
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
            self.release.add_permits(1);
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
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap().to_string();
        let child = Process::spawn_with_env(
            &self.client_bin,
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

    pub async fn refund_case(&mut self, boundary: Option<&str>, rotate: bool, lost_response: bool) {
        self.cycle += 1;
        eprintln!(
            "funds refund boundary={boundary:?} rotate={rotate} lost_response={lost_response}"
        );
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
                rotate_sat_keyset(&self.mint.mint(), 250).await.unwrap();
                self.release.add_permits(1);
            }
            if lost_response {
                tokio::time::timeout(DEADLINE, self.committed.notified())
                    .await
                    .expect("refund commit gate");
                drop(child);
                self.release.add_permits(1);
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

    async fn audit(&self) {
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
        let states = self
            .mint
            .mint()
            .check_state(&CheckStateRequest { ys })
            .await
            .unwrap();
        assert_eq!(states.states.len(), proofs.len());
        assert!(
            states.states.iter().all(|s| s.state == State::Unspent),
            "final custody includes spent/unknown proofs"
        );
        for proof in &proofs {
            let keys = self.mint.mint().keyset_pubkeys(&proof.keyset_id).unwrap();
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
            let restored = self
                .mint
                .mint()
                .restore(RestoreRequest {
                    outputs: swap.outputs().to_vec(),
                })
                .await
                .unwrap();
            assert!(
                restored.signatures == response.signatures,
                "accepted output restore mismatch"
            );
            let states = self
                .mint
                .mint()
                .check_state(&CheckStateRequest {
                    ys: swap.inputs().iter().map(|p| p.y().unwrap()).collect(),
                })
                .await
                .unwrap();
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
        self.dir.take().unwrap().close().unwrap();
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        if let Some(dir) = self.dir.take() {
            eprintln!(
                "SECRET wallet artifacts preserved after failure: {} (do not publish)",
                dir.keep().display()
            );
        }
    }
}
