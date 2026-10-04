//! Managed loopback traffic servers for end-to-end MONAD tests.
//!
//! `GET /v1/stream/{upload}/{download}` upgrades HTTP/1.1 with the exact token
//! `monad-ratio-stream/1`. Ratio components are integers in `1..=100`. For N
//! uploaded bytes the stream emits exactly `floor(N * download / upload)` bytes.
//! A 1:1 stream echoes input exactly; other ratios use deterministic generated
//! bytes. Ratios are not reduced because their bounded path representation is
//! itself part of the protocol contract.

use anyhow::{bail, Context, Result};
use axum::{
    body::Body,
    extract::{Path, Request, State},
    http::{header, Method, Response, StatusCode, Version},
    routing::any,
    Router,
};
use bytes::Bytes;
use hyper::upgrade::OnUpgrade;
use hyper_util::rt::TokioIo;
use monad_common::config::{MonadConfig, TrafficServerConfig};
use monad_management::{events::EventLog, Backend, Command};
use serde_json::{json, Value};
use std::{
    collections::BTreeMap,
    sync::{
        atomic::{AtomicU64, AtomicUsize, Ordering},
        Arc,
    },
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpListener,
    sync::{mpsc, oneshot, watch},
    task::JoinSet,
};

pub const UPGRADE_TOKEN: &str = "monad-ratio-stream/1";
const MAX_UPGRADES: usize = 128;
const READ_SIZE: usize = 8 * 1024;
const OUTPUT_CHUNK_SIZE: usize = 16 * 1024;
const OUTPUT_QUEUE_CHUNKS: usize = 8;

pub struct TrafficServer {
    name: String,
    listen: String,
    base_url: String,
    active_connections: AtomicUsize,
    total_connections: AtomicU64,
    uploaded_bytes: AtomicU64,
    downloaded_bytes: AtomicU64,
    events: EventLog,
}

impl TrafficServer {
    fn new(config: TrafficServerConfig, listen: String) -> Arc<Self> {
        Arc::new(Self {
            name: config.name,
            base_url: format!("http://{listen}"),
            listen,
            active_connections: AtomicUsize::new(0),
            total_connections: AtomicU64::new(0),
            uploaded_bytes: AtomicU64::new(0),
            downloaded_bytes: AtomicU64::new(0),
            events: EventLog::default(),
        })
    }

    fn snapshot(&self) -> Value {
        json!({
            "name": self.name,
            "listen": self.listen,
            "base_url": self.base_url,
            "active_connections": self.active_connections.load(Ordering::Relaxed),
            "total_connections": self.total_connections.load(Ordering::Relaxed),
            "uploaded_bytes": self.uploaded_bytes.load(Ordering::Relaxed),
            "downloaded_bytes": self.downloaded_bytes.load(Ordering::Relaxed),
            "events": self.events.snapshot(),
        })
    }
}

struct UpgradeJob {
    server: Arc<TrafficServer>,
    upload: u64,
    download: u64,
    upgrade: OnUpgrade,
}

#[derive(Clone)]
struct HttpState {
    server: Arc<TrafficServer>,
    upgrades: mpsc::Sender<UpgradeJob>,
}

fn response(status: StatusCode, message: &'static str) -> Response<Body> {
    Response::builder()
        .status(status)
        .header(header::CONTENT_TYPE, "text/plain; charset=utf-8")
        .body(Body::from(message))
        .expect("static response")
}

fn connection_has_upgrade(request: &Request) -> bool {
    request
        .headers()
        .get_all(header::CONNECTION)
        .iter()
        .any(|value| {
            value.to_str().is_ok_and(|value| {
                value
                    .split(',')
                    .any(|token| token.trim().eq_ignore_ascii_case("upgrade"))
            })
        })
}

async fn upgrade(
    State(state): State<HttpState>,
    Path((upload, download)): Path<(u64, u64)>,
    mut request: Request,
) -> Response<Body> {
    if request.method() != Method::GET || request.version() != Version::HTTP_11 {
        return response(StatusCode::BAD_REQUEST, "GET over HTTP/1.1 required");
    }
    if !(1..=100).contains(&upload) || !(1..=100).contains(&download) {
        return response(
            StatusCode::BAD_REQUEST,
            "ratio components must be in 1..=100",
        );
    }
    let mut upgrade_headers = request.headers().get_all(header::UPGRADE).iter();
    let exact_upgrade = upgrade_headers
        .next()
        .is_some_and(|value| value.as_bytes() == UPGRADE_TOKEN.as_bytes())
        && upgrade_headers.next().is_none();
    if !connection_has_upgrade(&request) || !exact_upgrade {
        return response(StatusCode::BAD_REQUEST, "invalid upgrade headers");
    }
    let has_body = request.headers().contains_key(header::TRANSFER_ENCODING)
        || request
            .headers()
            .get_all(header::CONTENT_LENGTH)
            .iter()
            .any(|value| value.as_bytes() != b"0");
    if has_body {
        return response(StatusCode::BAD_REQUEST, "request body is not allowed");
    }
    let job = UpgradeJob {
        server: state.server,
        upload,
        download,
        upgrade: hyper::upgrade::on(&mut request),
    };
    if state.upgrades.try_send(job).is_err() {
        return response(StatusCode::SERVICE_UNAVAILABLE, "upgrade capacity reached");
    }
    Response::builder()
        .status(StatusCode::SWITCHING_PROTOCOLS)
        .header(header::CONNECTION, "Upgrade")
        .header(header::UPGRADE, UPGRADE_TOKEN)
        .body(Body::empty())
        .expect("static upgrade response")
}

async fn serve_upgrade(job: UpgradeJob) -> Result<()> {
    let upgraded = job.upgrade.await.context("HTTP upgrade failed")?;
    let connection_number = job.server.total_connections.fetch_add(1, Ordering::Relaxed) + 1;
    job.server
        .active_connections
        .fetch_add(1, Ordering::Relaxed);
    job.server.events.record(
        "connection_opened",
        json!({"connection": connection_number, "upload": job.upload, "download": job.download}),
    );
    struct Active(Arc<TrafficServer>, u64);
    impl Drop for Active {
        fn drop(&mut self) {
            self.0.active_connections.fetch_sub(1, Ordering::Relaxed);
            self.0
                .events
                .record("connection_closed", json!({"connection": self.1}));
        }
    }
    let _active = Active(job.server.clone(), connection_number);
    let stream = TokioIo::new(upgraded);
    let (mut reader, mut writer) = tokio::io::split(stream);
    let (output, mut pending) = mpsc::channel::<Bytes>(OUTPUT_QUEUE_CHUNKS);
    let server = job.server.clone();
    let produce = async move {
        let mut input = vec![0u8; READ_SIZE];
        let mut remainder = 0u64;
        let mut pattern = 0u8;
        loop {
            let read = reader.read(&mut input).await?;
            if read == 0 {
                break;
            }
            server
                .uploaded_bytes
                .fetch_add(read as u64, Ordering::Relaxed);
            let numerator = remainder + read as u64 * job.download;
            let count = numerator / job.upload;
            remainder = numerator % job.upload;
            if job.upload == job.download {
                output
                    .send(Bytes::copy_from_slice(&input[..read]))
                    .await
                    .map_err(|_| anyhow::anyhow!("output writer stopped"))?;
            } else {
                let mut remaining = count as usize;
                while remaining != 0 {
                    let size = remaining.min(OUTPUT_CHUNK_SIZE);
                    let mut bytes = vec![0u8; size];
                    for byte in &mut bytes {
                        *byte = pattern;
                        pattern = pattern.wrapping_add(1);
                    }
                    output
                        .send(Bytes::from(bytes))
                        .await
                        .map_err(|_| anyhow::anyhow!("output writer stopped"))?;
                    remaining -= size;
                }
            }
        }
        Result::<()>::Ok(())
    };
    let server = job.server.clone();
    let write = async move {
        while let Some(bytes) = pending.recv().await {
            writer.write_all(&bytes).await?;
            server
                .downloaded_bytes
                .fetch_add(bytes.len() as u64, Ordering::Relaxed);
        }
        writer.shutdown().await?;
        Result::<()>::Ok(())
    };
    tokio::try_join!(produce, write)?;
    Ok(())
}

pub struct TrafficBackend {
    servers: BTreeMap<String, Arc<TrafficServer>>,
}

#[async_trait::async_trait]
impl Backend for TrafficBackend {
    async fn snapshot(&self) -> std::result::Result<Value, String> {
        let instances = self
            .servers
            .iter()
            .map(|(name, server)| (name.clone(), server.snapshot()))
            .collect::<BTreeMap<_, _>>();
        Ok(json!({"kind": "traffic_servers", "instances": instances}))
    }

    async fn execute(&self, _command: &Command) -> std::result::Result<Value, String> {
        Err("traffic servers do not support commands".into())
    }
}

pub async fn run(
    config: MonadConfig,
    selected: Option<&str>,
    shutdown: impl std::future::Future<Output = ()> + Send,
) -> Result<()> {
    config.validate()?;
    let servers = config
        .traffic_servers
        .into_iter()
        .filter(|server| selected.is_none_or(|name| name == server.name))
        .collect::<Vec<_>>();
    if servers.is_empty() {
        bail!("no matching traffic servers configured");
    }
    let socket = config.management.and_then(|m| m.traffic_server_socket);
    let (cancel, cancelled) = oneshot::channel();
    let mut task = tokio::spawn(run_owned(servers, socket, cancelled));
    tokio::select! {
        result = &mut task => result.context("traffic server owner task failed")?,
        () = shutdown => { drop(cancel); task.await.context("traffic server owner task failed")? }
    }
}

async fn run_owned(
    configs: Vec<TrafficServerConfig>,
    socket: Option<String>,
    mut cancelled: oneshot::Receiver<()>,
) -> Result<()> {
    let mut prepared = Vec::new();
    for config in configs {
        let listener = TcpListener::bind(&config.listen)
            .await
            .with_context(|| format!("bind traffic server '{}'", config.name))?;
        let listen = listener.local_addr()?.to_string();
        prepared.push((TrafficServer::new(config, listen), listener));
    }
    let managed = prepared
        .iter()
        .map(|(server, _)| (server.name.clone(), server.clone()))
        .collect::<BTreeMap<_, _>>();
    let (jobs, mut incoming) = mpsc::channel(MAX_UPGRADES);
    let (stop, stopped) = watch::channel(false);
    let mut services = JoinSet::new();
    for (server, listener) in prepared {
        tracing::info!(server = %server.name, address = %server.listen, "traffic server started");
        let router = Router::new()
            .route("/v1/stream/{upload}/{download}", any(upgrade))
            .with_state(HttpState {
                server,
                upgrades: jobs.clone(),
            });
        let stopped = stopped.clone();
        services.spawn(monad_management::serve_owned(
            listener,
            router,
            stopped_signal(stopped),
        ));
    }
    drop(jobs);
    if let Some(socket) = socket {
        let stopped = stopped.clone();
        services.spawn(monad_management::serve_unix(
            socket.into(),
            Arc::new(TrafficBackend { servers: managed }),
            stopped_signal(stopped),
        ));
    }
    let mut upgrades = JoinSet::new();
    let mut result = loop {
        tokio::select! {
            _ = &mut cancelled => break Ok(()),
            service = services.join_next() => break match service {
                Some(Ok(Err(error))) => Err(error.into()),
                Some(Err(error)) => Err(error.into()),
                _ => Err(anyhow::anyhow!("traffic server service stopped unexpectedly")),
            },
            Some(job) = incoming.recv(), if upgrades.len() < MAX_UPGRADES => {
                upgrades.spawn(serve_upgrade(job));
            }
            joined = upgrades.join_next(), if !upgrades.is_empty() => {
                if let Some(Ok(Err(error))) = joined {
                    tracing::debug!(%error, "traffic stream ended with an error");
                }
            }
        }
    };
    stop.send_replace(true);
    upgrades.abort_all();
    while upgrades.join_next().await.is_some() {}
    while let Some(joined) = services.join_next().await {
        if let Ok(Err(error)) = joined {
            if result.is_ok() {
                result = Err(error.into());
            }
        }
    }
    result
}

async fn stopped_signal(mut stopped: watch::Receiver<bool>) {
    while !*stopped.borrow() {
        if stopped.changed().await.is_err() {
            break;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{net::SocketAddr, time::Duration};
    use tokio::{io::AsyncWriteExt, net::TcpStream, sync::oneshot, task::JoinHandle};

    struct Running {
        address: SocketAddr,
        management: reqwest::Client,
        stop: oneshot::Sender<()>,
        task: JoinHandle<Result<()>>,
        _temp: tempfile::TempDir,
    }

    impl Running {
        async fn start() -> Self {
            let reserved = TcpListener::bind("127.0.0.1:0").await.unwrap();
            let address = reserved.local_addr().unwrap();
            drop(reserved);
            let temp = tempfile::tempdir().unwrap();
            let socket = temp.path().join("traffic.sock");
            let config: MonadConfig = serde_json::from_value(json!({
                "traffic_servers": [{"name": "test", "listen": address.to_string()}],
                "management": {
                    "listen": "127.0.0.1:0",
                    "traffic_server_socket": socket,
                }
            }))
            .unwrap();
            let management = monad_management::unix_client(socket).unwrap();
            let (stop, stopped) = oneshot::channel();
            let task = tokio::spawn(run(config, None, async {
                let _ = stopped.await;
            }));
            tokio::time::timeout(Duration::from_secs(5), async {
                loop {
                    if TcpStream::connect(address).await.is_ok() {
                        break;
                    }
                    tokio::time::sleep(Duration::from_millis(10)).await;
                }
            })
            .await
            .unwrap();
            Self {
                address,
                management,
                stop,
                task,
                _temp: temp,
            }
        }

        async fn snapshot(&self) -> Value {
            tokio::time::timeout(Duration::from_secs(5), async {
                loop {
                    if let Ok(response) = self
                        .management
                        .get("http://localhost/v1/snapshot")
                        .send()
                        .await
                    {
                        if let Ok(value) = response.json().await {
                            return value;
                        }
                    }
                    tokio::time::sleep(Duration::from_millis(10)).await;
                }
            })
            .await
            .unwrap()
        }

        async fn stop(self) {
            self.stop.send(()).unwrap();
            tokio::time::timeout(Duration::from_secs(2), self.task)
                .await
                .expect("traffic server shutdown must be bounded")
                .unwrap()
                .unwrap();
        }
    }

    async fn read_headers(stream: &mut TcpStream) -> (String, Vec<u8>) {
        let mut bytes = Vec::new();
        loop {
            let byte = stream.read_u8().await.unwrap();
            bytes.push(byte);
            if bytes.ends_with(b"\r\n\r\n") {
                break;
            }
        }
        (String::from_utf8(bytes).unwrap(), Vec::new())
    }

    async fn open(address: SocketAddr, upload: u64, download: u64) -> TcpStream {
        let mut stream = TcpStream::connect(address).await.unwrap();
        stream
            .write_all(
                format!(
                    "GET /v1/stream/{upload}/{download} HTTP/1.1\r\nHost: localhost\r\nConnection: keep-alive, Upgrade\r\nUpgrade: {UPGRADE_TOKEN}\r\n\r\n"
                )
                .as_bytes(),
            )
            .await
            .unwrap();
        let (headers, _) = read_headers(&mut stream).await;
        assert!(headers.starts_with("HTTP/1.1 101 "), "{headers}");
        stream
    }

    async fn exchange(address: SocketAddr, ratio: (u64, u64), fragments: &[&[u8]]) -> Vec<u8> {
        let mut stream = open(address, ratio.0, ratio.1).await;
        for fragment in fragments {
            stream.write_all(fragment).await.unwrap();
            tokio::task::yield_now().await;
        }
        stream.shutdown().await.unwrap();
        let mut output = Vec::new();
        stream.read_to_end(&mut output).await.unwrap();
        output
    }

    async fn exchange_cumulative(
        address: SocketAddr,
        ratio: (u64, u64),
        fragments: &[&[u8]],
    ) -> Vec<u8> {
        let mut stream = open(address, ratio.0, ratio.1).await;
        let mut uploaded = 0usize;
        let mut output = Vec::new();
        for fragment in fragments {
            stream.write_all(fragment).await.unwrap();
            uploaded += fragment.len();
            let expected = uploaded * ratio.1 as usize / ratio.0 as usize;
            let previous = output.len();
            output.resize(expected, 0);
            stream.read_exact(&mut output[previous..]).await.unwrap();
        }
        stream.shutdown().await.unwrap();
        let mut extra = Vec::new();
        stream.read_to_end(&mut extra).await.unwrap();
        assert!(extra.is_empty());
        output
    }

    async fn rejected(address: SocketAddr, request: &str) {
        let mut stream = TcpStream::connect(address).await.unwrap();
        stream.write_all(request.as_bytes()).await.unwrap();
        let (headers, _) = read_headers(&mut stream).await;
        assert!(
            headers.lines().next().unwrap().contains(" 400 "),
            "{headers}"
        );
    }

    #[tokio::test]
    async fn exact_echo_and_fragmented_ratio_accounting() {
        let running = Running::start().await;
        let echoed = exchange(running.address, (1, 1), &[b"exact ", b"echo", b" bytes"]).await;
        assert_eq!(echoed, b"exact echo bytes");

        let expanded = exchange_cumulative(running.address, (2, 3), &[b"a", b"bc", b"defg"]).await;
        assert_eq!(expanded.len(), 10);
        assert_eq!(expanded, (0u8..10).collect::<Vec<_>>());
        let contracted =
            exchange_cumulative(running.address, (3, 2), &[b"12", b"3", b"45678"]).await;
        assert_eq!(contracted.len(), 5);
        assert_eq!(contracted, (0u8..5).collect::<Vec<_>>());

        let snapshot = running.snapshot().await;
        let instance = &snapshot["data"]["instances"]["test"];
        assert_eq!(instance["active_connections"], 0);
        assert_eq!(instance["total_connections"], 3);
        assert_eq!(instance["uploaded_bytes"], 31);
        assert_eq!(instance["downloaded_bytes"], 31);
        assert_eq!(snapshot["data"]["kind"], "traffic_servers");
        running.stop().await;
    }

    #[tokio::test]
    async fn malformed_upgrades_and_ratios_are_rejected() {
        let running = Running::start().await;
        for request in [
            "POST /v1/stream/1/1 HTTP/1.1\r\nHost: x\r\nConnection: Upgrade\r\nUpgrade: monad-ratio-stream/1\r\n\r\n",
            "GET /v1/stream/1/1 HTTP/1.0\r\nConnection: Upgrade\r\nUpgrade: monad-ratio-stream/1\r\n\r\n",
            "GET /v1/stream/0/1 HTTP/1.1\r\nHost: x\r\nConnection: Upgrade\r\nUpgrade: monad-ratio-stream/1\r\n\r\n",
            "GET /v1/stream/1/101 HTTP/1.1\r\nHost: x\r\nConnection: Upgrade\r\nUpgrade: monad-ratio-stream/1\r\n\r\n",
            "GET /v1/stream/1/1 HTTP/1.1\r\nHost: x\r\nUpgrade: monad-ratio-stream/1\r\n\r\n",
            "GET /v1/stream/1/1 HTTP/1.1\r\nHost: x\r\nConnection: Upgrade\r\nUpgrade: wrong\r\n\r\n",
            "GET /v1/stream/1/1 HTTP/1.1\r\nHost: x\r\nConnection: Upgrade\r\nUpgrade: monad-ratio-stream/1\r\nContent-Length: 1\r\n\r\nx",
        ] {
            rejected(running.address, request).await;
        }
        running.stop().await;
    }

    #[tokio::test]
    async fn shutdown_aborts_and_awaits_an_open_upgrade() {
        let running = Running::start().await;
        let _open = open(running.address, 1, 100).await;
        tokio::time::timeout(Duration::from_secs(2), async {
            loop {
                if running.snapshot().await["data"]["instances"]["test"]["active_connections"] == 1
                {
                    break;
                }
            }
        })
        .await
        .unwrap();
        running.stop().await;
    }
}
