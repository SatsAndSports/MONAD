//! Runtime-owned speed/latency tests. Commands never own network tasks.
use crate::socks_client;
use serde::{Deserialize, Serialize};
use std::{
    collections::VecDeque,
    net::SocketAddr,
    sync::{Arc, Mutex},
    time::Duration,
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpStream,
    sync::{mpsc, oneshot},
    time::{timeout, Instant},
};

pub const MIN_TOTAL_RATE_BYTES_PER_SECOND: u64 = 1024;
pub const MAX_TOTAL_RATE_BYTES_PER_SECOND: u64 = 1 << 30;
const CHUNK: usize = 16 * 1024;
const SETUP_TIMEOUT: Duration = Duration::from_secs(15);
const IO_TIMEOUT: Duration = Duration::from_secs(30);
const TOKEN: &str = "monad-ratio-stream/1";

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct TrafficRunParams {
    pub server_url: String,
    pub total_rate_bytes_per_second: u64,
    pub upload_ratio: u8,
    pub download_ratio: u8,
}
impl TrafficRunParams {
    pub fn validate(&self) -> Result<(), String> {
        endpoint(&self.server_url)?;
        if !(MIN_TOTAL_RATE_BYTES_PER_SECOND..=MAX_TOTAL_RATE_BYTES_PER_SECOND)
            .contains(&self.total_rate_bytes_per_second)
        {
            return Err("rate must be 1024..=1073741824 bytes/s".into());
        }
        if !(1..=100).contains(&self.upload_ratio)
            || !(1..=100).contains(&self.download_ratio)
            || (self.upload_ratio != 1 && self.download_ratio != 1)
        {
            return Err(
                "upload:download ratio must be 1:100 through 100:1 with one component 1".into(),
            );
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Serialize, Default)]
pub struct LatencySnapshot {
    pub latest_ms: Option<f64>,
    pub median_ms: Option<f64>,
    pub p95_ms: Option<f64>,
    pub samples: usize,
}
#[derive(Debug, Clone, Serialize)]
pub struct TrafficSnapshot {
    pub revision: u64,
    pub run_id: u64,
    pub state: String,
    pub server_url: String,
    pub total_rate_bytes_per_second: u64,
    pub upload_ratio: u8,
    pub download_ratio: u8,
    pub started_at_unix_ms: Option<u64>,
    pub uploaded_bytes: u64,
    pub downloaded_bytes: u64,
    pub upload_rate_bytes_per_second: u64,
    pub download_rate_bytes_per_second: u64,
    pub latency: LatencySnapshot,
    pub failures: u64,
    pub latency_failures: u64,
    pub last_error: Option<String>,
}
impl Default for TrafficSnapshot {
    fn default() -> Self {
        Self {
            revision: 0,
            run_id: 0,
            state: "stopped".into(),
            server_url: String::new(),
            total_rate_bytes_per_second: 1024 * 1024,
            upload_ratio: 1,
            download_ratio: 1,
            started_at_unix_ms: None,
            uploaded_bytes: 0,
            downloaded_bytes: 0,
            upload_rate_bytes_per_second: 0,
            download_rate_bytes_per_second: 0,
            latency: LatencySnapshot::default(),
            failures: 0,
            latency_failures: 0,
            last_error: None,
        }
    }
}
struct Metrics {
    view: TrafficSnapshot,
    connected: [bool; 2],
    latency: VecDeque<f64>,
    // Sampled at 5 Hz, never per packet. Includes the baseline before the window.
    rates: VecDeque<(Instant, u64, u64)>,
}
impl Metrics {
    fn new(view: TrafficSnapshot) -> Self {
        Self {
            view,
            connected: [false; 2],
            latency: VecDeque::new(),
            rates: VecDeque::from([(Instant::now(), 0, 0)]),
        }
    }
    fn connection(&mut self, lane: usize, connected: bool) {
        self.connected[lane] = connected;
        self.view.state = if self.connected.iter().all(|v| *v) {
            "running"
        } else {
            "reconnecting"
        }
        .into();
        self.view.revision += 1;
    }
    fn failure(&mut self, lane: usize, error: &str) {
        self.connection(lane, false);
        self.view.failures += 1;
        self.view.latency_failures += u64::from(lane == 1);
        self.view.last_error = Some(error.chars().take(256).collect());
    }
    fn sample(&mut self, now: Instant) {
        self.rates
            .push_back((now, self.view.uploaded_bytes, self.view.downloaded_bytes));
        while self.rates.len() > 26 {
            self.rates.pop_front();
        }
        let first = self.rates.front().unwrap();
        let seconds = now.duration_since(first.0).as_secs_f64();
        if seconds > 0.0 {
            self.view.upload_rate_bytes_per_second =
                ((self.view.uploaded_bytes - first.1) as f64 / seconds) as u64;
            self.view.download_rate_bytes_per_second =
                ((self.view.downloaded_bytes - first.2) as f64 / seconds) as u64;
        }
        self.view.revision += 1;
    }
    fn probe(&mut self, ms: f64) {
        self.view.revision += 1;
        self.latency.push_back(ms);
        if self.latency.len() > 300 {
            self.latency.pop_front();
        }
        let mut sorted: Vec<_> = self.latency.iter().copied().collect();
        sorted.sort_by(f64::total_cmp);
        let n = sorted.len();
        self.view.latency = LatencySnapshot {
            latest_ms: Some(ms),
            median_ms: Some((sorted[(n - 1) / 2] + sorted[n / 2]) / 2.0),
            p95_ms: Some(sorted[(n * 95).div_ceil(100) - 1]),
            samples: n,
        };
    }
}
type Run = Arc<Mutex<Metrics>>;
enum Command {
    Start(TrafficRunParams, u64),
    Stop(u64),
}
struct Request {
    command: Command,
    reply: oneshot::Sender<Result<(), String>>,
}

/// Cloneable command handle. `serve` MUST be owned by the configured runtime.
#[derive(Clone)]
pub struct TrafficController {
    tx: mpsc::Sender<Request>,
    rx: Arc<Mutex<Option<mpsc::Receiver<Request>>>>,
    current: Arc<Mutex<Run>>,
    socks: SocketAddr,
}
impl TrafficController {
    pub fn new(socks: SocketAddr) -> Self {
        let (tx, rx) = mpsc::channel(16);
        Self {
            tx,
            rx: Arc::new(Mutex::new(Some(rx))),
            current: Arc::new(Mutex::new(Arc::new(Mutex::new(Metrics::new(
                TrafficSnapshot::default(),
            ))))),
            socks,
        }
    }
    pub fn snapshot(&self) -> TrafficSnapshot {
        self.current.lock().unwrap().lock().unwrap().view.clone()
    }
    async fn request(&self, command: Command) -> Result<(), String> {
        let (reply, result) = oneshot::channel();
        self.tx
            .try_send(Request { command, reply })
            .map_err(|_| "traffic controller unavailable or busy".to_string())?;
        result
            .await
            .map_err(|_| "traffic controller stopped".to_string())?
    }
    pub async fn start(
        &self,
        params: TrafficRunParams,
        expected_run_id: u64,
    ) -> Result<(), String> {
        params.validate()?;
        self.request(Command::Start(params, expected_run_id)).await
    }
    pub async fn stop(&self, expected_run_id: u64) -> Result<(), String> {
        self.request(Command::Stop(expected_run_id)).await
    }
    /// All run futures are directly owned here. Dropping this owner synchronously
    /// drops sockets; cancellation of a command waiter never cancels a transition.
    pub async fn serve(&self, shutdown: impl std::future::Future<Output = ()> + Send) {
        self.serve_inner(shutdown, None).await;
    }
    pub async fn serve_managed(
        &self,
        shutdown: impl std::future::Future<Output = ()> + Send,
        controls: Arc<crate::management::ClientManagement>,
    ) {
        self.serve_inner(shutdown, Some(controls.subscribe())).await;
    }
    async fn serve_inner(
        &self,
        shutdown: impl std::future::Future<Output = ()> + Send,
        mut controls: Option<tokio::sync::watch::Receiver<crate::management::ClientControls>>,
    ) {
        let mut rx = self.rx.lock().unwrap().take().expect("one traffic owner");
        // Also publish stopped if the process owner is abruptly cancelled.
        // Declared before `active`, so the sockets are dropped first.
        struct StopOnDrop<'a>(&'a TrafficController);
        impl Drop for StopOnDrop<'_> {
            fn drop(&mut self) {
                self.0.mark_stopped();
            }
        }
        let _stopped = StopOnDrop(self);
        let mut active: Option<std::pin::Pin<Box<dyn std::future::Future<Output = ()> + Send>>> =
            None;
        tokio::pin!(shutdown);
        loop {
            tokio::select! {
                biased;
                _ = &mut shutdown => break,
                _ = async { match &mut controls { Some(c) => { let _ = c.changed().await; }, None => std::future::pending().await } } => {
                    if controls.as_ref().is_some_and(|c| !c.borrow().enabled) {
                        active = None;
                        self.mark_stopped();
                    }
                }
                request = rx.recv() => {
                    let Some(request) = request else { break };
                    if matches!(request.command, Command::Start(..)) && controls.as_ref().is_some_and(|c| !c.borrow().enabled) {
                        let _ = request.reply.send(Err("client is disabled".into()));
                        continue;
                    }
                    let expected = match &request.command { Command::Start(_, id) | Command::Stop(id) => *id };
                    if expected != self.snapshot().run_id {
                        let _ = request.reply.send(Err("traffic run changed; refresh before retrying".into()));
                        continue;
                    }
                    // Drop completes cleanup: run futures never spawn children.
                    active = None;
                    let old = self.snapshot();
                    match request.command {
                        Command::Start(params, _) => {
                            let run = Arc::new(Mutex::new(Metrics::new(TrafficSnapshot {
                                run_id: old.run_id + 1, revision: old.revision + 1, state: "starting".into(),
                                server_url: params.server_url.clone(), total_rate_bytes_per_second: params.total_rate_bytes_per_second,
                                upload_ratio: params.upload_ratio, download_ratio: params.download_ratio,
                                started_at_unix_ms: Some(std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap_or_default().as_millis() as u64),
                                ..TrafficSnapshot::default()
                            })));
                            *self.current.lock().unwrap() = run.clone();
                            active = Some(Box::pin(run_test(self.socks, params, run)));
                        }
                        Command::Stop(_) => self.mark_stopped(),
                    }
                    let _ = request.reply.send(Ok(()));
                }
                // Unreachable today: run_test never completes because both
                // lanes retry forever and the sampler runs forever. Retained
                // as a defensive safety net.
                _ = async { match &mut active { Some(f) => f.await, None => std::future::pending().await } } => {
                    active = None;
                    self.mark_stopped();
                }
            }
        }
        drop(active);
    }
    fn mark_stopped(&self) {
        let run = self.current.lock().unwrap();
        let mut m = run.lock().unwrap();
        m.view.state = "stopped".into();
        m.view.upload_rate_bytes_per_second = 0;
        m.view.download_rate_bytes_per_second = 0;
        m.view.revision += 1;
    }
}

async fn run_test(socks: SocketAddr, params: TrafficRunParams, run: Run) {
    let sample = async {
        let mut tick = tokio::time::interval(Duration::from_millis(200));
        tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        loop {
            tick.tick().await;
            run.lock().unwrap().sample(Instant::now());
        }
    };
    tokio::join!(
        lane(socks, &params, &run, 0),
        lane(socks, &params, &run, 1),
        sample
    );
}
async fn lane(socks: SocketAddr, params: &TrafficRunParams, run: &Run, lane: usize) {
    let mut backoff = Duration::from_millis(250);
    loop {
        let started = Instant::now();
        let result = async {
            let stream = timeout(SETUP_TIMEOUT, connect(socks, params, lane))
                .await
                .map_err(|_| "traffic setup timed out".to_string())??;
            run.lock().unwrap().connection(lane, true);
            if lane == 0 {
                bulk(stream, params, run).await
            } else {
                latency(stream, run).await
            }
        }
        .await;
        run.lock().unwrap().failure(
            lane,
            &result
                .err()
                .unwrap_or_else(|| "traffic stream closed".into()),
        );
        if started.elapsed() >= Duration::from_secs(10) {
            backoff = Duration::from_millis(250);
        }
        tokio::time::sleep(backoff).await;
        backoff = (backoff * 2).min(Duration::from_secs(5));
    }
}

/// Short burst, initially empty, recreated empty after reconnect. The minimum
/// capacity accommodates one byte at 1:100 even at the lowest selected rate.
struct Bucket {
    rate: f64,
    capacity: f64,
    credit: f64,
    at: Instant,
}
impl Bucket {
    fn new(rate: u64) -> Self {
        Self {
            rate: rate as f64,
            capacity: (rate as f64 * 0.02).max(101.0),
            credit: 0.0,
            at: Instant::now(),
        }
    }
    async fn acquire(&mut self, amount: u64) {
        // Violating this would stall (not panic) the run in release builds;
        // chunk_size provably keeps chunk cost within capacity.
        debug_assert!(amount as f64 <= self.capacity);
        loop {
            let now = Instant::now();
            self.credit = (self.credit + now.duration_since(self.at).as_secs_f64() * self.rate)
                .min(self.capacity);
            self.at = now;
            if self.credit >= amount as f64 {
                self.credit -= amount as f64;
                return;
            }
            tokio::time::sleep(Duration::from_secs_f64(
                (amount as f64 - self.credit) / self.rate,
            ))
            .await;
        }
    }
}
fn response_delta(sent: u64, count: u64, p: &TrafficRunParams) -> u64 {
    let u = p.upload_ratio as u128;
    let d = p.download_ratio as u128;
    (((sent as u128 + count as u128) * d / u) - (sent as u128 * d / u)) as u64
}
fn chunk_size(p: &TrafficRunParams, bucket: &Bucket) -> usize {
    // Round down conservatively; ceil response cost is at most capacity.
    ((bucket.capacity as u64 * p.upload_ratio as u64
        / (p.upload_ratio as u64 + p.download_ratio as u64))
        .max(1) as usize)
        .min(CHUNK)
}
fn response_window(p: &TrafficRunParams, rtt_ms: f64) -> u64 {
    // Four RTTs, initially 250 ms, capped at 512 MiB of *work*, not allocation.
    let download_rate = p.total_rate_bytes_per_second as f64 * p.download_ratio as f64
        / (p.upload_ratio as f64 + p.download_ratio as f64);
    (download_rate * (rtt_ms / 1000.0 * 4.0).max(0.25)).clamp((4 << 20) as f64, (512 << 20) as f64)
        as u64
}
async fn bulk<S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin>(
    stream: S,
    p: &TrafficRunParams,
    run: &Run,
) -> Result<(), String> {
    let (mut reader, mut writer) = tokio::io::split(stream);
    let mut bucket = Bucket::new(p.total_rate_bytes_per_second);
    let size = chunk_size(p, &bucket);
    let output = vec![0u8; size];
    let mut input = vec![0u8; CHUNK];
    let mut sent = 0u64;
    let mut received = 0u64;
    let mut allowance = 0usize;
    let mut last_progress = Instant::now();
    loop {
        let expected = response_delta(0, sent, p);
        let rtt = run.lock().unwrap().view.latency.latest_ms.unwrap_or(250.0);
        let room = expected.saturating_sub(received) + response_delta(sent, size as u64, p)
            <= response_window(p, rtt);
        tokio::select! {
            result = reader.read(&mut input) => {
                let n = result.map_err(|e| format!("bulk read failed: {e}"))?;
                if n == 0 { return Err("bulk stream closed".into()); }
                received += n as u64;
                if received > expected { return Err("server exceeded ratio response allowance".into()); }
                let mut m = run.lock().unwrap();
                m.view.downloaded_bytes = m.view.downloaded_bytes.saturating_add(n as u64);
                m.view.revision += 1;
                last_progress = Instant::now();
            }
            result = writer.write(&output[..allowance]), if allowance > 0 && room => {
                let n = result.map_err(|e| format!("bulk write failed: {e}"))?;
                if n == 0 { return Err("bulk write closed".into()); }
                sent = sent.checked_add(n as u64).ok_or("bulk counter exhausted")?;
                allowance -= n;
                let mut m = run.lock().unwrap();
                m.view.uploaded_bytes = m.view.uploaded_bytes.saturating_add(n as u64);
                m.view.revision += 1;
                last_progress = Instant::now();
            }
            _ = bucket.acquire(size as u64 + response_delta(sent, size as u64, p)), if allowance == 0 && room => { allowance = size; }
            _ = tokio::time::sleep_until(last_progress + IO_TIMEOUT) => return Err("bulk progress timed out".into()),
        }
    }
}
async fn latency(mut stream: TcpStream, run: &Run) -> Result<(), String> {
    let mut sequence = 0u64;
    loop {
        let probe = sequence.to_be_bytes();
        let mut echo = [0; 8];
        let sent = Instant::now();
        timeout(Duration::from_secs(5), async {
            stream.write_all(&probe).await?;
            stream.read_exact(&mut echo).await?;
            Ok::<_, std::io::Error>(())
        })
        .await
        .map_err(|_| "latency probe timed out")?
        .map_err(|e| format!("latency I/O failed: {e}"))?;
        if echo != probe {
            return Err("latency echo mismatch".into());
        }
        run.lock()
            .unwrap()
            .probe(sent.elapsed().as_secs_f64() * 1000.0);
        sequence = sequence.wrapping_add(1);
        tokio::time::sleep(Duration::from_secs(1)).await;
    }
}
fn endpoint(value: &str) -> Result<(String, String), String> {
    if value.len() > 2048 {
        return Err("server URL too long".into());
    }
    let url = url::Url::parse(value).map_err(|_| "invalid server URL")?;
    if url.scheme() != "http"
        || url.host().is_none()
        || !url.username().is_empty()
        || url.password().is_some()
        || url.query().is_some()
        || url.fragment().is_some()
    {
        return Err("server URL requires http host without credentials, query or fragment".into());
    }
    let host = match url.host().unwrap() {
        url::Host::Ipv6(ip) => format!("[{ip}]"),
        other => other.to_string(),
    };
    let target = format!("{}:{}", host, url.port_or_known_default().unwrap());
    socks_client::parse_target(&target).map_err(|_| "invalid server destination")?;
    Ok((target, url.path().trim_end_matches('/').to_string()))
}
async fn connect(
    socks: SocketAddr,
    p: &TrafficRunParams,
    lane: usize,
) -> Result<TcpStream, String> {
    let (target, base) = endpoint(&p.server_url)?;
    let mut stream = socks_client::connect(socks, &target, SETUP_TIMEOUT)
        .await
        .map_err(|e| format!("SOCKS connection failed: {e}"))?
        .stream;
    stream
        .set_nodelay(true)
        .map_err(|e| format!("TCP configuration failed: {e}"))?;
    let (u, d) = if lane == 0 {
        (p.upload_ratio, p.download_ratio)
    } else {
        (1, 1)
    };
    stream.write_all(format!("GET {base}/v1/stream/{u}/{d} HTTP/1.1\r\nHost: {target}\r\nConnection: Upgrade\r\nUpgrade: {TOKEN}\r\n\r\n").as_bytes()).await.map_err(|e| format!("upgrade write failed: {e}"))?;
    read_upgrade(&mut stream).await?;
    Ok(stream)
}

async fn read_upgrade<S: tokio::io::AsyncRead + Unpin>(stream: &mut S) -> Result<(), String> {
    let mut headers = Vec::new();
    while !headers.ends_with(b"\r\n\r\n") {
        if headers.len() >= 8192 {
            return Err("upgrade headers too large".into());
        }
        headers.push(
            stream
                .read_u8()
                .await
                .map_err(|e| format!("upgrade read failed: {e}"))?,
        );
    }
    validate_upgrade(&headers)
}
fn validate_upgrade(bytes: &[u8]) -> Result<(), String> {
    let text = std::str::from_utf8(bytes).map_err(|_| "invalid upgrade headers")?;
    let mut lines = text.split("\r\n");
    let mut status = lines.next().unwrap_or_default().split_whitespace();
    if status.next() != Some("HTTP/1.1") || status.next() != Some("101") {
        return Err("server rejected upgrade".into());
    }
    let mut connection = false;
    let mut upgrade = 0;
    for line in lines.filter(|l| !l.is_empty()) {
        let (name, value) = line.split_once(':').ok_or("invalid upgrade header")?;
        http::header::HeaderName::from_bytes(name.as_bytes())
            .map_err(|_| "invalid upgrade header name")?;
        http::header::HeaderValue::from_str(value.trim())
            .map_err(|_| "invalid upgrade header value")?;
        if name.eq_ignore_ascii_case("connection") {
            connection |= value
                .split(',')
                .any(|v| v.trim().eq_ignore_ascii_case("upgrade"));
        }
        if name.eq_ignore_ascii_case("upgrade") {
            if value.trim() != TOKEN {
                return Err("wrong upgrade protocol".into());
            }
            upgrade += 1;
        }
    }
    if !connection || upgrade != 1 {
        return Err("missing or duplicate upgrade headers".into());
    }
    Ok(())
}

#[cfg(test)]
mod tests;
