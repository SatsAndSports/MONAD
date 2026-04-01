//! Per-client H2 session handler.
//!
//! After the Noise handshake, the server runs an H2 server on the encrypted
//! stream. The session starts paused-by-default with zero balance. A long-lived
//! `POST /control` stream is used to fund and observe the whole session.

use crate::proxy;
use crate::quic_pool::QuicPool;
use bytes::Bytes;
use h2::server;
use http::{Method, Response, StatusCode};
use monad_common::h2stream::wait_for_send_capacity;
use monad_common::noise::NoiseStream;
use monad_common::protocol::{ClientMessage, ServerMessage};
use monad_common::session::{SessionPricing, clamp_i128_to_i64};
use std::io;
use std::sync::Arc;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::TcpStream;
use tokio::sync::{mpsc, watch, Mutex};
use tracing::{debug, error, info, warn};

/// Custom header name for QUIC pinned public key in CONNECT requests.
pub const QUIC_PIN_HEADER: &str = "quic-pin";

const SERVER_MAX_VERSION: u8 = 0;
const DEFAULT_IN_BYTES_PER_MILLISAT: u64 = 1;
const DEFAULT_OUT_BYTES_PER_MILLISAT: u64 = 1;

#[derive(Debug, Clone)]
struct SessionSnapshot {
    session_total_in: u64,
    session_total_out: u64,
    remaining_milli_sats: i64,
    paused: bool,
}

impl SessionSnapshot {
    fn to_message(&self) -> ServerMessage {
        ServerMessage::SessionStatus {
            session_total_in: self.session_total_in,
            session_total_out: self.session_total_out,
            remaining_milli_sats: self.remaining_milli_sats,
            paused: self.paused,
        }
    }
}

#[derive(Debug)]
struct SessionInner {
    session_total_in: u64,
    session_total_out: u64,
    total_paid_millisats: u64,
    pricing: SessionPricing,
    paused: bool,
    control_attached: bool,
    control_tx: Option<mpsc::UnboundedSender<ServerMessage>>,
}

#[derive(Clone)]
pub(crate) struct SessionState {
    inner: Arc<Mutex<SessionInner>>,
    pause_tx: watch::Sender<bool>,
}

impl SessionState {
    fn new() -> Self {
        let (pause_tx, _) = watch::channel(true);
        Self {
            inner: Arc::new(Mutex::new(SessionInner {
                session_total_in: 0,
                session_total_out: 0,
                total_paid_millisats: 0,
                pricing: SessionPricing::new(
                    SERVER_MAX_VERSION,
                    DEFAULT_IN_BYTES_PER_MILLISAT,
                    DEFAULT_OUT_BYTES_PER_MILLISAT,
                ),
                paused: true,
                control_attached: false,
                control_tx: None,
            })),
            pause_tx,
        }
    }

    fn session_params_message(inner: &SessionInner, negotiated_version: u8) -> ServerMessage {
        ServerMessage::SessionParams {
            version: negotiated_version,
            in_bytes_per_millisat: inner.pricing.in_bytes_per_millisat,
            out_bytes_per_millisat: inner.pricing.out_bytes_per_millisat,
        }
    }

    fn remaining_milli_sats(inner: &SessionInner) -> i128 {
        let amount_due = inner
            .pricing
            .amount_due_millisats(inner.session_total_in, inner.session_total_out);
        inner.total_paid_millisats as i128 - amount_due as i128
    }

    fn snapshot_from_inner(inner: &SessionInner) -> SessionSnapshot {
        SessionSnapshot {
            session_total_in: inner.session_total_in,
            session_total_out: inner.session_total_out,
            remaining_milli_sats: clamp_i128_to_i64(Self::remaining_milli_sats(inner)),
            paused: inner.paused,
        }
    }

    fn refresh_pause_state(&self, inner: &mut SessionInner) {
        let was_paused = inner.paused;
        inner.paused = Self::remaining_milli_sats(inner) <= 0;
        if inner.paused != was_paused {
            let _ = self.pause_tx.send_replace(inner.paused);
        }
    }

    pub(crate) fn pause_receiver(&self) -> watch::Receiver<bool> {
        self.pause_tx.subscribe()
    }

    async fn snapshot(&self) -> SessionSnapshot {
        let inner = self.inner.lock().await;
        Self::snapshot_from_inner(&inner)
    }

    async fn session_params(&self, negotiated_version: u8) -> ServerMessage {
        let inner = self.inner.lock().await;
        Self::session_params_message(&inner, negotiated_version)
    }

    async fn is_paused(&self) -> bool {
        self.inner.lock().await.paused
    }

    async fn attach_control(
        &self,
        tx: mpsc::UnboundedSender<ServerMessage>,
    ) -> Result<SessionSnapshot, ()> {
        let mut inner = self.inner.lock().await;
        if inner.control_attached {
            return Err(());
        }

        inner.control_attached = true;
        inner.control_tx = Some(tx);
        Ok(Self::snapshot_from_inner(&inner))
    }

    async fn detach_control(&self) {
        let mut inner = self.inner.lock().await;
        inner.control_attached = false;
        inner.control_tx = None;
    }

    async fn apply_fake_payment(&self, milli_sats: u64) -> SessionSnapshot {
        let mut inner = self.inner.lock().await;
        inner.total_paid_millisats = inner.total_paid_millisats.saturating_add(milli_sats);
        self.refresh_pause_state(&mut inner);
        Self::snapshot_from_inner(&inner)
    }

    pub(crate) async fn note_outbound_bytes(&self, bytes: usize) -> bool {
        self.note_bytes(bytes, true).await
    }

    pub(crate) async fn note_inbound_bytes(&self, bytes: usize) -> bool {
        self.note_bytes(bytes, false).await
    }

    async fn note_bytes(&self, bytes: usize, outbound: bool) -> bool {
        let mut inner = self.inner.lock().await;

        if outbound {
            inner.session_total_out = inner.session_total_out.saturating_add(bytes as u64);
        } else {
            inner.session_total_in = inner.session_total_in.saturating_add(bytes as u64);
        }

        self.refresh_pause_state(&mut inner);
        inner.paused
    }

    async fn push_message(&self, message: ServerMessage) {
        let tx = {
            let inner = self.inner.lock().await;
            inner.control_tx.clone()
        };

        if let Some(tx) = tx {
            let _ = tx.send(message);
        }
    }

    pub(crate) async fn push_status(&self) {
        let snapshot = self.snapshot().await;
        self.push_message(snapshot.to_message()).await;
    }
}

/// An inbound relay session: an H2 server connection running over an
/// encrypted `NoiseStream`.
pub struct RelaySession<T: AsyncRead + AsyncWrite + Unpin + Send + 'static> {
    h2_conn: server::Connection<NoiseStream<T>, Bytes>,
    quic_pool: Option<QuicPool>,
    state: SessionState,
}

impl<T: AsyncRead + AsyncWrite + Unpin + Send + 'static> RelaySession<T> {
    /// Perform an H2 server handshake over the given `NoiseStream` and return
    /// a `RelaySession` ready to accept streams.
    pub async fn from_noise_stream(
        noise_stream: NoiseStream<T>,
        quic_pool: Option<QuicPool>,
    ) -> io::Result<Self> {
        let h2_conn = server::handshake(noise_stream)
            .await
            .map_err(|e| {
                io::Error::new(io::ErrorKind::Other, format!("h2 handshake error: {e}"))
            })?;

        info!("H2 connection established");

        Ok(Self {
            h2_conn,
            quic_pool,
            state: SessionState::new(),
        })
    }

    /// Run the accept loop: accept H2 streams and dispatch them to handlers.
    pub async fn run(mut self) -> io::Result<()> {
        while let Some(result) = self.h2_conn.accept().await {
            match result {
                Ok((request, mut respond)) => {
                    let method = request.method().clone();
                    let uri = request.uri().clone();

                    debug!(
                        "received H2 request: {method} {uri} (path={:?}, authority={:?})",
                        uri.path(),
                        uri.authority()
                    );

                    match (&method, uri.path()) {
                        (&Method::CONNECT, _) => {
                            if self.state.is_paused().await {
                                let resp = Response::builder()
                                    .status(StatusCode::PAYMENT_REQUIRED)
                                    .body(())
                                    .unwrap();
                                let _ = respond.send_response(resp, true);
                                continue;
                            }

                            let authority = uri
                                .authority()
                                .map(|a| a.to_string())
                                .unwrap_or_else(|| uri.to_string());

                            if authority.is_empty() {
                                warn!("CONNECT request missing authority");
                                let resp = Response::builder()
                                    .status(StatusCode::BAD_REQUEST)
                                    .body(())
                                    .unwrap();
                                let _ = respond.send_response(resp, true);
                                continue;
                            }

                            let quic_pin_header = request
                                .headers()
                                .get(QUIC_PIN_HEADER)
                                .and_then(|v| v.to_str().ok())
                                .map(|s| s.to_string());

                            if let Some(pin_hex) = quic_pin_header {
                                info!("CONNECT {authority} (via QUIC)");

                                let pinned_spki = match hex::decode(&pin_hex) {
                                    Ok(b) if !b.is_empty() => b,
                                    Ok(_) => {
                                        warn!("empty quic-pin header");
                                        let resp = Response::builder()
                                            .status(StatusCode::BAD_REQUEST)
                                            .body(())
                                            .unwrap();
                                        let _ = respond.send_response(resp, true);
                                        continue;
                                    }
                                    Err(e) => {
                                        warn!("invalid hex in quic-pin header: {e}");
                                        let resp = Response::builder()
                                            .status(StatusCode::BAD_REQUEST)
                                            .body(())
                                            .unwrap();
                                        let _ = respond.send_response(resp, true);
                                        continue;
                                    }
                                };

                                let pool = match &self.quic_pool {
                                    Some(p) => p.clone(),
                                    None => {
                                        warn!("CONNECT with quic-pin but QUIC pool is not available");
                                        let resp = Response::builder()
                                            .status(StatusCode::BAD_GATEWAY)
                                            .body(())
                                            .unwrap();
                                        let _ = respond.send_response(resp, true);
                                        continue;
                                    }
                                };

                                match pool.open_stream(&authority, pinned_spki).await {
                                    Ok(quic_stream) => {
                                        info!("QUIC stream opened to {authority}");
                                        let resp = Response::builder()
                                            .status(StatusCode::OK)
                                            .body(())
                                            .unwrap();
                                        match respond.send_response(resp, false) {
                                            Ok(h2_send) => {
                                                let (_, h2_recv) = request.into_parts();
                                                let label = format!("quic:{authority}");
                                                let state = self.state.clone();
                                                tokio::spawn(async move {
                                                    if let Err(e) = proxy::proxy_bidirectional_accounted(
                                                        h2_send,
                                                        h2_recv,
                                                        quic_stream,
                                                        &label,
                                                        state,
                                                    )
                                                    .await
                                                    {
                                                        error!("tunnel to quic:{authority} error: {e}");
                                                    }
                                                });
                                            }
                                            Err(e) => {
                                                error!("h2 send response error: {e}");
                                            }
                                        }
                                    }
                                    Err(e) => {
                                        warn!("failed to connect via QUIC to {authority}: {e}");
                                        let resp = Response::builder()
                                            .status(StatusCode::BAD_GATEWAY)
                                            .body(())
                                            .unwrap();
                                        let _ = respond.send_response(resp, true);
                                    }
                                }
                            } else {
                                info!("CONNECT {authority}");

                                match TcpStream::connect(&authority).await {
                                    Ok(tcp_stream) => {
                                        info!("connected to {authority}");
                                        let resp = Response::builder()
                                            .status(StatusCode::OK)
                                            .body(())
                                            .unwrap();
                                        match respond.send_response(resp, false) {
                                            Ok(h2_send) => {
                                                let (_, h2_recv) = request.into_parts();
                                                let state = self.state.clone();
                                                tokio::spawn(async move {
                                                    if let Err(e) = proxy::proxy_bidirectional_accounted(
                                                        h2_send,
                                                        h2_recv,
                                                        tcp_stream,
                                                        &authority,
                                                        state,
                                                    )
                                                    .await
                                                    {
                                                        error!("tunnel to {authority} error: {e}");
                                                    }
                                                });
                                            }
                                            Err(e) => {
                                                error!("h2 send response error: {e}");
                                            }
                                        }
                                    }
                                    Err(e) => {
                                        warn!("failed to connect to {authority}: {e}");
                                        let resp = Response::builder()
                                            .status(StatusCode::BAD_GATEWAY)
                                            .body(())
                                            .unwrap();
                                        let _ = respond.send_response(resp, true);
                                    }
                                }
                            }
                        }
                        (&Method::POST, "/control") => {
                            let (event_tx, event_rx) = mpsc::unbounded_channel();
                            let snapshot = match self.state.attach_control(event_tx).await {
                                Ok(snapshot) => snapshot,
                                Err(()) => {
                                    let resp = Response::builder()
                                        .status(StatusCode::CONFLICT)
                                        .body(())
                                        .unwrap();
                                    let _ = respond.send_response(resp, true);
                                    continue;
                                }
                            };

                            let resp = Response::builder()
                                .status(StatusCode::OK)
                                .body(())
                                .unwrap();
                            match respond.send_response(resp, false) {
                                Ok(h2_send) => {
                                    let (_, h2_recv) = request.into_parts();
                                    let state = self.state.clone();
                                    tokio::spawn(async move {
                                        if let Err(e) =
                                            handle_control_stream(h2_send, h2_recv, state, event_rx, snapshot)
                                                .await
                                        {
                                            error!("control channel error: {e}");
                                        }
                                    });
                                }
                                Err(e) => {
                                    error!("h2 send response error for control: {e}");
                                    self.state.detach_control().await;
                                }
                            }
                        }
                        _ => {
                            warn!("unsupported request: {method} {}", uri.path());
                            let resp = Response::builder()
                                .status(StatusCode::METHOD_NOT_ALLOWED)
                                .body(())
                                .unwrap();
                            let _ = respond.send_response(resp, true);
                        }
                    }
                }
                Err(e) => {
                    error!("h2 accept error: {e}");
                    break;
                }
            }
        }

        info!("H2 connection closed");
        Ok(())
    }
}

fn encode_server_message(message: &ServerMessage) -> io::Result<Bytes> {
    let bytes = serde_json::to_vec(message)
        .map_err(|e| io::Error::new(io::ErrorKind::Other, format!("json error: {e}")))?;
    let mut frame = Vec::with_capacity(bytes.len() + 1);
    frame.extend_from_slice(&bytes);
    frame.push(b'\n');
    Ok(Bytes::from(frame))
}

async fn send_control_message(
    h2_send: &mut h2::SendStream<Bytes>,
    message: &ServerMessage,
) -> io::Result<()> {
    let frame = encode_server_message(message)?;
    h2_send.reserve_capacity(frame.len());
    wait_for_send_capacity(h2_send).await?;
    h2_send
        .send_data(frame, false)
        .map_err(|e| io::Error::new(io::ErrorKind::Other, format!("h2 send error: {e}")))
}

/// Read one newline-delimited JSON message from the H2 recv stream.
async fn read_one_control_message(
    h2_recv: &mut h2::RecvStream,
    buf: &mut Vec<u8>,
) -> io::Result<Option<ClientMessage>> {
    loop {
        if let Some(newline_pos) = buf.iter().position(|&b| b == b'\n') {
            let line: Vec<u8> = buf.drain(..=newline_pos).collect();
            let line = line.trim_ascii();
            if line.is_empty() {
                continue;
            }
            let msg = serde_json::from_slice::<ClientMessage>(line)
                .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, format!("invalid message: {e}")))?;
            return Ok(Some(msg));
        }

        match h2_recv.data().await {
            Some(Ok(data)) => {
                let len = data.len();
                let _ = h2_recv.flow_control().release_capacity(len);
                buf.extend_from_slice(&data);
            }
            Some(Err(e)) => {
                return Err(io::Error::new(io::ErrorKind::Other, format!("h2 recv error: {e}")));
            }
            None => return Ok(None),
        }
    }
}

/// Handle a long-lived control stream for one paid relay session.
async fn handle_control_stream(
    mut h2_send: h2::SendStream<Bytes>,
    mut h2_recv: h2::RecvStream,
    state: SessionState,
    mut events: mpsc::UnboundedReceiver<ServerMessage>,
    initial_snapshot: SessionSnapshot,
) -> io::Result<()> {
    info!("control channel opened");

    // Wait for the client's Hello message before sending session params.
    let mut buf = Vec::new();
    let client_version = match read_one_control_message(&mut h2_recv, &mut buf).await? {
        Some(ClientMessage::Hello { version }) => {
            debug!("control: client hello version={version}");
            version
        }
        Some(other) => {
            warn!("control: expected Hello, got {other:?}");
            let err_msg = ServerMessage::Error {
                message: "expected Hello as first message".to_string(),
            };
            send_control_message(&mut h2_send, &err_msg).await?;
            state.detach_control().await;
            let _ = h2_send.send_data(Bytes::new(), true);
            return Ok(());
        }
        None => {
            debug!("control channel closed before Hello");
            state.detach_control().await;
            return Ok(());
        }
    };

    let negotiated_version = client_version.min(SERVER_MAX_VERSION);
    let params = state.session_params(negotiated_version).await;
    send_control_message(&mut h2_send, &params).await?;
    send_control_message(&mut h2_send, &initial_snapshot.to_message()).await?;

    loop {
        tokio::select! {
            maybe_event = events.recv() => {
                match maybe_event {
                    Some(message) => {
                        send_control_message(&mut h2_send, &message).await?;
                    }
                    None => break,
                }
            }
            maybe_chunk = h2_recv.data() => {
                match maybe_chunk {
                    Some(Ok(data)) => {
                        let len = data.len();
                        let _ = h2_recv.flow_control().release_capacity(len);
                        buf.extend_from_slice(&data);

                        while let Some(newline_pos) = buf.iter().position(|&b| b == b'\n') {
                            let line: Vec<u8> = buf.drain(..=newline_pos).collect();
                            let line = line.trim_ascii();

                            if line.is_empty() {
                                continue;
                            }

                            match serde_json::from_slice::<ClientMessage>(line) {
                                Ok(ClientMessage::Hello { .. }) => {
                                    warn!("control: unexpected Hello after handshake");
                                    let err_msg = ServerMessage::Error {
                                        message: "Hello already received".to_string(),
                                    };
                                    send_control_message(&mut h2_send, &err_msg).await?;
                                }
                                Ok(ClientMessage::Ping) => {
                                    send_control_message(&mut h2_send, &ServerMessage::Pong).await?;
                                }
                                Ok(ClientMessage::GetSessionStatus) => {
                                    let snapshot = state.snapshot().await;
                                    send_control_message(&mut h2_send, &snapshot.to_message()).await?;
                                }
                                Ok(ClientMessage::FakePayment { milli_sats }) => {
                                    let snapshot = state.apply_fake_payment(milli_sats).await;
                                    state.push_status().await;
                                    debug!(
                                        "fake payment accepted: added={} remaining={}",
                                        milli_sats,
                                        snapshot.remaining_milli_sats
                                    );
                                }
                                Err(e) => {
                                    warn!("control: invalid message: {e}");
                                    let err_msg = ServerMessage::Error {
                                        message: format!("invalid message: {e}"),
                                    };
                                    send_control_message(&mut h2_send, &err_msg).await?;
                                }
                            }
                        }
                    }
                    Some(Err(e)) => {
                        debug!("control h2 recv error: {e}");
                        break;
                    }
                    None => {
                        debug!("control channel closed by client");
                        break;
                    }
                }
            }
        }
    }

    state.detach_control().await;
    let _ = h2_send.send_data(Bytes::new(), true);
    info!("control channel closed");
    Ok(())
}
