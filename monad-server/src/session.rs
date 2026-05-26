//! Per-client H2 session handler.
//!
//! After the Noise handshake, the server runs an H2 server on the encrypted
//! stream. The session starts paused-by-default with zero balance. A long-lived
//! `POST /control` stream is used to fund and observe the whole session.

use crate::listener::SpilmanMintCache;
use crate::proxy;
use crate::quic_pool::QuicPool;
use bytes::Bytes;
use cashu::nuts::SecretKey;
use h2::server;
use http::{Method, Response, StatusCode};
use monad_common::h2stream::wait_for_send_capacity;
use monad_common::noise::NoiseStream;
use monad_common::protocol::{ClientMessage, KeysetAdvertisement, ServerMessage};
use monad_common::secp_identity::Secp256k1Pubkey;
use monad_common::session::{clamp_i128_to_i64, SessionPricing};
use monad_quic::client::ClientAuthMode;
use monad_quic::stream::STREAM_KIND_SECP_NOISE;
use std::io;
use std::sync::Arc;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::TcpStream;
use tokio::sync::{mpsc, watch, Mutex};
use tracing::{debug, error, info, warn};

/// Custom header name for QUIC pinned public key in CONNECT requests.
pub const QUIC_PIN_HEADER: &str = "quic-pin";
/// Custom header name for QUIC secp256k1 transport identity in CONNECT requests.
pub const QUIC_SECP256K1_PUBKEY_HEADER: &str = "quic-secp256k1-pubkey";

const SERVER_MIN_VERSION: u8 = 0;
const SERVER_MAX_VERSION: u8 = 0;
const DEFAULT_IN_BYTES_PER_MILLISAT: u64 = 1;
const DEFAULT_OUT_BYTES_PER_MILLISAT: u64 = 1;

#[derive(Debug)]
struct SessionInner {
    session_total_in: u64,
    session_total_out: u64,
    total_paid_millisats: u64,
    pricing: SessionPricing,
    paused: bool,
    control_attached: bool,
    control_tx: Option<mpsc::UnboundedSender<ServerMessage>>,
    // TODO: set this in a future ChannelLink handler. Currently always None
    // because Spilman channel linking is not yet implemented; only FakePayment
    // moves the balance today.
    linked_channel_id: Option<String>,
}

#[derive(Clone)]
pub(crate) struct SessionState {
    inner: Arc<Mutex<SessionInner>>,
    pause_tx: watch::Sender<bool>,
    payment_receiver_secret: SecretKey,
    spilman_mint_cache: SpilmanMintCache,
}

impl SessionState {
    fn new(payment_receiver_secret: SecretKey, spilman_mint_cache: SpilmanMintCache) -> Self {
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
                linked_channel_id: None,
            })),
            pause_tx,
            payment_receiver_secret,
            spilman_mint_cache,
        }
    }

    fn remaining_milli_sats(inner: &SessionInner) -> i128 {
        let amount_due = inner
            .pricing
            .amount_due_millisats(inner.session_total_in, inner.session_total_out);
        inner.total_paid_millisats as i128 - amount_due as i128
    }

    async fn session_status_message(&self, negotiated_version: u8) -> ServerMessage {
        let inner = self.inner.lock().await;

        let mut advertisements = Vec::new();
        for (mint_url, unit_map) in &self.spilman_mint_cache.advertised {
            for (unit, keyset_ids) in unit_map {
                advertisements.push(KeysetAdvertisement {
                    mint_url: mint_url.clone(),
                    unit: unit.clone(),
                    keyset_ids: keyset_ids.clone(),
                    // Use session defaults for now until we have per-advertisement config
                    in_bytes_per_millisat: inner.pricing.in_bytes_per_millisat,
                    out_bytes_per_millisat: inner.pricing.out_bytes_per_millisat,
                });
            }
        }

        ServerMessage::SessionStatus {
            version: negotiated_version,
            receiver_pubkey: self.payment_receiver_secret.public_key().to_hex(),
            advertisements,
            linked_channel_id: inner.linked_channel_id.clone(),
            active_in_rate: inner.pricing.in_bytes_per_millisat,
            active_out_rate: inner.pricing.out_bytes_per_millisat,
            session_total_in: inner.session_total_in,
            session_total_out: inner.session_total_out,
            total_paid_millisats: inner.total_paid_millisats,
            remaining_milli_sats: clamp_i128_to_i64(Self::remaining_milli_sats(&inner)),
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

    async fn is_paused(&self) -> bool {
        self.inner.lock().await.paused
    }

    async fn attach_control(&self, tx: mpsc::UnboundedSender<ServerMessage>) -> Result<(), ()> {
        let mut inner = self.inner.lock().await;
        if inner.control_attached {
            return Err(());
        }

        inner.control_attached = true;
        inner.control_tx = Some(tx);
        Ok(())
    }

    async fn detach_control(&self) {
        let mut inner = self.inner.lock().await;
        inner.control_attached = false;
        inner.control_tx = None;
    }

    async fn apply_fake_payment(&self, milli_sats: u64) {
        let mut inner = self.inner.lock().await;
        inner.total_paid_millisats = inner.total_paid_millisats.saturating_add(milli_sats);
        self.refresh_pause_state(&mut inner);
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
        let version = {
            let inner = self.inner.lock().await;
            inner.pricing.version
        };
        let status = self.session_status_message(version).await;
        self.push_message(status).await;
    }
}

/// An inbound relay session: an H2 server connection running over an
/// encrypted `NoiseStream`.
pub struct RelaySession<S: AsyncRead + AsyncWrite + Unpin + Send + 'static> {
    h2_conn: server::Connection<S, Bytes>,
    quic_pool: Option<QuicPool>,
    #[allow(dead_code)]
    session_id: [u8; 32],
    state: SessionState,
}

pub async fn relay_session_from_transport_stream<S>(
    stream: S,
    session_id: [u8; 32],
    quic_pool: Option<QuicPool>,
    payment_receiver_secret: SecretKey,
    spilman_mint_cache: SpilmanMintCache,
) -> io::Result<RelaySession<S>>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let h2_conn = server::handshake(stream)
        .await
        .map_err(|e| io::Error::other(format!("h2 handshake error: {e}")))?;

    info!(
        session_id = hex::encode(session_id),
        "H2 connection established"
    );

    Ok(RelaySession {
        h2_conn,
        quic_pool,
        session_id,
        state: SessionState::new(payment_receiver_secret, spilman_mint_cache),
    })
}

pub async fn relay_session_from_noise_stream<T>(
    noise_stream: NoiseStream<T>,
    quic_pool: Option<QuicPool>,
    payment_receiver_secret: SecretKey,
    spilman_mint_cache: SpilmanMintCache,
) -> io::Result<RelaySession<NoiseStream<T>>>
where
    T: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let session_id = *noise_stream.session_id();
    relay_session_from_transport_stream(
        noise_stream,
        session_id,
        quic_pool,
        payment_receiver_secret,
        spilman_mint_cache,
    )
    .await
}

impl<S: AsyncRead + AsyncWrite + Unpin + Send + 'static> RelaySession<S> {
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
                            let quic_secp256k1_pubkey_header = request
                                .headers()
                                .get(QUIC_SECP256K1_PUBKEY_HEADER)
                                .and_then(|v| v.to_str().ok())
                                .map(|s| s.to_string());

                            if quic_pin_header.is_some() && quic_secp256k1_pubkey_header.is_some() {
                                warn!(
                                    "CONNECT request provided both quic-pin and quic-secp256k1-pubkey headers"
                                );
                                let resp = Response::builder()
                                    .status(StatusCode::BAD_REQUEST)
                                    .body(())
                                    .unwrap();
                                let _ = respond.send_response(resp, true);
                                continue;
                            }

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
                                        warn!(
                                            "CONNECT with quic-pin but QUIC pool is not available"
                                        );
                                        let resp = Response::builder()
                                            .status(StatusCode::BAD_GATEWAY)
                                            .body(())
                                            .unwrap();
                                        let _ = respond.send_response(resp, true);
                                        continue;
                                    }
                                };

                                match pool
                                    .open_stream(
                                        &authority,
                                        ClientAuthMode::PinnedSpki(pinned_spki),
                                    )
                                    .await
                                {
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
                                                    if let Err(e) =
                                                        proxy::proxy_bidirectional_accounted(
                                                            h2_send,
                                                            h2_recv,
                                                            quic_stream,
                                                            &label,
                                                            state,
                                                        )
                                                        .await
                                                    {
                                                        error!(
                                                            "tunnel to quic:{authority} error: {e}"
                                                        );
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
                            } else if let Some(pubkey_hex) = quic_secp256k1_pubkey_header {
                                info!("CONNECT {authority} (via QUIC secp256k1 auth)");

                                let pubkey = match Secp256k1Pubkey::from_hex(&pubkey_hex) {
                                    Ok(pubkey) => pubkey,
                                    Err(e) => {
                                        warn!("invalid secp256k1 public key in quic-secp256k1-pubkey header: {e}");
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
                                        warn!(
                                            "CONNECT with quic-secp256k1-pubkey but QUIC pool is not available"
                                        );
                                        let resp = Response::builder()
                                            .status(StatusCode::BAD_GATEWAY)
                                            .body(())
                                            .unwrap();
                                        let _ = respond.send_response(resp, true);
                                        continue;
                                    }
                                };

                                match pool
                                    .open_stream_with_kind(
                                        &authority,
                                        ClientAuthMode::Secp256k1(pubkey),
                                        STREAM_KIND_SECP_NOISE,
                                    )
                                    .await
                                {
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
                                                    if let Err(e) =
                                                        proxy::proxy_bidirectional_accounted(
                                                            h2_send,
                                                            h2_recv,
                                                            quic_stream,
                                                            &label,
                                                            state,
                                                        )
                                                        .await
                                                    {
                                                        error!(
                                                            "tunnel to quic:{authority} error: {e}"
                                                        );
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
                                                    if let Err(e) =
                                                        proxy::proxy_bidirectional_accounted(
                                                            h2_send, h2_recv, tcp_stream,
                                                            &authority, state,
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
                            if self.state.attach_control(event_tx).await.is_err() {
                                let resp = Response::builder()
                                    .status(StatusCode::CONFLICT)
                                    .body(())
                                    .unwrap();
                                let _ = respond.send_response(resp, true);
                                continue;
                            }

                            let resp = Response::builder().status(StatusCode::OK).body(()).unwrap();
                            match respond.send_response(resp, false) {
                                Ok(h2_send) => {
                                    let (_, h2_recv) = request.into_parts();
                                    let state = self.state.clone();
                                    tokio::spawn(async move {
                                        if let Err(e) =
                                            handle_control_stream(h2_send, h2_recv, state, event_rx)
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
    let bytes =
        serde_json::to_vec(message).map_err(|e| io::Error::other(format!("json error: {e}")))?;
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
        .map_err(|e| io::Error::other(format!("h2 send error: {e}")))
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
            let msg = serde_json::from_slice::<ClientMessage>(line).map_err(|e| {
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
            Some(Err(e)) => {
                return Err(io::Error::other(format!("h2 recv error: {e}")));
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
) -> io::Result<()> {
    info!("control channel opened");

    // Wait for the client's Hello message before sending the initial SessionStatus.
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

    if !(SERVER_MIN_VERSION..=SERVER_MAX_VERSION).contains(&client_version) {
        warn!(
            "control: unsupported client version {} (supported range {}..={})",
            client_version, SERVER_MIN_VERSION, SERVER_MAX_VERSION
        );
        let err_msg = ServerMessage::Error {
            message: format!(
                "unsupported version: client offered {}, supported range is {}..={}",
                client_version, SERVER_MIN_VERSION, SERVER_MAX_VERSION
            ),
        };
        send_control_message(&mut h2_send, &err_msg).await?;
        state.detach_control().await;
        let _ = h2_send.send_data(Bytes::new(), true);
        return Ok(());
    }

    let negotiated_version = client_version;

    // Set initial version in session state, then build and send the initial
    // SessionStatus. This is race-free: the session starts paused and no
    // proxy task can be running yet (CONNECT requires unpaused), so nothing
    // else can mutate `inner` between attaching the control_tx and reading
    // the snapshot here.
    {
        let mut inner = state.inner.lock().await;
        inner.pricing.version = negotiated_version;
    }

    let initial_status = state.session_status_message(negotiated_version).await;
    send_control_message(&mut h2_send, &initial_status).await?;

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
                                Ok(ClientMessage::GetSessionStatus) => {
                                    let status = state.session_status_message(negotiated_version).await;
                                    send_control_message(&mut h2_send, &status).await?;
                                }
                                Ok(ClientMessage::FakePayment { milli_sats }) => {
                                    state.apply_fake_payment(milli_sats).await;
                                    state.push_status().await;
                                    debug!(
                                        "fake payment accepted: added={milli_sats}"
                                    );
                                }
                                Ok(other) => {
                                    warn!("control: message not yet implemented: {other:?}");
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
