//! Per-client H2 session handler.
//!
//! After the Noise handshake, the relay runs an H2 server on the encrypted
//! stream. The session starts paused-by-default with zero balance. A long-lived
//! `POST /control` stream is used to fund and observe the whole session.

use crate::listener::SpilmanMintCache;
use crate::payments::RelayPayments;
use crate::proxy;
use crate::quic_pool::QuicPool;
use crate::session_fsm::{
    apply_accounted_bytes, remaining_milli_sats, step, ByteDirection, ServerSessionState,
    SessionEffect, SessionEvent,
};
use crate::session_registry::SessionRegistry;
use bytes::Bytes;
use cashu::nuts::SecretKey;
use h2::{server, RecvStream};
use http::{Method, Request, Response, StatusCode};
use monad_common::control_codec::{send_json_line, try_decode_json_line};
use monad_common::protocol::{ClientMessage, KeysetAdvertisement, ServerErrorCode, ServerMessage};
use monad_common::secp_identity::Secp256k1Pubkey;
use monad_common::session::{clamp_i128_to_i64, SessionPricing};
use monad_quic::client::ClientAuthMode;
use monad_quic::stream::STREAM_KIND_SECP_NOISE;
use std::collections::VecDeque;
use std::io;
use std::sync::atomic::{AtomicU32, AtomicU64, Ordering};
use std::sync::Arc;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::TcpStream;
use tokio::sync::{mpsc, watch, Mutex};
use tokio_util::sync::CancellationToken;
use tracing::{debug, error, info, warn};

/// Custom header name for QUIC secp256k1 transport identity in CONNECT requests.
pub const QUIC_SECP256K1_PUBKEY_HEADER: &str = "quic-secp256k1-pubkey";

/// Authoritative per-session billing state used by the relay reducer and the
/// data-path byte accounting fast path.
///
/// `state` is the canonical reducer state shared with `session_fsm`; `pricing`
/// is the immutable session pricing used to compute amount due and pause state.
#[derive(Debug)]
struct BillingState {
    state: ServerSessionState,
    pricing: SessionPricing,
}

impl BillingState {
    fn remaining_milli_sats(&self) -> i128 {
        remaining_milli_sats(&self.state, self.pricing)
    }
}

/// Control-stream attachment state kept separate from billing updates.
#[derive(Debug, Default)]
struct ControlState {
    control_attached: bool,
    control_tx: Option<mpsc::UnboundedSender<ServerMessage>>,
}

impl ControlState {
    fn attach(&mut self, tx: mpsc::UnboundedSender<ServerMessage>) -> Result<(), ()> {
        if self.control_attached {
            return Err(());
        }

        self.control_attached = true;
        self.control_tx = Some(tx);
        Ok(())
    }

    fn detach(&mut self) {
        self.control_attached = false;
        self.control_tx = None;
    }

    fn sender(&self) -> Option<mpsc::UnboundedSender<ServerMessage>> {
        self.control_tx.clone()
    }
}

/// Lightweight observability counters that do not participate in billing.
#[derive(Debug, Default)]
struct SessionCounters {
    open_connects: AtomicU32,
    total_connects: AtomicU64,
}

impl SessionCounters {
    fn snapshot(&self) -> (u32, u64) {
        (
            self.open_connects.load(Ordering::Relaxed),
            self.total_connects.load(Ordering::Relaxed),
        )
    }

    fn connect_opened(&self) -> (u32, u64) {
        let open_connects = self
            .open_connects
            .fetch_add(1, Ordering::Relaxed)
            .saturating_add(1);
        let total_connects = self
            .total_connects
            .fetch_add(1, Ordering::Relaxed)
            .saturating_add(1);
        (open_connects, total_connects)
    }

    fn connect_closed(&self) -> (u32, u64) {
        let open_connects = self
            .open_connects
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |current| {
                Some(current.saturating_sub(1))
            })
            .map(|previous| previous.saturating_sub(1))
            .unwrap_or(0);
        let total_connects = self.total_connects.load(Ordering::Relaxed);
        (open_connects, total_connects)
    }
}

#[derive(Clone)]
pub(crate) struct SessionState {
    billing: Arc<Mutex<BillingState>>,
    control: Arc<Mutex<ControlState>>,
    counters: Arc<SessionCounters>,
    pause_tx: watch::Sender<bool>,
    termination: CancellationToken,
    session_id: [u8; 32],
    payments: Arc<dyn RelayPayments>,
    session_registry: Arc<SessionRegistry>,
    payment_receiver_secret: SecretKey,
    spilman_mint_cache: SpilmanMintCache,
}

impl SessionState {
    // Lifecycle and shared handles.

    fn new(
        session_id: [u8; 32],
        payments: Arc<dyn RelayPayments>,
        session_registry: Arc<SessionRegistry>,
        payment_receiver_secret: SecretKey,
        spilman_mint_cache: SpilmanMintCache,
        default_in_bytes_per_millisat: u64,
        default_out_bytes_per_millisat: u64,
    ) -> Self {
        let (pause_tx, _) = watch::channel(true);
        let termination = CancellationToken::new();
        session_registry.register_session(session_id, termination.clone());
        Self {
            billing: Arc::new(Mutex::new(BillingState {
                state: ServerSessionState {
                    session_total_in: 0,
                    session_total_out: 0,
                    total_paid_millisats: 0,
                    paused: true,
                    linked_channel_id: None,
                    terminated: false,
                },
                pricing: SessionPricing::new(
                    default_in_bytes_per_millisat.max(1),
                    default_out_bytes_per_millisat.max(1),
                ),
            })),
            control: Arc::new(Mutex::new(ControlState::default())),
            counters: Arc::new(SessionCounters::default()),
            pause_tx,
            termination,
            session_id,
            payments,
            session_registry,
            payment_receiver_secret,
            spilman_mint_cache,
        }
    }

    pub(crate) fn session_id(&self) -> [u8; 32] {
        self.session_id
    }

    pub(crate) fn pause_receiver(&self) -> watch::Receiver<bool> {
        self.pause_tx.subscribe()
    }

    pub(crate) fn termination_token(&self) -> CancellationToken {
        self.termination.clone()
    }

    pub(crate) fn terminate(&self) {
        self.termination.cancel();
    }

    pub(crate) fn is_terminated(&self) -> bool {
        self.termination.is_cancelled()
    }

    // Billing state and status snapshots.

    async fn session_status_message(&self) -> ServerMessage {
        let billing = self.billing.lock().await;
        let (open_connects, total_connects) = self.counters.snapshot();

        let mut advertisements = Vec::new();
        for (mint_url, unit_map) in &self.spilman_mint_cache.advertised {
            for (unit, keyset_ids) in unit_map {
                advertisements.push(KeysetAdvertisement {
                    mint_url: mint_url.clone(),
                    unit: unit.clone(),
                    keyset_ids: keyset_ids.clone(),
                    // Use session defaults for now until we have per-advertisement config.
                    in_bytes_per_millisat: billing.pricing.in_bytes_per_millisat,
                    out_bytes_per_millisat: billing.pricing.out_bytes_per_millisat,
                });
            }
        }

        ServerMessage::SessionStatus {
            receiver_pubkey: self.payment_receiver_secret.public_key().to_hex(),
            advertisements,
            linked_channel: billing
                .state
                .linked_channel_id
                .as_deref()
                .and_then(|channel_id| self.payments.linked_channel_status(channel_id)),
            active_in_rate: billing.pricing.in_bytes_per_millisat,
            active_out_rate: billing.pricing.out_bytes_per_millisat,
            session_total_in: billing.state.session_total_in,
            session_total_out: billing.state.session_total_out,
            total_paid_millisats: billing.state.total_paid_millisats,
            remaining_milli_sats: clamp_i128_to_i64(billing.remaining_milli_sats()),
            paused: billing.state.paused,
            open_connects,
            total_connects,
        }
    }

    async fn is_paused(&self) -> bool {
        self.billing.lock().await.state.paused
    }

    async fn attach_control(&self, tx: mpsc::UnboundedSender<ServerMessage>) -> Result<(), ()> {
        let mut control = self.control.lock().await;
        control.attach(tx.clone())?;
        self.session_registry.register_control(self.session_id, tx);
        Ok(())
    }

    async fn detach_control(&self) {
        let mut control = self.control.lock().await;
        control.detach();
        self.session_registry.deregister_control(&self.session_id);
    }

    pub(crate) async fn note_outbound_bytes(&self, bytes: usize) -> bool {
        self.note_bytes(bytes, true).await
    }

    pub(crate) async fn note_inbound_bytes(&self, bytes: usize) -> bool {
        self.note_bytes(bytes, false).await
    }

    async fn note_bytes(&self, bytes: usize, outbound: bool) -> bool {
        let mut billing = self.billing.lock().await;
        let direction = if outbound {
            ByteDirection::Outbound
        } else {
            ByteDirection::Inbound
        };
        let (next_state, pause_changed) =
            apply_accounted_bytes(billing.state.clone(), billing.pricing, direction, bytes);
        billing.state = next_state;
        if let Some(paused) = pause_changed {
            let _ = self.pause_tx.send_replace(paused);
        }
        billing.state.paused
    }

    // Control-stream state.

    async fn push_message(&self, message: ServerMessage) {
        let tx = {
            let control = self.control.lock().await;
            control.sender()
        };

        if let Some(tx) = tx {
            let _ = tx.send(message);
        }
    }

    pub(crate) async fn push_status(&self) {
        let status = self.session_status_message().await;
        self.push_message(status).await;
    }

    // Observability counters.

    pub(crate) fn connect_opened(&self) -> (u32, u64) {
        self.counters.connect_opened()
    }

    pub(crate) fn connect_closed(&self) -> (u32, u64) {
        self.counters.connect_closed()
    }
}

/// An inbound relay session: an H2 server connection running over an
/// encrypted transport stream.
pub struct RelaySession<S: AsyncRead + AsyncWrite + Unpin + Send + 'static> {
    h2_conn: server::Connection<S, Bytes>,
    quic_pool: Option<QuicPool>,
    #[allow(dead_code)]
    session_id: [u8; 32],
    state: SessionState,
}

#[derive(Clone)]
pub struct RelaySessionConfig {
    pub payments: Arc<dyn RelayPayments>,
    pub session_registry: Arc<SessionRegistry>,
    pub payment_receiver_secret: SecretKey,
    pub spilman_mint_cache: SpilmanMintCache,
    pub default_in_bytes_per_millisat: u64,
    pub default_out_bytes_per_millisat: u64,
}

pub async fn relay_session_from_transport_stream<S>(
    stream: S,
    session_id: [u8; 32],
    quic_pool: Option<QuicPool>,
    config: RelaySessionConfig,
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
        state: SessionState::new(
            session_id,
            config.payments,
            config.session_registry,
            config.payment_receiver_secret,
            config.spilman_mint_cache,
            config.default_in_bytes_per_millisat,
            config.default_out_bytes_per_millisat,
        ),
    })
}

impl<S: AsyncRead + AsyncWrite + Unpin + Send + 'static> RelaySession<S> {
    /// Spawn a CONNECT tunnel once the upstream connection has been established.
    ///
    /// Sends the `200 OK` response, bumps the session connect counters, logs the
    /// tunnel opening, and spawns the proxied byte-pipe task.
    async fn spawn_tunnel<T>(
        &self,
        respond: &mut server::SendResponse<Bytes>,
        request: Request<RecvStream>,
        target: T,
        authority: &str,
        label: &str,
    ) -> Result<(), h2::Error>
    where
        T: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    {
        let resp = Response::builder().status(StatusCode::OK).body(()).unwrap();
        let h2_send = respond.send_response(resp, false)?;
        let (_, h2_recv) = request.into_parts();
        let state = self.state.clone();
        let session_id = self.session_id;
        let (open_connects, total_connects) = state.connect_opened();
        info!(
            "CONNECT opened: {authority} ({label}) | session_id={} open_connects={} total_connects={}",
            hex::encode(session_id),
            open_connects,
            total_connects
        );
        let authority = authority.to_string();
        let label = label.to_string();
        tokio::spawn(async move {
            if let Err(e) =
                proxy::proxy_bidirectional_accounted(h2_send, h2_recv, target, &label, state).await
            {
                error!("tunnel to {authority} ({label}) error: {e}");
            }
        });
        Ok(())
    }

    /// Run the accept loop: accept H2 streams and dispatch them to handlers.
    pub async fn run(mut self) -> io::Result<()> {
        let termination = self.state.termination_token();
        loop {
            let result = tokio::select! {
                _ = termination.cancelled() => break,
                result = self.h2_conn.accept() => result,
            };

            let Some(result) = result else {
                break;
            };

            match result {
                Ok((request, mut respond)) => {
                    if self.state.is_terminated() {
                        break;
                    }
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

                            let quic_secp256k1_pubkey_header = request
                                .headers()
                                .get(QUIC_SECP256K1_PUBKEY_HEADER)
                                .and_then(|v| v.to_str().ok())
                                .map(|s| s.to_string());
                            if let Some(pubkey_hex) = quic_secp256k1_pubkey_header {
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
                                        if let Err(e) = self
                                            .spawn_tunnel(
                                                &mut respond,
                                                request,
                                                quic_stream,
                                                &authority,
                                                &format!("quic:{authority}"),
                                            )
                                            .await
                                        {
                                            error!("h2 send response error: {e}");
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
                                        if let Err(e) = self
                                            .spawn_tunnel(
                                                &mut respond,
                                                request,
                                                tcp_stream,
                                                &authority,
                                                &authority,
                                            )
                                            .await
                                        {
                                            error!("h2 send response error: {e}");
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
                                            if is_expected_control_channel_error(&e) {
                                                debug!(
                                                    "control channel closed during teardown: {e}"
                                                );
                                            } else {
                                                error!("control channel error: {e}");
                                            }
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
                    if is_expected_peer_close_error(&e) {
                        debug!("h2 accept loop ended after peer close: {e}");
                    } else {
                        warn!("h2 accept error: {e}");
                    }
                    break;
                }
            }
        }

        self.state
            .session_registry
            .deregister_session(&self.session_id);
        info!("H2 connection closed");
        Ok(())
    }
}

fn is_expected_peer_close_error(error: &h2::Error) -> bool {
    let message = error.to_string();
    message.contains("connection lost")
        || message.contains("sending stopped by peer")
        || message.contains("broken pipe")
        || message.contains("connection closed")
}

fn is_expected_control_channel_error(error: &io::Error) -> bool {
    let message = error.to_string();
    message.contains("h2 send stream closed")
        || message.contains("h2 recv error: h2 send stream closed")
        || message.contains("h2 recv error: stream closed because of a broken pipe")
        || message.contains("broken pipe")
        || message.contains("connection closed")
        || message.contains("sending stopped by peer")
        || message.contains("error 0")
}

async fn send_control_message(
    h2_send: &mut h2::SendStream<Bytes>,
    message: &ServerMessage,
) -> io::Result<()> {
    send_json_line(h2_send, message).await
}

/// Handle a long-lived control stream for one paid relay session.
async fn handle_control_stream(
    mut h2_send: h2::SendStream<Bytes>,
    mut h2_recv: h2::RecvStream,
    state: SessionState,
    mut events: mpsc::UnboundedReceiver<ServerMessage>,
) -> io::Result<()> {
    info!("control channel opened");

    let mut buf = Vec::new();
    // Bootstrap stays outside the explicit steady-state session FSM. After the
    // pre-H2 Noise bootstrap selected the session protocol, we immediately send
    // the initial SessionStatus before entering the reducer-driven control loop.
    let initial_status = state.session_status_message().await;
    send_control_message(&mut h2_send, &initial_status).await?;

    let mut terminate_session = false;

    loop {
        tokio::select! {
            maybe_event = events.recv() => {
                match maybe_event {
                    Some(message) => {
                        if let ServerMessage::ChannelEvicted { channel_id } = message {
                            terminate_session = process_session_event(
                                &state,
                                SessionEvent::ChannelEvicted { channel_id },
                                &mut h2_send,
                            )
                            .await?;
                            if terminate_session {
                                break;
                            }
                        } else {
                            send_control_message(&mut h2_send, &message).await?;
                        }
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

                        loop {
                            let message = match try_decode_json_line::<ClientMessage>(&mut buf) {
                                Ok(Some(message)) => message,
                                Ok(None) => break,
                                Err(e) => {
                                    warn!("control: invalid message: {e}");
                                    let err_msg = ServerMessage::Error {
                                        code: ServerErrorCode::ControlInvalidMessage,
                                        message: format!("invalid message: {e}"),
                                    };
                                    send_control_message(&mut h2_send, &err_msg).await?;
                                    continue;
                                }
                            };

                            match message {
                                ClientMessage::GetSessionStatus => {
                                    terminate_session = process_session_event(
                                        &state,
                                        SessionEvent::ClientGetSessionStatus,
                                        &mut h2_send,
                                    )
                                    .await?;
                                }
                                ClientMessage::ChannelLink { payment_json } => {
                                    terminate_session = process_session_event(
                                        &state,
                                        SessionEvent::ClientChannelLink { payment_json },
                                        &mut h2_send,
                                    )
                                    .await?;
                                }
                                ClientMessage::ChannelPayment { payment_json } => {
                                    terminate_session = process_session_event(
                                        &state,
                                        SessionEvent::ClientChannelPayment { payment_json },
                                        &mut h2_send,
                                    )
                                    .await?;
                                }
                            }

                            if terminate_session {
                                break;
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

        if terminate_session {
            break;
        }
    }

    let _ = process_session_event(&state, SessionEvent::ControlDetached, &mut h2_send).await?;

    state.detach_control().await;
    let _ = h2_send.send_data(Bytes::new(), true);
    info!("control channel closed");
    Ok(())
}

async fn process_session_event(
    state: &SessionState,
    initial_event: SessionEvent,
    h2_send: &mut h2::SendStream<Bytes>,
) -> io::Result<bool> {
    // Run a small local event queue so effects like link/payment validation can
    // feed result-events back into the same reducer pass without holding the
    // session mutex during validation.
    let mut pending = VecDeque::from([initial_event]);
    let mut terminate = false;

    while let Some(event) = pending.pop_front() {
        let effects = {
            let mut billing = state.billing.lock().await;
            let (next_state, effects) = step(billing.state.clone(), event, billing.pricing);
            billing.state = next_state;
            effects
        };

        for effect in effects {
            match effect {
                SessionEffect::SendControl(message) => {
                    send_control_message(h2_send, &message).await?;
                }
                SessionEffect::SendStatus => {
                    let status = state.session_status_message().await;
                    send_control_message(h2_send, &status).await?;
                }
                SessionEffect::RunLinkValidation { payment_json } => {
                    pending.push_back(SessionEvent::LinkValidationFinished(
                        state.payments.link_channel(state.session_id, &payment_json),
                    ));
                }
                SessionEffect::RunPaymentValidation {
                    expected_channel_id,
                    payment_json,
                } => {
                    pending.push_back(SessionEvent::PaymentValidationFinished(
                        state
                            .payments
                            .apply_channel_payment(&expected_channel_id, &payment_json),
                    ));
                }
                SessionEffect::NotifySessionEvicted {
                    target_session_id,
                    channel_id,
                } => {
                    let _ = state.session_registry.notify(
                        &target_session_id,
                        ServerMessage::ChannelEvicted { channel_id },
                    );
                }
                SessionEffect::ReleaseLinkedChannelOwnership { channel_id } => {
                    state
                        .payments
                        .release_channel_ownership(state.session_id, &channel_id);
                }
                SessionEffect::UpdatePauseWatch(paused) => {
                    let _ = state.pause_tx.send_replace(paused);
                }
                SessionEffect::EndSession => {
                    state.terminate();
                    terminate = true;
                }
            }
        }
    }

    Ok(terminate)
}
