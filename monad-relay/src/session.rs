//! Per-client H2 session handler.
//!
//! After the Noise handshake, the relay runs an H2 server on the encrypted
//! stream. The session starts paused-by-default with zero balance. A long-lived
//! `POST /control` stream is used to fund and observe the whole session.

use crate::control_driver::ControlDriver;
use crate::keyset_refresh::RelayKeysetRefreshCoordinator;
use crate::listener::{SharedSpilmanMintCache, TrustedMintUnits};
use crate::payments::RelayPayments;
use crate::proxy;
use crate::quic_pool::QuicPool;
use crate::session_fsm::{
    refresh_pause_state, remaining_milli_sats, step, ByteDirection, ServerSessionState,
    SessionByteTotals, SessionEvent,
};
use crate::session_registry::SessionRegistry;
use bytes::Bytes;
use futures_util::{future::BoxFuture, stream::FuturesUnordered, StreamExt};
use h2::{server, RecvStream};
use http::{Method, Request, Response, StatusCode};
use monad_common::blinded_connect::{BlindedConnectRequest, BLINDED_HOP_CONNECT_AUTHORITY};
use monad_common::blinded_hop::resolve_blinded_hop_for_intro;
use monad_common::control_codec::{
    send_json_line, try_decode_json_line, CONTROL_INVALID_MESSAGE_TEXT,
};
use monad_common::network_endpoint::validate_network_endpoint;
use monad_common::protocol::{
    ChannelEvictionScope, ClientMessage, MintUnitAdvertisement, MintUnitAdvertisements,
    ServerErrorCode, ServerMessage,
};
use monad_common::secp_identity::{Secp256k1Pubkey, SecpTransportKeypair};
use monad_common::session::SessionPricing;
use monad_quic::client::ClientAuthMode;
use monad_quic::stream::{STREAM_KIND_SECP_NOISE, STREAM_KIND_TWEAKED_NOISE};
use std::collections::{BTreeSet, VecDeque};
use std::io;
use std::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, Ordering};
use std::sync::{Arc, Mutex as BillingMutex};
use std::task::Poll;
use tokio::io::AsyncWriteExt;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::TcpStream;
use tokio::sync::{mpsc, watch, Mutex};
use tokio_util::sync::CancellationToken;
use tracing::{debug, error, info, warn};

/// Custom header name for QUIC secp256k1 transport identity in CONNECT requests.
pub const QUIC_SECP256K1_PUBKEY_HEADER: &str = "quic-secp256k1-pubkey";

/// Authoritative per-session payment and pause state used by the relay reducer.
///
/// `state` is the canonical reducer state shared with `session_fsm`; `pricing`
/// is the immutable session pricing used to compute amount due and pause state.
#[derive(Debug)]
struct BillingState {
    state: ServerSessionState,
    pricing: SessionPricing,
}

impl BillingState {
    fn remaining_milli_sats(&self, bytes: SessionByteTotals) -> i128 {
        remaining_milli_sats(&self.state, self.pricing, bytes)
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
}

/// Lightweight observability counters that do not participate in billing.
#[derive(Debug, Default)]
struct SessionCounters {
    open_connects: AtomicU32,
    total_connects: AtomicU64,
    failed_connects: AtomicU64,
}

/// Actual cleartext bytes forwarded during this session. Keeping these hot
/// counters independent avoids serializing data streams just to record traffic.
#[derive(Debug, Default)]
struct SessionByteCounters {
    inbound: AtomicU64,
    outbound: AtomicU64,
}

impl SessionByteCounters {
    fn snapshot(&self) -> SessionByteTotals {
        SessionByteTotals {
            inbound: self.inbound.load(Ordering::Relaxed),
            outbound: self.outbound.load(Ordering::Relaxed),
        }
    }

    fn record(&self, direction: ByteDirection, bytes: u64) {
        let counter = match direction {
            ByteDirection::Inbound => &self.inbound,
            ByteDirection::Outbound => &self.outbound,
        };
        counter.fetch_add(bytes, Ordering::Relaxed);
    }
}

impl SessionCounters {
    fn snapshot(&self) -> (u32, u64, u64) {
        (
            self.open_connects.load(Ordering::Relaxed),
            self.total_connects.load(Ordering::Relaxed),
            self.failed_connects.load(Ordering::Relaxed),
        )
    }

    fn connect_acceptance_available(&self) -> bool {
        self.open_connects.load(Ordering::Relaxed) != u32::MAX
            && self.total_connects.load(Ordering::Relaxed) != u64::MAX
    }

    fn connect_opened(&self) -> Option<(u32, u64)> {
        let open_connects = self
            .open_connects
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |current| {
                current.checked_add(1)
            })
            .ok()
            .map(|previous| previous + 1)?;
        let total_connects = match self.total_connects.fetch_update(
            Ordering::Relaxed,
            Ordering::Relaxed,
            |current| current.checked_add(1),
        ) {
            Ok(previous) => previous + 1,
            Err(_) => {
                let _ = self.open_connects.fetch_update(
                    Ordering::Relaxed,
                    Ordering::Relaxed,
                    |current| current.checked_sub(1),
                );
                return None;
            }
        };
        Some((open_connects, total_connects))
    }

    fn connect_failed(&self) -> Option<u64> {
        self.failed_connects
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |current| {
                current.checked_add(1)
            })
            .ok()
            .map(|previous| previous + 1)
    }

    fn connect_closed(&self) -> Option<(u32, u64)> {
        let open_connects = self
            .open_connects
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |current| {
                current.checked_sub(1)
            })
            .ok()
            .map(|previous| previous - 1)?;
        let total_connects = self.total_connects.load(Ordering::Relaxed);
        Some((open_connects, total_connects))
    }
}

#[derive(Clone)]
pub(crate) struct SessionState {
    billing: Arc<BillingMutex<BillingState>>,
    bytes: Arc<SessionByteCounters>,
    control: Arc<Mutex<ControlState>>,
    counters: Arc<SessionCounters>,
    pause_tx: watch::Sender<bool>,
    termination: CancellationToken,
    session_id: [u8; 32],
    payments: Arc<dyn RelayPayments>,
    owned_channels: Arc<std::sync::Mutex<BTreeSet<String>>>,
    session_registry: Arc<SessionRegistry>,
    transport_key: SecpTransportKeypair,
    receiver_pubkey_hex: String,
    trusted_mint_units: TrustedMintUnits,
    keyset_refresh: Option<Arc<RelayKeysetRefreshCoordinator>>,
    cashu_spilman_protocol_version: Option<String>,
    cashu_spilman_keyset_versions: Option<BTreeSet<String>>,
}

/// Snapshot-only handles have no back-reference to the registry/session owner.
#[derive(Debug, Clone)]
pub(crate) struct SessionMonitor {
    billing: Arc<BillingMutex<BillingState>>,
    bytes: Arc<SessionByteCounters>,
    counters: Arc<SessionCounters>,
}

impl SessionMonitor {
    pub(crate) async fn snapshot(&self, id: [u8; 32]) -> serde_json::Value {
        let bytes = self.bytes.snapshot();
        let billing = self.billing.lock().unwrap();
        let (active, total, _) = self.counters.snapshot();
        serde_json::json!({
            "session_id": hex::encode(id), "inbound_bytes": bytes.inbound,
            "outbound_bytes": bytes.outbound,
            "total_paid_msats": billing.state.total_paid_millisats,
            "remaining_msats": billing.remaining_milli_sats(bytes).to_string(),
            "paused": billing.state.paused, "linked_channel_id": billing.state.linked_channel_id,
            "active_tunnels": active, "total_tunnels": total,
        })
    }
}

impl SessionState {
    // Lifecycle and shared handles.

    fn new(session_id: [u8; 32], config: &RelaySessionConfig) -> Self {
        let (pause_tx, _) = watch::channel(true);
        let termination = CancellationToken::new();
        config
            .session_registry
            .register_session(session_id, termination.clone());
        let state = Self {
            billing: Arc::new(BillingMutex::new(BillingState {
                state: ServerSessionState {
                    total_paid_millisats: 0,
                    paused: true,
                    linked_channel_id: None,
                    terminated: false,
                },
                pricing: SessionPricing::new(
                    config.in_bytes_per_millisat,
                    config.out_bytes_per_millisat,
                ),
            })),
            bytes: Arc::new(SessionByteCounters::default()),
            control: Arc::new(Mutex::new(ControlState::default())),
            counters: Arc::new(SessionCounters::default()),
            pause_tx,
            termination,
            session_id,
            payments: config.payments.clone(),
            owned_channels: Arc::new(std::sync::Mutex::new(BTreeSet::new())),
            session_registry: config.session_registry.clone(),
            transport_key: config.transport_key.clone(),
            receiver_pubkey_hex: config.receiver_pubkey_hex.clone(),
            trusted_mint_units: config.trusted_mint_units.clone(),
            keyset_refresh: config.keyset_refresh.clone(),
            cashu_spilman_protocol_version: config.cashu_spilman_protocol_version.clone(),
            cashu_spilman_keyset_versions: config.cashu_spilman_keyset_versions.clone(),
        };
        config.session_registry.monitor(
            session_id,
            SessionMonitor {
                billing: state.billing.clone(),
                bytes: state.bytes.clone(),
                counters: state.counters.clone(),
            },
        );
        state
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

    pub(crate) fn unlink_channel(&self, channel_id: &str) -> Result<(), String> {
        self.payments.unlink_channel(self.session_id, channel_id)?;
        self.owned_channels.lock().unwrap().remove(channel_id);
        self.session_registry.events.record(
            "channel_unlinked",
            serde_json::json!({"channel_id":channel_id,"session_id":hex::encode(self.session_id)}),
        );
        Ok(())
    }

    // Driver-facing accessors for payment / registry / pause side effects.

    pub(crate) fn link_channel(
        &self,
        payment_json: &str,
    ) -> Result<crate::payments::LinkOutcome, crate::payments::LinkError> {
        if self.cashu_spilman_protocol_version.is_none()
            || self.cashu_spilman_keyset_versions.is_none()
        {
            return Err(crate::payments::LinkError::UnsupportedCashuSpilmanProtocolVersion);
        }
        let outcome = self.session_registry.with_controls(|controls| {
            if !controls.enabled || self.is_terminated() {
                return Err(crate::payments::LinkError::AdmissionDisabled);
            }
            if !controls.accept_new_channels {
                #[derive(serde::Deserialize)]
                struct ChannelReference {
                    channel_id: String,
                }
                let reference: ChannelReference = serde_json::from_str(payment_json)
                    .map_err(|e| crate::payments::LinkError::InvalidPayment(e.to_string()))?;
                if self
                    .payments
                    .channel_state(&reference.channel_id)
                    .map_err(crate::payments::LinkError::Internal)?
                    .is_none()
                {
                    return Err(crate::payments::LinkError::AdmissionDisabled);
                }
            }
            self.payments.link_channel(
                self.cashu_spilman_keyset_versions
                    .as_ref()
                    .expect("checked above"),
                self.session_id,
                payment_json,
            )
        })?;
        // Record the side effect before another await can cancel the reducer.
        self.owned_channels
            .lock()
            .unwrap()
            .insert(outcome.channel_id.clone());
        self.session_registry
            .record_channel_link(&outcome.channel_id);
        Ok(outcome)
    }

    pub(crate) async fn link_channel_with_keyset_refresh(
        &self,
        payment_json: &str,
    ) -> Result<crate::payments::LinkOutcome, crate::payments::LinkError> {
        use crate::keyset_refresh::{KeysetRefreshError, KeysetRefreshOutcome};
        use crate::payments::LinkError;

        let (mint_url, unit) = match self.link_channel(payment_json) {
            Err(LinkError::UnknownTrustedKeyset { mint_url, unit }) => (mint_url, unit),
            result => return result,
        };
        let Some(coordinator) = &self.keyset_refresh else {
            return Err(LinkError::MintOrKeysetNotAcceptable);
        };

        info!(mint = %mint_url, unit = %unit, "refreshing unknown channel funding keyset");
        match coordinator.refresh_mint_unit(&mint_url, &unit).await {
            Ok(KeysetRefreshOutcome::Refreshed) => match self.link_channel(payment_json) {
                Err(LinkError::UnknownTrustedKeyset { .. }) => {
                    Err(LinkError::MintOrKeysetNotAcceptable)
                }
                result => result,
            },
            Ok(KeysetRefreshOutcome::SkippedCooldown) => Err(LinkError::KeysetRefreshRateLimited),
            Err(KeysetRefreshError::Busy) => Err(LinkError::KeysetRefreshBusy),
            Err(KeysetRefreshError::Timeout) => Err(LinkError::KeysetRefreshFailed(
                "refresh timed out".to_string(),
            )),
            Err(KeysetRefreshError::RefreshFailed(message)) => {
                Err(LinkError::KeysetRefreshFailed(message))
            }
            Err(
                KeysetRefreshError::TargetTooLarge
                | KeysetRefreshError::UntrustedMint
                | KeysetRefreshError::UntrustedUnit,
            ) => Err(LinkError::MintOrKeysetNotAcceptable),
        }
    }

    pub(crate) async fn apply_channel_payment(
        &self,
        expected_channel_id: &str,
        payment_json: &str,
    ) -> Result<crate::payments::PaymentOutcome, crate::payments::ChannelPaymentError> {
        // Sample traffic before payment state so concurrent forwarding can only
        // make this headroom check more conservative for the client.
        let bytes = self.bytes.snapshot();
        let max_delta_millisats = {
            let billing = self.billing.lock().unwrap();
            let remaining = billing.remaining_milli_sats(bytes);
            if i64::try_from(remaining).is_err() {
                return Err(crate::payments::ChannelPaymentError::NumericLimitExceeded);
            }
            // Both wire fields must fit *before* the channel balance is stored.
            // Concurrent data accounting only decreases remaining credit, so
            // using this snapshot is conservative for the payment increment.
            let wire_headroom = (i64::MAX as i128 - remaining) as u64;
            (u64::MAX - billing.state.total_paid_millisats).min(wire_headroom)
        };
        let result = self.payments.apply_channel_payment_with_limit(
            self.session_id,
            expected_channel_id,
            payment_json,
            max_delta_millisats,
        )?;
        self.session_registry.events.record(
            "payment_accepted",
            serde_json::json!({
                "session_id": hex::encode(self.session_id), "channel_id": result.channel_id,
                "delta_msats": result.delta_millisats,
            }),
        );
        Ok(result)
    }

    pub(crate) fn notify_session_evicted(&self, target_session_id: &[u8; 32], channel_id: String) {
        let _ = self.session_registry.notify(
            target_session_id,
            ServerMessage::ChannelEvicted {
                channel_id,
                scope: ChannelEvictionScope::Session,
            },
        );
    }

    pub(crate) fn release_channel_ownership(&self, channel_id: &str) {
        self.payments
            .release_channel_ownership(self.session_id, channel_id);
        self.owned_channels.lock().unwrap().remove(channel_id);
    }

    fn cleanup(&self) {
        self.terminate();
        for channel_id in std::mem::take(&mut *self.owned_channels.lock().unwrap()) {
            self.payments
                .release_channel_ownership(self.session_id, &channel_id);
        }
        self.session_registry.deregister_session(&self.session_id);
    }

    pub(crate) fn update_pause_watch(&self, paused: bool) {
        let billing = self.billing.lock().unwrap();
        if billing.state.paused == paused {
            let _ = self.pause_tx.send_replace(paused);
        }
    }

    // Billing state and status snapshots.

    pub(crate) async fn session_status_message(&self) -> Option<ServerMessage> {
        let mut advertisements = MintUnitAdvertisements::new();
        for (mint_url, trusted_units) in &self.trusted_mint_units {
            for unit in trusted_units {
                advertisements.entry(mint_url.clone()).or_default().insert(
                    unit.clone(),
                    MintUnitAdvertisement {
                        minimum_channel_lifetime_secs: self
                            .payments
                            .minimum_channel_lifetime_secs(),
                        funding_keyset_recovery_window_secs: self
                            .payments
                            .funding_keyset_recovery_window_secs(),
                    },
                );
            }
        }

        // Control requests are serialized, so linkage cannot change while this
        // status is being prepared. Do not hold billing across storage access.
        let linked_channel_id = self.billing.lock().unwrap().state.linked_channel_id.clone();
        let linked_channel = linked_channel_id
            .as_deref()
            .and_then(|channel_id| self.payments.linked_channel_status(channel_id));
        let (open_connects, total_connects, failed_connects) = self.counters.snapshot();

        // Read hot traffic counters immediately before the payment snapshot.
        // Concurrent traffic after this point is reflected in a later status.
        let bytes = self.bytes.snapshot();
        let billing = self.billing.lock().unwrap();
        let Some(remaining_milli_sats) = monad_common::billing::remaining_milli_sats_to_wire(
            billing.remaining_milli_sats(bytes),
        ) else {
            drop(billing);
            self.terminate();
            return None;
        };

        Some(ServerMessage::SessionStatus {
            receiver_pubkey: self.receiver_pubkey_hex.clone(),
            advertisements,
            linked_channel,
            active_in_rate: billing.pricing.in_bytes_per_millisat,
            active_out_rate: billing.pricing.out_bytes_per_millisat,
            session_total_bytes_in: bytes.inbound,
            session_total_bytes_out: bytes.outbound,
            total_paid_millisats: billing.state.total_paid_millisats,
            remaining_milli_sats,
            paused: remaining_milli_sats <= 0,
            open_connects,
            total_connects,
            failed_connects,
        })
    }

    async fn is_paused(&self) -> bool {
        let billing = self.billing.lock().unwrap();
        billing.state.paused || billing.state.terminated
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

    /// Perform one nonblocking transport operation, then record its actual byte
    /// count and refresh pause state in the same poll. Cancellation/drop cannot
    /// interpose after a successful write. An already-started bounded chunk may
    /// take credit negative.
    pub(crate) fn poll_accounted_forward(
        &self,
        direction: ByteDirection,
        maximum_bytes: usize,
        forward: impl FnOnce() -> Poll<io::Result<usize>>,
    ) -> Poll<io::Result<(usize, bool)>> {
        let actual_bytes = match forward() {
            Poll::Pending => return Poll::Pending,
            Poll::Ready(Err(error)) => return Poll::Ready(Err(error)),
            Poll::Ready(Ok(actual)) if actual <= maximum_bytes => actual,
            Poll::Ready(Ok(_)) => {
                self.terminate();
                return Poll::Ready(Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "transport reported more bytes than offered",
                )));
            }
        };
        let Ok(actual_bytes_u64) = u64::try_from(actual_bytes) else {
            self.terminate();
            return Poll::Ready(Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "forwarded byte count is not representable",
            )));
        };
        self.bytes.record(direction, actual_bytes_u64);

        let bytes = self.bytes.snapshot();
        let mut billing = self.billing.lock().unwrap();
        let pricing = billing.pricing;
        let pause_changed = refresh_pause_state(&mut billing.state, pricing, bytes);
        if let Some(paused) = pause_changed {
            let _ = self.pause_tx.send_replace(paused);
        }
        Poll::Ready(Ok((actual_bytes, pause_changed.is_some())))
    }

    // Control-stream state.

    // Observability counters.

    fn connect_acceptance_available(&self) -> bool {
        self.counters.connect_acceptance_available()
    }

    pub(crate) fn connect_opened(&self) -> Option<(u32, u64)> {
        self.counters.connect_opened()
    }

    fn connect_failed(&self) -> Option<u64> {
        self.counters.connect_failed()
    }

    pub(crate) fn connect_closed(&self) -> Option<(u32, u64)> {
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

impl<S: AsyncRead + AsyncWrite + Unpin + Send + 'static> Drop for RelaySession<S> {
    fn drop(&mut self) {
        // run() owns child futures, not detached tasks. Its locals have already
        // dropped before self, so no child can re-acquire authority after cleanup.
        self.state.cleanup();
    }
}

struct ConnectHandler {
    state: SessionState,
    quic_pool: Option<QuicPool>,
    accepted: AtomicBool,
}

impl Drop for ConnectHandler {
    fn drop(&mut self) {
        if !self.accepted.load(Ordering::Relaxed) && self.state.connect_failed().is_none() {
            self.state.terminate();
        }
    }
}

const CONNECT_SETUP_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(10);
const CONTROL_INVALID_MESSAGE_SEND_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(2);

#[derive(Clone)]
pub struct RelaySessionConfig {
    pub payments: Arc<dyn RelayPayments>,
    pub session_registry: Arc<SessionRegistry>,
    pub transport_key: SecpTransportKeypair,
    pub receiver_pubkey_hex: String,
    pub spilman_mint_cache: SharedSpilmanMintCache,
    pub trusted_mint_units: TrustedMintUnits,
    pub keyset_refresh: Option<Arc<RelayKeysetRefreshCoordinator>>,
    pub cashu_spilman_protocol_version: Option<String>,
    pub cashu_spilman_keyset_versions: Option<BTreeSet<String>>,
    pub in_bytes_per_millisat: u64,
    pub out_bytes_per_millisat: u64,
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
    // Return connection-level receive capacity as soon as DATA frames are
    // buffered, while stream-level capacity stays reserved until the proxy
    // task consumes them. Paused CONNECT tunnels can fill their own stream
    // windows without starving the control stream that carries payments.
    let h2_conn = server::Builder::new()
        .recv_release_connection_on_buffer(true)
        .handshake(stream)
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
        state: SessionState::new(session_id, &config),
    })
}

impl ConnectHandler {
    async fn handle_connect(
        self,
        request: Request<RecvStream>,
        mut respond: server::SendResponse<Bytes>,
    ) {
        let controls = self.state.session_registry.controls();
        if let Some(code) = controls.tunnel_rejection() {
            let resp = Response::builder()
                .status(code.connect_status().unwrap())
                .header(
                    monad_common::rejection::CONNECT_REJECTION_HEADER,
                    code.header_value(),
                )
                .body(())
                .unwrap();
            let _ = respond.send_response(resp, true);
            return;
        }
        if self.state.is_paused().await {
            let resp = Response::builder()
                .status(StatusCode::PAYMENT_REQUIRED)
                .body(())
                .unwrap();
            let _ = respond.send_response(resp, true);
            return;
        }
        if !self.state.connect_acceptance_available() {
            let resp = Response::builder()
                .status(StatusCode::SERVICE_UNAVAILABLE)
                .body(())
                .unwrap();
            let _ = respond.send_response(resp, true);
            return;
        }
        let authority = request
            .uri()
            .authority()
            .map(|a| a.to_string())
            .unwrap_or_else(|| request.uri().to_string());
        if authority == BLINDED_HOP_CONNECT_AUTHORITY {
            self.handle_blinded_connect(&mut respond, request).await;
            return;
        }
        if let Err(e) = validate_network_endpoint(&authority) {
            warn!("invalid CONNECT endpoint {authority:?}: {e}");
            let resp = Response::builder()
                .status(StatusCode::BAD_REQUEST)
                .body(())
                .unwrap();
            let _ = respond.send_response(resp, true);
            return;
        }
        let quic_pubkey = request
            .headers()
            .get(QUIC_SECP256K1_PUBKEY_HEADER)
            .and_then(|v| v.to_str().ok())
            .map(Secp256k1Pubkey::from_hex);
        if let Some(pubkey) = quic_pubkey {
            let pubkey = match pubkey {
                Ok(pubkey) => pubkey,
                Err(e) => {
                    warn!("invalid secp256k1 public key in quic-secp256k1-pubkey header: {e}");
                    let resp = Response::builder()
                        .status(StatusCode::BAD_REQUEST)
                        .body(())
                        .unwrap();
                    let _ = respond.send_response(resp, true);
                    return;
                }
            };
            let Some(pool) = &self.quic_pool else {
                warn!("CONNECT with quic-secp256k1-pubkey but QUIC pool is not available");
                let resp = Response::builder()
                    .status(StatusCode::BAD_GATEWAY)
                    .body(())
                    .unwrap();
                let _ = respond.send_response(resp, true);
                return;
            };
            info!("CONNECT {authority} (via QUIC secp256k1 auth)");
            let target = tokio::time::timeout(
                CONNECT_SETUP_TIMEOUT,
                pool.open_stream_with_kind(
                    &authority,
                    ClientAuthMode::Secp256k1(pubkey),
                    STREAM_KIND_SECP_NOISE,
                ),
            )
            .await
            .unwrap_or_else(|_| {
                Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    "CONNECT setup timed out",
                ))
            });
            match target {
                Ok(stream) => {
                    if let Err(e) = self
                        .proxy_tunnel(
                            &mut respond,
                            request,
                            stream,
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
            let target =
                tokio::time::timeout(CONNECT_SETUP_TIMEOUT, TcpStream::connect(&authority))
                    .await
                    .unwrap_or_else(|_| {
                        Err(io::Error::new(
                            io::ErrorKind::TimedOut,
                            "CONNECT setup timed out",
                        ))
                    });
            match target {
                Ok(stream) => {
                    if let Err(e) = self
                        .proxy_tunnel(&mut respond, request, stream, &authority, &authority)
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

    /// Run a CONNECT tunnel once the upstream connection has been established.
    ///
    /// Sends the `200 OK` response, bumps the session connect counters, logs the
    /// tunnel opening, and drives the byte pipe in the session-owned future.
    async fn proxy_tunnel<T>(
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
        let paused = self.state.is_paused().await;
        if self.state.is_terminated() {
            respond.send_reset(h2::Reason::CANCEL);
            return Ok(());
        }
        if paused {
            let resp = Response::builder()
                .status(StatusCode::PAYMENT_REQUIRED)
                .body(())
                .unwrap();
            respond.send_response(resp, true)?;
            return Ok(());
        }
        let h2_send = self.state.session_registry.with_controls(|controls| {
            if let Some(code) = controls.tunnel_rejection() {
                let resp = Response::builder()
                    .status(code.connect_status().unwrap())
                    .header(
                        monad_common::rejection::CONNECT_REJECTION_HEADER,
                        code.header_value(),
                    )
                    .body(())
                    .unwrap();
                respond.send_response(resp, true)?;
                return Ok::<_, h2::Error>(None);
            }
            if self.state.is_terminated() {
                respond.send_reset(h2::Reason::CANCEL);
                return Ok(None);
            }
            if !self.state.connect_acceptance_available() {
                let resp = Response::builder()
                    .status(StatusCode::SERVICE_UNAVAILABLE)
                    .body(())
                    .unwrap();
                respond.send_response(resp, true)?;
                return Ok(None);
            }
            let resp = Response::builder().status(StatusCode::OK).body(()).unwrap();
            respond.send_response(resp, false).map(Some)
        })?;
        let Some(h2_send) = h2_send else {
            return Ok(());
        };
        let (_, h2_recv) = request.into_parts();
        let state = self.state.clone();
        let session_id = self.state.session_id;
        self.accepted.store(true, Ordering::Relaxed);
        let Some((open_connects, total_connects)) = state.connect_opened() else {
            state.terminate();
            return Ok(());
        };
        info!(
            "CONNECT opened: {authority} ({label}) | session_id={} open_connects={} total_connects={}",
            hex::encode(session_id),
            open_connects,
            total_connects
        );
        let authority = authority.to_string();
        let label = label.to_string();
        if let Err(e) =
            proxy::proxy_bidirectional_accounted(h2_send, h2_recv, target, &label, state).await
        {
            error!("tunnel to {authority} ({label}) error: {e}");
        }
        Ok(())
    }

    async fn handle_blinded_connect(
        &self,
        respond: &mut server::SendResponse<Bytes>,
        request: Request<RecvStream>,
    ) {
        let connect_request = match BlindedConnectRequest::from_headers(request.headers()) {
            Ok(request) => request,
            Err(e) => {
                warn!("invalid blinded CONNECT request headers: {e}");
                let resp = Response::builder()
                    .status(StatusCode::BAD_REQUEST)
                    .body(())
                    .unwrap();
                let _ = respond.send_response(resp, true);
                return;
            }
        };
        let descriptor = connect_request.into_descriptor();
        let resolved = match resolve_blinded_hop_for_intro(&self.state.transport_key, &descriptor) {
            Ok(resolved) => resolved,
            Err(e) => {
                warn!("failed to resolve blinded CONNECT descriptor: {e}");
                let resp = Response::builder()
                    .status(StatusCode::BAD_REQUEST)
                    .body(())
                    .unwrap();
                let _ = respond.send_response(resp, true);
                return;
            }
        };

        if let Err(e) = validate_network_endpoint(&resolved.next_hop_addr) {
            warn!(
                "invalid decrypted blinded next-hop endpoint {}: {e}",
                resolved.next_hop_addr
            );
            let resp = Response::builder()
                .status(StatusCode::BAD_REQUEST)
                .body(())
                .unwrap();
            let _ = respond.send_response(resp, true);
            return;
        }

        let pool = match &self.quic_pool {
            Some(p) => p.clone(),
            None => {
                warn!("blinded CONNECT requested but QUIC pool is not available");
                let resp = Response::builder()
                    .status(StatusCode::BAD_GATEWAY)
                    .body(())
                    .unwrap();
                let _ = respond.send_response(resp, true);
                return;
            }
        };

        info!(
            "CONNECT {} (via blinded QUIC secp256k1 auth)",
            resolved.next_hop_addr
        );

        let setup = async {
            let mut stream = pool
                .open_stream_with_kind(
                    &resolved.next_hop_addr,
                    ClientAuthMode::Secp256k1(resolved.next_hop_real_pubkey),
                    STREAM_KIND_TWEAKED_NOISE,
                )
                .await?;
            stream.write_all(&resolved.tweak).await?;
            stream.flush().await?;
            Ok::<_, io::Error>(stream)
        };
        match tokio::time::timeout(CONNECT_SETUP_TIMEOUT, setup)
            .await
            .unwrap_or_else(|_| {
                Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    "CONNECT setup timed out",
                ))
            }) {
            Ok(quic_stream) => {
                if let Err(e) = self
                    .proxy_tunnel(
                        respond,
                        request,
                        quic_stream,
                        &resolved.next_hop_addr,
                        &format!("quic-blinded:{}", resolved.next_hop_addr),
                    )
                    .await
                {
                    error!("h2 send response error: {e}");
                }
            }
            Err(e) => {
                warn!(
                    "failed to connect via blinded QUIC to {}: {e}",
                    resolved.next_hop_addr
                );
                let resp = Response::builder()
                    .status(StatusCode::BAD_GATEWAY)
                    .body(())
                    .unwrap();
                let _ = respond.send_response(resp, true);
            }
        }
    }
}

impl<S: AsyncRead + AsyncWrite + Unpin + Send + 'static> RelaySession<S> {
    /// Run the accept loop and all control, setup, and data futures together.
    pub async fn run(mut self) -> io::Result<()> {
        let termination = self.state.termination_token();
        let mut children: FuturesUnordered<BoxFuture<'static, ()>> = FuturesUnordered::new();
        loop {
            let result = tokio::select! {
                biased;
                _ = termination.cancelled() => break,
                Some(()) = children.next(), if !children.is_empty() => continue,
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
                            let handler = ConnectHandler {
                                state: self.state.clone(),
                                quic_pool: self.quic_pool.clone(),
                                accepted: AtomicBool::new(false),
                            };
                            children.push(Box::pin(handler.handle_connect(request, respond)));
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
                                    children.push(Box::pin(async move {
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
                                    }));
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

        // Drop every child synchronously before releasing session authority.
        // No join is necessary: none of these futures runs in another task.
        drop(children);
        let terminated = self.state.billing.lock().unwrap().state.terminated;
        if terminated {
            // Flush queued control errors without letting a peer delay teardown indefinitely.
            self.h2_conn.graceful_shutdown();
            let _ = tokio::time::timeout(
                std::time::Duration::from_millis(250),
                std::future::poll_fn(|cx| self.h2_conn.poll_closed(cx)),
            )
            .await;
        }
        self.state.cleanup();
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

pub(crate) async fn send_control_message(
    h2_send: &mut h2::SendStream<Bytes>,
    message: &ServerMessage,
) -> io::Result<()> {
    send_json_line(h2_send, message).await
}

/// Handle a long-lived control stream for one paid relay session.
struct InboundControlRequest {
    message: ClientMessage,
    // Held through validation, snapshot construction, and response submission.
    slot: Option<tokio::sync::OwnedSemaphorePermit>,
}

async fn read_control_requests(
    mut recv: h2::RecvStream,
    requests: mpsc::Sender<InboundControlRequest>,
) -> io::Result<()> {
    let slots = Arc::new(tokio::sync::Semaphore::new(
        monad_common::control_exchange::MAX_PENDING_REQUESTS,
    ));
    let mut buf = Vec::new();
    while let Some(data) = recv.data().await {
        let data = data.map_err(|_| io::Error::other("control receive failure"))?;
        recv.flow_control()
            .release_capacity(data.len())
            .map_err(io::Error::other)?;
        buf.extend_from_slice(&data);
        while let Some(message) = try_decode_json_line::<ClientMessage>(&mut buf)? {
            let slot = if matches!(
                message,
                ClientMessage::Ping { .. } | ClientMessage::ExtensionNotification(_)
            ) {
                None
            } else {
                Some(
                    slots
                        .clone()
                        .acquire_owned()
                        .await
                        .map_err(io::Error::other)?,
                )
            };
            requests
                .send(InboundControlRequest { message, slot })
                .await
                .map_err(|_| io::Error::other("control executor closed"))?;
        }
    }
    // An unterminated final line is never executed.
    Ok(())
}

async fn handle_control_stream(
    mut h2_send: h2::SendStream<Bytes>,
    h2_recv: h2::RecvStream,
    state: SessionState,
    mut events: mpsc::UnboundedReceiver<ServerMessage>,
) -> io::Result<()> {
    info!("control channel opened");
    let termination = state.termination_token();
    // Five ordinary requests including the active operation. Probes use no
    // ordinary slot; the separate envelope bound backpressures probe floods.
    let (request_tx, mut requests) = mpsc::channel(16);
    let reader = read_control_requests(h2_recv, request_tx);

    let result = async {
        // Bootstrap stays outside the explicit steady-state session FSM. After the
        // pre-H2 Noise bootstrap selected the session protocol, we immediately send
        // the initial SessionStatus before entering the reducer-driven control loop.
        let Some(initial_status) = state.session_status_message().await else {
            state.terminate();
            return Ok(());
        };
        send_control_message(&mut h2_send, &initial_status).await?;

        let mut terminate_session = false;

        loop {
            tokio::select! {
                maybe_event = events.recv() => {
                    match maybe_event {
                        Some(message) => {
                            if let ServerMessage::ChannelEvicted { channel_id, scope } = message {
                                terminate_session = process_session_event(
                                    &state,
                                    SessionEvent::ChannelEvicted { channel_id, scope },
                                    &mut h2_send,
                                )
                                .await?;
                                if terminate_session {
                                    break;
                                }
                            } else if matches!(message, ServerMessage::ChannelReleaseRequested { .. }) {
                                send_control_message(&mut h2_send, &message).await?;
                            }
                        }
                        None => break,
                    }
                }
                request = requests.recv() => {
                    match request {
                        Some(InboundControlRequest { message, slot }) => {
                                match message {
                                    ClientMessage::ChannelUnlink { channel_id } => {
                                        terminate_session = process_session_event(&state, SessionEvent::ClientChannelUnlink {channel_id}, &mut h2_send).await?;
                                    }
                                    ClientMessage::GetSessionStatus => {
                                        terminate_session = process_session_event(
                                            &state,
                                            SessionEvent::ClientGetSessionStatus,
                                            &mut h2_send,
                                        )
                                        .await?;
                                    }
                                    ClientMessage::Ping { nonce } => {
                                        terminate_session = process_session_event(
                                            &state,
                                            SessionEvent::ClientPing { nonce },
                                            &mut h2_send,
                                        )
                                        .await?;
                                    }
                                    ClientMessage::ExtensionNotification(_) => {
                                        // Optional hints must not elicit responses,
                                        // consume an ordinary permit, or mutate state.
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

                                drop(slot);
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

        Ok(())
    };
    let result = {
        tokio::pin!(reader, result);
        tokio::select! {
            biased;
            _ = termination.cancelled() => Ok(()),
            ingress = &mut reader => match ingress {
                Ok(()) => tokio::select! {
                    _ = termination.cancelled() => Ok(()),
                    result = &mut result => result,
                },
                Err(error) => Err(error),
            },
            result = &mut result => result,
        }
    };
    if result
        .as_ref()
        .is_err_and(|error| error.kind() == io::ErrorKind::InvalidData)
    {
        let error = ServerMessage::Error {
            code: ServerErrorCode::ControlInvalidMessage,
            message: CONTROL_INVALID_MESSAGE_TEXT.into(),
        };
        let _ = tokio::time::timeout(
            CONTROL_INVALID_MESSAGE_SEND_TIMEOUT,
            send_control_message(&mut h2_send, &error),
        )
        .await;
    }

    // Cleanup must run even when a control write or reducer effect fails.
    let _ = process_session_event(&state, SessionEvent::ControlDetached, &mut h2_send).await;
    state.detach_control().await;
    let _ = h2_send.send_data(Bytes::new(), true);
    info!("control channel closed");
    result
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
    let mut driver = ControlDriver::new(state, h2_send);

    while let Some(event) = pending.pop_front() {
        // Traffic is sampled before payment state so concurrent forwarding is
        // allowed to make a payment's pause decision temporarily generous.
        let bytes = state.bytes.snapshot();
        let effects = {
            let mut billing = state.billing.lock().unwrap();
            let (next_state, effects) = step(billing.state.clone(), event, billing.pricing, bytes);
            billing.state = next_state;
            effects
        };

        for effect in effects {
            if driver.interpret(effect, &mut pending).await? {
                terminate = true;
            }
        }
    }

    Ok(terminate)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::listener::{shared_spilman_mint_cache, SpilmanMintCache};
    use crate::payments::{testing::InMemoryRelayPayments, LinkError};
    use monad_common::bootstrap::{
        supported_cashu_spilman_keyset_versions, CASHU_SPILMAN_PROTOCOL_VERSION_2026_09_14,
    };
    use std::collections::BTreeMap;

    fn test_state() -> (SessionState, Arc<InMemoryRelayPayments>) {
        test_state_with_cache(shared_spilman_mint_cache(SpilmanMintCache::default()))
    }

    fn test_state_with_cache(
        cache: SharedSpilmanMintCache,
    ) -> (SessionState, Arc<InMemoryRelayPayments>) {
        let payments = Arc::new(InMemoryRelayPayments::new());
        let state = SessionState::new(
            [1; 32],
            &RelaySessionConfig {
                payments: payments.clone(),
                session_registry: Arc::new(SessionRegistry::default()),
                transport_key: SecpTransportKeypair::generate(),
                receiver_pubkey_hex: "receiver".to_string(),
                spilman_mint_cache: cache,
                trusted_mint_units: BTreeMap::from([(
                    "mint".to_string(),
                    BTreeSet::from(["sat".to_string()]),
                )]),
                keyset_refresh: None,
                cashu_spilman_protocol_version: Some(
                    CASHU_SPILMAN_PROTOCOL_VERSION_2026_09_14.to_string(),
                ),
                cashu_spilman_keyset_versions: Some(BTreeSet::from(["v1".to_string()])),
                in_bytes_per_millisat: 1,
                out_bytes_per_millisat: 1,
            },
        );
        (state, payments)
    }

    #[tokio::test]
    async fn abort_session_releases_registry_channel_and_paused_target() {
        use tokio::io::AsyncReadExt;
        use tokio::time::{timeout, Duration};

        for finish in ["abort", "panic", "transport loss", "terminate"] {
            let (state, payments) = test_state();
            let link = state
                .link_channel(
                    r#"{"channel_id":"abort-owned","balance":0,"capacity":100,"unit":"msat"}"#,
                )
                .unwrap();
            state.billing.lock().unwrap().state.linked_channel_id = Some(link.channel_id);
            state.billing.lock().unwrap().state.paused = false;
            state.update_pause_watch(false);
            let target = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let (client_io, server_io) = tokio::io::duplex(4096);
            let (mut client, client_conn) = h2::client::handshake(client_io).await.unwrap();
            let client_driver = tokio::spawn(client_conn);
            let server = h2::server::handshake(server_io).await.unwrap();
            let session = RelaySession {
                h2_conn: server,
                quic_pool: None,
                session_id: state.session_id,
                state: state.clone(),
            };
            let (panic_tx, panic_rx) = tokio::sync::oneshot::channel::<()>();
            let task = tokio::spawn(async move {
                tokio::select! {
                    result = session.run() => result,
                    _ = panic_rx => panic!("gated session owner panic"),
                }
            });
            let request = Request::builder()
                .method(Method::CONNECT)
                .uri(target.local_addr().unwrap().to_string())
                .body(())
                .unwrap();
            let (response, _send) = client.send_request(request, false).unwrap();
            let response = timeout(Duration::from_secs(2), response)
                .await
                .unwrap()
                .unwrap();
            assert_eq!(response.status(), StatusCode::OK);
            let (mut target, _) = target.accept().await.unwrap();
            state.billing.lock().unwrap().state.paused = true;
            state.update_pause_watch(true);
            match finish {
                "abort" => task.abort(),
                "panic" => {
                    panic_tx.send(()).unwrap();
                }
                "transport loss" => client_driver.abort(),
                "terminate" => state.terminate(),
                _ => unreachable!(),
            }
            let result = timeout(Duration::from_secs(2), task).await.unwrap();
            match finish {
                "abort" => assert!(result.unwrap_err().is_cancelled()),
                "panic" => assert!(result.unwrap_err().is_panic()),
                _ => result.unwrap().unwrap(),
            }
            assert!(
                !state.session_registry.terminate(&state.session_id),
                "aborted session is still registered"
            );
            assert_eq!(payments.owner_of("abort-owned"), None);
            assert_eq!(state.counters.snapshot(), (0, 1, 0));
            let mut byte = [0];
            assert_eq!(
                timeout(Duration::from_secs(2), target.read(&mut byte))
                    .await
                    .unwrap()
                    .unwrap(),
                0
            );
            client_driver.abort();
            let _ = client_driver.await;
        }
    }

    #[test]
    fn connect_counters_reject_overflow_without_wrapping() {
        let (state, _) = test_state();
        state
            .counters
            .open_connects
            .store(u32::MAX, Ordering::Relaxed);
        assert!(!state.connect_acceptance_available());
        assert_eq!(state.connect_opened(), None);
        assert_eq!(
            state.counters.open_connects.load(Ordering::Relaxed),
            u32::MAX
        );

        state.counters.open_connects.store(0, Ordering::Relaxed);
        state
            .counters
            .total_connects
            .store(u64::MAX, Ordering::Relaxed);
        assert!(!state.connect_acceptance_available());
        assert_eq!(state.connect_opened(), None);
        assert_eq!(state.counters.open_connects.load(Ordering::Relaxed), 0);
        assert_eq!(
            state.counters.total_connects.load(Ordering::Relaxed),
            u64::MAX
        );

        state
            .counters
            .failed_connects
            .store(u64::MAX, Ordering::Relaxed);
        assert_eq!(state.connect_failed(), None);

        state.counters.open_connects.store(1, Ordering::Relaxed);
        assert_eq!(state.connect_closed(), Some((0, u64::MAX)));
        assert_eq!(state.connect_closed(), None);
    }

    #[test]
    fn sqlite_new_channel_gate_distinguishes_unknown_and_lookup_failure() {
        use cdk_spilman::configurable_host::{SpilmanStorage, SqliteStorage};
        let db = tempfile::NamedTempFile::new().unwrap();
        let path = db.path().to_str().unwrap();
        let storage = Arc::new(SqliteStorage::open(path).unwrap());
        let (mut state, _) = test_state();
        state.payments = Arc::new(
            crate::payments::SpilmanRelayPayments::from_store_with_snapshot(
                cashu::nuts::SecretKey::generate(),
                SpilmanMintCache::default(),
                BTreeMap::new(),
                Default::default(),
                crate::channel_store::ChannelStore::new(storage.clone()),
            ),
        );
        state
            .session_registry
            .set_controls(crate::session_registry::RelayControls {
                accept_new_channels: false,
                ..Default::default()
            })
            .unwrap();
        let link = r#"{"channel_id":"channel","balance":0,"capacity":100,"unit":"msat"}"#;
        assert_eq!(state.link_channel(link), Err(LinkError::AdmissionDisabled));
        assert_eq!(state.payments.channel_state("channel").unwrap(), None);

        storage
            .save_funding(
                "channel",
                cdk_spilman::ChannelFunding {
                    params_json: "{}".to_string(),
                    funding_proofs_json: "[]".to_string(),
                    channel_secret_hex: String::new(),
                    keyset_info_json: "{}".to_string(),
                },
            )
            .unwrap();
        let conn = rusqlite::Connection::open(path).unwrap();
        conn.execute(
            "UPDATE spilman_channels SET state='invalid' WHERE channel_id='channel'",
            [],
        )
        .unwrap();
        assert!(matches!(
            state.link_channel(link),
            Err(LinkError::Internal(_))
        ));
        assert!(storage.get_funding("channel").is_some());
        conn.execute("DROP TABLE spilman_channels", []).unwrap();
        assert!(matches!(
            state.link_channel(link),
            Err(LinkError::Internal(_))
        ));
    }

    #[test]
    fn new_channel_gate_preserves_relinks_and_payments() {
        let (state, payments) = test_state();
        let existing = r#"{"channel_id":"existing","balance":0,"capacity":100,"unit":"msat"}"#;
        state.link_channel(existing).unwrap();
        payments.release_channel_ownership(state.session_id, "existing");
        state
            .session_registry
            .set_controls(crate::session_registry::RelayControls {
                accept_new_channels: false,
                ..Default::default()
            })
            .unwrap();
        state.link_channel(existing).unwrap();
        let payment = r#"{"channel_id":"existing","balance":10,"capacity":100,"unit":"msat"}"#;
        assert_eq!(
            payments
                .apply_channel_payment(state.session_id, "existing", payment)
                .unwrap()
                .delta_millisats,
            10
        );
        assert_eq!(
            state.link_channel(r#"{"channel_id":"new","balance":0,"capacity":100,"unit":"msat"}"#),
            Err(LinkError::AdmissionDisabled)
        );
        assert!(payments.channel_state("new").unwrap().is_none());
        state
            .session_registry
            .set_controls(Default::default())
            .unwrap();
        state
            .link_channel(r#"{"channel_id":"new","balance":0,"capacity":100,"unit":"msat"}"#)
            .unwrap();
        state.cleanup();
    }

    #[test]
    fn cleanup_covers_link_before_reducer_and_preserves_replacement_owner() {
        let (state, payments) = test_state();
        let payment = r#"{"channel_id":"owned","balance":0,"capacity":100,"unit":"msat"}"#;
        state.link_channel(payment).unwrap();
        // The reducer has not yet recorded the successful validation result.
        assert_eq!(payments.owner_of("owned"), Some(state.session_id));
        state.cleanup();
        assert_eq!(payments.owner_of("owned"), None);

        let (state, payments) = test_state();
        state.link_channel(payment).unwrap();
        payments
            .link_channel(&supported_cashu_spilman_keyset_versions(), [2; 32], payment)
            .unwrap();
        state.cleanup();
        state.cleanup();
        assert_eq!(payments.owner_of("owned"), Some([2; 32]));
    }

    async fn test_h2_streams(
        window: u32,
    ) -> (
        h2::SendStream<Bytes>,
        h2::RecvStream,
        h2::SendStream<Bytes>,
        h2::RecvStream,
        tokio::task::JoinSet<()>,
    ) {
        let (client_io, server_io) = tokio::io::duplex(4096);
        let (mut client, connection) = h2::client::Builder::new()
            .initial_window_size(window)
            .handshake::<_, Bytes>(client_io)
            .await
            .unwrap();
        let mut drivers = tokio::task::JoinSet::new();
        drivers.spawn(async move {
            let _ = connection.await;
        });
        let (response, client_send) = client
            .send_request(
                Request::builder()
                    .method(Method::POST)
                    .uri("https://monad/control")
                    .body(())
                    .unwrap(),
                false,
            )
            .unwrap();
        let mut server = h2::server::handshake(server_io).await.unwrap();
        let (request, mut respond) = server.accept().await.unwrap().unwrap();
        let send = respond.send_response(Response::new(()), false).unwrap();
        drivers.spawn(async move { while server.accept().await.is_some() {} });
        let recv = response.await.unwrap().into_body();
        (send, request.into_body(), client_send, recv, drivers)
    }

    #[tokio::test]
    async fn cancellation_during_replacement_status_releases_new_owner() {
        use std::future::Future;
        use std::task::Poll;

        let (state, payments) = test_state();
        let channel_a = r#"{"channel_id":"replace-a","balance":0,"capacity":100,"unit":"msat"}"#;
        let channel_b = r#"{"channel_id":"replace-b","balance":0,"capacity":100,"unit":"msat"}"#;
        let linked_a = state.link_channel(channel_a).unwrap();
        state.billing.lock().unwrap().state.linked_channel_id = Some(linked_a.channel_id);
        let (mut send, _recv, _client_send, _client_recv, mut drivers) = test_h2_streams(0).await;

        let mut replacement = Box::pin(process_session_event(
            &state,
            SessionEvent::ClientChannelLink {
                payment_json: channel_b.to_string(),
            },
            &mut send,
        ));
        std::future::poll_fn(|cx| {
            assert!(replacement.as_mut().poll(cx).is_pending());
            Poll::Ready(())
        })
        .await;

        assert_eq!(
            state
                .billing
                .lock()
                .unwrap()
                .state
                .linked_channel_id
                .as_deref(),
            Some("replace-b")
        );
        assert_eq!(payments.owner_of("replace-a"), None);
        assert_eq!(payments.owner_of("replace-b"), Some(state.session_id));

        drop(replacement);
        state.cleanup();
        assert_eq!(payments.owner_of("replace-a"), None);
        assert_eq!(payments.owner_of("replace-b"), None);
        drivers.shutdown().await;
    }

    #[derive(Clone, Copy, Debug)]
    enum BlockedOperation {
        Write,
        Shutdown,
        H2Capacity,
    }

    struct BlockedTarget {
        operation: BlockedOperation,
        entered: Option<tokio::sync::oneshot::Sender<()>>,
        dropped: Arc<std::sync::atomic::AtomicBool>,
    }

    impl Drop for BlockedTarget {
        fn drop(&mut self) {
            self.dropped.store(true, Ordering::SeqCst);
        }
    }

    impl AsyncRead for BlockedTarget {
        fn poll_read(
            mut self: std::pin::Pin<&mut Self>,
            _cx: &mut std::task::Context<'_>,
            buf: &mut tokio::io::ReadBuf<'_>,
        ) -> std::task::Poll<io::Result<()>> {
            if matches!(self.operation, BlockedOperation::H2Capacity) {
                if let Some(entered) = self.entered.take() {
                    buf.put_slice(b"x");
                    let _ = entered.send(());
                    return std::task::Poll::Ready(Ok(()));
                }
            }
            std::task::Poll::Pending
        }
    }

    impl AsyncWrite for BlockedTarget {
        fn poll_write(
            mut self: std::pin::Pin<&mut Self>,
            _cx: &mut std::task::Context<'_>,
            _buf: &[u8],
        ) -> std::task::Poll<io::Result<usize>> {
            if matches!(self.operation, BlockedOperation::Write) {
                if let Some(entered) = self.entered.take() {
                    let _ = entered.send(());
                }
            }
            std::task::Poll::Pending
        }
        fn poll_flush(
            self: std::pin::Pin<&mut Self>,
            _cx: &mut std::task::Context<'_>,
        ) -> std::task::Poll<io::Result<()>> {
            std::task::Poll::Ready(Ok(()))
        }
        fn poll_shutdown(
            mut self: std::pin::Pin<&mut Self>,
            _cx: &mut std::task::Context<'_>,
        ) -> std::task::Poll<io::Result<()>> {
            if matches!(self.operation, BlockedOperation::Shutdown) {
                if let Some(entered) = self.entered.take() {
                    let _ = entered.send(());
                }
            }
            std::task::Poll::Pending
        }
    }

    #[tokio::test]
    async fn termination_cancels_blocked_proxy_operations() {
        use tokio::time::{timeout, Duration};
        for operation in [
            BlockedOperation::Write,
            BlockedOperation::Shutdown,
            BlockedOperation::H2Capacity,
        ] {
            let (state, _) = test_state();
            {
                let mut billing = state.billing.lock().unwrap();
                billing.state.total_paid_millisats = 1000;
                billing.state.paused = false;
            }
            state.update_pause_watch(false);
            state.connect_opened().unwrap();
            let (send, recv, mut client_send, _client_recv, mut drivers) = test_h2_streams(0).await;
            let (entered, entered_rx) = tokio::sync::oneshot::channel();
            let dropped = Arc::new(std::sync::atomic::AtomicBool::new(false));
            let target = BlockedTarget {
                operation,
                entered: Some(entered),
                dropped: dropped.clone(),
            };
            match operation {
                BlockedOperation::Write => client_send
                    .send_data(Bytes::from_static(b"x"), false)
                    .unwrap(),
                BlockedOperation::Shutdown => client_send.send_data(Bytes::new(), true).unwrap(),
                BlockedOperation::H2Capacity => {}
            }
            let mut proxy = Box::pin(proxy::proxy_bidirectional_accounted(
                send,
                recv,
                target,
                "blocked",
                state.clone(),
            ));
            timeout(Duration::from_secs(2), async {
                tokio::select! {
                    result = &mut proxy => panic!("proxy completed before gate: {result:?}"),
                    result = entered_rx => result.unwrap(),
                }
            })
            .await
            .unwrap_or_else(|error| panic!("{operation:?} did not enter its gate: {error}"));
            state.terminate();
            timeout(Duration::from_secs(2), &mut proxy)
                .await
                .unwrap_or_else(|error| {
                    panic!("{operation:?} did not exit on termination: {error}")
                })
                .unwrap();
            assert!(dropped.load(Ordering::SeqCst));
            assert_eq!(state.counters.snapshot(), (0, 1, 0));
            drivers.shutdown().await;
        }
    }

    #[tokio::test]
    async fn termination_cancels_zero_window_control_bootstrap() {
        use std::future::Future;
        use std::task::Poll;
        let (state, payments) = test_state();
        let link = state
            .link_channel(r#"{"channel_id":"owned","balance":0,"capacity":100,"unit":"msat"}"#)
            .unwrap();
        state.billing.lock().unwrap().state.linked_channel_id = Some(link.channel_id);
        let (send, recv, _client_send, _client_recv, mut drivers) = test_h2_streams(0).await;
        let (tx, rx) = mpsc::unbounded_channel();
        state.attach_control(tx).await.unwrap();
        let mut control = Box::pin(handle_control_stream(send, recv, state.clone(), rx));
        std::future::poll_fn(|cx| {
            assert!(control.as_mut().poll(cx).is_pending());
            Poll::Ready(())
        })
        .await;
        state.terminate();
        tokio::time::timeout(std::time::Duration::from_secs(2), control)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(payments.owner_of("owned"), None);
        assert!(!state.control.lock().await.control_attached);
        drivers.shutdown().await;
    }

    async fn next_server_message(recv: &mut h2::RecvStream, buf: &mut Vec<u8>) -> ServerMessage {
        tokio::time::timeout(std::time::Duration::from_secs(3), async {
            loop {
                if let Some(message) = try_decode_json_line(buf).unwrap() {
                    return message;
                }
                let bytes = recv.data().await.unwrap().unwrap();
                recv.flow_control().release_capacity(bytes.len()).unwrap();
                buf.extend_from_slice(&bytes);
            }
        })
        .await
        .unwrap()
    }

    #[tokio::test]
    async fn five_large_requests_buffer_while_response_is_flow_blocked() {
        use monad_common::control_exchange::{Attribution, ControlExchange, PendingRequest};
        use tokio::time::{timeout, Duration};
        async fn next(recv: &mut h2::RecvStream, buf: &mut Vec<u8>) -> ServerMessage {
            next_server_message(recv, buf).await
        }
        let (state, payments) = test_state();
        let (send, recv, mut client_send, mut client_recv, mut drivers) = test_h2_streams(64).await;
        let (events, event_rx) = mpsc::unbounded_channel();
        state.attach_control(events.clone()).await.unwrap();
        let control = tokio::spawn(handle_control_stream(send, recv, state.clone(), event_rx));
        let payload = |balance| {
            serde_json::json!({"channel_id":"queued", "balance":balance,
            "padding":"x".repeat(200_000)})
            .to_string()
        };
        let messages = [
            ClientMessage::ChannelLink { payment_json: serde_json::json!({"channel_id":"queued","balance":0,"capacity":100,"unit":"msat","padding":"x".repeat(200_000)}).to_string() },
            ClientMessage::Ping { nonce: "between-link-and-payment".into() },
            ClientMessage::ChannelPayment { payment_json: payload(10) },
            ClientMessage::ChannelPayment { payment_json: payload(10) },
            ClientMessage::ChannelPayment { payment_json: payload(15) },
            ClientMessage::ChannelUnlink { channel_id: "queued".into() },
        ];
        // Do not consume response capacity yet. H2 may enqueue the initial
        // status using the first 64 bytes; the following response then blocks.
        // Ingress must still accept all five requests.
        for message in messages {
            timeout(
                Duration::from_secs(3),
                send_json_line(&mut client_send, &message),
            )
            .await
            .unwrap()
            .unwrap();
        }
        assert_eq!(
            payments
                .linked_channel_status("queued")
                .unwrap()
                .balance_raw,
            0,
            "later payments must not execute while the first response is blocked"
        );
        let mut buf = Vec::new();
        let mut exchange = ControlExchange::default();
        assert_eq!(
            exchange
                .observe(&next(&mut client_recv, &mut buf).await)
                .unwrap(),
            Attribution::InitialStatus
        );
        let expectations = [
            PendingRequest::Link {
                channel_id: "queued".into(),
            },
            PendingRequest::Payment {
                channel_id: "queued".into(),
                balance_raw: 10,
                minimum_increment_msats: 10,
            },
            PendingRequest::Payment {
                channel_id: "queued".into(),
                balance_raw: 10,
                minimum_increment_msats: 0,
            },
            PendingRequest::Payment {
                channel_id: "queued".into(),
                balance_raw: 15,
                minimum_increment_msats: 5,
            },
            PendingRequest::Unlink {
                channel_id: "queued".into(),
            },
        ];
        for expected in &expectations {
            exchange.enqueue(expected.clone()).unwrap();
        }
        for (i, expected) in expectations.into_iter().enumerate() {
            if i == 1 {
                let pong = next(&mut client_recv, &mut buf).await;
                assert!(
                    matches!(&pong, ServerMessage::Pong { nonce } if nonce == "between-link-and-payment")
                );
                assert_eq!(exchange.observe(&pong).unwrap(), Attribution::Notification);
            }
            let response = next(&mut client_recv, &mut buf).await;
            match &response {
                ServerMessage::SessionStatus {
                    total_paid_millisats,
                    linked_channel,
                    ..
                } => {
                    assert_eq!(*total_paid_millisats, [0, 10, 10, 15, 15][i]);
                    if i == 0 {
                        assert_eq!(linked_channel.as_ref().unwrap().balance_raw, 0);
                    }
                }
                ServerMessage::Error { code, .. } if i == 2 => {
                    assert_eq!(*code, ServerErrorCode::PaymentNoNewFunds)
                }
                other => panic!("unexpected reply {other:?}"),
            }
            assert_eq!(
                exchange.observe(&response).unwrap(),
                Attribution::Response(expected)
            );
        }
        assert!(exchange.is_empty());
        assert_eq!(payments.owner_of("queued"), None);
        events
            .send(ServerMessage::ChannelEvicted {
                channel_id: "queued".into(),
                scope: ChannelEvictionScope::Session,
            })
            .unwrap();
        assert!(matches!(
            next(&mut client_recv, &mut buf).await,
            ServerMessage::ChannelEvicted { .. }
        ));
        send_json_line(
            &mut client_send,
            &ClientMessage::Ping {
                nonce: "after-advisory".into(),
            },
        )
        .await
        .unwrap();
        assert!(
            matches!(
                next(&mut client_recv, &mut buf).await,
                ServerMessage::Pong { .. }
            ),
            "eviction must not push a status"
        );
        state.terminate();
        timeout(Duration::from_secs(3), control)
            .await
            .unwrap()
            .unwrap()
            .unwrap();
        drivers.shutdown().await;
    }

    #[tokio::test]
    async fn ingress_backpressures_sixth_ordinary_request_but_probes_use_no_slot() {
        use monad_common::protocol::ExtensionNotification;
        use tokio::time::{timeout, Duration};
        let (_send, recv, mut client_send, _client_recv, mut drivers) =
            test_h2_streams(65535).await;
        let (tx, mut requests) = mpsc::channel(16);
        let reader = tokio::spawn(read_control_requests(recv, tx));
        for _ in 0..5 {
            send_json_line(&mut client_send, &ClientMessage::GetSessionStatus)
                .await
                .unwrap();
        }
        send_json_line(
            &mut client_send,
            &ClientMessage::Ping {
                nonce: "free-slot".into(),
            },
        )
        .await
        .unwrap();
        let relaxed_extension = ClientMessage::ExtensionNotification(ExtensionNotification {
            name: "example.relaxed".into(),
            rest: serde_json::Map::from_iter([
                ("data".into(), serde_json::json!({"anything": [1, null]})),
                ("future_member".into(), serde_json::Value::Null),
            ]),
        });
        send_json_line(&mut client_send, &relaxed_extension)
            .await
            .unwrap();
        let mut held = Vec::new();
        for _ in 0..5 {
            let request = timeout(Duration::from_secs(2), requests.recv())
                .await
                .unwrap()
                .unwrap();
            assert!(request.slot.is_some());
            held.push(request);
        }
        let ping = timeout(Duration::from_secs(2), requests.recv())
            .await
            .unwrap()
            .unwrap();
        assert!(matches!(ping.message, ClientMessage::Ping { .. }));
        assert!(ping.slot.is_none());
        let extension = timeout(Duration::from_secs(2), requests.recv())
            .await
            .unwrap()
            .unwrap();
        assert!(matches!(
            extension.message,
            ClientMessage::ExtensionNotification(_)
        ));
        assert!(extension.slot.is_none());
        send_json_line(&mut client_send, &ClientMessage::GetSessionStatus)
            .await
            .unwrap();
        assert!(timeout(Duration::from_millis(50), requests.recv())
            .await
            .is_err());
        drop(held.pop());
        let sixth = timeout(Duration::from_secs(2), requests.recv())
            .await
            .unwrap()
            .unwrap();
        assert!(matches!(sixth.message, ClientMessage::GetSessionStatus));
        reader.abort();
        let _ = reader.await;
        drivers.shutdown().await;
    }

    #[tokio::test]
    async fn relaxed_extension_is_ignored_without_response_or_state_mutation() {
        let (state, payments) = test_state();
        let (send, recv, mut client_send, mut client_recv, mut drivers) =
            test_h2_streams(65535).await;
        let (events, event_rx) = mpsc::unbounded_channel();
        state.attach_control(events).await.unwrap();
        let control = tokio::spawn(handle_control_stream(send, recv, state.clone(), event_rx));
        let mut buf = Vec::new();
        let initial = next_server_message(&mut client_recv, &mut buf).await;
        assert!(matches!(initial, ServerMessage::SessionStatus { .. }));
        let relaxed_extension = Bytes::from_static(
            br#"{"type":"ExtensionNotification","name":"example.ignored","anything":[1,null],"future_member":{"relaxed":true}}
"#,
        );
        let mut typed_decode_buf = relaxed_extension.to_vec();
        let decoded: ClientMessage = try_decode_json_line(&mut typed_decode_buf)
            .unwrap()
            .unwrap();
        assert!(matches!(decoded, ClientMessage::ExtensionNotification(_)));
        client_send.send_data(relaxed_extension, false).unwrap();
        client_send
            .send_data(
                Bytes::from_static(
                    b"{\"type\":\"Ping\",\"nonce\":\"extension-had-no-response\"}\n",
                ),
                false,
            )
            .unwrap();
        let pong = next_server_message(&mut client_recv, &mut buf).await;
        assert!(
            matches!(&pong, ServerMessage::Pong { nonce } if nonce == "extension-had-no-response"),
            "valid extension must be ignored and never answered; got {pong:?}"
        );
        client_send
            .send_data(
                Bytes::from_static(b"{\"type\":\"ExtensionNotification\",\"name\":\"\"}\n"),
                false,
            )
            .unwrap();
        let error = next_server_message(&mut client_recv, &mut buf).await;
        assert!(matches!(
            error,
            ServerMessage::Error {
                code: ServerErrorCode::ControlInvalidMessage,
                ..
            }
        ));
        let result = tokio::time::timeout(std::time::Duration::from_secs(3), control)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(result.unwrap_err().kind(), io::ErrorKind::InvalidData);
        assert!(state.is_terminated());
        assert!(payments.owner_of("example.ignored").is_none());
        drivers.shutdown().await;
    }

    #[tokio::test]
    async fn malformed_input_cancels_queued_work_behind_blocked_initial_status() {
        let (state, payments) = test_state();
        let (send, recv, mut client_send, _client_recv, mut drivers) = test_h2_streams(0).await;
        let (events, event_rx) = mpsc::unbounded_channel();
        state.attach_control(events).await.unwrap();
        let control = tokio::spawn(handle_control_stream(send, recv, state.clone(), event_rx));
        send_json_line(
            &mut client_send,
            &ClientMessage::ChannelLink {
                payment_json:
                    r#"{"channel_id":"must-not-run","balance":0,"capacity":100,"unit":"msat"}"#
                        .into(),
            },
        )
        .await
        .unwrap();
        client_send
            .send_data(Bytes::from_static(b"not-json\n"), false)
            .unwrap();
        let result = tokio::time::timeout(
            CONTROL_INVALID_MESSAGE_SEND_TIMEOUT + std::time::Duration::from_secs(2),
            control,
        )
        .await
        .unwrap()
        .unwrap();
        assert_eq!(result.unwrap_err().kind(), io::ErrorKind::InvalidData);
        assert!(payments.linked_channel_status("must-not-run").is_none());
        assert!(state.is_terminated());
        drivers.shutdown().await;
    }

    #[tokio::test]
    async fn pending_connect_keeps_h2_progressing_until_cancel_or_deadline() {
        use tokio::time::{timeout, Duration};
        for wait_for_deadline in [false, true] {
            let (state, _) = test_state();
            state.billing.lock().unwrap().state.paused = false;
            state.update_pause_watch(false);
            // A bound UDP socket that observes but never answers QUIC Initials is
            // a deterministic setup gate, not an unroutable-host timing assumption.
            let blackhole = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
            let (client_io, server_io) = tokio::io::duplex(4096);
            let (mut client, client_conn) = h2::client::handshake(client_io).await.unwrap();
            let client_driver = tokio::spawn(client_conn);
            let server = h2::server::handshake(server_io).await.unwrap();
            let session = RelaySession {
                h2_conn: server,
                quic_pool: Some(QuicPool::new().unwrap()),
                session_id: state.session_id,
                state: state.clone(),
            };
            let task = tokio::spawn(session.run());
            let request = Request::builder()
                .method(Method::CONNECT)
                .uri(blackhole.local_addr().unwrap().to_string())
                .header(
                    QUIC_SECP256K1_PUBKEY_HEADER,
                    state.transport_key.pubkey().to_hex(),
                )
                .body(())
                .unwrap();
            let (pending_response, _send) = client.send_request(request, false).unwrap();
            let mut pending_response = Some(pending_response);
            let mut packet = [0; 2048];
            timeout(Duration::from_secs(2), blackhole.recv_from(&mut packet))
                .await
                .unwrap()
                .unwrap();

            let request = Request::builder()
                .method(Method::POST)
                .uri("https://monad/control")
                .body(())
                .unwrap();
            let (control_response, _control_send) = client.send_request(request, false).unwrap();
            let mut control = timeout(Duration::from_secs(2), control_response)
                .await
                .unwrap()
                .unwrap()
                .into_body();
            let status = timeout(Duration::from_secs(2), control.data())
                .await
                .unwrap()
                .unwrap()
                .unwrap();
            assert!(std::str::from_utf8(&status)
                .unwrap()
                .contains("SessionStatus"));
            if wait_for_deadline {
                let response = timeout(
                    CONNECT_SETUP_TIMEOUT + Duration::from_secs(2),
                    pending_response.take().unwrap(),
                )
                .await
                .unwrap()
                .unwrap();
                assert_eq!(response.status(), StatusCode::BAD_GATEWAY);
            }
            state.terminate();
            timeout(Duration::from_secs(2), task)
                .await
                .unwrap()
                .unwrap()
                .unwrap();
            if let Some(pending_response) = pending_response {
                assert!(timeout(Duration::from_secs(2), pending_response)
                    .await
                    .unwrap()
                    .is_err());
            }
            assert_eq!(state.counters.snapshot(), (0, 0, 1));
            assert!(!state.session_registry.terminate(&state.session_id));
            client_driver.abort();
            let _ = client_driver.await;
        }
    }

    #[tokio::test]
    async fn completed_partial_write_survives_termination_drop_and_abort() {
        use tokio::time::{timeout, Duration};

        #[derive(Debug)]
        struct PartialWriteTarget {
            entered: Option<tokio::sync::oneshot::Sender<()>>,
        }

        impl AsyncRead for PartialWriteTarget {
            fn poll_read(
                self: std::pin::Pin<&mut Self>,
                _cx: &mut std::task::Context<'_>,
                _buf: &mut tokio::io::ReadBuf<'_>,
            ) -> std::task::Poll<io::Result<()>> {
                std::task::Poll::Pending
            }
        }

        impl AsyncWrite for PartialWriteTarget {
            fn poll_write(
                mut self: std::pin::Pin<&mut Self>,
                _cx: &mut std::task::Context<'_>,
                buf: &[u8],
            ) -> std::task::Poll<io::Result<usize>> {
                if let Some(entered) = self.entered.take() {
                    let _ = entered.send(());
                    return std::task::Poll::Ready(Ok(buf.len().min(3)));
                }
                std::task::Poll::Pending
            }

            fn poll_flush(
                self: std::pin::Pin<&mut Self>,
                _cx: &mut std::task::Context<'_>,
            ) -> std::task::Poll<io::Result<()>> {
                std::task::Poll::Ready(Ok(()))
            }

            fn poll_shutdown(
                self: std::pin::Pin<&mut Self>,
                _cx: &mut std::task::Context<'_>,
            ) -> std::task::Poll<io::Result<()>> {
                std::task::Poll::Pending
            }
        }

        for finish in ["terminate", "drop", "abort"] {
            let (state, _) = test_state();
            {
                let mut billing = state.billing.lock().unwrap();
                billing.state.total_paid_millisats = 10;
                billing.state.paused = false;
            }
            state.update_pause_watch(false);
            state.connect_opened().unwrap();
            let (send, recv, mut client_send, _client_recv, mut drivers) = test_h2_streams(0).await;
            let (entered, entered_rx) = tokio::sync::oneshot::channel();
            let target = PartialWriteTarget {
                entered: Some(entered),
            };
            client_send
                .send_data(Bytes::from_static(b"0123456789"), false)
                .unwrap();
            let mut proxy = Box::pin(proxy::proxy_bidirectional_accounted(
                send,
                recv,
                target,
                "partial-write",
                state.clone(),
            ));
            if finish == "abort" {
                let task = tokio::spawn(proxy);
                timeout(Duration::from_secs(2), entered_rx)
                    .await
                    .unwrap()
                    .unwrap();
                task.abort();
                assert!(task.await.unwrap_err().is_cancelled());
            } else {
                timeout(Duration::from_secs(2), async {
                tokio::select! {
                    result = &mut proxy => panic!("proxy completed before partial write: {result:?}"),
                    result = entered_rx => result.unwrap(),
                }
            }).await.unwrap();
                // Counts are already current while the next write is blocked.
                assert_eq!(state.bytes.outbound.load(Ordering::Relaxed), 3);
                if finish == "terminate" {
                    state.terminate();
                    timeout(Duration::from_secs(2), &mut proxy)
                        .await
                        .unwrap()
                        .unwrap();
                }
                drop(proxy);
            }
            assert_eq!(state.bytes.outbound.load(Ordering::Relaxed), 3);
            assert_eq!(state.counters.snapshot(), (0, 1, 0));
            drivers.shutdown().await;
        }
    }

    #[tokio::test]
    async fn session_payment_limit_rejects_before_balance_mutation() {
        let (state, payments) = test_state();
        let link = state
            .link_channel(r#"{"channel_id":"limited","balance":0,"capacity":10,"unit":"msat"}"#)
            .unwrap();
        state.billing.lock().unwrap().state.linked_channel_id = Some(link.channel_id.clone());
        state.billing.lock().unwrap().state.total_paid_millisats = u64::MAX;
        // Keep remaining credit representable so this exercises u64 paid-total
        // exhaustion independently of the i64 remaining-credit check.
        state.bytes.outbound.store(u64::MAX, Ordering::Relaxed);

        let error = state
            .apply_channel_payment(
                "limited",
                r#"{"channel_id":"limited","balance":1,"signature":"sig"}"#,
            )
            .await
            .unwrap_err();
        assert_eq!(
            error,
            crate::payments::ChannelPaymentError::NumericLimitExceeded
        );
        assert_eq!(
            payments
                .linked_channel_status("limited")
                .unwrap()
                .balance_raw,
            0
        );
    }

    #[tokio::test]
    async fn payment_checks_signed_remaining_limit_before_acceptance() {
        for (unit, scale) in [("msat", 1_u64), ("sat", 1000)] {
            let (state, payments) = test_state();
            let link =
                format!(r#"{{"channel_id":"bounded","balance":0,"capacity":10,"unit":"{unit}"}}"#);
            state.link_channel(&link).unwrap();
            {
                let mut billing = state.billing.lock().unwrap();
                billing.state.total_paid_millisats = i64::MAX as u64 - scale;
                billing.state.linked_channel_id = Some("bounded".into());
            }
            let before = payments.linked_channel_status("bounded").unwrap();
            let rejected = state
                .apply_channel_payment("bounded", r#"{"channel_id":"bounded","balance":2}"#)
                .await;
            assert_eq!(
                rejected.unwrap_err(),
                crate::payments::ChannelPaymentError::NumericLimitExceeded
            );
            assert_eq!(payments.linked_channel_status("bounded").unwrap(), before);
            assert_eq!(
                state.billing.lock().unwrap().state.total_paid_millisats,
                i64::MAX as u64 - scale
            );
            let accepted = state
                .apply_channel_payment("bounded", r#"{"channel_id":"bounded","balance":1}"#)
                .await
                .unwrap();
            let mut billing = state.billing.lock().unwrap();
            let (next, _) = step(
                billing.state.clone(),
                SessionEvent::PaymentValidationFinished(Ok(accepted)),
                billing.pricing,
                state.bytes.snapshot(),
            );
            billing.state = next;
            assert_eq!(
                billing.remaining_milli_sats(state.bytes.snapshot()),
                i64::MAX as i128
            );
        }
    }

    #[tokio::test]
    async fn payment_limits_are_representation_bounds_not_optional_policy_caps() {
        let (state, payments) = test_state();
        let too_large_sat_balance = i64::MAX as u64 / 1000 + 1;
        state.link_channel(&format!(r#"{{"channel_id":"sat-limit","balance":0,"capacity":{too_large_sat_balance},"unit":"sat"}}"#)).unwrap();
        assert_eq!(
            state
                .apply_channel_payment(
                    "sat-limit",
                    &format!(r#"{{"channel_id":"sat-limit","balance":{too_large_sat_balance}}}"#)
                )
                .await
                .unwrap_err(),
            crate::payments::ChannelPaymentError::NumericLimitExceeded
        );
        assert_eq!(
            payments
                .linked_channel_status("sat-limit")
                .unwrap()
                .balance_raw,
            0
        );

        let large_msats = 9_000_000_000_000_001_u64;
        state
            .link_channel(&format!(
                r#"{{"channel_id":"large","balance":0,"capacity":{large_msats},"unit":"msat"}}"#
            ))
            .unwrap();
        assert_eq!(
            state
                .apply_channel_payment(
                    "large",
                    &format!(r#"{{"channel_id":"large","balance":{large_msats}}}"#)
                )
                .await
                .unwrap()
                .delta_millisats,
            large_msats
        );
    }

    #[test]
    fn pending_and_failed_transport_polls_do_not_charge_or_hold_accounting_lock() {
        let (state, _) = test_state();
        assert!(state
            .poll_accounted_forward(ByteDirection::Outbound, 10, || Poll::Pending)
            .is_pending());
        assert!(state.billing.try_lock().is_ok());
        assert_eq!(state.bytes.outbound.load(Ordering::Relaxed), 0);
        assert!(matches!(
            state.poll_accounted_forward(ByteDirection::Outbound, 10, || Poll::Ready(Err(
                io::ErrorKind::BrokenPipe.into()
            ))),
            Poll::Ready(Err(_))
        ));
        assert!(state.billing.try_lock().is_ok());
        assert_eq!(state.bytes.outbound.load(Ordering::Relaxed), 0);
        // A successful partial prefix counts exactly and may overshoot credit.
        assert!(matches!(
            state.poll_accounted_forward(ByteDirection::Outbound, 10, || Poll::Ready(Ok(3))),
            Poll::Ready(Ok((3, _)))
        ));
        assert_eq!(
            state
                .billing
                .lock()
                .unwrap()
                .remaining_milli_sats(state.bytes.snapshot()),
            -3
        );
    }

    #[test]
    fn concurrent_forwarders_accumulate_atomic_byte_totals() {
        for direction in [ByteDirection::Inbound, ByteDirection::Outbound] {
            let (state, _) = test_state();
            let gate = std::sync::Barrier::new(2);
            let forwarded = AtomicU64::new(0);
            std::thread::scope(|scope| {
                for _ in 0..2 {
                    scope.spawn(|| {
                        gate.wait();
                        state.poll_accounted_forward(direction, 4, || {
                            forwarded.fetch_add(4, Ordering::Relaxed);
                            Poll::Ready(Ok(4))
                        })
                    });
                }
            });
            assert_eq!(forwarded.load(Ordering::Relaxed), 8);
            let total = match direction {
                ByteDirection::Inbound => state.bytes.inbound.load(Ordering::Relaxed),
                ByteDirection::Outbound => state.bytes.outbound.load(Ordering::Relaxed),
            };
            assert_eq!(total, 8);
        }

        let (state, _) = test_state();
        let gate = std::sync::Barrier::new(2);
        let forwarded = AtomicU64::new(0);
        std::thread::scope(|scope| {
            for direction in [ByteDirection::Inbound, ByteDirection::Outbound] {
                let state = &state;
                let gate = &gate;
                let forwarded = &forwarded;
                scope.spawn(move || {
                    gate.wait();
                    state.poll_accounted_forward(direction, 1, || {
                        forwarded.fetch_add(1, Ordering::Relaxed);
                        Poll::Ready(Ok(1))
                    })
                });
            }
        });
        assert_eq!(forwarded.load(Ordering::Relaxed), 2);
        assert_eq!(
            state
                .billing
                .lock()
                .unwrap()
                .remaining_milli_sats(state.bytes.snapshot()),
            -2
        );
        assert!(state.billing.lock().unwrap().state.paused);
    }

    #[test]
    fn stale_pause_effect_cannot_overwrite_current_watch_state() {
        let (state, _) = test_state();
        let paused = state.pause_receiver();

        state.billing.lock().unwrap().state.paused = false;
        state.update_pause_watch(false);
        assert!(!*paused.borrow());

        state.billing.lock().unwrap().state.paused = true;
        state.pause_tx.send_replace(true);
        state.update_pause_watch(false);
        assert!(*paused.borrow());
    }

    #[tokio::test]
    async fn inbound_enqueued_before_pause_drains_and_survives_proxy_drop() {
        let (state, _) = test_state();
        {
            let mut billing = state.billing.lock().unwrap();
            billing.state.total_paid_millisats = 1;
            billing.state.paused = false;
        }
        state.update_pause_watch(false);
        state.connect_opened().unwrap();
        let (send, recv, _client_send, mut client_recv, mut drivers) = test_h2_streams(65535).await;
        let (target, mut peer) = tokio::io::duplex(64);
        peer.write_all(b"data").await.unwrap();
        let mut proxy = Box::pin(proxy::proxy_bidirectional_accounted(
            send,
            recv,
            target,
            "inbound",
            state.clone(),
        ));
        tokio::time::timeout(std::time::Duration::from_secs(2), async {
            tokio::select! {
                result = &mut proxy => panic!("proxy unexpectedly ended: {result:?}"),
                data = client_recv.data() => assert_eq!(data.unwrap().unwrap().as_ref(), b"data"),
            }
        })
        .await
        .unwrap();
        {
            let billing = state.billing.lock().unwrap();
            assert!(billing.state.paused);
            assert_eq!(state.bytes.inbound.load(Ordering::Relaxed), 4);
            assert_eq!(billing.remaining_milli_sats(state.bytes.snapshot()), -3);
        }
        drop(proxy);
        assert_eq!(state.bytes.inbound.load(Ordering::Relaxed), 4);
        assert_eq!(state.counters.snapshot(), (0, 1, 0));
        drivers.shutdown().await;
    }

    #[tokio::test]
    async fn proxy_preserves_reply_after_request_half_close() {
        use tokio::io::AsyncReadExt;
        let (state, _) = test_state();
        {
            let mut billing = state.billing.lock().unwrap();
            billing.state.total_paid_millisats = 1000;
            billing.state.paused = false;
        }
        state.update_pause_watch(false);
        state.connect_opened().unwrap();
        let (send, recv, mut client_send, mut client_recv, mut drivers) =
            test_h2_streams(65535).await;
        let (target, mut peer) = tokio::io::duplex(64);
        client_send
            .send_data(Bytes::from_static(b"request"), true)
            .unwrap();
        let proxy =
            proxy::proxy_bidirectional_accounted(send, recv, target, "half-close", state.clone());
        let target = async {
            let mut request = Vec::new();
            peer.read_to_end(&mut request).await.unwrap();
            assert_eq!(request, b"request");
            peer.write_all(b"reply after EOF").await.unwrap();
            peer.shutdown().await.unwrap();
        };
        let client = async {
            let mut reply = Vec::new();
            while let Some(chunk) = client_recv.data().await {
                reply.extend_from_slice(&chunk.unwrap());
            }
            assert_eq!(reply, b"reply after EOF");
        };
        let (result, (), ()) = tokio::time::timeout(std::time::Duration::from_secs(2), async {
            tokio::join!(proxy, target, client)
        })
        .await
        .unwrap();
        result.unwrap();
        assert_eq!(state.counters.snapshot(), (0, 1, 0));
        drivers.shutdown().await;
    }

    #[tokio::test]
    async fn connect_publication_rechecks_pause_termination_and_admission() {
        for mode in ["pause", "terminate", "admission"] {
            let terminate = mode == "terminate";
            let (state, _) = test_state();
            if terminate {
                state.terminate();
            }
            if mode == "admission" {
                state.billing.lock().unwrap().state.paused = false;
                state
                    .session_registry
                    .set_controls(crate::session_registry::RelayControls {
                        accept_new_tunnels: false,
                        ..Default::default()
                    })
                    .unwrap();
            }
            let (client_io, server_io) = tokio::io::duplex(4096);
            let (mut client, connection) = h2::client::handshake(client_io).await.unwrap();
            let mut drivers = tokio::task::JoinSet::new();
            drivers.spawn(async move {
                let _ = connection.await;
            });
            let (response, _send) = client
                .send_request(
                    Request::builder()
                        .method(Method::CONNECT)
                        .uri("target:80")
                        .body(())
                        .unwrap(),
                    false,
                )
                .unwrap();
            let mut server = h2::server::handshake(server_io).await.unwrap();
            let (request, mut respond) = server.accept().await.unwrap().unwrap();
            drivers.spawn(async move { while server.accept().await.is_some() {} });
            let (target, mut peer) = tokio::io::duplex(16);
            let handler = ConnectHandler {
                state: state.clone(),
                quic_pool: None,
                accepted: AtomicBool::new(false),
            };
            handler
                .proxy_tunnel(&mut respond, request, target, "target:80", "gated")
                .await
                .unwrap();
            let response = response.await;
            if terminate {
                assert!(response.is_err());
            } else if mode == "admission" {
                assert_eq!(response.unwrap().status(), StatusCode::SERVICE_UNAVAILABLE);
            } else {
                assert_eq!(response.unwrap().status(), StatusCode::PAYMENT_REQUIRED);
            }
            drop(handler);
            assert_eq!(state.counters.snapshot(), (0, 0, 1));
            use tokio::io::AsyncReadExt;
            assert_eq!(peer.read(&mut [0]).await.unwrap(), 0);
            drivers.shutdown().await;
        }
    }

    #[tokio::test]
    async fn status_rejects_unrepresentable_remaining_without_approximation() {
        let (state, _) = test_state();
        state.bytes.inbound.store(u64::MAX, Ordering::Relaxed);
        assert!(state.session_status_message().await.is_none());
        assert!(state.is_terminated());
    }

    #[tokio::test]
    async fn status_pause_matches_reported_byte_and_payment_totals() {
        let (state, _) = test_state();
        state.billing.lock().unwrap().state.paused = false;
        state.bytes.outbound.store(1, Ordering::Relaxed);

        let Some(ServerMessage::SessionStatus {
            session_total_bytes_out,
            total_paid_millisats,
            remaining_milli_sats,
            paused,
            ..
        }) = state.session_status_message().await
        else {
            panic!()
        };
        assert_eq!(session_total_bytes_out, 1);
        assert_eq!(total_paid_millisats, 0);
        assert_eq!(remaining_milli_sats, -1);
        assert!(paused);
    }

    #[tokio::test]
    async fn status_advertises_trusted_units_independently_of_cached_keysets_and_versions() {
        let cache = shared_spilman_mint_cache(SpilmanMintCache::default());
        let (mut state, _) = test_state_with_cache(cache.clone());
        state
            .trusted_mint_units
            .get_mut("mint")
            .unwrap()
            .insert("msat".into());
        let Some(ServerMessage::SessionStatus { advertisements, .. }) =
            state.session_status_message().await
        else {
            panic!()
        };
        assert_eq!(advertisements.len(), 1);
        assert_eq!(advertisements["mint"].len(), 2);
        assert_eq!(
            advertisements["mint"]["sat"].funding_keyset_recovery_window_secs,
            state.payments.funding_keyset_recovery_window_secs()
        );
        let expected = advertisements;
        state.cashu_spilman_keyset_versions = Some(BTreeSet::from(["v2".to_string()]));
        // Discovery/rotation changes the shared cache, not the advertised policy.
        cache.write().unwrap().advertised.insert(
            "mint".into(),
            BTreeMap::from([(
                "sat".into(),
                vec!["0000000000000001".into(), format!("01{}", "11".repeat(32))],
            )]),
        );
        cache.write().unwrap().advertised.insert(
            "untrusted".into(),
            BTreeMap::from([("sat".into(), vec!["0000000000000002".into()])]),
        );
        let Some(ServerMessage::SessionStatus { advertisements, .. }) =
            state.session_status_message().await
        else {
            panic!()
        };
        assert_eq!(advertisements, expected);
    }

    #[tokio::test]
    async fn fatal_cleanup_survives_reset_and_blocked_error_delivery() {
        for reset in [false, true] {
            let (state, payments) = test_state();
            let link = payments
                .link_channel(
                    &supported_cashu_spilman_keyset_versions(),
                    state.session_id,
                    r#"{"channel_id":"owned","balance":0,"capacity":100,"unit":"msat"}"#,
                )
                .unwrap();
            state.billing.lock().unwrap().state.linked_channel_id = Some(link.channel_id);
            let (client, server) = tokio::io::duplex(4096);
            let client_task = tokio::spawn(async move {
                let (mut client, connection) = h2::client::Builder::new()
                    .initial_window_size(0)
                    .handshake::<_, Bytes>(client)
                    .await
                    .unwrap();
                let driver = tokio::spawn(connection);
                let request = Request::builder()
                    .method(Method::POST)
                    .uri("https://monad/control")
                    .body(())
                    .unwrap();
                let (response, send) = client.send_request(request, false).unwrap();
                (response, send, driver)
            });
            let mut server = h2::server::handshake(server).await.unwrap();
            let (_request, mut respond) = server.accept().await.unwrap().unwrap();
            let mut send = respond.send_response(Response::new(()), false).unwrap();
            let server_driver =
                tokio::spawn(async move { while server.accept().await.is_some() {} });
            let (response, mut client_send, client_driver) = client_task.await.unwrap();
            let _response = response.await.unwrap();
            if reset {
                client_send.send_reset(h2::Reason::CANCEL);
            }
            assert!(tokio::time::timeout(
                std::time::Duration::from_secs(1),
                process_session_event(
                    &state,
                    SessionEvent::LinkValidationFinished(Err(
                        LinkError::KeysetVersionNotNegotiated
                    )),
                    &mut send
                )
            )
            .await
            .unwrap()
            .unwrap());
            assert!(state.is_terminated());
            assert!(payments.owner_of("owned").is_none());
            assert!(state.billing.lock().unwrap().state.terminated);
            server_driver.abort();
            client_driver.abort();
            let _ = server_driver.await;
            let _ = client_driver.await;
        }
    }
}
