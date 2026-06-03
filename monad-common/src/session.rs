//! Session types for MONAD relay connections.
//!
//! `RelayConnection` is the client-side handle to an established Noise+H2
//! session with a MONAD relay. It wraps the H2 client machinery and exposes
//! high-level methods for opening tunnels and control streams.

use bytes::Bytes;
use h2::client;
use http::{Method, Request, Uri};
use std::io;
use std::sync::Arc;
use std::sync::Mutex;
use tokio::sync::RwLock;
use tokio::task::JoinHandle;

use crate::h2stream::H2ConnectStream;
use crate::proxy::CleartextByteCounters;

// ---------------------------------------------------------------------------
// Shared math helpers
// ---------------------------------------------------------------------------

fn gcd_u64(mut a: u64, mut b: u64) -> u64 {
    while b != 0 {
        let tmp = a % b;
        a = b;
        b = tmp;
    }
    a
}

/// Compute the LCM of two `u64` values, saturating on overflow.
pub fn lcm_u64(a: u64, b: u64) -> u64 {
    if a == 0 || b == 0 {
        return 0;
    }
    (a / gcd_u64(a, b)).saturating_mul(b)
}

/// Clamp an `i128` to the `i64` range for wire representation.
pub fn clamp_i128_to_i64(value: i128) -> i64 {
    value.clamp(i64::MIN as i128, i64::MAX as i128) as i64
}

// ---------------------------------------------------------------------------
// SessionPricing — local persisted pricing with precomputed LCM
// ---------------------------------------------------------------------------

/// Local session pricing metadata, persisted on both client and relay.
///
/// Constructed from the wire `SessionStatus` message. Includes the
/// precomputed LCM of the two directional rates so billing math can
/// use integer arithmetic without recomputing it per chunk.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SessionPricing {
    pub in_bytes_per_millisat: u64,
    pub out_bytes_per_millisat: u64,
    pub pricing_lcm: u64,
}

/// Spilman session metadata fetched by the client after receiving `SessionStatus`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SessionSpilmanInfo {
    pub receiver_pubkey: String,
    pub mint_url: String,
    pub unit: String,
    pub keyset_id: String,
    pub keyset_info_json: String,
}

impl SessionPricing {
    /// Create a `SessionPricing` from the raw directional rates.
    ///
    /// Computes and caches `lcm(in_bytes_per_millisat, out_bytes_per_millisat)`.
    pub fn new(in_bytes_per_millisat: u64, out_bytes_per_millisat: u64) -> Self {
        let in_rate = in_bytes_per_millisat.max(1);
        let out_rate = out_bytes_per_millisat.max(1);
        Self {
            in_bytes_per_millisat: in_rate,
            out_bytes_per_millisat: out_rate,
            pricing_lcm: lcm_u64(in_rate, out_rate),
        }
    }

    /// Compute the total amount due in millisats for the given byte totals.
    ///
    /// Uses the formula:
    /// `ceil(in_bytes / in_bytes_per_millisat + out_bytes / out_bytes_per_millisat)`
    ///
    /// Implemented with integer-only arithmetic via the precomputed LCM.
    pub fn amount_due_millisats(&self, session_total_in: u64, session_total_out: u64) -> u128 {
        let lcm = self.pricing_lcm as u128;
        let due_units = session_total_in as u128 * (lcm / self.in_bytes_per_millisat as u128)
            + session_total_out as u128 * (lcm / self.out_bytes_per_millisat as u128);
        due_units.div_ceil(lcm)
    }
}

/// An established connection to a MONAD relay, ready to open H2 streams.
///
/// Created by performing a Noise NK handshake followed by an H2 client
/// handshake. For multi-hop chains, each intermediate hop adds a driver
/// handle via [`add_driver`](Self::add_driver).
pub struct RelayConnection {
    /// The H2 client send handle — cloned for each new stream.
    h2_client: Arc<tokio::sync::Mutex<client::SendRequest<Bytes>>>,
    /// Background tasks driving the H2 connection(s) in the hop chain.
    driver_handles: Mutex<Vec<JoinHandle<()>>>,
    /// Abortable background tasks associated with this relay connection, such as
    /// client-side control stream tasks.
    task_handles: Mutex<Vec<JoinHandle<()>>>,
    /// Noise handshake hash — unique session identifier agreed by both sides.
    session_id: [u8; 32],
    /// Session pricing metadata, set by the control task after receiving
    /// `SessionStatus` from the relay.
    session_pricing: Arc<RwLock<Option<SessionPricing>>>,
    /// Spilman mint/keyset info fetched by the client for this session.
    session_spilman_info: Arc<RwLock<Option<SessionSpilmanInfo>>>,
    /// Client-side passive cleartext byte counters for this relay session.
    /// Semantics intentionally mirror the relay's `session_total_in/out`
    /// billing counters for CONNECT payload bytes.
    cleartext_byte_counters: CleartextByteCounters,
}

impl RelayConnection {
    pub async fn from_transport_stream<T>(
        stream: T,
        session_id: [u8; 32],
    ) -> io::Result<(Self, JoinHandle<()>)>
    where
        T: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static,
    {
        let (h2_client, h2_conn) = client::handshake(stream)
            .await
            .map_err(|e| io::Error::other(format!("h2 handshake error: {e}")))?;

        let driver_handle = tokio::spawn(async move {
            if let Err(e) = h2_conn.await {
                if is_expected_h2_teardown_error(&e) {
                    tracing::debug!("H2 connection at hop closed during teardown: {e}");
                } else {
                    tracing::error!("H2 connection error at hop: {e}");
                }
            }
        });

        let conn = Self {
            h2_client: Arc::new(tokio::sync::Mutex::new(h2_client)),
            driver_handles: Mutex::new(Vec::new()),
            task_handles: Mutex::new(Vec::new()),
            session_id,
            session_pricing: Arc::new(RwLock::new(None)),
            session_spilman_info: Arc::new(RwLock::new(None)),
            cleartext_byte_counters: CleartextByteCounters::default(),
        };

        Ok((conn, driver_handle))
    }

    /// Open an H2 CONNECT tunnel to the given target authority.
    ///
    /// Returns an `H2ConnectStream` that implements `AsyncRead + AsyncWrite`,
    /// suitable for running a nested Noise+H2 session on top.
    pub async fn open_tunnel(&self, target_authority: &str) -> io::Result<H2ConnectStream> {
        self.open_tunnel_inner(target_authority, None).await
    }

    /// Open an H2 CONNECT tunnel with a `quic-secp256k1-pubkey` header, telling the relay
    /// to reach the target via QUIC and authenticate the connection using the
    /// provided x-only secp256k1 public key.
    pub async fn open_tunnel_quic_secp256k1(
        &self,
        target_authority: &str,
        pubkey_hex: &str,
    ) -> io::Result<H2ConnectStream> {
        self.open_tunnel_inner(
            target_authority,
            Some(("quic-secp256k1-pubkey", pubkey_hex.to_owned())),
        )
        .await
    }

    /// Clone the underlying `SendRequest` handle for direct H2 stream use
    /// (e.g., opening data tunnels via `tunnel::open_tunnel`).
    pub async fn clone_send_request(&self) -> client::SendRequest<Bytes> {
        let client = self.h2_client.lock().await;
        client.clone()
    }

    /// Open the long-lived control stream for this relay session.
    pub async fn open_control(&self) -> io::Result<(h2::SendStream<Bytes>, h2::RecvStream)> {
        let mut h2_client = self.clone_send_request().await;

        let request = Request::builder()
            .method(Method::POST)
            .uri("http://monad/control")
            .body(())
            .map_err(|e| {
                io::Error::new(io::ErrorKind::InvalidInput, format!("bad request: {e}"))
            })?;

        let (response_future, h2_send) = h2_client
            .send_request(request, false)
            .map_err(|e| io::Error::other(format!("h2 send error: {e}")))?;

        let response = response_future
            .await
            .map_err(|e| io::Error::other(format!("h2 response error: {e}")))?;

        if !response.status().is_success() {
            return Err(io::Error::new(
                io::ErrorKind::ConnectionRefused,
                format!("control stream rejected: {}", response.status()),
            ));
        }

        Ok((h2_send, response.into_body()))
    }

    /// Get the Noise handshake hash used as a unique session identifier.
    pub fn session_id(&self) -> &[u8; 32] {
        &self.session_id
    }

    /// Get the current session pricing, if set by the control task.
    pub async fn session_pricing(&self) -> Option<SessionPricing> {
        *self.session_pricing.read().await
    }

    /// Get a shared handle to the session pricing storage.
    ///
    /// Used by the control task to persist pricing when `SessionStatus`
    /// arrives from the relay.
    pub fn session_pricing_handle(&self) -> Arc<RwLock<Option<SessionPricing>>> {
        self.session_pricing.clone()
    }

    /// Get the fetched Spilman metadata for this session, if available.
    pub async fn session_spilman_info(&self) -> Option<SessionSpilmanInfo> {
        self.session_spilman_info.read().await.clone()
    }

    /// Get a shared handle to the Spilman session metadata storage.
    pub fn session_spilman_info_handle(&self) -> Arc<RwLock<Option<SessionSpilmanInfo>>> {
        self.session_spilman_info.clone()
    }

    /// Get a snapshot of `(inbound, outbound)` client-side cleartext bytes for this session.
    pub fn local_session_totals(&self) -> (u64, u64) {
        self.cleartext_byte_counters.snapshot()
    }

    /// Clone the per-session cleartext byte counters for passive tracking.
    pub fn cleartext_byte_counters(&self) -> CleartextByteCounters {
        self.cleartext_byte_counters.clone()
    }

    /// Append a driver handle from an intermediate hop in a multi-hop chain.
    pub fn add_driver(&mut self, handle: JoinHandle<()>) {
        self.driver_handles.lock().unwrap().push(handle);
    }

    /// Append an abortable background task associated with this connection.
    pub fn add_task(&mut self, handle: JoinHandle<()>) {
        self.task_handles.lock().unwrap().push(handle);
    }

    /// Move all background driver/task handles from another relay connection
    /// into this one. Used when nested hop setup returns only the final hop but
    /// we still need shutdown of earlier hop tasks to stay attached.
    pub fn absorb_handles_from(&mut self, other: &mut Self) {
        self.driver_handles
            .get_mut()
            .unwrap()
            .append(other.driver_handles.get_mut().unwrap());
        self.task_handles
            .get_mut()
            .unwrap()
            .append(other.task_handles.get_mut().unwrap());
    }

    /// Force-close the hop chain by aborting all background tasks attached to it.
    ///
    /// This is used by callers that only hold `Arc<RelayConnection>` handles and
    /// need to tear down a stale chain after swapping in a rebuilt replacement.
    pub async fn close(&self) {
        let task_handles = {
            let mut handles = self.task_handles.lock().unwrap();
            std::mem::take(&mut *handles)
        };

        for handle in task_handles {
            handle.abort();
            if let Err(e) = handle.await {
                if !e.is_cancelled() {
                    tracing::error!("background task panicked: {e}");
                }
            }
        }

        let driver_handles = {
            let mut handles = self.driver_handles.lock().unwrap();
            std::mem::take(&mut *handles)
        };

        for handle in driver_handles {
            handle.abort();
            if let Err(e) = handle.await {
                if !e.is_cancelled() {
                    tracing::error!("H2 driver task panicked: {e}");
                }
            }
        }
    }

    /// Shut down the hop chain cleanly by dropping the shared H2 client handle
    /// and waiting for all per-hop H2 driver tasks to exit.
    pub async fn shutdown(self) {
        drop(self.h2_client);

        for handle in self.task_handles.into_inner().unwrap() {
            handle.abort();
            if let Err(e) = handle.await {
                if !e.is_cancelled() {
                    tracing::error!("background task panicked: {e}");
                }
            }
        }

        for handle in self.driver_handles.into_inner().unwrap() {
            if let Err(e) = handle.await {
                tracing::error!("H2 driver task panicked: {e}");
            }
        }
    }

    /// Internal: open a CONNECT tunnel with an optional QUIC transport header.
    async fn open_tunnel_inner(
        &self,
        target_authority: &str,
        quic_header: Option<(&str, String)>,
    ) -> io::Result<H2ConnectStream> {
        let mut h2_client = self.clone_send_request().await;

        let uri: Uri = target_authority
            .parse()
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, format!("bad URI: {e}")))?;

        let mut builder = Request::builder().method(Method::CONNECT).uri(uri);

        if let Some((header_name, header_value)) = quic_header {
            builder = builder.header(header_name, header_value);
        }

        let request = builder.body(()).map_err(|e| {
            io::Error::new(io::ErrorKind::InvalidInput, format!("bad request: {e}"))
        })?;

        let (response_future, h2_send) = h2_client
            .send_request(request, false)
            .map_err(|e| io::Error::other(format!("h2 send error: {e}")))?;

        let response = response_future
            .await
            .map_err(|e| io::Error::other(format!("h2 response error: {e}")))?;

        if !response.status().is_success() {
            return Err(io::Error::new(
                io::ErrorKind::ConnectionRefused,
                format!("CONNECT rejected: {}", response.status()),
            ));
        }

        let h2_recv = response.into_body();
        Ok(H2ConnectStream::new(
            h2_send,
            h2_recv,
            Some(self.cleartext_byte_counters.clone()),
        ))
    }
}

fn is_expected_h2_teardown_error(error: &h2::Error) -> bool {
    let message = error.to_string();
    message.contains("sending stopped by peer")
        || message.contains("broken pipe")
        || message.contains("h2 send stream closed")
        || message.contains("h2 recv error: h2 send stream closed")
        || message.contains("h2 recv error: stream closed because of a broken pipe")
        || message.contains("stream closed because of a broken pipe")
        || message.contains("error 0")
        || message.contains("connection closed")
}
