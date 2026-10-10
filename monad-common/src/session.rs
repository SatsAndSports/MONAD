//! Session types for MONAD relay connections.
//!
//! `RelayConnection` is the client-side handle to an established Noise+H2
//! session with a MONAD relay. It wraps the H2 client machinery and exposes
//! high-level methods for opening tunnels and control streams.

use bytes::Bytes;
use h2::client;
use http::{Method, Request, Uri};
use std::collections::BTreeSet;
use std::io;
use std::sync::Arc;
use std::sync::Mutex;
use tokio::sync::{watch, RwLock};
use tokio::task::JoinHandle;

use crate::blinded_connect::{BlindedConnectRequest, BLINDED_HOP_CONNECT_AUTHORITY};
use crate::h2stream::{H2ConnectStream, MAX_H2_HEADER_LIST_SIZE};
use crate::proxy::CleartextByteCounters;

// ---------------------------------------------------------------------------
// SessionPricing — validated directional session rates
// ---------------------------------------------------------------------------

/// Local session pricing metadata, persisted on both client and relay.
///
/// Constructed from validated configuration or the wire `SessionStatus` message.
/// Amount-due calculations use exact integer quotient/remainder arithmetic.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SessionPricing {
    pub in_bytes_per_millisat: u64,
    pub out_bytes_per_millisat: u64,
}

/// Spilman session metadata fetched by the client after receiving `SessionStatus`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SessionSpilmanInfo {
    pub receiver_pubkey: String,
    pub mint_url: String,
    pub unit: String,
    pub keyset_id: String,
    pub keyset_info_json: String,
    pub cashu_spilman_protocol_version: Option<String>,
    pub cashu_spilman_keyset_versions: Option<BTreeSet<String>>,
}

impl SessionPricing {
    /// Create validated `SessionPricing` from raw directional rates.
    pub fn try_new(
        in_bytes_per_millisat: u64,
        out_bytes_per_millisat: u64,
    ) -> Result<Self, crate::billing::PricingError> {
        crate::billing::amount_due_millisats(0, 0, in_bytes_per_millisat, out_bytes_per_millisat)?;
        Ok(Self {
            in_bytes_per_millisat,
            out_bytes_per_millisat,
        })
    }

    /// Create `SessionPricing` from rates already validated by configuration or
    /// test setup. Use [`Self::try_new`] for untrusted wire input.
    pub fn new(in_bytes_per_millisat: u64, out_bytes_per_millisat: u64) -> Self {
        Self::try_new(in_bytes_per_millisat, out_bytes_per_millisat)
            .expect("session pricing rates must be positive")
    }

    /// Compute the total amount due in millisats for the given byte totals.
    ///
    /// Uses the formula:
    /// `ceil(in_bytes / in_bytes_per_millisat + out_bytes / out_bytes_per_millisat)`
    ///
    /// Implemented with exact integer quotient/remainder arithmetic.
    pub fn amount_due_millisats(
        &self,
        session_total_bytes_in: u64,
        session_total_bytes_out: u64,
    ) -> u128 {
        crate::billing::amount_due_millisats(
            session_total_bytes_in,
            session_total_bytes_out,
            self.in_bytes_per_millisat,
            self.out_bytes_per_millisat,
        )
        .expect("SessionPricing rates are validated positive")
    }

    /// Compute exact remaining session credit for the given totals.
    pub fn remaining_milli_sats(
        &self,
        total_paid_millisats: u64,
        session_total_bytes_in: u64,
        session_total_bytes_out: u64,
    ) -> i128 {
        total_paid_millisats as i128
            - self.amount_due_millisats(session_total_bytes_in, session_total_bytes_out) as i128
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
    close_lock: tokio::sync::Mutex<()>,
    /// Noise handshake hash — unique session identifier agreed by both sides.
    session_id: [u8; 32],
    /// Session pricing metadata, set by the control task after receiving
    /// `SessionStatus` from the relay.
    session_pricing: Arc<RwLock<Option<SessionPricing>>>,
    /// Spilman mint/keyset info fetched by the client for this session.
    session_spilman_info: Arc<RwLock<Option<SessionSpilmanInfo>>>,
    /// Bootstrap-negotiated Cashu Spilman protocol version for this session.
    cashu_spilman_protocol_version: Arc<RwLock<Option<String>>>,
    /// Bootstrap-negotiated Cashu Spilman keyset-format versions for this session.
    cashu_spilman_keyset_versions: Arc<RwLock<Option<BTreeSet<String>>>>,
    /// Client-side cleartext byte counters for this relay session.
    /// Semantics intentionally mirror the relay's `session_total_bytes_in/out`
    /// billing counters for CONNECT payload bytes and are read by the client
    /// session driver when estimating current spend between relay status updates
    /// and sizing proactive payments.
    cleartext_byte_counters: CleartextByteCounters,
    /// Watch receivers that flip to true when a funded hop's session driver
    /// terminates. The runtime uses these to detect when the route needs
    /// rebuilding and to identify the failed hop.
    failure_watchers: Mutex<Vec<(usize, watch::Receiver<bool>)>>,
}

impl RelayConnection {
    pub async fn from_transport_stream<T>(
        stream: T,
        session_id: [u8; 32],
    ) -> io::Result<(Self, JoinHandle<()>)>
    where
        T: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static,
    {
        // Return connection-level receive capacity as soon as DATA frames are
        // buffered, while stream-level capacity stays reserved until each
        // stream is consumed. A paused CONNECT tunnel may therefore fill its
        // own stream window without starving the shared connection window the
        // control stream needs for payments.
        let (h2_client, h2_conn) = client::Builder::new()
            .max_header_list_size(MAX_H2_HEADER_LIST_SIZE)
            .recv_release_connection_on_buffer(true)
            .handshake(stream)
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
            close_lock: tokio::sync::Mutex::new(()),
            session_id,
            session_pricing: Arc::new(RwLock::new(None)),
            session_spilman_info: Arc::new(RwLock::new(None)),
            cashu_spilman_protocol_version: Arc::new(RwLock::new(None)),
            cashu_spilman_keyset_versions: Arc::new(RwLock::new(None)),
            cleartext_byte_counters: CleartextByteCounters::default(),
            failure_watchers: Mutex::new(Vec::new()),
        };

        Ok((conn, driver_handle))
    }

    /// Open an H2 CONNECT tunnel to the given target authority.
    ///
    /// Returns an `H2ConnectStream` that implements `AsyncRead + AsyncWrite`,
    /// suitable for running a nested Noise+H2 session on top.
    pub async fn open_tunnel(&self, target_authority: &str) -> io::Result<H2ConnectStream> {
        self.open_tunnel_with_headers(target_authority, &[]).await
    }

    /// Open an H2 CONNECT tunnel with a `quic-secp256k1-pubkey` header, telling the relay
    /// to reach the target via QUIC and authenticate the connection using the
    /// provided x-only secp256k1 public key.
    pub async fn open_tunnel_quic_secp256k1(
        &self,
        target_authority: &str,
        pubkey_hex: &str,
    ) -> io::Result<H2ConnectStream> {
        let headers = [("quic-secp256k1-pubkey", pubkey_hex.to_owned())];
        self.open_tunnel_with_headers(target_authority, &headers)
            .await
    }

    /// Open an H2 CONNECT tunnel carrying a blinded-hop descriptor in headers.
    pub async fn open_tunnel_blinded_hop(
        &self,
        request: &BlindedConnectRequest,
    ) -> io::Result<H2ConnectStream> {
        let headers = request.header_pairs();
        self.open_tunnel_with_headers(BLINDED_HOP_CONNECT_AUTHORITY, &headers)
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

    pub async fn cashu_spilman_protocol_version(&self) -> Option<String> {
        self.cashu_spilman_protocol_version.read().await.clone()
    }

    pub async fn set_cashu_spilman_protocol_version(&self, version: Option<String>) {
        *self.cashu_spilman_protocol_version.write().await = version;
    }

    pub async fn cashu_spilman_keyset_versions(&self) -> Option<BTreeSet<String>> {
        self.cashu_spilman_keyset_versions.read().await.clone()
    }

    pub async fn set_cashu_spilman_keyset_versions(&self, versions: Option<BTreeSet<String>>) {
        *self.cashu_spilman_keyset_versions.write().await = versions;
    }

    /// Get a shared handle to the Spilman session metadata storage.
    pub fn session_spilman_info_handle(&self) -> Arc<RwLock<Option<SessionSpilmanInfo>>> {
        self.session_spilman_info.clone()
    }

    pub fn cashu_spilman_protocol_version_handle(&self) -> Arc<RwLock<Option<String>>> {
        self.cashu_spilman_protocol_version.clone()
    }

    pub fn cashu_spilman_keyset_versions_handle(&self) -> Arc<RwLock<Option<BTreeSet<String>>>> {
        self.cashu_spilman_keyset_versions.clone()
    }

    /// Get a snapshot of `(inbound, outbound)` client-side cleartext bytes for this session.
    ///
    /// This is primarily useful for tests and diagnostics; the client payment
    /// driver reads the same counters directly when estimating local spend and
    /// sizing payments.
    pub fn local_session_totals(&self) -> (u64, u64) {
        self.cleartext_byte_counters.snapshot()
    }

    /// Clone the per-session cleartext byte counters for local spend estimation
    /// and payment sizing.
    pub fn cleartext_byte_counters(&self) -> CleartextByteCounters {
        self.cleartext_byte_counters.clone()
    }

    /// Append a driver handle from an intermediate hop in a multi-hop chain.
    pub fn add_driver(&mut self, handle: JoinHandle<()>) {
        self.driver_handles.lock().unwrap().push(handle);
    }

    /// Append an abortable background task associated with this connection.
    pub fn add_task(&self, handle: JoinHandle<()>) {
        self.task_handles.lock().unwrap().push(handle);
    }

    /// Register a watch receiver that signals when a funded hop's session
    /// driver has terminated. The runtime can await any of these to detect
    /// route failure.
    pub fn add_failure_watcher(&self, hop_idx: usize, rx: watch::Receiver<bool>) {
        self.failure_watchers.lock().unwrap().push((hop_idx, rx));
    }

    /// Return whether this connection has funded-hop failure watchers.
    pub fn has_failure_watchers(&self) -> bool {
        !self.failure_watchers.lock().unwrap().is_empty()
    }

    /// Wait until a registered failure watcher signals true or loses its sender.
    /// Returns immediately with `None` if there are no watchers.
    pub async fn wait_for_failure(&self) -> Option<usize> {
        let watchers: Vec<_> = {
            let guards = self.failure_watchers.lock().unwrap();
            guards.iter().cloned().collect()
        };
        if watchers.is_empty() {
            return None;
        }

        Some(wait_for_watcher_failure(watchers).await)
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
        self.failure_watchers
            .get_mut()
            .unwrap()
            .append(other.failure_watchers.get_mut().unwrap());
    }

    /// Force-close the hop chain by aborting all background tasks attached to it.
    ///
    /// This is used by callers that only hold `Arc<RelayConnection>` handles and
    /// need to tear down a stale chain after swapping in a rebuilt replacement.
    pub async fn close(&self) {
        use std::future::Future;
        use std::task::Poll;

        let _guard = self.close_lock.lock().await;
        for handles in [&self.task_handles, &self.driver_handles] {
            for handle in handles.lock().unwrap().iter() {
                handle.abort();
            }
        }
        // Keep pending handles owned by the connection even if close itself is
        // cancelled. A later close must still await a blocking wallet call.
        std::future::poll_fn(|cx| {
            let mut pending = false;
            for handles in [&self.task_handles, &self.driver_handles] {
                handles.lock().unwrap().retain_mut(|handle| {
                    match std::pin::Pin::new(handle).poll(cx) {
                        Poll::Pending => {
                            pending = true;
                            true
                        }
                        Poll::Ready(result) => {
                            if let Err(e) = result {
                                if !e.is_cancelled() {
                                    tracing::error!("connection task panicked: {e}");
                                }
                            }
                            false
                        }
                    }
                });
            }
            if pending {
                Poll::Pending
            } else {
                Poll::Ready(())
            }
        })
        .await;
    }

    /// Shut down the hop chain by aborting background tasks attached to it.
    pub async fn shutdown(&self) {
        self.close().await;
    }

    /// Internal: open a CONNECT tunnel with arbitrary extra headers.
    pub async fn open_tunnel_with_headers(
        &self,
        target_authority: &str,
        extra_headers: &[(&'static str, String)],
    ) -> io::Result<H2ConnectStream> {
        if target_authority != BLINDED_HOP_CONNECT_AUTHORITY {
            crate::network_endpoint::validate_network_endpoint(target_authority)?;
        }
        let mut h2_client = self.clone_send_request().await;

        let uri: Uri = target_authority
            .parse()
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, format!("bad URI: {e}")))?;

        let mut builder = Request::builder().method(Method::CONNECT).uri(uri);

        for (header_name, header_value) in extra_headers {
            builder = builder.header(*header_name, header_value);
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
            return Err(crate::rejection::connect_error(
                response.status(),
                response.headers(),
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

async fn wait_for_watcher_failure(watchers: Vec<(usize, watch::Receiver<bool>)>) -> usize {
    use std::future::Future;
    use std::task::Poll;

    // These futures belong to the caller: suffix rebuild cancellation must not
    // leave tasks watching the surviving prefix. Sender loss also means failure.
    let mut waits: Vec<_> = watchers
        .into_iter()
        .map(|(hop, mut rx)| {
            Box::pin(async move {
                loop {
                    if *rx.borrow_and_update() || rx.changed().await.is_err() {
                        return hop;
                    }
                }
            })
        })
        .collect();
    std::future::poll_fn(|cx| {
        for wait in &mut waits {
            if let Poll::Ready(hop) = wait.as_mut().poll(cx) {
                return Poll::Ready(hop);
            }
        }
        Poll::Pending
    })
    .await
}

impl Drop for RelayConnection {
    fn drop(&mut self) {
        // Fallback only: callers needing quiescence must await close().
        for handle in self
            .task_handles
            .get_mut()
            .unwrap()
            .iter()
            .chain(self.driver_handles.get_mut().unwrap().iter())
        {
            handle.abort();
        }
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

#[cfg(test)]
mod pricing_tests {
    use super::SessionPricing;

    #[test]
    fn checked_pricing_rejects_zero_rates() {
        assert!(SessionPricing::try_new(0, 1).is_err());
        assert!(SessionPricing::try_new(1, 0).is_err());
        assert!(SessionPricing::try_new(0, 0).is_err());
        assert!(SessionPricing::try_new(1, 1).is_ok());
    }

    #[test]
    fn pricing_reports_exact_combined_due() {
        let pricing = SessionPricing::try_new(3, 3).unwrap();
        assert_eq!(pricing.amount_due_millisats(5, 5), 4);
        assert_eq!(pricing.remaining_milli_sats(10, 5, 5), 6);
    }
}

#[cfg(test)]
mod failure_watcher_tests {
    use super::wait_for_watcher_failure;
    use tokio::sync::watch;

    #[tokio::test]
    async fn already_failed_and_closed_watchers_are_failures() {
        let (_tx, rx) = watch::channel(true);
        assert_eq!(wait_for_watcher_failure(vec![(3, rx)]).await, 3);
        let (tx, rx) = watch::channel(false);
        drop(tx);
        assert_eq!(wait_for_watcher_failure(vec![(7, rx)]).await, 7);
    }

    #[tokio::test]
    async fn cancelling_wait_releases_all_prefix_watchers() {
        use std::future::Future;
        use std::task::Poll;

        let (tx, rx) = watch::channel(false);
        for _ in 0..32 {
            let mut wait = Box::pin(wait_for_watcher_failure(vec![(0, rx.clone())]));
            std::future::poll_fn(|cx| {
                assert!(wait.as_mut().poll(cx).is_pending());
                Poll::Ready(())
            })
            .await;
            assert_eq!(tx.receiver_count(), 2);
            drop(wait);
            assert_eq!(tx.receiver_count(), 1);
        }
    }
}
