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
use tokio::task::JoinHandle;

use crate::h2stream::H2ConnectStream;
use crate::noise::NoiseStream;

/// An established connection to a MONAD relay, ready to open H2 streams.
///
/// Created by performing a Noise NK handshake followed by an H2 client
/// handshake. For multi-hop chains, each intermediate hop adds a driver
/// handle via [`add_driver`](Self::add_driver).
pub struct RelayConnection {
    /// The H2 client send handle — cloned for each new stream.
    h2_client: Arc<tokio::sync::Mutex<client::SendRequest<Bytes>>>,
    /// Background tasks driving the H2 connection(s) in the hop chain.
    driver_handles: Vec<JoinHandle<()>>,
    /// Abortable background tasks associated with this relay connection, such as
    /// client-side control stream tasks.
    task_handles: Vec<JoinHandle<()>>,
}

impl RelayConnection {
    /// Perform an H2 client handshake over an established `NoiseStream`.
    ///
    /// Returns a `RelayConnection` (with no driver handles yet) and the
    /// `JoinHandle` for the spawned H2 connection driver. The caller is
    /// responsible for attaching the driver via [`add_driver`](Self::add_driver)
    /// — either to this connection or, during multi-hop chain building, to
    /// the final connection in the chain.
    pub async fn from_noise_stream<T>(
        noise_stream: NoiseStream<T>,
    ) -> io::Result<(Self, JoinHandle<()>)>
    where
        T: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static,
    {
        let (h2_client, h2_conn) = client::handshake(noise_stream)
            .await
            .map_err(|e| {
                io::Error::new(io::ErrorKind::Other, format!("h2 handshake error: {e}"))
            })?;

        let driver_handle = tokio::spawn(async move {
            if let Err(e) = h2_conn.await {
                tracing::error!("H2 connection error at hop: {e}");
            }
        });

        let conn = Self {
            h2_client: Arc::new(tokio::sync::Mutex::new(h2_client)),
            driver_handles: Vec::new(),
            task_handles: Vec::new(),
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

    /// Open an H2 CONNECT tunnel with a `quic-pin` header, telling the relay
    /// to reach the target via QUIC instead of TCP.
    pub async fn open_tunnel_quic(
        &self,
        target_authority: &str,
        pin: &[u8],
    ) -> io::Result<H2ConnectStream> {
        self.open_tunnel_inner(target_authority, Some(pin)).await
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
            .map_err(|e| {
                io::Error::new(io::ErrorKind::Other, format!("h2 send error: {e}"))
            })?;

        let response = response_future
            .await
            .map_err(|e| {
                io::Error::new(io::ErrorKind::Other, format!("h2 response error: {e}"))
            })?;

        if !response.status().is_success() {
            return Err(io::Error::new(
                io::ErrorKind::ConnectionRefused,
                format!("control stream rejected: {}", response.status()),
            ));
        }

        Ok((h2_send, response.into_body()))
    }

    /// Append a driver handle from an intermediate hop in a multi-hop chain.
    pub fn add_driver(&mut self, handle: JoinHandle<()>) {
        self.driver_handles.push(handle);
    }

    /// Append an abortable background task associated with this connection.
    pub fn add_task(&mut self, handle: JoinHandle<()>) {
        self.task_handles.push(handle);
    }

    /// Shut down the hop chain cleanly by dropping the shared H2 client handle
    /// and waiting for all per-hop H2 driver tasks to exit.
    pub async fn shutdown(self) {
        drop(self.h2_client);

        for handle in self.task_handles {
            handle.abort();
            if let Err(e) = handle.await {
                if !e.is_cancelled() {
                    tracing::error!("background task panicked: {e}");
                }
            }
        }

        for handle in self.driver_handles {
            if let Err(e) = handle.await {
                tracing::error!("H2 driver task panicked: {e}");
            }
        }
    }

    /// Internal: open a CONNECT tunnel with an optional `quic-pin` header.
    async fn open_tunnel_inner(
        &self,
        target_authority: &str,
        quic_pin: Option<&[u8]>,
    ) -> io::Result<H2ConnectStream> {
        let mut h2_client = self.clone_send_request().await;

        let uri: Uri = target_authority
            .parse()
            .map_err(|e| {
                io::Error::new(io::ErrorKind::InvalidInput, format!("bad URI: {e}"))
            })?;

        let mut builder = Request::builder()
            .method(Method::CONNECT)
            .uri(uri);

        if let Some(pin) = quic_pin {
            builder = builder.header("quic-pin", hex::encode(pin));
        }

        let request = builder
            .body(())
            .map_err(|e| {
                io::Error::new(io::ErrorKind::InvalidInput, format!("bad request: {e}"))
            })?;

        let (response_future, h2_send) = h2_client
            .send_request(request, false)
            .map_err(|e| {
                io::Error::new(io::ErrorKind::Other, format!("h2 send error: {e}"))
            })?;

        let response = response_future
            .await
            .map_err(|e| {
                io::Error::new(io::ErrorKind::Other, format!("h2 response error: {e}"))
            })?;

        if !response.status().is_success() {
            return Err(io::Error::new(
                io::ErrorKind::ConnectionRefused,
                format!("CONNECT rejected: {}", response.status()),
            ));
        }

        let h2_recv = response.into_body();
        Ok(H2ConnectStream::new(h2_send, h2_recv))
    }
}
