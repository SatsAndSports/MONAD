//! Per-client H2 session handler.
//!
//! After the Noise handshake, the server runs an H2 server on the encrypted stream.
//! It accepts H2 streams and routes them:
//!   - CONNECT requests → open TCP (or QUIC) connection to target, bidirectional proxy
//!   - POST /control → control channel (Ping/Pong, future: payments)

use crate::proxy;
use crate::quic_pool::QuicPool;
use bytes::Bytes;
use h2::server;
use http::{Method, Response, StatusCode};
use monad_common::h2stream::wait_for_send_capacity;
use monad_common::noise::NoiseStream;
use monad_common::protocol::{ClientMessage, ServerMessage};
use std::io;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::TcpStream;
use tracing::{debug, error, info, warn};

/// Custom header name for QUIC pinned public key in CONNECT requests.
///
/// When present on a CONNECT request, the server connects to the target
/// via QUIC instead of TCP, authenticating the target with this pinned key.
pub const QUIC_PIN_HEADER: &str = "quic-pin";

/// An inbound relay session: an H2 server connection running over an
/// encrypted `NoiseStream`.
///
/// Created from a `NoiseStream` after the Noise NK handshake. Call
/// [`run`](Self::run) to start the accept loop that dispatches CONNECT
/// and control requests.
pub struct RelaySession<T: AsyncRead + AsyncWrite + Unpin + Send + 'static> {
    h2_conn: server::Connection<NoiseStream<T>, Bytes>,
    quic_pool: Option<QuicPool>,
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

        Ok(Self { h2_conn, quic_pool })
    }

    /// Run the accept loop: accept H2 streams and dispatch them to handlers.
    ///
    /// Returns when the H2 connection closes (client disconnects or error).
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

                            // Check for quic-pin header → QUIC transport
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
                                                tokio::spawn(async move {
                                                    if let Err(e) = proxy::proxy_bidirectional(
                                                        h2_send, h2_recv, quic_stream, &label,
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
                                // Plain TCP CONNECT
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
                                                tokio::spawn(async move {
                                                    if let Err(e) = proxy::proxy_bidirectional(
                                                        h2_send, h2_recv, tcp_stream, &authority,
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
                            let resp = Response::builder()
                                .status(StatusCode::OK)
                                .body(())
                                .unwrap();
                            match respond.send_response(resp, false) {
                                Ok(h2_send) => {
                                    let (_, h2_recv) = request.into_parts();
                                    tokio::spawn(async move {
                                        if let Err(e) =
                                            handle_control_stream(h2_send, h2_recv).await
                                        {
                                            error!("control channel error: {e}");
                                        }
                                    });
                                }
                                Err(e) => {
                                    error!("h2 send response error for control: {e}");
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

/// Handle a control channel stream.
///
/// Reads JSON-encoded ClientMessage frames, responds with ServerMessage frames.
/// Currently supports Ping → Pong. Future: payment tokens, session management.
async fn handle_control_stream(
    mut h2_send: h2::SendStream<Bytes>,
    mut h2_recv: h2::RecvStream,
) -> io::Result<()> {
    info!("control channel opened");

    let mut buf = Vec::new();

    loop {
        match h2_recv.data().await {
            Some(Ok(data)) => {
                let len = data.len();
                let _ = h2_recv.flow_control().release_capacity(len);

                buf.extend_from_slice(&data);

                // Process all complete newline-delimited JSON messages
                while let Some(newline_pos) = buf.iter().position(|&b| b == b'\n') {
                    let line: Vec<u8> = buf.drain(..=newline_pos).collect();
                    let line = line.trim_ascii();

                    if line.is_empty() {
                        continue;
                    }

                    match serde_json::from_slice::<ClientMessage>(line) {
                        Ok(msg) => {
                            debug!("control recv: {msg:?}");
                            let response = match msg {
                                ClientMessage::Ping => ServerMessage::Pong,
                            };

                            let response_bytes = serde_json::to_vec(&response).map_err(|e| {
                                io::Error::new(io::ErrorKind::Other, format!("json error: {e}"))
                            })?;

                            let mut frame = Vec::with_capacity(response_bytes.len() + 1);
                            frame.extend_from_slice(&response_bytes);
                            frame.push(b'\n');

                            h2_send.reserve_capacity(frame.len());
                            wait_for_send_capacity(&mut h2_send).await?;

                            h2_send.send_data(Bytes::from(frame), false).map_err(|e| {
                                io::Error::new(io::ErrorKind::Other, format!("h2 send error: {e}"))
                            })?;

                            debug!("control sent: {response:?}");
                        }
                        Err(e) => {
                            warn!("control: invalid message: {e}");
                            let err_msg = ServerMessage::Error {
                                message: format!("invalid message: {e}"),
                            };
                            let err_bytes = serde_json::to_vec(&err_msg).unwrap();
                            let mut frame = Vec::with_capacity(err_bytes.len() + 1);
                            frame.extend_from_slice(&err_bytes);
                            frame.push(b'\n');

                            h2_send.reserve_capacity(frame.len());
                            if wait_for_send_capacity(&mut h2_send).await.is_err() {
                                break;
                            }

                            let _ = h2_send.send_data(Bytes::from(frame), false);
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

    let _ = h2_send.send_data(Bytes::new(), true);
    info!("control channel closed");
    Ok(())
}
