//! Per-client H2 session handler.
//!
//! After the Noise handshake, the server runs an H2 server on the encrypted stream.
//! It accepts H2 streams and routes them:
//!   - CONNECT requests → open TCP to target, bidirectional proxy
//!   - POST /control → control channel (Ping/Pong, future: payments)

use crate::proxy;
use bytes::Bytes;
use h2::server;
use http::{Method, Response, StatusCode};
use paidtor_common::noise::NoiseStream;
use paidtor_common::protocol::{ClientMessage, ServerMessage};
use std::io;
use tokio::net::TcpStream;
use tracing::{debug, error, info, warn};

/// Handle a single client session: run the H2 server and process streams.
pub async fn handle_session(noise_stream: NoiseStream<TcpStream>) -> io::Result<()> {
    let mut h2_conn = server::handshake(noise_stream)
        .await
        .map_err(|e| io::Error::new(io::ErrorKind::Other, format!("h2 handshake error: {e}")))?;

    info!("H2 connection established");

    while let Some(result) = h2_conn.accept().await {
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

                        info!("opening tunnel to {authority}");

                        // Connect to the external target BEFORE spawning the proxy.
                        // This ensures the 200 OK response is sent from this task,
                        // which is the same task driving the H2 connection.
                        match TcpStream::connect(&authority).await {
                            Ok(tcp_stream) => {
                                info!("connected to {authority}");

                                // Send 200 OK
                                let resp = Response::builder()
                                    .status(StatusCode::OK)
                                    .body(())
                                    .unwrap();
                                match respond.send_response(resp, false) {
                                    Ok(h2_send) => {
                                        let (_, h2_recv) = request.into_parts();

                                        // Now spawn the bidirectional proxy
                                        tokio::spawn(async move {
                                            if let Err(e) = proxy::proxy_bidirectional(
                                                h2_send, h2_recv, tcp_stream,
                                            )
                                            .await
                                            {
                                                error!("tunnel to {authority} error: {e}");
                                            }
                                            debug!("tunnel to {authority} closed");
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
                    (&Method::POST, "/control") => {
                        // Send 200 OK from this task (same as CONNECT above)
                        let resp = Response::builder()
                            .status(StatusCode::OK)
                            .body(())
                            .unwrap();
                        match respond.send_response(resp, false) {
                            Ok(h2_send) => {
                                let (_, h2_recv) = request.into_parts();

                                // Spawn control channel handler
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
                            match std::future::poll_fn(|cx| h2_send.poll_capacity(cx)).await {
                                Some(Ok(_)) => {}
                                Some(Err(e)) => {
                                    return Err(io::Error::new(
                                        io::ErrorKind::Other,
                                        format!("h2 capacity error: {e}"),
                                    ));
                                }
                                None => {
                                    return Err(io::Error::new(
                                        io::ErrorKind::BrokenPipe,
                                        "h2 send stream closed",
                                    ));
                                }
                            }

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
                            match std::future::poll_fn(|cx| h2_send.poll_capacity(cx)).await {
                                Some(Ok(_)) => {}
                                _ => break,
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
