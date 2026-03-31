//! Per-client H2 session handler.
//!
//! After the Noise handshake, the server runs an H2 server on the encrypted stream.
//! It accepts H2 streams and routes them:
//!   - CONNECT requests → open TCP to target, bidirectional proxy
//!   - POST /control → control channel (stub for now)

use crate::proxy;
use bytes::Bytes;
use h2::server;
use http::{Method, Response, StatusCode};
use paidtor_common::noise::NoiseStream;
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
        let (request, mut respond) = match result {
            Ok(pair) => pair,
            Err(e) => {
                error!("h2 accept error: {e}");
                break;
            }
        };

        let method = request.method().clone();
        let uri = request.uri().clone();

        debug!("received H2 request: {method} {uri}");

        match method {
            Method::CONNECT => {
                // Extract target from URI authority (e.g., "example.com:443")
                let authority = match uri.authority() {
                    Some(auth) => auth.to_string(),
                    None => {
                        warn!("CONNECT request missing authority");
                        let response = Response::builder()
                            .status(StatusCode::BAD_REQUEST)
                            .body(())
                            .unwrap();
                        let _ = respond.send_response(response, true);
                        continue;
                    }
                };

                // Spawn a task to handle this tunnel
                tokio::spawn(async move {
                    if let Err(e) = handle_connect(authority, request, respond).await {
                        error!("tunnel error: {e}");
                    }
                });
            }
            _ => {
                // For now, reject anything that isn't CONNECT
                // (control channel can be added later)
                warn!("unsupported method: {method}");
                let response = Response::builder()
                    .status(StatusCode::METHOD_NOT_ALLOWED)
                    .body(())
                    .unwrap();
                let _ = respond.send_response(response, true);
            }
        }
    }

    info!("H2 connection closed");
    Ok(())
}

/// Handle a CONNECT tunnel request.
async fn handle_connect(
    target: String,
    request: http::Request<h2::RecvStream>,
    mut respond: h2::server::SendResponse<Bytes>,
) -> io::Result<()> {
    info!("opening tunnel to {target}");

    // Connect to the external target
    let tcp_stream = match TcpStream::connect(&target).await {
        Ok(stream) => {
            info!("connected to {target}");
            stream
        }
        Err(e) => {
            warn!("failed to connect to {target}: {e}");
            let response = Response::builder()
                .status(StatusCode::BAD_GATEWAY)
                .body(())
                .unwrap();
            let _ = respond.send_response(response, true);
            return Err(e);
        }
    };

    // Send 200 OK to indicate the tunnel is established
    let response = Response::builder()
        .status(StatusCode::OK)
        .body(())
        .unwrap();
    let h2_send = respond
        .send_response(response, false)
        .map_err(|e| io::Error::new(io::ErrorKind::Other, format!("h2 send response error: {e}")))?;

    // Get the recv stream from the request body
    let (_, h2_recv) = request.into_parts();

    // Bidirectional proxy between H2 stream and external TCP
    proxy::proxy_bidirectional(h2_send, h2_recv, tcp_stream).await
}
