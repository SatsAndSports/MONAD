use anyhow::{Context, Result};
use bytes::Bytes;
use h2::server;
use http::{Method, Response, StatusCode};
use monad_noise_secp256k1_proto::{handshake_initiator, handshake_responder, SecpNoiseStream};
use monad_quic::stream::QuicStream;
use monad_quic_npub_proto::{
    build_permissive_client_config, AUTH_STREAM_KIND, EXPORTER_LABEL, STREAM_ERROR_AUTH_REQUIRED,
    STREAM_ERROR_UNKNOWN_KIND,
};
use monad_secp256k1_identity::{transport_auth_digest, TransportKeypair};
use quinn::Endpoint;
use std::net::SocketAddr;
use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc,
};
use tokio::io::AsyncWriteExt;

pub const NOISE_H2_STREAM_KIND: u8 = 0x02;

fn stream_error_code(code: u64) -> quinn::VarInt {
    quinn::VarInt::from_u64(code).expect("valid QUIC application error code")
}

fn reject_stream(send: &mut quinn::SendStream, recv: &mut quinn::RecvStream, code: u64) {
    let code = stream_error_code(code);
    let _ = recv.stop(code);
    let _ = send.reset(code);
}

fn export_binding(conn: &quinn::Connection) -> Result<[u8; monad_quic_npub_proto::EXPORTER_LEN]> {
    let mut exporter = [0u8; monad_quic_npub_proto::EXPORTER_LEN];
    conn.export_keying_material(&mut exporter, EXPORTER_LABEL, b"")
        .map_err(|e| anyhow::anyhow!("failed to export QUIC keying material: {e:?}"))?;
    Ok(exporter)
}

async fn handle_auth_stream(
    conn: &quinn::Connection,
    transport_key: &TransportKeypair,
    authenticated: &AtomicBool,
    send: &mut quinn::SendStream,
    recv: &mut quinn::RecvStream,
) {
    let mut challenge = [0u8; 32];
    if recv.read_exact(&mut challenge).await.is_err() {
        reject_stream(send, recv, monad_quic_npub_proto::STREAM_ERROR_BAD_AUTH);
        return;
    }

    let exporter = match export_binding(conn) {
        Ok(bytes) => bytes,
        Err(_) => {
            reject_stream(send, recv, monad_quic_npub_proto::STREAM_ERROR_BAD_AUTH);
            return;
        }
    };
    let digest = transport_auth_digest(EXPORTER_LABEL, &challenge, &exporter);
    let signature = transport_key.sign_digest(&digest);
    if send.write_all(&signature).await.is_err() {
        return;
    }
    let _ = send.finish();
    authenticated.store(true, Ordering::Release);
}

async fn handle_h2_server(stream: SecpNoiseStream<QuicStream>) -> Result<()> {
    let mut conn = server::handshake(stream).await?;
    while let Some(result) = conn.accept().await {
        let (request, mut respond) = result?;
        match (request.method().clone(), request.uri().path()) {
            (Method::POST, "/control") => {
                let resp = Response::builder().status(StatusCode::OK).body(())?;
                let mut send = respond.send_response(resp, false)?;
                send.send_data(Bytes::from_static(b"pong"), true)?;
            }
            (Method::POST, "/echo") => {
                let (_, mut recv) = request.into_parts();
                let mut body = Vec::new();
                while let Some(chunk) = recv.data().await {
                    body.extend_from_slice(&chunk?);
                }
                let resp = Response::builder().status(StatusCode::OK).body(())?;
                let mut send = respond.send_response(resp, false)?;
                send.send_data(Bytes::from(body), true)?;
            }
            _ => {
                let resp = Response::builder().status(StatusCode::NOT_FOUND).body(())?;
                let _ = respond.send_response(resp, true);
            }
        }
    }
    Ok(())
}

async fn handle_noise_h2_stream(
    authenticated: &AtomicBool,
    transport_key: &TransportKeypair,
    send: quinn::SendStream,
    recv: quinn::RecvStream,
) {
    if !authenticated.load(Ordering::Acquire) {
        let mut send = send;
        let mut recv = recv;
        reject_stream(&mut send, &mut recv, STREAM_ERROR_AUTH_REQUIRED);
        return;
    }

    let mut quic_stream = QuicStream::new(send, recv);
    let (send_cipher, recv_cipher, session_id) =
        match handshake_responder(&mut quic_stream, transport_key).await {
            Ok(v) => v,
            Err(_) => return,
        };
    let noise_stream = SecpNoiseStream::new(quic_stream, send_cipher, recv_cipher, session_id);
    let _ = handle_h2_server(noise_stream).await;
}

async fn handle_proto_stream(
    conn: &quinn::Connection,
    transport_key: &TransportKeypair,
    authenticated: &AtomicBool,
    mut send: quinn::SendStream,
    mut recv: quinn::RecvStream,
) {
    let mut kind = [0u8; 1];
    if recv.read_exact(&mut kind).await.is_err() {
        return;
    }

    match kind[0] {
        AUTH_STREAM_KIND => {
            handle_auth_stream(conn, transport_key, authenticated, &mut send, &mut recv).await;
        }
        NOISE_H2_STREAM_KIND => {
            handle_noise_h2_stream(authenticated, transport_key, send, recv).await;
        }
        _ => reject_stream(&mut send, &mut recv, STREAM_ERROR_UNKNOWN_KIND),
    }
}

async fn handle_connection(conn: quinn::Connection, transport_key: Arc<TransportKeypair>) {
    let authenticated = Arc::new(AtomicBool::new(false));
    while let Ok((send, recv)) = conn.accept_bi().await {
        let conn = conn.clone();
        let transport_key = transport_key.clone();
        let authenticated = authenticated.clone();
        tokio::spawn(async move {
            handle_proto_stream(&conn, &transport_key, &authenticated, send, recv).await;
        });
    }
}

pub async fn start_server() -> Result<(Endpoint, SocketAddr, String)> {
    let transport_key = Arc::new(TransportKeypair::generate());
    let npub = transport_key.npub();
    let km = monad_quic::keygen::generate()?;
    let server_config = monad_quic::server::build_server_config(&km.cert_pem, &km.key_pem)?;
    let endpoint = Endpoint::server(server_config, "127.0.0.1:0".parse()?)?;
    let addr = endpoint.local_addr()?;

    let ep = endpoint.clone();
    tokio::spawn(async move {
        while let Some(incoming) = ep.accept().await {
            let transport_key = transport_key.clone();
            tokio::spawn(async move {
                let conn = match incoming.await {
                    Ok(c) => c,
                    Err(_) => return,
                };
                handle_connection(conn, transport_key).await;
            });
        }
    });

    Ok((endpoint, addr, npub))
}

pub async fn connect(addr: SocketAddr) -> Result<quinn::Connection> {
    let client_config = build_permissive_client_config()?;
    let mut endpoint = Endpoint::client("0.0.0.0:0".parse().unwrap())?;
    endpoint.set_default_client_config(client_config);
    Ok(endpoint.connect(addr, "monad-relay")?.await?)
}

pub async fn open_noise_h2_stream(
    conn: &quinn::Connection,
    server_npub: &str,
) -> Result<SecpNoiseStream<QuicStream>> {
    let (mut send, recv) = conn
        .open_bi()
        .await
        .context("failed to open noise/h2 stream")?;
    send.write_all(&[NOISE_H2_STREAM_KIND]).await?;
    send.flush().await?;
    let mut quic_stream = QuicStream::new(send, recv);
    let (send_cipher, recv_cipher, session_id) =
        handshake_initiator(&mut quic_stream, server_npub).await?;
    Ok(SecpNoiseStream::new(
        quic_stream,
        send_cipher,
        recv_cipher,
        session_id,
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use h2::client;
    use http::Request;
    use monad_quic_npub_proto::authenticate_connection;
    use tokio::time::{timeout, Duration};

    async fn connect_h2_client(
        addr: SocketAddr,
        npub: &str,
    ) -> Result<(client::SendRequest<Bytes>, tokio::task::JoinHandle<()>)> {
        let conn = connect(addr).await?;
        authenticate_connection(&conn, npub).await?;
        let stream = open_noise_h2_stream(&conn, npub).await?;
        let (client, h2_conn) = client::handshake(stream).await?;
        let driver = tokio::spawn(async move {
            h2_conn.await.unwrap();
        });
        Ok((client, driver))
    }

    #[tokio::test]
    async fn test_full_proto_quic_auth_then_noise_then_h2() {
        let (_server, addr, npub) = start_server().await.unwrap();
        let (mut client, driver) = connect_h2_client(addr, &npub).await.unwrap();

        let control_request = Request::builder()
            .method(Method::POST)
            .uri("http://monad/control")
            .body(())
            .unwrap();
        let (control_response_future, _send) = client.send_request(control_request, true).unwrap();
        let control_response = control_response_future.await.unwrap();
        let mut control_recv = control_response.into_body();
        let mut control_buf = Vec::new();
        while let Some(chunk) = control_recv.data().await {
            control_buf.extend_from_slice(&chunk.unwrap());
        }
        assert_eq!(control_buf, b"pong");

        let echo_request = Request::builder()
            .method(Method::POST)
            .uri("http://monad/echo")
            .body(())
            .unwrap();
        let (echo_response_future, mut echo_send) =
            client.send_request(echo_request, false).unwrap();
        echo_send
            .send_data(Bytes::from_static(b"hello full proto"), true)
            .unwrap();
        let echo_response = echo_response_future.await.unwrap();
        assert_eq!(echo_response.status(), StatusCode::OK);
        let mut echo_recv = echo_response.into_body();
        let mut echoed = Vec::new();
        while let Some(chunk) = echo_recv.data().await {
            echoed.extend_from_slice(&chunk.unwrap());
        }
        assert_eq!(echoed, b"hello full proto");
        drop(client);
        driver.abort();
    }

    #[tokio::test]
    async fn test_full_proto_wrong_npub_fails_before_noise() {
        let (_server, addr, _npub) = start_server().await.unwrap();
        let wrong_npub = TransportKeypair::generate().npub();
        let conn = connect(addr).await.unwrap();

        assert!(authenticate_connection(&conn, &wrong_npub).await.is_err());
    }

    #[tokio::test]
    async fn test_full_proto_data_stream_before_auth_rejected() {
        let (_server, addr, npub) = start_server().await.unwrap();
        let conn = connect(addr).await.unwrap();
        let result = timeout(Duration::from_secs(1), open_noise_h2_stream(&conn, &npub)).await;
        assert!(
            result.is_ok(),
            "server did not reject unauthenticated data stream promptly"
        );
        assert!(
            result.unwrap().is_err(),
            "data stream unexpectedly succeeded before auth"
        );
    }

    #[tokio::test]
    async fn test_full_proto_many_noise_h2_streams_after_one_auth() {
        let (_server, addr, npub) = start_server().await.unwrap();
        let conn = connect(addr).await.unwrap();
        authenticate_connection(&conn, &npub).await.unwrap();

        let mut handles = Vec::new();
        for i in 0..8 {
            let conn = conn.clone();
            let npub = npub.clone();
            handles.push(tokio::spawn(async move {
                let stream = open_noise_h2_stream(&conn, &npub).await.unwrap();
                let (mut client, h2_conn) = client::handshake(stream).await.unwrap();
                let driver = tokio::spawn(async move {
                    h2_conn.await.unwrap();
                });

                let payload = format!("many stream {i}");
                let request = Request::builder()
                    .method(Method::POST)
                    .uri("http://monad/echo")
                    .body(())
                    .unwrap();
                let (response_future, mut send) = client.send_request(request, false).unwrap();
                send.send_data(Bytes::from(payload.clone()), true).unwrap();
                let response = response_future.await.unwrap();
                let mut recv = response.into_body();
                let mut echoed = Vec::new();
                while let Some(chunk) = recv.data().await {
                    echoed.extend_from_slice(&chunk.unwrap());
                }
                assert_eq!(echoed, payload.as_bytes());
                drop(client);
                driver.abort();
            }));
        }

        for handle in handles {
            handle.await.unwrap();
        }
    }
}
