//! Integration test: exercises the full PaidTor stack.
//!
//! Spins up three components in a single tokio runtime:
//!   1. An "uppercase" TCP server (simulates an external target)
//!   2. A PaidTor server (Noise NK + H2)
//!   3. A test client that opens both a control channel and a data tunnel
//!
//! Validates:
//!   - Noise NK handshake and encrypted transport
//!   - H2 multiplexing: control + data streams coexisting
//!   - Control channel: Ping → Pong round-trip
//!   - Data channel: CONNECT → proxy → uppercase server → response

use bytes::Bytes;
use h2::client;
use http::{Method, Request};
use paidtor_common::noise::{self, NoiseStream};
use paidtor_common::protocol::{ClientMessage, ServerMessage};
use paidtor_server::listener::ServerConfig;
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

// ---------------------------------------------------------------------------
// Test helpers
// ---------------------------------------------------------------------------

/// A simple TCP server that reads data, converts it to uppercase, writes it back.
async fn run_uppercase_server(listener: TcpListener) {
    loop {
        let (mut stream, _) = match listener.accept().await {
            Ok(conn) => conn,
            Err(_) => break,
        };

        tokio::spawn(async move {
            let mut buf = vec![0u8; 4096];
            loop {
                match stream.read(&mut buf).await {
                    Ok(0) => break,
                    Ok(n) => {
                        let upper: Vec<u8> = buf[..n]
                            .iter()
                            .map(|b| b.to_ascii_uppercase())
                            .collect();
                        if stream.write_all(&upper).await.is_err() {
                            break;
                        }
                    }
                    Err(_) => break,
                }
            }
        });
    }
}

/// Spin up a PaidTor server and return (server_addr, pubkey).
async fn start_paidtor_server() -> (std::net::SocketAddr, Vec<u8>) {
    let (privkey, pubkey) = noise::generate_keypair();

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();

    let config = Arc::new(ServerConfig {
        private_key: privkey,
    });

    tokio::spawn(paidtor_server::listener::run(listener, config));

    (addr, pubkey)
}

/// Connect to a PaidTor server and return an H2 client handle.
async fn connect_client(
    server_addr: std::net::SocketAddr,
    pubkey: &[u8],
) -> client::SendRequest<Bytes> {
    let mut tcp = TcpStream::connect(server_addr).await.unwrap();
    let transport = noise::handshake_initiator(&mut tcp, pubkey)
        .await
        .unwrap();
    let noise_stream = NoiseStream::new(tcp, transport);

    let (h2_client, h2_conn) = client::handshake(noise_stream).await.unwrap();

    tokio::spawn(async move {
        if let Err(e) = h2_conn.await {
            eprintln!("H2 connection error: {e}");
        }
    });

    h2_client
}

/// Open a CONNECT tunnel, send payload, read response.
async fn tunnel_roundtrip(
    h2_client: &mut client::SendRequest<Bytes>,
    target_authority: &str,
    payload: &[u8],
) -> Vec<u8> {
    let request = Request::builder()
        .method(Method::CONNECT)
        .uri(target_authority)
        .body(())
        .unwrap();

    let (response_future, mut h2_send) = h2_client.send_request(request, false).unwrap();

    let response = response_future.await.unwrap();
    assert!(
        response.status().is_success(),
        "CONNECT failed: {}",
        response.status()
    );

    let mut h2_recv = response.into_body();

    // Send payload and close our send side
    h2_send.reserve_capacity(payload.len());
    std::future::poll_fn(|cx| h2_send.poll_capacity(cx))
        .await
        .expect("stream closed")
        .expect("capacity error");
    h2_send
        .send_data(Bytes::copy_from_slice(payload), true)
        .unwrap();

    // Read the response
    let mut result = Vec::new();
    while let Some(chunk) = h2_recv.data().await {
        let data = chunk.unwrap();
        let len = data.len();
        let _ = h2_recv.flow_control().release_capacity(len);
        result.extend_from_slice(&data);
    }

    result
}

/// Send a Ping on the control channel and assert we get a Pong back.
async fn control_ping_pong(h2_client: &mut client::SendRequest<Bytes>) {
    let request = Request::builder()
        .method(Method::POST)
        .uri("http://paidtor/control")
        .body(())
        .unwrap();

    let (response_future, mut h2_send) = h2_client.send_request(request, false).unwrap();

    let response = response_future.await.unwrap();
    assert!(
        response.status().is_success(),
        "control channel rejected: {}",
        response.status()
    );

    let mut h2_recv = response.into_body();

    // Send Ping (newline-delimited JSON)
    let ping = serde_json::to_vec(&ClientMessage::Ping).unwrap();
    let mut frame = Vec::with_capacity(ping.len() + 1);
    frame.extend_from_slice(&ping);
    frame.push(b'\n');

    h2_send.reserve_capacity(frame.len());
    std::future::poll_fn(|cx| h2_send.poll_capacity(cx))
        .await
        .expect("stream closed")
        .expect("capacity error");
    h2_send
        .send_data(Bytes::from(frame), true)
        .unwrap();

    // Read Pong
    let mut response_buf = Vec::new();
    while let Some(chunk) = h2_recv.data().await {
        let data = chunk.unwrap();
        let len = data.len();
        let _ = h2_recv.flow_control().release_capacity(len);
        response_buf.extend_from_slice(&data);
    }

    let response_str = String::from_utf8(response_buf).unwrap();
    let first_line = response_str
        .lines()
        .next()
        .expect("no response from control channel");
    let msg: ServerMessage = serde_json::from_str(first_line).unwrap();

    match msg {
        ServerMessage::Pong => {}
        other => panic!("expected Pong, got: {other:?}"),
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

/// Test both the control channel (Ping/Pong) and a data tunnel (uppercase)
/// sequentially over the same H2 connection.
#[tokio::test]
async fn test_control_and_data_channels() {
    // Uppercase server
    let upper_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let upper_addr = upper_listener.local_addr().unwrap();
    tokio::spawn(run_uppercase_server(upper_listener));

    // PaidTor server
    let (server_addr, pubkey) = start_paidtor_server().await;

    // Client
    let mut h2 = connect_client(server_addr, &pubkey).await;

    // Control channel: Ping/Pong
    control_ping_pong(&mut h2).await;

    // Data channel: CONNECT → uppercase
    let target = format!("127.0.0.1:{}", upper_addr.port());
    let result = tunnel_roundtrip(&mut h2, &target, b"hello world").await;
    assert_eq!(result, b"HELLO WORLD");
}

/// Test control and data channels running concurrently over the same connection.
#[tokio::test]
async fn test_concurrent_channels() {
    let upper_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let upper_addr = upper_listener.local_addr().unwrap();
    tokio::spawn(run_uppercase_server(upper_listener));

    let (server_addr, pubkey) = start_paidtor_server().await;
    let h2 = connect_client(server_addr, &pubkey).await;

    let target = format!("127.0.0.1:{}", upper_addr.port());

    let mut h2_for_control = h2.clone();
    let control_task = tokio::spawn(async move {
        control_ping_pong(&mut h2_for_control).await;
    });

    let mut h2_for_data = h2.clone();
    let data_task = tokio::spawn(async move {
        let result = tunnel_roundtrip(&mut h2_for_data, &target, b"concurrent test").await;
        assert_eq!(result, b"CONCURRENT TEST");
    });

    control_task.await.unwrap();
    data_task.await.unwrap();
}

/// Test two data tunnels simultaneously through the same H2 connection.
#[tokio::test]
async fn test_multiple_tunnels() {
    let upper_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let upper_addr = upper_listener.local_addr().unwrap();
    tokio::spawn(run_uppercase_server(upper_listener));

    let (server_addr, pubkey) = start_paidtor_server().await;
    let h2 = connect_client(server_addr, &pubkey).await;

    let target = format!("127.0.0.1:{}", upper_addr.port());

    let ta1 = target.clone();
    let mut h2a = h2.clone();
    let tunnel_a = tokio::spawn(async move {
        let result = tunnel_roundtrip(&mut h2a, &ta1, b"first tunnel").await;
        assert_eq!(result, b"FIRST TUNNEL");
    });

    let ta2 = target.clone();
    let mut h2b = h2.clone();
    let tunnel_b = tokio::spawn(async move {
        let result = tunnel_roundtrip(&mut h2b, &ta2, b"second tunnel").await;
        assert_eq!(result, b"SECOND TUNNEL");
    });

    tunnel_a.await.unwrap();
    tunnel_b.await.unwrap();
}
