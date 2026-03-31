//! Integration test: exercises the full MONAD stack.
//!
//! Spins up three components in a single tokio runtime:
//!   1. An "uppercase" TCP server (simulates an external target)
//!   2. A MONAD server (Noise NK + H2)
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
use monad_common::h2stream::wait_for_send_capacity;
use monad_common::noise;
use monad_client::connector::{self, Hop, ServerConnection};
use monad_common::protocol::{ClientMessage, ServerMessage};
use monad_server::listener::ServerConfig;
use std::net::{IpAddr, Ipv6Addr, SocketAddr};
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

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

/// Spin up a MONAD server and return (server_addr, pubkey).
async fn start_monad_server() -> (std::net::SocketAddr, Vec<u8>) {
    let (privkey, pubkey) = noise::generate_keypair();

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();

    let config = Arc::new(ServerConfig {
        private_key: privkey,
    });

    tokio::spawn(monad_server::listener::run(listener, config));

    (addr, pubkey)
}

/// Spin up a MONAD server bound to a specific address and return (server_addr, pubkey).
async fn start_monad_server_at(bind_addr: SocketAddr) -> Option<(SocketAddr, Vec<u8>)> {
    let (privkey, pubkey) = noise::generate_keypair();

    let listener = match TcpListener::bind(bind_addr).await {
        Ok(listener) => listener,
        Err(e) => {
            eprintln!("skipping IPv6 test: failed to bind {bind_addr}: {e}");
            return None;
        }
    };
    let addr = listener.local_addr().unwrap();

    let config = Arc::new(ServerConfig {
        private_key: privkey,
    });

    tokio::spawn(monad_server::listener::run(listener, config));

    Some((addr, pubkey))
}

async fn bind_ipv6_listener() -> Option<TcpListener> {
    match TcpListener::bind(SocketAddr::new(IpAddr::V6(Ipv6Addr::LOCALHOST), 0)).await {
        Ok(listener) => Some(listener),
        Err(e) => {
            eprintln!("skipping IPv6 test: IPv6 loopback unavailable: {e}");
            None
        }
    }
}

/// Connect to a MONAD server through the real client connector.
async fn connect_client(server_addr: std::net::SocketAddr, pubkey: &[u8]) -> ServerConnection {
    connector::connect_through_chain(&[Hop {
        addr: server_addr.to_string(),
        pubkey: pubkey.to_vec(),
    }])
    .await
    .unwrap()
}

async fn clone_h2_client(conn: &ServerConnection) -> client::SendRequest<Bytes> {
    let client = conn.h2_client.lock().await;
    client.clone()
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
    wait_for_send_capacity(&mut h2_send).await.unwrap();
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
    wait_for_send_capacity(&mut h2_send).await.unwrap();
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

    // MONAD server
    let (server_addr, pubkey) = start_monad_server().await;

    // Client
    let conn = connect_client(server_addr, &pubkey).await;
    let mut h2 = clone_h2_client(&conn).await;

    // Control channel: Ping/Pong
    control_ping_pong(&mut h2).await;

    // Data channel: CONNECT → uppercase
    let target = format!("127.0.0.1:{}", upper_addr.port());
    let result = tunnel_roundtrip(&mut h2, &target, b"hello world").await;
    assert_eq!(result, b"HELLO WORLD");

    drop(h2);
    conn.shutdown().await;
}

/// Test control and data channels running concurrently over the same connection.
#[tokio::test]
async fn test_concurrent_channels() {
    let upper_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let upper_addr = upper_listener.local_addr().unwrap();
    tokio::spawn(run_uppercase_server(upper_listener));

    let (server_addr, pubkey) = start_monad_server().await;
    let conn = connect_client(server_addr, &pubkey).await;
    let h2 = clone_h2_client(&conn).await;

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

    drop(h2);
    conn.shutdown().await;
}

/// Test two data tunnels simultaneously through the same H2 connection.
#[tokio::test]
async fn test_multiple_tunnels() {
    let upper_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let upper_addr = upper_listener.local_addr().unwrap();
    tokio::spawn(run_uppercase_server(upper_listener));

    let (server_addr, pubkey) = start_monad_server().await;
    let conn = connect_client(server_addr, &pubkey).await;
    let h2 = clone_h2_client(&conn).await;

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

    drop(h2);
    conn.shutdown().await;
}

// ---------------------------------------------------------------------------
// Nested / onion routing tests
// ---------------------------------------------------------------------------

/// Test nested tunneling: Client → Server T → Server S → uppercase server.
///
/// T only sees encrypted Noise bytes heading to S. It has no idea that
/// inside those bytes is another MONAD session asking S to connect
/// to the uppercase server.
#[tokio::test]
async fn test_nested_tunnel() {
    // Uppercase server (final external target)
    let upper_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let upper_addr = upper_listener.local_addr().unwrap();
    tokio::spawn(run_uppercase_server(upper_listener));

    // Server S (final hop — will proxy to uppercase server)
    let (s_addr, s_pubkey) = start_monad_server().await;

    // Server T (intermediate hop — will proxy to S)
    let (t_addr, t_pubkey) = start_monad_server().await;

    // Client connects through T → S
    let conn = connector::connect_through_chain(&[
        Hop { addr: t_addr.to_string(), pubkey: t_pubkey },
        Hop { addr: s_addr.to_string(), pubkey: s_pubkey },
    ]).await.unwrap();
    let mut h2 = clone_h2_client(&conn).await;

    // Open a tunnel to the uppercase server (through S, via T)
    let target = format!("127.0.0.1:{}", upper_addr.port());
    let result = tunnel_roundtrip(&mut h2, &target, b"nested hello").await;
    assert_eq!(result, b"NESTED HELLO");

    drop(h2);
    conn.shutdown().await;
}

/// Test nested tunneling with 3 hops: Client → A → B → C → uppercase.
#[tokio::test]
async fn test_three_hop_tunnel() {
    let upper_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let upper_addr = upper_listener.local_addr().unwrap();
    tokio::spawn(run_uppercase_server(upper_listener));

    let (a_addr, a_pubkey) = start_monad_server().await;
    let (b_addr, b_pubkey) = start_monad_server().await;
    let (c_addr, c_pubkey) = start_monad_server().await;

    let conn = connector::connect_through_chain(&[
        Hop { addr: a_addr.to_string(), pubkey: a_pubkey },
        Hop { addr: b_addr.to_string(), pubkey: b_pubkey },
        Hop { addr: c_addr.to_string(), pubkey: c_pubkey },
    ]).await.unwrap();
    let mut h2 = clone_h2_client(&conn).await;

    let target = format!("127.0.0.1:{}", upper_addr.port());
    let result = tunnel_roundtrip(&mut h2, &target, b"three hops").await;
    assert_eq!(result, b"THREE HOPS");

    drop(h2);
    conn.shutdown().await;
}

#[tokio::test]
async fn test_connect_to_ipv6_target() {
    let Some(upper_listener) = bind_ipv6_listener().await else {
        return;
    };
    let upper_addr = upper_listener.local_addr().unwrap();
    tokio::spawn(run_uppercase_server(upper_listener));

    let (server_addr, pubkey) = start_monad_server().await;
    let conn = connect_client(server_addr, &pubkey).await;
    let mut h2 = clone_h2_client(&conn).await;

    let target = format!("[::1]:{}", upper_addr.port());
    let result = tunnel_roundtrip(&mut h2, &target, b"ipv6 target").await;
    assert_eq!(result, b"IPV6 TARGET");

    drop(h2);
    conn.shutdown().await;
}

#[tokio::test]
async fn test_connect_to_ipv6_server() {
    let Some((server_addr, pubkey)) =
        start_monad_server_at(SocketAddr::new(IpAddr::V6(Ipv6Addr::LOCALHOST), 0)).await
    else {
        return;
    };

    let upper_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let upper_addr = upper_listener.local_addr().unwrap();
    tokio::spawn(run_uppercase_server(upper_listener));

    let conn = connect_client(server_addr, &pubkey).await;
    let mut h2 = clone_h2_client(&conn).await;
    let target = format!("127.0.0.1:{}", upper_addr.port());
    let result = tunnel_roundtrip(&mut h2, &target, b"ipv6 server").await;
    assert_eq!(result, b"IPV6 SERVER");

    drop(h2);
    conn.shutdown().await;
}

#[tokio::test]
async fn test_mixed_ipv4_ipv6_hops() {
    let Some((ipv6_hop_addr, ipv6_hop_pubkey)) =
        start_monad_server_at(SocketAddr::new(IpAddr::V6(Ipv6Addr::LOCALHOST), 0)).await
    else {
        return;
    };

    let (ipv4_hop_addr, ipv4_hop_pubkey) = start_monad_server().await;

    let upper_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let upper_addr = upper_listener.local_addr().unwrap();
    tokio::spawn(run_uppercase_server(upper_listener));

    let conn = connector::connect_through_chain(&[
        Hop { addr: ipv4_hop_addr.to_string(), pubkey: ipv4_hop_pubkey },
        Hop { addr: ipv6_hop_addr.to_string(), pubkey: ipv6_hop_pubkey },
    ]).await.unwrap();
    let mut h2 = clone_h2_client(&conn).await;

    let target = format!("127.0.0.1:{}", upper_addr.port());
    let result = tunnel_roundtrip(&mut h2, &target, b"mixed hops").await;
    assert_eq!(result, b"MIXED HOPS");

    drop(h2);
    conn.shutdown().await;
}

#[tokio::test]
async fn test_connect_with_hostname_resolution() {
    let upper_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let upper_addr = upper_listener.local_addr().unwrap();
    tokio::spawn(run_uppercase_server(upper_listener));

    let (server_addr, pubkey) = start_monad_server().await;
    let conn = connect_client(server_addr, &pubkey).await;
    let mut h2 = clone_h2_client(&conn).await;

    let target = format!("localhost:{}", upper_addr.port());
    let result = tunnel_roundtrip(&mut h2, &target, b"hostname test").await;
    assert_eq!(result, b"HOSTNAME TEST");

    drop(h2);
    conn.shutdown().await;
}
