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
use http::{Method, Request, Uri};
use paidtor_common::h2stream::H2ConnectStream;
use paidtor_common::noise::{self, NoiseStream};
use paidtor_common::protocol::{ClientMessage, ServerMessage};
use paidtor_server::listener::ServerConfig;
use std::net::{IpAddr, Ipv6Addr, SocketAddr};
use std::sync::Arc;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
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

/// Spin up a PaidTor server bound to a specific address and return (server_addr, pubkey).
async fn start_paidtor_server_at(bind_addr: SocketAddr) -> Option<(SocketAddr, Vec<u8>)> {
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

    tokio::spawn(paidtor_server::listener::run(listener, config));

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

/// Connect to a PaidTor server and return an H2 client handle.
async fn connect_client(
    server_addr: std::net::SocketAddr,
    pubkey: &[u8],
) -> client::SendRequest<Bytes> {
    let mut tcp = TcpStream::connect(server_addr).await.unwrap();
    let transport = noise::handshake_initiator(&mut tcp, pubkey)
        .await
        .unwrap();
    let label = format!("test-client -> {server_addr}");
    let noise_stream = NoiseStream::new(tcp, transport, label);

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

// ---------------------------------------------------------------------------
// Nested / onion routing helpers and tests
// ---------------------------------------------------------------------------

/// Open an H2 CONNECT tunnel and return an H2ConnectStream.
async fn open_h2_connect(
    h2_client: &mut client::SendRequest<Bytes>,
    target_authority: &str,
) -> H2ConnectStream {
    let uri: Uri = target_authority.parse().unwrap();
    let request = Request::builder()
        .method(Method::CONNECT)
        .uri(uri)
        .body(())
        .unwrap();

    let (response_future, h2_send) = h2_client.send_request(request, false).unwrap();
    let response = response_future.await.unwrap();
    assert!(response.status().is_success());

    let h2_recv = response.into_body();
    H2ConnectStream::new(h2_send, h2_recv)
}

/// Connect to a PaidTor server through a chain of hops.
/// Returns an H2 client handle for the last hop.
async fn connect_through_hops(
    hops: &[(std::net::SocketAddr, Vec<u8>)],
) -> client::SendRequest<Bytes> {
    assert!(!hops.is_empty());

    // TCP connect to the first hop
    let tcp = TcpStream::connect(hops[0].0).await.unwrap();
    connect_chain(tcp, hops, 0).await
}

/// Recursive chain builder (using Box::pin for async recursion).
fn connect_chain<S>(
    mut stream: S,
    hops: &[(std::net::SocketAddr, Vec<u8>)],
    idx: usize,
) -> std::pin::Pin<Box<dyn std::future::Future<Output = client::SendRequest<Bytes>> + Send>>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let hops = hops.to_vec();
    Box::pin(async move {
        let (_, ref pubkey) = hops[idx];

        // Noise handshake with this hop
        let transport = noise::handshake_initiator(&mut stream, pubkey)
            .await
            .unwrap();
        let (addr, _) = &hops[idx];
        let label = format!("test-chain hop {}/{} to {}", idx + 1, hops.len(), addr);
        let noise_stream = NoiseStream::new(stream, transport, label);

        // H2 handshake
        let (mut h2_client, h2_conn) = client::handshake(noise_stream).await.unwrap();
        tokio::spawn(async move {
            if let Err(e) = h2_conn.await {
                eprintln!("H2 connection error: {e}");
            }
        });

        if idx < hops.len() - 1 {
            // Open CONNECT tunnel to the next hop
            let next_addr = hops[idx + 1].0.to_string();
            let h2_connect_stream = open_h2_connect(&mut h2_client, &next_addr).await;

            // Recurse: Noise + H2 over the tunnel
            connect_chain(h2_connect_stream, &hops, idx + 1).await
        } else {
            // Last hop
            h2_client
        }
    })
}

/// Test nested tunneling: Client → Server T → Server S → uppercase server.
///
/// T only sees encrypted Noise bytes heading to S. It has no idea that
/// inside those bytes is another PaidTor session asking S to connect
/// to the uppercase server.
#[tokio::test]
async fn test_nested_tunnel() {
    // Uppercase server (final external target)
    let upper_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let upper_addr = upper_listener.local_addr().unwrap();
    tokio::spawn(run_uppercase_server(upper_listener));

    // Server S (final hop — will proxy to uppercase server)
    let (s_addr, s_pubkey) = start_paidtor_server().await;

    // Server T (intermediate hop — will proxy to S)
    let (t_addr, t_pubkey) = start_paidtor_server().await;

    // Client connects through T → S
    let mut h2 = connect_through_hops(&[
        (t_addr, t_pubkey),
        (s_addr, s_pubkey),
    ])
    .await;

    // Open a tunnel to the uppercase server (through S, via T)
    let target = format!("127.0.0.1:{}", upper_addr.port());
    let result = tunnel_roundtrip(&mut h2, &target, b"nested hello").await;
    assert_eq!(result, b"NESTED HELLO");
}

/// Test nested tunneling with 3 hops: Client → A → B → C → uppercase.
#[tokio::test]
async fn test_three_hop_tunnel() {
    let upper_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let upper_addr = upper_listener.local_addr().unwrap();
    tokio::spawn(run_uppercase_server(upper_listener));

    let (a_addr, a_pubkey) = start_paidtor_server().await;
    let (b_addr, b_pubkey) = start_paidtor_server().await;
    let (c_addr, c_pubkey) = start_paidtor_server().await;

    let mut h2 = connect_through_hops(&[
        (a_addr, a_pubkey),
        (b_addr, b_pubkey),
        (c_addr, c_pubkey),
    ])
    .await;

    let target = format!("127.0.0.1:{}", upper_addr.port());
    let result = tunnel_roundtrip(&mut h2, &target, b"three hops").await;
    assert_eq!(result, b"THREE HOPS");
}

#[tokio::test]
async fn test_connect_to_ipv6_target() {
    let Some(upper_listener) = bind_ipv6_listener().await else {
        return;
    };
    let upper_addr = upper_listener.local_addr().unwrap();
    tokio::spawn(run_uppercase_server(upper_listener));

    let (server_addr, pubkey) = start_paidtor_server().await;
    let mut h2 = connect_client(server_addr, &pubkey).await;

    let target = format!("[::1]:{}", upper_addr.port());
    let result = tunnel_roundtrip(&mut h2, &target, b"ipv6 target").await;
    assert_eq!(result, b"IPV6 TARGET");
}

#[tokio::test]
async fn test_connect_to_ipv6_server() {
    let Some((server_addr, pubkey)) =
        start_paidtor_server_at(SocketAddr::new(IpAddr::V6(Ipv6Addr::LOCALHOST), 0)).await
    else {
        return;
    };

    let upper_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let upper_addr = upper_listener.local_addr().unwrap();
    tokio::spawn(run_uppercase_server(upper_listener));

    let mut h2 = connect_client(server_addr, &pubkey).await;
    let target = format!("127.0.0.1:{}", upper_addr.port());
    let result = tunnel_roundtrip(&mut h2, &target, b"ipv6 server").await;
    assert_eq!(result, b"IPV6 SERVER");
}

#[tokio::test]
async fn test_mixed_ipv4_ipv6_hops() {
    let Some((ipv6_hop_addr, ipv6_hop_pubkey)) =
        start_paidtor_server_at(SocketAddr::new(IpAddr::V6(Ipv6Addr::LOCALHOST), 0)).await
    else {
        return;
    };

    let (ipv4_hop_addr, ipv4_hop_pubkey) = start_paidtor_server().await;

    let upper_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let upper_addr = upper_listener.local_addr().unwrap();
    tokio::spawn(run_uppercase_server(upper_listener));

    let mut h2 = connect_through_hops(&[
        (ipv4_hop_addr, ipv4_hop_pubkey),
        (ipv6_hop_addr, ipv6_hop_pubkey),
    ])
    .await;

    let target = format!("127.0.0.1:{}", upper_addr.port());
    let result = tunnel_roundtrip(&mut h2, &target, b"mixed hops").await;
    assert_eq!(result, b"MIXED HOPS");
}

#[tokio::test]
async fn test_connect_with_hostname_resolution() {
    let upper_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let upper_addr = upper_listener.local_addr().unwrap();
    tokio::spawn(run_uppercase_server(upper_listener));

    let (server_addr, pubkey) = start_paidtor_server().await;
    let mut h2 = connect_client(server_addr, &pubkey).await;

    let target = format!("localhost:{}", upper_addr.port());
    let result = tunnel_roundtrip(&mut h2, &target, b"hostname test").await;
    assert_eq!(result, b"HOSTNAME TEST");
}
