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
use monad_common::identity;
use monad_common::noise;
use monad_client::connector::{self, Hop, ServerConnection};
use monad_common::protocol::{ClientMessage, ServerMessage};
use monad_server::listener::ServerConfig;
use monad_quic::stream::QuicStream;
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

/// Spin up a MONAD server and return (server_addr, ed25519_pubkey).
async fn start_monad_server() -> (std::net::SocketAddr, Vec<u8>) {
    let (seed, pubkey) = identity::generate_identity().unwrap();
    let x25519_priv = identity::ed25519_seed_to_x25519_private(&seed);

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();

    let config = Arc::new(ServerConfig {
        private_key: x25519_priv.to_vec(),
    });

    tokio::spawn(monad_server::listener::run(listener, None, config));

    (addr, pubkey.to_vec())
}

/// Spin up a MONAD server bound to a specific address and return (server_addr, ed25519_pubkey).
async fn start_monad_server_at(bind_addr: SocketAddr) -> Option<(SocketAddr, Vec<u8>)> {
    let (seed, pubkey) = identity::generate_identity().unwrap();
    let x25519_priv = identity::ed25519_seed_to_x25519_private(&seed);

    let listener = match TcpListener::bind(bind_addr).await {
        Ok(listener) => listener,
        Err(e) => {
            eprintln!("skipping IPv6 test: failed to bind {bind_addr}: {e}");
            return None;
        }
    };
    let addr = listener.local_addr().unwrap();

    let config = Arc::new(ServerConfig {
        private_key: x25519_priv.to_vec(),
    });

    tokio::spawn(monad_server::listener::run(listener, None, config));

    Some((addr, pubkey.to_vec()))
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
        use_quic: false,
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
        Hop { addr: t_addr.to_string(), pubkey: t_pubkey, use_quic: false },
        Hop { addr: s_addr.to_string(), pubkey: s_pubkey, use_quic: false },
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
        Hop { addr: a_addr.to_string(), pubkey: a_pubkey, use_quic: false },
        Hop { addr: b_addr.to_string(), pubkey: b_pubkey, use_quic: false },
        Hop { addr: c_addr.to_string(), pubkey: c_pubkey, use_quic: false },
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
        Hop { addr: ipv4_hop_addr.to_string(), pubkey: ipv4_hop_pubkey, use_quic: false },
        Hop { addr: ipv6_hop_addr.to_string(), pubkey: ipv6_hop_pubkey, use_quic: false },
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

// ---------------------------------------------------------------------------
// QUIC transport tests
// ---------------------------------------------------------------------------

/// Spin up a MONAD server with both TCP and QUIC listeners.
/// Returns (server_addr, ed25519_pubkey).
/// Both Noise and QUIC use the same Ed25519 identity.
async fn start_monad_server_with_quic() -> (SocketAddr, Vec<u8>) {
    let (seed, pubkey) = identity::generate_identity().unwrap();
    let x25519_priv = identity::ed25519_seed_to_x25519_private(&seed);
    let quic_km = monad_quic::keygen::generate_from_seed(&seed).unwrap();

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();

    let quic_config =
        monad_quic::server::build_server_config(&quic_km.cert_pem, &quic_km.key_pem).unwrap();
    let quic_endpoint = quinn::Endpoint::server(quic_config, addr).unwrap();

    let config = Arc::new(ServerConfig {
        private_key: x25519_priv.to_vec(),
    });

    tokio::spawn(monad_server::listener::run(
        listener,
        Some(quic_endpoint),
        config,
    ));

    (addr, pubkey.to_vec())
}

/// Connect to a MONAD server over QUIC, run a Noise+H2 session,
/// and return an H2 client handle.
/// Takes a single Ed25519 public key — derives X25519 for Noise and SPKI for QUIC.
async fn connect_client_quic(
    server_addr: SocketAddr,
    ed25519_pubkey: &[u8],
) -> ServerConnection {
    let ed25519_pub: [u8; 32] = ed25519_pubkey.try_into().unwrap();

    // Derive SPKI DER for QUIC pinned key verification
    let pinned_spki = identity::ed25519_pubkey_to_spki_der(&ed25519_pub);
    let client_config = monad_quic::client::build_client_config(pinned_spki).unwrap();

    let mut endpoint = quinn::Endpoint::client("0.0.0.0:0".parse().unwrap()).unwrap();
    endpoint.set_default_client_config(client_config);

    // Connect via QUIC
    let conn = endpoint
        .connect(server_addr, "monad-relay")
        .unwrap()
        .await
        .unwrap();

    // Open a bidirectional QUIC stream
    let (send, recv) = conn.open_bi().await.unwrap();
    let mut quic_stream = QuicStream::new(send, recv);

    // Derive X25519 public key for Noise handshake
    let x25519_pub = identity::ed25519_pubkey_to_x25519_pubkey(&ed25519_pub).unwrap();

    // Noise handshake over the QUIC stream
    let transport = noise::handshake_initiator(&mut quic_stream, &x25519_pub)
        .await
        .unwrap();
    let noise_stream =
        noise::NoiseStream::new(quic_stream, transport, "test-quic-client".to_string());

    // H2 client handshake over the Noise stream
    let (h2_client, h2_conn) = h2::client::handshake(noise_stream).await.unwrap();

    let driver_handle = tokio::spawn(async move {
        if let Err(e) = h2_conn.await {
            eprintln!("H2 driver error (QUIC): {e}");
        }
    });

    ServerConnection {
        h2_client: Arc::new(tokio::sync::Mutex::new(h2_client)),
        driver_handles: vec![driver_handle],
    }
}

/// Test: connect to a MONAD server over QUIC, open a CONNECT tunnel,
/// proxy data through the uppercase server.
#[tokio::test]
async fn test_quic_single_hop() {
    let upper_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let upper_addr = upper_listener.local_addr().unwrap();
    tokio::spawn(run_uppercase_server(upper_listener));

    let (server_addr, pubkey) = start_monad_server_with_quic().await;
    let conn = connect_client_quic(server_addr, &pubkey).await;
    let mut h2 = clone_h2_client(&conn).await;

    let result = tunnel_roundtrip(&mut h2, &upper_addr.to_string(), b"hello via quic").await;
    assert_eq!(result, b"HELLO VIA QUIC");

    drop(h2);
    conn.shutdown().await;
}

/// Test: connect via QUIC and run both control and data channels.
#[tokio::test]
async fn test_quic_control_and_data() {
    let upper_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let upper_addr = upper_listener.local_addr().unwrap();
    tokio::spawn(run_uppercase_server(upper_listener));

    let (server_addr, pubkey) = start_monad_server_with_quic().await;
    let conn = connect_client_quic(server_addr, &pubkey).await;
    let mut h2 = clone_h2_client(&conn).await;

    // Control channel
    control_ping_pong(&mut h2).await;

    // Data channel
    let result = tunnel_roundtrip(&mut h2, &upper_addr.to_string(), b"quic data test").await;
    assert_eq!(result, b"QUIC DATA TEST");

    drop(h2);
    conn.shutdown().await;
}

/// Test: 2-hop nested route where relay S forwards to relay T via QUIC.
///
/// Client → S (TCP+Noise+H2) → CONNECT T:port [quic-pin header] → T (QUIC+Noise+H2) → uppercase
///
/// This test manually constructs the H2 CONNECT request with the quic-pin header
/// to exercise the server-side QUIC forwarding path directly.
#[tokio::test]
async fn test_nested_quic_tunnel() {
    // Uppercase server (final external target)
    let upper_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let upper_addr = upper_listener.local_addr().unwrap();
    tokio::spawn(run_uppercase_server(upper_listener));

    // Server T (final hop — QUIC-enabled, will proxy to uppercase server)
    let (t_addr, t_pubkey) = start_monad_server_with_quic().await;

    // Server S (intermediate hop — TCP only, will forward via QUIC to T)
    let (s_addr, s_pubkey) = start_monad_server().await;

    // Client connects to S via TCP (first hop)
    let conn_to_s = connect_client(s_addr, &s_pubkey).await;
    let mut h2_to_s = clone_h2_client(&conn_to_s).await;

    // Derive QUIC pin (SPKI DER hex) from T's Ed25519 public key
    let t_ed25519: [u8; 32] = t_pubkey.as_slice().try_into().unwrap();
    let t_spki = identity::ed25519_pubkey_to_spki_der(&t_ed25519);
    let t_quic_pin = hex::encode(&t_spki);

    // Ask S to CONNECT to T via QUIC (using quic-pin header)
    let t_authority = format!("127.0.0.1:{}", t_addr.port());
    let request = Request::builder()
        .method(Method::CONNECT)
        .uri(&t_authority)
        .header(monad_server::session::QUIC_PIN_HEADER, &t_quic_pin)
        .body(())
        .unwrap();

    let (response_future, h2_send_to_t) = h2_to_s.send_request(request, false).unwrap();
    let response = response_future.await.unwrap();
    assert!(
        response.status().is_success(),
        "CONNECT quic: failed: {}",
        response.status()
    );

    // Now we have a bidirectional tunnel from C to T (through S's QUIC forwarding).
    // Wrap it as an H2ConnectStream, do a Noise handshake to T, run H2.
    let h2_recv_from_t = response.into_body();
    let h2_connect_stream =
        monad_common::h2stream::H2ConnectStream::new(h2_send_to_t, h2_recv_from_t);

    // Derive X25519 public key from T's Ed25519 key for the Noise handshake
    let t_x25519_pub = identity::ed25519_pubkey_to_x25519_pubkey(&t_ed25519).unwrap();

    // Noise handshake to T (nested inside the QUIC-forwarded tunnel)
    let mut stream = h2_connect_stream;
    let transport = noise::handshake_initiator(&mut stream, &t_x25519_pub)
        .await
        .unwrap();
    let noise_stream =
        noise::NoiseStream::new(stream, transport, "test-nested-quic-client".to_string());

    // H2 handshake to T
    let (mut h2_to_t, h2_conn_to_t) = h2::client::handshake(noise_stream).await.unwrap();
    tokio::spawn(async move {
        if let Err(e) = h2_conn_to_t.await {
            eprintln!("H2 driver error (nested QUIC): {e}");
        }
    });

    // Open a CONNECT tunnel to the uppercase server through T
    let target = format!("127.0.0.1:{}", upper_addr.port());
    let result = tunnel_roundtrip(&mut h2_to_t, &target, b"nested quic hello").await;
    assert_eq!(result, b"NESTED QUIC HELLO");

    drop(h2_to_t);
    drop(h2_to_s);
    conn_to_s.shutdown().await;
}

/// Test: 2-hop nested route using the client connector with quic_pin on the Hop.
///
/// Client → S (TCP) → T (QUIC) → uppercase
///
/// This exercises the full client-side --hop quic: path through the connector library.
#[tokio::test]
async fn test_connector_quic_hop() {
    let upper_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let upper_addr = upper_listener.local_addr().unwrap();
    tokio::spawn(run_uppercase_server(upper_listener));

    // Server T (final hop — QUIC-enabled)
    let (t_addr, t_pubkey) = start_monad_server_with_quic().await;

    // Server S (intermediate hop — TCP only)
    let (s_addr, s_pubkey) = start_monad_server().await;

    // Use the client connector with a QUIC hop (single key per hop)
    let conn = connector::connect_through_chain(&[
        Hop {
            addr: s_addr.to_string(),
            pubkey: s_pubkey,
            use_quic: false,
        },
        Hop {
            addr: format!("127.0.0.1:{}", t_addr.port()),
            pubkey: t_pubkey,
            use_quic: true,
        },
    ])
    .await
    .unwrap();
    let mut h2 = clone_h2_client(&conn).await;

    let target = format!("127.0.0.1:{}", upper_addr.port());
    let result = tunnel_roundtrip(&mut h2, &target, b"connector quic hop").await;
    assert_eq!(result, b"CONNECTOR QUIC HOP");

    drop(h2);
    conn.shutdown().await;
}

/// Test: multiple clients simultaneously request QUIC forwarding to the same target.
///
/// This exercises the QUIC connection pool's concurrent access path:
/// - only one QUIC handshake should occur to T
/// - the other clients should wait and then reuse the same connection
/// - all clients should successfully tunnel data through
#[tokio::test]
async fn test_concurrent_quic_pool_access() {
    let upper_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let upper_addr = upper_listener.local_addr().unwrap();
    tokio::spawn(run_uppercase_server(upper_listener));

    // Server T (QUIC-enabled, shared target)
    let (t_addr, t_pubkey) = start_monad_server_with_quic().await;

    // Server S (intermediate, all clients connect through this)
    let (s_addr, s_pubkey) = start_monad_server().await;

    let t_port = t_addr.port();
    let upper_port = upper_addr.port();

    // Spawn 5 clients concurrently, all routing through S → QUIC → T → uppercase
    let mut handles = Vec::new();
    for i in 0..5 {
        let s_addr = s_addr;
        let s_pubkey = s_pubkey.clone();
        let t_pubkey = t_pubkey.clone();

        handles.push(tokio::spawn(async move {
            let conn = connector::connect_through_chain(&[
                Hop {
                    addr: s_addr.to_string(),
                    pubkey: s_pubkey,
                    use_quic: false,
                },
                Hop {
                    addr: format!("127.0.0.1:{t_port}"),
                    pubkey: t_pubkey,
                    use_quic: true,
                },
            ])
            .await
            .unwrap();
            let mut h2 = {
                let client = conn.h2_client.lock().await;
                client.clone()
            };

            let payload = format!("concurrent client {i}");
            let target = format!("127.0.0.1:{upper_port}");
            let result = tunnel_roundtrip(&mut h2, &target, payload.as_bytes()).await;
            assert_eq!(result, payload.to_ascii_uppercase().into_bytes());

            drop(h2);
            conn.shutdown().await;
        }));
    }

    for handle in handles {
        handle.await.unwrap();
    }
}
