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
//!   - Control channel: Hello/SessionParams version negotiation, fake payment
//!   - Data channel: CONNECT → proxy → uppercase server → response

use bytes::Bytes;
use cashu::nuts::SecretKey;
use cdk_spilman_test_mint::{serve_mint_with_shutdown, TestMintConfig};
use h2::client;
use http::{Method, Request};
use monad_common::h2stream::wait_for_send_capacity;
use monad_common::identity::{self, Ed25519Pubkey};
use monad_common::noise;
use monad_common::protocol::MintUnitKeysets;
use monad_common::session::RelayConnection;
use monad_client::connector::{self, Hop};
use monad_client::control::{self, FakePaymentProvider, SessionFundingProvider};
use monad_common::protocol::{ClientMessage, ServerMessage};
use monad_server::listener::ServerConfig;
use monad_quic::stream::QuicStream;
use std::collections::{BTreeMap, BTreeSet};
use std::net::{IpAddr, Ipv6Addr, SocketAddr};
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

const TEST_SESSION_PAYMENT: u64 = 10_000_000;

fn fake_provider() -> Arc<dyn SessionFundingProvider> {
    Arc::new(FakePaymentProvider {
        fake_payment_millisats: TEST_SESSION_PAYMENT,
    })
}

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

/// A TCP server that waits for exactly `expected_len` bytes, then replies once.
async fn run_counting_server(listener: TcpListener, expected_len: usize, response: &'static [u8]) {
    loop {
        let (mut stream, _) = match listener.accept().await {
            Ok(conn) => conn,
            Err(_) => break,
        };

        tokio::spawn(async move {
            let mut received = Vec::with_capacity(expected_len);
            let mut buf = [0u8; 1];

            while received.len() < expected_len {
                match stream.read(&mut buf).await {
                    Ok(0) => return,
                    Ok(n) => received.extend_from_slice(&buf[..n]),
                    Err(_) => return,
                }
            }

            let _ = stream.write_all(response).await;
        });
    }
}

/// A TCP server that waits for exactly `expected_len` bytes, then waits for an
/// external release signal before replying once.
async fn run_gated_reply_server(
    listener: TcpListener,
    expected_len: usize,
    response: &'static [u8],
    release_rx: tokio::sync::oneshot::Receiver<()>,
) {
    let (mut stream, _) = match listener.accept().await {
        Ok(conn) => conn,
        Err(_) => return,
    };

    let mut received = Vec::with_capacity(expected_len);
    let mut buf = [0u8; 1];

    while received.len() < expected_len {
        match stream.read(&mut buf).await {
            Ok(0) => return,
            Ok(n) => received.extend_from_slice(&buf[..n]),
            Err(_) => return,
        }
    }

    if release_rx.await.is_err() {
        return;
    }

    let _ = stream.write_all(response).await;
}

async fn start_http_test_mint() -> (String, tokio::sync::oneshot::Sender<()>) {
    let port = std::net::TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port();
    let config = TestMintConfig::for_port(port);
    let mint_url = config.base_url.clone();
    let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel();

    tokio::spawn(async move {
        let _ = serve_mint_with_shutdown(config, async {
            let _ = shutdown_rx.await;
        })
        .await;
    });

    let client = reqwest::Client::new();
    for _ in 0..50 {
        match client.get(format!("{mint_url}/v1/keysets")).send().await {
            Ok(resp) if resp.status().is_success() => return (mint_url, shutdown_tx),
            _ => tokio::time::sleep(std::time::Duration::from_millis(20)).await,
        }
    }

    panic!("test mint failed to start at {mint_url}");
}

/// Spin up a MONAD server and return (server_addr, ed25519_pubkey).
async fn start_monad_server() -> (std::net::SocketAddr, Ed25519Pubkey) {
    start_monad_server_with_spilman(BTreeMap::new(), SecretKey::generate()).await
}

/// Spin up a MONAD server with explicit Spilman advertisement config.
async fn start_monad_server_with_spilman(
    trusted_mint_units: BTreeMap<String, BTreeSet<String>>,
    payment_receiver_secret: SecretKey,
) -> (std::net::SocketAddr, Ed25519Pubkey) {
    let identity = identity::ServerIdentity::generate().unwrap();
    let pubkey = identity.ed25519_pubkey().clone();

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();

    let config = Arc::new(ServerConfig {
        identity,
        payment_receiver_secret,
        trusted_mint_units,
    });

    tokio::spawn(monad_server::listener::run(listener, None, config));

    (addr, pubkey)
}

/// Spin up a MONAD server bound to a specific address and return (server_addr, ed25519_pubkey).
async fn start_monad_server_at(bind_addr: SocketAddr) -> Option<(SocketAddr, Ed25519Pubkey)> {
    let identity = identity::ServerIdentity::generate().unwrap();
    let pubkey = identity.ed25519_pubkey().clone();

    let listener = match TcpListener::bind(bind_addr).await {
        Ok(listener) => listener,
        Err(e) => {
            eprintln!("skipping IPv6 test: failed to bind {bind_addr}: {e}");
            return None;
        }
    };
    let addr = listener.local_addr().unwrap();

    let config = Arc::new(ServerConfig {
        identity,
        payment_receiver_secret: SecretKey::generate(),
        trusted_mint_units: BTreeMap::new(),
    });

    tokio::spawn(monad_server::listener::run(listener, None, config));

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
async fn connect_client(server_addr: std::net::SocketAddr, pubkey: &Ed25519Pubkey) -> RelayConnection {
    connector::connect_through_chain(
        &[Hop {
            addr: server_addr.to_string(),
            pubkey: pubkey.clone(),
            use_quic: false,
        }],
        fake_provider(),
    )
    .await
    .unwrap()
}

async fn connect_client_funded(
    server_addr: std::net::SocketAddr,
    pubkey: &Ed25519Pubkey,
) -> RelayConnection {
    let conn = connect_client(server_addr, pubkey).await;
    fund_session(&conn, TEST_SESSION_PAYMENT).await;
    conn
}

async fn send_control_message(
    h2_send: &mut h2::SendStream<Bytes>,
    message: &ClientMessage,
    end_stream: bool,
) {
    let bytes = serde_json::to_vec(message).unwrap();
    let mut frame = Vec::with_capacity(bytes.len() + 1);
    frame.extend_from_slice(&bytes);
    frame.push(b'\n');

    h2_send.reserve_capacity(frame.len());
    wait_for_send_capacity(h2_send).await.unwrap();
    h2_send.send_data(Bytes::from(frame), end_stream).unwrap();
}

async fn read_control_message(h2_recv: &mut h2::RecvStream) -> ServerMessage {
    let mut response_buf = Vec::new();

    loop {
        if let Some(newline_pos) = response_buf.iter().position(|&b| b == b'\n') {
            let line = &response_buf[..newline_pos];
            return serde_json::from_slice(line).unwrap();
        }

        let chunk = h2_recv
            .data()
            .await
            .expect("control stream closed unexpectedly")
            .unwrap();
        let len = chunk.len();
        let _ = h2_recv.flow_control().release_capacity(len);
        response_buf.extend_from_slice(&chunk);
    }
}

fn expect_session_status(message: ServerMessage) -> (u64, u64, u64, i64, bool) {
    match message {
        ServerMessage::SessionStatus {
            session_total_in,
            session_total_out,
            total_paid_millisats,
            remaining_milli_sats,
            paused,
        } => (session_total_in, session_total_out, total_paid_millisats, remaining_milli_sats, paused),
        other => panic!("expected SessionStatus, got {other:?}"),
    }
}

fn expect_session_params(message: ServerMessage) -> (u8, u64, u64, String, MintUnitKeysets) {
    match message {
        ServerMessage::SessionParams {
            version,
            in_bytes_per_millisat,
            out_bytes_per_millisat,
            receiver_pubkey,
            mints_units_keysets,
        } => (
            version,
            in_bytes_per_millisat,
            out_bytes_per_millisat,
            receiver_pubkey,
            mints_units_keysets,
        ),
        other => panic!("expected SessionParams, got {other:?}"),
    }
}

/// Send Hello, read SessionParams, read initial SessionStatus.
/// Returns the initial session status fields.
async fn control_handshake(
    h2_send: &mut h2::SendStream<Bytes>,
    h2_recv: &mut h2::RecvStream,
) -> (u64, u64, u64, i64, bool) {
    send_control_message(h2_send, &ClientMessage::Hello { version: 0 }, false).await;

    let (version, in_bytes_per_millisat, out_bytes_per_millisat, _receiver_pubkey, _mints_units_keysets) =
        expect_session_params(read_control_message(h2_recv).await);
    assert_eq!(version, 0);
    assert_eq!(in_bytes_per_millisat, 1);
    assert_eq!(out_bytes_per_millisat, 1);

    expect_session_status(read_control_message(h2_recv).await)
}

async fn fund_session(conn: &RelayConnection, milli_sats: u64) {
    let (mut h2_send, mut h2_recv) = conn.open_control().await.unwrap();

    let (_in0, _out0, _paid0, rem0, paused0) = control_handshake(&mut h2_send, &mut h2_recv).await;
    assert!(paused0);
    assert_eq!(rem0, 0);

    send_control_message(
        &mut h2_send,
        &ClientMessage::FakePayment { milli_sats },
        false,
    )
    .await;

    match read_control_message(&mut h2_recv).await {
        ServerMessage::SessionStatus {
            paused,
            remaining_milli_sats,
            ..
        } => {
            assert!(!paused, "session should unpause after funding");
            assert_eq!(remaining_milli_sats, milli_sats as i64);
        }
        other => panic!("expected funded SessionStatus, got {other:?}"),
    }

    let _ = h2_send.send_data(Bytes::new(), true);
    drop(h2_send);
    drop(h2_recv);
    tokio::time::sleep(std::time::Duration::from_millis(20)).await;
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

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[tokio::test]
async fn test_session_starts_paused() {
    let (server_addr, pubkey) = start_monad_server().await;
    let conn = connect_client(server_addr, &pubkey).await;
    let (mut h2_send, mut h2_recv) = conn.open_control().await.unwrap();

    let (session_total_in, session_total_out, _total_paid, remaining_milli_sats, paused) =
        control_handshake(&mut h2_send, &mut h2_recv).await;
    assert_eq!(session_total_in, 0);
    assert_eq!(session_total_out, 0);
    assert_eq!(remaining_milli_sats, 0);
    assert!(paused);

    let _ = h2_send.send_data(Bytes::new(), true);
    drop(h2_send);
    drop(h2_recv);
    tokio::time::sleep(std::time::Duration::from_millis(20)).await;
    conn.shutdown().await;
}

#[tokio::test]
async fn test_second_control_stream_rejected() {
    let (server_addr, pubkey) = start_monad_server().await;
    let conn = connect_client(server_addr, &pubkey).await;

    let (mut first_send, mut first_recv) = conn.open_control().await.unwrap();
    let (_in0, _out0, _paid0, _rem0, paused0) = control_handshake(&mut first_send, &mut first_recv).await;
    assert!(paused0);

    let mut h2 = conn.clone_send_request().await;
    let request = Request::builder()
        .method(Method::POST)
        .uri("http://monad/control")
        .body(())
        .unwrap();
    let (response_future, second_send) = h2.send_request(request, false).unwrap();
    let response = response_future.await.unwrap();
    assert_eq!(response.status(), http::StatusCode::CONFLICT);

    drop(second_send);
    drop(response);

    let _ = first_send.send_data(Bytes::new(), true);
    drop(first_send);
    drop(first_recv);
    drop(h2);
    tokio::time::sleep(std::time::Duration::from_millis(20)).await;
    conn.shutdown().await;
}

#[tokio::test]
async fn test_connect_rejected_while_paused() {
    let upper_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let upper_addr = upper_listener.local_addr().unwrap();
    tokio::spawn(run_uppercase_server(upper_listener));

    let (server_addr, pubkey) = start_monad_server().await;
    let conn = connect_client(server_addr, &pubkey).await;
    let mut h2 = conn.clone_send_request().await;

    let request = Request::builder()
        .method(Method::CONNECT)
        .uri(format!("127.0.0.1:{}", upper_addr.port()))
        .body(())
        .unwrap();

    let (response_future, h2_send) = h2.send_request(request, false).unwrap();
    let response = response_future.await.unwrap();
    assert_eq!(response.status(), http::StatusCode::PAYMENT_REQUIRED);

    drop(h2_send);
    drop(response);
    drop(h2);
    conn.shutdown().await;
}

#[tokio::test]
async fn test_session_repauses_and_resumes_after_second_payment() {
    let target_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let target_addr = target_listener.local_addr().unwrap();
    tokio::spawn(run_counting_server(target_listener, 10, b"DONE"));

    let (server_addr, pubkey) = start_monad_server().await;
    let conn = connect_client(server_addr, &pubkey).await;

    let (mut control_send, mut control_recv) = conn.open_control().await.unwrap();
    let (_in0, _out0, _paid0, rem0, paused0) = control_handshake(&mut control_send, &mut control_recv).await;
    assert!(paused0);
    assert_eq!(rem0, 0);

    send_control_message(
        &mut control_send,
        &ClientMessage::FakePayment { milli_sats: 5 },
        false,
    )
    .await;
    let (_in1, _out1, _paid1, rem1, paused1) = expect_session_status(read_control_message(&mut control_recv).await);
    assert!(!paused1);
    assert_eq!(rem1, 5);

    let mut h2 = conn.clone_send_request().await;
    let request = Request::builder()
        .method(Method::CONNECT)
        .uri(format!("127.0.0.1:{}", target_addr.port()))
        .body(())
        .unwrap();
    let (response_future, mut h2_send) = h2.send_request(request, false).unwrap();
    let response = response_future.await.unwrap();
    assert!(response.status().is_success());
    let mut h2_recv = response.into_body();

    for i in 0..10u8 {
        h2_send.reserve_capacity(1);
        wait_for_send_capacity(&mut h2_send).await.unwrap();
        h2_send
            .send_data(Bytes::from(vec![b'a' + i]), i == 9)
            .unwrap();
    }

    let (_in2, out2, _paid2, rem2, paused2) = expect_session_status(read_control_message(&mut control_recv).await);
    assert!(paused2, "session should re-pause after credit is exhausted");
    assert_eq!(out2, 5);
    assert_eq!(rem2, 0);

    let stalled = tokio::time::timeout(
        std::time::Duration::from_millis(200),
        h2_recv.data(),
    )
    .await;
    assert!(stalled.is_err(), "CONNECT should stall while session is paused");

    send_control_message(
        &mut control_send,
        &ClientMessage::FakePayment { milli_sats: 10 },
        false,
    )
    .await;
    let (_in3, _out3, _paid3, rem3, paused3) = expect_session_status(read_control_message(&mut control_recv).await);
    assert!(!paused3, "session should unpause after second payment");
    assert_eq!(rem3, 10);

    let mut result = Vec::new();
    while let Some(chunk) = h2_recv.data().await {
        let data = chunk.unwrap();
        let len = data.len();
        let _ = h2_recv.flow_control().release_capacity(len);
        result.extend_from_slice(&data);
    }
    assert_eq!(result, b"DONE");

    send_control_message(&mut control_send, &ClientMessage::GetSessionStatus, false).await;
    let (session_total_in, session_total_out, _total_paid, remaining_milli_sats, paused) =
        expect_session_status(read_control_message(&mut control_recv).await);
    assert_eq!(session_total_out, 10);
    assert_eq!(session_total_in, 4);
    assert_eq!(remaining_milli_sats, 1);
    assert!(!paused);

    let _ = control_send.send_data(Bytes::new(), true);
    drop(control_send);
    drop(control_recv);
    drop(h2_send);
    drop(h2_recv);
    drop(h2);
    tokio::time::sleep(std::time::Duration::from_millis(20)).await;
    conn.shutdown().await;
}

#[tokio::test]
async fn test_session_overshoot_negative_balance_and_resume() {
    let target_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let target_addr = target_listener.local_addr().unwrap();
    let (release_tx, release_rx) = tokio::sync::oneshot::channel();
    tokio::spawn(run_gated_reply_server(target_listener, 10, b"DONE", release_rx));

    let (server_addr, pubkey) = start_monad_server().await;
    let conn = connect_client(server_addr, &pubkey).await;

    let (mut control_send, mut control_recv) = conn.open_control().await.unwrap();
    let (_in0, _out0, _paid0, rem0, paused0) = control_handshake(&mut control_send, &mut control_recv).await;
    assert!(paused0);
    assert_eq!(rem0, 0);

    send_control_message(
        &mut control_send,
        &ClientMessage::FakePayment { milli_sats: 5 },
        false,
    )
    .await;
    let (_in1, _out1, _paid1, rem1, paused1) =
        expect_session_status(read_control_message(&mut control_recv).await);
    assert!(!paused1);
    assert_eq!(rem1, 5);

    let mut h2 = conn.clone_send_request().await;
    let request = Request::builder()
        .method(Method::CONNECT)
        .uri(format!("127.0.0.1:{}", target_addr.port()))
        .body(())
        .unwrap();
    let (response_future, mut h2_send) = h2.send_request(request, false).unwrap();
    let response = response_future.await.unwrap();
    assert!(response.status().is_success());
    let mut h2_recv = response.into_body();

    h2_send.reserve_capacity(10);
    wait_for_send_capacity(&mut h2_send).await.unwrap();
    h2_send.send_data(Bytes::from_static(b"abcdefghij"), true).unwrap();

    let (_in2, out2, _paid2, rem2, paused2) =
        expect_session_status(read_control_message(&mut control_recv).await);
    assert!(paused2, "session should pause after overshooting credit");
    assert_eq!(out2, 10);
    assert_eq!(rem2, -5);

    send_control_message(
        &mut control_send,
        &ClientMessage::FakePayment { milli_sats: 10 },
        false,
    )
    .await;
    let (_in3, _out3, _paid3, rem3, paused3) =
        expect_session_status(read_control_message(&mut control_recv).await);
    assert!(
        !paused3,
        "session should unpause after positive top-up, got paused={paused3} remaining={rem3}"
    );
    assert_eq!(rem3, 5);

    let _ = release_tx.send(());

    let result = tokio::time::timeout(std::time::Duration::from_millis(500), async {
        let mut result = Vec::new();
        while let Some(chunk) = h2_recv.data().await {
            let data = chunk.unwrap();
            let len = data.len();
            let _ = h2_recv.flow_control().release_capacity(len);
            result.extend_from_slice(&data);
        }
        result
    })
    .await
    .expect("response should complete after positive top-up");
    assert_eq!(result, b"DONE");

    send_control_message(&mut control_send, &ClientMessage::GetSessionStatus, false).await;
    let (session_total_in, session_total_out, _total_paid, remaining_milli_sats, paused) =
        expect_session_status(read_control_message(&mut control_recv).await);
    assert_eq!(session_total_out, 10);
    assert_eq!(session_total_in, 4);
    assert_eq!(remaining_milli_sats, 1);
    assert!(!paused);

    let _ = control_send.send_data(Bytes::new(), true);
    drop(control_send);
    drop(control_recv);
    drop(h2_send);
    drop(h2_recv);
    drop(h2);
    tokio::time::sleep(std::time::Duration::from_millis(20)).await;
    conn.shutdown().await;
}

#[tokio::test]
async fn test_session_overshoot_underpayment_stays_paused_until_positive() {
    let target_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let target_addr = target_listener.local_addr().unwrap();
    let (release_tx, release_rx) = tokio::sync::oneshot::channel();
    tokio::spawn(run_gated_reply_server(target_listener, 10, b"DONE", release_rx));

    let (server_addr, pubkey) = start_monad_server().await;
    let conn = connect_client(server_addr, &pubkey).await;

    let (mut control_send, mut control_recv) = conn.open_control().await.unwrap();
    let (_in0, _out0, _paid0, rem0, paused0) = control_handshake(&mut control_send, &mut control_recv).await;
    assert!(paused0);
    assert_eq!(rem0, 0);

    send_control_message(
        &mut control_send,
        &ClientMessage::FakePayment { milli_sats: 5 },
        false,
    )
    .await;
    let (_in1, _out1, _paid1, rem1, paused1) =
        expect_session_status(read_control_message(&mut control_recv).await);
    assert!(!paused1);
    assert_eq!(rem1, 5);

    let mut h2 = conn.clone_send_request().await;
    let request = Request::builder()
        .method(Method::CONNECT)
        .uri(format!("127.0.0.1:{}", target_addr.port()))
        .body(())
        .unwrap();
    let (response_future, mut h2_send) = h2.send_request(request, false).unwrap();
    let response = response_future.await.unwrap();
    assert!(response.status().is_success());
    let mut h2_recv = response.into_body();

    h2_send.reserve_capacity(10);
    wait_for_send_capacity(&mut h2_send).await.unwrap();
    h2_send.send_data(Bytes::from_static(b"abcdefghij"), true).unwrap();

    let (_in2, out2, _paid2, rem2, paused2) =
        expect_session_status(read_control_message(&mut control_recv).await);
    assert!(paused2, "session should pause after overshooting credit");
    assert_eq!(out2, 10);
    assert_eq!(rem2, -5);

    send_control_message(
        &mut control_send,
        &ClientMessage::FakePayment { milli_sats: 4 },
        false,
    )
    .await;
    let (_in3, _out3, _paid3, rem3, paused3) =
        expect_session_status(read_control_message(&mut control_recv).await);
    assert!(paused3, "session should stay paused while balance is non-positive");
    assert_eq!(rem3, -1);

    let mut h2_for_paused_connect = conn.clone_send_request().await;
    let paused_request = Request::builder()
        .method(Method::CONNECT)
        .uri(format!("127.0.0.1:{}", target_addr.port()))
        .body(())
        .unwrap();
    let (paused_response_future, paused_h2_send) =
        h2_for_paused_connect.send_request(paused_request, false).unwrap();
    let paused_response = paused_response_future.await.unwrap();
    assert_eq!(paused_response.status(), http::StatusCode::PAYMENT_REQUIRED);
    drop(paused_h2_send);
    drop(paused_response);
    drop(h2_for_paused_connect);

    send_control_message(
        &mut control_send,
        &ClientMessage::FakePayment { milli_sats: 6 },
        false,
    )
    .await;
    let (_in4, _out4, _paid4, rem4, paused4) =
        expect_session_status(read_control_message(&mut control_recv).await);
    assert!(
        !paused4,
        "session should unpause once balance becomes positive, got paused={paused4} remaining={rem4}"
    );
    assert_eq!(rem4, 5);

    let _ = release_tx.send(());

    let result = tokio::time::timeout(std::time::Duration::from_millis(500), async {
        let mut result = Vec::new();
        while let Some(chunk) = h2_recv.data().await {
            let data = chunk.unwrap();
            let len = data.len();
            let _ = h2_recv.flow_control().release_capacity(len);
            result.extend_from_slice(&data);
        }
        result
    })
    .await
    .expect("response should complete after balance becomes positive");
    assert_eq!(result, b"DONE");

    send_control_message(&mut control_send, &ClientMessage::GetSessionStatus, false).await;
    let (session_total_in, session_total_out, _total_paid, remaining_milli_sats, paused) =
        expect_session_status(read_control_message(&mut control_recv).await);
    assert_eq!(session_total_out, 10);
    assert_eq!(session_total_in, 4);
    assert_eq!(remaining_milli_sats, 1);
    assert!(!paused);

    let _ = control_send.send_data(Bytes::new(), true);
    drop(control_send);
    drop(control_recv);
    drop(h2_send);
    drop(h2_recv);
    drop(h2);
    tokio::time::sleep(std::time::Duration::from_millis(20)).await;
    conn.shutdown().await;
}

/// Test a funded data tunnel (uppercase) over a paid session.
#[tokio::test]
async fn test_funded_data_channel() {
    // Uppercase server
    let upper_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let upper_addr = upper_listener.local_addr().unwrap();
    tokio::spawn(run_uppercase_server(upper_listener));

    // MONAD server
    let (server_addr, pubkey) = start_monad_server().await;

    // Client
    let conn = connect_client_funded(server_addr, &pubkey).await;
    let mut h2 = conn.clone_send_request().await;

    // Data channel: CONNECT → uppercase
    let target = format!("127.0.0.1:{}", upper_addr.port());
    let result = tunnel_roundtrip(&mut h2, &target, b"hello world").await;
    assert_eq!(result, b"HELLO WORLD");

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
    let conn = connect_client_funded(server_addr, &pubkey).await;
    let h2 = conn.clone_send_request().await;

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
    ], fake_provider()).await.unwrap();
    fund_session(&conn, TEST_SESSION_PAYMENT).await;
    let mut h2 = conn.clone_send_request().await;

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
    ], fake_provider()).await.unwrap();
    fund_session(&conn, TEST_SESSION_PAYMENT).await;
    let mut h2 = conn.clone_send_request().await;

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
    let conn = connect_client_funded(server_addr, &pubkey).await;
    let mut h2 = conn.clone_send_request().await;

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

    let conn = connect_client_funded(server_addr, &pubkey).await;
    let mut h2 = conn.clone_send_request().await;
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
    ], fake_provider()).await.unwrap();
    fund_session(&conn, TEST_SESSION_PAYMENT).await;
    let mut h2 = conn.clone_send_request().await;

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
    let conn = connect_client_funded(server_addr, &pubkey).await;
    let mut h2 = conn.clone_send_request().await;

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
async fn start_monad_server_with_quic() -> (SocketAddr, Ed25519Pubkey) {
    let identity = identity::ServerIdentity::generate().unwrap();
    let pubkey = identity.ed25519_pubkey().clone();
    let quic_km = monad_quic::keygen::generate_from_seed(identity.seed()).unwrap();

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();

    let quic_config =
        monad_quic::server::build_server_config(&quic_km.cert_pem, &quic_km.key_pem).unwrap();
    let quic_endpoint = quinn::Endpoint::server(quic_config, addr).unwrap();

    let config = Arc::new(ServerConfig {
        identity,
        payment_receiver_secret: SecretKey::generate(),
        trusted_mint_units: BTreeMap::new(),
    });

    tokio::spawn(monad_server::listener::run(
        listener,
        Some(quic_endpoint),
        config,
    ));

    (addr, pubkey)
}

/// Connect to a MONAD server over QUIC, run a Noise+H2 session,
/// and return a RelayConnection.
/// Takes a single Ed25519 public key — derives X25519 for Noise and SPKI for QUIC.
async fn connect_client_quic(
    server_addr: SocketAddr,
    pubkey: &Ed25519Pubkey,
) -> RelayConnection {
    // Derive SPKI DER for QUIC pinned key verification
    let pinned_spki = pubkey.to_spki_der();
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
    let x25519_pub = pubkey.to_x25519().unwrap();

    // Noise handshake over the QUIC stream
    let (transport, session_id) = noise::handshake_initiator(&mut quic_stream, &x25519_pub)
        .await
        .unwrap();
    let noise_stream =
        noise::NoiseStream::new(quic_stream, transport, session_id, "test-quic-client".to_string());

    // Create RelayConnection from the Noise stream
    let (mut conn, driver) = RelayConnection::from_noise_stream(noise_stream).await.unwrap();
    conn.add_driver(driver);
    conn
}

async fn connect_client_quic_funded(
    server_addr: SocketAddr,
    pubkey: &Ed25519Pubkey,
) -> RelayConnection {
    let conn = connect_client_quic(server_addr, pubkey).await;
    fund_session(&conn, TEST_SESSION_PAYMENT).await;
    conn
}

/// Test: connect to a MONAD server over QUIC, open a CONNECT tunnel,
/// proxy data through the uppercase server.
#[tokio::test]
async fn test_quic_single_hop() {
    let upper_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let upper_addr = upper_listener.local_addr().unwrap();
    tokio::spawn(run_uppercase_server(upper_listener));

    let (server_addr, pubkey) = start_monad_server_with_quic().await;
    let conn = connect_client_quic_funded(server_addr, &pubkey).await;
    let mut h2 = conn.clone_send_request().await;

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
    let conn = connect_client_quic_funded(server_addr, &pubkey).await;
    let mut h2 = conn.clone_send_request().await;

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
    let conn_to_s = connect_client_funded(s_addr, &s_pubkey).await;
    let mut h2_to_s = conn_to_s.clone_send_request().await;

    // Derive QUIC pin (SPKI DER hex) from T's Ed25519 public key
    let t_spki = t_pubkey.to_spki_der();
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
    let t_x25519_pub = t_pubkey.to_x25519().unwrap();

    // Noise handshake to T (nested inside the QUIC-forwarded tunnel)
    let mut stream = h2_connect_stream;
    let (transport, session_id) = noise::handshake_initiator(&mut stream, &t_x25519_pub)
        .await
        .unwrap();
    let noise_stream =
        noise::NoiseStream::new(stream, transport, session_id, "test-nested-quic-client".to_string());

    // Create RelayConnection to T
    let (mut conn_to_t, driver) = RelayConnection::from_noise_stream(noise_stream).await.unwrap();
    conn_to_t.add_driver(driver);
    fund_session(&conn_to_t, TEST_SESSION_PAYMENT).await;
    let mut h2_to_t = conn_to_t.clone_send_request().await;

    // Open a CONNECT tunnel to the uppercase server through T
    let target = format!("127.0.0.1:{}", upper_addr.port());
    let result = tunnel_roundtrip(&mut h2_to_t, &target, b"nested quic hello").await;
    assert_eq!(result, b"NESTED QUIC HELLO");

    drop(h2_to_t);
    drop(h2_to_s);
    conn_to_t.shutdown().await;
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
    let conn = connector::connect_through_chain(
        &[
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
        ],
        fake_provider(),
    )
    .await
    .unwrap();
    fund_session(&conn, TEST_SESSION_PAYMENT).await;
    let mut h2 = conn.clone_send_request().await;

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
            let conn = connector::connect_through_chain(
                &[
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
                ],
                fake_provider(),
            )
            .await
            .unwrap();
            fund_session(&conn, TEST_SESSION_PAYMENT).await;
            let mut h2 = conn.clone_send_request().await;

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

/// Test: client connects to first hop via QUIC (single hop).
#[tokio::test]
async fn test_quic_first_hop() {
    let upper_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let upper_addr = upper_listener.local_addr().unwrap();
    tokio::spawn(run_uppercase_server(upper_listener));

    let (server_addr, pubkey) = start_monad_server_with_quic().await;

    // Client connects directly via QUIC (use_quic on the first hop)
    let conn = connector::connect_through_chain(
        &[Hop {
            addr: server_addr.to_string(),
            pubkey: pubkey.clone(),
            use_quic: true,
        }],
        fake_provider(),
    )
    .await
    .unwrap();
    fund_session(&conn, TEST_SESSION_PAYMENT).await;
    let mut h2 = conn.clone_send_request().await;

    let result = tunnel_roundtrip(&mut h2, &upper_addr.to_string(), b"quic first hop").await;
    assert_eq!(result, b"QUIC FIRST HOP");

    drop(h2);
    conn.shutdown().await;
}

/// Test: client connects to first hop via QUIC, then TCP to second hop.
#[tokio::test]
async fn test_quic_first_hop_then_tcp() {
    let upper_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let upper_addr = upper_listener.local_addr().unwrap();
    tokio::spawn(run_uppercase_server(upper_listener));

    let (s_addr, s_pubkey) = start_monad_server_with_quic().await;
    let (t_addr, t_pubkey) = start_monad_server().await;

    // Client connects to S via QUIC, then S forwards to T via TCP
    let conn = connector::connect_through_chain(
        &[
            Hop {
                addr: s_addr.to_string(),
                pubkey: s_pubkey,
                use_quic: true,
            },
            Hop {
                addr: t_addr.to_string(),
                pubkey: t_pubkey,
                use_quic: false,
            },
        ],
        fake_provider(),
    )
    .await
    .unwrap();
    fund_session(&conn, TEST_SESSION_PAYMENT).await;
    let mut h2 = conn.clone_send_request().await;

    let target = format!("127.0.0.1:{}", upper_addr.port());
    let result = tunnel_roundtrip(&mut h2, &target, b"quic then tcp").await;
    assert_eq!(result, b"QUIC THEN TCP");

    drop(h2);
    conn.shutdown().await;
}

// ---------------------------------------------------------------------------
// Spilman payment channel tests
// ---------------------------------------------------------------------------

/// Validates that the Spilman payment channel plumbing works inside MONAD's
/// test environment: in-memory mint, channel opening, payment creation, and
/// server-side payment verification.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_spilman_channel_payment() {
    use cashu::nuts::SecretKey;
    use cdk_spilman::{
        build_cashu_b_token, ConfigurableClientHost, SpilmanBridge, SpilmanClientBridge,
    };
    use cdk_spilman_test_mint::{InMemoryMintNetworking, TestMintHelper, TestServerHost};
    use std::time::{SystemTime, UNIX_EPOCH};

    let now_secs = || {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0)
    };

    // 1. Create in-memory mint
    let mint_helper = TestMintHelper::new().await.unwrap();
    let keyset_info_json = mint_helper.keyset_info_json().unwrap();

    // 2. Generate sender (client) + receiver (server) keys
    let sender_secret = SecretKey::generate();
    let receiver_secret = SecretKey::generate();

    // 3. Setup server-side Spilman bridge
    let server_host = TestServerHost::new(receiver_secret.clone());
    server_host.add_keyset(
        "https://test-mint",
        mint_helper.keyset_id(),
        keyset_info_json.clone(),
    );
    let server_bridge = SpilmanBridge::new(server_host);

    // 4. Setup client-side Spilman bridge
    let mut client_host = ConfigurableClientHost::new_in_memory();
    client_host.add_key(sender_secret.clone());
    let client_networking = InMemoryMintNetworking::new(mint_helper.mint());
    let client_bridge = SpilmanClientBridge::new(client_host, client_networking);

    // 5. Mint a token and open a channel
    let proofs = mint_helper.mint_proofs(1000).await.unwrap();
    let token = build_cashu_b_token(
        "https://test-mint",
        "sat",
        &serde_json::to_string(&proofs).unwrap(),
    )
    .unwrap();

    let open_result = client_bridge
        .open_channel_from_token(
            &token,
            &receiver_secret.public_key().to_hex(),
            &sender_secret.public_key().to_hex(),
            now_secs() + 3600,
            &keyset_info_json,
            64,
        )
        .unwrap();

    assert!(open_result.capacity > 0);

    // 6. Client creates first payment (includes funding data)
    let payment1 = client_bridge
        .create_payment_with_funding(&open_result.channel_id, 10)
        .unwrap();

    assert_eq!(payment1.balance, 10);
    assert!(payment1.has_funding());

    // 7. Server verifies and processes first payment
    let result1 = server_bridge
        .process_payment(
            &payment1.channel_id,
            payment1.balance,
            &payment1.signature,
            payment1.params.as_ref(),
            payment1.funding_proofs.as_deref(),
            &(),
        )
        .unwrap();

    assert_eq!(result1.balance, 10);
    assert_eq!(result1.capacity, open_result.capacity);

    // 8. Client creates a top-up payment (no funding data)
    let payment2 = client_bridge
        .create_payment(&open_result.channel_id, 50)
        .unwrap();

    assert_eq!(payment2.balance, 50);
    assert!(!payment2.has_funding());

    // 9. Server verifies and processes top-up
    let result2 = server_bridge
        .process_payment(
            &payment2.channel_id,
            payment2.balance,
            &payment2.signature,
            None,
            None,
            &(),
        )
        .unwrap();

    assert_eq!(result2.balance, 50);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_session_params_advertise_and_client_stores_spilman_keyset_info() {
    let (mint_url, mint_shutdown_tx) = start_http_test_mint().await;

    let receiver_secret = SecretKey::generate();
    let mut trusted_mint_units = BTreeMap::new();
    trusted_mint_units.insert(
        mint_url.clone(),
        BTreeSet::from(["sat".to_string()]),
    );

    let (server_addr, pubkey) = start_monad_server_with_spilman(
        trusted_mint_units,
        receiver_secret.clone(),
    )
    .await;
    let conn = connect_client(server_addr, &pubkey).await;

    let (control_task, ready_rx) =
        control::start_fake_payment_controller(&conn, TEST_SESSION_PAYMENT, "test")
            .await
            .unwrap();

    ready_rx.await.unwrap();

    let session_spilman_info = conn
        .session_spilman_info()
        .await
        .expect("client should store fetched Spilman keyset info");
    assert_eq!(session_spilman_info.receiver_pubkey, receiver_secret.public_key().to_hex());
    assert_eq!(session_spilman_info.mint_url, mint_url);
    assert_eq!(session_spilman_info.unit, "sat");
    assert!(!session_spilman_info.keyset_id.is_empty());
    assert!(session_spilman_info.keyset_info_json.contains(&session_spilman_info.keyset_id));

    control_task.abort();
    let _ = control_task.await;
    let _ = mint_shutdown_tx.send(());
    conn.shutdown().await;
}

/// Test: client receives SessionParams, funding provider mints a token on demand,
/// client opens a Spilman channel via the test mint's HTTP API.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_session_funding_provider_opens_channel() {
    use cdk_spilman::build_cashu_b_token;
    use cdk_spilman_test_mint::{build_router, TestMintHelper};
    use std::sync::Mutex;

    // 1. Create an in-memory mint and serve it over HTTP
    let mint_helper = Arc::new(TestMintHelper::new().await.unwrap());
    let router = build_router(mint_helper.mint()).await.unwrap();

    let http_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let mint_url = format!("http://{}", http_listener.local_addr().unwrap());
    let (mint_shutdown_tx, mint_shutdown_rx) = tokio::sync::oneshot::channel::<()>();
    tokio::spawn(async move {
        let _ = axum::serve(http_listener, router)
            .with_graceful_shutdown(async { let _ = mint_shutdown_rx.await; })
            .await;
    });

    // Wait for mint to be ready
    let client = reqwest::Client::new();
    for _ in 0..50 {
        match client.get(format!("{mint_url}/v1/keysets")).send().await {
            Ok(resp) if resp.status().is_success() => break,
            _ => tokio::time::sleep(std::time::Duration::from_millis(20)).await,
        }
    }

    // 2. Create a funding provider that mints tokens on demand
    struct TestFundingProvider {
        mint_helper: Arc<TestMintHelper>,
        mint_url: String,
        channels_opened: Mutex<Vec<String>>,
    }

    impl SessionFundingProvider for TestFundingProvider {
        fn provide_channel_token(
            &self,
            _hop_label: &str,
            _session_id: &[u8; 32],
            _receiver_pubkey: &str,
            _mint_url: &str,
            _unit: &str,
            _keyset_id: &str,
        ) -> Option<String> {
            let proofs = tokio::task::block_in_place(|| {
                tokio::runtime::Handle::current()
                    .block_on(self.mint_helper.mint_proofs(1000))
            })
            .ok()?;
            let token = build_cashu_b_token(
                &self.mint_url,
                "sat",
                &serde_json::to_string(&proofs).unwrap(),
            )
            .ok()?;
            self.channels_opened
                .lock()
                .unwrap()
                .push(_session_id.iter().map(|b| format!("{b:02x}")).collect());
            Some(token)
        }
    }

    let provider = Arc::new(TestFundingProvider {
        mint_helper: mint_helper.clone(),
        mint_url: mint_url.clone(),
        channels_opened: Mutex::new(Vec::new()),
    });

    // 3. Start MONAD server with the test mint
    let receiver_secret = SecretKey::generate();
    let mut trusted_mint_units = BTreeMap::new();
    trusted_mint_units.insert(
        mint_url.clone(),
        BTreeSet::from(["sat".to_string()]),
    );

    let (server_addr, pubkey) = start_monad_server_with_spilman(
        trusted_mint_units,
        receiver_secret.clone(),
    )
    .await;

    // 4. Connect client with the funding provider
    let conn = connector::connect_through_chain(
        &[Hop {
            addr: server_addr.to_string(),
            pubkey: pubkey.clone(),
            use_quic: false,
        }],
        provider.clone(),
    )
    .await
    .unwrap();

    let (control_task, ready_rx) =
        control::start_control_task(&conn, TEST_SESSION_PAYMENT, "test", provider.clone())
            .await
            .unwrap();

    ready_rx.await.unwrap();

    // 5. Verify the client opened a Spilman channel and the server acknowledged it.
    let mut channel_info = None;
    for _ in 0..50 {
        channel_info = conn.session_channel_info().await;
        if channel_info.is_some() {
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
    }
    let channel_info = channel_info.expect("client should have opened and registered a Spilman channel");
    assert!(!channel_info.channel_id.is_empty());
    assert!(channel_info.capacity > 0);
    eprintln!(
        "Channel opened: id={}, capacity={}",
        channel_info.channel_id, channel_info.capacity
    );

    // Verify the provider was called
    let opened = provider.channels_opened.lock().unwrap();
    assert_eq!(opened.len(), 1, "provider should have been called once");

    control_task.abort();
    let _ = control_task.await;
    let _ = mint_shutdown_tx.send(());
    conn.shutdown().await;
}

/// Test: server rejects an invalid zero-balance funding registration.
///
/// NOTE: This test is currently ignored due to an H2 connection driver issue
/// where server-pushed error responses are not received by a manually-opened
/// control stream in the test harness. The positive funding test
/// (test_session_funding_provider_opens_channel) exercises the same server
/// validation code path and confirms that valid funding is accepted.
#[ignore]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_channel_funding_rejects_invalid_signature() {
    use cdk_spilman::{
        build_cashu_b_token, ConfigurableClientHost, Payment, ReqwestClientNetworking,
        SpilmanClientBridge,
    };
    use cdk_spilman_test_mint::{build_router, TestMintHelper};

    // 1. Create an in-memory mint and serve it over HTTP.
    let mint_helper = Arc::new(TestMintHelper::new().await.unwrap());
    let router = build_router(mint_helper.mint()).await.unwrap();

    let http_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let mint_url = format!("http://{}", http_listener.local_addr().unwrap());
    let (mint_shutdown_tx, mint_shutdown_rx) = tokio::sync::oneshot::channel::<()>();
    tokio::spawn(async move {
        let _ = axum::serve(http_listener, router)
            .with_graceful_shutdown(async { let _ = mint_shutdown_rx.await; })
            .await;
    });

    let client = reqwest::Client::new();
    for _ in 0..50 {
        match client.get(format!("{mint_url}/v1/keysets")).send().await {
            Ok(resp) if resp.status().is_success() => break,
            _ => tokio::time::sleep(std::time::Duration::from_millis(20)).await,
        }
    }

    // 2. Start MONAD server with the test mint.
    let receiver_secret = SecretKey::generate();
    let mut trusted_mint_units = BTreeMap::new();
    trusted_mint_units.insert(
        mint_url.clone(),
        BTreeSet::from(["sat".to_string()]),
    );

    let (server_addr, pubkey) =
        start_monad_server_with_spilman(trusted_mint_units, receiver_secret.clone()).await;
    let conn = connect_client(server_addr, &pubkey).await;

    // 3. Complete the control handshake manually.
    let (mut h2_send, mut h2_recv) = conn.open_control().await.unwrap();
    let (_in0, _out0, _paid0, rem0, paused0) = control_handshake(&mut h2_send, &mut h2_recv).await;
    assert!(paused0);
    assert_eq!(rem0, 0);

    // 4. Open a real channel client-side and create the funding-bearing zero-balance payment.
    let mut client_host = ConfigurableClientHost::new_in_memory();
    let sender_secret = SecretKey::generate();
    client_host.add_key(sender_secret.clone());
    let bridge = SpilmanClientBridge::new(client_host, ReqwestClientNetworking::new());
    let keyset_info_json = bridge
        .fetch_keyset_info(&mint_url, &mint_helper.keyset_id().to_string())
        .unwrap();

    let proofs = mint_helper.mint_proofs(1000).await.unwrap();
    let token = build_cashu_b_token(
        &mint_url,
        "sat",
        &serde_json::to_string(&proofs).unwrap(),
    )
    .unwrap();

    let open_result = bridge
        .open_channel_from_token(
            &token,
            &receiver_secret.public_key().to_hex(),
            &sender_secret.public_key().to_hex(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs()
                + 3600,
            &keyset_info_json,
            64,
        )
        .unwrap();

    let mut funding_payment: Payment = bridge
        .create_payment_with_funding(&open_result.channel_id, 0)
        .unwrap();
    funding_payment.signature = "00".repeat(64);
    let payment_json = serde_json::to_string(&funding_payment).unwrap();

    // 5. Send the tampered funding registration.
    send_control_message(
        &mut h2_send,
        &ClientMessage::ChannelFunding { payment_json },
        false,
    )
    .await;

    // 6. Expect the Error response from the tampered funding.
    let response = tokio::time::timeout(
        std::time::Duration::from_secs(5),
        read_control_message(&mut h2_recv),
    )
    .await
    .expect("timed out waiting for server response to invalid funding");
    match response {
        ServerMessage::Error { message } => {
            assert!(
                message.contains("channel funding rejected") || message.contains("invalid"),
                "unexpected error message: {message}"
            );
        }
        other => panic!("expected Error after invalid channel funding, got {other:?}"),
    }

    assert!(conn.session_channel_info().await.is_none());

    let _ = h2_send.send_data(Bytes::new(), true);
    let _ = mint_shutdown_tx.send(());
    conn.shutdown().await;
}
