//! Integration test: exercises the full MONAD stack.
//!
//! Spins up three components in a single tokio runtime:
//!   1. An "uppercase" TCP server (simulates an external target)
//!   2. A MONAD relay (Noise NK + H2)
//!   3. A test client that opens both a control channel and a data tunnel
//!
//! Validates:
//!   - Noise NK handshake and encrypted transport
//!   - H2 multiplexing: control + data streams coexisting
//!   - Control channel: Hello/SessionStatus version negotiation, channel linking,
//!     incremental channel payments, and linked-channel state synchronization
//!   - Data channel: CONNECT → proxy → uppercase server → response

use bytes::Bytes;
use h2::client;
use http::{Method, Request};
use monad_client::connector::{self, Hop, HopIdentity};
use monad_client::session_driver::start_session_payment_driver;
use monad_client::tunnel;
use monad_client::wallet::{MockWallet, MonadWallet, WalletChannel, WalletChannelState};
use monad_common::h2stream::wait_for_send_capacity;
use monad_common::noise_secp256k1;
use monad_common::protocol::{ClientMessage, ServerMessage};
use monad_common::quic_cert_identity::QuicCertIdentity;
use monad_common::secp_identity::{Secp256k1Pubkey, SecpTransportKeypair};
use monad_common::session::RelayConnection;

use cdk_spilman_test_mint::{build_router, build_test_mint, TestMintConfig};
use monad_quic::client::{build_client_config_for_auth, connect_with_auth, ClientAuthMode};
use monad_relay::listener::{
    discover_spilman_mint_cache, run_with_payments, ServerConfig, SpilmanMintCache,
};
use monad_relay::payments::testing::InMemoryRelayPayments;
use monad_relay::quic_pool::QuicPool;
use std::collections::{BTreeMap, BTreeSet};
use std::io;
use std::net::{IpAddr, Ipv6Addr, SocketAddr};
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio::time::{timeout, Duration};

const TEST_SESSION_PAYMENT: u64 = 10_000_000;
const TEST_CHANNEL_CAPACITY_UNITS: u64 = u64::MAX / 4096;
const MAX_SHARED_BIND_RETRIES: usize = 32;
const SYNTHETIC_TEST_MINT_URL: &str = "https://test-mint.invalid";
const SYNTHETIC_TEST_MINT_UNIT: &str = "msat";
const SYNTHETIC_TEST_KEYSET_ID: &str = "00testkeyset0000";

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
                        let upper: Vec<u8> =
                            buf[..n].iter().map(|b| b.to_ascii_uppercase()).collect();
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

async fn bind_tcp_and_quic_on_same_port(
    bind_addr: SocketAddr,
    quic_server_config: quinn::ServerConfig,
) -> io::Result<(TcpListener, quinn::Endpoint, SocketAddr)> {
    let mut last_addr_in_use: Option<io::Error> = None;

    for _ in 0..MAX_SHARED_BIND_RETRIES {
        let listener = match TcpListener::bind(bind_addr).await {
            Ok(listener) => listener,
            Err(err) if err.kind() == io::ErrorKind::AddrInUse => {
                last_addr_in_use = Some(err);
                continue;
            }
            Err(err) => return Err(err),
        };

        let addr = listener.local_addr()?;
        match quinn::Endpoint::server(quic_server_config.clone(), addr) {
            Ok(quic_endpoint) => return Ok((listener, quic_endpoint, addr)),
            Err(err) if err.kind() == io::ErrorKind::AddrInUse => {
                last_addr_in_use = Some(err);
                drop(listener);
            }
            Err(err) => return Err(err),
        }
    }

    Err(last_addr_in_use.unwrap_or_else(|| {
        io::Error::other(format!(
            "failed to bind shared TCP/QUIC test server after {MAX_SHARED_BIND_RETRIES} retries"
        ))
    }))
}

fn synthetic_test_mint_cache() -> SpilmanMintCache {
    let mut advertised = BTreeMap::new();
    advertised.insert(
        SYNTHETIC_TEST_MINT_URL.to_string(),
        BTreeMap::from([(
            SYNTHETIC_TEST_MINT_UNIT.to_string(),
            vec![SYNTHETIC_TEST_KEYSET_ID.to_string()],
        )]),
    );
    SpilmanMintCache {
        advertised,
        keyset_info_json_by_mint: BTreeMap::new(),
    }
}

/// Spin up a MONAD relay and return `(relay_addr, secp256k1 pubkey)`.
async fn start_monad_relay() -> (std::net::SocketAddr, Secp256k1Pubkey) {
    let identity = QuicCertIdentity::generate().unwrap();
    let transport_key = SecpTransportKeypair::generate();
    let pubkey = transport_key.pubkey();
    let quic_km = monad_quic::keygen::generate_from_seed(identity.seed()).unwrap();
    let quic_server_config =
        monad_quic::server::build_server_config(&quic_km.cert_pem, &quic_km.key_pem).unwrap();
    let (listener, quic_endpoint, addr) =
        bind_tcp_and_quic_on_same_port("127.0.0.1:0".parse().unwrap(), quic_server_config)
            .await
            .unwrap();

    let config = Arc::new(ServerConfig {
        identity,
        transport_key: Some(transport_key),
        payment_receiver_secret: cashu::nuts::SecretKey::generate(),
        trusted_mint_units: BTreeMap::new(),
    });
    let payments = Arc::new(InMemoryRelayPayments::new());
    let synthetic_mint_cache = Arc::new(synthetic_test_mint_cache());

    tokio::spawn(run_with_payments(
        listener,
        Some(quic_endpoint),
        config,
        payments,
        synthetic_mint_cache,
    ));

    (addr, pubkey)
}

async fn start_monad_relay_with_test_payments() -> (
    std::net::SocketAddr,
    Secp256k1Pubkey,
    Arc<InMemoryRelayPayments>,
) {
    let identity = QuicCertIdentity::generate().unwrap();
    let transport_key = SecpTransportKeypair::generate();
    let pubkey = transport_key.pubkey();
    let quic_km = monad_quic::keygen::generate_from_seed(identity.seed()).unwrap();
    let quic_server_config =
        monad_quic::server::build_server_config(&quic_km.cert_pem, &quic_km.key_pem).unwrap();
    let (listener, quic_endpoint, addr) =
        bind_tcp_and_quic_on_same_port("127.0.0.1:0".parse().unwrap(), quic_server_config)
            .await
            .unwrap();

    let config = Arc::new(ServerConfig {
        identity,
        transport_key: Some(transport_key),
        payment_receiver_secret: cashu::nuts::SecretKey::generate(),
        trusted_mint_units: BTreeMap::new(),
    });
    let payments = Arc::new(InMemoryRelayPayments::new());
    let synthetic_mint_cache = Arc::new(synthetic_test_mint_cache());

    tokio::spawn(run_with_payments(
        listener,
        Some(quic_endpoint),
        config,
        payments.clone(),
        synthetic_mint_cache,
    ));

    (addr, pubkey, payments)
}

/// Spin up a MONAD relay with explicit Spilman advertisement config.
async fn start_monad_relay_with_spilman(
    trusted_mint_units: BTreeMap<String, BTreeSet<String>>,
    payment_receiver_secret: cashu::nuts::SecretKey,
) -> (std::net::SocketAddr, Secp256k1Pubkey) {
    let identity = QuicCertIdentity::generate().unwrap();
    let transport_key = SecpTransportKeypair::generate();
    let pubkey = transport_key.pubkey();
    let quic_km = monad_quic::keygen::generate_from_seed(identity.seed()).unwrap();
    let quic_server_config =
        monad_quic::server::build_server_config(&quic_km.cert_pem, &quic_km.key_pem).unwrap();
    let (listener, quic_endpoint, addr) =
        bind_tcp_and_quic_on_same_port("127.0.0.1:0".parse().unwrap(), quic_server_config)
            .await
            .unwrap();

    let config = Arc::new(ServerConfig {
        identity,
        transport_key: Some(transport_key),
        payment_receiver_secret,
        trusted_mint_units,
    });

    let discovered_spilman_mint_cache = Arc::new(
        discover_spilman_mint_cache(&config.trusted_mint_units)
            .await
            .unwrap(),
    );
    let payments = Arc::new(InMemoryRelayPayments::new());

    tokio::spawn(run_with_payments(
        listener,
        Some(quic_endpoint),
        config,
        payments,
        discovered_spilman_mint_cache,
    ));

    (addr, pubkey)
}

async fn start_http_test_mint() -> (String, String, tokio::sync::oneshot::Sender<()>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let config = TestMintConfig::for_port(addr.port());
    let mint = Arc::new(build_test_mint(&config).await.unwrap());
    let router = build_router(Arc::clone(&mint)).await.unwrap();
    let keyset_id = mint
        .get_active_keysets()
        .get(&cashu::nuts::CurrencyUnit::Sat)
        .unwrap()
        .to_string();
    let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel();
    tokio::spawn(async move {
        axum::serve(listener, router)
            .with_graceful_shutdown(async {
                let _ = shutdown_rx.await;
            })
            .await
            .unwrap();
        mint.stop().await.unwrap();
    });

    (config.base_url, keyset_id, shutdown_tx)
}

/// Spin up a MONAD relay bound to a specific address and return `(relay_addr, secp256k1 pubkey)`.
async fn start_monad_relay_at(bind_addr: SocketAddr) -> Option<(SocketAddr, Secp256k1Pubkey)> {
    let identity = QuicCertIdentity::generate().unwrap();
    let transport_key = SecpTransportKeypair::generate();
    let pubkey = transport_key.pubkey();
    let quic_km = monad_quic::keygen::generate_from_seed(identity.seed()).unwrap();
    let quic_server_config =
        monad_quic::server::build_server_config(&quic_km.cert_pem, &quic_km.key_pem).unwrap();
    let (listener, quic_endpoint, addr) =
        match bind_tcp_and_quic_on_same_port(bind_addr, quic_server_config).await {
            Ok(bound) => bound,
            Err(e) => {
                eprintln!("skipping IPv6 test: failed to bind {bind_addr}: {e}");
                return None;
            }
        };

    let config = Arc::new(ServerConfig {
        identity,
        transport_key: Some(transport_key),
        payment_receiver_secret: cashu::nuts::SecretKey::generate(),
        trusted_mint_units: BTreeMap::new(),
    });
    let payments = Arc::new(InMemoryRelayPayments::new());
    let synthetic_mint_cache = Arc::new(synthetic_test_mint_cache());

    tokio::spawn(run_with_payments(
        listener,
        Some(quic_endpoint),
        config,
        payments,
        synthetic_mint_cache,
    ));

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

/// Connect to a MONAD relay over QUIC with secp256k1 transport auth.
async fn connect_client_quic_secp(
    server_addr: std::net::SocketAddr,
    pubkey: &Secp256k1Pubkey,
) -> RelayConnection {
    connector::connect_through_chain(&[Hop {
        addr: server_addr.to_string(),
        identity: HopIdentity::Secp256k1(*pubkey),
        use_quic: true,
    }])
    .await
    .unwrap()
}

async fn connect_client_tcp(
    server_addr: std::net::SocketAddr,
    pubkey: &Secp256k1Pubkey,
) -> RelayConnection {
    connector::connect_through_chain(&[Hop {
        addr: server_addr.to_string(),
        identity: HopIdentity::Secp256k1(*pubkey),
        use_quic: false,
    }])
    .await
    .unwrap()
}

async fn connect_nested_session(
    parent_conn: &RelayConnection,
    next_hop_addr: &str,
    next_hop_pubkey: &Secp256k1Pubkey,
) -> RelayConnection {
    let mut stream = parent_conn.open_tunnel(next_hop_addr).await.unwrap();
    let (send_cipher, recv_cipher, session_id) =
        noise_secp256k1::handshake_initiator(&mut stream, next_hop_pubkey)
            .await
            .unwrap();
    let noise_stream = noise_secp256k1::SecpNoiseStream::new(
        stream,
        send_cipher,
        recv_cipher,
        session_id,
        format!("nested session to {next_hop_addr}"),
    );
    let (mut conn, driver) = RelayConnection::from_transport_stream(noise_stream, session_id)
        .await
        .unwrap();
    conn.add_driver(driver);
    conn
}

async fn connect_nested_session_quic(
    parent_conn: &RelayConnection,
    next_hop_addr: &str,
    next_hop_pubkey: &Secp256k1Pubkey,
) -> RelayConnection {
    let mut stream = parent_conn
        .open_tunnel_quic_secp256k1(next_hop_addr, &next_hop_pubkey.to_hex())
        .await
        .unwrap();
    let (send_cipher, recv_cipher, session_id) =
        noise_secp256k1::handshake_initiator(&mut stream, next_hop_pubkey)
            .await
            .unwrap();
    let noise_stream = noise_secp256k1::SecpNoiseStream::new(
        stream,
        send_cipher,
        recv_cipher,
        session_id,
        format!("nested quic session to {next_hop_addr}"),
    );
    let (mut conn, driver) = RelayConnection::from_transport_stream(noise_stream, session_id)
        .await
        .unwrap();
    conn.add_driver(driver);
    conn
}

async fn connect_client_quic_secp_funded(
    server_addr: std::net::SocketAddr,
    pubkey: &Secp256k1Pubkey,
) -> RelayConnection {
    let mut conn = connect_client_quic_secp(server_addr, pubkey).await;
    fund_session(&mut conn, TEST_SESSION_PAYMENT).await;
    conn
}

async fn connect_client_tcp_funded(
    server_addr: std::net::SocketAddr,
    pubkey: &Secp256k1Pubkey,
) -> RelayConnection {
    let mut conn = connect_client_tcp(server_addr, pubkey).await;
    fund_session(&mut conn, TEST_SESSION_PAYMENT).await;
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

async fn request_session_status(
    h2_send: &mut h2::SendStream<Bytes>,
    h2_recv: &mut h2::RecvStream,
) -> (u64, u64, u64, i64, bool) {
    send_control_message(h2_send, &ClientMessage::GetSessionStatus, false).await;
    expect_session_status(read_control_message(h2_recv).await)
}

type SessionStatusTuple = (u64, u64, u64, i64, bool);

async fn wait_for_session_totals(
    h2_send: &mut h2::SendStream<Bytes>,
    h2_recv: &mut h2::RecvStream,
    expected_in: u64,
    expected_out: u64,
) -> Result<SessionStatusTuple, String> {
    let deadline = tokio::time::Instant::now() + Duration::from_millis(500);

    loop {
        let status = request_session_status(h2_send, h2_recv).await;
        if status.0 == expected_in && status.1 == expected_out {
            return Ok(status);
        }

        if tokio::time::Instant::now() >= deadline {
            let (actual_in, actual_out, _paid, remaining, paused) = status;
            return Err(format!(
                "timed out waiting for session totals: expected in={expected_in} out={expected_out}, got in={actual_in} out={actual_out} remaining={remaining} paused={paused}"
            ));
        }
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
            ..
        } => (
            session_total_in,
            session_total_out,
            total_paid_millisats,
            remaining_milli_sats,
            paused,
        ),
        other => panic!("expected SessionStatus, got {other:?}"),
    }
}

/// Send Hello, read initial SessionStatus.
/// Returns the initial session status fields.
async fn control_handshake(
    h2_send: &mut h2::SendStream<Bytes>,
    h2_recv: &mut h2::RecvStream,
) -> (u64, u64, u64, i64, bool) {
    send_control_message(h2_send, &ClientMessage::Hello { version: 0 }, false).await;

    let message = read_control_message(h2_recv).await;
    match &message {
        ServerMessage::SessionStatus {
            version,
            active_in_rate,
            active_out_rate,
            ..
        } => {
            assert_eq!(*version, 0);
            assert_eq!(*active_in_rate, 1);
            assert_eq!(*active_out_rate, 1);
        }
        other => panic!("expected SessionStatus, got {other:?}"),
    }

    expect_session_status(message)
}

async fn open_funded_control(
    conn: &RelayConnection,
    milli_sats: u64,
) -> (h2::SendStream<Bytes>, h2::RecvStream) {
    let (mut h2_send, mut h2_recv) = conn.open_control().await.unwrap();

    let (_in0, _out0, _paid0, rem0, paused0) = control_handshake(&mut h2_send, &mut h2_recv).await;
    assert!(paused0);
    assert_eq!(rem0, 0);

    let mut channel = SessionPaymentChannel::for_session_id(conn.session_id());
    let (_in1, _out1, paid1, rem1, paused1) = channel.link(&mut h2_send, &mut h2_recv).await;
    assert_eq!(paid1, 0);
    assert_eq!(rem1, 0);
    assert!(paused1);
    let (_in2, _out2, _paid2, rem2, paused2) =
        channel.pay(&mut h2_send, &mut h2_recv, milli_sats).await;
    assert!(!paused2, "session should unpause after funding");
    assert_eq!(rem2, milli_sats as i64);

    (h2_send, h2_recv)
}

async fn fund_session(conn: &mut RelayConnection, milli_sats: u64) {
    let (h2_send, h2_recv) = open_funded_control(conn, milli_sats).await;

    let keepalive = tokio::spawn(async move {
        let mut send = h2_send;
        let mut recv = h2_recv;
        while let Some(chunk) = recv.data().await {
            match chunk {
                Ok(data) => {
                    let len = data.len();
                    let _ = recv.flow_control().release_capacity(len);
                }
                Err(_) => break,
            }
        }
        let _ = send.send_data(Bytes::new(), true);
    });
    conn.add_task(keepalive);
}

struct SessionPaymentChannel {
    channel_id: String,
    cumulative_balance_units: u64,
    unit: &'static str,
}

impl SessionPaymentChannel {
    fn for_session_id(session_id: &[u8; 32]) -> Self {
        Self {
            channel_id: format!("test-chan-{}", hex::encode(&session_id[..8])),
            cumulative_balance_units: 0,
            unit: "msat",
        }
    }

    fn for_explicit_id(channel_id: impl Into<String>) -> Self {
        Self {
            channel_id: channel_id.into(),
            cumulative_balance_units: 0,
            unit: "msat",
        }
    }

    fn with_unit(mut self, unit: &'static str) -> Self {
        self.unit = unit;
        self
    }

    fn capacity_units(&self) -> u64 {
        TEST_CHANNEL_CAPACITY_UNITS
    }

    fn expected_capacity_millisats(&self) -> u64 {
        match self.unit {
            "sat" => self.capacity_units() * 1000,
            _ => self.capacity_units(),
        }
    }

    fn link_json(&self) -> String {
        serde_json::json!({
            "channel_id": self.channel_id,
            "balance": 0,
            "capacity": self.capacity_units(),
            "unit": self.unit,
        })
        .to_string()
    }

    fn payment_json(&self) -> String {
        serde_json::json!({
            "channel_id": self.channel_id,
            "balance": self.cumulative_balance_units,
        })
        .to_string()
    }

    async fn link(
        &mut self,
        h2_send: &mut h2::SendStream<Bytes>,
        h2_recv: &mut h2::RecvStream,
    ) -> (u64, u64, u64, i64, bool) {
        send_control_message(
            h2_send,
            &ClientMessage::ChannelLink {
                payment_json: self.link_json(),
            },
            false,
        )
        .await;

        match read_control_message(h2_recv).await {
            ServerMessage::ChannelLinkAccepted {
                channel_id,
                capacity,
            } => {
                assert_eq!(channel_id, self.channel_id);
                assert_eq!(capacity, self.expected_capacity_millisats());
            }
            other => panic!("expected ChannelLinkAccepted, got {other:?}"),
        }

        match read_control_message(h2_recv).await {
            ServerMessage::SessionStatus {
                linked_channel,
                session_total_in,
                session_total_out,
                total_paid_millisats,
                remaining_milli_sats,
                paused,
                ..
            } => {
                let linked_channel = linked_channel.expect("linked channel status after link");
                assert_eq!(linked_channel.channel_id, self.channel_id);
                assert_eq!(linked_channel.balance_raw, 0);
                assert_eq!(linked_channel.capacity_raw, self.capacity_units());
                assert_eq!(linked_channel.unit, self.unit);
                (
                    session_total_in,
                    session_total_out,
                    total_paid_millisats,
                    remaining_milli_sats,
                    paused,
                )
            }
            other => panic!("expected SessionStatus after link, got {other:?}"),
        }
    }

    async fn pay(
        &mut self,
        h2_send: &mut h2::SendStream<Bytes>,
        h2_recv: &mut h2::RecvStream,
        delta_millisats: u64,
    ) -> (u64, u64, u64, i64, bool) {
        let delta_units = match self.unit {
            "sat" => {
                assert_eq!(
                    delta_millisats % 1000,
                    0,
                    "sat test deltas must be multiples of 1000 millisats"
                );
                delta_millisats / 1000
            }
            _ => delta_millisats,
        };
        self.cumulative_balance_units = self.cumulative_balance_units.saturating_add(delta_units);

        send_control_message(
            h2_send,
            &ClientMessage::ChannelPayment {
                payment_json: self.payment_json(),
            },
            false,
        )
        .await;

        match read_control_message(h2_recv).await {
            ServerMessage::SessionStatus {
                linked_channel,
                session_total_in,
                session_total_out,
                total_paid_millisats,
                remaining_milli_sats,
                paused,
                ..
            } => {
                let linked_channel = linked_channel.expect("linked channel status after payment");
                assert_eq!(linked_channel.channel_id, self.channel_id);
                assert_eq!(linked_channel.balance_raw, self.cumulative_balance_units);
                assert_eq!(linked_channel.capacity_raw, self.capacity_units());
                assert_eq!(linked_channel.unit, self.unit);
                (
                    session_total_in,
                    session_total_out,
                    total_paid_millisats,
                    remaining_milli_sats,
                    paused,
                )
            }
            other => panic!("expected SessionStatus after payment, got {other:?}"),
        }
    }
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

fn mock_wallet_channel(
    channel_id: &str,
    receiver_pubkey: String,
    mint_url: String,
    keyset_id: String,
) -> WalletChannel {
    WalletChannel {
        channel_id: channel_id.to_string(),
        state: WalletChannelState::Open,
        receiver_pubkey,
        mint_url,
        unit: "sat".to_string(),
        keyset_id,
        attached_session_id: None,
        capacity_msats: 20_000_000,
        current_signed_balance_msats: 0,
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[tokio::test]
async fn test_session_starts_paused() {
    let (server_addr, pubkey) = start_monad_relay().await;
    let conn = connect_client_quic_secp(server_addr, &pubkey).await;
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
    let (server_addr, pubkey) = start_monad_relay().await;
    let conn = connect_client_quic_secp(server_addr, &pubkey).await;

    let (mut first_send, mut first_recv) = conn.open_control().await.unwrap();
    let (_in0, _out0, _paid0, _rem0, paused0) =
        control_handshake(&mut first_send, &mut first_recv).await;
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

    let (server_addr, pubkey) = start_monad_relay().await;
    let conn = connect_client_quic_secp(server_addr, &pubkey).await;
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
async fn test_channel_link_does_not_unpause_session() {
    let (server_addr, pubkey) = start_monad_relay().await;
    let conn = connect_client_quic_secp(server_addr, &pubkey).await;
    let (mut control_send, mut control_recv) = conn.open_control().await.unwrap();

    let (_in0, _out0, _paid0, rem0, paused0) =
        control_handshake(&mut control_send, &mut control_recv).await;
    assert!(paused0);
    assert_eq!(rem0, 0);

    let mut channel = SessionPaymentChannel::for_explicit_id("chan-msat");
    let (_in1, _out1, paid1, rem1, paused1) =
        channel.link(&mut control_send, &mut control_recv).await;
    assert_eq!(paid1, 0);
    assert_eq!(rem1, 0);
    assert!(paused1);

    let _ = control_send.send_data(Bytes::new(), true);
    drop(control_send);
    drop(control_recv);
    tokio::time::sleep(std::time::Duration::from_millis(20)).await;
    conn.shutdown().await;
}

#[tokio::test]
async fn test_non_zero_channel_link_is_rejected_and_does_not_link_session() {
    let (server_addr, pubkey) = start_monad_relay().await;
    let conn = connect_client_quic_secp(server_addr, &pubkey).await;
    let (mut control_send, mut control_recv) = conn.open_control().await.unwrap();

    let (_in0, _out0, _paid0, rem0, paused0) =
        control_handshake(&mut control_send, &mut control_recv).await;
    assert!(paused0);
    assert_eq!(rem0, 0);

    let payment_json = serde_json::json!({
        "channel_id": "bad-link",
        "balance": 1,
        "capacity": TEST_CHANNEL_CAPACITY_UNITS,
        "unit": "msat",
    })
    .to_string();
    send_control_message(
        &mut control_send,
        &ClientMessage::ChannelLink { payment_json },
        false,
    )
    .await;

    match read_control_message(&mut control_recv).await {
        ServerMessage::Error { message } => {
            assert!(
                message.contains("link balance must be zero"),
                "unexpected error: {message}"
            );
        }
        other => panic!("expected Error for non-zero ChannelLink, got {other:?}"),
    }

    send_control_message(&mut control_send, &ClientMessage::GetSessionStatus, false).await;
    match read_control_message(&mut control_recv).await {
        ServerMessage::SessionStatus {
            linked_channel,
            total_paid_millisats,
            remaining_milli_sats,
            paused,
            ..
        } => {
            assert_eq!(linked_channel, None);
            assert_eq!(total_paid_millisats, 0);
            assert_eq!(remaining_milli_sats, 0);
            assert!(paused);
        }
        other => panic!("expected SessionStatus after rejected link, got {other:?}"),
    }

    let _ = control_send.send_data(Bytes::new(), true);
    drop(control_send);
    drop(control_recv);
    tokio::time::sleep(std::time::Duration::from_millis(20)).await;
    conn.shutdown().await;
}

#[tokio::test]
async fn test_unsupported_unit_channel_link_is_rejected_and_does_not_link_session() {
    let (server_addr, pubkey) = start_monad_relay().await;
    let conn = connect_client_quic_secp(server_addr, &pubkey).await;
    let (mut control_send, mut control_recv) = conn.open_control().await.unwrap();

    let (_in0, _out0, _paid0, rem0, paused0) =
        control_handshake(&mut control_send, &mut control_recv).await;
    assert!(paused0);
    assert_eq!(rem0, 0);

    let payment_json = serde_json::json!({
        "channel_id": "bad-unit",
        "balance": 0,
        "capacity": TEST_CHANNEL_CAPACITY_UNITS,
        "unit": "usd",
    })
    .to_string();
    send_control_message(
        &mut control_send,
        &ClientMessage::ChannelLink { payment_json },
        false,
    )
    .await;

    match read_control_message(&mut control_recv).await {
        ServerMessage::Error { message } => {
            assert!(
                message.contains("unsupported unit"),
                "unexpected error: {message}"
            );
        }
        other => panic!("expected Error for unsupported-unit ChannelLink, got {other:?}"),
    }

    send_control_message(&mut control_send, &ClientMessage::GetSessionStatus, false).await;
    match read_control_message(&mut control_recv).await {
        ServerMessage::SessionStatus {
            linked_channel,
            total_paid_millisats,
            remaining_milli_sats,
            paused,
            ..
        } => {
            assert_eq!(linked_channel, None);
            assert_eq!(total_paid_millisats, 0);
            assert_eq!(remaining_milli_sats, 0);
            assert!(paused);
        }
        other => {
            panic!("expected SessionStatus after rejected unsupported-unit link, got {other:?}")
        }
    }

    let _ = control_send.send_data(Bytes::new(), true);
    drop(control_send);
    drop(control_recv);
    tokio::time::sleep(std::time::Duration::from_millis(20)).await;
    conn.shutdown().await;
}

#[tokio::test]
async fn test_channel_payment_msat_unpauses_with_raw_delta() {
    let (server_addr, pubkey) = start_monad_relay().await;
    let conn = connect_client_quic_secp(server_addr, &pubkey).await;
    let (mut control_send, mut control_recv) = conn.open_control().await.unwrap();

    let (_in0, _out0, _paid0, _rem0, paused0) =
        control_handshake(&mut control_send, &mut control_recv).await;
    assert!(paused0);

    let mut channel = SessionPaymentChannel::for_explicit_id("chan-msat");
    let (_in1, _out1, paid1, rem1, paused1) =
        channel.link(&mut control_send, &mut control_recv).await;
    assert_eq!(paid1, 0);
    assert_eq!(rem1, 0);
    assert!(paused1);
    let (_in1, _out1, paid1, rem1, paused1) =
        channel.pay(&mut control_send, &mut control_recv, 50).await;
    assert_eq!(paid1, 50);
    assert_eq!(rem1, 50);
    assert!(!paused1);

    let _ = control_send.send_data(Bytes::new(), true);
    drop(control_send);
    drop(control_recv);
    tokio::time::sleep(std::time::Duration::from_millis(20)).await;
    conn.shutdown().await;
}

#[tokio::test]
async fn test_channel_payment_with_funding_payload_is_rejected_and_state_is_unchanged() {
    let (server_addr, pubkey) = start_monad_relay().await;
    let conn = connect_client_quic_secp(server_addr, &pubkey).await;
    let (mut control_send, mut control_recv) = conn.open_control().await.unwrap();

    let (_in0, _out0, _paid0, _rem0, paused0) =
        control_handshake(&mut control_send, &mut control_recv).await;
    assert!(paused0);

    let mut channel = SessionPaymentChannel::for_explicit_id("chan-funded-payload");
    let (_in1, _out1, paid1, rem1, paused1) =
        channel.link(&mut control_send, &mut control_recv).await;
    assert_eq!(paid1, 0);
    assert_eq!(rem1, 0);
    assert!(paused1);
    let (_in2, _out2, paid2, rem2, paused2) =
        channel.pay(&mut control_send, &mut control_recv, 50).await;
    assert_eq!(paid2, 50);
    assert_eq!(rem2, 50);
    assert!(!paused2);

    let bad_payment_json = serde_json::json!({
        "channel_id": channel.channel_id,
        "balance": channel.cumulative_balance_units + 1,
        "params": { "fake": true },
    })
    .to_string();
    send_control_message(
        &mut control_send,
        &ClientMessage::ChannelPayment {
            payment_json: bad_payment_json,
        },
        false,
    )
    .await;

    match read_control_message(&mut control_recv).await {
        ServerMessage::Error { message } => {
            assert!(
                message.contains("must not include funding"),
                "unexpected error: {message}"
            );
        }
        other => panic!("expected Error for funding-bearing ChannelPayment, got {other:?}"),
    }

    send_control_message(&mut control_send, &ClientMessage::GetSessionStatus, false).await;
    match read_control_message(&mut control_recv).await {
        ServerMessage::SessionStatus {
            linked_channel,
            total_paid_millisats,
            remaining_milli_sats,
            paused,
            ..
        } => {
            assert_eq!(
                linked_channel
                    .as_ref()
                    .map(|channel| channel.channel_id.as_str()),
                Some("chan-funded-payload")
            );
            assert_eq!(total_paid_millisats, 50);
            assert_eq!(remaining_milli_sats, 50);
            assert!(!paused);
        }
        other => {
            panic!("expected SessionStatus after rejected funding-bearing payment, got {other:?}")
        }
    }

    let _ = control_send.send_data(Bytes::new(), true);
    drop(control_send);
    drop(control_recv);
    tokio::time::sleep(std::time::Duration::from_millis(20)).await;
    conn.shutdown().await;
}

#[tokio::test]
async fn test_session_payment_driver_links_unpauses_and_allows_data_flow() {
    let upper_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let upper_addr = upper_listener.local_addr().unwrap();
    tokio::spawn(run_uppercase_server(upper_listener));

    let (mint_url, keyset_id, mint_shutdown) = start_http_test_mint().await;
    let payment_receiver_secret = cashu::nuts::SecretKey::generate();
    let receiver_pubkey = payment_receiver_secret.public_key().to_hex();
    let mut trusted_mint_units = BTreeMap::new();
    trusted_mint_units.insert(mint_url.clone(), BTreeSet::from(["sat".to_string()]));
    let (server_addr, pubkey) =
        start_monad_relay_with_spilman(trusted_mint_units, payment_receiver_secret).await;

    let wallet = Arc::new(MockWallet::new());
    wallet
        .insert_channel(mock_wallet_channel(
            "driver-chan",
            receiver_pubkey,
            mint_url,
            keyset_id,
        ))
        .unwrap();

    let conn = connect_client_quic_secp(server_addr, &pubkey).await;
    let (driver_handle, ready_rx) = start_session_payment_driver(
        &conn,
        wallet.clone() as Arc<dyn monad_client::wallet::MonadWallet>,
        "integration hop",
    )
    .await
    .unwrap();
    timeout(Duration::from_secs(2), ready_rx)
        .await
        .expect("driver should ready")
        .expect("driver ready signal");

    let mut h2 = conn.clone_send_request().await;
    let target = format!("127.0.0.1:{}", upper_addr.port());
    let result = tunnel_roundtrip(&mut h2, &target, b"wallet flow").await;
    assert_eq!(result, b"WALLET FLOW");
    assert!(wallet.last_link_payload("driver-chan").unwrap().is_some());
    assert!(wallet
        .last_payment_payload("driver-chan")
        .unwrap()
        .is_some());

    driver_handle.abort();
    let _ = driver_handle.await;
    drop(h2);
    conn.shutdown().await;
    let _ = mint_shutdown.send(());
}

#[tokio::test]
async fn test_session_payment_driver_marks_invalid_channel_and_reselects() {
    let (mint_url, keyset_id, mint_shutdown) = start_http_test_mint().await;
    let payment_receiver_secret = cashu::nuts::SecretKey::generate();
    let receiver_pubkey = payment_receiver_secret.public_key().to_hex();
    let mut trusted_mint_units = BTreeMap::new();
    trusted_mint_units.insert(mint_url.clone(), BTreeSet::from(["sat".to_string()]));
    let (server_addr, pubkey) =
        start_monad_relay_with_spilman(trusted_mint_units, payment_receiver_secret).await;

    let wallet = Arc::new(MockWallet::new());
    wallet
        .insert_channel(mock_wallet_channel(
            "a-bad",
            receiver_pubkey.clone(),
            mint_url.clone(),
            keyset_id.clone(),
        ))
        .unwrap();
    wallet
        .insert_channel(mock_wallet_channel(
            "b-good",
            receiver_pubkey,
            mint_url,
            keyset_id,
        ))
        .unwrap();
    wallet.force_next_link_wrong_receiver("a-bad").unwrap();

    let conn = connect_client_quic_secp(server_addr, &pubkey).await;
    let (driver_handle, ready_rx) = start_session_payment_driver(
        &conn,
        wallet.clone() as Arc<dyn monad_client::wallet::MonadWallet>,
        "integration hop",
    )
    .await
    .unwrap();
    timeout(Duration::from_secs(2), ready_rx)
        .await
        .expect("driver should ready after reselection")
        .expect("driver ready signal");

    assert_eq!(
        wallet.get_channel("a-bad").unwrap().state,
        WalletChannelState::Closing
    );
    assert!(wallet.last_link_payload("a-bad").unwrap().is_some());
    assert!(wallet.last_link_payload("b-good").unwrap().is_some());
    assert!(wallet.last_payment_payload("b-good").unwrap().is_some());

    driver_handle.abort();
    let _ = driver_handle.await;
    conn.shutdown().await;
    let _ = mint_shutdown.send(());
}

#[tokio::test]
async fn test_session_payment_driver_detaches_evicted_channel() {
    let (mint_url, keyset_id, mint_shutdown) = start_http_test_mint().await;
    let payment_receiver_secret = cashu::nuts::SecretKey::generate();
    let receiver_pubkey = payment_receiver_secret.public_key().to_hex();
    let mut trusted_mint_units = BTreeMap::new();
    trusted_mint_units.insert(mint_url.clone(), BTreeSet::from(["sat".to_string()]));
    let (server_addr, pubkey) =
        start_monad_relay_with_spilman(trusted_mint_units, payment_receiver_secret).await;

    let wallet_a = Arc::new(MockWallet::new());
    let wallet_b = Arc::new(MockWallet::new());
    for wallet in [&wallet_a, &wallet_b] {
        wallet
            .insert_channel(mock_wallet_channel(
                "shared-channel",
                receiver_pubkey.clone(),
                mint_url.clone(),
                keyset_id.clone(),
            ))
            .unwrap();
    }

    let conn_a = connect_client_quic_secp(server_addr, &pubkey).await;
    let (driver_a, ready_a) = start_session_payment_driver(
        &conn_a,
        wallet_a.clone() as Arc<dyn monad_client::wallet::MonadWallet>,
        "driver a",
    )
    .await
    .unwrap();
    timeout(Duration::from_secs(2), ready_a)
        .await
        .expect("driver a should ready")
        .expect("driver a ready signal");
    assert!(wallet_a.attachment("shared-channel").unwrap().is_some());

    let conn_b = connect_client_quic_secp(server_addr, &pubkey).await;
    let (driver_b, ready_b) = start_session_payment_driver(
        &conn_b,
        wallet_b.clone() as Arc<dyn monad_client::wallet::MonadWallet>,
        "driver b",
    )
    .await
    .unwrap();
    timeout(Duration::from_secs(2), ready_b)
        .await
        .expect("driver b should ready")
        .expect("driver b ready signal");

    timeout(Duration::from_secs(2), async {
        loop {
            if wallet_a.attachment("shared-channel").unwrap().is_none() {
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("driver a should observe eviction");
    assert!(wallet_b.attachment("shared-channel").unwrap().is_some());

    driver_a.abort();
    let _ = driver_a.await;
    driver_b.abort();
    let _ = driver_b.await;
    conn_a.shutdown().await;
    conn_b.shutdown().await;
    let _ = mint_shutdown.send(());
}

#[tokio::test]
async fn test_channel_payment_sat_unpauses_with_millisat_conversion() {
    let (server_addr, pubkey) = start_monad_relay().await;
    let conn = connect_client_quic_secp(server_addr, &pubkey).await;
    let (mut control_send, mut control_recv) = conn.open_control().await.unwrap();

    let (_in0, _out0, _paid0, _rem0, paused0) =
        control_handshake(&mut control_send, &mut control_recv).await;
    assert!(paused0);

    let mut channel = SessionPaymentChannel::for_explicit_id("chan-sat").with_unit("sat");
    let (_in1, _out1, paid1, rem1, paused1) =
        channel.link(&mut control_send, &mut control_recv).await;
    assert_eq!(paid1, 0);
    assert_eq!(rem1, 0);
    assert!(paused1);
    let (_in1, _out1, paid1, rem1, paused1) = channel
        .pay(&mut control_send, &mut control_recv, 5_000)
        .await;
    assert_eq!(paid1, 5_000);
    assert_eq!(rem1, 5_000);
    assert!(!paused1);

    let _ = control_send.send_data(Bytes::new(), true);
    drop(control_send);
    drop(control_recv);
    tokio::time::sleep(std::time::Duration::from_millis(20)).await;
    conn.shutdown().await;
}

#[tokio::test]
async fn test_channel_eviction_clears_linked_channel() {
    let (server_addr, pubkey) = start_monad_relay().await;
    let conn_a = connect_client_quic_secp(server_addr, &pubkey).await;
    let conn_b = connect_client_quic_secp(server_addr, &pubkey).await;

    let (mut send_a, mut recv_a) = conn_a.open_control().await.unwrap();
    let (mut send_b, mut recv_b) = conn_b.open_control().await.unwrap();
    let _ = control_handshake(&mut send_a, &mut recv_a).await;
    let _ = control_handshake(&mut send_b, &mut recv_b).await;

    let mut channel_a = SessionPaymentChannel::for_explicit_id("shared");
    let mut channel_b = SessionPaymentChannel::for_explicit_id("shared");
    let _ = channel_a.link(&mut send_a, &mut recv_a).await;
    let _ = channel_b.link(&mut send_b, &mut recv_b).await;

    let evicted = timeout(
        Duration::from_millis(500),
        read_control_message(&mut recv_a),
    )
    .await
    .expect("expected eviction event");
    match evicted {
        ServerMessage::ChannelEvicted { channel_id } => {
            assert_eq!(channel_id, "shared");
        }
        other => panic!("expected ChannelEvicted, got {other:?}"),
    }

    match read_control_message(&mut recv_a).await {
        ServerMessage::SessionStatus {
            linked_channel,
            paused,
            ..
        } => {
            assert_eq!(linked_channel, None);
            assert!(paused);
        }
        other => panic!("expected SessionStatus for evicted session, got {other:?}"),
    }

    let _ = send_a.send_data(Bytes::new(), true);
    let _ = send_b.send_data(Bytes::new(), true);
    drop(send_a);
    drop(recv_a);
    drop(send_b);
    drop(recv_b);
    tokio::time::sleep(std::time::Duration::from_millis(20)).await;
    conn_a.shutdown().await;
    conn_b.shutdown().await;
}

#[tokio::test]
async fn test_control_detach_releases_channel_ownership() {
    let (server_addr, pubkey, payments) = start_monad_relay_with_test_payments().await;
    let conn_a = connect_client_quic_secp(server_addr, &pubkey).await;
    let conn_b = connect_client_quic_secp(server_addr, &pubkey).await;

    let (mut send_a, mut recv_a) = conn_a.open_control().await.unwrap();
    let (mut send_b, mut recv_b) = conn_b.open_control().await.unwrap();
    let _ = control_handshake(&mut send_a, &mut recv_a).await;
    let _ = control_handshake(&mut send_b, &mut recv_b).await;

    let mut channel = SessionPaymentChannel::for_explicit_id("detach-owned");
    let _ = channel.link(&mut send_a, &mut recv_a).await;
    assert_eq!(
        payments.owner_of("detach-owned"),
        Some(*conn_a.session_id()),
        "relay should record channel ownership for the linked session"
    );

    let _ = send_a.send_data(Bytes::new(), true);
    drop(send_a);
    drop(recv_a);

    timeout(Duration::from_secs(2), async {
        loop {
            if payments.owner_of("detach-owned").is_none() {
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("relay should release linked channel ownership after control detach");
    assert_eq!(
        payments.owner_of("detach-owned"),
        None,
        "relay should clear ownership map on detach"
    );

    let _ = channel.link(&mut send_b, &mut recv_b).await;
    assert_eq!(
        payments.owner_of("detach-owned"),
        Some(*conn_b.session_id()),
        "ownership should transfer cleanly to the new session"
    );

    let _ = send_b.send_data(Bytes::new(), true);
    drop(send_b);
    drop(recv_b);
    tokio::time::sleep(Duration::from_millis(20)).await;
    conn_a.shutdown().await;
    conn_b.shutdown().await;
}

#[tokio::test]
async fn test_control_detach_ends_active_and_future_streams() {
    let target_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let target_addr = target_listener.local_addr().unwrap();
    let (release_tx, release_rx) = tokio::sync::oneshot::channel();
    tokio::spawn(run_gated_reply_server(
        target_listener,
        5,
        b"DONE",
        release_rx,
    ));

    let (server_addr, pubkey) = start_monad_relay().await;
    let conn = connect_client_quic_secp(server_addr, &pubkey).await;

    let (mut control_send, mut control_recv) = conn.open_control().await.unwrap();
    let (_in0, _out0, _paid0, rem0, paused0) =
        control_handshake(&mut control_send, &mut control_recv).await;
    assert!(paused0);
    assert_eq!(rem0, 0);

    let mut channel = SessionPaymentChannel::for_session_id(conn.session_id());
    let _ = channel.link(&mut control_send, &mut control_recv).await;
    let (_in1, _out1, _paid1, rem1, paused1) = channel
        .pay(&mut control_send, &mut control_recv, TEST_SESSION_PAYMENT)
        .await;
    assert!(!paused1);
    assert_eq!(rem1, TEST_SESSION_PAYMENT as i64);

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

    h2_send.reserve_capacity(5);
    wait_for_send_capacity(&mut h2_send).await.unwrap();
    h2_send
        .send_data(Bytes::from_static(b"hello"), true)
        .unwrap();

    let _ = control_send.send_data(Bytes::new(), true);
    drop(control_send);
    drop(control_recv);

    let tunnel_ended = timeout(Duration::from_secs(2), async {
        match h2_recv.data().await {
            Some(Ok(_)) => Ok::<(), &'static str>(()),
            Some(Err(_)) | None => Err("ended"),
        }
    })
    .await;
    assert!(
        tunnel_ended.is_ok(),
        "active tunnel should end promptly after control detach"
    );

    let mut h2_after = conn.clone_send_request().await;
    let followup_request = Request::builder()
        .method(Method::CONNECT)
        .uri(format!("127.0.0.1:{}", target_addr.port()))
        .body(())
        .unwrap();
    let followup = timeout(Duration::from_secs(2), async {
        h2_after.send_request(followup_request, false)
    })
    .await;
    assert!(followup.is_ok(), "new stream attempt should fail promptly");
    if let Ok((response_future, _send)) = followup.unwrap() {
        let response = timeout(Duration::from_secs(2), response_future).await;
        assert!(
            response.is_err() || response.unwrap().is_err(),
            "followup CONNECT should not succeed after session teardown"
        );
    }

    let _ = release_tx.send(());
    drop(h2_send);
    drop(h2_recv);
    drop(h2);
    conn.shutdown().await;
}

async fn assert_nested_detach_releases_both_channels(
    parent_conn: RelayConnection,
    child_addr: std::net::SocketAddr,
    child_pubkey: Secp256k1Pubkey,
    parent_payments: Arc<InMemoryRelayPayments>,
    child_payments: Arc<InMemoryRelayPayments>,
) {
    let parent_conn = parent_conn;

    let (mut parent_send, mut parent_recv) = parent_conn.open_control().await.unwrap();
    let (_in0, _out0, _paid0, rem0, paused0) =
        control_handshake(&mut parent_send, &mut parent_recv).await;
    assert!(paused0);
    assert_eq!(rem0, 0);
    let mut parent_channel = SessionPaymentChannel::for_session_id(parent_conn.session_id());
    let _ = parent_channel
        .link(&mut parent_send, &mut parent_recv)
        .await;
    let _ = parent_channel
        .pay(&mut parent_send, &mut parent_recv, TEST_SESSION_PAYMENT)
        .await;
    assert_eq!(
        parent_payments.owner_of(&parent_channel.channel_id),
        Some(*parent_conn.session_id())
    );

    let child_conn =
        connect_nested_session(&parent_conn, &child_addr.to_string(), &child_pubkey).await;

    let (mut child_send, mut child_recv) = child_conn.open_control().await.unwrap();
    let (_in1, _out1, _paid1, rem1, paused1) =
        control_handshake(&mut child_send, &mut child_recv).await;
    assert!(paused1);
    assert_eq!(rem1, 0);
    let mut child_channel = SessionPaymentChannel::for_session_id(child_conn.session_id());
    let _ = child_channel.link(&mut child_send, &mut child_recv).await;
    let _ = child_channel
        .pay(&mut child_send, &mut child_recv, TEST_SESSION_PAYMENT)
        .await;
    assert_eq!(
        child_payments.owner_of(&child_channel.channel_id),
        Some(*child_conn.session_id())
    );

    let _ = parent_send.send_data(Bytes::new(), true);
    drop(parent_send);
    drop(parent_recv);

    timeout(Duration::from_secs(2), async {
        loop {
            if parent_payments
                .owner_of(&parent_channel.channel_id)
                .is_none()
                && child_payments.owner_of(&child_channel.channel_id).is_none()
            {
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("nested teardown should release both parent and child channels");

    let child_control_ended = timeout(Duration::from_secs(2), child_recv.data()).await;
    assert!(
        child_control_ended.is_ok(),
        "child control stream should end promptly when the parent session ends"
    );

    let mut child_h2 = child_conn.clone_send_request().await;
    let followup = timeout(Duration::from_secs(2), async {
        child_h2.send_request(
            Request::builder()
                .method(Method::CONNECT)
                .uri("127.0.0.1:9")
                .body(())
                .unwrap(),
            false,
        )
    })
    .await;
    assert!(
        followup.is_ok(),
        "child followup request should fail promptly"
    );
    if let Ok((response_future, _send)) = followup.unwrap() {
        let response = timeout(Duration::from_secs(2), response_future).await;
        assert!(response.is_err() || response.unwrap().is_err());
    }

    let _ = child_send.send_data(Bytes::new(), true);
    drop(child_send);
    child_conn.shutdown().await;
    parent_conn.shutdown().await;
}

#[tokio::test]
async fn test_nested_quic_parent_control_detach_releases_child_channel() {
    let (child_addr, child_pubkey, child_payments) = start_monad_relay_with_test_payments().await;
    let (parent_addr, parent_pubkey, parent_payments) =
        start_monad_relay_with_test_payments().await;

    let parent_conn = connect_client_quic_secp(parent_addr, &parent_pubkey).await;
    assert_nested_detach_releases_both_channels(
        parent_conn,
        child_addr,
        child_pubkey,
        parent_payments,
        child_payments,
    )
    .await;
}

#[tokio::test]
async fn test_nested_tcp_parent_control_detach_releases_child_channel() {
    let (child_addr, child_pubkey, child_payments) = start_monad_relay_with_test_payments().await;
    let (parent_addr, parent_pubkey, parent_payments) =
        start_monad_relay_with_test_payments().await;

    let parent_conn = connect_client_tcp(parent_addr, &parent_pubkey).await;
    assert_nested_detach_releases_both_channels(
        parent_conn,
        child_addr,
        child_pubkey,
        parent_payments,
        child_payments,
    )
    .await;
}

#[tokio::test]
async fn test_relinking_session_to_second_channel_preserves_credit_and_rejects_old_channel_payment()
{
    let (server_addr, pubkey) = start_monad_relay().await;
    let conn = connect_client_quic_secp(server_addr, &pubkey).await;
    let (mut control_send, mut control_recv) = conn.open_control().await.unwrap();

    let (_in0, _out0, _paid0, rem0, paused0) =
        control_handshake(&mut control_send, &mut control_recv).await;
    assert!(paused0);
    assert_eq!(rem0, 0);

    let mut channel_a = SessionPaymentChannel::for_explicit_id("chan-a");
    let mut channel_b = SessionPaymentChannel::for_explicit_id("chan-b");

    let (_in1, _out1, paid1, rem1, paused1) =
        channel_a.link(&mut control_send, &mut control_recv).await;
    assert_eq!(paid1, 0);
    assert_eq!(rem1, 0);
    assert!(paused1);
    let (_in1, _out1, paid1, rem1, paused1) =
        channel_a.pay(&mut control_send, &mut control_recv, 7).await;
    assert_eq!(paid1, 7);
    assert_eq!(rem1, 7);
    assert!(!paused1);

    let (_in2, _out2, paid2, rem2, paused2) =
        channel_b.link(&mut control_send, &mut control_recv).await;
    assert_eq!(paid2, 7);
    assert_eq!(rem2, 7);
    assert!(!paused2);
    send_control_message(&mut control_send, &ClientMessage::GetSessionStatus, false).await;
    match read_control_message(&mut control_recv).await {
        ServerMessage::SessionStatus {
            linked_channel,
            total_paid_millisats,
            remaining_milli_sats,
            paused,
            ..
        } => {
            assert_eq!(
                linked_channel
                    .as_ref()
                    .map(|channel| channel.channel_id.as_str()),
                Some("chan-b")
            );
            assert_eq!(total_paid_millisats, 7);
            assert_eq!(remaining_milli_sats, 7);
            assert!(!paused);
        }
        other => panic!("expected SessionStatus after relink, got {other:?}"),
    }

    let (_in2, _out2, paid2, rem2, paused2) =
        channel_b.pay(&mut control_send, &mut control_recv, 5).await;
    assert_eq!(paid2, 12);
    assert_eq!(rem2, 12);
    assert!(!paused2);

    channel_a.cumulative_balance_units = channel_a.cumulative_balance_units.saturating_add(1);
    send_control_message(
        &mut control_send,
        &ClientMessage::ChannelPayment {
            payment_json: channel_a.payment_json(),
        },
        false,
    )
    .await;
    match read_control_message(&mut control_recv).await {
        ServerMessage::Error { message } => {
            assert!(
                message.contains("wrong channel"),
                "unexpected error: {message}"
            );
        }
        other => panic!("expected Error for old channel payment, got {other:?}"),
    }

    send_control_message(&mut control_send, &ClientMessage::GetSessionStatus, false).await;
    match read_control_message(&mut control_recv).await {
        ServerMessage::SessionStatus {
            linked_channel,
            total_paid_millisats,
            remaining_milli_sats,
            paused,
            ..
        } => {
            assert_eq!(
                linked_channel
                    .as_ref()
                    .map(|channel| channel.channel_id.as_str()),
                Some("chan-b")
            );
            assert_eq!(total_paid_millisats, 12);
            assert_eq!(remaining_milli_sats, 12);
            assert!(!paused);
        }
        other => panic!("expected SessionStatus after rejected old channel payment, got {other:?}"),
    }

    let _ = control_send.send_data(Bytes::new(), true);
    drop(control_send);
    drop(control_recv);
    tokio::time::sleep(std::time::Duration::from_millis(20)).await;
    conn.shutdown().await;
}

#[tokio::test]
async fn test_session_repauses_and_resumes_after_second_payment() {
    let target_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let target_addr = target_listener.local_addr().unwrap();
    tokio::spawn(run_counting_server(target_listener, 10, b"DONE"));

    let (server_addr, pubkey) = start_monad_relay().await;
    let conn = connect_client_quic_secp(server_addr, &pubkey).await;

    let (mut control_send, mut control_recv) = conn.open_control().await.unwrap();
    let (_in0, _out0, _paid0, rem0, paused0) =
        control_handshake(&mut control_send, &mut control_recv).await;
    assert!(paused0);
    assert_eq!(rem0, 0);

    let mut channel = SessionPaymentChannel::for_session_id(conn.session_id());
    let (_in1, _out1, paid1, rem1, paused1) =
        channel.link(&mut control_send, &mut control_recv).await;
    assert_eq!(paid1, 0);
    assert_eq!(rem1, 0);
    assert!(paused1);
    let (_in1, _out1, _paid1, rem1, paused1) =
        channel.pay(&mut control_send, &mut control_recv, 5).await;
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

    let (_in2, out2, _paid2, rem2, paused2) =
        expect_session_status(read_control_message(&mut control_recv).await);
    assert!(paused2, "session should re-pause after credit is exhausted");
    assert_eq!(out2, 5);
    assert_eq!(rem2, 0);

    let stalled = tokio::time::timeout(std::time::Duration::from_millis(200), h2_recv.data()).await;
    assert!(
        stalled.is_err(),
        "CONNECT should stall while session is paused"
    );

    let (_in3, _out3, _paid3, rem3, paused3) =
        channel.pay(&mut control_send, &mut control_recv, 10).await;
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
    tokio::spawn(run_gated_reply_server(
        target_listener,
        10,
        b"DONE",
        release_rx,
    ));

    let (server_addr, pubkey) = start_monad_relay().await;
    let conn = connect_client_quic_secp(server_addr, &pubkey).await;

    let (mut control_send, mut control_recv) = conn.open_control().await.unwrap();
    let (_in0, _out0, _paid0, rem0, paused0) =
        control_handshake(&mut control_send, &mut control_recv).await;
    assert!(paused0);
    assert_eq!(rem0, 0);

    let mut channel = SessionPaymentChannel::for_session_id(conn.session_id());
    let (_in1, _out1, paid1, rem1, paused1) =
        channel.link(&mut control_send, &mut control_recv).await;
    assert_eq!(paid1, 0);
    assert_eq!(rem1, 0);
    assert!(paused1);
    let (_in1, _out1, _paid1, rem1, paused1) =
        channel.pay(&mut control_send, &mut control_recv, 5).await;
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
    h2_send
        .send_data(Bytes::from_static(b"abcdefghij"), true)
        .unwrap();

    let (_in2, out2, _paid2, rem2, paused2) =
        expect_session_status(read_control_message(&mut control_recv).await);
    assert!(paused2, "session should pause after overshooting credit");
    assert_eq!(out2, 10);
    assert_eq!(rem2, -5);

    let (_in3, _out3, _paid3, rem3, paused3) =
        channel.pay(&mut control_send, &mut control_recv, 10).await;
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
    tokio::spawn(run_gated_reply_server(
        target_listener,
        10,
        b"DONE",
        release_rx,
    ));

    let (server_addr, pubkey) = start_monad_relay().await;
    let conn = connect_client_quic_secp(server_addr, &pubkey).await;

    let (mut control_send, mut control_recv) = conn.open_control().await.unwrap();
    let (_in0, _out0, _paid0, rem0, paused0) =
        control_handshake(&mut control_send, &mut control_recv).await;
    assert!(paused0);
    assert_eq!(rem0, 0);

    let mut channel = SessionPaymentChannel::for_session_id(conn.session_id());
    let (_in1, _out1, paid1, rem1, paused1) =
        channel.link(&mut control_send, &mut control_recv).await;
    assert_eq!(paid1, 0);
    assert_eq!(rem1, 0);
    assert!(paused1);
    let (_in1, _out1, _paid1, rem1, paused1) =
        channel.pay(&mut control_send, &mut control_recv, 5).await;
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
    h2_send
        .send_data(Bytes::from_static(b"abcdefghij"), true)
        .unwrap();

    let (_in2, out2, _paid2, rem2, paused2) =
        expect_session_status(read_control_message(&mut control_recv).await);
    assert!(paused2, "session should pause after overshooting credit");
    assert_eq!(out2, 10);
    assert_eq!(rem2, -5);

    let (_in3, _out3, _paid3, rem3, paused3) =
        channel.pay(&mut control_send, &mut control_recv, 4).await;
    assert!(
        paused3,
        "session should stay paused while balance is non-positive"
    );
    assert_eq!(rem3, -1);

    let mut h2_for_paused_connect = conn.clone_send_request().await;
    let paused_request = Request::builder()
        .method(Method::CONNECT)
        .uri(format!("127.0.0.1:{}", target_addr.port()))
        .body(())
        .unwrap();
    let (paused_response_future, paused_h2_send) = h2_for_paused_connect
        .send_request(paused_request, false)
        .unwrap();
    let paused_response = paused_response_future.await.unwrap();
    assert_eq!(paused_response.status(), http::StatusCode::PAYMENT_REQUIRED);
    drop(paused_h2_send);
    drop(paused_response);
    drop(h2_for_paused_connect);

    let (_in4, _out4, _paid4, rem4, paused4) =
        channel.pay(&mut control_send, &mut control_recv, 6).await;
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

    // MONAD relay
    let (server_addr, pubkey) = start_monad_relay().await;

    // Client
    let conn = connect_client_quic_secp_funded(server_addr, &pubkey).await;
    let mut h2 = conn.clone_send_request().await;

    // Data channel: CONNECT → uppercase
    let target = format!("127.0.0.1:{}", upper_addr.port());
    let result = tunnel_roundtrip(&mut h2, &target, b"hello world").await;
    assert_eq!(result, b"HELLO WORLD");

    drop(h2);
    conn.shutdown().await;
}

#[tokio::test]
async fn test_client_cleartext_accounting_matches_relay_single_hop() {
    let upper_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let upper_addr = upper_listener.local_addr().unwrap();
    tokio::spawn(run_uppercase_server(upper_listener));

    let (server_addr, pubkey) = start_monad_relay().await;
    let conn = connect_client_quic_secp(server_addr, &pubkey).await;
    let (mut control_send, mut control_recv) =
        open_funded_control(&conn, TEST_SESSION_PAYMENT).await;

    let mut tunnel = conn.open_tunnel(&upper_addr.to_string()).await.unwrap();
    tunnel
        .write_all(b"hello single-hop accounting")
        .await
        .unwrap();
    tunnel.shutdown().await.unwrap();

    let mut result = Vec::new();
    tunnel.read_to_end(&mut result).await.unwrap();
    assert_eq!(result, b"HELLO SINGLE-HOP ACCOUNTING");

    let (expected_in, expected_out) = conn.local_session_totals();
    assert_eq!(expected_out, b"hello single-hop accounting".len() as u64);
    assert_eq!(expected_in, b"HELLO SINGLE-HOP ACCOUNTING".len() as u64);

    let (session_total_in, session_total_out, _paid, _remaining, _paused) =
        wait_for_session_totals(
            &mut control_send,
            &mut control_recv,
            expected_in,
            expected_out,
        )
        .await
        .expect("single-hop QUIC accounting should converge to exact totals");
    assert_eq!(session_total_in, expected_in);
    assert_eq!(session_total_out, expected_out);

    let _ = control_send.send_data(Bytes::new(), true);
    drop(control_send);
    drop(control_recv);
    conn.shutdown().await;
}

#[tokio::test]
async fn test_client_cleartext_accounting_matches_relay_single_hop_tcp() {
    let upper_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let upper_addr = upper_listener.local_addr().unwrap();
    tokio::spawn(run_uppercase_server(upper_listener));

    let (server_addr, pubkey) = start_monad_relay().await;
    let conn = connect_client_tcp(server_addr, &pubkey).await;
    let (mut control_send, mut control_recv) =
        open_funded_control(&conn, TEST_SESSION_PAYMENT).await;

    let mut tunnel = conn.open_tunnel(&upper_addr.to_string()).await.unwrap();
    tunnel.write_all(b"hello tcp accounting").await.unwrap();
    tunnel.shutdown().await.unwrap();

    let mut result = Vec::new();
    tunnel.read_to_end(&mut result).await.unwrap();
    assert_eq!(result, b"HELLO TCP ACCOUNTING");

    let (expected_in, expected_out) = conn.local_session_totals();
    assert_eq!(expected_out, b"hello tcp accounting".len() as u64);
    assert_eq!(expected_in, b"HELLO TCP ACCOUNTING".len() as u64);

    let (session_total_in, session_total_out, _paid, _remaining, _paused) =
        wait_for_session_totals(
            &mut control_send,
            &mut control_recv,
            expected_in,
            expected_out,
        )
        .await
        .expect("single-hop TCP accounting should converge to exact totals");
    assert_eq!(session_total_in, expected_in);
    assert_eq!(session_total_out, expected_out);

    let _ = control_send.send_data(Bytes::new(), true);
    drop(control_send);
    drop(control_recv);
    conn.shutdown().await;
}

#[tokio::test]
async fn test_client_cleartext_accounting_aggregates_multiple_tunnels() {
    let upper_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let upper_addr = upper_listener.local_addr().unwrap();
    tokio::spawn(run_uppercase_server(upper_listener));

    let (server_addr, pubkey) = start_monad_relay().await;
    let conn = connect_client_quic_secp(server_addr, &pubkey).await;
    let (mut control_send, mut control_recv) =
        open_funded_control(&conn, TEST_SESSION_PAYMENT).await;

    let payload_a = b"first aggregate tunnel".to_vec();
    let payload_b = b"second aggregate".to_vec();
    let target = upper_addr.to_string();

    let mut tunnel_a = conn.open_tunnel(&target).await.unwrap();
    let mut tunnel_b = conn.open_tunnel(&target).await.unwrap();

    let task_a = tokio::spawn(async move {
        tunnel_a.write_all(&payload_a).await.unwrap();
        tunnel_a.shutdown().await.unwrap();
        let mut result = Vec::new();
        tunnel_a.read_to_end(&mut result).await.unwrap();
        result
    });
    let task_b = tokio::spawn(async move {
        tunnel_b.write_all(&payload_b).await.unwrap();
        tunnel_b.shutdown().await.unwrap();
        let mut result = Vec::new();
        tunnel_b.read_to_end(&mut result).await.unwrap();
        result
    });

    let result_a = task_a.await.unwrap();
    let result_b = task_b.await.unwrap();
    assert_eq!(result_a, b"FIRST AGGREGATE TUNNEL");
    assert_eq!(result_b, b"SECOND AGGREGATE");

    let (expected_in, expected_out) = conn.local_session_totals();
    assert_eq!(
        expected_out,
        (b"first aggregate tunnel".len() + b"second aggregate".len()) as u64
    );
    assert_eq!(
        expected_in,
        (b"FIRST AGGREGATE TUNNEL".len() + b"SECOND AGGREGATE".len()) as u64
    );

    let (session_total_in, session_total_out, _paid, _remaining, _paused) =
        wait_for_session_totals(
            &mut control_send,
            &mut control_recv,
            expected_in,
            expected_out,
        )
        .await
        .expect("multi-stream accounting should converge to aggregate totals");
    assert_eq!(session_total_in, expected_in);
    assert_eq!(session_total_out, expected_out);

    let _ = control_send.send_data(Bytes::new(), true);
    drop(control_send);
    drop(control_recv);
    conn.shutdown().await;
}

/// Test two data tunnels simultaneously through the same H2 connection.
#[tokio::test]
async fn test_multiple_tunnels() {
    let upper_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let upper_addr = upper_listener.local_addr().unwrap();
    tokio::spawn(run_uppercase_server(upper_listener));

    let (server_addr, pubkey) = start_monad_relay().await;
    let conn = connect_client_quic_secp_funded(server_addr, &pubkey).await;
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

#[tokio::test]
async fn test_tcp_secp_single_hop() {
    let upper_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let upper_addr = upper_listener.local_addr().unwrap();
    tokio::spawn(run_uppercase_server(upper_listener));

    let (server_addr, pubkey) = start_monad_relay().await;
    let conn = connect_client_tcp_funded(server_addr, &pubkey).await;
    let mut h2 = conn.clone_send_request().await;

    let result = tunnel_roundtrip(&mut h2, &upper_addr.to_string(), b"hello via tcp secp").await;
    assert_eq!(result, b"HELLO VIA TCP SECP");

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
    let (s_addr, s_pubkey) = start_monad_relay().await;

    // Server T (intermediate hop — will proxy to S)
    let (t_addr, t_pubkey) = start_monad_relay().await;

    // Client connects through T → S
    let mut conn = connector::connect_through_chain(&[
        Hop {
            addr: t_addr.to_string(),
            identity: HopIdentity::Secp256k1(t_pubkey),
            use_quic: true,
        },
        Hop {
            addr: s_addr.to_string(),
            identity: HopIdentity::Secp256k1(s_pubkey),
            use_quic: true,
        },
    ])
    .await
    .unwrap();
    fund_session(&mut conn, TEST_SESSION_PAYMENT).await;
    let mut h2 = conn.clone_send_request().await;

    // Open a tunnel to the uppercase server (through S, via T)
    let target = format!("127.0.0.1:{}", upper_addr.port());
    let result = tunnel_roundtrip(&mut h2, &target, b"nested hello").await;
    assert_eq!(result, b"NESTED HELLO");

    drop(h2);
    conn.shutdown().await;
}

#[tokio::test]
async fn test_client_cleartext_accounting_matches_relay_nested_sessions() {
    let upper_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let upper_addr = upper_listener.local_addr().unwrap();
    tokio::spawn(run_uppercase_server(upper_listener));

    let (child_addr, child_pubkey) = start_monad_relay().await;
    let (parent_addr, parent_pubkey) = start_monad_relay().await;

    let parent_conn = connect_client_quic_secp(parent_addr, &parent_pubkey).await;
    let (mut parent_control_send, mut parent_control_recv) =
        open_funded_control(&parent_conn, TEST_SESSION_PAYMENT).await;

    let child_conn =
        connect_nested_session(&parent_conn, &child_addr.to_string(), &child_pubkey).await;
    let (mut child_control_send, mut child_control_recv) =
        open_funded_control(&child_conn, TEST_SESSION_PAYMENT).await;

    let mut tunnel = child_conn
        .open_tunnel(&upper_addr.to_string())
        .await
        .unwrap();
    tunnel.write_all(b"nested accounting").await.unwrap();
    tunnel.shutdown().await.unwrap();

    let mut result = Vec::new();
    tunnel.read_to_end(&mut result).await.unwrap();
    assert_eq!(result, b"NESTED ACCOUNTING");

    let (child_expected_in, child_expected_out) = child_conn.local_session_totals();
    assert_eq!(child_expected_out, b"nested accounting".len() as u64);
    assert_eq!(child_expected_in, b"NESTED ACCOUNTING".len() as u64);

    let (child_session_total_in, child_session_total_out, _paid, _remaining, _paused) =
        wait_for_session_totals(
            &mut child_control_send,
            &mut child_control_recv,
            child_expected_in,
            child_expected_out,
        )
        .await
        .expect("nested child TCP accounting should converge to exact totals");
    assert_eq!(child_session_total_in, child_expected_in);
    assert_eq!(child_session_total_out, child_expected_out);

    let (parent_expected_in, parent_expected_out) = parent_conn.local_session_totals();
    let (parent_session_total_in, parent_session_total_out, _paid, _remaining, _paused) =
        wait_for_session_totals(
            &mut parent_control_send,
            &mut parent_control_recv,
            parent_expected_in,
            parent_expected_out,
        )
        .await
        .expect("nested parent TCP accounting should converge to exact totals");
    assert_eq!(parent_session_total_in, parent_expected_in);
    assert_eq!(parent_session_total_out, parent_expected_out);

    let _ = child_control_send.send_data(Bytes::new(), true);
    let _ = parent_control_send.send_data(Bytes::new(), true);
    drop(child_control_send);
    drop(child_control_recv);
    drop(parent_control_send);
    drop(parent_control_recv);
    child_conn.shutdown().await;
    parent_conn.shutdown().await;
}

#[tokio::test]
async fn test_client_cleartext_accounting_matches_relay_nested_quic_sessions() {
    let upper_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let upper_addr = upper_listener.local_addr().unwrap();
    tokio::spawn(run_uppercase_server(upper_listener));

    let (child_addr, child_pubkey) = start_monad_relay().await;
    let (parent_addr, parent_pubkey) = start_monad_relay().await;

    let parent_conn = connect_client_quic_secp(parent_addr, &parent_pubkey).await;
    let (mut parent_control_send, mut parent_control_recv) =
        open_funded_control(&parent_conn, TEST_SESSION_PAYMENT).await;

    let child_conn =
        connect_nested_session_quic(&parent_conn, &child_addr.to_string(), &child_pubkey).await;
    let (mut child_control_send, mut child_control_recv) =
        open_funded_control(&child_conn, TEST_SESSION_PAYMENT).await;

    let mut tunnel = child_conn
        .open_tunnel(&upper_addr.to_string())
        .await
        .unwrap();
    tunnel.write_all(b"nested quic accounting").await.unwrap();
    tunnel.shutdown().await.unwrap();

    let mut result = Vec::new();
    tunnel.read_to_end(&mut result).await.unwrap();
    assert_eq!(result, b"NESTED QUIC ACCOUNTING");

    let (child_expected_in, child_expected_out) = child_conn.local_session_totals();
    assert_eq!(child_expected_out, b"nested quic accounting".len() as u64);
    assert_eq!(child_expected_in, b"NESTED QUIC ACCOUNTING".len() as u64);

    let (child_session_total_in, child_session_total_out, _paid, _remaining, _paused) =
        wait_for_session_totals(
            &mut child_control_send,
            &mut child_control_recv,
            child_expected_in,
            child_expected_out,
        )
        .await
        .expect("nested child QUIC accounting should converge to exact totals");
    assert_eq!(child_session_total_in, child_expected_in);
    assert_eq!(child_session_total_out, child_expected_out);

    let (parent_expected_in, parent_expected_out) = parent_conn.local_session_totals();
    let (parent_session_total_in, parent_session_total_out, _paid, _remaining, _paused) =
        wait_for_session_totals(
            &mut parent_control_send,
            &mut parent_control_recv,
            parent_expected_in,
            parent_expected_out,
        )
        .await
        .expect("nested parent QUIC accounting should converge to exact totals");
    assert_eq!(parent_session_total_in, parent_expected_in);
    assert_eq!(parent_session_total_out, parent_expected_out);

    let _ = child_control_send.send_data(Bytes::new(), true);
    let _ = parent_control_send.send_data(Bytes::new(), true);
    drop(child_control_send);
    drop(child_control_recv);
    drop(parent_control_send);
    drop(parent_control_recv);
    child_conn.shutdown().await;
    parent_conn.shutdown().await;
}

#[tokio::test]
async fn test_client_tunnel_helper_updates_session_accounting() {
    let upper_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let upper_addr = upper_listener.local_addr().unwrap();
    tokio::spawn(run_uppercase_server(upper_listener));

    let (server_addr, pubkey) = start_monad_relay().await;
    let conn = connect_client_quic_secp(server_addr, &pubkey).await;
    let (mut control_send, mut control_recv) =
        open_funded_control(&conn, TEST_SESSION_PAYMENT).await;

    let local_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let local_addr = local_listener.local_addr().unwrap();
    let local_peer = tokio::spawn(async move {
        let mut stream = tokio::net::TcpStream::connect(local_addr).await.unwrap();
        let mut socks_reply = [0u8; 10];
        stream.read_exact(&mut socks_reply).await.unwrap();
        assert_eq!(socks_reply, [0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0]);
        stream.write_all(b"helper path payload").await.unwrap();
        stream.shutdown().await.unwrap();
        let mut result = Vec::new();
        stream.read_to_end(&mut result).await.unwrap();
        result
    });

    let (mut accepted, _) = local_listener.accept().await.unwrap();
    tunnel::open_tunnel(&conn, &upper_addr.to_string(), &mut accepted)
        .await
        .unwrap();
    let result = local_peer.await.unwrap();
    assert_eq!(result, b"HELPER PATH PAYLOAD");

    let (expected_in, expected_out) = conn.local_session_totals();
    assert_eq!(expected_out, b"helper path payload".len() as u64);
    assert_eq!(expected_in, b"HELPER PATH PAYLOAD".len() as u64);

    let (session_total_in, session_total_out, _paid, _remaining, _paused) =
        wait_for_session_totals(
            &mut control_send,
            &mut control_recv,
            expected_in,
            expected_out,
        )
        .await
        .expect("tunnel helper accounting should converge to exact totals");
    assert_eq!(session_total_in, expected_in);
    assert_eq!(session_total_out, expected_out);

    let _ = control_send.send_data(Bytes::new(), true);
    drop(control_send);
    drop(control_recv);
    conn.shutdown().await;
}

#[tokio::test]
async fn test_nested_plain_tcp_tunnel() {
    let upper_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let upper_addr = upper_listener.local_addr().unwrap();
    tokio::spawn(run_uppercase_server(upper_listener));

    let (s_addr, s_pubkey) = start_monad_relay().await;
    let (t_addr, t_pubkey) = start_monad_relay().await;

    let mut conn = connector::connect_through_chain(&[
        Hop {
            addr: t_addr.to_string(),
            identity: HopIdentity::Secp256k1(t_pubkey),
            use_quic: false,
        },
        Hop {
            addr: s_addr.to_string(),
            identity: HopIdentity::Secp256k1(s_pubkey),
            use_quic: false,
        },
    ])
    .await
    .unwrap();
    fund_session(&mut conn, TEST_SESSION_PAYMENT).await;
    let mut h2 = conn.clone_send_request().await;

    let target = format!("127.0.0.1:{}", upper_addr.port());
    let result = tunnel_roundtrip(&mut h2, &target, b"nested tcp hello").await;
    assert_eq!(result, b"NESTED TCP HELLO");

    drop(h2);
    conn.shutdown().await;
}

/// Test nested tunneling with 3 hops: Client → A → B → C → uppercase.
#[tokio::test]
async fn test_three_hop_tunnel() {
    let upper_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let upper_addr = upper_listener.local_addr().unwrap();
    tokio::spawn(run_uppercase_server(upper_listener));

    let (a_addr, a_pubkey) = start_monad_relay().await;
    let (b_addr, b_pubkey) = start_monad_relay().await;
    let (c_addr, c_pubkey) = start_monad_relay().await;

    let mut conn = connector::connect_through_chain(&[
        Hop {
            addr: a_addr.to_string(),
            identity: HopIdentity::Secp256k1(a_pubkey),
            use_quic: true,
        },
        Hop {
            addr: b_addr.to_string(),
            identity: HopIdentity::Secp256k1(b_pubkey),
            use_quic: true,
        },
        Hop {
            addr: c_addr.to_string(),
            identity: HopIdentity::Secp256k1(c_pubkey),
            use_quic: true,
        },
    ])
    .await
    .unwrap();
    fund_session(&mut conn, TEST_SESSION_PAYMENT).await;
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

    let (server_addr, pubkey) = start_monad_relay().await;
    let conn = connect_client_quic_secp_funded(server_addr, &pubkey).await;
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
        start_monad_relay_at(SocketAddr::new(IpAddr::V6(Ipv6Addr::LOCALHOST), 0)).await
    else {
        return;
    };

    let upper_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let upper_addr = upper_listener.local_addr().unwrap();
    tokio::spawn(run_uppercase_server(upper_listener));

    let conn = connect_client_quic_secp_funded(server_addr, &pubkey).await;
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
        start_monad_relay_at(SocketAddr::new(IpAddr::V6(Ipv6Addr::LOCALHOST), 0)).await
    else {
        return;
    };

    let (ipv4_hop_addr, ipv4_hop_pubkey) = start_monad_relay().await;

    let upper_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let upper_addr = upper_listener.local_addr().unwrap();
    tokio::spawn(run_uppercase_server(upper_listener));

    let mut conn = connector::connect_through_chain(&[
        Hop {
            addr: ipv4_hop_addr.to_string(),
            identity: HopIdentity::Secp256k1(ipv4_hop_pubkey),
            use_quic: true,
        },
        Hop {
            addr: ipv6_hop_addr.to_string(),
            identity: HopIdentity::Secp256k1(ipv6_hop_pubkey),
            use_quic: true,
        },
    ])
    .await
    .unwrap();
    fund_session(&mut conn, TEST_SESSION_PAYMENT).await;
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

    let (server_addr, pubkey) = start_monad_relay().await;
    let conn = connect_client_quic_secp_funded(server_addr, &pubkey).await;
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

#[tokio::test]
async fn test_quic_secp256k1_first_hop_single_hop() {
    let upper_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let upper_addr = upper_listener.local_addr().unwrap();
    tokio::spawn(run_uppercase_server(upper_listener));

    let (server_addr, pubkey) = start_monad_relay().await;
    let mut conn = connector::connect_through_chain(&[Hop {
        addr: server_addr.to_string(),
        identity: HopIdentity::Secp256k1(pubkey),
        use_quic: true,
    }])
    .await
    .unwrap();
    fund_session(&mut conn, TEST_SESSION_PAYMENT).await;
    let mut h2 = conn.clone_send_request().await;

    let result = tunnel_roundtrip(&mut h2, &upper_addr.to_string(), b"quic secp first hop").await;
    assert_eq!(result, b"QUIC SECP FIRST HOP");

    drop(h2);
    conn.shutdown().await;
}

#[tokio::test]
async fn test_two_hop_quic_secp_chain() {
    let upper_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let upper_addr = upper_listener.local_addr().unwrap();
    tokio::spawn(run_uppercase_server(upper_listener));

    let (first_addr, first_pubkey) = start_monad_relay().await;
    let (second_addr, second_pubkey) = start_monad_relay().await;

    let mut conn = connector::connect_through_chain(&[
        Hop {
            addr: first_addr.to_string(),
            identity: HopIdentity::Secp256k1(first_pubkey),
            use_quic: true,
        },
        Hop {
            addr: second_addr.to_string(),
            identity: HopIdentity::Secp256k1(second_pubkey),
            use_quic: true,
        },
    ])
    .await
    .unwrap();
    fund_session(&mut conn, TEST_SESSION_PAYMENT).await;
    let mut h2 = conn.clone_send_request().await;

    let result = tunnel_roundtrip(&mut h2, &upper_addr.to_string(), b"mixed secp second hop").await;
    assert_eq!(result, b"MIXED SECP SECOND HOP");

    drop(h2);
    conn.shutdown().await;
}

#[tokio::test]
async fn test_quic_unknown_stream_kind_rejected() {
    let (server_addr, pubkey) = start_monad_relay().await;

    let client_config = build_client_config_for_auth(ClientAuthMode::Secp256k1(pubkey)).unwrap();

    let mut endpoint = quinn::Endpoint::client("0.0.0.0:0".parse().unwrap()).unwrap();
    endpoint.set_default_client_config(client_config);

    let conn = connect_with_auth(&endpoint, server_addr, ClientAuthMode::Secp256k1(pubkey))
        .await
        .unwrap();

    let (mut send, mut recv) = conn.open_bi().await.unwrap();
    send.write_all(&[0xff]).await.unwrap();
    send.flush().await.unwrap();

    let mut buf = [0u8; 1];
    let result = timeout(Duration::from_secs(1), recv.read(&mut buf)).await;
    assert!(
        result.is_ok(),
        "relay did not reject unknown stream kind promptly"
    );
    assert!(
        result.unwrap().is_err(),
        "relay accepted unknown stream kind unexpectedly"
    );
}

#[tokio::test]
async fn test_quic_secp256k1_auth_direct_connection() {
    let (server_addr, pubkey) = start_monad_relay().await;
    let mut endpoint = quinn::Endpoint::client("0.0.0.0:0".parse().unwrap()).unwrap();
    let client_config = build_client_config_for_auth(ClientAuthMode::Secp256k1(pubkey)).unwrap();
    endpoint.set_default_client_config(client_config);

    let conn = connect_with_auth(&endpoint, server_addr, ClientAuthMode::Secp256k1(pubkey))
        .await
        .unwrap();
    drop(conn);
}

#[tokio::test]
async fn test_quic_secp256k1_auth_direct_connection_wrong_key_fails() {
    let (server_addr, _pubkey) = start_monad_relay().await;
    let wrong_pubkey = SecpTransportKeypair::generate().pubkey();
    let mut endpoint = quinn::Endpoint::client("0.0.0.0:0".parse().unwrap()).unwrap();
    let client_config =
        build_client_config_for_auth(ClientAuthMode::Secp256k1(wrong_pubkey)).unwrap();
    endpoint.set_default_client_config(client_config);

    let result = connect_with_auth(
        &endpoint,
        server_addr,
        ClientAuthMode::Secp256k1(wrong_pubkey),
    )
    .await;
    assert!(result.is_err(), "expected wrong secp256k1 auth to fail");
}

#[tokio::test]
async fn test_quic_pool_supports_secp256k1_auth() {
    let (server_addr, pubkey) = start_monad_relay().await;
    let pool = QuicPool::new().unwrap();

    let stream = pool
        .open_stream(&server_addr.to_string(), ClientAuthMode::Secp256k1(pubkey))
        .await
        .unwrap();
    drop(stream);
}

#[tokio::test]
async fn test_quic_pool_rejects_wrong_secp256k1_pubkey() {
    let (server_addr, _pubkey) = start_monad_relay().await;
    let wrong_pubkey = SecpTransportKeypair::generate().pubkey();
    let pool = QuicPool::new().unwrap();

    let err = match pool
        .open_stream(
            &server_addr.to_string(),
            ClientAuthMode::Secp256k1(wrong_pubkey),
        )
        .await
    {
        Ok(_) => panic!("expected wrong secp256k1 pubkey to reject pooled QUIC connect"),
        Err(err) => err,
    };
    assert_eq!(err.kind(), std::io::ErrorKind::PermissionDenied);
}

/// Test: connect to a MONAD relay over QUIC, open a CONNECT tunnel,
/// proxy data through the uppercase server.
#[tokio::test]
async fn test_quic_single_hop() {
    let upper_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let upper_addr = upper_listener.local_addr().unwrap();
    tokio::spawn(run_uppercase_server(upper_listener));

    let (server_addr, pubkey) = start_monad_relay().await;
    let conn = connect_client_quic_secp_funded(server_addr, &pubkey).await;
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

    let (server_addr, pubkey) = start_monad_relay().await;
    let conn = connect_client_quic_secp_funded(server_addr, &pubkey).await;
    let mut h2 = conn.clone_send_request().await;

    // Data channel
    let result = tunnel_roundtrip(&mut h2, &upper_addr.to_string(), b"quic data test").await;
    assert_eq!(result, b"QUIC DATA TEST");

    drop(h2);
    conn.shutdown().await;
}

/// Test: 2-hop nested route where relay S forwards to relay T via QUIC.
///
/// Client → S (QUIC+Noise+H2) → CONNECT T:port [quic-secp256k1-pubkey header] → T (QUIC+Noise+H2) → uppercase
///
/// This test manually constructs the H2 CONNECT request with the
/// `quic-secp256k1-pubkey` header
/// to exercise the relay-side QUIC forwarding path directly.
#[tokio::test]
async fn test_nested_quic_tunnel() {
    // Uppercase server (final external target)
    let upper_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let upper_addr = upper_listener.local_addr().unwrap();
    tokio::spawn(run_uppercase_server(upper_listener));

    // Server T (final hop — QUIC-enabled, will proxy to uppercase server)
    let (t_addr, t_pubkey) = start_monad_relay().await;

    // Server S (intermediate hop — TCP only, will forward via QUIC to T)
    let (s_addr, s_pubkey) = start_monad_relay().await;

    // Client connects to S via TCP (first hop)
    let conn_to_s = connect_client_quic_secp_funded(s_addr, &s_pubkey).await;
    let mut h2_to_s = conn_to_s.clone_send_request().await;

    let t_quic_pubkey = t_pubkey.to_hex();

    // Ask S to CONNECT to T via QUIC (using secp256k1 auth header)
    let t_authority = format!("127.0.0.1:{}", t_addr.port());
    let request = Request::builder()
        .method(Method::CONNECT)
        .uri(&t_authority)
        .header(
            monad_relay::session::QUIC_SECP256K1_PUBKEY_HEADER,
            &t_quic_pubkey,
        )
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
        monad_common::h2stream::H2ConnectStream::new(h2_send_to_t, h2_recv_from_t, None);

    // secp Noise handshake to T (nested inside the QUIC-forwarded tunnel)
    let mut stream = h2_connect_stream;
    let (send_cipher, recv_cipher, session_id) =
        noise_secp256k1::handshake_initiator(&mut stream, &t_pubkey)
            .await
            .unwrap();
    let noise_stream = noise_secp256k1::SecpNoiseStream::new(
        stream,
        send_cipher,
        recv_cipher,
        session_id,
        "nested quic secp test",
    );

    // Create RelayConnection to T
    let (mut conn_to_t, driver) = RelayConnection::from_transport_stream(noise_stream, session_id)
        .await
        .unwrap();
    conn_to_t.add_driver(driver);
    fund_session(&mut conn_to_t, TEST_SESSION_PAYMENT).await;
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

#[tokio::test]
async fn test_relay_can_connect_to_itself_via_quic() {
    let upper_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let upper_addr = upper_listener.local_addr().unwrap();
    tokio::spawn(run_uppercase_server(upper_listener));

    let (relay_addr, relay_pubkey) = start_monad_relay().await;

    let mut outer_conn = connect_client_quic_secp(relay_addr, &relay_pubkey).await;
    fund_session(&mut outer_conn, TEST_SESSION_PAYMENT).await;

    let mut inner_conn =
        connect_nested_session_quic(&outer_conn, &relay_addr.to_string(), &relay_pubkey).await;
    fund_session(&mut inner_conn, TEST_SESSION_PAYMENT).await;

    let mut h2 = inner_conn.clone_send_request().await;
    let result = tunnel_roundtrip(&mut h2, &upper_addr.to_string(), b"self quic hello").await;
    assert_eq!(result, b"SELF QUIC HELLO");

    drop(h2);
    inner_conn.shutdown().await;
    outer_conn.shutdown().await;
}

#[tokio::test]
async fn test_relay_can_connect_to_itself_via_tcp() {
    let upper_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let upper_addr = upper_listener.local_addr().unwrap();
    tokio::spawn(run_uppercase_server(upper_listener));

    let (relay_addr, relay_pubkey) = start_monad_relay().await;

    let mut outer_conn = connect_client_quic_secp(relay_addr, &relay_pubkey).await;
    fund_session(&mut outer_conn, TEST_SESSION_PAYMENT).await;

    let mut inner_conn =
        connect_nested_session(&outer_conn, &relay_addr.to_string(), &relay_pubkey).await;
    fund_session(&mut inner_conn, TEST_SESSION_PAYMENT).await;

    let mut h2 = inner_conn.clone_send_request().await;
    let result = tunnel_roundtrip(&mut h2, &upper_addr.to_string(), b"self tcp hello").await;
    assert_eq!(result, b"SELF TCP HELLO");

    drop(h2);
    inner_conn.shutdown().await;
    outer_conn.shutdown().await;
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
    let (t_addr, t_pubkey) = start_monad_relay().await;

    // Server S (intermediate hop — TCP only)
    let (s_addr, s_pubkey) = start_monad_relay().await;

    // Use the client connector with a QUIC hop (single key per hop)
    let mut conn = connector::connect_through_chain(&[
        Hop {
            addr: s_addr.to_string(),
            identity: HopIdentity::Secp256k1(s_pubkey),
            use_quic: true,
        },
        Hop {
            addr: format!("127.0.0.1:{}", t_addr.port()),
            identity: HopIdentity::Secp256k1(t_pubkey),
            use_quic: true,
        },
    ])
    .await
    .unwrap();
    fund_session(&mut conn, TEST_SESSION_PAYMENT).await;
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
    let (t_addr, t_pubkey) = start_monad_relay().await;

    // Server S (intermediate, all clients connect through this)
    let (s_addr, s_pubkey) = start_monad_relay().await;

    let t_port = t_addr.port();
    let upper_port = upper_addr.port();

    // Spawn 5 clients concurrently, all routing through S → QUIC → T → uppercase
    let mut handles = Vec::new();
    for i in 0..5 {
        handles.push(tokio::spawn(async move {
            let mut conn = connector::connect_through_chain(&[
                Hop {
                    addr: s_addr.to_string(),
                    identity: HopIdentity::Secp256k1(s_pubkey),
                    use_quic: true,
                },
                Hop {
                    addr: format!("127.0.0.1:{t_port}"),
                    identity: HopIdentity::Secp256k1(t_pubkey),
                    use_quic: true,
                },
            ])
            .await
            .unwrap();
            fund_session(&mut conn, TEST_SESSION_PAYMENT).await;
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

    let (server_addr, pubkey) = start_monad_relay().await;

    // Client connects directly via QUIC (use_quic on the first hop)
    let mut conn = connector::connect_through_chain(&[Hop {
        addr: server_addr.to_string(),
        identity: HopIdentity::Secp256k1(pubkey),
        use_quic: true,
    }])
    .await
    .unwrap();
    fund_session(&mut conn, TEST_SESSION_PAYMENT).await;
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

    let (s_addr, s_pubkey) = start_monad_relay().await;
    let (t_addr, t_pubkey) = start_monad_relay().await;

    // Client connects to S via QUIC, then S forwards to T via TCP
    let mut conn = connector::connect_through_chain(&[
        Hop {
            addr: s_addr.to_string(),
            identity: HopIdentity::Secp256k1(s_pubkey),
            use_quic: true,
        },
        Hop {
            addr: t_addr.to_string(),
            identity: HopIdentity::Secp256k1(t_pubkey),
            use_quic: true,
        },
    ])
    .await
    .unwrap();
    fund_session(&mut conn, TEST_SESSION_PAYMENT).await;
    let mut h2 = conn.clone_send_request().await;

    let target = format!("127.0.0.1:{}", upper_addr.port());
    let result = tunnel_roundtrip(&mut h2, &target, b"quic then tcp").await;
    assert_eq!(result, b"QUIC THEN TCP");

    drop(h2);
    conn.shutdown().await;
}
