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
//!   - Control channel: SessionStatus bootstrap, channel linking,
//!     incremental channel payments, and linked-channel state synchronization
//!   - Data channel: CONNECT → proxy → uppercase server → response

mod common;

use bytes::Bytes;
use h2::client;
use http::{Method, Request};
use monad_client::connector;
use monad_client::route::{Route, RouteHop};
use monad_client::session_driver::{start_session_payment_driver, PaymentPolicy};
use monad_client::tunnel;
use monad_client::wallet::{
    MockWallet, MonadWallet, RelayPaymentOffer, WalletChannel, WalletChannelState,
};
use monad_common::blinded_connect::BlindedConnectRequest;
use monad_common::blinded_hop::{build_blinded_hop_descriptor, BlindedHopDescriptor};
use monad_common::bootstrap::{
    decode_server_response, encode_client_hello, initial_server_capabilities,
    BootstrapCapabilities, BootstrapClientHello, BootstrapV1ClientHello, BOOTSTRAP_VERSION,
    CASHU_SPILMAN_PROTOCOL_VERSION_2026_03_20, PRICING_POLICY_SESSION_CONSTANT,
};
use monad_common::control_codec::{encode_json_line, try_decode_json_line};
use monad_common::h2stream::wait_for_send_capacity;
use monad_common::noise_secp256k1;
use monad_common::protocol::{ClientMessage, ServerErrorCode, ServerMessage};
use monad_common::quic_cert_identity::QuicCertIdentity;
use monad_common::secp_identity::{Secp256k1Pubkey, SecpTransportKeypair};
use monad_common::session::RelayConnection;

use cdk_spilman::configurable_host::{SpilmanStorage, SqliteStorage};
use cdk_spilman::configurable_networking::ReqwestNetworking;
use cdk_spilman::{
    ChannelState, ClosingData, ConfigurableClientHost, EstablishedChannel, MintConnection,
    SpilmanClientBridge,
};
use cdk_spilman_test_mint::{
    build_router, build_test_mint, rotate_sat_keyset, InMemoryMintNetworking, TestMintConfig,
    TestMintHelper,
};
use common::signing_wallet::TestSigningWallet;
use monad_quic::client::{build_client_config_for_auth, connect_with_auth, ClientAuthMode};
use monad_relay::config::RelayConfig;
use monad_relay::listener::{
    discover_spilman_mint_cache, discover_spilman_mint_cache_with_storage, run_with_payments,
    run_with_payments_and_registry_and_shutdown, shared_spilman_mint_cache, CachedKeyset,
    ServerConfig, SpilmanMintCache,
};
use monad_relay::payments::{testing::InMemoryRelayPayments, RelayPayments, SpilmanRelayPayments};
use monad_relay::quic_pool::QuicPool;
use monad_relay::session_registry::SessionRegistry;
use monad_relay::wallet_manager::{DrainSwapNetworking, RelayWalletManager};
use std::collections::{BTreeMap, BTreeSet};
use std::future::Future;
use std::io;
use std::net::{IpAddr, Ipv6Addr, SocketAddr};
use std::pin::Pin;
use std::sync::{
    atomic::{AtomicUsize, Ordering},
    Arc, Mutex,
};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
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
    mint_cache_with_keyset(
        SYNTHETIC_TEST_MINT_URL,
        SYNTHETIC_TEST_MINT_UNIT,
        SYNTHETIC_TEST_KEYSET_ID,
        r#"{"keysetId":"00testkeyset0000","unit":"msat","keys":{},"inputFeePpk":0}"#,
        true,
    )
}

fn synthetic_trusted_mint_units() -> BTreeMap<String, BTreeSet<String>> {
    BTreeMap::from([(
        SYNTHETIC_TEST_MINT_URL.to_string(),
        BTreeSet::from([SYNTHETIC_TEST_MINT_UNIT.to_string()]),
    )])
}

fn mint_cache_with_keyset(
    mint_url: impl Into<String>,
    unit: impl Into<String>,
    keyset_id: impl Into<String>,
    keyset_info_json: impl Into<String>,
    active: bool,
) -> SpilmanMintCache {
    let mint_url = mint_url.into();
    let unit = unit.into();
    let keyset_id = keyset_id.into();
    let info_json = keyset_info_json.into();
    SpilmanMintCache {
        advertised: BTreeMap::from([(
            mint_url.clone(),
            BTreeMap::from([(unit.clone(), vec![keyset_id.clone()])]),
        )]),
        keysets: BTreeMap::from([(
            mint_url,
            BTreeMap::from([(
                keyset_id,
                CachedKeyset {
                    unit,
                    active,
                    input_fee_ppk: keyset_info_input_fee_ppk(&info_json),
                    info_json,
                },
            )]),
        )]),
    }
}

fn keyset_info_input_fee_ppk(info_json: &str) -> u64 {
    serde_json::from_str::<serde_json::Value>(info_json)
        .ok()
        .and_then(|value| value.get("inputFeePpk").and_then(|fee| fee.as_u64()))
        .unwrap_or(0)
}

/// Spin up a MONAD relay and return `(relay_addr, secp256k1 pubkey)`.
async fn start_monad_relay() -> (std::net::SocketAddr, Secp256k1Pubkey) {
    start_monad_relay_with_transport_key(SecpTransportKeypair::generate()).await
}

async fn start_monad_relay_with_transport_key_and_capabilities(
    transport_key: SecpTransportKeypair,
    bootstrap_capabilities: BootstrapCapabilities,
) -> (std::net::SocketAddr, Secp256k1Pubkey) {
    let identity = QuicCertIdentity::generate().unwrap();
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
        receiver_pubkey_hex: cashu::nuts::SecretKey::generate().public_key().to_hex(),
        trusted_mint_units: synthetic_trusted_mint_units(),
        in_bytes_per_millisat: 1,
        out_bytes_per_millisat: 1,
        bootstrap_capabilities: Some(bootstrap_capabilities),
        relay_wallet_name: "test-relay".to_string(),
        spilman_storage_path: tempfile::NamedTempFile::new()
            .unwrap()
            .path()
            .to_str()
            .unwrap()
            .to_string(),
    });
    let payments = Arc::new(InMemoryRelayPayments::new());

    let synthetic_mint_cache = shared_spilman_mint_cache(synthetic_test_mint_cache());

    tokio::spawn(run_with_payments(
        listener,
        Some(quic_endpoint),
        config,
        payments,
        synthetic_mint_cache,
    ));

    (addr, pubkey)
}

async fn start_monad_relay_with_transport_key(
    transport_key: SecpTransportKeypair,
) -> (std::net::SocketAddr, Secp256k1Pubkey) {
    start_monad_relay_with_transport_key_and_capabilities(
        transport_key,
        initial_server_capabilities(),
    )
    .await
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
        receiver_pubkey_hex: cashu::nuts::SecretKey::generate().public_key().to_hex(),
        trusted_mint_units: synthetic_trusted_mint_units(),
        in_bytes_per_millisat: 1,
        out_bytes_per_millisat: 1,
        bootstrap_capabilities: None,
        relay_wallet_name: "test-relay".to_string(),
        spilman_storage_path: tempfile::NamedTempFile::new()
            .unwrap()
            .path()
            .to_str()
            .unwrap()
            .to_string(),
    });
    let payments = Arc::new(InMemoryRelayPayments::new());
    let synthetic_mint_cache = shared_spilman_mint_cache(synthetic_test_mint_cache());

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
) -> (
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
        receiver_pubkey_hex: payment_receiver_secret.public_key().to_hex(),
        trusted_mint_units,
        in_bytes_per_millisat: 1,
        out_bytes_per_millisat: 1,
        bootstrap_capabilities: None,
        relay_wallet_name: "test-relay".to_string(),
        spilman_storage_path: tempfile::NamedTempFile::new()
            .unwrap()
            .path()
            .to_str()
            .unwrap()
            .to_string(),
    });

    let discovered_spilman_mint_cache = shared_spilman_mint_cache(
        discover_spilman_mint_cache(&config.trusted_mint_units)
            .await
            .unwrap(),
    );
    let payments = Arc::new(InMemoryRelayPayments::new());

    tokio::spawn(run_with_payments(
        listener,
        Some(quic_endpoint),
        config,
        payments.clone(),
        discovered_spilman_mint_cache,
    ));

    (addr, pubkey, payments)
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
        receiver_pubkey_hex: cashu::nuts::SecretKey::generate().public_key().to_hex(),
        trusted_mint_units: synthetic_trusted_mint_units(),
        in_bytes_per_millisat: 1,
        out_bytes_per_millisat: 1,
        bootstrap_capabilities: None,
        relay_wallet_name: "test-relay".to_string(),
        spilman_storage_path: tempfile::NamedTempFile::new()
            .unwrap()
            .path()
            .to_str()
            .unwrap()
            .to_string(),
    });
    let payments = Arc::new(InMemoryRelayPayments::new());
    let synthetic_mint_cache = shared_spilman_mint_cache(synthetic_test_mint_cache());

    tokio::spawn(run_with_payments(
        listener,
        Some(quic_endpoint),
        config,
        payments,
        synthetic_mint_cache,
    ));

    Some((addr, pubkey))
}

/// Spin up a MONAD relay with durable `SpilmanRelayPayments` and a graceful
/// shutdown signal. Returns the bound address, transport pubkey, join handle,
/// a oneshot sender that can be used to trigger shutdown, and the concrete
/// payments implementation so tests can call close_channel directly.
async fn start_persistent_relay(
    bind_addr: SocketAddr,
    transport_key: &SecpTransportKeypair,
    payment_receiver_secret: cashu::nuts::SecretKey,
    storage_path: &str,
    mint_cache: SpilmanMintCache,
    trusted_mint_units: BTreeMap<String, BTreeSet<String>>,
) -> io::Result<(
    SocketAddr,
    Secp256k1Pubkey,
    tokio::task::JoinHandle<io::Result<()>>,
    tokio::sync::oneshot::Sender<()>,
    Arc<SpilmanRelayPayments>,
)> {
    let wallet_name = format!(
        "test-relay-{}",
        payment_receiver_secret.public_key().to_hex()
    );
    let wallet_manager = Arc::new(RelayWalletManager::open(storage_path)?);
    start_managed_persistent_relay(
        bind_addr,
        transport_key,
        payment_receiver_secret,
        &wallet_name,
        wallet_manager,
        mint_cache,
        trusted_mint_units,
    )
    .await
}

async fn start_managed_persistent_relay(
    bind_addr: SocketAddr,
    transport_key: &SecpTransportKeypair,
    payment_receiver_secret: cashu::nuts::SecretKey,
    wallet_name: &str,
    wallet_manager: Arc<RelayWalletManager>,
    mint_cache: SpilmanMintCache,
    trusted_mint_units: BTreeMap<String, BTreeSet<String>>,
) -> io::Result<(
    SocketAddr,
    Secp256k1Pubkey,
    tokio::task::JoinHandle<io::Result<()>>,
    tokio::sync::oneshot::Sender<()>,
    Arc<SpilmanRelayPayments>,
)> {
    wallet_manager.register_identity(wallet_name, payment_receiver_secret.clone())?;

    // Install the supplied cache snapshot into the wallet manager so that
    // manager-driven close/drain paths use the same trusted keyset view as the
    // relay sessions they serve.
    wallet_manager.install_keyset_cache(mint_cache);
    wallet_manager.set_trusted_mint_units(trusted_mint_units.clone());

    let identity = QuicCertIdentity::generate().unwrap();
    let pubkey = transport_key.pubkey();
    let quic_km = monad_quic::keygen::generate_from_seed(identity.seed()).unwrap();
    let quic_server_config =
        monad_quic::server::build_server_config(&quic_km.cert_pem, &quic_km.key_pem).unwrap();
    let (listener, quic_endpoint, addr) =
        bind_tcp_and_quic_on_same_port(bind_addr, quic_server_config).await?;

    let config = Arc::new(ServerConfig {
        identity,
        transport_key: Some(transport_key.clone()),
        receiver_pubkey_hex: payment_receiver_secret.public_key().to_hex(),
        trusted_mint_units,
        in_bytes_per_millisat: 1,
        out_bytes_per_millisat: 1,
        bootstrap_capabilities: None,
        relay_wallet_name: wallet_name.to_string(),
        spilman_storage_path: String::new(),
    });

    let payments = wallet_manager.spilman_payments_for_live(wallet_name)?;
    let payments_for_spawn: Arc<dyn RelayPayments> = payments.clone();
    let mint_cache = wallet_manager.keyset_cache();
    let session_registry = Arc::new(SessionRegistry::new());

    let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel();
    let handle = tokio::spawn(run_with_payments_and_registry_and_shutdown(
        listener,
        Some(quic_endpoint),
        config,
        payments_for_spawn,
        mint_cache,
        session_registry,
        async {
            let _ = shutdown_rx.await;
        },
    ));

    Ok((addr, pubkey, handle, shutdown_tx, payments))
}

/// Start a relay using a YAML-derived `RelayConfig`.  This exercises the same
/// config-to-runtime conversion path as the production binary.
async fn start_relay_from_config(
    relay_config: &RelayConfig,
    wallet_manager: Arc<RelayWalletManager>,
    mint_cache: SpilmanMintCache,
) -> io::Result<(
    SocketAddr,
    Secp256k1Pubkey,
    tokio::task::JoinHandle<io::Result<()>>,
    tokio::sync::oneshot::Sender<()>,
    Arc<SpilmanRelayPayments>,
)> {
    use cashu::nuts::SecretKey;
    use monad_common::quic_cert_identity::QuicCertIdentity;

    let identity = QuicCertIdentity::from_hex(&relay_config.quic_cert_seed)
        .map_err(|e| io::Error::other(format!("bad quic cert seed: {e}")))?;
    let transport_key = SecpTransportKeypair::from_secret_bytes(
        &hex::decode(&relay_config.transport_key)
            .map_err(|e| io::Error::other(format!("bad transport key hex: {e}")))?
            .try_into()
            .map_err(|_| io::Error::other("transport key must be 32 bytes"))?,
    )
    .map_err(|e| io::Error::other(format!("bad transport key: {e}")))?;
    let pubkey = transport_key.pubkey();

    if let Some(secret_hex) = &relay_config.receiver_secret_hex {
        let secret = SecretKey::from_hex(secret_hex)
            .map_err(|e| io::Error::other(format!("bad receiver secret: {e}")))?;
        wallet_manager.register_identity(&relay_config.name, secret)?;
    }

    let receiver_pubkey_hex = wallet_manager.receiver_pubkey_hex(&relay_config.name)?;
    let trusted_mint_units = relay_config.trusted_mint_units();
    wallet_manager.set_trusted_mint_units(trusted_mint_units.clone());

    let quic_km = monad_quic::keygen::generate_from_seed(identity.seed()).unwrap();
    let quic_server_config =
        monad_quic::server::build_server_config(&quic_km.cert_pem, &quic_km.key_pem).unwrap();
    let bind_addr: SocketAddr = relay_config
        .listen
        .parse()
        .map_err(|e| io::Error::other(format!("invalid listen address: {e}")))?;
    let (listener, quic_endpoint, addr) =
        bind_tcp_and_quic_on_same_port(bind_addr, quic_server_config).await?;

    let config = Arc::new(ServerConfig {
        identity,
        transport_key: Some(transport_key),
        receiver_pubkey_hex,
        trusted_mint_units,
        in_bytes_per_millisat: relay_config.in_bytes_per_millisat,
        out_bytes_per_millisat: relay_config.out_bytes_per_millisat,
        bootstrap_capabilities: None,
        relay_wallet_name: relay_config.name.clone(),
        spilman_storage_path: relay_config.wallet_db_path.clone(),
    });

    let payments = wallet_manager.spilman_payments_for(
        &relay_config.name,
        mint_cache.clone(),
        relay_config.trusted_mint_units(),
    )?;
    let payments_for_spawn: Arc<dyn RelayPayments> = payments.clone();
    let mint_cache = shared_spilman_mint_cache(mint_cache);
    let session_registry = Arc::new(SessionRegistry::new());

    let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel();
    let handle = tokio::spawn(run_with_payments_and_registry_and_shutdown(
        listener,
        Some(quic_endpoint),
        config,
        payments_for_spawn,
        mint_cache,
        session_registry,
        async {
            let _ = shutdown_rx.await;
        },
    ));

    Ok((addr, pubkey, handle, shutdown_tx, payments))
}

fn sum_proof_amounts(proofs_json: &str) -> u64 {
    let proofs: Vec<cashu::nuts::Proof> =
        serde_json::from_str(proofs_json).unwrap_or_else(|_| Vec::new());
    proofs.iter().map(|p| u64::from(p.amount)).sum()
}

struct DirectMintConnection {
    mint: Arc<cdk::mint::Mint>,
}

#[async_trait::async_trait]
impl MintConnection for DirectMintConnection {
    async fn process_swap(
        &self,
        request: cashu::nuts::SwapRequest,
    ) -> anyhow::Result<cashu::nuts::SwapResponse> {
        self.mint
            .process_swap_request(request)
            .await
            .map_err(|e| anyhow::anyhow!(e.to_string()))
    }

    async fn post_restore(
        &self,
        request: cashu::nuts::RestoreRequest,
    ) -> anyhow::Result<cashu::nuts::RestoreResponse> {
        self.mint
            .restore(request)
            .await
            .map_err(|e| anyhow::anyhow!(e.to_string()))
    }

    async fn check_state(
        &self,
        ys: Vec<cashu::nuts::PublicKey>,
    ) -> anyhow::Result<cashu::nuts::CheckStateResponse> {
        self.mint
            .check_state(&cashu::nuts::CheckStateRequest { ys })
            .await
            .map_err(|e| anyhow::anyhow!(e.to_string()))
    }
}

fn parse_proofs_json(proofs_json: &str) -> Vec<cashu::nuts::Proof> {
    serde_json::from_str(proofs_json).expect("proof JSON should decode")
}

fn canonical_proof_values_without_witness(proofs: &[cashu::nuts::Proof]) -> Vec<serde_json::Value> {
    let mut values = proofs
        .iter()
        .map(|proof| {
            let mut value = serde_json::to_value(proof).expect("proof should serialize");
            if let Some(object) = value.as_object_mut() {
                object.remove("witness");
            }
            value
        })
        .collect::<Vec<_>>();
    values.sort_by(|a, b| {
        let a_key = format!(
            "{}:{}:{}",
            a.get("amount").and_then(|v| v.as_u64()).unwrap_or(0),
            a.get("id").and_then(|v| v.as_str()).unwrap_or_default(),
            a.get("secret").and_then(|v| v.as_str()).unwrap_or_default()
        );
        let b_key = format!(
            "{}:{}:{}",
            b.get("amount").and_then(|v| v.as_u64()).unwrap_or(0),
            b.get("id").and_then(|v| v.as_str()).unwrap_or_default(),
            b.get("secret").and_then(|v| v.as_str()).unwrap_or_default()
        );
        a_key.cmp(&b_key)
    });
    values
}

fn assert_proofs_have_p2pk_e(proofs: &[cashu::nuts::Proof], label: &str) {
    assert!(!proofs.is_empty(), "{label} should not be empty");
    for (index, proof) in proofs.iter().enumerate() {
        assert!(
            proof.p2pk_e.is_some(),
            "{label}[{index}] should include p2pk_e"
        );
    }
}

fn assert_same_p2pk_e(restored: &[cashu::nuts::Proof], relay: &[cashu::nuts::Proof]) {
    assert_eq!(
        restored.len(),
        relay.len(),
        "restored and relay sender proof counts should match"
    );
    let restored_p2pk_e = restored
        .iter()
        .map(|proof| proof.p2pk_e.map(|key| key.to_hex()))
        .collect::<Vec<_>>();
    let relay_p2pk_e = relay
        .iter()
        .map(|proof| proof.p2pk_e.map(|key| key.to_hex()))
        .collect::<Vec<_>>();
    assert_eq!(
        restored_p2pk_e, relay_p2pk_e,
        "restored sender proofs should use the same p2pk_e keys as relay sender proofs"
    );
}

fn assert_proofs_have_no_witness_signatures(proofs: &[cashu::nuts::Proof], label: &str) {
    for (index, proof) in proofs.iter().enumerate() {
        let Some(cashu::nuts::Witness::P2PKWitness(witness)) = &proof.witness else {
            continue;
        };
        assert!(
            witness.signatures.is_empty(),
            "{label}[{index}] should not include witness signatures"
        );
    }
}

fn assert_proofs_have_witness_signatures(proofs: &[cashu::nuts::Proof], label: &str) {
    assert!(!proofs.is_empty(), "{label} should not be empty");
    for (index, proof) in proofs.iter().enumerate() {
        let signatures = match &proof.witness {
            Some(cashu::nuts::Witness::P2PKWitness(witness)) => &witness.signatures,
            other => panic!("{label}[{index}] should include a P2PK witness, got {other:?}"),
        };
        assert!(
            !signatures.is_empty(),
            "{label}[{index}] should include witness signatures"
        );
        assert!(
            signatures.iter().all(|signature| !signature.is_empty()),
            "{label}[{index}] should not include empty witness signatures"
        );
    }
}

async fn mixed_input_fee_for_proofs(mint_url: &str, proofs_jsons: &[&str]) -> u64 {
    let keysets: serde_json::Value = reqwest::Client::new()
        .get(format!("{mint_url}/v1/keysets"))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let fee_by_keyset = keysets["keysets"]
        .as_array()
        .unwrap()
        .iter()
        .map(|keyset| {
            (
                keyset["id"].as_str().unwrap().to_string(),
                keyset["input_fee_ppk"].as_u64().unwrap_or(0),
            )
        })
        .collect::<BTreeMap<_, _>>();
    let fee_ppk_sum = proofs_jsons
        .iter()
        .flat_map(|proofs_json| {
            serde_json::from_str::<Vec<cashu::nuts::Proof>>(proofs_json).unwrap()
        })
        .map(|proof| fee_by_keyset[&proof.keyset_id.to_string()])
        .sum::<u64>();
    fee_ppk_sum.div_ceil(1000)
}

fn assert_closed_payout_at_least(
    payments: &SpilmanRelayPayments,
    channel_id: &str,
    expected_exit_balance_raw: u64,
) {
    let closed_data = payments
        .closed_data(channel_id)
        .expect("closed data should be present after successful close");
    let receiver_proof_sum = sum_proof_amounts(&closed_data.receiver_proofs_json);
    let sender_proof_sum = sum_proof_amounts(&closed_data.sender_proofs_json);

    assert!(
        receiver_proof_sum >= expected_exit_balance_raw,
        "receiver proofs should cover the relay's latest exit balance"
    );
    assert_eq!(
        receiver_proof_sum, closed_data.receiver_sum,
        "receiver proof sum should match stored receiver close sum"
    );
    assert_eq!(
        sender_proof_sum, closed_data.sender_sum,
        "sender proof sum should match stored sender close sum"
    );
    assert_eq!(
        receiver_proof_sum + sender_proof_sum,
        closed_data.value_after_stage1,
        "proof sums should match the stage-1 close value"
    );
}

async fn create_paid_closed_channel(
    wallet_manager: &RelayWalletManager,
    payments: &SpilmanRelayPayments,
    wallet: &TestSigningWallet,
    offer: &RelayPaymentOffer,
    session_id: [u8; 32],
    funded_balance_raw: u64,
) -> String {
    let channel_id = wallet.pre_create_channel(1000).await.unwrap();
    wallet
        .attach_channel_to_session(&channel_id, session_id)
        .unwrap();
    let link_json = wallet.build_link_request(&channel_id, offer).unwrap();
    payments.link_channel(session_id, &link_json).unwrap();
    let payment_json = wallet
        .build_channel_payment(&channel_id, offer, 0, funded_balance_raw)
        .unwrap();
    payments
        .apply_channel_payment(&channel_id, &payment_json)
        .unwrap();

    let net = wallet_manager
        .reqwest_networking_for_channel(&channel_id)
        .expect("wallet manager should build close networking");
    let close_success = payments
        .close_channel_async(&channel_id, &net)
        .await
        .expect("relay should close test channel");
    assert!(close_success.receiver_sum >= funded_balance_raw);
    assert_closed_payout_at_least(payments, &channel_id, funded_balance_raw);
    channel_id
}

struct DropAfterSwap<'a> {
    inner: &'a ReqwestNetworking,
}

impl DrainSwapNetworking for DropAfterSwap<'_> {
    fn call_mint_swap<'a>(
        &'a self,
        mint_url: &'a str,
        swap_request_json: &'a str,
    ) -> Pin<Box<dyn Future<Output = Result<String, String>> + Send + 'a>> {
        Box::pin(async move {
            let _ = self
                .inner
                .call_mint_swap(mint_url, swap_request_json)
                .await?;
            Err("simulated transport drop after accepted swap".to_string())
        })
    }

    fn call_mint_restore<'a>(
        &'a self,
        mint_url: &'a str,
        restore_request_json: &'a str,
    ) -> Pin<Box<dyn Future<Output = Result<String, String>> + Send + 'a>> {
        self.inner.call_mint_restore(mint_url, restore_request_json)
    }
}

struct CountingDrainNet<'a> {
    inner: &'a ReqwestNetworking,
    swaps: Arc<AtomicUsize>,
    output_keysets_by_call: Arc<Mutex<Vec<Vec<String>>>>,
}

impl DrainSwapNetworking for CountingDrainNet<'_> {
    fn call_mint_swap<'a>(
        &'a self,
        mint_url: &'a str,
        swap_request_json: &'a str,
    ) -> Pin<Box<dyn Future<Output = Result<String, String>> + Send + 'a>> {
        self.swaps.fetch_add(1, Ordering::SeqCst);
        self.output_keysets_by_call
            .lock()
            .unwrap()
            .push(output_keyset_ids_from_swap_request(swap_request_json));
        self.inner.call_mint_swap(mint_url, swap_request_json)
    }

    fn call_mint_restore<'a>(
        &'a self,
        mint_url: &'a str,
        restore_request_json: &'a str,
    ) -> Pin<Box<dyn Future<Output = Result<String, String>> + Send + 'a>> {
        self.inner.call_mint_restore(mint_url, restore_request_json)
    }
}

fn output_keyset_ids_from_swap_request(swap_request_json: &str) -> Vec<String> {
    let value: serde_json::Value = serde_json::from_str(swap_request_json).unwrap();
    value
        .get("outputs")
        .and_then(|outputs| outputs.as_array())
        .into_iter()
        .flatten()
        .filter_map(|output| {
            output
                .get("id")
                .or_else(|| output.get("keyset_id"))
                .or_else(|| output.get("keysetId"))
                .and_then(|id| id.as_str())
                .map(ToString::to_string)
        })
        .collect()
}

struct KeysetThenRejectSwap {
    swaps: AtomicUsize,
}

impl DrainSwapNetworking for KeysetThenRejectSwap {
    fn call_mint_swap<'a>(
        &'a self,
        _mint_url: &'a str,
        _swap_request_json: &'a str,
    ) -> Pin<Box<dyn Future<Output = Result<String, String>> + Send + 'a>> {
        let attempt = self.swaps.fetch_add(1, Ordering::SeqCst);
        Box::pin(async move {
            if attempt == 0 {
                Err(r#"{"code":12001,"detail":"keyset is not known"}"#.to_string())
            } else {
                Err(r#"{"code":11001,"detail":"proofs already spent"}"#.to_string())
            }
        })
    }

    fn call_mint_restore<'a>(
        &'a self,
        _mint_url: &'a str,
        _restore_request_json: &'a str,
    ) -> Pin<Box<dyn Future<Output = Result<String, String>> + Send + 'a>> {
        Box::pin(async { Err("restore should not be called".to_string()) })
    }
}

struct AlwaysKeysetRejectSwap {
    swaps: AtomicUsize,
}

impl DrainSwapNetworking for AlwaysKeysetRejectSwap {
    fn call_mint_swap<'a>(
        &'a self,
        _mint_url: &'a str,
        _swap_request_json: &'a str,
    ) -> Pin<Box<dyn Future<Output = Result<String, String>> + Send + 'a>> {
        self.swaps.fetch_add(1, Ordering::SeqCst);
        Box::pin(async { Err(r#"{"code":12001,"detail":"keyset is not known"}"#.to_string()) })
    }

    fn call_mint_restore<'a>(
        &'a self,
        _mint_url: &'a str,
        _restore_request_json: &'a str,
    ) -> Pin<Box<dyn Future<Output = Result<String, String>> + Send + 'a>> {
        Box::pin(async { Err("restore should not be called".to_string()) })
    }
}

struct RejectSwap;

impl DrainSwapNetworking for RejectSwap {
    fn call_mint_swap<'a>(
        &'a self,
        _mint_url: &'a str,
        _swap_request_json: &'a str,
    ) -> Pin<Box<dyn Future<Output = Result<String, String>> + Send + 'a>> {
        Box::pin(async { Err(r#"{"code":11001,"detail":"proofs already spent"}"#.to_string()) })
    }

    fn call_mint_restore<'a>(
        &'a self,
        _mint_url: &'a str,
        _restore_request_json: &'a str,
    ) -> Pin<Box<dyn Future<Output = Result<String, String>> + Send + 'a>> {
        Box::pin(async { Err("restore should not be called".to_string()) })
    }
}

struct DrainTestContext {
    mint_url: String,
    wallet_manager: RelayWalletManager,
    payments: Arc<SpilmanRelayPayments>,
    wallet: TestSigningWallet,
    offer: RelayPaymentOffer,
    _temp_db: tempfile::NamedTempFile,
    mint_shutdown_tx: Option<tokio::sync::oneshot::Sender<()>>,
}

impl DrainTestContext {
    async fn new(relay_name: &str) -> Self {
        let mint_helper = TestMintHelper::new().await.unwrap();
        let mint_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let mint_addr = mint_listener.local_addr().unwrap();
        let mint_url = format!("http://127.0.0.1:{}", mint_addr.port());
        let mint_router = build_router(mint_helper.mint()).await.unwrap();
        let (mint_shutdown_tx, mint_shutdown_rx) = tokio::sync::oneshot::channel();
        tokio::spawn(async move {
            axum::serve(mint_listener, mint_router)
                .with_graceful_shutdown(async {
                    let _ = mint_shutdown_rx.await;
                })
                .await
                .unwrap();
        });

        let keyset_id = mint_helper.keyset_id().to_string();
        let keyset_info_json = mint_helper.keyset_info_json().unwrap();
        let mint_cache =
            mint_cache_with_keyset(&mint_url, "sat", &keyset_id, &keyset_info_json, true);
        let trusted_mint_units =
            BTreeMap::from([(mint_url.clone(), BTreeSet::from(["sat".to_string()]))]);
        let temp_db = tempfile::NamedTempFile::new().unwrap();
        let wallet_manager = RelayWalletManager::open(temp_db.path().to_str().unwrap()).unwrap();
        let receiver_secret = cashu::nuts::SecretKey::generate();
        let receiver_pubkey_hex = receiver_secret.public_key().to_hex();
        wallet_manager
            .register_identity(relay_name, receiver_secret)
            .unwrap();
        wallet_manager.install_keyset_cache(mint_cache.clone());
        let payments = wallet_manager
            .spilman_payments_for(relay_name, mint_cache, trusted_mint_units)
            .unwrap();
        let wallet = TestSigningWallet::new(
            mint_helper.mint(),
            receiver_pubkey_hex.clone(),
            mint_url.clone(),
            keyset_id.clone(),
            keyset_info_json,
        )
        .await;
        let offer = RelayPaymentOffer {
            receiver_pubkey: receiver_pubkey_hex,
            mint_url: mint_url.clone(),
            unit: "sat".to_string(),
            accepted_keyset_ids: vec![keyset_id],
            in_bytes_per_millisat: 1,
            out_bytes_per_millisat: 1,
        };

        Self {
            mint_url,
            wallet_manager,
            payments,
            wallet,
            offer,
            _temp_db: temp_db,
            mint_shutdown_tx: Some(mint_shutdown_tx),
        }
    }

    async fn create_closed_channel(&self, session_id: [u8; 32], funded_balance_raw: u64) -> String {
        create_paid_closed_channel(
            &self.wallet_manager,
            &self.payments,
            &self.wallet,
            &self.offer,
            session_id,
            funded_balance_raw,
        )
        .await
    }

    fn net_for(&self, channel_id: &str) -> ReqwestNetworking {
        self.wallet_manager
            .reqwest_networking_for_channel(channel_id)
            .unwrap()
    }

    fn shutdown(mut self) {
        if let Some(tx) = self.mint_shutdown_tx.take() {
            let _ = tx.send(());
        }
    }
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
    connect_route_hops(vec![cleartext_route_hop(
        server_addr.to_string(),
        *pubkey,
        true,
    )])
    .await
}

async fn connect_client_tcp(
    server_addr: std::net::SocketAddr,
    pubkey: &Secp256k1Pubkey,
) -> RelayConnection {
    connect_route_hops(vec![cleartext_route_hop(
        server_addr.to_string(),
        *pubkey,
        false,
    )])
    .await
}

fn cleartext_route_hop(
    addr: impl Into<String>,
    pubkey: Secp256k1Pubkey,
    use_quic: bool,
) -> RouteHop {
    RouteHop::Cleartext {
        addr: addr.into(),
        pubkey,
        use_quic,
    }
}

async fn connect_route_hops(hops: Vec<RouteHop>) -> RelayConnection {
    connector::connect_route(&Route::new(hops).unwrap())
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

async fn connect_nested_session_blinded(
    parent_conn: &RelayConnection,
    descriptor: &BlindedHopDescriptor,
) -> RelayConnection {
    let request = BlindedConnectRequest::from_descriptor(descriptor);
    let mut stream = parent_conn.open_tunnel_blinded_hop(&request).await.unwrap();
    let (send_cipher, recv_cipher, session_id) =
        noise_secp256k1::handshake_initiator(&mut stream, &descriptor.tweaked_pubkey)
            .await
            .unwrap();
    let noise_stream = noise_secp256k1::SecpNoiseStream::new(
        stream,
        send_cipher,
        recv_cipher,
        session_id,
        "nested blinded session",
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
    let frame = encode_json_line(message).unwrap();
    h2_send.reserve_capacity(frame.len());
    wait_for_send_capacity(h2_send).await.unwrap();
    h2_send.send_data(frame, end_stream).unwrap();
}

async fn read_control_message(h2_recv: &mut h2::RecvStream) -> ServerMessage {
    let mut response_buf = Vec::new();

    loop {
        if let Some(message) = try_decode_json_line::<ServerMessage>(&mut response_buf).unwrap() {
            return message;
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

#[derive(Debug, Clone)]
struct TestSessionStatus {
    advertisements: Vec<monad_common::protocol::KeysetAdvertisement>,
    linked_channel: Option<monad_common::protocol::LinkedChannelStatus>,
    active_in_rate: u64,
    active_out_rate: u64,
    session_total_in: u64,
    session_total_out: u64,
    total_paid_millisats: u64,
    remaining_milli_sats: i64,
    paused: bool,
    open_connects: u32,
    total_connects: u64,
}

impl TestSessionStatus {
    fn as_tuple(&self) -> (u64, u64, u64, i64, bool) {
        (
            self.session_total_in,
            self.session_total_out,
            self.total_paid_millisats,
            self.remaining_milli_sats,
            self.paused,
        )
    }

    fn assert_linked_channel(
        &self,
        channel_id: &str,
        balance_raw: u64,
        capacity_raw: u64,
        unit: &str,
    ) {
        let linked_channel = self
            .linked_channel
            .as_ref()
            .expect("expected linked channel in SessionStatus");
        assert_eq!(linked_channel.channel_id, channel_id);
        assert_eq!(linked_channel.balance_raw, balance_raw);
        assert_eq!(linked_channel.capacity_raw, capacity_raw);
        assert_eq!(linked_channel.unit, unit);
    }
}

struct ControlSessionHarness {
    send: h2::SendStream<Bytes>,
    recv: h2::RecvStream,
}

impl ControlSessionHarness {
    async fn open(conn: &RelayConnection) -> Self {
        let (send, recv) = conn.open_control().await.unwrap();
        Self { send, recv }
    }

    async fn handshake(&mut self) -> TestSessionStatus {
        control_handshake_status(&mut self.send, &mut self.recv).await
    }

    async fn get_status(&mut self) -> TestSessionStatus {
        request_session_status_status(&mut self.send, &mut self.recv).await
    }

    async fn expect_error(&mut self) -> (ServerErrorCode, String) {
        match read_control_message(&mut self.recv).await {
            ServerMessage::Error { code, message } => (code, message),
            other => panic!("expected Error, got {other:?}"),
        }
    }

    async fn close(mut self) {
        let _ = self.send.send_data(Bytes::new(), true);
    }
}

async fn request_session_status_status(
    h2_send: &mut h2::SendStream<Bytes>,
    h2_recv: &mut h2::RecvStream,
) -> TestSessionStatus {
    send_control_message(h2_send, &ClientMessage::GetSessionStatus, false).await;
    expect_session_status_struct(read_control_message(h2_recv).await)
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
        let status = request_session_status_status(h2_send, h2_recv).await;
        if status.session_total_in == expected_in && status.session_total_out == expected_out {
            return Ok(status.as_tuple());
        }

        if tokio::time::Instant::now() >= deadline {
            let actual_in = status.session_total_in;
            let actual_out = status.session_total_out;
            let remaining = status.remaining_milli_sats;
            let paused = status.paused;
            return Err(format!(
                "timed out waiting for session totals: expected in={expected_in} out={expected_out}, got in={actual_in} out={actual_out} remaining={remaining} paused={paused}"
            ));
        }
    }
}

fn expect_session_status_struct(message: ServerMessage) -> TestSessionStatus {
    match message {
        ServerMessage::SessionStatus {
            advertisements,
            linked_channel,
            active_in_rate,
            active_out_rate,
            session_total_in,
            session_total_out,
            total_paid_millisats,
            remaining_milli_sats,
            paused,
            open_connects,
            total_connects,
            ..
        } => TestSessionStatus {
            advertisements,
            linked_channel,
            active_in_rate,
            active_out_rate,
            session_total_in,
            session_total_out,
            total_paid_millisats,
            remaining_milli_sats,
            paused,
            open_connects,
            total_connects,
        },
        other => panic!("expected SessionStatus, got {other:?}"),
    }
}

fn expect_session_status(message: ServerMessage) -> (u64, u64, u64, i64, bool) {
    expect_session_status_struct(message).as_tuple()
}

/// Read the initial SessionStatus sent immediately after control attach.
/// Returns the initial session status fields.
async fn control_handshake(
    _h2_send: &mut h2::SendStream<Bytes>,
    h2_recv: &mut h2::RecvStream,
) -> (u64, u64, u64, i64, bool) {
    control_handshake_status(_h2_send, h2_recv).await.as_tuple()
}

async fn control_handshake_status(
    _h2_send: &mut h2::SendStream<Bytes>,
    h2_recv: &mut h2::RecvStream,
) -> TestSessionStatus {
    expect_session_status_struct(read_control_message(h2_recv).await)
}

async fn open_funded_control(
    conn: &RelayConnection,
    milli_sats: u64,
) -> (h2::SendStream<Bytes>, h2::RecvStream) {
    let (mut h2_send, mut h2_recv) = conn.open_control().await.unwrap();

    let status0 = control_handshake_status(&mut h2_send, &mut h2_recv).await;
    assert!(status0.paused);
    assert_eq!(status0.remaining_milli_sats, 0);

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

async fn open_two_control_sessions(
    conn_a: &RelayConnection,
    conn_b: &RelayConnection,
) -> (
    h2::SendStream<Bytes>,
    h2::RecvStream,
    h2::SendStream<Bytes>,
    h2::RecvStream,
) {
    let (mut send_a, mut recv_a) = conn_a.open_control().await.unwrap();
    let (mut send_b, mut recv_b) = conn_b.open_control().await.unwrap();
    let _ = control_handshake(&mut send_a, &mut recv_a).await;
    let _ = control_handshake(&mut send_b, &mut recv_b).await;
    (send_a, recv_a, send_b, recv_b)
}

async fn assert_evicted_then_status(
    recv: &mut h2::RecvStream,
    expected_channel_id: &str,
) -> TestSessionStatus {
    let evicted = timeout(Duration::from_millis(500), read_control_message(recv))
        .await
        .expect("expected eviction event");
    match evicted {
        ServerMessage::ChannelEvicted { channel_id } => {
            assert_eq!(channel_id, expected_channel_id);
        }
        other => panic!("expected ChannelEvicted, got {other:?}"),
    }

    expect_session_status_struct(read_control_message(recv).await)
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

    async fn link_expect_balance(
        &mut self,
        h2_send: &mut h2::SendStream<Bytes>,
        h2_recv: &mut h2::RecvStream,
        expected_balance_raw: u64,
    ) -> TestSessionStatus {
        send_control_message(
            h2_send,
            &ClientMessage::ChannelLink {
                payment_json: self.link_json(),
            },
            false,
        )
        .await;

        let status = expect_session_status_struct(read_control_message(h2_recv).await);
        status.assert_linked_channel(
            &self.channel_id,
            expected_balance_raw,
            self.capacity_units(),
            self.unit,
        );
        status
    }

    async fn link(
        &mut self,
        h2_send: &mut h2::SendStream<Bytes>,
        h2_recv: &mut h2::RecvStream,
    ) -> (u64, u64, u64, i64, bool) {
        self.link_expect_balance(h2_send, h2_recv, self.cumulative_balance_units)
            .await
            .as_tuple()
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

        let status = expect_session_status_struct(read_control_message(h2_recv).await);
        status.assert_linked_channel(
            &self.channel_id,
            self.cumulative_balance_units,
            self.capacity_units(),
            self.unit,
        );
        status.as_tuple()
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

async fn open_connect_tunnel(
    h2_client: &mut client::SendRequest<Bytes>,
    target_authority: &str,
) -> (h2::SendStream<Bytes>, h2::RecvStream) {
    let request = Request::builder()
        .method(Method::CONNECT)
        .uri(target_authority)
        .body(())
        .unwrap();

    let (response_future, h2_send) = h2_client.send_request(request, false).unwrap();
    let response = response_future.await.unwrap();
    assert!(
        response.status().is_success(),
        "CONNECT failed: {}",
        response.status()
    );
    (h2_send, response.into_body())
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
async fn test_session_active_rates_remain_immutable_across_status_updates() {
    let (server_addr, pubkey) = start_monad_relay().await;
    let conn = connect_client_quic_secp(server_addr, &pubkey).await;
    let mut control = ControlSessionHarness::open(&conn).await;

    let initial = control.handshake().await;
    assert_eq!(initial.active_in_rate, 1);
    assert_eq!(initial.active_out_rate, 1);

    let mut channel = SessionPaymentChannel::for_explicit_id("chan-rates");
    let linked = channel
        .link_expect_balance(&mut control.send, &mut control.recv, 0)
        .await;
    assert_eq!(linked.active_in_rate, initial.active_in_rate);
    assert_eq!(linked.active_out_rate, initial.active_out_rate);

    let _ = channel.pay(&mut control.send, &mut control.recv, 10).await;
    let funded = control.get_status().await;
    assert_eq!(funded.active_in_rate, initial.active_in_rate);
    assert_eq!(funded.active_out_rate, initial.active_out_rate);

    control.close().await;
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
    let mut control = ControlSessionHarness::open(&conn).await;

    let status0 = control.handshake().await;
    assert!(status0.paused);
    assert_eq!(status0.remaining_milli_sats, 0);

    let mut channel = SessionPaymentChannel::for_explicit_id("chan-msat");
    let (_in1, _out1, paid1, rem1, paused1) =
        channel.link(&mut control.send, &mut control.recv).await;
    assert_eq!(paid1, 0);
    assert_eq!(rem1, 0);
    assert!(paused1);

    control.close().await;
    tokio::time::sleep(std::time::Duration::from_millis(20)).await;
    conn.shutdown().await;
}

#[tokio::test]
async fn test_non_zero_channel_link_is_rejected_and_does_not_link_session() {
    let (server_addr, pubkey) = start_monad_relay().await;
    let conn = connect_client_quic_secp(server_addr, &pubkey).await;
    let mut control = ControlSessionHarness::open(&conn).await;

    let status0 = control.handshake().await;
    assert!(status0.paused);
    assert_eq!(status0.remaining_milli_sats, 0);

    let payment_json = serde_json::json!({
        "channel_id": "bad-link",
        "balance": 1,
        "capacity": TEST_CHANNEL_CAPACITY_UNITS,
        "unit": "msat",
    })
    .to_string();
    send_control_message(
        &mut control.send,
        &ClientMessage::ChannelLink { payment_json },
        false,
    )
    .await;

    let (code, message) = control.expect_error().await;
    assert_eq!(code, ServerErrorCode::LinkNonZeroBalance);
    assert!(
        message.contains("link balance must be zero"),
        "unexpected error: {message}"
    );

    let status = control.get_status().await;
    assert_eq!(status.linked_channel, None);
    assert_eq!(status.total_paid_millisats, 0);
    assert_eq!(status.remaining_milli_sats, 0);
    assert!(status.paused);

    control.close().await;
    tokio::time::sleep(std::time::Duration::from_millis(20)).await;
    conn.shutdown().await;
}

#[tokio::test]
async fn test_unsupported_unit_channel_link_is_rejected_and_does_not_link_session() {
    let (server_addr, pubkey) = start_monad_relay().await;
    let conn = connect_client_quic_secp(server_addr, &pubkey).await;
    let mut control = ControlSessionHarness::open(&conn).await;

    let status0 = control.handshake().await;
    assert!(status0.paused);
    assert_eq!(status0.remaining_milli_sats, 0);

    let payment_json = serde_json::json!({
        "channel_id": "bad-unit",
        "balance": 0,
        "capacity": TEST_CHANNEL_CAPACITY_UNITS,
        "unit": "usd",
    })
    .to_string();
    send_control_message(
        &mut control.send,
        &ClientMessage::ChannelLink { payment_json },
        false,
    )
    .await;

    let (code, message) = control.expect_error().await;
    assert_eq!(code, ServerErrorCode::LinkUnsupportedUnit);
    assert!(
        message.contains("unsupported unit"),
        "unexpected error: {message}"
    );

    let status = control.get_status().await;
    assert_eq!(status.linked_channel, None);
    assert_eq!(status.total_paid_millisats, 0);
    assert_eq!(status.remaining_milli_sats, 0);
    assert!(status.paused);

    control.close().await;
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
        ServerMessage::Error { code, message } => {
            assert_eq!(code, ServerErrorCode::PaymentInvalid);
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
    let (server_addr, pubkey, _payments) =
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
        monad_client::session_driver::PaymentPolicy::default(),
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
async fn test_session_payment_driver_proactively_pays_from_local_counters() {
    let upper_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let upper_addr = upper_listener.local_addr().unwrap();
    tokio::spawn(run_uppercase_server(upper_listener));

    let (mint_url, keyset_id, mint_shutdown) = start_http_test_mint().await;
    let payment_receiver_secret = cashu::nuts::SecretKey::generate();
    let receiver_pubkey = payment_receiver_secret.public_key().to_hex();
    let mut trusted_mint_units = BTreeMap::new();
    trusted_mint_units.insert(mint_url.clone(), BTreeSet::from(["sat".to_string()]));
    let (server_addr, pubkey, _payments) =
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
        monad_client::session_driver::PaymentPolicy::default(),
    )
    .await
    .unwrap();
    timeout(Duration::from_secs(2), ready_rx)
        .await
        .expect("driver should ready")
        .expect("driver ready signal");

    let initial_payment_builds = wallet
        .successful_payment_build_count("driver-chan")
        .unwrap();
    assert_eq!(initial_payment_builds, 1);

    let target = format!("127.0.0.1:{}", upper_addr.port());
    let mut tunnel = conn.open_tunnel(&target).await.unwrap();
    tunnel.write_all(b"wallet proactive").await.unwrap();
    tunnel.shutdown().await.unwrap();
    let mut result = Vec::new();
    tunnel.read_to_end(&mut result).await.unwrap();
    assert_eq!(result, b"WALLET PROACTIVE");

    timeout(Duration::from_secs(2), async {
        loop {
            if wallet
                .successful_payment_build_count("driver-chan")
                .unwrap()
                >= 2
            {
                break;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await
    .expect("timer-driven local-counter payment should happen");

    driver_handle.abort();
    let _ = driver_handle.await;
    conn.shutdown().await;
    let _ = mint_shutdown.send(());
}

#[tokio::test]
async fn test_session_payment_driver_timer_does_not_duplicate_payment_builds() {
    let upper_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let upper_addr = upper_listener.local_addr().unwrap();
    tokio::spawn(run_uppercase_server(upper_listener));

    let (mint_url, keyset_id, mint_shutdown) = start_http_test_mint().await;
    let payment_receiver_secret = cashu::nuts::SecretKey::generate();
    let receiver_pubkey = payment_receiver_secret.public_key().to_hex();
    let mut trusted_mint_units = BTreeMap::new();
    trusted_mint_units.insert(mint_url.clone(), BTreeSet::from(["sat".to_string()]));
    let (server_addr, pubkey, _payments) =
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
        monad_client::session_driver::PaymentPolicy::default(),
    )
    .await
    .unwrap();
    timeout(Duration::from_secs(2), ready_rx)
        .await
        .expect("driver should ready")
        .expect("driver ready signal");

    let target = format!("127.0.0.1:{}", upper_addr.port());
    let mut tunnel = conn.open_tunnel(&target).await.unwrap();
    tunnel.write_all(b"wallet one topup").await.unwrap();
    tunnel.shutdown().await.unwrap();
    let mut result = Vec::new();
    tunnel.read_to_end(&mut result).await.unwrap();
    assert_eq!(result, b"WALLET ONE TOPUP");

    timeout(Duration::from_secs(2), async {
        loop {
            if wallet
                .successful_payment_build_count("driver-chan")
                .unwrap()
                >= 2
            {
                break;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await
    .expect("one additional payment build should happen");

    tokio::time::sleep(Duration::from_millis(800)).await;
    assert_eq!(
        wallet
            .successful_payment_build_count("driver-chan")
            .unwrap(),
        2
    );

    driver_handle.abort();
    let _ = driver_handle.await;
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
    let (server_addr, pubkey, _payments) =
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
        monad_client::session_driver::PaymentPolicy::default(),
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

/// End-to-end test that the session payment driver marks a channel unusable
/// and reselects to another channel when the relay rejects a payment with
/// `ChannelClosed`.
#[tokio::test]
async fn test_session_payment_driver_marks_channel_closed_and_reselects() {
    let (mint_url, keyset_id, mint_shutdown) = start_http_test_mint().await;
    let payment_receiver_secret = cashu::nuts::SecretKey::generate();
    let receiver_pubkey = payment_receiver_secret.public_key().to_hex();
    let mut trusted_mint_units = BTreeMap::new();
    trusted_mint_units.insert(mint_url.clone(), BTreeSet::from(["sat".to_string()]));
    let (server_addr, pubkey, payments) =
        start_monad_relay_with_spilman(trusted_mint_units, payment_receiver_secret).await;

    let wallet = Arc::new(MockWallet::new());
    wallet
        .insert_channel(mock_wallet_channel(
            "a-first",
            receiver_pubkey.clone(),
            mint_url.clone(),
            keyset_id.clone(),
        ))
        .unwrap();
    wallet
        .insert_channel(mock_wallet_channel(
            "b-second",
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
        PaymentPolicy {
            target_topup_buffer_msats: 1000,
            minimum_topup_msats: 1000,
        },
    )
    .await
    .unwrap();
    timeout(Duration::from_secs(2), ready_rx)
        .await
        .expect("driver should ready")
        .expect("driver ready signal");

    // The driver linked and paid "a-first" to reach the target buffer. Close
    // it from the relay side to simulate a unilateral close.
    assert!(
        payments.mark_closed("a-first"),
        "relay should have recorded the channel"
    );

    // Send exactly the remaining balance worth of outbound data. The relay
    // proxies it, then pauses. The driver tries to top up the now-closed
    // channel, gets ChannelClosed, marks it unusable, and reselects.
    let upper_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let upper_addr = upper_listener.local_addr().unwrap();
    tokio::spawn(run_counting_server(upper_listener, 1000, b"OK"));
    let mut tunnel = conn.open_tunnel(&upper_addr.to_string()).await.unwrap();
    tunnel.write_all(&[b'x'; 1000]).await.unwrap();
    tunnel.shutdown().await.unwrap();
    let mut result = Vec::new();
    tunnel.read_to_end(&mut result).await.unwrap();
    assert_eq!(result, b"OK");

    timeout(Duration::from_secs(3), async {
        loop {
            let first_state = wallet.get_channel("a-first").unwrap().state;
            let second_linked = wallet.last_link_payload("b-second").unwrap().is_some();
            let second_paid = wallet.last_payment_payload("b-second").unwrap().is_some();
            if first_state != WalletChannelState::Open && second_linked && second_paid {
                break;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await
    .expect("driver should mark first channel unusable and reselect second channel");

    assert_eq!(
        wallet.get_channel("a-first").unwrap().state,
        WalletChannelState::Closing,
        "closed channel should be marked unusable"
    );
    assert!(
        wallet.last_link_payload("b-second").unwrap().is_some(),
        "second channel should be linked"
    );
    assert!(
        wallet.last_payment_payload("b-second").unwrap().is_some(),
        "second channel should receive a payment"
    );

    driver_handle.abort();
    let _ = driver_handle.await;
    conn.shutdown().await;
    let _ = mint_shutdown.send(());
}

#[tokio::test]
async fn test_closed_channel_payment_is_rejected_after_successful_link_and_payment() {
    let (server_addr, pubkey, payments) = start_monad_relay_with_test_payments().await;
    let conn = connect_client_quic_secp(server_addr, &pubkey).await;
    let mut control = ControlSessionHarness::open(&conn).await;

    let status0 = control.handshake().await;
    assert!(status0.paused);

    let mut channel = SessionPaymentChannel::for_explicit_id("chan-closed-later");
    let (_in1, _out1, paid1, rem1, paused1) =
        channel.link(&mut control.send, &mut control.recv).await;
    assert_eq!(paid1, 0);
    assert_eq!(rem1, 0);
    assert!(paused1);

    let (_in2, _out2, paid2, rem2, paused2) =
        channel.pay(&mut control.send, &mut control.recv, 50).await;
    assert_eq!(paid2, 50);
    assert_eq!(rem2, 50);
    assert!(!paused2);

    assert!(payments.mark_closed("chan-closed-later"));
    channel.cumulative_balance_units = channel.cumulative_balance_units.saturating_add(1);
    send_control_message(
        &mut control.send,
        &ClientMessage::ChannelPayment {
            payment_json: channel.payment_json(),
        },
        false,
    )
    .await;

    let (code, message) = control.expect_error().await;
    assert_eq!(code, ServerErrorCode::ChannelClosed);
    assert!(
        message.contains("channel closed"),
        "unexpected error: {message}"
    );

    let status = control.get_status().await;
    status.assert_linked_channel(
        "chan-closed-later",
        50,
        channel.capacity_units(),
        channel.unit,
    );
    assert_eq!(status.total_paid_millisats, 50);
    assert_eq!(status.remaining_milli_sats, 50);
    assert!(!status.paused);

    control.close().await;
    conn.shutdown().await;
}

#[tokio::test]
async fn test_session_payment_driver_detaches_evicted_channel() {
    let (mint_url, keyset_id, mint_shutdown) = start_http_test_mint().await;
    let payment_receiver_secret = cashu::nuts::SecretKey::generate();
    let receiver_pubkey = payment_receiver_secret.public_key().to_hex();
    let mut trusted_mint_units = BTreeMap::new();
    trusted_mint_units.insert(mint_url.clone(), BTreeSet::from(["sat".to_string()]));
    let (server_addr, pubkey, _payments) =
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
        monad_client::session_driver::PaymentPolicy::default(),
    )
    .await
    .unwrap();
    timeout(Duration::from_secs(2), ready_a)
        .await
        .expect("driver a should ready")
        .expect("driver a ready signal");
    assert!(wallet_a.attachment("shared-channel").unwrap().is_some());
    wallet_b
        .set_balance(
            "shared-channel",
            wallet_a
                .get_channel("shared-channel")
                .unwrap()
                .current_signed_balance_msats,
        )
        .unwrap();

    let conn_b = connect_client_quic_secp(server_addr, &pubkey).await;
    let (driver_b, ready_b) = start_session_payment_driver(
        &conn_b,
        wallet_b.clone() as Arc<dyn monad_client::wallet::MonadWallet>,
        "driver b",
        monad_client::session_driver::PaymentPolicy::default(),
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

    let (mut send_a, mut recv_a, mut send_b, mut recv_b) =
        open_two_control_sessions(&conn_a, &conn_b).await;

    let mut channel_a = SessionPaymentChannel::for_explicit_id("shared");
    let mut channel_b = SessionPaymentChannel::for_explicit_id("shared");
    let _ = channel_a.link(&mut send_a, &mut recv_a).await;
    let _ = channel_b.link(&mut send_b, &mut recv_b).await;

    let eviction_status = assert_evicted_then_status(&mut recv_a, "shared").await;
    assert_eq!(eviction_status.linked_channel, None);
    assert!(eviction_status.paused);

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
async fn test_channel_eviction_preserves_existing_session_balance() {
    let upper_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let upper_addr = upper_listener.local_addr().unwrap();
    tokio::spawn(run_uppercase_server(upper_listener));

    let (server_addr, pubkey, payments) = start_monad_relay_with_test_payments().await;
    let conn_a = connect_client_quic_secp(server_addr, &pubkey).await;
    let conn_b = connect_client_quic_secp(server_addr, &pubkey).await;

    let (mut send_a, mut recv_a, mut send_b, mut recv_b) =
        open_two_control_sessions(&conn_a, &conn_b).await;

    let mut channel_a = SessionPaymentChannel::for_explicit_id("shared-funded");
    let mut channel_b = SessionPaymentChannel::for_explicit_id("shared-funded");
    let _ = channel_a.link(&mut send_a, &mut recv_a).await;
    let (_in, _out, paid_before_eviction, remaining_before_eviction, paused_before_eviction) =
        channel_a
            .pay(&mut send_a, &mut recv_a, TEST_SESSION_PAYMENT)
            .await;
    assert!(!paused_before_eviction);
    assert!(remaining_before_eviction > 0);

    let takeover_status = channel_b
        .link_expect_balance(&mut send_b, &mut recv_b, channel_a.cumulative_balance_units)
        .await;
    assert_eq!(
        takeover_status
            .linked_channel
            .as_ref()
            .map(|channel| channel.channel_id.as_str()),
        Some("shared-funded")
    );

    let eviction_status = assert_evicted_then_status(&mut recv_a, "shared-funded").await;
    assert_eq!(eviction_status.linked_channel, None);
    assert_eq!(eviction_status.total_paid_millisats, paid_before_eviction);
    assert_eq!(
        eviction_status.remaining_milli_sats,
        remaining_before_eviction
    );
    assert!(!eviction_status.paused);
    assert_eq!(
        payments.owner_of("shared-funded"),
        Some(*conn_b.session_id()),
        "ownership should transfer to the new session while credited balance remains usable"
    );

    let mut h2_a = conn_a.clone_send_request().await;
    let target = format!("127.0.0.1:{}", upper_addr.port());
    let result = tunnel_roundtrip(&mut h2_a, &target, b"still funded").await;
    assert_eq!(result, b"STILL FUNDED");

    drop(h2_a);
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
        ServerMessage::Error { code, message } => {
            assert_eq!(code, ServerErrorCode::PaymentWrongChannel);
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
    assert!(
        (5..=10).contains(&out2),
        "paused status should account for between 5 and 10 outbound bytes, got {out2}"
    );
    assert_eq!(rem2, 5 - out2 as i64);

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
async fn test_outbound_bytes_sent_after_pause_are_delivered_after_unpause() {
    let target_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let target_addr = target_listener.local_addr().unwrap();
    tokio::spawn(run_counting_server(target_listener, 20, b"DONE"));

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
            .send_data(Bytes::from(vec![b'a' + i]), false)
            .unwrap();
    }

    let (_in2, out2, _paid2, rem2, paused2) =
        expect_session_status(read_control_message(&mut control_recv).await);
    assert!(
        paused2,
        "session should pause after exhausting initial credit"
    );
    assert!(
        (5..=10).contains(&out2),
        "paused status should account for between 5 and 10 outbound bytes, got {out2}"
    );
    assert_eq!(rem2, 5 - out2 as i64);

    for i in 10..20u8 {
        h2_send.reserve_capacity(1);
        wait_for_send_capacity(&mut h2_send).await.unwrap();
        h2_send
            .send_data(Bytes::from(vec![b'a' + i]), i == 19)
            .unwrap();
    }

    let stalled = tokio::time::timeout(std::time::Duration::from_millis(200), h2_recv.data()).await;
    assert!(
        stalled.is_err(),
        "response should remain stalled while paused even after more outbound bytes are queued"
    );

    let (_in3, _out3, _paid3, rem3, paused3) =
        channel.pay(&mut control_send, &mut control_recv, 20).await;
    assert!(!paused3, "session should unpause after second payment");
    assert_eq!(rem3, 25 - out2 as i64);

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
    assert_eq!(session_total_out, 20);
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

#[tokio::test]
async fn test_inbound_bytes_pushed_after_pause_are_delivered_after_unpause() {
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

    let _ = release_tx.send(());

    channel.cumulative_balance_units = channel.cumulative_balance_units.saturating_add(10);
    send_control_message(
        &mut control_send,
        &ClientMessage::ChannelPayment {
            payment_json: channel.payment_json(),
        },
        false,
    )
    .await;

    let (rem3, paused3) = loop {
        let (_in3, _out3, _paid3, remaining, paused) =
            expect_session_status(read_control_message(&mut control_recv).await);
        if !paused {
            break (remaining, paused);
        }
    };
    assert!(
        !paused3,
        "session should unpause after positive top-up, got paused={paused3} remaining={rem3}"
    );
    assert_eq!(rem3, 1);

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

/// End-to-end test that a relay restart preserves accepted Spilman channel
/// state in its SQLite backing store, using real Cashu signatures and the
/// full `SpilmanRelayPayments` validation path.
#[tokio::test(flavor = "multi_thread")]
async fn test_two_relays_share_one_wallet_manager_db() {
    let mint_helper = TestMintHelper::new().await.unwrap();
    let mint_url = "https://test-mint.invalid".to_string();
    let keyset_id = mint_helper.keyset_id().to_string();
    let keyset_info_json = mint_helper.keyset_info_json().unwrap();
    let mint_cache = mint_cache_with_keyset(&mint_url, "sat", &keyset_id, &keyset_info_json, true);
    let trusted_mint_units =
        BTreeMap::from([(mint_url.clone(), BTreeSet::from(["sat".to_string()]))]);

    let temp_db = tempfile::NamedTempFile::new().unwrap();
    let storage_path = temp_db.path().to_str().unwrap().to_string();
    let wallet_manager = Arc::new(RelayWalletManager::open(&storage_path).unwrap());

    let receiver_secret_a = cashu::nuts::SecretKey::generate();
    let receiver_pubkey_a = receiver_secret_a.public_key().to_hex();
    let wallet_a = Arc::new(
        TestSigningWallet::new(
            mint_helper.mint(),
            receiver_pubkey_a.clone(),
            mint_url.clone(),
            keyset_id.clone(),
            keyset_info_json.clone(),
        )
        .await,
    );
    let channel_id_a = wallet_a.pre_create_channel(1000).await.unwrap();

    let receiver_secret_b = cashu::nuts::SecretKey::generate();
    let receiver_pubkey_b = receiver_secret_b.public_key().to_hex();
    let wallet_b = Arc::new(
        TestSigningWallet::new(
            mint_helper.mint(),
            receiver_pubkey_b.clone(),
            mint_url.clone(),
            keyset_id.clone(),
            keyset_info_json.clone(),
        )
        .await,
    );
    let channel_id_b = wallet_b.pre_create_channel(1000).await.unwrap();

    let transport_key_a = SecpTransportKeypair::generate();
    let (server_addr_a, pubkey_a, handle_a, shutdown_tx_a, _payments_a) =
        start_managed_persistent_relay(
            "127.0.0.1:0".parse().unwrap(),
            &transport_key_a,
            receiver_secret_a,
            "relay-a",
            wallet_manager.clone(),
            mint_cache.clone(),
            trusted_mint_units.clone(),
        )
        .await
        .unwrap();

    let transport_key_b = SecpTransportKeypair::generate();
    let (server_addr_b, pubkey_b, handle_b, shutdown_tx_b, _payments_b) =
        start_managed_persistent_relay(
            "127.0.0.1:0".parse().unwrap(),
            &transport_key_b,
            receiver_secret_b,
            "relay-b",
            wallet_manager.clone(),
            mint_cache,
            trusted_mint_units,
        )
        .await
        .unwrap();

    let conn_a = connect_client_quic_secp(server_addr_a, &pubkey_a).await;
    let (mut control_send_a, mut control_recv_a) = conn_a.open_control().await.unwrap();
    let status0_a = control_handshake_status(&mut control_send_a, &mut control_recv_a).await;
    let offer_a = RelayPaymentOffer::from_advertisement(
        receiver_pubkey_a,
        status0_a
            .advertisements
            .iter()
            .find(|a| a.unit == "sat")
            .expect("relay-a should advertise sat keyset"),
    );
    wallet_a
        .attach_channel_to_session(&channel_id_a, *conn_a.session_id())
        .unwrap();
    let link_json_a = wallet_a
        .build_link_request(&channel_id_a, &offer_a)
        .unwrap();
    send_control_message(
        &mut control_send_a,
        &ClientMessage::ChannelLink {
            payment_json: link_json_a,
        },
        false,
    )
    .await;
    let _ = expect_session_status_struct(read_control_message(&mut control_recv_a).await);
    let payment_json_a = wallet_a
        .build_channel_payment(&channel_id_a, &offer_a, 0, 1)
        .unwrap();
    send_control_message(
        &mut control_send_a,
        &ClientMessage::ChannelPayment {
            payment_json: payment_json_a,
        },
        false,
    )
    .await;
    let paid_a = expect_session_status_struct(read_control_message(&mut control_recv_a).await);
    assert_eq!(paid_a.total_paid_millisats, 1000);

    let conn_b = connect_client_quic_secp(server_addr_b, &pubkey_b).await;
    let (mut control_send_b, mut control_recv_b) = conn_b.open_control().await.unwrap();
    let status0_b = control_handshake_status(&mut control_send_b, &mut control_recv_b).await;
    let offer_b = RelayPaymentOffer::from_advertisement(
        receiver_pubkey_b,
        status0_b
            .advertisements
            .iter()
            .find(|a| a.unit == "sat")
            .expect("relay-b should advertise sat keyset"),
    );
    wallet_b
        .attach_channel_to_session(&channel_id_b, *conn_b.session_id())
        .unwrap();
    let link_json_b = wallet_b
        .build_link_request(&channel_id_b, &offer_b)
        .unwrap();
    send_control_message(
        &mut control_send_b,
        &ClientMessage::ChannelLink {
            payment_json: link_json_b,
        },
        false,
    )
    .await;
    let _ = expect_session_status_struct(read_control_message(&mut control_recv_b).await);
    let payment_json_b = wallet_b
        .build_channel_payment(&channel_id_b, &offer_b, 0, 1)
        .unwrap();
    send_control_message(
        &mut control_send_b,
        &ClientMessage::ChannelPayment {
            payment_json: payment_json_b,
        },
        false,
    )
    .await;
    let paid_b = expect_session_status_struct(read_control_message(&mut control_recv_b).await);
    assert_eq!(paid_b.total_paid_millisats, 1000);

    assert_ne!(channel_id_a, channel_id_b);
    assert_eq!(
        wallet_manager
            .relay_name_for_channel(&channel_id_a)
            .unwrap(),
        Some("relay-a".to_string())
    );
    assert_eq!(
        wallet_manager
            .relay_name_for_channel(&channel_id_b)
            .unwrap(),
        Some("relay-b".to_string())
    );

    let _ = control_send_a.send_data(Bytes::new(), true);
    drop(control_send_a);
    drop(control_recv_a);
    conn_a.shutdown().await;
    let _ = control_send_b.send_data(Bytes::new(), true);
    drop(control_send_b);
    drop(control_recv_b);
    conn_b.shutdown().await;

    let _ = shutdown_tx_a.send(());
    handle_a.await.unwrap().unwrap();
    let _ = shutdown_tx_b.send(());
    handle_b.await.unwrap().unwrap();
}

#[tokio::test(flavor = "multi_thread")]
async fn test_relay_restart_preserves_channel_state_with_real_signatures() {
    let upper_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let upper_addr = upper_listener.local_addr().unwrap();
    tokio::spawn(run_uppercase_server(upper_listener));

    let mint_helper = TestMintHelper::new().await.unwrap();
    let mint_url = "https://test-mint.invalid".to_string();
    let keyset_id = mint_helper.keyset_id().to_string();
    let keyset_info_json = mint_helper.keyset_info_json().unwrap();
    let mint_cache = mint_cache_with_keyset(&mint_url, "sat", &keyset_id, &keyset_info_json, true);
    let trusted_mint_units =
        BTreeMap::from([(mint_url.clone(), BTreeSet::from(["sat".to_string()]))]);

    let temp_db = tempfile::NamedTempFile::new().unwrap();
    let storage_path = temp_db.path().to_str().unwrap().to_string();

    let transport_key = SecpTransportKeypair::generate();
    let payment_receiver_secret = cashu::nuts::SecretKey::generate();
    let receiver_pubkey_hex = payment_receiver_secret.public_key().to_hex();

    // Phase A: first relay session, driven by the payment driver.
    let (server_addr, pubkey, handle, shutdown_tx, _payments) = start_persistent_relay(
        "127.0.0.1:0".parse().unwrap(),
        &transport_key,
        payment_receiver_secret.clone(),
        &storage_path,
        mint_cache.clone(),
        trusted_mint_units.clone(),
    )
    .await
    .unwrap();

    let wallet = Arc::new(
        TestSigningWallet::new(
            mint_helper.mint(),
            receiver_pubkey_hex.clone(),
            mint_url.clone(),
            keyset_id.clone(),
            keyset_info_json.clone(),
        )
        .await,
    );
    let channel_id = wallet.pre_create_channel(1000).await.unwrap();

    let conn = connect_client_quic_secp(server_addr, &pubkey).await;
    let (driver_handle, ready_rx) = start_session_payment_driver(
        &conn,
        wallet.clone() as Arc<dyn monad_client::wallet::MonadWallet>,
        "real-crypto hop",
        monad_client::session_driver::PaymentPolicy {
            target_topup_buffer_msats: 1000,
            minimum_topup_msats: 1000,
        },
    )
    .await
    .unwrap();

    timeout(Duration::from_secs(5), ready_rx)
        .await
        .expect("driver should ready")
        .expect("driver ready signal");

    let mut tunnel = conn.open_tunnel(&upper_addr.to_string()).await.unwrap();
    tunnel.write_all(b"before restart").await.unwrap();
    tunnel.shutdown().await.unwrap();
    let mut result = Vec::new();
    tunnel.read_to_end(&mut result).await.unwrap();
    assert_eq!(result, b"BEFORE RESTART");

    let first_session_id = *conn.session_id();
    let stored_balance_msats = wallet
        .get_channel(&channel_id)
        .unwrap()
        .current_signed_balance_msats;
    assert_eq!(
        stored_balance_msats, 1000,
        "first session should be credited exactly 1000 msats"
    );

    driver_handle.abort();
    let _ = driver_handle.await;
    conn.shutdown().await;

    // Phase B: graceful relay shutdown.
    let _ = shutdown_tx.send(());
    handle.await.unwrap().unwrap();

    // Phase C: restart the relay with the same SQLite file and identity. Use
    // a fresh port; graceful shutdown may leave the old socket in TIME_WAIT
    // briefly, and persistence does not depend on the endpoint address.
    let (server_addr2, pubkey2, handle2, shutdown_tx2, _payments2) = start_persistent_relay(
        "127.0.0.1:0".parse().unwrap(),
        &transport_key,
        payment_receiver_secret,
        &storage_path,
        mint_cache,
        trusted_mint_units,
    )
    .await
    .unwrap();
    assert_eq!(pubkey2, pubkey);

    // Phase D: reconnect and explicitly verify persistence.
    let conn2 = connect_client_quic_secp(server_addr2, &pubkey2).await;
    let (mut control_send2, mut control_recv2) = conn2.open_control().await.unwrap();
    let status0 = control_handshake_status(&mut control_send2, &mut control_recv2).await;
    assert!(status0.paused, "new session should start paused");
    assert!(status0.linked_channel.is_none());

    // Detach from the old session and attach to the new one so the wallet can
    // build signed link/payment payloads for this session.
    wallet
        .detach_channel_from_session(&channel_id, first_session_id)
        .unwrap();
    wallet
        .attach_channel_to_session(&channel_id, *conn2.session_id())
        .unwrap();

    let offer = RelayPaymentOffer::from_advertisement(
        receiver_pubkey_hex,
        status0
            .advertisements
            .iter()
            .find(|a| a.unit == "sat")
            .expect("relay should advertise sat keyset"),
    );

    let link_json = wallet.build_link_request(&channel_id, &offer).unwrap();
    send_control_message(
        &mut control_send2,
        &ClientMessage::ChannelLink {
            payment_json: link_json,
        },
        false,
    )
    .await;

    let status_after_link =
        expect_session_status_struct(read_control_message(&mut control_recv2).await);
    let linked_channel = status_after_link
        .linked_channel
        .as_ref()
        .expect("channel should be linked after restart");
    assert_eq!(linked_channel.channel_id, channel_id);
    assert_eq!(
        linked_channel.balance_raw,
        stored_balance_msats / 1000,
        "stored balance should survive restart"
    );

    // Pay an additional 1 sat above the stored balance to prove delta
    // accounting resumes from the persisted balance.
    let stored_balance_raw = stored_balance_msats / 1000;
    let delta_raw = 1u64;
    let payment_json = wallet
        .build_channel_payment(
            &channel_id,
            &offer,
            stored_balance_raw,
            stored_balance_raw + delta_raw,
        )
        .unwrap();
    send_control_message(
        &mut control_send2,
        &ClientMessage::ChannelPayment { payment_json },
        false,
    )
    .await;

    let status_after_pay =
        expect_session_status_struct(read_control_message(&mut control_recv2).await);
    assert!(
        !status_after_pay.paused,
        "session should unpause after payment"
    );
    assert_eq!(
        status_after_pay.total_paid_millisats,
        delta_raw * 1000,
        "only the delta should credit the new session"
    );

    let mut tunnel2 = conn2.open_tunnel(&upper_addr.to_string()).await.unwrap();
    tunnel2.write_all(b"after restart").await.unwrap();
    tunnel2.shutdown().await.unwrap();
    let mut result2 = Vec::new();
    tunnel2.read_to_end(&mut result2).await.unwrap();
    assert_eq!(result2, b"AFTER RESTART");

    let _ = control_send2.send_data(Bytes::new(), true);
    drop(control_send2);
    drop(control_recv2);
    conn2.shutdown().await;

    let _ = shutdown_tx2.send(());
    handle2.await.unwrap().unwrap();
}

/// End-to-end test that changing the relay's current trusted mint policy does
/// not invalidate an already-accepted stored channel. The relay should stop
/// advertising that mint for new channels, but the client must still be able to
/// re-link and continue paying on the old channel.
#[tokio::test(flavor = "multi_thread")]
async fn test_relay_policy_change_stops_advertising_but_existing_channel_still_works() {
    let upper_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let upper_addr = upper_listener.local_addr().unwrap();
    tokio::spawn(run_uppercase_server(upper_listener));

    let mint_helper = TestMintHelper::new().await.unwrap();
    let mint_url = "https://test-mint.invalid".to_string();
    let keyset_id = mint_helper.keyset_id().to_string();
    let keyset_info_json = mint_helper.keyset_info_json().unwrap();
    let allowed_mint_cache =
        mint_cache_with_keyset(&mint_url, "sat", &keyset_id, &keyset_info_json, true);
    let allowed_trusted_mint_units =
        BTreeMap::from([(mint_url.clone(), BTreeSet::from(["sat".to_string()]))]);

    let temp_db = tempfile::NamedTempFile::new().unwrap();
    let storage_path = temp_db.path().to_str().unwrap().to_string();

    let transport_key = SecpTransportKeypair::generate();
    let payment_receiver_secret = cashu::nuts::SecretKey::generate();
    let receiver_pubkey_hex = payment_receiver_secret.public_key().to_hex();

    let (server_addr, pubkey, handle, shutdown_tx, _payments) = start_persistent_relay(
        "127.0.0.1:0".parse().unwrap(),
        &transport_key,
        payment_receiver_secret.clone(),
        &storage_path,
        allowed_mint_cache,
        allowed_trusted_mint_units,
    )
    .await
    .unwrap();

    let wallet = Arc::new(
        TestSigningWallet::new(
            mint_helper.mint(),
            receiver_pubkey_hex.clone(),
            mint_url.clone(),
            keyset_id.clone(),
            keyset_info_json.clone(),
        )
        .await,
    );
    let channel_id = wallet.pre_create_channel(1000).await.unwrap();

    let conn = connect_client_quic_secp(server_addr, &pubkey).await;
    let (mut control_send, mut control_recv) = conn.open_control().await.unwrap();
    let status0 = control_handshake_status(&mut control_send, &mut control_recv).await;
    let offer = RelayPaymentOffer::from_advertisement(
        receiver_pubkey_hex.clone(),
        status0
            .advertisements
            .iter()
            .find(|a| a.unit == "sat")
            .expect("relay should advertise sat keyset before policy change"),
    );

    wallet
        .attach_channel_to_session(&channel_id, *conn.session_id())
        .unwrap();
    let link_json = wallet.build_link_request(&channel_id, &offer).unwrap();
    send_control_message(
        &mut control_send,
        &ClientMessage::ChannelLink {
            payment_json: link_json,
        },
        false,
    )
    .await;
    let _ = expect_session_status_struct(read_control_message(&mut control_recv).await);

    let payment_json = wallet
        .build_channel_payment(&channel_id, &offer, 0, 1)
        .unwrap();
    send_control_message(
        &mut control_send,
        &ClientMessage::ChannelPayment { payment_json },
        false,
    )
    .await;
    let status_after_pay =
        expect_session_status_struct(read_control_message(&mut control_recv).await);
    assert_eq!(status_after_pay.total_paid_millisats, 1000);

    let first_session_id = *conn.session_id();
    let stored_balance_msats = wallet
        .get_channel(&channel_id)
        .unwrap()
        .current_signed_balance_msats;

    let _ = control_send.send_data(Bytes::new(), true);
    drop(control_send);
    drop(control_recv);
    conn.shutdown().await;
    let _ = shutdown_tx.send(());
    handle.await.unwrap().unwrap();

    let disallowed_mint_cache = SpilmanMintCache::default();
    let disallowed_trusted_mint_units = BTreeMap::new();
    let (server_addr2, pubkey2, handle2, shutdown_tx2, _payments2) = start_persistent_relay(
        "127.0.0.1:0".parse().unwrap(),
        &transport_key,
        payment_receiver_secret,
        &storage_path,
        disallowed_mint_cache,
        disallowed_trusted_mint_units,
    )
    .await
    .unwrap();
    assert_eq!(pubkey2, pubkey);

    let conn2 = connect_client_quic_secp(server_addr2, &pubkey2).await;
    let (mut control_send2, mut control_recv2) = conn2.open_control().await.unwrap();
    let status_after_restart =
        control_handshake_status(&mut control_send2, &mut control_recv2).await;
    assert!(
        status_after_restart
            .advertisements
            .iter()
            .all(|a| a.unit != "sat"),
        "relay should stop advertising sat mint after policy change"
    );

    wallet
        .detach_channel_from_session(&channel_id, first_session_id)
        .unwrap();
    wallet
        .attach_channel_to_session(&channel_id, *conn2.session_id())
        .unwrap();

    let old_offer = RelayPaymentOffer {
        receiver_pubkey: receiver_pubkey_hex,
        mint_url,
        unit: "sat".to_string(),
        accepted_keyset_ids: vec![keyset_id],
        in_bytes_per_millisat: 1,
        out_bytes_per_millisat: 1,
    };
    let link_json = wallet.build_link_request(&channel_id, &old_offer).unwrap();
    send_control_message(
        &mut control_send2,
        &ClientMessage::ChannelLink {
            payment_json: link_json,
        },
        false,
    )
    .await;
    let status_after_link =
        expect_session_status_struct(read_control_message(&mut control_recv2).await);
    status_after_link.assert_linked_channel(&channel_id, stored_balance_msats / 1000, 1000, "sat");

    let stored_balance_raw = stored_balance_msats / 1000;
    let payment_json = wallet
        .build_channel_payment(
            &channel_id,
            &old_offer,
            stored_balance_raw,
            stored_balance_raw + 1,
        )
        .unwrap();
    send_control_message(
        &mut control_send2,
        &ClientMessage::ChannelPayment { payment_json },
        false,
    )
    .await;
    let status_after_second_pay =
        expect_session_status_struct(read_control_message(&mut control_recv2).await);
    assert_eq!(status_after_second_pay.total_paid_millisats, 1000);

    let mut tunnel = conn2.open_tunnel(&upper_addr.to_string()).await.unwrap();
    tunnel.write_all(b"after policy change").await.unwrap();
    tunnel.shutdown().await.unwrap();
    let mut result = Vec::new();
    tunnel.read_to_end(&mut result).await.unwrap();
    assert_eq!(result, b"AFTER POLICY CHANGE");

    let _ = control_send2.send_data(Bytes::new(), true);
    drop(control_send2);
    drop(control_recv2);
    conn2.shutdown().await;
    let _ = shutdown_tx2.send(());
    handle2.await.unwrap().unwrap();
}

/// A relay must reject ChannelLink when the funding token itself uses a keyset
/// outside the relay's accepted/known trusted set, regardless of whether that
/// keyset is currently active at the mint. This test starts with relay-accepted
/// keyset A, rotates the mint to active keyset B, then links a B-funded channel
/// while the relay still accepts only A.
#[tokio::test(flavor = "multi_thread")]
async fn test_channel_link_rejects_unaccepted_funding_keyset() {
    let mint_helper = TestMintHelper::new().await.unwrap();
    let mint = mint_helper.mint();
    let mint_url = "https://test-mint.invalid".to_string();
    let accepted_keyset_id = mint_helper.keyset_id().to_string();
    let accepted_keyset_info_json = mint_helper.keyset_info_json().unwrap();

    let rejected_keyset_id = rotate_sat_keyset(&mint, 400).await.unwrap().to_string();
    assert_ne!(accepted_keyset_id, rejected_keyset_id);
    let client_bridge = SpilmanClientBridge::new(
        ConfigurableClientHost::new_in_memory(),
        InMemoryMintNetworking::new(mint.clone()),
    );
    let rejected_keyset_info_json = client_bridge
        .fetch_keyset_info(&mint_url, &rejected_keyset_id)
        .expect("fetch rejected keyset info");

    let accepted_mint_cache = mint_cache_with_keyset(
        &mint_url,
        "sat",
        &accepted_keyset_id,
        accepted_keyset_info_json,
        true,
    );
    let trusted_mint_units =
        BTreeMap::from([(mint_url.clone(), BTreeSet::from(["sat".to_string()]))]);

    let temp_db = tempfile::NamedTempFile::new().unwrap();
    let storage_path = temp_db.path().to_str().unwrap().to_string();

    let transport_key = SecpTransportKeypair::generate();
    let payment_receiver_secret = cashu::nuts::SecretKey::generate();
    let receiver_pubkey_hex = payment_receiver_secret.public_key().to_hex();

    let (server_addr, pubkey, handle, shutdown_tx, _payments) = start_persistent_relay(
        "127.0.0.1:0".parse().unwrap(),
        &transport_key,
        payment_receiver_secret,
        &storage_path,
        accepted_mint_cache,
        trusted_mint_units,
    )
    .await
    .unwrap();

    let wallet = Arc::new(
        TestSigningWallet::new(
            mint,
            receiver_pubkey_hex,
            mint_url,
            rejected_keyset_id.clone(),
            rejected_keyset_info_json,
        )
        .await,
    );
    let channel_id = wallet.pre_create_channel(1000).await.unwrap();
    assert_eq!(
        wallet.get_channel(&channel_id).unwrap().keyset_id,
        rejected_keyset_id
    );

    let conn = connect_client_quic_secp(server_addr, &pubkey).await;
    let (mut control_send, mut control_recv) = conn.open_control().await.unwrap();
    let status0 = control_handshake_status(&mut control_send, &mut control_recv).await;
    let advertised_sat = status0
        .advertisements
        .iter()
        .find(|ad| ad.unit == "sat")
        .expect("relay should advertise accepted sat keyset");
    assert_eq!(advertised_sat.keyset_ids, vec![accepted_keyset_id]);
    assert!(!advertised_sat.keyset_ids.contains(&rejected_keyset_id));

    wallet
        .attach_channel_to_session(&channel_id, *conn.session_id())
        .unwrap();
    let payment_json = wallet.build_raw_link_request(&channel_id).unwrap();
    send_control_message(
        &mut control_send,
        &ClientMessage::ChannelLink { payment_json },
        false,
    )
    .await;

    match read_control_message(&mut control_recv).await {
        ServerMessage::Error { code, message } => {
            assert_eq!(code, ServerErrorCode::LinkMintOrKeysetUnacceptable);
            assert!(message.contains("mint or keyset not acceptable"));
        }
        other => panic!("expected LinkMintOrKeysetUnacceptable error, got {other:?}"),
    }

    let _ = control_send.send_data(Bytes::new(), true);
    drop(control_send);
    drop(control_recv);
    conn.shutdown().await;
    let _ = shutdown_tx.send(());
    handle.await.unwrap().unwrap();
}

/// A relay can be started from a YAML config file and advertises exactly the
/// mints/units configured for that relay.
#[tokio::test(flavor = "multi_thread")]
async fn test_relay_starts_from_yaml_config_and_advertises_configured_mints() {
    use monad_relay::config::MonadConfig;
    use std::fs;

    let mint_helper = TestMintHelper::new().await.unwrap();
    let mint_url = "https://test-mint.invalid".to_string();
    let keyset_id = mint_helper.keyset_id().to_string();
    let keyset_info_json = mint_helper.keyset_info_json().unwrap();
    let mint_cache = mint_cache_with_keyset(&mint_url, "sat", &keyset_id, &keyset_info_json, true);

    let temp_dir = tempfile::tempdir().unwrap();
    let config_path = temp_dir.path().join("relay.yaml");
    let db_path = temp_dir.path().join("relay.db");

    let receiver_secret = cashu::nuts::SecretKey::generate();
    let receiver_secret_hex = receiver_secret.to_secret_hex();
    let transport_key = SecpTransportKeypair::generate();
    let transport_key_hex = hex::encode(transport_key.normalized_secret_bytes());
    let quic_cert = QuicCertIdentity::generate().unwrap();
    let quic_seed_hex = hex::encode(quic_cert.seed());

    let yaml = format!(
        r#"
relays:
  - name: yaml-relay
    wallet_db_path: {}
    receiver_secret_hex: {}
    quic_cert_seed: {}
    transport_key: {}
    listen: 127.0.0.1:0
    quic: true
    trusted_mints:
      - url: {}
        units: [sat]
    in_bytes_per_millisat: 1
    out_bytes_per_millisat: 1
"#,
        db_path.to_str().unwrap(),
        receiver_secret_hex,
        quic_seed_hex,
        transport_key_hex,
        mint_url,
    );
    fs::write(&config_path, yaml).unwrap();

    let config = MonadConfig::load(&config_path).unwrap();
    let relay = config.select_relay(None).unwrap();

    let wallet_manager = Arc::new(RelayWalletManager::open(&relay.wallet_db_path).unwrap());
    let (server_addr, pubkey, handle, shutdown_tx, _payments) =
        start_relay_from_config(relay, wallet_manager, mint_cache)
            .await
            .unwrap();

    let conn = connect_client_quic_secp(server_addr, &pubkey).await;
    let (mut control_send, mut control_recv) = conn.open_control().await.unwrap();
    let status = control_handshake_status(&mut control_send, &mut control_recv).await;

    assert_eq!(status.advertisements.len(), 1);
    assert_eq!(status.advertisements[0].mint_url, mint_url);
    assert_eq!(status.advertisements[0].unit, "sat");
    assert!(status.advertisements[0].keyset_ids.contains(&keyset_id));

    let _ = control_send.send_data(Bytes::new(), true);
    drop(control_send);
    drop(control_recv);
    conn.shutdown().await;
    let _ = shutdown_tx.send(());
    handle.await.unwrap().unwrap();
}

#[tokio::test(flavor = "multi_thread")]
async fn test_yaml_config_allows_distinct_per_relay_pricing() {
    use monad_relay::config::MonadConfig;
    use std::fs;

    let mint_helper = TestMintHelper::new().await.unwrap();
    let mint_url = "https://test-mint.invalid".to_string();
    let keyset_id = mint_helper.keyset_id().to_string();
    let keyset_info_json = mint_helper.keyset_info_json().unwrap();
    let mint_cache = mint_cache_with_keyset(&mint_url, "sat", &keyset_id, &keyset_info_json, true);

    let temp_dir = tempfile::tempdir().unwrap();
    let config_path = temp_dir.path().join("relay.yaml");
    let db_path_a = temp_dir.path().join("relay-a.db");
    let db_path_b = temp_dir.path().join("relay-b.db");
    let listen_a = TcpListener::bind("127.0.0.1:0")
        .await
        .unwrap()
        .local_addr()
        .unwrap();
    let listen_b = TcpListener::bind("127.0.0.1:0")
        .await
        .unwrap()
        .local_addr()
        .unwrap();

    let receiver_secret_a = cashu::nuts::SecretKey::generate();
    let receiver_secret_b = cashu::nuts::SecretKey::generate();
    let transport_key_a = SecpTransportKeypair::generate();
    let transport_key_b = SecpTransportKeypair::generate();
    let quic_cert_a = QuicCertIdentity::generate().unwrap();
    let quic_cert_b = QuicCertIdentity::generate().unwrap();

    let yaml = format!(
        r#"
relays:
  - name: relay-a
    wallet_db_path: {}
    receiver_secret_hex: {}
    quic_cert_seed: {}
    transport_key: {}
    listen: {}
    quic: true
    in_bytes_per_millisat: 11
    out_bytes_per_millisat: 22
    trusted_mints:
      - url: {}
        units: [sat]
  - name: relay-b
    wallet_db_path: {}
    receiver_secret_hex: {}
    quic_cert_seed: {}
    transport_key: {}
    listen: {}
    quic: true
    in_bytes_per_millisat: 33
    out_bytes_per_millisat: 44
    trusted_mints:
      - url: {}
        units: [sat]
"#,
        db_path_a.to_str().unwrap(),
        receiver_secret_a.to_secret_hex(),
        hex::encode(quic_cert_a.seed()),
        hex::encode(transport_key_a.normalized_secret_bytes()),
        listen_a,
        mint_url,
        db_path_b.to_str().unwrap(),
        receiver_secret_b.to_secret_hex(),
        hex::encode(quic_cert_b.seed()),
        hex::encode(transport_key_b.normalized_secret_bytes()),
        listen_b,
        mint_url,
    );
    fs::write(&config_path, yaml).unwrap();

    let config = MonadConfig::load(&config_path).unwrap();
    let relay_a = config.select_relay(Some("relay-a")).unwrap();
    let relay_b = config.select_relay(Some("relay-b")).unwrap();

    let wallet_manager_a = Arc::new(RelayWalletManager::open(&relay_a.wallet_db_path).unwrap());
    let (server_addr_a, pubkey_a, handle_a, shutdown_tx_a, _payments_a) =
        start_relay_from_config(relay_a, wallet_manager_a, mint_cache.clone())
            .await
            .unwrap();
    let wallet_manager_b = Arc::new(RelayWalletManager::open(&relay_b.wallet_db_path).unwrap());
    let (server_addr_b, pubkey_b, handle_b, shutdown_tx_b, _payments_b) =
        start_relay_from_config(relay_b, wallet_manager_b, mint_cache)
            .await
            .unwrap();

    let conn_a = connect_client_quic_secp(server_addr_a, &pubkey_a).await;
    let mut control_a = ControlSessionHarness::open(&conn_a).await;
    let status_a = control_a.handshake().await;
    assert_eq!(status_a.active_in_rate, 11);
    assert_eq!(status_a.active_out_rate, 22);
    assert_eq!(status_a.advertisements.len(), 1);
    assert_eq!(status_a.advertisements[0].in_bytes_per_millisat, 11);
    assert_eq!(status_a.advertisements[0].out_bytes_per_millisat, 22);

    let conn_b = connect_client_quic_secp(server_addr_b, &pubkey_b).await;
    let mut control_b = ControlSessionHarness::open(&conn_b).await;
    let status_b = control_b.handshake().await;
    assert_eq!(status_b.active_in_rate, 33);
    assert_eq!(status_b.active_out_rate, 44);
    assert_eq!(status_b.advertisements.len(), 1);
    assert_eq!(status_b.advertisements[0].in_bytes_per_millisat, 33);
    assert_eq!(status_b.advertisements[0].out_bytes_per_millisat, 44);

    control_a.close().await;
    control_b.close().await;
    conn_a.shutdown().await;
    conn_b.shutdown().await;
    let _ = shutdown_tx_a.send(());
    let _ = shutdown_tx_b.send(());
    handle_a.await.unwrap().unwrap();
    handle_b.await.unwrap().unwrap();
}

/// End-to-end test that the relay can unilaterally close a funded Spilman
/// channel and that further payments on that channel are rejected.
#[tokio::test(flavor = "multi_thread")]
async fn test_channel_close_blocks_further_payments_with_real_signatures() {
    let upper_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let upper_addr = upper_listener.local_addr().unwrap();
    tokio::spawn(run_uppercase_server(upper_listener));

    let mint_helper = TestMintHelper::new().await.unwrap();
    let mint_url = "https://test-mint.invalid".to_string();
    let keyset_id = mint_helper.keyset_id().to_string();
    let keyset_info_json = mint_helper.keyset_info_json().unwrap();
    let mint_cache = mint_cache_with_keyset(&mint_url, "sat", &keyset_id, &keyset_info_json, true);
    let trusted_mint_units =
        BTreeMap::from([(mint_url.clone(), BTreeSet::from(["sat".to_string()]))]);

    let temp_db = tempfile::NamedTempFile::new().unwrap();
    let storage_path = temp_db.path().to_str().unwrap().to_string();

    let transport_key = SecpTransportKeypair::generate();
    let payment_receiver_secret = cashu::nuts::SecretKey::generate();
    let receiver_pubkey_hex = payment_receiver_secret.public_key().to_hex();

    let (server_addr, pubkey, handle, shutdown_tx, payments) = start_persistent_relay(
        "127.0.0.1:0".parse().unwrap(),
        &transport_key,
        payment_receiver_secret,
        &storage_path,
        mint_cache,
        trusted_mint_units,
    )
    .await
    .unwrap();

    let wallet = Arc::new(
        TestSigningWallet::new(
            mint_helper.mint(),
            receiver_pubkey_hex.clone(),
            mint_url.clone(),
            keyset_id.clone(),
            keyset_info_json.clone(),
        )
        .await,
    );
    let channel_id = wallet.pre_create_channel(1000).await.unwrap();

    let conn = connect_client_quic_secp(server_addr, &pubkey).await;
    let (mut control_send, mut control_recv) = conn.open_control().await.unwrap();
    let status0 = control_handshake_status(&mut control_send, &mut control_recv).await;

    let offer = RelayPaymentOffer::from_advertisement(
        receiver_pubkey_hex,
        status0
            .advertisements
            .iter()
            .find(|a| a.unit == "sat")
            .expect("relay should advertise sat keyset"),
    );

    // Link the pre-created channel to this session.
    wallet
        .attach_channel_to_session(&channel_id, *conn.session_id())
        .unwrap();
    let link_json = wallet.build_link_request(&channel_id, &offer).unwrap();
    send_control_message(
        &mut control_send,
        &ClientMessage::ChannelLink {
            payment_json: link_json,
        },
        false,
    )
    .await;
    let _link_status = expect_session_status_struct(read_control_message(&mut control_recv).await);

    // Fund the session by paying part of the channel capacity.
    let capacity_raw = wallet.get_channel(&channel_id).unwrap().capacity_msats / 1000;
    let funded_balance_raw = capacity_raw / 2;
    let payment_json = wallet
        .build_channel_payment(&channel_id, &offer, 0, funded_balance_raw)
        .unwrap();
    send_control_message(
        &mut control_send,
        &ClientMessage::ChannelPayment { payment_json },
        false,
    )
    .await;
    let funded_status = expect_session_status_struct(read_control_message(&mut control_recv).await);
    assert!(
        !funded_status.paused,
        "session should be unpaused after payment"
    );
    assert_eq!(
        funded_status.total_paid_millisats,
        funded_balance_raw * 1000
    );

    // Use the session to verify it is functional.
    let mut tunnel = conn.open_tunnel(&upper_addr.to_string()).await.unwrap();
    tunnel.write_all(b"before close").await.unwrap();
    tunnel.shutdown().await.unwrap();
    let mut result = Vec::new();
    tunnel.read_to_end(&mut result).await.unwrap();
    assert_eq!(result, b"BEFORE CLOSE");

    // Close the channel through the relay, using the in-memory mint networking.
    let mint_networking = InMemoryMintNetworking::new(mint_helper.mint());
    let close_success = payments
        .close_channel(&channel_id, &mint_networking)
        .expect("relay should close the channel");
    assert!(!close_success.already_closed);
    assert_eq!(close_success.receiver_sum, funded_balance_raw);
    assert_eq!(
        close_success.receiver_sum + close_success.sender_sum,
        close_success.total_value
    );
    assert_eq!(close_success.total_value, capacity_raw);

    assert_eq!(
        payments.channel_state(&channel_id),
        Some(ChannelState::Closed),
        "channel should be Closed after unilateral close"
    );

    assert_closed_payout_at_least(&payments, &channel_id, funded_balance_raw);

    // A further payment on the same linked channel must be rejected because
    // the channel is closed.
    let payment_json = wallet
        .build_channel_payment(
            &channel_id,
            &offer,
            funded_balance_raw,
            funded_balance_raw + 1,
        )
        .unwrap();
    send_control_message(
        &mut control_send,
        &ClientMessage::ChannelPayment { payment_json },
        false,
    )
    .await;

    let (code, message) = match read_control_message(&mut control_recv).await {
        ServerMessage::Error { code, message } => (code, message),
        other => panic!("expected ChannelClosed error, got {other:?}"),
    };
    assert_eq!(code, ServerErrorCode::ChannelClosed);
    assert!(
        message.contains("channel closed"),
        "unexpected error: {message}"
    );

    // A subsequent ChannelLink for the same closed channel must also be
    // rejected, even though the wallet still produces a valid signed link
    // request (balance 0).
    let link_json = wallet.build_link_request(&channel_id, &offer).unwrap();
    send_control_message(
        &mut control_send,
        &ClientMessage::ChannelLink {
            payment_json: link_json,
        },
        false,
    )
    .await;

    let (code, message) = match read_control_message(&mut control_recv).await {
        ServerMessage::Error { code, message } => (code, message),
        other => panic!("expected ChannelClosed error on re-link, got {other:?}"),
    };
    assert_eq!(code, ServerErrorCode::ChannelClosed);
    assert!(
        message.contains("channel closed"),
        "unexpected re-link error: {message}"
    );

    let _ = control_send.send_data(Bytes::new(), true);
    drop(control_send);
    drop(control_recv);
    conn.shutdown().await;

    let _ = shutdown_tx.send(());
    handle.await.unwrap().unwrap();
}

#[tokio::test(flavor = "multi_thread")]
async fn test_client_observes_relay_close_and_restores_sender_proofs() {
    let mint_helper = TestMintHelper::new().await.unwrap();
    let mint_url = "https://test-mint.invalid".to_string();
    let keyset_id = mint_helper.keyset_id().to_string();
    let keyset_info_json = mint_helper.keyset_info_json().unwrap();
    let mint_cache = mint_cache_with_keyset(&mint_url, "sat", &keyset_id, &keyset_info_json, true);
    let trusted_mint_units =
        BTreeMap::from([(mint_url.clone(), BTreeSet::from(["sat".to_string()]))]);

    let temp_db = tempfile::NamedTempFile::new().unwrap();
    let storage_path = temp_db.path().to_str().unwrap().to_string();

    let transport_key = SecpTransportKeypair::generate();
    let payment_receiver_secret = cashu::nuts::SecretKey::generate();
    let receiver_pubkey_hex = payment_receiver_secret.public_key().to_hex();

    let (server_addr, pubkey, handle, shutdown_tx, payments) = start_persistent_relay(
        "127.0.0.1:0".parse().unwrap(),
        &transport_key,
        payment_receiver_secret,
        &storage_path,
        mint_cache,
        trusted_mint_units,
    )
    .await
    .unwrap();

    let wallet = Arc::new(
        TestSigningWallet::new(
            mint_helper.mint(),
            receiver_pubkey_hex.clone(),
            mint_url.clone(),
            keyset_id.clone(),
            keyset_info_json.clone(),
        )
        .await,
    );
    let channel_id = wallet.pre_create_channel(1000).await.unwrap();

    let conn = connect_client_quic_secp(server_addr, &pubkey).await;
    let (mut control_send, mut control_recv) = conn.open_control().await.unwrap();
    let status0 = control_handshake_status(&mut control_send, &mut control_recv).await;
    let offer = RelayPaymentOffer::from_advertisement(
        receiver_pubkey_hex,
        status0
            .advertisements
            .iter()
            .find(|a| a.unit == "sat")
            .expect("relay should advertise sat keyset"),
    );

    wallet
        .attach_channel_to_session(&channel_id, *conn.session_id())
        .unwrap();
    let link_json = wallet.build_link_request(&channel_id, &offer).unwrap();
    send_control_message(
        &mut control_send,
        &ClientMessage::ChannelLink {
            payment_json: link_json,
        },
        false,
    )
    .await;
    let _link_status = expect_session_status_struct(read_control_message(&mut control_recv).await);

    let capacity_raw = wallet.get_channel(&channel_id).unwrap().capacity_msats / 1000;
    let funded_balance_raw = capacity_raw / 2;
    let payment_json = wallet
        .build_channel_payment(&channel_id, &offer, 0, funded_balance_raw)
        .unwrap();
    send_control_message(
        &mut control_send,
        &ClientMessage::ChannelPayment { payment_json },
        false,
    )
    .await;
    let funded_status = expect_session_status_struct(read_control_message(&mut control_recv).await);
    assert!(!funded_status.paused);

    let funding = wallet.client_channel_funding(&channel_id).unwrap();
    let established = EstablishedChannel::from_client_channel_funding(&funding).unwrap();
    let mint_connection = DirectMintConnection {
        mint: mint_helper.mint(),
    };

    let before = established
        .check_funding_token_state(&mint_connection)
        .await
        .unwrap();
    assert_eq!(before.state, cashu::nuts::State::Unspent);

    let mint_networking = InMemoryMintNetworking::new(mint_helper.mint());
    let close_success = payments
        .close_channel(&channel_id, &mint_networking)
        .expect("relay should close the channel");
    assert!(!close_success.already_closed);
    assert_eq!(close_success.receiver_sum, funded_balance_raw);

    let after = established
        .check_funding_token_state(&mint_connection)
        .await
        .unwrap();
    assert_eq!(after.state, cashu::nuts::State::Spent);

    let restored_sender_proofs = EstablishedChannel::restore_sender_proofs_from_client_funding(
        &funding,
        wallet.sender_secret(),
        &mint_connection,
    )
    .await
    .unwrap();
    let relay_sender_proofs = parse_proofs_json(&close_success.sender_proofs);

    assert_proofs_have_p2pk_e(&restored_sender_proofs, "restored sender proofs");
    assert_proofs_have_p2pk_e(&relay_sender_proofs, "relay sender proofs");
    assert_same_p2pk_e(&restored_sender_proofs, &relay_sender_proofs);
    assert_proofs_have_witness_signatures(&restored_sender_proofs, "restored sender proofs");
    assert_proofs_have_no_witness_signatures(&relay_sender_proofs, "relay sender proofs");

    assert_eq!(
        restored_sender_proofs
            .iter()
            .map(|p| u64::from(p.amount))
            .sum::<u64>(),
        close_success.sender_sum
    );
    assert_eq!(
        canonical_proof_values_without_witness(&restored_sender_proofs),
        canonical_proof_values_without_witness(&relay_sender_proofs)
    );

    let _ = control_send.send_data(Bytes::new(), true);
    drop(control_send);
    drop(control_recv);
    conn.shutdown().await;

    let _ = shutdown_tx.send(());
    handle.await.unwrap().unwrap();
}

/// End-to-end test that the relay-wallet manager can close a funded channel
/// by channel id, discovering the owning relay identity and mint from the
/// stored metadata.
#[tokio::test(flavor = "multi_thread")]
async fn test_wallet_manager_close_channel_by_id() {
    let upper_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    tokio::spawn(run_uppercase_server(upper_listener));

    let mint_helper = TestMintHelper::new().await.unwrap();
    let mint_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let mint_addr = mint_listener.local_addr().unwrap();
    let mint_url = format!("http://127.0.0.1:{}", mint_addr.port());
    let mint_router = build_router(mint_helper.mint()).await.unwrap();
    let (mint_shutdown_tx, mint_shutdown_rx) = tokio::sync::oneshot::channel();
    tokio::spawn(async move {
        axum::serve(mint_listener, mint_router)
            .with_graceful_shutdown(async {
                let _ = mint_shutdown_rx.await;
            })
            .await
            .unwrap();
    });
    let keyset_id = mint_helper.keyset_id().to_string();
    let keyset_info_json = mint_helper.keyset_info_json().unwrap();
    let mint_cache = mint_cache_with_keyset(&mint_url, "sat", &keyset_id, &keyset_info_json, true);
    let trusted_mint_units =
        BTreeMap::from([(mint_url.clone(), BTreeSet::from(["sat".to_string()]))]);

    let temp_db = tempfile::NamedTempFile::new().unwrap();
    let storage_path = temp_db.path().to_str().unwrap().to_string();

    let transport_key = SecpTransportKeypair::generate();
    let payment_receiver_secret = cashu::nuts::SecretKey::generate();
    let receiver_pubkey_hex = payment_receiver_secret.public_key().to_hex();

    let wallet_manager = Arc::new(RelayWalletManager::open(&storage_path).unwrap());
    wallet_manager
        .register_identity("test-wallet-relay", payment_receiver_secret.clone())
        .unwrap();

    let (server_addr, pubkey, handle, shutdown_tx, payments) = start_managed_persistent_relay(
        "127.0.0.1:0".parse().unwrap(),
        &transport_key,
        payment_receiver_secret,
        "test-wallet-relay",
        wallet_manager.clone(),
        mint_cache,
        trusted_mint_units,
    )
    .await
    .unwrap();

    let wallet = Arc::new(
        TestSigningWallet::new(
            mint_helper.mint(),
            receiver_pubkey_hex.clone(),
            mint_url.clone(),
            keyset_id.clone(),
            keyset_info_json.clone(),
        )
        .await,
    );
    let channel_id = wallet.pre_create_channel(1000).await.unwrap();

    let conn = connect_client_quic_secp(server_addr, &pubkey).await;
    let (mut control_send, mut control_recv) = conn.open_control().await.unwrap();
    let status0 = control_handshake_status(&mut control_send, &mut control_recv).await;

    let offer = RelayPaymentOffer::from_advertisement(
        receiver_pubkey_hex,
        status0
            .advertisements
            .iter()
            .find(|a| a.unit == "sat")
            .expect("relay should advertise sat keyset"),
    );

    wallet
        .attach_channel_to_session(&channel_id, *conn.session_id())
        .unwrap();
    let link_json = wallet.build_link_request(&channel_id, &offer).unwrap();
    send_control_message(
        &mut control_send,
        &ClientMessage::ChannelLink {
            payment_json: link_json,
        },
        false,
    )
    .await;
    let _link_status = expect_session_status_struct(read_control_message(&mut control_recv).await);

    let capacity_raw = wallet.get_channel(&channel_id).unwrap().capacity_msats / 1000;
    let funded_balance_raw = capacity_raw / 2;
    let payment_json = wallet
        .build_channel_payment(&channel_id, &offer, 0, funded_balance_raw)
        .unwrap();
    send_control_message(
        &mut control_send,
        &ClientMessage::ChannelPayment { payment_json },
        false,
    )
    .await;
    let funded_status = expect_session_status_struct(read_control_message(&mut control_recv).await);
    assert!(!funded_status.paused);

    // Close the channel through the wallet manager by channel id using the
    // same reqwest-based networking path as the CLI.
    let net = wallet_manager
        .reqwest_networking_for_channel(&channel_id)
        .expect("wallet manager should build reqwest networking for channel");
    let close_success = wallet_manager
        .close_channel(&channel_id, &net)
        .await
        .expect("wallet manager should close the channel");
    assert!(!close_success.already_closed);
    assert_eq!(close_success.receiver_sum, funded_balance_raw);
    assert_eq!(close_success.total_value, capacity_raw);
    assert_closed_payout_at_least(&payments, &channel_id, funded_balance_raw);

    let _ = control_send.send_data(Bytes::new(), true);
    drop(control_send);
    drop(control_recv);
    conn.shutdown().await;

    let _ = shutdown_tx.send(());
    handle.await.unwrap().unwrap();
    let _ = mint_shutdown_tx.send(());
}

/// End-to-end test that a channel already persisted in `Closing` can be
/// completed to `Closed` through the wallet-manager close path, and that a
/// second close reports `already_closed`.
#[tokio::test(flavor = "multi_thread")]
async fn test_wallet_manager_close_channel_from_closing_state() {
    let upper_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    tokio::spawn(run_uppercase_server(upper_listener));

    let mint_helper = TestMintHelper::new().await.unwrap();
    let mint_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let mint_addr = mint_listener.local_addr().unwrap();
    let mint_url = format!("http://127.0.0.1:{}", mint_addr.port());
    let mint_router = build_router(mint_helper.mint()).await.unwrap();
    let (mint_shutdown_tx, mint_shutdown_rx) = tokio::sync::oneshot::channel();
    tokio::spawn(async move {
        axum::serve(mint_listener, mint_router)
            .with_graceful_shutdown(async {
                let _ = mint_shutdown_rx.await;
            })
            .await
            .unwrap();
    });
    let keyset_id = mint_helper.keyset_id().to_string();
    let keyset_info_json = mint_helper.keyset_info_json().unwrap();
    let mint_cache = mint_cache_with_keyset(&mint_url, "sat", &keyset_id, &keyset_info_json, true);
    let trusted_mint_units =
        BTreeMap::from([(mint_url.clone(), BTreeSet::from(["sat".to_string()]))]);

    let temp_db = tempfile::NamedTempFile::new().unwrap();
    let storage_path = temp_db.path().to_str().unwrap().to_string();

    let transport_key = SecpTransportKeypair::generate();
    let payment_receiver_secret = cashu::nuts::SecretKey::generate();
    let receiver_pubkey_hex = payment_receiver_secret.public_key().to_hex();

    let wallet_manager = Arc::new(RelayWalletManager::open(&storage_path).unwrap());
    wallet_manager
        .register_identity("test-wallet-relay", payment_receiver_secret.clone())
        .unwrap();

    let (server_addr, pubkey, handle, shutdown_tx, payments) = start_managed_persistent_relay(
        "127.0.0.1:0".parse().unwrap(),
        &transport_key,
        payment_receiver_secret,
        "test-wallet-relay",
        wallet_manager.clone(),
        mint_cache,
        trusted_mint_units,
    )
    .await
    .unwrap();

    let wallet = Arc::new(
        TestSigningWallet::new(
            mint_helper.mint(),
            receiver_pubkey_hex.clone(),
            mint_url.clone(),
            keyset_id.clone(),
            keyset_info_json.clone(),
        )
        .await,
    );
    let channel_id = wallet.pre_create_channel(1000).await.unwrap();

    let conn = connect_client_quic_secp(server_addr, &pubkey).await;
    let (mut control_send, mut control_recv) = conn.open_control().await.unwrap();
    let status0 = control_handshake_status(&mut control_send, &mut control_recv).await;

    let offer = RelayPaymentOffer::from_advertisement(
        receiver_pubkey_hex,
        status0
            .advertisements
            .iter()
            .find(|a| a.unit == "sat")
            .expect("relay should advertise sat keyset"),
    );

    wallet
        .attach_channel_to_session(&channel_id, *conn.session_id())
        .unwrap();
    let link_json = wallet.build_link_request(&channel_id, &offer).unwrap();
    send_control_message(
        &mut control_send,
        &ClientMessage::ChannelLink {
            payment_json: link_json,
        },
        false,
    )
    .await;
    let _ = expect_session_status_struct(read_control_message(&mut control_recv).await);

    let capacity_raw = wallet.get_channel(&channel_id).unwrap().capacity_msats / 1000;
    let funded_balance_raw = capacity_raw / 2;
    let payment_json = wallet
        .build_channel_payment(&channel_id, &offer, 0, funded_balance_raw)
        .unwrap();
    send_control_message(
        &mut control_send,
        &ClientMessage::ChannelPayment { payment_json },
        false,
    )
    .await;
    let funded_status = expect_session_status_struct(read_control_message(&mut control_recv).await);
    assert!(!funded_status.paused);

    // Force the channel into durable Closing state without finishing the close.
    let storage = SqliteStorage::open(&storage_path).unwrap();
    let latest_payment = storage
        .get_balance(&channel_id)
        .expect("storage should contain latest payment proof");
    storage
        .mark_closing(
            &channel_id,
            ClosingData {
                expiry_timestamp: 0,
                balance: latest_payment.balance,
                signature: latest_payment.signature.clone(),
            },
        )
        .expect("storage should persist Closing state");
    assert_eq!(storage.get_state(&channel_id), ChannelState::Closing);

    let net = wallet_manager
        .reqwest_networking_for_channel(&channel_id)
        .expect("wallet manager should build reqwest networking for channel");

    let close_success = wallet_manager
        .close_channel(&channel_id, &net)
        .await
        .expect("wallet manager should complete close from Closing state");
    assert!(!close_success.already_closed);
    assert_eq!(close_success.receiver_sum, funded_balance_raw);
    assert_eq!(close_success.total_value, capacity_raw);
    assert_eq!(
        payments.channel_state(&channel_id),
        Some(ChannelState::Closed)
    );
    assert!(payments.closed_data(&channel_id).is_some());

    let second_close = wallet_manager
        .close_channel(&channel_id, &net)
        .await
        .expect("second close on already-closed channel should succeed");
    assert!(second_close.already_closed);
    assert_eq!(second_close.receiver_sum, funded_balance_raw);
    assert_eq!(second_close.total_value, capacity_raw);
    assert_closed_payout_at_least(&payments, &channel_id, funded_balance_raw);

    let _ = control_send.send_data(Bytes::new(), true);
    drop(control_send);
    drop(control_recv);
    conn.shutdown().await;

    let _ = shutdown_tx.send(());
    handle.await.unwrap().unwrap();
    let _ = mint_shutdown_tx.send(());
}

#[tokio::test(flavor = "multi_thread")]
async fn test_wallet_manager_drain_swap_combines_multiple_closed_channels() {
    let mint_helper = TestMintHelper::new().await.unwrap();
    let mint_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let mint_addr = mint_listener.local_addr().unwrap();
    let mint_url = format!("http://127.0.0.1:{}", mint_addr.port());
    let mint_router = build_router(mint_helper.mint()).await.unwrap();
    let (mint_shutdown_tx, mint_shutdown_rx) = tokio::sync::oneshot::channel();
    tokio::spawn(async move {
        axum::serve(mint_listener, mint_router)
            .with_graceful_shutdown(async {
                let _ = mint_shutdown_rx.await;
            })
            .await
            .unwrap();
    });

    let keyset_id = mint_helper.keyset_id().to_string();
    let keyset_info_json = mint_helper.keyset_info_json().unwrap();
    let mint_cache = mint_cache_with_keyset(&mint_url, "sat", &keyset_id, &keyset_info_json, true);
    let trusted_mint_units =
        BTreeMap::from([(mint_url.clone(), BTreeSet::from(["sat".to_string()]))]);
    let temp_db = tempfile::NamedTempFile::new().unwrap();
    let wallet_manager = RelayWalletManager::open(temp_db.path().to_str().unwrap()).unwrap();
    let receiver_secret = cashu::nuts::SecretKey::generate();
    let receiver_pubkey_hex = receiver_secret.public_key().to_hex();
    wallet_manager
        .register_identity("drain-relay", receiver_secret)
        .unwrap();
    wallet_manager.install_keyset_cache(mint_cache.clone());
    let payments = wallet_manager
        .spilman_payments_for("drain-relay", mint_cache, trusted_mint_units)
        .unwrap();
    let wallet = TestSigningWallet::new(
        mint_helper.mint(),
        receiver_pubkey_hex.clone(),
        mint_url.clone(),
        keyset_id.clone(),
        keyset_info_json,
    )
    .await;
    let offer = RelayPaymentOffer {
        receiver_pubkey: receiver_pubkey_hex,
        mint_url: mint_url.clone(),
        unit: "sat".to_string(),
        accepted_keyset_ids: vec![keyset_id],
        in_bytes_per_millisat: 1,
        out_bytes_per_millisat: 1,
    };

    let ch1 =
        create_paid_closed_channel(&wallet_manager, &payments, &wallet, &offer, [1u8; 32], 300)
            .await;
    let ch2 =
        create_paid_closed_channel(&wallet_manager, &payments, &wallet, &offer, [2u8; 32], 200)
            .await;

    let net = wallet_manager.reqwest_networking_for_channel(&ch1).unwrap();
    let drain = wallet_manager
        .drain_closed_channels_to_swap("drain-relay", &mint_url, "sat", &net, None)
        .await
        .expect("drain should swap closed receiver proofs");
    assert_eq!(drain.input_amount_raw, 500);
    assert_eq!(drain.output_amount_raw, 500);
    assert_eq!(sum_proof_amounts(&drain.output_proofs_json), 500);
    assert_eq!(
        BTreeSet::from_iter(drain.channel_ids.iter().cloned()),
        BTreeSet::from([ch1, ch2])
    );
    assert!(!drain.recovered);

    let drains = wallet_manager.list_drains().unwrap();
    assert_eq!(drains.len(), 1);
    assert_eq!(drains[0].state, "Completed");
    let no_more = wallet_manager
        .drain_closed_channels_to_swap("drain-relay", &mint_url, "sat", &net, None)
        .await
        .unwrap_err();
    assert!(no_more.contains("no closed channels"));

    let _ = mint_shutdown_tx.send(());
}

#[tokio::test(flavor = "multi_thread")]
async fn test_wallet_manager_drain_swap_recovers_after_ambiguous_submission() {
    let mint_helper = TestMintHelper::new().await.unwrap();
    let mint_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let mint_addr = mint_listener.local_addr().unwrap();
    let mint_url = format!("http://127.0.0.1:{}", mint_addr.port());
    let mint_router = build_router(mint_helper.mint()).await.unwrap();
    let (mint_shutdown_tx, mint_shutdown_rx) = tokio::sync::oneshot::channel();
    tokio::spawn(async move {
        axum::serve(mint_listener, mint_router)
            .with_graceful_shutdown(async {
                let _ = mint_shutdown_rx.await;
            })
            .await
            .unwrap();
    });

    let keyset_id = mint_helper.keyset_id().to_string();
    let keyset_info_json = mint_helper.keyset_info_json().unwrap();
    let mint_cache = mint_cache_with_keyset(&mint_url, "sat", &keyset_id, &keyset_info_json, true);
    let trusted_mint_units =
        BTreeMap::from([(mint_url.clone(), BTreeSet::from(["sat".to_string()]))]);
    let temp_db = tempfile::NamedTempFile::new().unwrap();
    let wallet_manager = RelayWalletManager::open(temp_db.path().to_str().unwrap()).unwrap();
    let receiver_secret = cashu::nuts::SecretKey::generate();
    let receiver_pubkey_hex = receiver_secret.public_key().to_hex();
    wallet_manager
        .register_identity("drain-recovery-relay", receiver_secret)
        .unwrap();
    wallet_manager.install_keyset_cache(mint_cache.clone());
    let payments = wallet_manager
        .spilman_payments_for("drain-recovery-relay", mint_cache, trusted_mint_units)
        .unwrap();
    let wallet = TestSigningWallet::new(
        mint_helper.mint(),
        receiver_pubkey_hex.clone(),
        mint_url.clone(),
        keyset_id.clone(),
        keyset_info_json,
    )
    .await;
    let offer = RelayPaymentOffer {
        receiver_pubkey: receiver_pubkey_hex,
        mint_url: mint_url.clone(),
        unit: "sat".to_string(),
        accepted_keyset_ids: vec![keyset_id],
        in_bytes_per_millisat: 1,
        out_bytes_per_millisat: 1,
    };

    let channel_id =
        create_paid_closed_channel(&wallet_manager, &payments, &wallet, &offer, [3u8; 32], 400)
            .await;

    let net = wallet_manager
        .reqwest_networking_for_channel(&channel_id)
        .unwrap();
    let dropped = DropAfterSwap { inner: &net };
    let err = wallet_manager
        .drain_closed_channels_to_swap("drain-recovery-relay", &mint_url, "sat", &dropped, None)
        .await
        .unwrap_err();
    assert!(err.contains("submitted"));

    let drains = wallet_manager.list_drains().unwrap();
    assert_eq!(drains.len(), 1);
    assert_eq!(drains[0].state, "Submitted");
    let drain_id = drains[0].drain_id.clone();

    let reserved = wallet_manager
        .drain_closed_channels_to_swap("drain-recovery-relay", &mint_url, "sat", &net, None)
        .await
        .unwrap_err();
    assert!(reserved.contains("no closed channels"));

    let recovered = wallet_manager
        .recover_submitted_drain(&drain_id, &net)
        .await
        .expect("submitted drain should recover via restore");
    assert!(recovered.recovered);
    assert_eq!(recovered.input_amount_raw, 400);
    assert_eq!(recovered.output_amount_raw, 400);
    assert_eq!(sum_proof_amounts(&recovered.output_proofs_json), 400);
    assert_eq!(recovered.channel_ids, vec![channel_id]);
    assert_eq!(wallet_manager.list_drains().unwrap()[0].state, "Completed");

    let _ = mint_shutdown_tx.send(());
}

#[tokio::test(flavor = "multi_thread")]
async fn test_wallet_manager_drain_swap_limit_selects_subset() {
    let ctx = DrainTestContext::new("drain-limit-relay").await;
    let ch1 = ctx.create_closed_channel([10u8; 32], 100).await;
    let ch2 = ctx.create_closed_channel([11u8; 32], 200).await;
    let ch3 = ctx.create_closed_channel([12u8; 32], 300).await;
    let net = ctx.net_for(&ch1);

    let first = ctx
        .wallet_manager
        .drain_closed_channels_to_swap("drain-limit-relay", &ctx.mint_url, "sat", &net, Some(2))
        .await
        .unwrap();
    assert_eq!(first.channel_ids.len(), 2);

    let second = ctx
        .wallet_manager
        .drain_closed_channels_to_swap("drain-limit-relay", &ctx.mint_url, "sat", &net, None)
        .await
        .unwrap();
    assert_eq!(second.channel_ids.len(), 1);
    assert_eq!(first.input_amount_raw + second.input_amount_raw, 600);
    let drained = first
        .channel_ids
        .into_iter()
        .chain(second.channel_ids)
        .collect::<BTreeSet<_>>();
    assert_eq!(drained, BTreeSet::from([ch1, ch2, ch3]));
    ctx.shutdown();
}

#[tokio::test(flavor = "multi_thread")]
async fn test_wallet_manager_drain_swap_filters_by_mint_and_unit() {
    let ctx = DrainTestContext::new("drain-filter-relay").await;
    let channel_id = ctx.create_closed_channel([13u8; 32], 250).await;
    let net = ctx.net_for(&channel_id);

    let wrong_mint = ctx
        .wallet_manager
        .drain_closed_channels_to_swap(
            "drain-filter-relay",
            "http://127.0.0.1:1",
            "sat",
            &net,
            None,
        )
        .await
        .unwrap_err();
    assert!(wrong_mint.contains("no closed channels"));
    let wrong_unit = ctx
        .wallet_manager
        .drain_closed_channels_to_swap("drain-filter-relay", &ctx.mint_url, "msat", &net, None)
        .await
        .unwrap_err();
    assert!(wrong_unit.contains("no closed channels"));
    assert!(ctx.wallet_manager.list_drains().unwrap().is_empty());

    let drain = ctx
        .wallet_manager
        .drain_closed_channels_to_swap("drain-filter-relay", &ctx.mint_url, "sat", &net, None)
        .await
        .unwrap();
    assert_eq!(drain.channel_ids, vec![channel_id]);
    assert_eq!(drain.input_amount_raw, 250);
    ctx.shutdown();
}

#[tokio::test(flavor = "multi_thread")]
async fn test_wallet_manager_drain_swap_ignores_non_closed_channels() {
    let ctx = DrainTestContext::new("drain-open-relay").await;
    let channel_id = ctx.wallet.pre_create_channel(1000).await.unwrap();
    ctx.wallet
        .attach_channel_to_session(&channel_id, [14u8; 32])
        .unwrap();
    let link_json = ctx
        .wallet
        .build_link_request(&channel_id, &ctx.offer)
        .unwrap();
    ctx.payments.link_channel([14u8; 32], &link_json).unwrap();
    let payment_json = ctx
        .wallet
        .build_channel_payment(&channel_id, &ctx.offer, 0, 100)
        .unwrap();
    ctx.payments
        .apply_channel_payment(&channel_id, &payment_json)
        .unwrap();

    let net = ctx.net_for(&channel_id);
    let err = ctx
        .wallet_manager
        .drain_closed_channels_to_swap("drain-open-relay", &ctx.mint_url, "sat", &net, None)
        .await
        .unwrap_err();
    assert!(err.contains("no closed channels"));
    assert!(ctx.wallet_manager.list_drains().unwrap().is_empty());
    ctx.shutdown();
}

#[tokio::test(flavor = "multi_thread")]
async fn test_wallet_manager_recover_completed_drain_is_idempotent() {
    let ctx = DrainTestContext::new("drain-idempotent-relay").await;
    let channel_id = ctx.create_closed_channel([15u8; 32], 350).await;
    let net = ctx.net_for(&channel_id);
    let drain = ctx
        .wallet_manager
        .drain_closed_channels_to_swap("drain-idempotent-relay", &ctx.mint_url, "sat", &net, None)
        .await
        .unwrap();

    let recovered = ctx
        .wallet_manager
        .recover_submitted_drain(&drain.drain_id, &net)
        .await
        .unwrap();
    assert!(!recovered.recovered);
    assert_eq!(recovered.output_proofs_json, drain.output_proofs_json);
    assert_eq!(recovered.channel_ids, drain.channel_ids);
    assert_eq!(
        ctx.wallet_manager.list_drains().unwrap()[0].state,
        "Completed"
    );
    ctx.shutdown();
}

#[tokio::test(flavor = "multi_thread")]
async fn test_wallet_manager_recover_missing_drain_errors() {
    let ctx = DrainTestContext::new("drain-missing-relay").await;
    let err = ctx
        .wallet_manager
        .recover_submitted_drain("missing-drain", &RejectSwap)
        .await
        .unwrap_err();
    assert!(err.contains("not found"));
    ctx.shutdown();
}

#[tokio::test(flavor = "multi_thread")]
async fn test_wallet_manager_drain_recovery_survives_manager_reopen() {
    let ctx = DrainTestContext::new("drain-reopen-relay").await;
    let channel_id = ctx.create_closed_channel([16u8; 32], 450).await;
    let db_path = ctx._temp_db.path().to_str().unwrap().to_string();
    let net = ctx.net_for(&channel_id);
    let dropped = DropAfterSwap { inner: &net };
    let err = ctx
        .wallet_manager
        .drain_closed_channels_to_swap("drain-reopen-relay", &ctx.mint_url, "sat", &dropped, None)
        .await
        .unwrap_err();
    assert!(err.contains("submitted"));
    let drain_id = ctx.wallet_manager.list_drains().unwrap()[0]
        .drain_id
        .clone();

    let reopened = RelayWalletManager::open(&db_path).unwrap();
    let reopened_net = reopened
        .reqwest_networking_for_channel(&channel_id)
        .unwrap();
    let recovered = reopened
        .recover_submitted_drain(&drain_id, &reopened_net)
        .await
        .unwrap();
    assert!(recovered.recovered);
    assert_eq!(recovered.input_amount_raw, 450);
    assert_eq!(sum_proof_amounts(&recovered.output_proofs_json), 450);
    assert_eq!(reopened.list_drains().unwrap()[0].state, "Completed");
    ctx.shutdown();
}

#[tokio::test(flavor = "multi_thread")]
async fn test_wallet_manager_drain_explicit_mint_rejection_marks_failed_and_releases_channels() {
    let ctx = DrainTestContext::new("drain-failed-relay").await;
    let channel_id = ctx.create_closed_channel([17u8; 32], 275).await;
    let err = ctx
        .wallet_manager
        .drain_closed_channels_to_swap(
            "drain-failed-relay",
            &ctx.mint_url,
            "sat",
            &RejectSwap,
            None,
        )
        .await
        .unwrap_err();
    assert!(err.contains("failed"));
    let drains = ctx.wallet_manager.list_drains().unwrap();
    assert_eq!(drains.len(), 1);
    assert_eq!(drains[0].state, "Failed");

    let net = ctx.net_for(&channel_id);
    let retry = ctx
        .wallet_manager
        .drain_closed_channels_to_swap("drain-failed-relay", &ctx.mint_url, "sat", &net, None)
        .await
        .unwrap();
    assert_eq!(retry.channel_ids, vec![channel_id]);
    assert_eq!(retry.input_amount_raw, 275);
    let states = ctx
        .wallet_manager
        .list_drains()
        .unwrap()
        .into_iter()
        .map(|d| d.state)
        .collect::<BTreeSet<_>>();
    assert_eq!(
        states,
        BTreeSet::from(["Completed".to_string(), "Failed".to_string()])
    );
    ctx.shutdown();
}

#[tokio::test(flavor = "multi_thread")]
async fn test_wallet_manager_drain_keyset_rejection_refreshes_reprepares_and_retries_same_drain() {
    let mint_helper = TestMintHelper::new().await.unwrap();
    let mint = mint_helper.mint();
    let mint_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let mint_addr = mint_listener.local_addr().unwrap();
    let mint_url = format!("http://127.0.0.1:{}", mint_addr.port());
    let mint_router = build_router(mint.clone()).await.unwrap();
    let (mint_shutdown_tx, mint_shutdown_rx) = tokio::sync::oneshot::channel();
    tokio::spawn(async move {
        axum::serve(mint_listener, mint_router)
            .with_graceful_shutdown(async {
                let _ = mint_shutdown_rx.await;
            })
            .await
            .unwrap();
    });

    let old_keyset_id = mint_helper.keyset_id().to_string();
    let old_keyset_info_json = mint_helper.keyset_info_json().unwrap();
    let old_mint_cache = mint_cache_with_keyset(
        &mint_url,
        "sat",
        &old_keyset_id,
        &old_keyset_info_json,
        true,
    );
    let trusted_mint_units =
        BTreeMap::from([(mint_url.clone(), BTreeSet::from(["sat".to_string()]))]);
    let temp_db = tempfile::NamedTempFile::new().unwrap();
    let wallet_manager = RelayWalletManager::open(temp_db.path().to_str().unwrap()).unwrap();
    let receiver_secret = cashu::nuts::SecretKey::generate();
    let receiver_pubkey_hex = receiver_secret.public_key().to_hex();
    wallet_manager
        .register_identity("drain-keyset-retry-relay", receiver_secret)
        .unwrap();
    wallet_manager.install_keyset_cache(old_mint_cache.clone());
    let payments = wallet_manager
        .spilman_payments_for(
            "drain-keyset-retry-relay",
            old_mint_cache,
            trusted_mint_units,
        )
        .unwrap();
    let wallet = TestSigningWallet::new(
        mint.clone(),
        receiver_pubkey_hex.clone(),
        mint_url.clone(),
        old_keyset_id.clone(),
        old_keyset_info_json,
    )
    .await;
    let offer = RelayPaymentOffer {
        receiver_pubkey: receiver_pubkey_hex,
        mint_url: mint_url.clone(),
        unit: "sat".to_string(),
        accepted_keyset_ids: vec![old_keyset_id.clone()],
        in_bytes_per_millisat: 1,
        out_bytes_per_millisat: 1,
    };
    let channel_id =
        create_paid_closed_channel(&wallet_manager, &payments, &wallet, &offer, [21u8; 32], 300)
            .await;

    let new_keyset_id = rotate_sat_keyset(&mint, 500).await.unwrap().to_string();
    assert_ne!(old_keyset_id, new_keyset_id);
    let net = wallet_manager
        .reqwest_networking_for_channel(&channel_id)
        .unwrap();
    let swaps = Arc::new(AtomicUsize::new(0));
    let output_keysets_by_call = Arc::new(Mutex::new(Vec::new()));
    let counting = CountingDrainNet {
        inner: &net,
        swaps: swaps.clone(),
        output_keysets_by_call: output_keysets_by_call.clone(),
    };
    let drain = wallet_manager
        .drain_closed_channels_to_swap(
            "drain-keyset-retry-relay",
            &mint_url,
            "sat",
            &counting,
            None,
        )
        .await
        .expect("stale drain output keyset should refresh and retry");
    assert_eq!(swaps.load(Ordering::SeqCst), 2);
    let output_keysets_by_call = output_keysets_by_call.lock().unwrap().clone();
    assert_eq!(output_keysets_by_call.len(), 2);
    assert!(output_keysets_by_call[0].contains(&old_keyset_id));
    assert!(output_keysets_by_call[1].contains(&new_keyset_id));
    assert_eq!(wallet_manager.list_drains().unwrap().len(), 1);
    assert_eq!(wallet_manager.list_drains().unwrap()[0].state, "Completed");
    assert_eq!(drain.channel_ids, vec![channel_id]);
    let output_proofs: Vec<cashu::nuts::Proof> =
        serde_json::from_str(&drain.output_proofs_json).unwrap();
    assert!(output_proofs
        .iter()
        .all(|proof| proof.keyset_id.to_string() == new_keyset_id));

    let _ = mint_shutdown_tx.send(());
}

#[tokio::test(flavor = "multi_thread")]
async fn test_wallet_manager_drain_keyset_rejection_unchanged_keyset_marks_failed_and_releases() {
    let ctx = DrainTestContext::new("drain-keyset-retry-failed-relay").await;
    let channel_id = ctx.create_closed_channel([22u8; 32], 275).await;
    let scripted = KeysetThenRejectSwap {
        swaps: AtomicUsize::new(0),
    };
    let err = ctx
        .wallet_manager
        .drain_closed_channels_to_swap(
            "drain-keyset-retry-failed-relay",
            &ctx.mint_url,
            "sat",
            &scripted,
            None,
        )
        .await
        .unwrap_err();
    assert!(err.contains("failed"));
    assert!(err.contains("retry keyset unchanged after refresh"));
    assert_eq!(scripted.swaps.load(Ordering::SeqCst), 1);
    let drains = ctx.wallet_manager.list_drains().unwrap();
    assert_eq!(drains.len(), 1);
    assert_eq!(drains[0].state, "Failed");

    let net = ctx.net_for(&channel_id);
    let retry = ctx
        .wallet_manager
        .drain_closed_channels_to_swap(
            "drain-keyset-retry-failed-relay",
            &ctx.mint_url,
            "sat",
            &net,
            None,
        )
        .await
        .unwrap();
    assert_eq!(retry.channel_ids, vec![channel_id]);
    let states = ctx
        .wallet_manager
        .list_drains()
        .unwrap()
        .into_iter()
        .map(|d| d.state)
        .collect::<BTreeSet<_>>();
    assert_eq!(
        states,
        BTreeSet::from(["Completed".to_string(), "Failed".to_string()])
    );
    ctx.shutdown();
}

#[tokio::test(flavor = "multi_thread")]
async fn test_wallet_manager_drain_repeated_keyset_rejection_skips_retry_when_keyset_unchanged() {
    let ctx = DrainTestContext::new("drain-keyset-retry-once-relay").await;
    let channel_id = ctx.create_closed_channel([23u8; 32], 275).await;
    let scripted = AlwaysKeysetRejectSwap {
        swaps: AtomicUsize::new(0),
    };
    let err = ctx
        .wallet_manager
        .drain_closed_channels_to_swap(
            "drain-keyset-retry-once-relay",
            &ctx.mint_url,
            "sat",
            &scripted,
            None,
        )
        .await
        .unwrap_err();
    assert!(err.contains("failed"));
    assert!(err.contains("retry keyset unchanged after refresh"));
    assert_eq!(scripted.swaps.load(Ordering::SeqCst), 1);
    let drains = ctx.wallet_manager.list_drains().unwrap();
    assert_eq!(drains.len(), 1);
    assert_eq!(drains[0].state, "Failed");

    let net = ctx.net_for(&channel_id);
    let retry = ctx
        .wallet_manager
        .drain_closed_channels_to_swap(
            "drain-keyset-retry-once-relay",
            &ctx.mint_url,
            "sat",
            &net,
            None,
        )
        .await
        .unwrap();
    assert_eq!(retry.channel_ids, vec![channel_id]);
    ctx.shutdown();
}

#[tokio::test(flavor = "multi_thread")]
async fn test_wallet_manager_drain_retry_refresh_failure_marks_failed_and_releases() {
    let ctx = DrainTestContext::new("drain-refresh-failed-relay").await;
    let channel_id = ctx.create_closed_channel([26u8; 32], 275).await;
    let db_path = ctx._temp_db.path().to_str().unwrap().to_string();
    let bad_mint_url = "http://127.0.0.1:1";

    let conn = rusqlite::Connection::open(&db_path).unwrap();
    let original_funding_json: String = conn
        .query_row(
            "SELECT funding_json FROM spilman_channels WHERE channel_id = ?1",
            rusqlite::params![channel_id],
            |row| row.get(0),
        )
        .unwrap();
    let mut funding_value: serde_json::Value =
        serde_json::from_str(&original_funding_json).unwrap();
    let mut params_value: serde_json::Value = serde_json::from_str(
        funding_value["params_json"]
            .as_str()
            .expect("funding params json"),
    )
    .unwrap();
    params_value["mint"] = serde_json::Value::String(bad_mint_url.to_string());
    funding_value["params_json"] = serde_json::Value::String(params_value.to_string());
    conn.execute(
        "UPDATE spilman_channels SET funding_json = ?2 WHERE channel_id = ?1",
        rusqlite::params![channel_id, funding_value.to_string()],
    )
    .unwrap();
    drop(conn);

    let stale_cache = ctx.wallet_manager.keyset_cache_snapshot();
    let old_keyset_id = ctx.offer.accepted_keyset_ids[0].clone();
    let old_keyset = stale_cache
        .keysets
        .get(&ctx.mint_url)
        .and_then(|by_id| by_id.get(&old_keyset_id))
        .expect("old keyset cached")
        .clone();
    let retry_manager = RelayWalletManager::open(&db_path).unwrap();
    retry_manager.install_keyset_cache(SpilmanMintCache {
        advertised: BTreeMap::from([(
            bad_mint_url.to_string(),
            BTreeMap::from([("sat".to_string(), vec![old_keyset_id.clone()])]),
        )]),
        keysets: BTreeMap::from([(
            bad_mint_url.to_string(),
            BTreeMap::from([(old_keyset_id, old_keyset)]),
        )]),
    });

    let scripted = AlwaysKeysetRejectSwap {
        swaps: AtomicUsize::new(0),
    };
    let err = retry_manager
        .drain_closed_channels_to_swap(
            "drain-refresh-failed-relay",
            bad_mint_url,
            "sat",
            &scripted,
            None,
        )
        .await
        .unwrap_err();
    assert!(err.contains("refresh keysets after keyset rejection"));
    assert_eq!(scripted.swaps.load(Ordering::SeqCst), 1);
    let drains = retry_manager.list_drains().unwrap();
    assert_eq!(drains.len(), 1);
    assert_eq!(drains[0].state, "Failed");

    let conn = rusqlite::Connection::open(&db_path).unwrap();
    conn.execute(
        "UPDATE spilman_channels SET funding_json = ?2 WHERE channel_id = ?1",
        rusqlite::params![channel_id, original_funding_json],
    )
    .unwrap();
    drop(conn);

    let net = ctx.net_for(&channel_id);
    let retry = ctx
        .wallet_manager
        .drain_closed_channels_to_swap(
            "drain-refresh-failed-relay",
            &ctx.mint_url,
            "sat",
            &net,
            None,
        )
        .await
        .unwrap();
    assert_eq!(retry.channel_ids, vec![channel_id]);
    ctx.shutdown();
}

#[tokio::test(flavor = "multi_thread")]
async fn test_wallet_manager_drain_preparation_failure_does_not_reserve_channels() {
    let ctx = DrainTestContext::new("drain-invalid-relay").await;
    let channel_id = ctx.create_closed_channel([18u8; 32], 325).await;
    let db_path = ctx._temp_db.path().to_str().unwrap();
    let conn = rusqlite::Connection::open(db_path).unwrap();
    let original_closed_json: String = conn
        .query_row(
            "SELECT closed_json FROM spilman_channels WHERE channel_id = ?1",
            rusqlite::params![channel_id],
            |row| row.get(0),
        )
        .unwrap();
    let mut closed_value: serde_json::Value = serde_json::from_str(&original_closed_json).unwrap();
    closed_value["receiver_proofs_json"] = serde_json::Value::String("[]".to_string());
    conn.execute(
        "UPDATE spilman_channels SET closed_json = ?2 WHERE channel_id = ?1",
        rusqlite::params![channel_id, closed_value.to_string()],
    )
    .unwrap();

    let net = ctx.net_for(&channel_id);
    let err = ctx
        .wallet_manager
        .drain_closed_channels_to_swap("drain-invalid-relay", &ctx.mint_url, "sat", &net, None)
        .await
        .unwrap_err();
    assert!(err.contains("no receiver proofs"));
    assert!(ctx.wallet_manager.list_drains().unwrap().is_empty());

    conn.execute(
        "UPDATE spilman_channels SET closed_json = ?2 WHERE channel_id = ?1",
        rusqlite::params![channel_id, original_closed_json],
    )
    .unwrap();
    let drain = ctx
        .wallet_manager
        .drain_closed_channels_to_swap("drain-invalid-relay", &ctx.mint_url, "sat", &net, None)
        .await
        .unwrap();
    assert_eq!(drain.channel_ids, vec![channel_id]);
    assert_eq!(drain.input_amount_raw, 325);
    ctx.shutdown();
}

#[tokio::test(flavor = "multi_thread")]
async fn test_wallet_manager_drain_swap_combines_closed_channels_from_different_keysets() {
    let mint_helper = TestMintHelper::new().await.unwrap();
    let mint = mint_helper.mint();
    let mint_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let mint_addr = mint_listener.local_addr().unwrap();
    let mint_url = format!("http://127.0.0.1:{}", mint_addr.port());
    let mint_router = build_router(mint.clone()).await.unwrap();
    let (mint_shutdown_tx, mint_shutdown_rx) = tokio::sync::oneshot::channel();
    tokio::spawn(async move {
        axum::serve(mint_listener, mint_router)
            .with_graceful_shutdown(async {
                let _ = mint_shutdown_rx.await;
            })
            .await
            .unwrap();
    });

    let old_keyset_id = mint_helper.keyset_id().to_string();
    let old_keyset_info_json = mint_helper.keyset_info_json().unwrap();
    let trusted_mint_units =
        BTreeMap::from([(mint_url.clone(), BTreeSet::from(["sat".to_string()]))]);
    let receiver_secret = cashu::nuts::SecretKey::generate();
    let receiver_pubkey_hex = receiver_secret.public_key().to_hex();
    let temp_db = tempfile::NamedTempFile::new().unwrap();
    let wallet_manager = RelayWalletManager::open(temp_db.path().to_str().unwrap()).unwrap();
    wallet_manager
        .register_identity("mixed-keyset-drain-relay", receiver_secret)
        .unwrap();

    let old_mint_cache = mint_cache_with_keyset(
        &mint_url,
        "sat",
        &old_keyset_id,
        &old_keyset_info_json,
        true,
    );
    let old_payments = wallet_manager
        .spilman_payments_for(
            "mixed-keyset-drain-relay",
            old_mint_cache,
            trusted_mint_units.clone(),
        )
        .unwrap();
    let old_wallet = TestSigningWallet::new(
        mint.clone(),
        receiver_pubkey_hex.clone(),
        mint_url.clone(),
        old_keyset_id.clone(),
        old_keyset_info_json,
    )
    .await;
    let old_offer = RelayPaymentOffer {
        receiver_pubkey: receiver_pubkey_hex.clone(),
        mint_url: mint_url.clone(),
        unit: "sat".to_string(),
        accepted_keyset_ids: vec![old_keyset_id.clone()],
        in_bytes_per_millisat: 1,
        out_bytes_per_millisat: 1,
    };
    let old_channel = create_paid_closed_channel(
        &wallet_manager,
        &old_payments,
        &old_wallet,
        &old_offer,
        [19u8; 32],
        300,
    )
    .await;

    let new_keyset_id = rotate_sat_keyset(&mint, 400).await.unwrap().to_string();
    assert_ne!(old_keyset_id, new_keyset_id);
    let client_bridge = SpilmanClientBridge::new(
        ConfigurableClientHost::new_in_memory(),
        InMemoryMintNetworking::new(mint.clone()),
    );
    let new_keyset_info_json = client_bridge
        .fetch_keyset_info(&mint_url, &new_keyset_id)
        .expect("fetch rotated keyset info");
    let new_mint_cache = mint_cache_with_keyset(
        &mint_url,
        "sat",
        &new_keyset_id,
        &new_keyset_info_json,
        true,
    );
    let new_payments = wallet_manager
        .spilman_payments_for(
            "mixed-keyset-drain-relay",
            new_mint_cache,
            trusted_mint_units.clone(),
        )
        .unwrap();
    let new_wallet = TestSigningWallet::new(
        mint.clone(),
        receiver_pubkey_hex.clone(),
        mint_url.clone(),
        new_keyset_id.clone(),
        new_keyset_info_json,
    )
    .await;
    let new_offer = RelayPaymentOffer {
        receiver_pubkey: receiver_pubkey_hex,
        mint_url: mint_url.clone(),
        unit: "sat".to_string(),
        accepted_keyset_ids: vec![new_keyset_id.clone()],
        in_bytes_per_millisat: 1,
        out_bytes_per_millisat: 1,
    };
    let new_channel = create_paid_closed_channel(
        &wallet_manager,
        &new_payments,
        &new_wallet,
        &new_offer,
        [20u8; 32],
        200,
    )
    .await;

    let old_closed = old_payments
        .closed_data(&old_channel)
        .expect("old channel closed data");
    let new_closed = new_payments
        .closed_data(&new_channel)
        .expect("new channel closed data");
    let expected_input = old_closed.receiver_sum + new_closed.receiver_sum;
    let expected_fee = mixed_input_fee_for_proofs(
        &mint_url,
        &[
            &old_closed.receiver_proofs_json,
            &new_closed.receiver_proofs_json,
        ],
    )
    .await;
    let expected_output = expected_input - expected_fee;
    wallet_manager
        .refresh_trusted_mint_cache(&trusted_mint_units)
        .await
        .expect("seed shared drain cache with rotated keysets");

    let net = wallet_manager
        .reqwest_networking_for_channel(&old_channel)
        .unwrap();
    let drain = wallet_manager
        .drain_closed_channels_to_swap("mixed-keyset-drain-relay", &mint_url, "sat", &net, None)
        .await
        .expect("mixed-keyset closed channels should drain together");
    assert_eq!(drain.input_amount_raw, expected_input);
    assert_eq!(drain.output_amount_raw, expected_output);
    assert_eq!(
        sum_proof_amounts(&drain.output_proofs_json),
        expected_output
    );
    assert_eq!(
        BTreeSet::from_iter(drain.channel_ids.iter().cloned()),
        BTreeSet::from([old_channel, new_channel])
    );

    let output_proofs: Vec<cashu::nuts::Proof> =
        serde_json::from_str(&drain.output_proofs_json).unwrap();
    assert!(output_proofs
        .iter()
        .all(|proof| proof.keyset_id.to_string() == new_keyset_id));

    let storage = SqliteStorage::open(temp_db.path().to_str().unwrap()).unwrap();
    let old_cached = storage
        .get_keyset(&mint_url, &old_keyset_id.parse().unwrap())
        .expect("old keyset should be cached");
    let new_cached = storage
        .get_keyset(&mint_url, &new_keyset_id.parse().unwrap())
        .expect("new keyset should be cached");
    assert!(!old_cached.active);
    assert!(new_cached.active);

    let _ = mint_shutdown_tx.send(());
}

#[tokio::test(flavor = "multi_thread")]
async fn test_wallet_manager_drain_mixed_keysets_stale_output_cache_refreshes_and_retries() {
    let mint_helper = TestMintHelper::new().await.unwrap();
    let mint = mint_helper.mint();
    let mint_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let mint_addr = mint_listener.local_addr().unwrap();
    let mint_url = format!("http://127.0.0.1:{}", mint_addr.port());
    let mint_router = build_router(mint.clone()).await.unwrap();
    let (mint_shutdown_tx, mint_shutdown_rx) = tokio::sync::oneshot::channel();
    tokio::spawn(async move {
        axum::serve(mint_listener, mint_router)
            .with_graceful_shutdown(async {
                let _ = mint_shutdown_rx.await;
            })
            .await
            .unwrap();
    });

    let old_keyset_id = mint_helper.keyset_id().to_string();
    let old_keyset_info_json = mint_helper.keyset_info_json().unwrap();
    let trusted_mint_units =
        BTreeMap::from([(mint_url.clone(), BTreeSet::from(["sat".to_string()]))]);
    let receiver_secret = cashu::nuts::SecretKey::generate();
    let receiver_pubkey_hex = receiver_secret.public_key().to_hex();
    let temp_db = tempfile::NamedTempFile::new().unwrap();
    let wallet_manager = RelayWalletManager::open(temp_db.path().to_str().unwrap()).unwrap();
    wallet_manager
        .register_identity("mixed-keyset-stale-drain-relay", receiver_secret)
        .unwrap();

    let old_mint_cache = mint_cache_with_keyset(
        &mint_url,
        "sat",
        &old_keyset_id,
        &old_keyset_info_json,
        true,
    );
    let old_payments = wallet_manager
        .spilman_payments_for(
            "mixed-keyset-stale-drain-relay",
            old_mint_cache.clone(),
            trusted_mint_units.clone(),
        )
        .unwrap();
    let old_wallet = TestSigningWallet::new(
        mint.clone(),
        receiver_pubkey_hex.clone(),
        mint_url.clone(),
        old_keyset_id.clone(),
        old_keyset_info_json.clone(),
    )
    .await;
    let old_offer = RelayPaymentOffer {
        receiver_pubkey: receiver_pubkey_hex.clone(),
        mint_url: mint_url.clone(),
        unit: "sat".to_string(),
        accepted_keyset_ids: vec![old_keyset_id.clone()],
        in_bytes_per_millisat: 1,
        out_bytes_per_millisat: 1,
    };
    let old_channel = create_paid_closed_channel(
        &wallet_manager,
        &old_payments,
        &old_wallet,
        &old_offer,
        [24u8; 32],
        300,
    )
    .await;

    let new_keyset_id = rotate_sat_keyset(&mint, 600).await.unwrap().to_string();
    let client_bridge = SpilmanClientBridge::new(
        ConfigurableClientHost::new_in_memory(),
        InMemoryMintNetworking::new(mint.clone()),
    );
    let new_keyset_info_json = client_bridge
        .fetch_keyset_info(&mint_url, &new_keyset_id)
        .expect("fetch rotated keyset info");
    let new_mint_cache = mint_cache_with_keyset(
        &mint_url,
        "sat",
        &new_keyset_id,
        &new_keyset_info_json,
        true,
    );
    let new_payments = wallet_manager
        .spilman_payments_for(
            "mixed-keyset-stale-drain-relay",
            new_mint_cache,
            trusted_mint_units,
        )
        .unwrap();
    let new_wallet = TestSigningWallet::new(
        mint.clone(),
        receiver_pubkey_hex.clone(),
        mint_url.clone(),
        new_keyset_id.clone(),
        new_keyset_info_json.clone(),
    )
    .await;
    let new_offer = RelayPaymentOffer {
        receiver_pubkey: receiver_pubkey_hex,
        mint_url: mint_url.clone(),
        unit: "sat".to_string(),
        accepted_keyset_ids: vec![new_keyset_id.clone()],
        in_bytes_per_millisat: 1,
        out_bytes_per_millisat: 1,
    };
    let new_channel = create_paid_closed_channel(
        &wallet_manager,
        &new_payments,
        &new_wallet,
        &new_offer,
        [25u8; 32],
        200,
    )
    .await;

    let old_closed = old_payments
        .closed_data(&old_channel)
        .expect("old channel closed data");
    let new_closed = new_payments
        .closed_data(&new_channel)
        .expect("new channel closed data");
    let expected_input = old_closed.receiver_sum + new_closed.receiver_sum;
    let expected_fee = mixed_input_fee_for_proofs(
        &mint_url,
        &[
            &old_closed.receiver_proofs_json,
            &new_closed.receiver_proofs_json,
        ],
    )
    .await;
    let expected_output = expected_input - expected_fee;

    let mut stale_cache = old_mint_cache;
    stale_cache
        .advertised
        .get_mut(&mint_url)
        .unwrap()
        .get_mut("sat")
        .unwrap()
        .push(new_keyset_id.clone());
    stale_cache.keysets.get_mut(&mint_url).unwrap().insert(
        new_keyset_id.clone(),
        CachedKeyset {
            unit: "sat".to_string(),
            active: false,
            input_fee_ppk: keyset_info_input_fee_ppk(&new_keyset_info_json),
            info_json: new_keyset_info_json,
        },
    );
    wallet_manager.install_keyset_cache(stale_cache);

    let net = wallet_manager
        .reqwest_networking_for_channel(&old_channel)
        .unwrap();
    let swaps = Arc::new(AtomicUsize::new(0));
    let output_keysets_by_call = Arc::new(Mutex::new(Vec::new()));
    let counting = CountingDrainNet {
        inner: &net,
        swaps: swaps.clone(),
        output_keysets_by_call: output_keysets_by_call.clone(),
    };
    let drain = wallet_manager
        .drain_closed_channels_to_swap(
            "mixed-keyset-stale-drain-relay",
            &mint_url,
            "sat",
            &counting,
            None,
        )
        .await
        .expect("mixed stale-cache drain should refresh and retry");
    assert_eq!(swaps.load(Ordering::SeqCst), 2);
    let output_keysets_by_call = output_keysets_by_call.lock().unwrap().clone();
    assert_eq!(output_keysets_by_call.len(), 2);
    assert!(output_keysets_by_call[0].contains(&old_keyset_id));
    assert!(output_keysets_by_call[1].contains(&new_keyset_id));
    assert_eq!(drain.input_amount_raw, expected_input);
    assert_eq!(drain.output_amount_raw, expected_output);
    assert_eq!(
        BTreeSet::from_iter(drain.channel_ids.iter().cloned()),
        BTreeSet::from([old_channel, new_channel])
    );
    let output_proofs: Vec<cashu::nuts::Proof> =
        serde_json::from_str(&drain.output_proofs_json).unwrap();
    assert!(output_proofs
        .iter()
        .all(|proof| proof.keyset_id.to_string() == new_keyset_id));

    let _ = mint_shutdown_tx.send(());
}

#[tokio::test(flavor = "multi_thread")]
async fn test_relay_startup_discovery_persists_keysets_to_sqlite_cache() {
    let mint_helper = TestMintHelper::new().await.unwrap();
    let mint = mint_helper.mint();
    let old_keyset_id = mint_helper.keyset_id().to_string();
    let new_keyset_id = rotate_sat_keyset(&mint, 250).await.unwrap().to_string();
    assert_ne!(old_keyset_id, new_keyset_id);

    let mint_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let mint_addr = mint_listener.local_addr().unwrap();
    let mint_url = format!("http://127.0.0.1:{}", mint_addr.port());
    let mint_router = build_router(mint).await.unwrap();
    let (mint_shutdown_tx, mint_shutdown_rx) = tokio::sync::oneshot::channel();
    tokio::spawn(async move {
        axum::serve(mint_listener, mint_router)
            .with_graceful_shutdown(async {
                let _ = mint_shutdown_rx.await;
            })
            .await
            .unwrap();
    });

    let temp_db = tempfile::NamedTempFile::new().unwrap();
    let storage = SqliteStorage::open(temp_db.path().to_str().unwrap()).unwrap();
    let trusted_mint_units =
        BTreeMap::from([(mint_url.clone(), BTreeSet::from(["sat".to_string()]))]);
    let cache = discover_spilman_mint_cache_with_storage(
        &trusted_mint_units,
        Some(&storage as &dyn SpilmanStorage),
    )
    .await
    .unwrap();

    assert!(cache
        .advertised
        .get(&mint_url)
        .and_then(|units| units.get("sat"))
        .is_some_and(|ids| ids.contains(&old_keyset_id) && ids.contains(&new_keyset_id)));
    let old_cached = storage
        .get_keyset(&mint_url, &old_keyset_id.parse().unwrap())
        .expect("startup discovery should cache old keyset");
    let new_cached = storage
        .get_keyset(&mint_url, &new_keyset_id.parse().unwrap())
        .expect("startup discovery should cache new keyset");
    assert!(!old_cached.active);
    assert!(new_cached.active);

    let _ = mint_shutdown_tx.send(());
}

#[tokio::test(flavor = "multi_thread")]
async fn test_session_status_reflects_manager_keyset_refresh_mid_session() {
    let mint_helper = TestMintHelper::new().await.unwrap();
    let mint = mint_helper.mint();
    let old_keyset_id = mint_helper.keyset_id().to_string();

    let mint_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let mint_addr = mint_listener.local_addr().unwrap();
    let mint_url = format!("http://127.0.0.1:{}", mint_addr.port());
    let mint_router = build_router(mint.clone()).await.unwrap();
    let (mint_shutdown_tx, mint_shutdown_rx) = tokio::sync::oneshot::channel();
    tokio::spawn(async move {
        axum::serve(mint_listener, mint_router)
            .with_graceful_shutdown(async {
                let _ = mint_shutdown_rx.await;
            })
            .await
            .unwrap();
    });

    let temp_db = tempfile::NamedTempFile::new().unwrap();
    let wallet_manager =
        Arc::new(RelayWalletManager::open(temp_db.path().to_str().unwrap()).unwrap());
    let receiver_secret = cashu::nuts::SecretKey::generate();
    let receiver_pubkey_hex = receiver_secret.public_key().to_hex();
    wallet_manager
        .register_identity("live-cache-relay", receiver_secret)
        .unwrap();
    let trusted_mint_units =
        BTreeMap::from([(mint_url.clone(), BTreeSet::from(["sat".to_string()]))]);
    let shared_cache = wallet_manager
        .refresh_trusted_mint_cache(&trusted_mint_units)
        .await
        .unwrap();

    let identity = QuicCertIdentity::generate().unwrap();
    let transport_key = SecpTransportKeypair::generate();
    let transport_pubkey = transport_key.pubkey();
    let quic_km = monad_quic::keygen::generate_from_seed(identity.seed()).unwrap();
    let quic_server_config =
        monad_quic::server::build_server_config(&quic_km.cert_pem, &quic_km.key_pem).unwrap();
    let (listener, quic_endpoint, server_addr) =
        bind_tcp_and_quic_on_same_port("127.0.0.1:0".parse().unwrap(), quic_server_config)
            .await
            .unwrap();
    let config = Arc::new(ServerConfig {
        identity,
        transport_key: Some(transport_key),
        receiver_pubkey_hex,
        trusted_mint_units: trusted_mint_units.clone(),
        in_bytes_per_millisat: 1,
        out_bytes_per_millisat: 1,
        bootstrap_capabilities: None,
        relay_wallet_name: "live-cache-relay".to_string(),
        spilman_storage_path: temp_db.path().to_str().unwrap().to_string(),
    });
    let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel();
    let payments = wallet_manager.payments_for("live-cache-relay").unwrap();
    let handle = tokio::spawn(run_with_payments_and_registry_and_shutdown(
        listener,
        Some(quic_endpoint),
        config,
        payments,
        shared_cache,
        Arc::new(SessionRegistry::new()),
        async {
            let _ = shutdown_rx.await;
        },
    ));

    let conn = connect_client_quic_secp(server_addr, &transport_pubkey).await;
    let mut control = ControlSessionHarness::open(&conn).await;
    let initial = control.handshake().await;
    let initial_sat = initial
        .advertisements
        .iter()
        .find(|ad| ad.mint_url == mint_url && ad.unit == "sat")
        .expect("initial sat advertisement");
    assert!(initial_sat.keyset_ids.contains(&old_keyset_id));

    let new_keyset_id = rotate_sat_keyset(&mint, 250).await.unwrap().to_string();
    assert_ne!(old_keyset_id, new_keyset_id);
    wallet_manager
        .refresh_trusted_mint_cache(&trusted_mint_units)
        .await
        .unwrap();

    let refreshed = control.get_status().await;
    let refreshed_sat = refreshed
        .advertisements
        .iter()
        .find(|ad| ad.mint_url == mint_url && ad.unit == "sat")
        .expect("refreshed sat advertisement");
    assert!(refreshed_sat.keyset_ids.contains(&old_keyset_id));
    assert!(refreshed_sat.keyset_ids.contains(&new_keyset_id));

    control.close().await;
    conn.shutdown().await;
    let _ = shutdown_tx.send(());
    let _ = mint_shutdown_tx.send(());
    handle.await.unwrap().unwrap();
}

#[tokio::test]
async fn test_session_status_reports_open_and_total_connect_counts() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let target_addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        loop {
            let Ok((_stream, _)) = listener.accept().await else {
                return;
            };
            tokio::spawn(async move {
                tokio::time::sleep(Duration::from_secs(60)).await;
            });
        }
    });

    let (server_addr, pubkey) = start_monad_relay().await;
    let conn = connect_client_quic_secp(server_addr, &pubkey).await;
    let (control_send, control_recv) = open_funded_control(&conn, TEST_SESSION_PAYMENT).await;
    let mut control = ControlSessionHarness {
        send: control_send,
        recv: control_recv,
    };

    let initial = control.get_status().await;
    assert_eq!(initial.open_connects, 0);
    assert_eq!(initial.total_connects, 0);

    let mut h2 = conn.clone_send_request().await;
    let target = format!("127.0.0.1:{}", target_addr.port());

    let (mut tunnel1_send, tunnel1_recv) = open_connect_tunnel(&mut h2, &target).await;
    let status1 = control.get_status().await;
    assert_eq!(status1.open_connects, 1);
    assert_eq!(status1.total_connects, 1);

    let (mut tunnel2_send, tunnel2_recv) = open_connect_tunnel(&mut h2, &target).await;
    let status2 = control.get_status().await;
    assert_eq!(status2.open_connects, 2);
    assert_eq!(status2.total_connects, 2);

    let _ = tunnel1_send.send_data(Bytes::new(), true);
    drop(tunnel1_send);
    drop(tunnel1_recv);
    timeout(Duration::from_secs(2), async {
        loop {
            let status = control.get_status().await;
            if status.open_connects == 1 && status.total_connects == 2 {
                break;
            }
        }
    })
    .await
    .expect("open CONNECT count should drop after first tunnel closes");

    let _ = tunnel2_send.send_data(Bytes::new(), true);
    drop(tunnel2_send);
    drop(tunnel2_recv);
    timeout(Duration::from_secs(2), async {
        loop {
            let status = control.get_status().await;
            if status.open_connects == 0 && status.total_connects == 2 {
                break;
            }
        }
    })
    .await
    .expect("open CONNECT count should drop to zero after all tunnels close");

    control.close().await;
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
    let mut conn = connect_route_hops(vec![
        cleartext_route_hop(t_addr.to_string(), t_pubkey, true),
        cleartext_route_hop(s_addr.to_string(), s_pubkey, true),
    ])
    .await;
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

    let mut conn = connect_route_hops(vec![
        cleartext_route_hop(t_addr.to_string(), t_pubkey, false),
        cleartext_route_hop(s_addr.to_string(), s_pubkey, false),
    ])
    .await;
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

    let mut conn = connect_route_hops(vec![
        cleartext_route_hop(a_addr.to_string(), a_pubkey, true),
        cleartext_route_hop(b_addr.to_string(), b_pubkey, true),
        cleartext_route_hop(c_addr.to_string(), c_pubkey, true),
    ])
    .await;
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

    let mut conn = connect_route_hops(vec![
        cleartext_route_hop(ipv4_hop_addr.to_string(), ipv4_hop_pubkey, true),
        cleartext_route_hop(ipv6_hop_addr.to_string(), ipv6_hop_pubkey, true),
    ])
    .await;
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
    let mut conn = connect_route_hops(vec![cleartext_route_hop(
        server_addr.to_string(),
        pubkey,
        true,
    )])
    .await;
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

    let mut conn = connect_route_hops(vec![
        cleartext_route_hop(first_addr.to_string(), first_pubkey, true),
        cleartext_route_hop(second_addr.to_string(), second_pubkey, true),
    ])
    .await;
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
async fn test_nested_blinded_quic_tunnel() {
    let upper_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let upper_addr = upper_listener.local_addr().unwrap();
    tokio::spawn(run_uppercase_server(upper_listener));

    let hidden_transport_key = SecpTransportKeypair::generate();
    let (hidden_addr, _hidden_pubkey) =
        start_monad_relay_with_transport_key(hidden_transport_key.clone()).await;

    let (intro_addr, intro_pubkey) = start_monad_relay().await;

    let descriptor = build_blinded_hop_descriptor(
        intro_pubkey.to_compressed_bytes(),
        &hidden_addr.to_string(),
        &hidden_transport_key,
    )
    .unwrap();

    let mut intro_conn = connect_client_quic_secp(intro_addr, &intro_pubkey).await;
    fund_session(&mut intro_conn, TEST_SESSION_PAYMENT).await;

    let mut hidden_conn = connect_nested_session_blinded(&intro_conn, &descriptor).await;
    fund_session(&mut hidden_conn, TEST_SESSION_PAYMENT).await;

    let mut h2 = hidden_conn.clone_send_request().await;
    let result = tunnel_roundtrip(&mut h2, &upper_addr.to_string(), b"nested blinded hello").await;
    assert_eq!(result, b"NESTED BLINDED HELLO");

    drop(h2);
    hidden_conn.shutdown().await;
    intro_conn.shutdown().await;
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
    let mut conn = connect_route_hops(vec![
        cleartext_route_hop(s_addr.to_string(), s_pubkey, true),
        cleartext_route_hop(format!("127.0.0.1:{}", t_addr.port()), t_pubkey, true),
    ])
    .await;
    fund_session(&mut conn, TEST_SESSION_PAYMENT).await;
    let mut h2 = conn.clone_send_request().await;

    let target = format!("127.0.0.1:{}", upper_addr.port());
    let result = tunnel_roundtrip(&mut h2, &target, b"connector quic hop").await;
    assert_eq!(result, b"CONNECTOR QUIC HOP");

    drop(h2);
    conn.shutdown().await;
}

#[tokio::test]
async fn test_connector_blinded_hop() {
    let upper_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let upper_addr = upper_listener.local_addr().unwrap();
    tokio::spawn(run_uppercase_server(upper_listener));

    let hidden_transport_key = SecpTransportKeypair::generate();
    let (hidden_addr, _hidden_pubkey) =
        start_monad_relay_with_transport_key(hidden_transport_key.clone()).await;
    let (intro_addr, intro_pubkey) = start_monad_relay().await;

    let descriptor = build_blinded_hop_descriptor(
        intro_pubkey.to_compressed_bytes(),
        &hidden_addr.to_string(),
        &hidden_transport_key,
    )
    .unwrap();

    let route = Route::new(vec![
        cleartext_route_hop(intro_addr.to_string(), intro_pubkey, true),
        RouteHop::Blinded {
            descriptor: descriptor.clone(),
        },
    ])
    .unwrap();
    let mut conn = connector::connect_route(&route).await.unwrap();
    fund_session(&mut conn, TEST_SESSION_PAYMENT).await;

    let mut h2 = conn.clone_send_request().await;
    let result = tunnel_roundtrip(&mut h2, &upper_addr.to_string(), b"connector blinded hop").await;
    assert_eq!(result, b"CONNECTOR BLINDED HOP");

    drop(h2);
    conn.shutdown().await;
}

#[tokio::test]
async fn test_connector_rejects_blinded_hop_when_relay_lacks_capability() {
    let hidden_transport_key = SecpTransportKeypair::generate();
    let (hidden_addr, _hidden_pubkey) =
        start_monad_relay_with_transport_key(hidden_transport_key.clone()).await;

    let mut capabilities = initial_server_capabilities();
    capabilities.blinded_connect_v1 = false;
    let (intro_addr, intro_pubkey) = start_monad_relay_with_transport_key_and_capabilities(
        SecpTransportKeypair::generate(),
        capabilities,
    )
    .await;

    let descriptor = build_blinded_hop_descriptor(
        intro_pubkey.to_compressed_bytes(),
        &hidden_addr.to_string(),
        &hidden_transport_key,
    )
    .unwrap();

    let route = Route::new(vec![
        cleartext_route_hop(intro_addr.to_string(), intro_pubkey, true),
        RouteHop::Blinded { descriptor },
    ])
    .unwrap();
    let err = match connector::connect_route(&route).await {
        Ok(_) => panic!("expected connector route to fail on missing blinded capability"),
        Err(err) => err,
    };
    assert_eq!(err.kind(), io::ErrorKind::Unsupported);
    assert!(err.to_string().contains("cannot forward"));
}

#[tokio::test]
async fn test_connector_stores_negotiated_cashu_spilman_protocol_version() {
    let (relay_addr, relay_pubkey) = start_monad_relay().await;

    let conn = connect_route_hops(vec![cleartext_route_hop(
        relay_addr.to_string(),
        relay_pubkey,
        true,
    )])
    .await;

    assert_eq!(
        conn.cashu_spilman_protocol_version().await.as_deref(),
        Some(CASHU_SPILMAN_PROTOCOL_VERSION_2026_03_20)
    );

    conn.shutdown().await;
}

#[tokio::test]
async fn test_bootstrap_negotiates_session_constant_pricing_policy() {
    let (relay_addr, relay_pubkey) = start_monad_relay().await;
    let mut stream = TcpStream::connect(relay_addr).await.unwrap();

    let (_, _, _, accept) = noise_secp256k1::handshake_initiator_with_pubkey_and_server_accept(
        &mut stream,
        relay_pubkey.to_compressed_bytes(),
    )
    .await
    .unwrap();

    assert_eq!(
        accept.pricing_policy.as_deref(),
        Some(PRICING_POLICY_SESSION_CONSTANT)
    );
}

#[tokio::test]
async fn test_bootstrap_rejects_client_without_mutual_pricing_policy() {
    let (relay_addr, relay_pubkey) = start_monad_relay().await;
    let mut stream = TcpStream::connect(relay_addr).await.unwrap();
    let hello = BootstrapClientHello {
        versions: BTreeMap::from([(
            BOOTSTRAP_VERSION.to_string(),
            serde_json::to_value(BootstrapV1ClientHello {
                session_protocols: vec!["h2".to_string()],
                cashu_spilman_protocol_versions: vec![
                    CASHU_SPILMAN_PROTOCOL_VERSION_2026_03_20.to_string()
                ],
                pricing_policies: vec!["future".to_string()],
            })
            .unwrap(),
        )]),
    };
    let payload = encode_client_hello(&hello).unwrap();

    let (_, _, _, server_payload) = noise_secp256k1::handshake_initiator_with_pubkey_and_payload(
        &mut stream,
        relay_pubkey.to_compressed_bytes(),
        &payload,
    )
    .await
    .unwrap();
    let response = decode_server_response(&server_payload).unwrap();

    match response {
        monad_common::bootstrap::BootstrapServerResponse::Reject { reason, .. } => {
            assert!(reason.contains("unsupported pricing_policies"));
        }
        monad_common::bootstrap::BootstrapServerResponse::Accept { .. } => {
            panic!("expected bootstrap handshake to be rejected")
        }
    }
}

#[tokio::test]
async fn test_bootstrap_rejects_client_without_mutual_cashu_spilman_protocol_version() {
    let (relay_addr, relay_pubkey) = start_monad_relay().await;
    let mut stream = TcpStream::connect(relay_addr).await.unwrap();
    let hello = BootstrapClientHello {
        versions: BTreeMap::from([(
            BOOTSTRAP_VERSION.to_string(),
            serde_json::to_value(BootstrapV1ClientHello {
                session_protocols: vec!["h2".to_string()],
                cashu_spilman_protocol_versions: vec!["future".to_string()],
                pricing_policies: vec![PRICING_POLICY_SESSION_CONSTANT.to_string()],
            })
            .unwrap(),
        )]),
    };
    let payload = encode_client_hello(&hello).unwrap();

    let (_, _, _, server_payload) = noise_secp256k1::handshake_initiator_with_pubkey_and_payload(
        &mut stream,
        relay_pubkey.to_compressed_bytes(),
        &payload,
    )
    .await
    .unwrap();
    let response = decode_server_response(&server_payload).unwrap();

    match response {
        monad_common::bootstrap::BootstrapServerResponse::Reject { reason, .. } => {
            assert!(reason.contains("unsupported cashu_spilman_protocol_versions"));
        }
        monad_common::bootstrap::BootstrapServerResponse::Accept { .. } => {
            panic!("expected bootstrap handshake to be rejected")
        }
    }
}

#[tokio::test]
async fn test_connector_two_consecutive_blinded_hops() {
    let upper_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let upper_addr = upper_listener.local_addr().unwrap();
    tokio::spawn(run_uppercase_server(upper_listener));

    let hidden_b_transport_key = SecpTransportKeypair::generate();
    let hidden_c_transport_key = SecpTransportKeypair::generate();
    let (hidden_b_addr, hidden_b_pubkey) =
        start_monad_relay_with_transport_key(hidden_b_transport_key.clone()).await;
    let (hidden_c_addr, _hidden_c_pubkey) =
        start_monad_relay_with_transport_key(hidden_c_transport_key.clone()).await;
    let (intro_addr, intro_pubkey) = start_monad_relay().await;

    let descriptor_ab = build_blinded_hop_descriptor(
        intro_pubkey.to_compressed_bytes(),
        &hidden_b_addr.to_string(),
        &hidden_b_transport_key,
    )
    .unwrap();
    let descriptor_bc = build_blinded_hop_descriptor(
        hidden_b_pubkey.to_compressed_bytes(),
        &hidden_c_addr.to_string(),
        &hidden_c_transport_key,
    )
    .unwrap();

    let route = Route::new(vec![
        cleartext_route_hop(intro_addr.to_string(), intro_pubkey, true),
        RouteHop::Blinded {
            descriptor: descriptor_ab,
        },
        RouteHop::Blinded {
            descriptor: descriptor_bc,
        },
    ])
    .unwrap();
    let mut conn = connector::connect_route(&route).await.unwrap();
    fund_session(&mut conn, TEST_SESSION_PAYMENT).await;

    let mut h2 = conn.clone_send_request().await;
    let result = tunnel_roundtrip(&mut h2, &upper_addr.to_string(), b"two blinded hops").await;
    assert_eq!(result, b"TWO BLINDED HOPS");

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
            let mut conn = connect_route_hops(vec![
                cleartext_route_hop(s_addr.to_string(), s_pubkey, true),
                cleartext_route_hop(format!("127.0.0.1:{t_port}"), t_pubkey, true),
            ])
            .await;
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
    let mut conn = connect_route_hops(vec![cleartext_route_hop(
        server_addr.to_string(),
        pubkey,
        true,
    )])
    .await;
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
    let mut conn = connect_route_hops(vec![
        cleartext_route_hop(s_addr.to_string(), s_pubkey, true),
        cleartext_route_hop(t_addr.to_string(), t_pubkey, true),
    ])
    .await;
    fund_session(&mut conn, TEST_SESSION_PAYMENT).await;
    let mut h2 = conn.clone_send_request().await;

    let target = format!("127.0.0.1:{}", upper_addr.port());
    let result = tunnel_roundtrip(&mut h2, &target, b"quic then tcp").await;
    assert_eq!(result, b"QUIC THEN TCP");

    drop(h2);
    conn.shutdown().await;
}
