use cashu::nuts::SecretKey;
use clap::{Parser, Subcommand};
use monad_common::config::MonadConfig;
use monad_common::quic_cert_identity::QuicCertIdentity;
use monad_common::secp_identity::SecpTransportKeypair;
use monad_common::wallet_lock::{WalletLockMode, WalletLocks};
use monad_relay::listener;
use monad_relay::wallet_cli::{run_wallet_command, WalletArgs};
use monad_relay::wallet_manager::RelayWalletManager;
use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;
use std::sync::Arc;
use tokio::net::TcpListener;
use tokio::sync::watch;
use tokio::task::JoinSet;
use tracing::{error, info};

#[derive(Parser)]
#[command(name = "monad-relay", about = "MONAD relay")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Generate a new relay identity set
    Keygen,

    /// Run a relay from a YAML config file
    Run {
        /// Path to the relay YAML config file.
        #[arg(long)]
        config: String,

        /// Name of one relay to run. Omit to run every configured relay.
        #[arg(long)]
        relay: Option<String>,
    },

    /// Inspect and administer the shared relay-wallet database
    Wallet(WalletArgs),
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()),
        )
        .init();

    let cli = Cli::parse();

    match cli.command {
        Command::Keygen => keygen(),
        Command::Run { config, relay } => run(config, relay).await,
        Command::Wallet(args) => run_wallet_command(args).await,
    }
}

fn keygen() -> anyhow::Result<()> {
    let identity = QuicCertIdentity::generate()?;
    let transport_key = SecpTransportKeypair::generate();

    // Generate QUIC certificate from the same seed
    let quic_km = monad_quic::keygen::generate_from_seed(identity.seed())?;

    let pubkey = identity.ed25519_pubkey();
    let transport_pubkey = transport_key.pubkey();
    println!("# MONAD relay identity set");
    println!("#");
    println!("# The Ed25519 key is used for QUIC certificate generation.");
    println!();
    println!(
        "Private key (Ed25519 seed): {}",
        hex::encode(identity.seed())
    );
    println!("Public key (Ed25519):       {pubkey}");
    println!();
    println!("# Shared secp256k1 transport identity");
    println!(
        "Private key (secp256k1):    {}",
        hex::encode(transport_key.normalized_secret_bytes())
    );
    println!("Public key (secp256k1 x-only): {transport_pubkey}");
    println!();
    println!("# --- QUIC certificate (derived from the Ed25519 key) ---");
    println!("{}", quic_km.cert_pem);
    println!("# Run the relay with a config file such as:");
    println!("#   monad-relay run --config monad.yaml --relay <name>");
    println!("#");
    println!("# MONAD clients use the secp transport public key:");
    println!("#   {transport_pubkey}");
    Ok(())
}

async fn run(config_path: String, relay_name: Option<String>) -> anyhow::Result<()> {
    let config = MonadConfig::load(&config_path)?;
    let relay_wallet = config
        .relay_wallet
        .as_ref()
        .ok_or_else(|| anyhow::anyhow!("relay_wallet is required to run a relay"))?;
    let selected = config.select_relays(relay_name.as_deref())?;
    let mut prepared = Vec::with_capacity(selected.len());
    for relay in selected {
        let identity = QuicCertIdentity::from_hex(&relay.quic_cert_seed)
            .map_err(|e| anyhow::anyhow!("bad QUIC cert seed for relay '{}': {e}", relay.name))?;
        let transport_key = parse_transport_key(&relay.transport_key)
            .map_err(|e| anyhow::anyhow!("bad transport key for relay '{}': {e}", relay.name))?;
        let receiver_secret = relay
            .receiver_secret_hex
            .as_deref()
            .map(SecretKey::from_hex)
            .transpose()
            .map_err(|e| anyhow::anyhow!("bad receiver secret for relay '{}': {e}", relay.name))?;
        let quic_km = monad_quic::keygen::generate_from_seed(identity.seed())?;
        let quic_config =
            monad_quic::server::build_server_config(&quic_km.cert_pem, &quic_km.key_pem)?;
        let tcp_listener = TcpListener::bind(&relay.listen)
            .await
            .map_err(|e| anyhow::anyhow!("bind TCP listener for relay '{}': {e}", relay.name))?;
        let local_addr = tcp_listener.local_addr()?;
        let quic_endpoint = quinn::Endpoint::server(quic_config, local_addr)
            .map_err(|e| anyhow::anyhow!("bind QUIC listener for relay '{}': {e}", relay.name))?;
        prepared.push((
            relay,
            identity,
            transport_key,
            receiver_secret,
            tcp_listener,
            quic_endpoint,
        ));
    }

    let wallet_locks = WalletLocks::acquire(
        [Path::new(&relay_wallet.db_path)],
        WalletLockMode::Runtime,
        "relay",
    )?;
    let wallet_manager = Arc::new(RelayWalletManager::open_with_locks(
        &relay_wallet.db_path,
        wallet_locks,
    )?);

    for (relay, _, _, receiver_secret, _, _) in &prepared {
        match (receiver_secret, wallet_manager.receiver_secret(&relay.name)) {
            (Some(configured), Ok(stored))
                if configured.to_secret_hex() != stored.to_secret_hex() =>
            {
                anyhow::bail!(
                    "relay wallet identity '{}' already exists with a different receiver secret",
                    relay.name
                );
            }
            (Some(_), Ok(_)) => {}
            (Some(_), Err(error)) if error.kind() == std::io::ErrorKind::NotFound => {}
            (None, Ok(_)) => {}
            (None, Err(error)) => {
                return Err(anyhow::anyhow!(
                    "relay '{}' has no receiver_secret_hex and is not registered in '{}': {error}",
                    relay.name,
                    relay_wallet.db_path
                ));
            }
            (_, Err(error)) => {
                return Err(anyhow::anyhow!(
                    "load relay wallet identity '{}': {error}",
                    relay.name
                ));
            }
        }
    }
    for (relay, _, _, receiver_secret, _, _) in &prepared {
        if let Some(secret) = receiver_secret {
            wallet_manager
                .register_identity(&relay.name, secret.clone())
                .map_err(|e| {
                    anyhow::anyhow!(
                        "register relay identity '{}' in '{}': {e}",
                        relay.name,
                        relay_wallet.db_path
                    )
                })?;
        }
    }

    let mut trusted_mint_units = BTreeMap::<String, BTreeSet<String>>::new();
    for (relay, ..) in &prepared {
        for (mint, units) in relay.trusted_mint_units() {
            trusted_mint_units.entry(mint).or_default().extend(units);
        }
    }
    wallet_manager
        .refresh_trusted_mint_cache(&trusted_mint_units)
        .await
        .map_err(anyhow::Error::msg)?;
    wallet_manager.enter_steady_state()?;

    let (shutdown_tx, shutdown_rx) = watch::channel(false);
    let mut workers = JoinSet::new();
    let registries: BTreeMap<_, _> = prepared
        .iter()
        .map(|(relay, ..)| {
            (
                relay.name.clone(),
                Arc::new(monad_relay::session_registry::SessionRegistry::new()),
            )
        })
        .collect();
    if let Some(path) = config
        .management
        .as_ref()
        .and_then(|m| m.relay_socket.clone())
    {
        let backend = Arc::new(monad_relay::management::RelayBackend::new(
            registries.clone(),
            wallet_manager.clone(),
        ));
        let mut stopped = shutdown_rx.clone();
        workers.spawn(async move {
            let result = monad_management::serve_unix(path.into(), backend, async move {
                while !*stopped.borrow() {
                    if stopped.changed().await.is_err() {
                        break;
                    }
                }
            })
            .await;
            ("management".to_string(), result)
        });
    }
    for (relay, identity, transport_key, _, tcp_listener, quic_endpoint) in prepared {
        let registry = registries[&relay.name].clone();
        let receiver_pubkey_hex = wallet_manager.receiver_pubkey_hex(&relay.name)?;
        let server_config = Arc::new(listener::ServerConfig {
            identity,
            transport_key: Some(transport_key),
            receiver_pubkey_hex,
            trusted_mint_units: relay.trusted_mint_units(),
            in_bytes_per_millisat: relay.pricing.in_bytes_per_millisat,
            out_bytes_per_millisat: relay.pricing.out_bytes_per_millisat,
            bootstrap_capabilities: None,
            relay_wallet_name: relay.name.clone(),
            spilman_storage_path: relay_wallet.db_path.clone(),
            channel_policy: relay.channel_policy.clone(),
        });
        let manager = wallet_manager.clone();
        let mut relay_shutdown = shutdown_rx.clone();
        let name = relay.name.clone();
        info!(relay = %name, address = %tcp_listener.local_addr()?, "relay starting");
        workers.spawn(async move {
            let result = listener::run_with_wallet_manager_registry_and_shutdown(
                tcp_listener,
                Some(quic_endpoint),
                server_config,
                manager,
                registry,
                async move {
                    while !*relay_shutdown.borrow() {
                        if relay_shutdown.changed().await.is_err() {
                            break;
                        }
                    }
                },
            )
            .await;
            (name, result)
        });
    }

    let mut failure = tokio::select! {
        signal = tokio::signal::ctrl_c() => {
            signal.map_err(|e| anyhow::anyhow!("listen for Ctrl+C: {e}"))?;
            None
        }
        result = workers.join_next() => {
            worker_result(result)
        }
    };
    let _ = shutdown_tx.send(true);

    while let Some(result) = workers.join_next().await {
        let error = match result {
            Ok((_, Ok(()))) => None,
            Ok((name, Err(error))) => Some(anyhow::anyhow!("relay '{name}' failed: {error}")),
            Err(error) => Some(anyhow::anyhow!("relay worker task failed: {error}")),
        };
        if let Some(error) = error {
            error!(%error, "relay worker failed during coordinated shutdown");
            if failure.is_none() {
                failure = Some(error);
            }
        }
    }

    match failure {
        Some(error) => Err(error),
        None => Ok(()),
    }
}

fn worker_result(
    result: Option<Result<(String, std::io::Result<()>), tokio::task::JoinError>>,
) -> Option<anyhow::Error> {
    match result {
        Some(Ok((name, Ok(())))) => Some(anyhow::anyhow!("relay '{name}' stopped unexpectedly")),
        Some(Ok((name, Err(error)))) => Some(anyhow::anyhow!("relay '{name}' failed: {error}")),
        Some(Err(error)) => Some(anyhow::anyhow!("relay worker task failed: {error}")),
        None => Some(anyhow::anyhow!(
            "relay worker set became empty unexpectedly"
        )),
    }
}

fn parse_transport_key(hex_key: &str) -> anyhow::Result<SecpTransportKeypair> {
    let bytes = hex::decode(hex_key)
        .map_err(|e| anyhow::anyhow!("invalid secp256k1 transport key hex: {e}"))?;
    let bytes: [u8; 32] = bytes
        .as_slice()
        .try_into()
        .map_err(|_| anyhow::anyhow!("secp256k1 transport key must be 32 bytes"))?;
    SecpTransportKeypair::from_secret_bytes(&bytes)
        .map_err(|e| anyhow::anyhow!("bad secp256k1 transport key: {e}"))
}
