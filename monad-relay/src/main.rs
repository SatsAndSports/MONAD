use cashu::nuts::SecretKey;
use clap::{Parser, Subcommand};
use monad_common::quic_cert_identity::QuicCertIdentity;
use monad_common::secp_identity::SecpTransportKeypair;
use monad_relay::config::MonadConfig;
use monad_relay::listener;
use monad_relay::listener::discover_spilman_mint_cache;
use monad_relay::wallet_cli::{run_wallet_command, WalletArgs};
use monad_relay::wallet_manager::RelayWalletManager;
use std::sync::Arc;
use tokio::net::TcpListener;
use tracing::info;

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

        /// Name of the relay to run. Required if the config contains more than
        /// one relay.
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
    println!("#   monad-relay run --config relay.yaml --relay <name>");
    println!("#");
    println!("# MONAD clients use the secp transport key:");
    println!("#   secp256k1:{transport_pubkey}");
    Ok(())
}

async fn run(config_path: String, relay_name: Option<String>) -> anyhow::Result<()> {
    let config = MonadConfig::load(&config_path)?;
    let relay = config.select_relay(relay_name.as_deref())?;

    let identity = QuicCertIdentity::from_hex(&relay.quic_cert_seed)
        .map_err(|e| anyhow::anyhow!("bad QUIC cert seed for relay '{}': {e}", relay.name))?;
    let transport_key = parse_transport_key(&relay.transport_key)
        .map_err(|e| anyhow::anyhow!("bad transport key for relay '{}': {e}", relay.name))?;

    let quic_config = if relay.quic {
        let quic_km = monad_quic::keygen::generate_from_seed(identity.seed())?;
        Some(monad_quic::server::build_server_config(
            &quic_km.cert_pem,
            &quic_km.key_pem,
        )?)
    } else {
        None
    };

    let wallet_manager = Arc::new(RelayWalletManager::open(&relay.wallet_db_path)?);

    let receiver_pubkey_hex = match &relay.receiver_secret_hex {
        Some(secret_hex) => {
            let secret = SecretKey::from_hex(secret_hex).map_err(|e| {
                anyhow::anyhow!("bad receiver secret for relay '{}': {e}", relay.name)
            })?;
            let receiver_pubkey_hex = secret.public_key().to_hex();
            wallet_manager.register_identity(&relay.name, secret)?;
            receiver_pubkey_hex
        }
        None => wallet_manager
            .receiver_pubkey_hex(&relay.name)
            .map_err(|e| {
                anyhow::anyhow!(
                    "relay '{}' has no receiver_secret_hex and is not registered in '{}': {e}",
                    relay.name,
                    relay.wallet_db_path
                )
            })?,
    };

    let trusted_mint_units = relay.trusted_mint_units();
    let discovered_spilman_mint_cache =
        Arc::new(discover_spilman_mint_cache(&trusted_mint_units).await?);

    let server_config = Arc::new(listener::ServerConfig {
        identity,
        transport_key: Some(transport_key),
        receiver_pubkey_hex,
        trusted_mint_units,
        default_in_bytes_per_millisat: relay.default_in_bytes_per_millisat,
        default_out_bytes_per_millisat: relay.default_out_bytes_per_millisat,
        bootstrap_capabilities: None,
        relay_wallet_name: relay.name.clone(),
        spilman_storage_path: relay.wallet_db_path.clone(),
    });

    let tcp_listener = TcpListener::bind(&relay.listen).await?;

    let quic_endpoint = if let Some(quinn_config) = quic_config {
        let local_addr = tcp_listener.local_addr()?;
        let endpoint = quinn::Endpoint::server(quinn_config, local_addr)?;
        info!("QUIC listener enabled on {local_addr}");
        Some(endpoint)
    } else {
        None
    };

    info!(relay = %relay.name, "relay starting");
    listener::run_with_wallet_manager(
        tcp_listener,
        quic_endpoint,
        server_config,
        wallet_manager,
        discovered_spilman_mint_cache,
    )
    .await?;

    Ok(())
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
