use cashu::nuts::SecretKey;
use clap::{Parser, Subcommand};
use monad_common::quic_cert_identity::QuicCertIdentity;
use monad_common::secp_identity::SecpTransportKeypair;
use monad_relay::listener;
use std::collections::{BTreeMap, BTreeSet};
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

    /// Run the relay
    Run {
        /// Address to listen on (TCP and optionally QUIC/UDP on the same port)
        #[arg(long, default_value = "0.0.0.0:9050")]
        listen: String,

        /// Relay Ed25519 seed (hex-encoded, 32 bytes).
        /// Used for QUIC certificate generation.
        #[arg(long, env = "MONAD_QUIC_CERT_SEED")]
        quic_cert_seed: String,

        /// Shared secp256k1 transport private key (hex-encoded, 32 bytes).
        /// Used for secp-authenticated transports, including TCP and QUIC secp auth.
        #[arg(long, env = "MONAD_TRANSPORT_KEY")]
        transport_key: String,

        /// Enable QUIC listener. The QUIC certificate is derived from the
        /// Ed25519 seed. If omitted, only TCP is accepted.
        #[arg(long)]
        quic: bool,
    },
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
        Command::Keygen => {
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
            println!("# Run the relay with:");
            println!(
                "#   monad-relay run --quic-cert-seed {} --transport-key {} --quic",
                hex::encode(identity.seed()),
                hex::encode(transport_key.normalized_secret_bytes())
            );
            println!("#");
            println!("# MONAD clients use the secp transport key:");
            println!("#   secp256k1:{transport_pubkey}");
        }
        Command::Run {
            listen,
            quic_cert_seed,
            transport_key,
            quic,
        } => {
            let identity = QuicCertIdentity::from_hex(&quic_cert_seed)
                .map_err(|e| anyhow::anyhow!("bad QUIC cert seed: {e}"))?;
            let transport_key = parse_transport_key(&transport_key)?;

            // Optionally set up QUIC listener from the same seed
            let quic_config = if quic {
                let quic_km = monad_quic::keygen::generate_from_seed(identity.seed())?;
                let relay_config =
                    monad_quic::server::build_server_config(&quic_km.cert_pem, &quic_km.key_pem)?;
                Some(relay_config)
            } else {
                None
            };

            let mut trusted_mint_units = BTreeMap::<String, BTreeSet<String>>::new();
            trusted_mint_units.insert(
                "https://dev.mint.camelus.app".to_string(),
                BTreeSet::from(["sat".to_string()]),
            );

            let config = Arc::new(listener::ServerConfig {
                identity,
                transport_key: Some(transport_key),
                payment_receiver_secret: SecretKey::generate(),
                trusted_mint_units,
            });

            let tcp_listener = TcpListener::bind(&listen).await?;

            let quic_endpoint = if let Some(quinn_config) = quic_config {
                let local_addr = tcp_listener.local_addr()?;
                let endpoint = quinn::Endpoint::server(quinn_config, local_addr)?;
                info!("QUIC listener enabled on {local_addr}");
                Some(endpoint)
            } else {
                None
            };

            info!("relay starting");
            listener::run(tcp_listener, quic_endpoint, config).await?;
        }
    }

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
