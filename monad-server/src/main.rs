use clap::{Parser, Subcommand};
use monad_common::identity::ServerIdentity;
use monad_server::listener;
use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;
use tokio::net::TcpListener;
use tracing::info;

const HARDCODED_PAYMENT_RECEIVER_PUBKEY: &str =
    "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798";

#[derive(Parser)]
#[command(name = "monad-server", about = "MONAD tunnel server")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Generate a new server identity (unified Ed25519 key for Noise + QUIC)
    Keygen,

    /// Run the server
    Run {
        /// Address to listen on (TCP and optionally QUIC/UDP on the same port)
        #[arg(long, default_value = "0.0.0.0:9050")]
        listen: String,

        /// Server private key — Ed25519 seed (hex-encoded, 32 bytes).
        /// Used for both Noise (via X25519 derivation) and QUIC (via Ed25519 certificate).
        #[arg(long, env = "MONAD_PRIVATE_KEY")]
        private_key: String,

        /// Enable QUIC listener. The QUIC certificate is derived from the
        /// same Ed25519 private key. If omitted, only TCP is accepted.
        #[arg(long)]
        quic: bool,
    },
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "info".into()),
        )
        .init();

    let cli = Cli::parse();

    match cli.command {
        Command::Keygen => {
            let identity = ServerIdentity::generate()?;

            // Generate QUIC certificate from the same seed
            let quic_km = monad_quic::keygen::generate_from_seed(identity.seed())?;

            let pubkey = identity.ed25519_pubkey();
            println!("# MONAD server identity (unified Ed25519 key)");
            println!("#");
            println!("# One key is used for both Noise and QUIC authentication.");
            println!();
            println!("Private key (Ed25519 seed): {}", hex::encode(identity.seed()));
            println!("Public key (Ed25519):       {pubkey}");
            println!();
            println!("# --- QUIC certificate (derived from the same key) ---");
            println!("{}", quic_km.cert_pem);
            println!("# Run the server with:");
            println!("#   monad-server run --private-key {} --quic", hex::encode(identity.seed()));
            println!("#");
            println!("# Give the public key to clients:");
            println!("#   {pubkey}");
            println!("#");
            println!("# For a QUIC hop, clients use the same key:");
            println!("#   --hop quic:addr:port,{pubkey}");
        }
        Command::Run {
            listen,
            private_key,
            quic,
        } => {
            let identity = ServerIdentity::from_hex(&private_key)
                .map_err(|e| anyhow::anyhow!("bad private key: {e}"))?;

            // Optionally set up QUIC listener from the same seed
            let quic_config = if quic {
                let quic_km = monad_quic::keygen::generate_from_seed(identity.seed())?;
                let server_config =
                    monad_quic::server::build_server_config(&quic_km.cert_pem, &quic_km.key_pem)?;
                Some(server_config)
            } else {
                None
            };

            let config = Arc::new(listener::ServerConfig {
                identity,
                payment_receiver_pubkey: HARDCODED_PAYMENT_RECEIVER_PUBKEY.to_string(),
                trusted_mint_units: BTreeMap::<String, BTreeSet<String>>::new(),
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

            info!("server starting");
            listener::run(tcp_listener, quic_endpoint, config).await?;
        }
    }

    Ok(())
}
