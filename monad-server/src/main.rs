use clap::{Parser, Subcommand};
use monad_common::noise;
use monad_server::listener;
use std::sync::Arc;
use tokio::net::TcpListener;
use tracing::info;

#[derive(Parser)]
#[command(name = "monad-server", about = "MONAD tunnel server")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Generate a new server keypair (Noise + QUIC)
    Keygen,

    /// Run the server
    Run {
        /// Address to listen on (TCP and optionally QUIC/UDP on the same port)
        #[arg(long, default_value = "0.0.0.0:9050")]
        listen: String,

        /// Server Noise private key (hex-encoded, 32 bytes)
        #[arg(long, env = "PAIDTOR_PRIVATE_KEY")]
        private_key: String,

        /// QUIC certificate PEM file (enables QUIC listener)
        #[arg(long)]
        quic_cert: Option<String>,

        /// QUIC private key PEM file (required if --quic-cert is set)
        #[arg(long)]
        quic_key: Option<String>,
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
            // Generate Noise keypair
            let (privkey, pubkey) = noise::generate_keypair();

            // Generate QUIC certificate
            let quic_km = monad_quic::keygen::generate()?;

            println!("# --- Noise keypair ---");
            println!("Private key: {}", hex::encode(&privkey));
            println!("Public key:  {}", hex::encode(&pubkey));
            println!();
            println!("# --- QUIC certificate ---");
            println!("{}", quic_km.key_pem);
            println!("{}", quic_km.cert_pem);
            println!("QUIC pin: {}", quic_km.pin_hex);
            println!();
            println!("# Save the QUIC key to server-quic.key and cert to server-quic.crt, then:");
            println!("#");
            println!(
                "#   monad-server run --private-key {} \\",
                hex::encode(&privkey)
            );
            println!("#     --quic-cert server-quic.crt --quic-key server-quic.key");
            println!("#");
            println!("# Give these to clients:");
            println!("#   Noise public key: {}", hex::encode(&pubkey));
            println!("#   QUIC pin:         {}", quic_km.pin_hex);
        }
        Command::Run {
            listen,
            private_key,
            quic_cert,
            quic_key,
        } => {
            let privkey = hex::decode(&private_key)?;
            if privkey.len() != 32 {
                anyhow::bail!("private key must be 32 bytes (64 hex chars)");
            }

            // Load optional QUIC configuration
            let quic_config = match (quic_cert, quic_key) {
                (Some(cert_path), Some(key_path)) => {
                    let cert_pem = std::fs::read_to_string(&cert_path)
                        .map_err(|e| anyhow::anyhow!("failed to read QUIC cert {cert_path}: {e}"))?;
                    let key_pem = std::fs::read_to_string(&key_path)
                        .map_err(|e| anyhow::anyhow!("failed to read QUIC key {key_path}: {e}"))?;
                    let server_config = monad_quic::server::build_server_config(&cert_pem, &key_pem)?;
                    Some(server_config)
                }
                (None, None) => None,
                _ => anyhow::bail!("--quic-cert and --quic-key must both be provided or both omitted"),
            };

            let config = Arc::new(listener::ServerConfig {
                private_key: privkey,
            });

            let tcp_listener = TcpListener::bind(&listen).await?;

            // Optionally bind a QUIC endpoint on the same port (UDP)
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
