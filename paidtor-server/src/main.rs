mod listener;
mod proxy;
mod session;

use clap::{Parser, Subcommand};
use paidtor_common::noise;
use std::sync::Arc;
use tokio::net::TcpListener;
use tracing::info;

#[derive(Parser)]
#[command(name = "paidtor-server", about = "PaidTor tunnel server")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Generate a new server keypair
    Keygen,

    /// Run the server
    Run {
        /// Address to listen on
        #[arg(long, default_value = "0.0.0.0:9050")]
        listen: String,

        /// Server private key (hex-encoded, 32 bytes)
        #[arg(long, env = "PAIDTOR_PRIVATE_KEY")]
        private_key: String,
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
            let (privkey, pubkey) = noise::generate_keypair();
            println!("Private key: {}", hex::encode(&privkey));
            println!("Public key:  {}", hex::encode(&pubkey));
            println!();
            println!("Run the server with:");
            println!(
                "  paidtor-server run --private-key {}",
                hex::encode(&privkey)
            );
            println!();
            println!("Give this public key to clients:");
            println!("  {}", hex::encode(&pubkey));
        }
        Command::Run {
            listen,
            private_key,
        } => {
            let privkey = hex::decode(&private_key)?;
            if privkey.len() != 32 {
                anyhow::bail!("private key must be 32 bytes (64 hex chars)");
            }

            let config = Arc::new(listener::ServerConfig {
                private_key: privkey,
            });

            let tcp_listener = TcpListener::bind(&listen).await?;
            info!("server starting");

            listener::run(tcp_listener, config).await?;
        }
    }

    Ok(())
}
