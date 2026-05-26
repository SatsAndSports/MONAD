use std::net::SocketAddr;

use anyhow::Result;
use clap::{Parser, Subcommand};
use tracing_subscriber::EnvFilter;

#[derive(Parser)]
#[command(
    name = "monad-quic",
    about = "MONAD QUIC proof-of-concept: pinned-key echo server and client"
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Generate a new self-signed certificate and pinned public key
    Keygen,

    /// Run the QUIC echo server
    Server {
        /// Address to listen on
        #[arg(long, default_value = "0.0.0.0:4433")]
        listen: SocketAddr,

        /// Path to the certificate PEM file
        #[arg(long)]
        cert: String,

        /// Path to the private key PEM file
        #[arg(long)]
        key: String,
    },

    /// Run the QUIC echo client
    Client {
        /// Server address to connect to
        #[arg(long, default_value = "127.0.0.1:4433")]
        connect: SocketAddr,

        /// Pinned server public key (SPKI DER, hex-encoded)
        #[arg(long)]
        pin: String,

        /// Number of bidirectional streams to open
        #[arg(long, default_value = "4")]
        streams: usize,

        /// Bytes to send per stream
        #[arg(long, default_value = "65536")]
        bytes: usize,
    },
}

fn main() -> Result<()> {
    let cli = Cli::parse();

    match cli.command {
        Command::Keygen => monad_quic::keygen::run_keygen(),
        Command::Server { listen, cert, key } => {
            init_tracing();
            let rt = tokio::runtime::Runtime::new()?;
            rt.block_on(async {
                let cert_pem = std::fs::read_to_string(&cert)
                    .map_err(|e| anyhow::anyhow!("failed to read cert file {cert}: {e}"))?;
                let key_pem = std::fs::read_to_string(&key)
                    .map_err(|e| anyhow::anyhow!("failed to read key file {key}: {e}"))?;
                monad_quic::server::run_server(listen, &cert_pem, &key_pem).await
            })
        }
        Command::Client {
            connect,
            pin,
            streams,
            bytes,
        } => {
            init_tracing();
            let rt = tokio::runtime::Runtime::new()?;
            rt.block_on(monad_quic::client::run_client(
                connect, &pin, streams, bytes,
            ))
        }
    }
}

fn init_tracing() {
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")),
        )
        .init();
}
