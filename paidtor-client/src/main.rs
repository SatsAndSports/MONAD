mod connector;
mod socks;
mod tunnel;

use clap::Parser;
use std::sync::Arc;
use tokio::net::TcpListener;
use tracing::{error, info, warn};

#[derive(Parser)]
#[command(name = "paidtor-client", about = "PaidTor tunnel client")]
struct Cli {
    /// Server address (host:port)
    #[arg(long)]
    server: String,

    /// Server's Noise static public key (hex-encoded, 32 bytes)
    #[arg(long)]
    server_pubkey: String,

    /// Local SOCKS5 proxy address to listen on
    #[arg(long, default_value = "127.0.0.1:1080")]
    socks: String,
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

    let server_pubkey = hex::decode(&cli.server_pubkey)?;
    if server_pubkey.len() != 32 {
        anyhow::bail!("server public key must be 32 bytes (64 hex chars)");
    }

    // Connect to the PaidTor server
    let conn = connector::connect(&cli.server, &server_pubkey).await?;
    info!("connected to server at {}", cli.server);

    // The H2 client handle can be cloned for each tunnel
    let h2_client = Arc::new(tokio::sync::Mutex::new(conn.h2_client));

    // Start the local SOCKS5 proxy
    let socks_listener = TcpListener::bind(&cli.socks).await?;
    info!("SOCKS5 proxy listening on {}", cli.socks);

    loop {
        let (mut local_stream, peer_addr) = socks_listener.accept().await?;
        info!("SOCKS5 connection from {peer_addr}");

        let h2_client = h2_client.clone();

        tokio::spawn(async move {
            // Perform SOCKS5 handshake to learn the target
            let target = match socks::socks5_handshake(&mut local_stream).await {
                Ok(t) => t,
                Err(e) => {
                    warn!("SOCKS5 handshake failed from {peer_addr}: {e}");
                    return;
                }
            };

            info!("SOCKS5 CONNECT to {} from {peer_addr}", target.authority);

            // Clone the H2 client for this tunnel
            let h2 = {
                let client = h2_client.lock().await;
                client.clone()
            };

            // Open tunnel and proxy
            match tunnel::open_tunnel(h2, &target.authority, &mut local_stream).await {
                Ok(()) => {
                    info!("tunnel to {} closed", target.authority);
                }
                Err(e) => {
                    // Send SOCKS5 failure reply
                    let _ =
                        socks::send_reply(&mut local_stream, 0x01, "0.0.0.0", 0).await;
                    error!("tunnel to {} failed: {e}", target.authority);
                }
            }
        });
    }
}
