mod connector;
mod socks;
mod tunnel;

use clap::Parser;
use connector::Hop;
use std::sync::Arc;
use tokio::net::TcpListener;
use tracing::{error, info, warn};

#[derive(Parser)]
#[command(name = "paidtor-client", about = "PaidTor tunnel client")]
struct Cli {
    /// Server hop(s) in order: addr,pubkey_hex
    ///
    /// For a direct connection, specify one hop (the server).
    /// For onion routing, specify multiple hops in order.
    /// The last hop is the server that proxies to external targets.
    ///
    /// Example (direct):
    ///   --hop 1.2.3.4:9050,<pubkey_hex>
    ///
    /// Example (nested, through T then S):
    ///   --hop T_addr:9050,<T_pubkey> --hop S_addr:9050,<S_pubkey>
    #[arg(long, required = true)]
    hop: Vec<String>,

    /// Local SOCKS5 proxy address to listen on
    #[arg(long, default_value = "127.0.0.1:1080")]
    socks: String,
}

fn parse_hop(s: &str) -> anyhow::Result<Hop> {
    let (addr, pubkey_hex) = s
        .rsplit_once(',')
        .ok_or_else(|| anyhow::anyhow!("hop must be addr:port,pubkey_hex — got: {s}"))?;

    let pubkey = hex::decode(pubkey_hex)?;
    if pubkey.len() != 32 {
        anyhow::bail!(
            "public key must be 32 bytes (64 hex chars), got {} bytes for hop {addr}",
            pubkey.len()
        );
    }

    Ok(Hop {
        addr: addr.to_string(),
        pubkey,
    })
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

    // Parse hops
    let hops: Vec<Hop> = cli
        .hop
        .iter()
        .map(|s| parse_hop(s))
        .collect::<Result<_, _>>()?;

    if hops.is_empty() {
        anyhow::bail!("at least one --hop is required");
    }

    info!(
        "connecting through {} hop(s): {}",
        hops.len(),
        hops.iter()
            .map(|h| h.addr.as_str())
            .collect::<Vec<_>>()
            .join(" → ")
    );

    // Connect through the hop chain
    let conn = connector::connect_through_chain(&hops).await?;

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
                    let _ = socks::send_reply(&mut local_stream, 0x01, "0.0.0.0", 0).await;
                    error!("tunnel to {} failed: {e}", target.authority);
                }
            }
        });
    }
}
