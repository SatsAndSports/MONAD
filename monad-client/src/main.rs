use clap::Parser;
use monad_client::connector;
use monad_client::connector::Hop;
use monad_client::socks;
use monad_client::tunnel;
use std::sync::Arc;
use tokio::net::TcpListener;
use tokio::task::JoinSet;
use tracing::{error, info, warn};

#[derive(Parser)]
#[command(name = "monad-client", about = "MONAD tunnel client")]
struct Cli {
    /// Server hop(s) in order: addr,pubkey_hex or quic:addr,pubkey_hex,quic_pin_hex
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
    ///
    /// Example (QUIC hop — previous relay connects via QUIC):
    ///   --hop T_addr:9050,<T_pubkey> --hop quic:S_addr:9050,<S_pubkey>,<S_quic_pin>
    #[arg(long, required = true)]
    hop: Vec<String>,

    /// Local SOCKS5 proxy address to listen on
    #[arg(long, default_value = "127.0.0.1:1080")]
    socks: String,
}

fn parse_hop(s: &str) -> anyhow::Result<Hop> {
    // Check for quic: prefix
    if let Some(rest) = s.strip_prefix("quic:") {
        // Format: quic:addr:port,noise_pubkey_hex,quic_pin_hex
        // Split from the right: last comma separates quic_pin, second-to-last separates noise key
        let (addr_and_noise, quic_pin_hex) = rest
            .rsplit_once(',')
            .ok_or_else(|| anyhow::anyhow!("QUIC hop must be quic:addr:port,pubkey_hex,quic_pin_hex — got: {s}"))?;

        let (addr, noise_hex) = addr_and_noise
            .rsplit_once(',')
            .ok_or_else(|| anyhow::anyhow!("QUIC hop must be quic:addr:port,pubkey_hex,quic_pin_hex — got: {s}"))?;

        let pubkey = hex::decode(noise_hex)?;
        if pubkey.len() != 32 {
            anyhow::bail!(
                "Noise public key must be 32 bytes (64 hex chars), got {} bytes for hop {addr}",
                pubkey.len()
            );
        }

        let quic_pin = hex::decode(quic_pin_hex)?;
        if quic_pin.is_empty() {
            anyhow::bail!("QUIC pin must not be empty for hop {addr}");
        }

        Ok(Hop {
            addr: addr.to_string(),
            pubkey,
            quic_pin: Some(quic_pin),
        })
    } else {
        // Standard TCP hop: addr:port,noise_pubkey_hex
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
            quic_pin: None,
        })
    }
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

    // Start the local SOCKS5 proxy
    let socks_listener = TcpListener::bind(&cli.socks).await?;
    info!("SOCKS5 proxy listening on {}", cli.socks);

    if let Err(e) = accept_loop(&socks_listener, conn.h2_client.clone()).await {
        error!("accept loop error: {e}");
    }

    conn.shutdown().await;

    info!("client shut down");
    Ok(())
}

async fn accept_loop(
    socks_listener: &TcpListener,
    h2_client: Arc<tokio::sync::Mutex<h2::client::SendRequest<bytes::Bytes>>>,
) -> anyhow::Result<()> {
    let mut tunnels = JoinSet::new();

    loop {
        tokio::select! {
            result = socks_listener.accept() => {
                let (mut local_stream, peer_addr) = result?;
                info!("SOCKS5 connection from {peer_addr}");

                let h2_client = h2_client.clone();

                tunnels.spawn(async move {
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

                while let Some(result) = tunnels.try_join_next() {
                    if let Err(e) = result {
                        error!("tunnel task panicked: {e}");
                    }
                }
            }
            _ = tokio::signal::ctrl_c() => {
                info!("shutting down (Ctrl+C)...");
                break;
            }
        }
    }

    let active = tunnels.len();
    if active > 0 {
        info!("waiting for {active} active tunnel(s) to finish...");

        let timeout = tokio::time::sleep(std::time::Duration::from_secs(5));
        tokio::pin!(timeout);

        loop {
            tokio::select! {
                result = tunnels.join_next() => {
                    match result {
                        Some(Ok(())) => {}
                        Some(Err(e)) => error!("tunnel task panicked: {e}"),
                        None => {
                            info!("all tunnels finished");
                            break;
                        }
                    }
                }
                _ = &mut timeout => {
                    let remaining = tunnels.len();
                    info!("shutdown timeout, aborting {remaining} remaining tunnel(s)");
                    tunnels.abort_all();
                    break;
                }
            }
        }
    }

    while let Some(result) = tunnels.join_next().await {
        if let Err(e) = result {
            error!("tunnel task panicked: {e}");
        }
    }

    drop(h2_client);

    Ok(())
}
