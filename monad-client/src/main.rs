use clap::Parser;
use monad_client::connector;
use monad_client::connector::Hop;
use monad_client::socks;
use monad_client::tunnel;
use monad_common::identity::Ed25519Pubkey;
use monad_common::session::RelayConnection;
use tokio::net::TcpListener;
use tokio::task::JoinSet;
use tracing::{error, info, warn};

#[derive(Parser)]
#[command(name = "monad-client", about = "MONAD tunnel client")]
struct Cli {
    /// Server hop(s) in order: addr:port,pubkey_hex or quic:addr:port,pubkey_hex
    ///
    /// Each hop uses a single Ed25519 public key (32 bytes, 64 hex chars).
    /// The key is used for both Noise authentication and QUIC pinning.
    ///
    /// For a direct connection, specify one hop:
    ///   --hop 1.2.3.4:9050,<pubkey>
    ///
    /// For onion routing, specify multiple hops:
    ///   --hop T:9050,<T_pubkey> --hop S:9050,<S_pubkey>
    ///
    /// For QUIC hops (previous relay connects via QUIC):
    ///   --hop T:9050,<T_pubkey> --hop quic:S:9050,<S_pubkey>
    #[arg(long, required = true)]
    hop: Vec<String>,

    /// Local SOCKS5 proxy address to listen on
    #[arg(long, default_value = "127.0.0.1:1080")]
    socks: String,
}

fn parse_hop(s: &str) -> anyhow::Result<Hop> {
    // Check for quic: prefix
    let (rest, use_quic) = if let Some(rest) = s.strip_prefix("quic:") {
        (rest, true)
    } else {
        (s, false)
    };

    // Format: addr:port,pubkey_hex (one comma, pubkey is always last)
    let (addr, pubkey_hex) = rest
        .rsplit_once(',')
        .ok_or_else(|| anyhow::anyhow!("hop must be addr:port,pubkey_hex — got: {s}"))?;

    let pubkey = Ed25519Pubkey::from_hex(pubkey_hex)
        .map_err(|e| anyhow::anyhow!("bad public key for hop {addr}: {e}"))?;

    Ok(Hop {
        addr: addr.to_string(),
        pubkey,
        use_quic,
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
            .map(|h| if h.use_quic {
                format!("quic:{}", h.addr)
            } else {
                h.addr.clone()
            })
            .collect::<Vec<_>>()
            .join(" → ")
    );

    // Connect through the hop chain
    let conn = connector::connect_through_chain(&hops).await?;

    // Start the local SOCKS5 proxy
    let socks_listener = TcpListener::bind(&cli.socks).await?;
    info!("SOCKS5 proxy listening on {}", cli.socks);

    if let Err(e) = accept_loop(&socks_listener, &conn).await {
        error!("accept loop error: {e}");
    }

    conn.shutdown().await;

    info!("client shut down");
    Ok(())
}

async fn accept_loop(
    socks_listener: &TcpListener,
    conn: &RelayConnection,
) -> anyhow::Result<()> {
    let mut tunnels = JoinSet::new();

    loop {
        tokio::select! {
            result = socks_listener.accept() => {
                let (mut local_stream, peer_addr) = result?;
                info!("SOCKS5 connection from {peer_addr}");

                // Clone the H2 client for this tunnel (before spawning)
                let h2 = conn.clone_send_request().await;

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

    Ok(())
}
