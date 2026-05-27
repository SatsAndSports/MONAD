use clap::Parser;
use monad_client::connector;
use monad_client::connector::Hop;
use monad_client::control;
use monad_client::socks;
use monad_client::tunnel;
use monad_common::identity::Ed25519Pubkey;
use monad_common::secp_identity::Secp256k1Pubkey;
use monad_common::session::RelayConnection;
use tokio::net::TcpListener;
use tokio::task::JoinSet;
use tracing::{error, info, warn};

#[derive(Parser)]
#[command(name = "monad-client", about = "MONAD tunnel client")]
struct Cli {
    /// Server hop(s) in order: addr:port,<identity> or quic:addr:port,<identity>
    ///
    /// Supported identity forms:
    /// - legacy untagged Ed25519 hex: `<pubkey_hex>`
    /// - explicit Ed25519: `ed25519:<pubkey_hex>`
    /// - explicit secp256k1 transport identity: `secp256k1:<33-byte-compressed-pubkey-hex>`
    ///
    /// Non-QUIC hops are secp256k1-only. Ed25519 hop identities remain supported
    /// for legacy QUIC/plain-noise hops.
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

    /// Fake session funding amount sent whenever the relay reports the session
    /// is paused with a non-positive balance.
    #[arg(long, default_value_t = 1024)]
    fake_payment_millisats: u64,
}

fn parse_hop_identity(identity: &str, addr: &str) -> anyhow::Result<connector::HopIdentity> {
    if let Some(rest) = identity.strip_prefix("ed25519:") {
        let pubkey = Ed25519Pubkey::from_hex(rest)
            .map_err(|e| anyhow::anyhow!("bad Ed25519 public key for hop {addr}: {e}"))?;
        return Ok(connector::HopIdentity::Ed25519(pubkey));
    }

    if let Some(rest) = identity.strip_prefix("secp256k1:") {
        let pubkey = Secp256k1Pubkey::from_hex(rest)
            .map_err(|e| anyhow::anyhow!("bad secp256k1 public key for hop {addr}: {e}"))?;
        return Ok(connector::HopIdentity::Secp256k1(pubkey));
    }

    let pubkey = Ed25519Pubkey::from_hex(identity)
        .map_err(|e| anyhow::anyhow!("bad legacy Ed25519 public key for hop {addr}: {e}"))?;
    Ok(connector::HopIdentity::Ed25519(pubkey))
}

fn parse_hop(s: &str) -> anyhow::Result<Hop> {
    // Check for quic: prefix
    let (rest, use_quic) = if let Some(rest) = s.strip_prefix("quic:") {
        (rest, true)
    } else {
        (s, false)
    };

    // Format: addr:port,<identity> (one comma, identity is always last)
    let (addr, identity) = rest
        .rsplit_once(',')
        .ok_or_else(|| anyhow::anyhow!("hop must be addr:port,<identity> — got: {s}"))?;

    let identity = parse_hop_identity(identity, addr)?;

    Ok(Hop {
        addr: addr.to_string(),
        identity,
        use_quic,
    })
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()),
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
                format!("quic:{}({})", h.addr, h.identity.describe())
            } else {
                format!("{}({})", h.addr, h.identity.describe())
            })
            .collect::<Vec<_>>()
            .join(" → ")
    );

    // Connect through the hop chain
    let mut conn = connector::connect_through_chain(&hops).await?;

    // Open the long-lived control stream before accepting SOCKS traffic.
    let last_hop = hops.last().unwrap();
    let hop_label = format!("hop {}/{} to {}", hops.len(), hops.len(), last_hop.addr);
    let (control_task, ready_rx) =
        control::start_control_task(&conn, cli.fake_payment_millisats, &hop_label).await?;
    conn.add_task(control_task);

    ready_rx
        .await
        .map_err(|_| anyhow::anyhow!("control task exited before session was funded"))?;

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

async fn accept_loop(socks_listener: &TcpListener, conn: &RelayConnection) -> anyhow::Result<()> {
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

#[cfg(test)]
mod tests {
    use super::*;
    use monad_common::identity::ServerIdentity;
    use monad_common::secp_identity::SecpTransportKeypair;

    #[test]
    fn test_parse_hop_legacy_ed25519() {
        let hop = parse_hop(
            "127.0.0.1:9050,00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff",
        )
        .unwrap();
        assert!(!hop.use_quic);
        assert!(matches!(hop.identity, connector::HopIdentity::Ed25519(_)));
    }

    #[test]
    fn test_parse_hop_explicit_ed25519() {
        let hop = parse_hop("quic:127.0.0.1:9050,ed25519:00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff").unwrap();
        assert!(hop.use_quic);
        assert!(matches!(hop.identity, connector::HopIdentity::Ed25519(_)));
    }

    #[test]
    fn test_parse_hop_explicit_secp256k1() {
        let keypair = SecpTransportKeypair::generate();
        let pubkey = keypair.pubkey().to_hex();
        let hop = parse_hop(&format!("127.0.0.1:9050,secp256k1:{pubkey}")).unwrap();

        assert!(matches!(hop.identity, connector::HopIdentity::Secp256k1(_)));
    }

    #[tokio::test]
    async fn test_non_quic_ed25519_hop_rejected() {
        let identity = ServerIdentity::generate().unwrap();
        let err = match connector::connect_through_chain(&[Hop {
            addr: "127.0.0.1:9050".to_string(),
            identity: connector::HopIdentity::Ed25519(identity.ed25519_pubkey().clone()),
            use_quic: false,
        }])
        .await
        {
            Ok(_) => panic!("expected non-QUIC Ed25519 hop to be rejected"),
            Err(err) => err,
        };

        assert_eq!(err.kind(), std::io::ErrorKind::Unsupported);
        assert!(err
            .to_string()
            .contains("legacy Ed25519 transport hops currently require QUIC"));
    }
}
