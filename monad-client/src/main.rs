use clap::Parser;
use monad_client::route::{Route, RouteHop};
use monad_common::secp_identity::Secp256k1Pubkey;
use tracing::info;

#[derive(Parser)]
#[command(name = "monad-client", about = "MONAD tunnel client")]
struct Cli {
    /// Server hop(s) in order: addr:port,<identity> or quic:addr:port,<identity>
    ///
    /// Supported identity form:
    /// - explicit secp256k1 transport identity: `secp256k1:<32-byte-x-only-pubkey-hex>`
    ///
    /// The `monad-client` binary now uses secp256k1 transport identities for
    /// both TCP and QUIC hops.
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

fn parse_hop_pubkey(identity: &str, addr: &str) -> anyhow::Result<Secp256k1Pubkey> {
    if let Some(rest) = identity.strip_prefix("secp256k1:") {
        let pubkey = Secp256k1Pubkey::from_hex(rest)
            .map_err(|e| anyhow::anyhow!("bad secp256k1 public key for hop {addr}: {e}"))?;
        return Ok(pubkey);
    }

    if identity.starts_with("ed25519:") {
        anyhow::bail!(
            "legacy Ed25519 hop identities are no longer accepted by monad-client for hop {addr}; use secp256k1:<pubkey>"
        );
    }

    anyhow::bail!(
        "hop {addr} must use explicit secp256k1:<pubkey> identity syntax; legacy untagged identities are no longer accepted"
    )
}

fn parse_hop(s: &str) -> anyhow::Result<RouteHop> {
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

    let pubkey = parse_hop_pubkey(identity, addr)?;

    Ok(RouteHop::Cleartext {
        addr: addr.to_string(),
        pubkey,
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
    let hops: Vec<RouteHop> = cli
        .hop
        .iter()
        .map(|s| parse_hop(s))
        .collect::<Result<_, _>>()?;

    let route = Route::new(hops)?;

    info!(
        "connecting through {} hop(s): {}",
        route.hops().len(),
        route
            .hops()
            .iter()
            .map(|hop| match hop {
                RouteHop::Cleartext { addr, use_quic, .. } => {
                    if *use_quic {
                        format!("quic:{addr}(secp256k1)")
                    } else {
                        format!("{addr}(secp256k1)")
                    }
                }
                RouteHop::Blinded { descriptor } => {
                    format!("blinded:{}", descriptor.tweaked_pubkey.to_hex())
                }
            })
            .collect::<Vec<_>>()
            .join(" → ")
    );

    anyhow::bail!(
        "MONAD client wallet config/funding runtime is not wired yet; monad-client CLI is temporarily unavailable"
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use monad_common::secp_identity::SecpTransportKeypair;

    #[test]
    fn test_parse_hop_legacy_ed25519_rejected() {
        let err = parse_hop(
            "127.0.0.1:9050,00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff",
        )
        .unwrap_err();
        assert!(err
            .to_string()
            .contains("must use explicit secp256k1:<pubkey> identity syntax"));
    }

    #[test]
    fn test_parse_hop_explicit_ed25519_rejected() {
        let err = parse_hop("quic:127.0.0.1:9050,ed25519:00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff").unwrap_err();
        assert!(err
            .to_string()
            .contains("legacy Ed25519 hop identities are no longer accepted"));
    }

    #[test]
    fn test_parse_hop_explicit_secp256k1() {
        let keypair = SecpTransportKeypair::generate();
        let pubkey = keypair.pubkey().to_hex();
        let hop = parse_hop(&format!("127.0.0.1:9050,secp256k1:{pubkey}")).unwrap();

        assert!(matches!(hop, RouteHop::Cleartext { .. }));
    }
}
