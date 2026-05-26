//! Establishes a connection to a MONAD server, optionally through a chain
//! of intermediate hops (onion routing / nested tunneling).
//!
//! Single hop:   TCP → Noise(S) → H2
//! Two hops:     TCP → Noise(T) → H2 → CONNECT(S) → Noise(S) → H2
//! N hops:       Each hop wraps the previous one via H2ConnectStream.

use crate::control;
use monad_common::identity::Ed25519Pubkey;
use monad_common::noise::{self, NoiseStream};
use monad_common::noise_secp256k1;
use monad_common::secp_identity::Secp256k1Pubkey;
use monad_common::session::RelayConnection;
use monad_quic::client::{build_client_config_for_auth, connect_with_auth, ClientAuthMode};
use monad_quic::stream::{open_monad_stream, open_monad_stream_with_kind, STREAM_KIND_SECP_NOISE};
use std::io;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::TcpStream;
use tracing::info;

const INTERMEDIATE_FAKE_PAYMENT_MILLISATS: u64 = 10_000_000;

/// A hop identity for transport authentication.
#[derive(Debug, Clone)]
pub enum HopIdentity {
    Ed25519(Ed25519Pubkey),
    Secp256k1(Secp256k1Pubkey),
}

impl HopIdentity {
    pub fn describe(&self) -> &'static str {
        match self {
            Self::Ed25519(_) => "ed25519",
            Self::Secp256k1(_) => "secp256k1",
        }
    }
}

/// A hop in the tunnel chain: server address and its transport identity.
///
/// Today, MONAD's mainline transport uses Ed25519 public keys, from which the
/// X25519 Noise key and QUIC SPKI pin are derived automatically. secp256k1
/// identities are parsed and carried through the hop model for the dual-stack
/// migration, but their transport path is not integrated into the mainline
/// connector yet.
///
/// If `use_quic` is true, the previous relay in the chain will connect to this
/// hop via QUIC instead of TCP.
#[derive(Debug, Clone)]
pub struct Hop {
    pub addr: String,
    /// Transport identity for this hop.
    pub identity: HopIdentity,
    /// Whether the previous relay should connect to this hop via QUIC.
    pub use_quic: bool,
}

/// Connect to a MONAD server directly (single hop).
///
/// Equivalent to `connect_through_chain(&[hop])`.
#[allow(dead_code)]
pub async fn connect(
    server_addr: &str,
    server_pubkey: Ed25519Pubkey,
) -> io::Result<RelayConnection> {
    connect_through_chain(&[Hop {
        addr: server_addr.to_string(),
        identity: HopIdentity::Ed25519(server_pubkey),
        use_quic: false,
    }])
    .await
}

/// Connect to a MONAD server through a chain of hops.
///
/// `hops` must have at least one entry. The first hop is connected to via TCP.
/// Each subsequent hop is reached by opening an H2 CONNECT tunnel through the
/// previous hop. The returned `RelayConnection` is for the *last* hop in the chain.
///
/// Example with 2 hops [T, S]:
///   TCP → Noise(T) → H2 → CONNECT(S:port) → Noise(S) → H2 → (returned client)
///
/// T only sees encrypted Noise bytes. It has no idea that inside those bytes
/// is another MONAD session asking S to proxy onward.
pub async fn connect_through_chain(hops: &[Hop]) -> io::Result<RelayConnection> {
    if hops.is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "at least one hop is required",
        ));
    }

    let first = &hops[0];

    if matches!(first.identity, HopIdentity::Secp256k1(_)) && !first.use_quic {
        return Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "secp256k1 transport hops currently require QUIC",
        ));
    }

    if first.use_quic {
        // Connect to the first hop via QUIC
        info!("connecting to first hop via QUIC: {}", first.addr);

        // Resolve the target address
        let socket_addr = tokio::net::lookup_host(&first.addr)
            .await?
            .next()
            .ok_or_else(|| io::Error::other(format!("no addresses found for {}", first.addr)))?;

        let mut endpoint = quinn::Endpoint::client("0.0.0.0:0".parse().unwrap())
            .map_err(|e| io::Error::other(format!("QUIC endpoint: {e}")))?;
        let auth = match &first.identity {
            HopIdentity::Ed25519(pubkey) => ClientAuthMode::PinnedSpki(pubkey.to_spki_der()),
            HopIdentity::Secp256k1(pubkey) => ClientAuthMode::Secp256k1(*pubkey),
        };
        let client_config = build_client_config_for_auth(auth.clone())
            .map_err(|e| io::Error::other(format!("failed to build QUIC client config: {e}")))?;
        endpoint.set_default_client_config(client_config);

        let conn = connect_with_auth(&endpoint, socket_addr, auth)
            .await
            .map_err(|e| {
                io::Error::new(
                    io::ErrorKind::ConnectionRefused,
                    format!("QUIC handshake failed with {}: {e}", first.addr),
                )
            })?;

        let quic_stream = match &first.identity {
            HopIdentity::Ed25519(_) => open_monad_stream(&conn).await?,
            HopIdentity::Secp256k1(_) => {
                open_monad_stream_with_kind(&conn, STREAM_KIND_SECP_NOISE).await?
            }
        };
        info!("QUIC connected to {}", first.addr);

        chain_from_stream(quic_stream, hops, 0).await
    } else {
        // Connect to the first hop via TCP
        info!("connecting to first hop: {}", first.addr);
        let tcp_stream = TcpStream::connect(&first.addr).await?;
        info!("TCP connected to {}", first.addr);

        chain_from_stream(tcp_stream, hops, 0).await
    }
}

/// Recursively build the tunnel chain starting from a given stream and hop index.
///
/// This function performs the Noise handshake and H2 setup for `hops[hop_idx]`,
/// then if there are more hops, opens a CONNECT tunnel and recurses.
///
/// The returned future is boxed to allow async recursion with different stream types
/// at each nesting level.
fn chain_from_stream<S>(
    mut stream: S,
    hops: &[Hop],
    hop_idx: usize,
) -> std::pin::Pin<Box<dyn std::future::Future<Output = io::Result<RelayConnection>> + Send>>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    // Clone what we need since we're moving into a boxed future
    let hops = hops.to_vec();

    Box::pin(async move {
        let hop = &hops[hop_idx];

        info!(
            "hop {}/{}: Noise handshake with {}",
            hop_idx + 1,
            hops.len(),
            hop.addr
        );

        let label = format!("client hop {}/{} to {}", hop_idx + 1, hops.len(), hop.addr);
        let (conn, driver) = match &hop.identity {
            HopIdentity::Ed25519(pubkey) => {
                let x25519_pub = pubkey.to_x25519()?;
                let (transport, session_id) =
                    noise::handshake_initiator(&mut stream, &x25519_pub).await?;
                let noise_stream = NoiseStream::new(stream, transport, session_id, label);
                RelayConnection::from_noise_stream(noise_stream).await?
            }
            HopIdentity::Secp256k1(pubkey) => {
                let (send_cipher, recv_cipher, session_id) =
                    noise_secp256k1::handshake_initiator(&mut stream, pubkey).await?;
                let secp_stream = noise_secp256k1::SecpNoiseStream::new(
                    stream,
                    send_cipher,
                    recv_cipher,
                    session_id,
                );
                RelayConnection::from_transport_stream(secp_stream, session_id).await?
            }
        };

        info!(
            "hop {}/{}: H2 connection established",
            hop_idx + 1,
            hops.len()
        );

        if hop_idx < hops.len() - 1 {
            let hop_label = format!("hop {}/{} to {}", hop_idx + 1, hops.len(), hop.addr);
            let (control_task, ready_rx) =
                control::start_control_task(&conn, INTERMEDIATE_FAKE_PAYMENT_MILLISATS, &hop_label)
                    .await?;
            ready_rx.await.map_err(|_| {
                io::Error::new(
                    io::ErrorKind::BrokenPipe,
                    format!("control task exited before hop {} was funded", hop.addr),
                )
            })?;

            // Not the last hop — open a CONNECT tunnel to the next hop
            let next = &hops[hop_idx + 1];
            info!(
                "hop {}/{}: opening CONNECT tunnel to next hop {}",
                hop_idx + 1,
                hops.len(),
                next.addr
            );

            // Open the CONNECT tunnel, with QUIC pin if the next hop uses QUIC
            let h2_connect_stream = if next.use_quic {
                match &next.identity {
                    HopIdentity::Ed25519(pubkey) => {
                        let spki = pubkey.to_spki_der();
                        conn.open_tunnel_quic(&next.addr, &spki).await?
                    }
                    HopIdentity::Secp256k1(pubkey) => {
                        conn.open_tunnel_quic_secp256k1(&next.addr, &pubkey.to_hex())
                            .await?
                    }
                }
            } else {
                if matches!(next.identity, HopIdentity::Secp256k1(_)) {
                    return Err(io::Error::new(
                        io::ErrorKind::Unsupported,
                        "secp256k1 transport hops currently require QUIC",
                    ));
                }
                conn.open_tunnel(&next.addr).await?
            };

            // Recurse: perform Noise + H2 over this tunnel for the next hop.
            // Attach this hop's driver to the final connection.
            let mut next_conn = chain_from_stream(h2_connect_stream, &hops, hop_idx + 1).await?;
            next_conn.add_driver(driver);
            next_conn.add_task(control_task);
            Ok(next_conn)
        } else {
            // Last hop — attach the driver and return for actual use
            let mut conn = conn;
            conn.add_driver(driver);
            info!("tunnel chain established ({} hops)", hops.len());
            Ok(conn)
        }
    }) // close Box::pin(async move { ... })
}
