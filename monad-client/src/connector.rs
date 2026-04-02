//! Establishes a connection to a MONAD server, optionally through a chain
//! of intermediate hops (onion routing / nested tunneling).
//!
//! Single hop:   TCP → Noise(S) → H2
//! Two hops:     TCP → Noise(T) → H2 → CONNECT(S) → Noise(S) → H2
//! N hops:       Each hop wraps the previous one via H2ConnectStream.

use crate::control;
use monad_common::identity::Ed25519Pubkey;
use monad_common::noise::{self, NoiseStream};
use monad_common::session::RelayConnection;
use monad_quic::stream::QuicStream;
use std::io;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::TcpStream;
use tracing::info;

const INTERMEDIATE_FAKE_PAYMENT_MILLISATS: u64 = 10_000_000;

/// A hop in the tunnel chain: server address and its Ed25519 public key.
///
/// The Ed25519 public key is the server's unified identity. The X25519 public
/// key for Noise and the SPKI DER for QUIC pinning are derived from it
/// automatically.
///
/// If `use_quic` is true, the previous relay in the chain will connect to this
/// hop via QUIC instead of TCP.
#[derive(Debug, Clone)]
pub struct Hop {
    pub addr: String,
    /// Ed25519 public key — the server's unified identity.
    pub pubkey: Ed25519Pubkey,
    /// Whether the previous relay should connect to this hop via QUIC.
    pub use_quic: bool,
}

/// Connect to a MONAD server directly (single hop).
///
/// Equivalent to `connect_through_chain(&[hop])`.
#[allow(dead_code)]
pub async fn connect(server_addr: &str, server_pubkey: Ed25519Pubkey) -> io::Result<RelayConnection> {
    connect_through_chain(&[Hop {
        addr: server_addr.to_string(),
        pubkey: server_pubkey,
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

    if first.use_quic {
        // Connect to the first hop via QUIC
        info!("connecting to first hop via QUIC: {}", first.addr);

        let pinned_spki = first.pubkey.to_spki_der();

        let client_config =
            monad_quic::client::build_client_config(pinned_spki).map_err(|e| {
                io::Error::new(
                    io::ErrorKind::Other,
                    format!("failed to build QUIC client config: {e}"),
                )
            })?;

        // Resolve the target address
        let socket_addr = tokio::net::lookup_host(&first.addr)
            .await?
            .next()
            .ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::Other,
                    format!("no addresses found for {}", first.addr),
                )
            })?;

        let mut endpoint = quinn::Endpoint::client("0.0.0.0:0".parse().unwrap())
            .map_err(|e| io::Error::new(io::ErrorKind::Other, format!("QUIC endpoint: {e}")))?;
        endpoint.set_default_client_config(client_config);

        let conn = endpoint
            .connect(socket_addr, "monad-relay")
            .map_err(|e| io::Error::new(io::ErrorKind::Other, format!("QUIC connect: {e}")))?
            .await
            .map_err(|e| {
                io::Error::new(
                    io::ErrorKind::ConnectionRefused,
                    format!("QUIC handshake failed with {}: {e}", first.addr),
                )
            })?;

        let (send, recv) = conn.open_bi().await.map_err(|e| {
            io::Error::new(
                io::ErrorKind::Other,
                format!("failed to open QUIC stream: {e}"),
            )
        })?;
        let quic_stream = QuicStream::new(send, recv);
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

    // Derive X25519 public key from the Ed25519 public key for Noise
    let x25519_pub = hop.pubkey.to_x25519()?;

    // Noise NK handshake with this hop
    let (transport, session_id) = noise::handshake_initiator(&mut stream, &x25519_pub).await?;
    let label = format!("client hop {}/{} to {}", hop_idx + 1, hops.len(), hop.addr);
    let noise_stream = NoiseStream::new(stream, transport, session_id, label);

    // H2 handshake over the encrypted stream
    let (conn, driver) = RelayConnection::from_noise_stream(noise_stream).await?;

    info!("hop {}/{}: H2 connection established", hop_idx + 1, hops.len());

    if hop_idx < hops.len() - 1 {
        let (control_task, ready_rx) =
            control::start_fake_payment_controller(&conn, INTERMEDIATE_FAKE_PAYMENT_MILLISATS)
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
            let spki = next.pubkey.to_spki_der();
            conn.open_tunnel_quic(&next.addr, &spki).await?
        } else {
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
