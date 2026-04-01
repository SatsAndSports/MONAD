//! Establishes a connection to a MONAD server, optionally through a chain
//! of intermediate hops (onion routing / nested tunneling).
//!
//! Single hop:   TCP → Noise(S) → H2
//! Two hops:     TCP → Noise(T) → H2 → CONNECT(S) → Noise(S) → H2
//! N hops:       Each hop wraps the previous one via H2ConnectStream.

use bytes::Bytes;
use h2::client;
use http::{Method, Request, Uri};
use monad_common::h2stream::H2ConnectStream;
use monad_common::identity;
use monad_common::noise::{self, NoiseStream};
use monad_quic::stream::QuicStream;
use std::io;
use std::sync::Arc;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::TcpStream;
use tokio::task::JoinHandle;
use tracing::info;

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
    /// Ed25519 public key (32 bytes) — the server's unified identity.
    pub pubkey: Vec<u8>,
    /// Whether the previous relay should connect to this hop via QUIC.
    pub use_quic: bool,
}

/// An established connection to a MONAD server, ready to open H2 streams.
pub struct ServerConnection {
    /// The H2 client send handle — use this to open new streams (CONNECT, etc.)
    pub h2_client: Arc<tokio::sync::Mutex<client::SendRequest<Bytes>>>,
    /// Background tasks driving the H2 connection(s) in the hop chain.
    pub driver_handles: Vec<JoinHandle<()>>,
}

impl ServerConnection {
    /// Shut down the hop chain cleanly by dropping the shared H2 client handle
    /// and waiting for all per-hop H2 driver tasks to exit.
    pub async fn shutdown(self) {
        drop(self.h2_client);

        for handle in self.driver_handles {
            if let Err(e) = handle.await {
                tracing::error!("H2 driver task panicked: {e}");
            }
        }
    }
}

/// Connect to a MONAD server directly (single hop).
///
/// Equivalent to `connect_through_chain(&[hop])`.
#[allow(dead_code)]
pub async fn connect(server_addr: &str, server_pubkey: &[u8]) -> io::Result<ServerConnection> {
    connect_through_chain(&[Hop {
        addr: server_addr.to_string(),
        pubkey: server_pubkey.to_vec(),
        use_quic: false,
    }])
    .await
}

/// Connect to a MONAD server through a chain of hops.
///
/// `hops` must have at least one entry. The first hop is connected to via TCP.
/// Each subsequent hop is reached by opening an H2 CONNECT tunnel through the
/// previous hop. The returned `ServerConnection` is for the *last* hop in the chain.
///
/// Example with 2 hops [T, S]:
///   TCP → Noise(T) → H2 → CONNECT(S:port) → Noise(S) → H2 → (returned client)
///
/// T only sees encrypted Noise bytes. It has no idea that inside those bytes
/// is another MONAD session asking S to proxy onward.
pub async fn connect_through_chain(hops: &[Hop]) -> io::Result<ServerConnection> {
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

        let ed25519_pub: [u8; 32] = first.pubkey.as_slice().try_into().map_err(|_| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                format!("public key must be 32 bytes, got {}", first.pubkey.len()),
            )
        })?;
        let pinned_spki = identity::ed25519_pubkey_to_spki_der(&ed25519_pub);

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
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = io::Result<ServerConnection>> + Send>>
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
    let ed25519_pub: [u8; 32] = hop.pubkey.as_slice().try_into().map_err(|_| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            format!("public key must be 32 bytes, got {}", hop.pubkey.len()),
        )
    })?;
    let x25519_pub = identity::ed25519_pubkey_to_x25519_pubkey(&ed25519_pub)?;

    // Noise NK handshake with this hop
    let transport = noise::handshake_initiator(&mut stream, &x25519_pub).await?;
    let label = format!("client hop {}/{} to {}", hop_idx + 1, hops.len(), hop.addr);
    let noise_stream = NoiseStream::new(stream, transport, label);

    // H2 handshake over the encrypted stream
    let (h2_client, h2_conn) = client::handshake(noise_stream)
        .await
        .map_err(|e| io::Error::new(io::ErrorKind::Other, format!("h2 handshake error: {e}")))?;

    info!("hop {}/{}: H2 connection established", hop_idx + 1, hops.len());

    // Spawn background task to drive this H2 connection
    let driver_handle = tokio::spawn(async move {
        if let Err(e) = h2_conn.await {
            tracing::error!("H2 connection error at hop: {e}");
        }
    });

    if hop_idx < hops.len() - 1 {
        // Not the last hop — open a CONNECT tunnel to the next hop
        let next = &hops[hop_idx + 1];
        info!(
            "hop {}/{}: opening CONNECT tunnel to next hop {}",
            hop_idx + 1,
            hops.len(),
            next.addr
        );

        // If the next hop uses QUIC, compute the SPKI DER for the quic-pin header
        let quic_pin = if next.use_quic {
            let next_ed25519: [u8; 32] = next.pubkey.as_slice().try_into().map_err(|_| {
                io::Error::new(
                    io::ErrorKind::InvalidData,
                    "next hop public key must be 32 bytes",
                )
            })?;
            Some(identity::ed25519_pubkey_to_spki_der(&next_ed25519))
        } else {
            None
        };

        let h2_connect_stream =
            open_h2_connect(h2_client, &next.addr, quic_pin.as_deref()).await?;

        // Recurse: perform Noise + H2 over this tunnel for the next hop
        let mut conn = chain_from_stream(h2_connect_stream, &hops, hop_idx + 1).await?;
        conn.driver_handles.push(driver_handle);
        Ok(conn)
    } else {
        // Last hop — return the H2 client for actual use
        info!("tunnel chain established ({} hops)", hops.len());
        Ok(ServerConnection {
            h2_client: Arc::new(tokio::sync::Mutex::new(h2_client)),
            driver_handles: vec![driver_handle],
        })
    }
    }) // close Box::pin(async move { ... })
}

/// Open an H2 CONNECT tunnel to the given target authority, returning
/// an `H2ConnectStream` that implements `AsyncRead + AsyncWrite`.
///
/// If `quic_pin` is provided, a `quic-pin` header is added to the CONNECT
/// request, telling the relay to use QUIC transport to reach the target.
async fn open_h2_connect(
    mut h2_client: client::SendRequest<Bytes>,
    target_authority: &str,
    quic_pin: Option<&[u8]>,
) -> io::Result<H2ConnectStream> {
    let uri: Uri = target_authority
        .parse()
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, format!("bad URI: {e}")))?;

    let mut builder = Request::builder()
        .method(Method::CONNECT)
        .uri(uri);

    if let Some(pin) = quic_pin {
        builder = builder.header("quic-pin", hex::encode(pin));
    }

    let request = builder
        .body(())
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, format!("bad request: {e}")))?;

    let (response_future, h2_send) = h2_client
        .send_request(request, false)
        .map_err(|e| io::Error::new(io::ErrorKind::Other, format!("h2 send error: {e}")))?;

    let response = response_future
        .await
        .map_err(|e| io::Error::new(io::ErrorKind::Other, format!("h2 response error: {e}")))?;

    if !response.status().is_success() {
        return Err(io::Error::new(
            io::ErrorKind::ConnectionRefused,
            format!("CONNECT rejected: {}", response.status()),
        ));
    }

    let h2_recv = response.into_body();
    Ok(H2ConnectStream::new(h2_send, h2_recv))
}
