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
use monad_common::noise::{self, NoiseStream};
use std::io;
use std::sync::Arc;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::TcpStream;
use tokio::task::JoinHandle;
use tracing::info;

/// A hop in the tunnel chain: server address and its Noise public key.
///
/// If `quic_pin` is set, the previous relay in the chain will connect to this
/// hop via QUIC instead of TCP, using the pinned public key to authenticate it.
#[derive(Debug, Clone)]
pub struct Hop {
    pub addr: String,
    pub pubkey: Vec<u8>,
    /// Optional QUIC pinned public key (SPKI DER, hex-decoded).
    /// When set, the CONNECT request to this hop includes a `quic-pin` header
    /// so the preceding relay uses QUIC transport.
    pub quic_pin: Option<Vec<u8>>,
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
        quic_pin: None,
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

    // Connect to the first hop via TCP
    let first = &hops[0];
    info!("connecting to first hop: {}", first.addr);
    let tcp_stream = TcpStream::connect(&first.addr).await?;
    info!("TCP connected to {}", first.addr);

    // Perform Noise + H2 on the first hop, then chain through the rest
    chain_from_stream(tcp_stream, hops, 0).await
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

    // Noise NK handshake with this hop
    let transport = noise::handshake_initiator(&mut stream, &hop.pubkey).await?;
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

        let h2_connect_stream =
            open_h2_connect(h2_client, &next.addr, next.quic_pin.as_deref()).await?;

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
