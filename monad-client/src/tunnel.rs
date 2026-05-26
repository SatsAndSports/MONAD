//! Opens an H2 CONNECT tunnel through the server and proxies data bidirectionally
//! between a local TCP socket and the H2 stream.

use crate::socks;
use bytes::Bytes;
use h2::client::SendRequest;
use http::{Method, Request, Uri};
use monad_common::proxy::proxy_bidirectional;
use std::io;
use tokio::net::TcpStream;
use tracing::info;

/// Open a tunnel to `target_authority` (e.g., "example.com:443") through the MONAD server
/// and proxy data bidirectionally between the local `client_stream` and the remote target.
///
/// Sends the SOCKS5 success reply to the local client before starting the proxy.
/// On completion, logs the total proxied bytes in each direction.
pub async fn open_tunnel(
    mut h2_client: SendRequest<Bytes>,
    target_authority: &str,
    local_stream: &mut TcpStream,
) -> io::Result<()> {
    info!("opening tunnel to {target_authority}");

    // Build the CONNECT request
    let uri: Uri = target_authority
        .parse()
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, format!("bad URI: {e}")))?;

    let request = Request::builder()
        .method(Method::CONNECT)
        .uri(uri)
        .body(())
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, format!("bad request: {e}")))?;

    // Send the CONNECT request
    let (response_future, h2_send) = h2_client
        .send_request(request, false)
        .map_err(|e| io::Error::other(format!("h2 send error: {e}")))?;

    // Wait for the server's response
    let response = response_future
        .await
        .map_err(|e| io::Error::other(format!("h2 response error: {e}")))?;

    if !response.status().is_success() {
        return Err(io::Error::new(
            io::ErrorKind::ConnectionRefused,
            format!("server rejected CONNECT: {}", response.status()),
        ));
    }

    info!("tunnel established to {target_authority}");

    // Send SOCKS5 success reply to local client
    socks::send_reply(local_stream, 0x00, "0.0.0.0", 0).await?;

    let h2_recv = response.into_body();

    // Proxy data bidirectionally between the H2 stream and the local socket.
    // `&mut TcpStream` implements AsyncRead + AsyncWrite, so the shared proxy
    // function works directly without transferring ownership.
    proxy_bidirectional(h2_send, h2_recv, &mut *local_stream, target_authority).await
}
