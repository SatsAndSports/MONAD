//! Opens an H2 CONNECT tunnel through the relay and proxies data bidirectionally
//! between a local TCP socket and the H2 stream.

use crate::socks;
use http::{Method, Request, Uri};
use monad_common::network_endpoint::validate_network_endpoint;
use monad_common::proxy::proxy_bidirectional_from_client;
use monad_common::session::RelayConnection;
use std::io;
use tokio::net::TcpStream;
use tracing::info;

/// Open a tunnel to `target_authority` (e.g., "example.com:443") through the MONAD relay
/// and proxy data bidirectionally between the local `client_stream` and the remote target.
///
/// Sends the SOCKS5 success reply to the local client before starting the proxy.
/// On completion, logs the total proxied bytes in each direction.
pub async fn open_tunnel(
    conn: &RelayConnection,
    target_authority: &str,
    local_stream: &mut TcpStream,
) -> io::Result<()> {
    open_tunnel_observed(conn, target_authority, local_stream, None).await
}

pub(crate) async fn open_tunnel_observed(
    conn: &RelayConnection,
    target_authority: &str,
    local_stream: &mut TcpStream,
    management: Option<&crate::management::ClientManagement>,
) -> io::Result<()> {
    validate_network_endpoint(target_authority)?;
    info!("opening tunnel to {target_authority}");
    let mut h2_client = conn.clone_send_request().await;

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

    // Wait for the relay's response
    let response = response_future
        .await
        .map_err(|e| io::Error::other(format!("h2 response error: {e}")))?;

    if !response.status().is_success() {
        let error = monad_common::rejection::connect_error(response.status(), response.headers());
        if let Some(management) = management {
            management.note_exit_result(conn.session_id(), target_authority, Some(&error));
        }
        let reply = if monad_common::rejection::Rejection::from_io(&error).is_some_and(|r| {
            r.code == monad_common::rejection::RejectionCode::DestinationPolicyDenied
        }) {
            0x02
        } else {
            0x05
        };
        let _ = socks::send_reply(local_stream, reply, "0.0.0.0", 0).await;
        return Err(error);
    }

    info!("tunnel established to {target_authority}");
    if let Some(management) = management {
        management.note_exit_result(conn.session_id(), target_authority, None);
    }

    // Send SOCKS5 success reply to local client
    socks::send_reply(local_stream, 0x00, "0.0.0.0", 0).await?;

    let h2_recv = response.into_body();

    // Proxy data bidirectionally between the H2 stream and the local socket.
    // `&mut TcpStream` implements AsyncRead + AsyncWrite, so the shared proxy
    // function works directly without transferring ownership.
    proxy_bidirectional_from_client(
        h2_send,
        h2_recv,
        &mut *local_stream,
        target_authority,
        Some(conn.cleartext_byte_counters()),
    )
    .await
}
