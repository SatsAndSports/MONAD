//! Opens an H2 CONNECT tunnel through the relay and proxies data bidirectionally
//! between a local TCP socket and the H2 stream.

use crate::socks;
use crate::socks_diagnostics::{SocksDiagnostic, SocksReplyMode};
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
    open_tunnel_with_reply_mode(
        conn,
        target_authority,
        local_stream,
        SocksReplyMode::Standard,
    )
    .await
}

/// Open a tunnel with the mode returned by SOCKS method negotiation.
pub async fn open_tunnel_with_reply_mode(
    conn: &RelayConnection,
    target_authority: &str,
    local_stream: &mut TcpStream,
    reply_mode: SocksReplyMode,
) -> io::Result<()> {
    open_tunnel_observed(conn, target_authority, local_stream, None, reply_mode).await
}

pub(crate) async fn open_tunnel_observed(
    conn: &RelayConnection,
    target_authority: &str,
    local_stream: &mut TcpStream,
    management: Option<&crate::management::ClientManagement>,
    reply_mode: SocksReplyMode,
) -> io::Result<()> {
    let setup = async {
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
            .map_err(|e| {
                io::Error::new(io::ErrorKind::InvalidInput, format!("bad request: {e}"))
            })?;

        // Send the CONNECT request
        let (response_future, h2_send) = h2_client
            .send_request(request, false)
            .map_err(|e| io::Error::other(format!("h2 send error: {e}")))?;

        // Wait for the relay's response
        let response = response_future
            .await
            .map_err(|e| io::Error::other(format!("h2 response error: {e}")))?;
        Ok::<_, io::Error>((h2_send, response))
    }
    .await;
    let (h2_send, response) = match setup {
        Ok(setup) => setup,
        Err(error) => {
            let mut diagnostic = SocksDiagnostic::connect_failure(&error, None);
            if let Some(context) = &mut diagnostic.context {
                context.target_hop = conn.route_hop();
            }
            if let Some(management) = management {
                management.note_exit_result(
                    conn.session_id(),
                    target_authority,
                    Some(&error),
                    Some(&diagnostic),
                );
            }
            let _ = socks::send_failure(local_stream, reply_mode, 0x01, &diagnostic).await;
            return Err(error);
        }
    };

    if !response.status().is_success() {
        let error = monad_common::rejection::connect_error(response.status(), response.headers());
        let mut diagnostic =
            SocksDiagnostic::connect_failure(&error, Some(response.status().as_u16()));
        if let Some(context) = &mut diagnostic.context {
            context.reporting_hop = conn.route_hop();
        }
        if let Some(management) = management {
            management.note_exit_result(
                conn.session_id(),
                target_authority,
                Some(&error),
                Some(&diagnostic),
            );
        }
        let reply = crate::socks_diagnostics::socks_reply_code(&error);
        let _ = socks::send_failure(local_stream, reply_mode, reply, &diagnostic).await;
        return Err(error);
    }

    info!("tunnel established to {target_authority}");
    if let Some(management) = management {
        management.note_exit_result(conn.session_id(), target_authority, None, None);
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
