//! Opens an H2 CONNECT tunnel through the server and proxies data bidirectionally
//! between a local TCP socket and the H2 stream.

use crate::socks;
use bytes::Bytes;
use h2::client::SendRequest;
use http::{Method, Request, Uri};
use std::io;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tracing::{debug, info};

/// Open a tunnel to `target_authority` (e.g., "example.com:443") through the PaidTor server
/// and proxy data bidirectionally between the local `client_stream` and the remote target.
///
/// Sends the SOCKS5 success reply to the local client before starting the proxy.
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
    let (response_future, mut h2_send) = h2_client
        .send_request(request, false)
        .map_err(|e| io::Error::new(io::ErrorKind::Other, format!("h2 send error: {e}")))?;

    // Wait for the server's response
    let response = response_future
        .await
        .map_err(|e| io::Error::new(io::ErrorKind::Other, format!("h2 response error: {e}")))?;

    if !response.status().is_success() {
        return Err(io::Error::new(
            io::ErrorKind::ConnectionRefused,
            format!("server rejected CONNECT: {}", response.status()),
        ));
    }

    info!("tunnel established to {target_authority}");

    // Send SOCKS5 success reply to local client
    socks::send_reply(local_stream, 0x00, "0.0.0.0", 0).await?;

    let mut h2_recv = response.into_body();

    // Split the local stream for bidirectional I/O.
    // We need to take ownership, so we use a trick: swap with a dummy and split.
    // Actually, since we have &mut TcpStream, we can use split() (borrowed version).
    let (mut local_read, mut local_write) = tokio::io::split(local_stream);

    // Local -> H2 (data from local app going to remote target via server)
    let local_to_h2 = async {
        let mut buf = vec![0u8; 16384];
        loop {
            match local_read.read(&mut buf).await {
                Ok(0) => {
                    debug!("local read EOF");
                    break;
                }
                Ok(n) => {
                    let data = Bytes::copy_from_slice(&buf[..n]);

                    // Reserve capacity and wait for it
                    h2_send.reserve_capacity(data.len());
                    loop {
                        if h2_send.capacity() > 0 {
                            break;
                        }
                        tokio::task::yield_now().await;
                    }

                    if let Err(e) = h2_send.send_data(data, false) {
                        debug!("h2 send error: {e}");
                        break;
                    }
                }
                Err(e) => {
                    debug!("local read error: {e}");
                    break;
                }
            }
        }
        let _ = h2_send.send_data(Bytes::new(), true);
    };

    // H2 -> Local (data from remote target coming through server to local app)
    let h2_to_local = async {
        loop {
            match h2_recv.data().await {
                Some(Ok(data)) => {
                    let len = data.len();
                    let _ = h2_recv.flow_control().release_capacity(len);

                    if let Err(e) = local_write.write_all(&data).await {
                        debug!("local write error: {e}");
                        break;
                    }
                }
                Some(Err(e)) => {
                    debug!("h2 recv error: {e}");
                    break;
                }
                None => {
                    debug!("h2 recv stream ended");
                    break;
                }
            }
        }
        let _ = local_write.shutdown().await;
    };

    // Run both directions to completion (not select!) so that when the local
    // app finishes sending, we still receive the full response from the remote.
    tokio::join!(local_to_h2, h2_to_local);

    Ok(())
}
