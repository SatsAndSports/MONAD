//! Bidirectional proxy between an H2 stream and an external TCP connection.
//!
//! When the server receives a CONNECT request, it opens a TCP connection to the
//! target and then copies bytes bidirectionally between the H2 stream and the
//! external socket.

use bytes::Bytes;
use h2::RecvStream;
use h2::SendStream;
use std::io;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tracing::debug;

/// Proxy bytes bidirectionally between an H2 send/recv stream pair and an
/// external TCP connection.
///
/// This runs until either side closes or an error occurs.
pub async fn proxy_bidirectional(
    mut h2_send: SendStream<Bytes>,
    mut h2_recv: RecvStream,
    target: TcpStream,
) -> io::Result<()> {
    let (mut tcp_read, mut tcp_write) = target.into_split();

    // H2 recv -> TCP write (data from client going to external target)
    let h2_to_tcp = async {
        loop {
            match h2_recv.data().await {
                Some(Ok(data)) => {
                    // Release H2 flow control capacity
                    let len = data.len();
                    let _ = h2_recv.flow_control().release_capacity(len);

                    if let Err(e) = tcp_write.write_all(&data).await {
                        debug!("tcp write error: {e}");
                        break;
                    }
                }
                Some(Err(e)) => {
                    debug!("h2 recv error: {e}");
                    break;
                }
                None => {
                    // H2 stream closed (client done sending)
                    debug!("h2 recv stream ended");
                    break;
                }
            }
        }
        let _ = tcp_write.shutdown().await;
    };

    // TCP read -> H2 send (data from external target going to client)
    let tcp_to_h2 = async {
        let mut buf = vec![0u8; 16384];
        loop {
            match tcp_read.read(&mut buf).await {
                Ok(0) => {
                    debug!("tcp read EOF");
                    break;
                }
                Ok(n) => {
                    let data = Bytes::copy_from_slice(&buf[..n]);

                    // Reserve capacity on the H2 stream before sending
                    h2_send.reserve_capacity(data.len());

                    // Wait for capacity to be available
                    match futures_poll_capacity(&mut h2_send).await {
                        Ok(()) => {}
                        Err(e) => {
                            debug!("h2 capacity error: {e}");
                            break;
                        }
                    }

                    if let Err(e) = h2_send.send_data(data, false) {
                        debug!("h2 send error: {e}");
                        break;
                    }
                }
                Err(e) => {
                    debug!("tcp read error: {e}");
                    break;
                }
            }
        }
        // Send empty frame with END_STREAM to signal we're done
        let _ = h2_send.send_data(Bytes::new(), true);
    };

    tokio::select! {
        _ = h2_to_tcp => {},
        _ = tcp_to_h2 => {},
    }

    Ok(())
}

/// Wait for H2 send capacity to be available.
async fn futures_poll_capacity(send: &mut SendStream<Bytes>) -> Result<(), h2::Error> {
    loop {
        match send.capacity() {
            0 => {
                // No capacity yet — yield and try again
                tokio::task::yield_now().await;
            }
            _ => return Ok(()),
        }
    }
}
