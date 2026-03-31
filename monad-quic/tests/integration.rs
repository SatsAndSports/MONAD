use std::net::SocketAddr;
use anyhow::{Context, Result};
use quinn::Endpoint;
use rand::RngCore;

/// Helper: generate key material, start a QUIC echo server on a random port,
/// return the server endpoint (to keep it alive) and the connect address + pin.
async fn start_echo_server() -> Result<(Endpoint, SocketAddr, String)> {
    let km = monad_quic::keygen::generate()?;
    let server_config = monad_quic::server::build_server_config(&km.cert_pem, &km.key_pem)?;

    // Bind to 127.0.0.1:0 to get a random port
    let endpoint = Endpoint::server(server_config, "127.0.0.1:0".parse()?)?;
    let listen_addr = endpoint.local_addr()?;

    // Spawn the accept loop
    let ep = endpoint.clone();
    tokio::spawn(async move {
        while let Some(incoming) = ep.accept().await {
            tokio::spawn(async move {
                let conn = match incoming.await {
                    Ok(c) => c,
                    Err(_) => return,
                };
                loop {
                    match conn.accept_bi().await {
                        Ok((mut send, mut recv)) => {
                            tokio::spawn(async move {
                                let mut buf = vec![0u8; 64 * 1024];
                                loop {
                                    match recv.read(&mut buf).await {
                                        Ok(Some(n)) => {
                                            if send.write_all(&buf[..n]).await.is_err() {
                                                return;
                                            }
                                        }
                                        _ => break,
                                    }
                                }
                                let _ = send.finish();
                            });
                        }
                        Err(_) => break,
                    }
                }
            });
        }
    });

    Ok((endpoint, listen_addr, km.pin_hex))
}

/// Helper: connect a client to the server, open `num_streams` bidirectional
/// streams, send `bytes_per_stream` random bytes on each, read the echo,
/// and verify correctness. Returns the number of successful streams.
async fn run_echo_client(
    connect: SocketAddr,
    pin_hex: &str,
    num_streams: usize,
    bytes_per_stream: usize,
) -> Result<usize> {
    let pinned_spki = hex::decode(pin_hex).context("invalid pin hex")?;
    let client_config = monad_quic::client::build_client_config(pinned_spki)?;

    let mut endpoint = Endpoint::client("0.0.0.0:0".parse()?)?;
    endpoint.set_default_client_config(client_config);

    let conn = endpoint
        .connect(connect, "monad-relay")?
        .await
        .context("failed to connect")?;

    let mut handles = Vec::with_capacity(num_streams);
    for i in 0..num_streams {
        let conn = conn.clone();
        handles.push(tokio::spawn(async move {
            echo_one_stream(conn, i, bytes_per_stream).await
        }));
    }

    let mut ok_count = 0usize;
    for handle in handles {
        if let Ok(Ok(())) = handle.await {
            ok_count += 1;
        }
    }

    conn.close(0u32.into(), b"done");
    endpoint.wait_idle().await;

    Ok(ok_count)
}

async fn echo_one_stream(
    conn: quinn::Connection,
    _index: usize,
    bytes_per_stream: usize,
) -> Result<()> {
    let (mut send, mut recv) = conn.open_bi().await.context("failed to open stream")?;

    let mut payload = vec![0u8; bytes_per_stream];
    rand::rng().fill_bytes(&mut payload);

    send.write_all(&payload).await?;
    send.finish()?;

    let echoed = recv
        .read_to_end(bytes_per_stream + 1)
        .await
        .context("failed to read echo")?;

    assert_eq!(echoed.len(), payload.len(), "echo length mismatch");
    assert_eq!(echoed, payload, "echo data mismatch");

    Ok(())
}

// ── Tests ──────────────────────────────────────────────────────────────

#[tokio::test]
async fn test_basic_echo_4_streams() {
    let (_server, addr, pin) = start_echo_server().await.unwrap();
    let ok = run_echo_client(addr, &pin, 4, 65536).await.unwrap();
    assert_eq!(ok, 4, "expected all 4 streams to succeed");
}

#[tokio::test]
async fn test_wrong_pin_rejected() {
    let (_server, addr, _pin) = start_echo_server().await.unwrap();
    let wrong_pin = "302a300506032b6570032100\
                     aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    let result = run_echo_client(addr, wrong_pin, 1, 64).await;
    assert!(result.is_err(), "connection with wrong pin should fail");
}

#[tokio::test]
async fn test_1000_concurrent_streams() {
    let (_server, addr, pin) = start_echo_server().await.unwrap();
    let ok = run_echo_client(addr, &pin, 1000, 4096).await.unwrap();
    assert_eq!(ok, 1000, "expected all 1000 streams to succeed");
}

#[tokio::test]
async fn test_large_payload_single_stream() {
    let (_server, addr, pin) = start_echo_server().await.unwrap();
    // 4 MB on a single stream
    let ok = run_echo_client(addr, &pin, 1, 4 * 1024 * 1024).await.unwrap();
    assert_eq!(ok, 1, "expected single large-payload stream to succeed");
}

#[tokio::test]
async fn test_multiple_connections() {
    let (_server, addr, pin) = start_echo_server().await.unwrap();

    // Open 3 separate connections, each with 10 streams
    let mut handles = Vec::new();
    for _ in 0..3 {
        let addr = addr;
        let pin = pin.clone();
        handles.push(tokio::spawn(async move {
            run_echo_client(addr, &pin, 10, 8192).await
        }));
    }

    for handle in handles {
        let ok = handle.await.unwrap().unwrap();
        assert_eq!(ok, 10, "expected all 10 streams per connection to succeed");
    }
}
