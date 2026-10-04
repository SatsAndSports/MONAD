use bytes::{Buf, Bytes};
use http::{Method, Request, Response};
use std::future::poll_fn;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

const INITIAL_WINDOW: usize = 65_535;

async fn echo_server(listener: TcpListener) {
    let (mut stream, _) = listener.accept().await.unwrap();
    let mut buf = [0u8; 4096];
    loop {
        match stream.read(&mut buf).await {
            Ok(0) | Err(_) => break,
            Ok(n) => {
                if stream.write_all(&buf[..n]).await.is_err() {
                    break;
                }
            }
        }
    }
}

/// A request body that the server has stopped consuming may retain its entire
/// stream-level receive window, but it must not retain the connection-level
/// receive window needed by another stream.
#[tokio::test]
async fn default_receive_accounting_still_blocks_shared_connection_window() {
    let echo = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let echo_addr = echo.local_addr().unwrap();
    tokio::spawn(echo_server(echo));

    let (client_io, server_io) = tokio::io::duplex(4096);
    let (mut client, client_connection) = h2::client::Builder::new()
        .handshake(client_io)
        .await
        .unwrap();
    let client_driver = tokio::spawn(async move {
        let _ = client_connection.await;
    });

    let server = h2::server::handshake(server_io).await.unwrap();
    let server_driver = tokio::spawn(async move {
        let mut server = server;
        let mut proxy: Option<tokio::task::JoinHandle<()>> = None;
        while let Some(Ok((request, mut respond))) = server.accept().await {
            let recv = request.into_body();
            let send = respond.send_response(Response::new(()), false).unwrap();
            proxy = Some(tokio::spawn(async move {
                let mut recv = recv;
                let mut send = send;
                let target = tokio::net::TcpStream::connect(echo_addr).await.unwrap();
                let mut consumed = 0usize;
                let (mut target_read, mut target_write) = tokio::io::split(target);
                let h2_to_target = async {
                    while let Some(chunk) = recv.data().await {
                        let data = chunk.unwrap();
                        consumed += data.len();
                        if consumed > 5 {
                            std::future::pending::<()>().await;
                        }
                        recv.flow_control().release_capacity(data.len()).unwrap();
                        if target_write.write_all(&data).await.is_err() {
                            return Err(());
                        }
                    }
                    let _ = target_write.shutdown().await;
                    Ok::<(), ()>(())
                };
                let target_to_h2 = async {
                    let mut buf = [0u8; 4096];
                    while let Ok(n) = target_read.read(&mut buf).await {
                        if n == 0 {
                            break;
                        }
                        send.reserve_capacity(n);
                        let _ = poll_fn(|cx| send.poll_capacity(cx)).await;
                        let _ = send.send_data(Bytes::copy_from_slice(&buf[..n]), false);
                    }
                    let _ = send.send_data(Bytes::new(), true);
                    Ok::<(), ()>(())
                };
                let _ = tokio::try_join!(h2_to_target, target_to_h2);
            }));
        }
        if let Some(proxy) = proxy {
            let _ = proxy.await;
        }
    });

    let (proxy_response, mut proxy_send) = client
        .send_request(
            Request::builder()
                .method(Method::POST)
                .uri("http://monad/proxy")
                .body(())
                .unwrap(),
            false,
        )
        .unwrap();
    let mut proxy_recv = proxy_response.await.unwrap().into_body();
    proxy_send.reserve_capacity(5);
    poll_fn(|cx| proxy_send.poll_capacity(cx)).await.unwrap().unwrap();
    proxy_send.send_data(Bytes::from_static(b"12345"), false).unwrap();
    let initial = tokio::time::timeout(Duration::from_secs(2), proxy_recv.data())
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    assert_eq!(initial, Bytes::from_static(b"12345"));
    proxy_recv
        .flow_control()
        .release_capacity(initial.len())
        .unwrap();

    for _ in 0..4 {
        proxy_send
            .send_data(Bytes::from(vec![0; 16_383]), false)
            .unwrap();
    }
    proxy_send.send_data(Bytes::from_static(b"6"), false).unwrap();
    tokio::time::sleep(Duration::from_millis(50)).await;

    let (blocked_response, mut blocked_send) = client
        .send_request(
            Request::builder()
                .method(Method::POST)
                .uri("http://monad/blocked")
                .body(())
                .unwrap(),
            false,
        )
        .unwrap();
    assert!(blocked_response.await.unwrap().status().is_success());
    blocked_send
        .send_data(Bytes::from(vec![0; INITIAL_WINDOW]), false)
        .unwrap();
    tokio::time::sleep(Duration::from_millis(50)).await;

    let still_blocked = tokio::time::timeout(Duration::from_millis(100), async {
        proxy_send.reserve_capacity(INITIAL_WINDOW);
        poll_fn(|cx| proxy_send.poll_capacity(cx)).await
    })
    .await;
    assert!(
        still_blocked.is_err(),
        "historical accounting must retain connection credit for unread DATA"
    );

    client_driver.abort();
    server_driver.abort();
    let _ = client_driver.await;
    let _ = server_driver.await;
}

#[tokio::test]
async fn blocked_request_body_does_not_starve_another_stream() {
    let _ = env_logger::try_init();
    let echo = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let echo_addr = echo.local_addr().unwrap();
    tokio::spawn(echo_server(echo));

    let (client_io, server_io) = tokio::io::duplex(4096);
    let (mut client, client_connection) = h2::client::Builder::new()
        .handshake(client_io)
        .await
        .unwrap();
    let client_driver = tokio::spawn(async move {
        let _ = client_connection.await;
    });

    let server = h2::server::Builder::new()
        .recv_release_connection_on_buffer(true)
        .handshake(server_io)
        .await
        .unwrap();
    let server_driver = tokio::spawn(async move {
        let mut server = server;
        let mut blocked: Vec<h2::RecvStream> = Vec::new();
        let mut proxy: Option<tokio::task::JoinHandle<()>> = None;

        while let Some(Ok((request, mut respond))) = server.accept().await {
            match request.uri().path() {
                "/blocked" => {
                    blocked.push(request.into_body());
                    let _ = respond.send_response(Response::new(()), false).unwrap();
                }
                "/proxy" => {
                    let recv = request.into_body();
                    let send = respond.send_response(Response::new(()), false).unwrap();
                    proxy = Some(tokio::spawn(async move {
                        let mut recv = recv;
                        let mut send = send;
                        let target = tokio::net::TcpStream::connect(echo_addr).await.unwrap();
                        let mut consumed = 0usize;
                        let (mut target_read, mut target_write) = tokio::io::split(target);
                        let h2_to_target = async {
                            let mut result = Ok(());
                            while let Some(chunk) = recv.data().await {
                                match chunk {
                                    Ok(data) => {
                                        consumed += data.len();
                                        if consumed > 5 {
                                            // Pause before releasing capacity:
                                            // the received frame remains fully
                                            // reserved on this stream.
                                            std::future::pending::<()>().await;
                                        }
                                        if data.len() > 0 {
                                            recv.flow_control()
                                                .release_capacity(data.len())
                                                .unwrap();
                                        }
                                        if target_write.write_all(&data).await.is_err() {
                                            result = Err(());
                                            break;
                                        }
                                    }
                                    Err(_) => {
                                        result = Err(());
                                        break;
                                    }
                                }
                            }
                            let _ = target_write.shutdown().await;
                            result
                        };
                        let target_to_h2 = async {
                            let mut buf = [0u8; 4096];
                            let mut result = Ok(());
                            loop {
                                match target_read.read(&mut buf).await {
                                    Ok(0) | Err(_) => break,
                                    Ok(n) => {
                                        send.reserve_capacity(n);
                                        let _ = poll_fn(|cx| send.poll_capacity(cx))
                                            .await
                                            .ok_or(())
                                            .and_then(|r| r.map_err(|_| ()))?;
                                        if send
                                            .send_data(Bytes::copy_from_slice(&buf[..n]), false)
                                            .is_err()
                                        {
                                            result = Err(());
                                            break;
                                        }
                                    }
                                }
                            }
                            let _ = send.send_data(Bytes::new(), true);
                            result
                        };
                        let _ = tokio::try_join!(h2_to_target, target_to_h2);
                    }));
                }
                _ => unreachable!(),
            }
        }

        drop(blocked);
        if let Some(proxy) = proxy {
            let _ = proxy.await;
        }
    });

    let blocked_response = client
        .send_request(
            Request::builder()
                .method(Method::POST)
                .uri("http://monad/blocked")
                .body(())
                .unwrap(),
            false,
        )
        .unwrap()
        .0
        .await
        .unwrap();
    assert!(blocked_response.status().is_success());

    let (proxy_response, mut proxy_send) = client
        .send_request(
            Request::builder()
                .method(Method::POST)
                .uri("http://monad/proxy")
                .body(())
                .unwrap(),
            false,
        )
        .unwrap();
    let mut proxy_recv = proxy_response.await.unwrap().into_body();

    proxy_send.reserve_capacity(5);
    std::future::poll_fn(|cx| proxy_send.poll_capacity(cx))
        .await
        .unwrap()
        .unwrap();
    proxy_send.send_data(Bytes::from_static(b"12345"), false).unwrap();

    // Let the server consume and release those five bytes, then block its
    // read loop. The queued DATA below fills this stream's receive window.
    let echo_seen = tokio::time::timeout(Duration::from_secs(2), async {
        let mut received = Vec::new();
        while received.len() < 5 {
            let Some(chunk) = proxy_recv.data().await else {
                panic!("proxy stream closed");
            };
            let chunk = chunk.unwrap();
            received.extend_from_slice(&chunk);
            proxy_recv.flow_control().release_capacity(chunk.len()).unwrap();
        }
        assert_eq!(received, b"12345");
    })
    .await;
    echo_seen.expect("proxy should echo the initial request bytes");
    let proxy_stalled = tokio::time::timeout(Duration::from_millis(50), async {
        let _ = proxy_recv.data().await;
    })
    .await;
    assert!(proxy_stalled.is_err(), "proxy unexpectedly completed");

    // The first queued frame makes the application pause before it releases
    // stream capacity. Queue 65,535 more bytes without respecting h2's send
    // flow-control capacity. This models bytes that were already queued when
    // a payment pause arrived; the receiver must return connection credit as
    // it buffers them even though their stream credit remains withheld.
    for _ in 0..4 {
        proxy_send
            .send_data(Bytes::from(vec![0; 16_383]), false)
            .unwrap();
    }
    proxy_send.send_data(Bytes::from_static(b"6"), false).unwrap();
    tokio::time::sleep(Duration::from_millis(50)).await;

    // A second application stream whose body is not consumed may retain a
    // full stream-level window, but the connection window must remain usable.
    let (blocked_response_2, mut blocked_send) = client
        .send_request(
            Request::builder()
                .method(Method::POST)
                .uri("http://monad/blocked")
                .body(())
                .unwrap(),
            false,
        )
        .unwrap();
    assert!(blocked_response_2.await.unwrap().status().is_success());
    let control_progress = tokio::time::timeout(Duration::from_secs(2), async {
        blocked_send
            .send_data(Bytes::from(vec![0; INITIAL_WINDOW]), false)
            .unwrap();
        tokio::time::sleep(Duration::from_millis(50)).await;
        let mut payload = Bytes::from(vec![1; INITIAL_WINDOW]);
        proxy_send.reserve_capacity(INITIAL_WINDOW);
        while payload.has_remaining() {
            let amount = payload.remaining().min(16_384);
            proxy_send
                .send_data(payload.split_to(amount), false)
                .unwrap();
        }
    })
    .await;
    control_progress.expect("blocked receive buffering must not starve active send capacity");

    // The receiver-side behavior is what matters: each buffered DATA frame
    // returns connection-level capacity while the paused application stream
    // keeps its stream-level capacity reserved. The proxy's application task
    // is intentionally paused, so its response path cannot be used as the
    // completion signal here.

    client_driver.abort();
    server_driver.abort();
    let _ = client_driver.await;
    let _ = server_driver.await;
}
