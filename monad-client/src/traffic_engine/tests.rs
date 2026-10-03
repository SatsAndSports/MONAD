use super::*;
use tokio::{net::TcpListener, task::JoinSet};

fn params(rate: u64, u: u8, d: u8) -> TrafficRunParams {
    TrafficRunParams {
        server_url: "http://localhost:8080".into(),
        total_rate_bytes_per_second: rate,
        upload_ratio: u,
        download_ratio: d,
    }
}

#[tokio::test(start_paused = true)]
async fn every_rate_and_ratio_boundary_progresses_without_initial_or_idle_burst() {
    for rate in [1024, 32767, 32768, 1 << 30] {
        for (u, d) in [(1, 1), (1, 100), (100, 1)] {
            let p = params(rate, u, d);
            let mut bucket = Bucket::new(rate);
            let size = chunk_size(&p, &bucket) as u64;
            let cost = size + response_delta(0, size, &p);
            assert!(size > 0 && cost as f64 <= bucket.capacity);
            let start = Instant::now();
            bucket.acquire(cost).await;
            assert!(start.elapsed().as_secs_f64() >= cost as f64 / rate as f64);
            tokio::time::advance(Duration::from_secs(10)).await;
            bucket.acquire(cost).await;
            assert!(bucket.credit <= bucket.capacity);
            // New connections never receive credit for the disconnected interval.
            assert_eq!(Bucket::new(rate).credit, 0.0);
        }
    }
}

#[test]
fn ratio_math_and_window_cover_bandwidth_delay_and_overflow() {
    for (u, d) in [(1, 1), (1, 100), (100, 1)] {
        let p = params(1 << 30, u, d);
        let mut sent = 0;
        let mut response = 0;
        for count in [1, 3, 97, 8193, 16384] {
            response += response_delta(sent, count, &p);
            sent += count;
        }
        assert_eq!(response, sent * d as u64 / u as u64);
        assert_eq!(
            response_delta(u64::MAX - 100, 99, &p),
            (((u64::MAX as u128 - 1) * d as u128 / u as u128)
                - ((u64::MAX as u128 - 100) * d as u128 / u as u128)) as u64
        );
    }
    assert!(response_window(&params(1 << 30, 1, 100), 100.0) >= 400 << 20);
    assert_eq!(
        response_window(&params(1 << 30, 1, 100), 10000.0),
        512 << 20
    );
}

#[test]
fn endpoint_and_upgrade_validation() {
    assert_eq!(endpoint("http://[::1]:8080").unwrap().0, "[::1]:8080");
    assert_eq!(endpoint("http://localhost").unwrap().0, "localhost:80");
    for url in [
        "https://localhost",
        "http://u:p@localhost",
        "http://localhost/?a",
        "http://localhost/#a",
        "http://localhost:0",
    ] {
        assert!(endpoint(url).is_err(), "{url}");
    }
    let good = b"HTTP/1.1 101 Switching Protocols\r\nConnection: keep-alive, Upgrade\r\nUpgrade: monad-ratio-stream/1\r\n\r\n";
    validate_upgrade(good).unwrap();
    for bad in [
        "HTTP/1.1 1010 Wrong\r\n\r\n",
        "HTTP/1.1 101 OK\r\n\r\n",
        "HTTP/1.1 101 OK\r\nConnection: Upgrade\r\nUpgrade: wrong\r\n\r\n",
    ] {
        assert!(validate_upgrade(bad.as_bytes()).is_err());
    }
}

#[tokio::test]
async fn upgrade_bounds_and_read_ahead_payload() {
    let mut oversized = &[b'x'; 8193][..];
    assert_eq!(
        read_upgrade(&mut oversized).await.unwrap_err(),
        "upgrade headers too large"
    );
    let mut bytes =
        &b"HTTP/1.1 101 OK\r\nConnection: Upgrade\r\nUpgrade: monad-ratio-stream/1\r\n\r\nPAYLOAD"
            [..];
    read_upgrade(&mut bytes).await.unwrap();
    assert_eq!(bytes, b"PAYLOAD");
}

#[tokio::test(start_paused = true)]
async fn metrics_decay_are_bounded_and_preserve_fractional_rtt() {
    let mut m = Metrics::new(TrafficSnapshot::default());
    m.view.uploaded_bytes = 10000;
    for _ in 0..30 {
        tokio::time::advance(Duration::from_millis(200)).await;
        m.sample(Instant::now());
    }
    assert_eq!(m.view.upload_rate_bytes_per_second, 0);
    assert_eq!(m.rates.len(), 26);
    m.probe(0.125);
    m.probe(0.375);
    assert_eq!(m.view.latency.median_ms, Some(0.25));
    for _ in 0..400 {
        m.probe(0.5);
    }
    assert_eq!(m.latency.len(), 300);
}

#[tokio::test]
async fn partial_writes_are_counted_and_excess_output_and_eof_are_rejected() {
    let p = params(1 << 30, 1, 1);
    let run = Arc::new(Mutex::new(Metrics::new(TrafficSnapshot::default())));
    let (client, mut server) = tokio::io::duplex(13);
    let work = bulk(client, &p, &run);
    tokio::pin!(work);
    let peer = async {
        let mut input = [0; 7];
        server.read_exact(&mut input).await.unwrap();
        // Duplex capacity forces a partial write, and counters must already
        // reflect it even though a complete 16 KiB chunk has not been sent.
        let uploaded = run.lock().unwrap().view.uploaded_bytes;
        assert!(uploaded > 0 && uploaded < CHUNK as u64);
        drop(server);
    };
    let (result, ()) = tokio::join!(&mut work, peer);
    assert!(result.is_err());

    let (client, mut server) = tokio::io::duplex(16);
    server.write_all(&[1; 8]).await.unwrap();
    assert!(bulk(client, &params(1024, 1, 1), &run)
        .await
        .unwrap_err()
        .contains("exceeded"));
}

#[tokio::test(start_paused = true)]
async fn silent_stream_times_out_and_blocked_io_is_drop_cancellable() {
    let run = Arc::new(Mutex::new(Metrics::new(TrafficSnapshot::default())));
    let (client, _server) = tokio::io::duplex(1);
    assert!(bulk(client, &params(1 << 30, 1, 100), &run)
        .await
        .unwrap_err()
        .contains("timed out"));
    let (client, mut server) = tokio::io::duplex(1);
    {
        let p = params(1 << 30, 1, 1);
        let work = bulk(client, &p, &run);
        tokio::pin!(work);
        tokio::select! { _=tokio::time::sleep(Duration::from_secs(1))=>{}, _=&mut work=>panic!("expected backpressure") }
    }
    let mut remainder = Vec::new();
    server.read_to_end(&mut remainder).await.unwrap();
    assert!(remainder.len() <= 1);
}

#[tokio::test]
async fn managed_disable_stops_generator_and_rejects_queued_start() {
    let controls = Arc::new(crate::management::ClientManagement::default());
    let c = TrafficController::new("127.0.0.1:1".parse().unwrap());
    let (stop, stopped) = oneshot::channel();
    let owned = c.clone();
    let managed = controls.clone();
    let task = tokio::spawn(async move {
        owned
            .serve_managed(
                async {
                    let _ = stopped.await;
                },
                managed,
            )
            .await
    });
    c.start(params(1024, 1, 1), 0).await.unwrap();
    controls.set_enabled(false).unwrap();
    assert!(c.start(params(1024, 1, 1), 1).await.is_err());
    assert_eq!(c.snapshot().state, "stopped");
    stop.send(()).unwrap();
    task.await.unwrap();
}

#[tokio::test]
async fn abrupt_owner_cancellation_closes_sockets_and_publishes_stopped() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let (c, _stop, task) = owner(listener.local_addr().unwrap()).await;
    c.start(params(1024, 1, 1), 0).await.unwrap();
    let (mut peer, _) = timeout(Duration::from_secs(1), listener.accept())
        .await
        .unwrap()
        .unwrap();
    let mut greeting = [0; 3];
    peer.read_exact(&mut greeting).await.unwrap();
    task.abort();
    assert!(task.await.unwrap_err().is_cancelled());
    assert_eq!(c.snapshot().state, "stopped");
    assert_eq!(
        timeout(Duration::from_secs(1), peer.read(&mut [0; 1]))
            .await
            .unwrap()
            .unwrap(),
        0
    );
}

#[tokio::test]
async fn latency_reconnect_does_not_restart_bulk_and_restores_running() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let (stop_peer, peer_stopped) = oneshot::channel();
    let bulks = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let counts = bulks.clone();
    let peer = tokio::spawn(async move {
        let mut tasks = JoinSet::new();
        let mut probes = 0;
        tokio::pin!(peer_stopped);
        loop {
            tokio::select! {
                _=&mut peer_stopped=>break,
                Some(result)=tasks.join_next(),if !tasks.is_empty()=>{result.unwrap();},
                accepted=listener.accept()=>{
                    let (mut stream,_)=accepted.unwrap();
                    // Our fake SOCKS peer also implements the target protocol.
                    let mut greeting=[0;3];stream.read_exact(&mut greeting).await.unwrap();
                    stream.write_all(&[5,0]).await.unwrap();
                    let mut h=[0;5];stream.read_exact(&mut h).await.unwrap();
                    let mut rest=vec![0;h[4] as usize+2];stream.read_exact(&mut rest).await.unwrap();
                    stream.write_all(&[5,0,0,1,127,0,0,1,0,0]).await.unwrap();
                    let mut headers=Vec::new();
                    while !headers.ends_with(b"\r\n\r\n"){headers.push(stream.read_u8().await.unwrap());}
                    let bulk=String::from_utf8(headers).unwrap().contains("/1/5 ");
                    stream.write_all(b"HTTP/1.1 101 OK\r\nConnection: upgrade\r\nUpgrade: monad-ratio-stream/1\r\n\r\n").await.unwrap();
                    if bulk {counts.fetch_add(1,std::sync::atomic::Ordering::SeqCst);} else {probes+=1;}
                    let fail_probe=!bulk && probes==1;
                    tasks.spawn(async move {
                        if fail_probe {return;}
                        let mut bytes=[0;1024];
                        loop {
                            let Ok(n)=stream.read(&mut bytes).await else {break;};
                            if n==0{break;}
                            for _ in 0..if bulk {5}else{1} {if stream.write_all(&bytes[..n]).await.is_err(){return;}}
                        }
                    });
                }
            }
        }
        tasks.shutdown().await;
    });
    let (c, stop, task) = owner(address).await;
    c.start(params(100_000, 1, 5), 0).await.unwrap();
    timeout(Duration::from_secs(3), async {
        loop {
            let s = c.snapshot();
            if s.latency_failures > 0
                && s.latency.samples > 0
                && s.downloaded_bytes > 0
                && s.state == "running"
            {
                break;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await
    .unwrap();
    assert_eq!(bulks.load(std::sync::atomic::Ordering::SeqCst), 1);
    stop.send(()).unwrap();
    task.await.unwrap();
    stop_peer.send(()).unwrap();
    peer.await.unwrap();
}

#[tokio::test]
async fn run_publication_is_coherent_and_old_metrics_cannot_change_replacement() {
    let (c, stop, task) = owner("127.0.0.1:1".parse().unwrap()).await;
    c.start(params(1024, 1, 100), 0).await.unwrap();
    let old = c.current.lock().unwrap().clone();
    c.start(params(2048, 100, 1), 1).await.unwrap();
    {
        let mut old = old.lock().unwrap();
        old.view.uploaded_bytes = 99999;
        old.connection(0, true);
        old.probe(999.0);
    }
    let s = c.snapshot();
    assert_eq!(
        (
            s.run_id,
            s.total_rate_bytes_per_second,
            s.upload_ratio,
            s.download_ratio
        ),
        (2, 2048, 100, 1)
    );
    assert_eq!(s.uploaded_bytes, 0);
    assert_eq!(s.latency.samples, 0);
    stop.send(()).unwrap();
    task.await.unwrap();
}

async fn proxy(listener: TcpListener, stop: oneshot::Receiver<()>) {
    let mut tasks = JoinSet::new();
    tokio::pin!(stop);
    loop {
        tokio::select! {
            _ = &mut stop => break,
            Some(_) = tasks.join_next(), if !tasks.is_empty() => {},
            accepted = listener.accept() => {
                let (mut client,_) = accepted.unwrap();
                tasks.spawn(async move {
                    let mut greeting = [0;3]; client.read_exact(&mut greeting).await?;
                    assert_eq!(greeting,[5,1,0]); client.write_all(&[5,0]).await?;
                    let mut header = [0;4]; client.read_exact(&mut header).await?;
                    let host = match header[3] {
                        1 => { let mut b=[0;4]; client.read_exact(&mut b).await?; std::net::Ipv4Addr::from(b).to_string() },
                        4 => { let mut b=[0;16]; client.read_exact(&mut b).await?; format!("[{}]",std::net::Ipv6Addr::from(b)) },
                        3 => { let n=client.read_u8().await?; let mut b=vec![0;n as usize]; client.read_exact(&mut b).await?; String::from_utf8(b).unwrap() },
                        _ => panic!("invalid address"),
                    };
                    let port=client.read_u16().await?;
                    let mut upstream=TcpStream::connect(format!("{host}:{port}")).await?;
                    client.write_all(&[5,0,0,1,127,0,0,1,0,0]).await?;
                    tokio::io::copy_bidirectional(&mut client,&mut upstream).await?;
                    Ok::<_,std::io::Error>(())
                });
            }
        }
    }
    tasks.shutdown().await;
}

async fn owner(
    socks: SocketAddr,
) -> (
    TrafficController,
    oneshot::Sender<()>,
    tokio::task::JoinHandle<()>,
) {
    let c = TrafficController::new(socks);
    let (stop, stopped) = oneshot::channel();
    let owned = c.clone();
    let task = tokio::spawn(async move {
        owned
            .serve(async {
                let _ = stopped.await;
            })
            .await
    });
    (c, stop, task)
}

#[tokio::test]
async fn real_server_low_rate_extreme_ratios_and_run_replacement() {
    let temp = tempfile::tempdir().unwrap();
    let socket = temp.path().join("traffic.sock");
    let config = serde_json::from_value(serde_json::json!({
        "traffic_servers": [
            {"name":"test","listen":"127.0.0.1:0"},
            {"name":"ipv6","listen":"[::1]:0"}
        ],
        "management":{"listen":"127.0.0.1:0","traffic_server_socket":socket}
    }))
    .unwrap();
    let (server_stop, server_stopped) = oneshot::channel();
    let server = tokio::spawn(monad_test_traffic::run(config, None, async {
        let _ = server_stopped.await;
    }));
    let ipc = monad_management::unix_client(socket).unwrap();
    let urls = timeout(Duration::from_secs(5), async {
        loop {
            if let Ok(response) = ipc.get("http://localhost/v1/snapshot").send().await {
                let v: serde_json::Value = response.json().await.unwrap();
                let v4 = v["data"]["instances"]["test"]["base_url"]
                    .as_str()
                    .unwrap()
                    .to_string();
                break [
                    v4.clone(),
                    v4.replace("127.0.0.1", "localhost"),
                    v["data"]["instances"]["ipv6"]["base_url"]
                        .as_str()
                        .unwrap()
                        .to_string(),
                ];
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .unwrap();
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let (proxy_stop, proxy_stopped) = oneshot::channel();
    let proxy_task = tokio::spawn(proxy(listener, proxy_stopped));
    let (c, stop, task) = owner(address).await;
    for (u, d, url) in [(1, 1), (1, 100), (100, 1)]
        .into_iter()
        .flat_map(|(u, d)| urls.iter().map(move |url| (u, d, url)))
    {
        let mut p = params(1024, u, d);
        p.server_url = url.clone();
        let before = c.snapshot().run_id;
        c.start(p, before).await.unwrap();
        assert!(
            c.stop(before).await.is_err(),
            "stale stop must not stop replacement"
        );
        timeout(Duration::from_secs(5), async {
            loop {
                let s = c.snapshot();
                if s.uploaded_bytes > 0 && s.downloaded_bytes > 0 && s.latency.samples > 0 {
                    assert_eq!(s.state, "running");
                    break;
                }
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
        })
        .await
        .unwrap();
        let s = c.snapshot();
        assert!(
            s.uploaded_bytes + s.downloaded_bytes < 6 * 1024,
            "low rate cannot burst megabytes"
        );
    }
    c.stop(c.snapshot().run_id).await.unwrap();
    assert_eq!(c.snapshot().upload_rate_bytes_per_second, 0);
    stop.send(()).unwrap();
    task.await.unwrap();
    proxy_stop.send(()).unwrap();
    proxy_task.await.unwrap();
    server_stop.send(()).unwrap();
    server.await.unwrap().unwrap();
}

#[tokio::test]
async fn stop_and_owner_shutdown_interrupt_stalled_upgrade_and_cancelled_waiter() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let (c, stop, task) = owner(addr).await;
    // Fake SOCKS peer completes CONNECT then never answers HTTP upgrade.
    let peers = tokio::spawn(async move {
        let mut sockets = Vec::new();
        for _ in 0..2 {
            let (mut s, _) = listener.accept().await.unwrap();
            let mut b = [0; 3];
            s.read_exact(&mut b).await.unwrap();
            s.write_all(&[5, 0]).await.unwrap();
            let mut h = [0; 5];
            s.read_exact(&mut h).await.unwrap();
            let mut rest = vec![0; h[4] as usize + 2];
            s.read_exact(&mut rest).await.unwrap();
            s.write_all(&[5, 0, 0, 1, 127, 0, 0, 1, 0, 0])
                .await
                .unwrap();
            sockets.push(s);
        }
        sockets
    });
    c.start(params(1024, 1, 1), 0).await.unwrap();
    let mut sockets = timeout(Duration::from_secs(2), peers)
        .await
        .unwrap()
        .unwrap();
    // Dropped reply receiver must not cancel the accepted stop command.
    let (reply, result) = oneshot::channel();
    c.tx.try_send(Request {
        command: Command::Stop(1),
        reply,
    })
    .unwrap();
    drop(result);
    timeout(Duration::from_secs(1), async {
        for s in &mut sockets {
            let mut data = Vec::new();
            if let Err(error) = s.read_to_end(&mut data).await {
                assert_eq!(error.kind(), std::io::ErrorKind::ConnectionReset);
            }
        }
    })
    .await
    .unwrap();
    assert_eq!(c.snapshot().state, "stopped");
    c.start(params(1024, 1, 1), 1).await.unwrap();
    stop.send(()).unwrap();
    timeout(Duration::from_secs(1), task)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(c.snapshot().state, "stopped");
}
