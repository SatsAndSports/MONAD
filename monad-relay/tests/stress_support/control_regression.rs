use super::*;
use monad_common::protocol::{LinkedChannelStatus, MintUnitAdvertisement};

async fn request(recv: &mut h2::RecvStream, buffer: &mut Vec<u8>) -> ClientMessage {
    loop {
        if let Some(message) = try_decode_json_line(buffer).unwrap() {
            return message;
        }
        let data = recv.data().await.unwrap().unwrap();
        recv.flow_control().release_capacity(data.len()).unwrap();
        buffer.extend_from_slice(&data);
    }
}

fn status(
    receiver: &str,
    linked: Option<LinkedChannelStatus>,
    paid: u64,
    due: u64,
) -> ServerMessage {
    ServerMessage::SessionStatus {
        receiver_pubkey: receiver.into(),
        advertisements: BTreeMap::from([(
            SYNTHETIC_TEST_MINT_URL.into(),
            BTreeMap::from([(
                "msat".into(),
                MintUnitAdvertisement {
                    commitment_modes: Default::default(),
                    minimum_channel_lifetime_secs: 3600,
                    funding_keyset_recovery_window_secs: 0,
                },
            )]),
        )]),
        linked_channel: linked,
        active_in_rate: 1,
        active_out_rate: 1,
        session_total_bytes_in: due,
        session_total_bytes_out: 0,
        total_paid_millisats: paid,
        remaining_milli_sats: paid as i64 - due as i64,
        paused: paid <= due,
        open_connects: 0,
        total_connects: 0,
        failed_connects: 0,
    }
}

/// Drive the actual harness control task against a scripted H2 peer. Replies
/// are withheld until all five FIFO slots are occupied, then kept pipelined
/// across link, initial payment, and refill confirmations. No mint/network
/// timing is required to reproduce the old queue-empty starvation gate.
#[tokio::test(start_paused = true)]
async fn pipelined_status_cannot_starve_funding_or_readiness() {
    pipelined_funding(false).await;
}

#[tokio::test(start_paused = true)]
async fn release_waits_for_payment_but_not_status_queue_drain() {
    pipelined_funding(true).await;
}

async fn pipelined_funding(release_during_payment: bool) {
    tokio::time::timeout(Duration::from_secs(10), async {
        let (client, server) = tokio::io::duplex(1 << 20);
        let (peer_tx, peer_rx) = oneshot::channel();
        let server_task = tokio::spawn(async move {
            let mut server = h2::server::handshake(server).await.unwrap();
            let (request, mut respond) = server.accept().await.unwrap().unwrap();
            let send = respond
                .send_response(http::Response::new(()), false)
                .unwrap();
            peer_tx.send((send, request.into_body())).unwrap();
            while server.accept().await.is_some() {}
        });
        let (mut conn, driver) = RelayConnection::from_transport_stream(client, [42; 32])
            .await
            .unwrap();
        conn.add_driver(driver);
        let stats = Arc::new(PaymentStats::default());
        let payment = StressPaymentConfig {
            mode: StressPaymentMode::Buffered,
            channel_capacity_msats: 1_000_000,
            initial_payment_msats: 100_000,
            payment_chunk_msats: 100_000,
            target_buffer_msats: 20_000,
            status_poll_interval: Duration::from_millis(100),
        };
        let (task, ready) =
            start_huge_funding_control(&conn, "scripted hop", payment, stats.clone())
                .await
                .unwrap();
        conn.add_task(task);
        let (mut send, mut recv) = peer_rx.await.unwrap();
        let mut buffer = Vec::new();
        let receiver = cashu::nuts::SecretKey::generate().public_key().to_hex();
        send_json_line(&mut send, &status(&receiver, None, 0, 0))
            .await
            .unwrap();
        let ClientMessage::ChannelLink {
            channel_id, params, ..
        } = request(&mut recv, &mut buffer).await
        else {
            panic!("expected initial link")
        };
        let mut linked = LinkedChannelStatus {
            channel_id: channel_id.clone(),
            balance_raw: 0,
            capacity_raw: params["capacity"].as_u64().unwrap(),
            unit: "msat".into(),
        };
        for _ in 0..4 {
            assert!(matches!(
                request(&mut recv, &mut buffer).await,
                ClientMessage::GetSessionStatus
            ));
        }
        // Link acknowledgement leaves four status requests outstanding. The
        // old harness waits for an empty FIFO and sends another poll instead.
        send_json_line(&mut send, &status(&receiver, Some(linked.clone()), 0, 0))
            .await
            .unwrap();
        assert!(matches!(
            request(&mut recv, &mut buffer).await,
            ClientMessage::ChannelPayment {
                balance_raw: 100_000,
                ..
            }
        ));

        // These statuses precede the payment. They must not create another
        // payment or prematurely confirm the one already sent.
        for _ in 0..4 {
            send_json_line(&mut send, &status(&receiver, Some(linked.clone()), 0, 0))
                .await
                .unwrap();
            assert!(matches!(
                request(&mut recv, &mut buffer).await,
                ClientMessage::GetSessionStatus
            ));
        }
        assert_eq!(stats.initial_payments.load(Ordering::Relaxed), 1);
        assert_eq!(stats.startup_unpauses.load(Ordering::Relaxed), 0);
        linked.balance_raw = 100_000;
        send_json_line(
            &mut send,
            &status(&receiver, Some(linked.clone()), 100_000, 90_000),
        )
        .await
        .unwrap();
        ready
            .await
            .expect("funded readiness must not wait for queued status replies");
        assert!(matches!(
            request(&mut recv, &mut buffer).await,
            ClientMessage::ChannelPayment {
                balance_raw: 200_000,
                ..
            }
        ));
        if release_during_payment {
            send_json_line(
                &mut send,
                &ServerMessage::ChannelReleaseRequested {
                    channel_id: channel_id.clone(),
                },
            )
            .await
            .unwrap();
        }

        // Keep the FIFO full with low-credit replies generated before that
        // refill. Exactly one refill may be submitted until its own reply.
        for _ in 0..4 {
            send_json_line(
                &mut send,
                &status(&receiver, Some(linked.clone()), 100_000, 90_000),
            )
            .await
            .unwrap();
            assert!(matches!(
                request(&mut recv, &mut buffer).await,
                ClientMessage::GetSessionStatus
            ));
        }
        linked.balance_raw = 200_000;
        send_json_line(&mut send, &status(&receiver, Some(linked), 200_000, 90_000))
            .await
            .unwrap();
        let next = request(&mut recv, &mut buffer).await;
        if release_during_payment {
            assert!(
                matches!(next, ClientMessage::ChannelUnlink { channel_id: id } if id == channel_id)
            );
        } else {
            assert!(matches!(next, ClientMessage::GetSessionStatus));
        }
        assert_eq!(stats.initial_payments.load(Ordering::Relaxed), 1);
        assert_eq!(stats.startup_unpauses.load(Ordering::Relaxed), 1);
        assert_eq!(stats.topups_total.load(Ordering::Relaxed), 1);
        assert_eq!(stats.topups_proactive.load(Ordering::Relaxed), 1);
        assert_eq!(stats.control_errors.load(Ordering::Relaxed), 0);
        conn.shutdown().await;
        server_task.abort();
        let _ = server_task.await;
    })
    .await
    .expect("pipelined funding test timed out");
}
