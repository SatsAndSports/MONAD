use super::*;
use monad_common::protocol::LinkedChannelStatus;
use monad_relay::payments::{ChannelPaymentError, LinkError, LinkOutcome, PaymentOutcome};

#[derive(Default)]
struct Observations {
    armed: Option<[u8; 32]>,
    links: Vec<([u8; 32], LinkedChannelStatus)>,
    payments: Vec<[u8; 32]>,
    releases: Vec<[u8; 32]>,
    rejected: Option<([u8; 32], LinkedChannelStatus, Arc<SessionRegistry>)>,
}

#[derive(Default)]
pub(super) struct PaymentObserver {
    state: Mutex<Observations>,
    rejected: tokio::sync::Notify,
}

pub(super) struct ObservedPayments {
    pub inner: Arc<SpilmanRelayPayments>,
    pub observer: Arc<PaymentObserver>,
    pub registry: Arc<SessionRegistry>,
}

impl RelayPayments for ObservedPayments {
    fn funding_keyset_recovery_window_secs(&self) -> u64 {
        self.inner.funding_keyset_recovery_window_secs()
    }

    fn link_channel(
        &self,
        versions: &BTreeSet<String>,
        session: [u8; 32],
        json: &str,
    ) -> Result<LinkOutcome, LinkError> {
        let result = self.inner.link_channel(versions, session, json)?;
        let status = self
            .inner
            .linked_channel_status(&result.channel_id)
            .unwrap();
        self.observer
            .state
            .lock()
            .unwrap()
            .links
            .push((session, status));
        Ok(result)
    }

    fn apply_channel_payment(
        &self,
        session: [u8; 32],
        channel: &str,
        json: &str,
    ) -> Result<PaymentOutcome, ChannelPaymentError> {
        let mut state = self.observer.state.lock().unwrap();
        state.payments.push(session);
        if state.armed == Some(session) {
            state.armed = None;
            let before = self.inner.linked_channel_status(channel).unwrap();
            // Lose ownership at the payment boundary. The real signature validation
            // still runs, then the real owned-payment CAS must reject the commit.
            self.inner.release_channel_ownership(session, channel);
            let result = self.inner.apply_channel_payment(session, channel, json);
            assert_eq!(result, Err(ChannelPaymentError::Conflict));
            assert_eq!(self.inner.linked_channel_status(channel).unwrap(), before);
            state.rejected = Some((session, before, self.registry.clone()));
            self.observer.rejected.notify_one();
            result
        } else {
            self.inner.apply_channel_payment(session, channel, json)
        }
    }

    fn linked_channel_status(&self, channel: &str) -> Option<LinkedChannelStatus> {
        self.inner.linked_channel_status(channel)
    }

    fn release_channel_ownership(&self, session: [u8; 32], channel: &str) {
        self.inner.release_channel_ownership(session, channel);
        self.observer.state.lock().unwrap().releases.push(session);
    }

    fn channel_state(&self, channel: &str) -> Option<ChannelState> {
        self.inner.channel_state(channel)
    }
}

async fn configured_payment_conflict(failed_hop: usize) {
    let observer = Arc::new(PaymentObserver::default());
    let fixture = ConfiguredRouteFixture::start_observed(
        ConfiguredRouteFixtureConfig {
            subnet: 60 + failed_hop as u8,
            hop_count: 3,
            proof_batches: 5,
            wallet_seed: 65 + failed_hop as u8,
            channel_funding_token_target_msats: 11_000_000,
            label: "payment-conflict",
        },
        Some(observer.clone()),
    )
    .await;
    let stats = SharedRouteRuntimeStats::default();
    let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel();
    let client = tokio::spawn(run_configured_client_until_shutdown_with_stats(
        fixture.config.clone(),
        Some("local"),
        stats.clone(),
        async {
            let _ = shutdown_rx.await;
        },
    ));
    assert!(wait_for_configured_route_connected(&stats, 0).await);
    wait_for_configured_roundtrip(
        fixture.socks_listen,
        fixture.upper_addr,
        b"before conflict",
        "initial route",
    )
    .await;
    let initial = fixture.open_client_wallet().list_channels().unwrap();
    assert_eq!(initial.len(), 3);
    let (old_session, prior_calls) = {
        let mut state = observer.state.lock().unwrap();
        assert_eq!(state.links.len(), 3);
        let session = state.links[failed_hop].0;
        let calls = state.payments.iter().filter(|s| **s == session).count();
        state.armed = Some(session);
        (session, calls)
    };

    // Enough cleartext to require a topup, but well below channel capacity.
    // The old stream is allowed to fail; only the new route may resume traffic.
    let socks = fixture.socks_listen;
    let target = fixture.upper_addr;
    let traffic = tokio::spawn(async move {
        configured_client_socks_roundtrip(socks, target, &vec![b'x'; 1_200_000]).await
    });
    timeout(Duration::from_secs(30), observer.rejected.notified())
        .await
        .unwrap();
    let recovered = wait_for_configured_route_stats(&stats, |s| s.route_connected_total == 2)
        .await
        .expect("conflict must rebuild the configured route");
    assert_eq!(recovered.route_failures_total, 1);
    assert_eq!(recovered.suffix_rebuild_failures_total, 0);
    assert_eq!(recovered.suffix_rebuild_fallbacks_total, 0);
    assert_eq!(recovered.full_reconnects_total, u64::from(failed_hop == 0));
    assert_eq!(
        recovered.suffix_rebuild_successes_total,
        u64::from(failed_hop != 0)
    );
    let interrupted = timeout(Duration::from_secs(5), traffic)
        .await
        .unwrap()
        .unwrap();
    assert!(
        !matches!(interrupted, Ok(bytes) if bytes == vec![b'X'; 1_200_000]),
        "active stream on the rejected session must not complete"
    );
    wait_for_configured_roundtrip(socks, target, b"after conflict", "recovered route").await;
    let rebuilt = fixture.open_client_wallet().list_channels().unwrap();
    assert_suffix_rebuild_channel_invariants(
        &initial,
        &rebuilt,
        failed_hop,
        3 - failed_hop,
        "payment conflict",
    );
    {
        let state = observer.state.lock().unwrap();
        for (hop, (session, status)) in state.links.iter().take(3).enumerate() {
            let channel = rebuilt
                .iter()
                .find(|c| c.channel_id == status.channel_id)
                .unwrap();
            assert_eq!(channel.state, WalletChannelState::Open);
            assert!(channel.attached_session_id.is_some());
            assert_eq!(
                channel.attached_session_id == Some(*session),
                hop < failed_hop,
                "only the exact prefix sessions may survive"
            );
        }
        let (session, rejected_status, registry) = state.rejected.as_ref().unwrap();
        assert_eq!(*session, old_session);
        assert_eq!(
            state.payments.iter().filter(|s| **s == old_session).count(),
            prior_calls + 1,
            "no blind payment retry on the obsolete session"
        );
        assert!(
            state.releases.contains(&old_session),
            "normal session cleanup must release ownership"
        );
        assert!(
            !registry.terminate(&old_session),
            "old session must be deregistered"
        );
        let (new_session, relink_status) = state
            .links
            .iter()
            .skip(3)
            .find(|(_, status)| status.channel_id == rejected_status.channel_id)
            .unwrap();
        assert_ne!(*new_session, old_session);
        assert_eq!(
            relink_status, rejected_status,
            "relink must see the unchanged durable baseline"
        );
        assert!(
            state.payments.contains(new_session),
            "new session must authorize fresh funding after relink"
        );
        let durable = fixture.wallet_manager.list_channels(None).unwrap();
        let accepted = durable
            .iter()
            .find(|c| c.channel_id == rejected_status.channel_id)
            .unwrap();
        assert!(
            accepted.balance_raw > rejected_status.balance_raw,
            "resumed traffic must be backed by a newly accepted payment"
        );
    }
    let _ = shutdown_tx.send(());
    timeout(Duration::from_secs(5), client)
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    timeout(Duration::from_secs(10), fixture.shutdown())
        .await
        .unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn configured_payment_conflict_rebuilds_middle_hop_suffix() {
    timeout(Duration::from_secs(90), configured_payment_conflict(1))
        .await
        .unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn configured_payment_conflict_rebuilds_first_hop_route() {
    timeout(Duration::from_secs(90), configured_payment_conflict(0))
        .await
        .unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn payment_conflict_wire_error_without_funded_status() {
    timeout(Duration::from_secs(45), async {
        let observer = Arc::new(PaymentObserver::default());
        let fixture = ConfiguredRouteFixture::start_observed(
            ConfiguredRouteFixtureConfig {
                subnet: 62,
                hop_count: 1,
                proof_batches: 0,
                wallet_seed: 67,
                channel_funding_token_target_msats: 11_000_000,
                label: "conflict-wire",
            },
            Some(observer.clone()),
        )
        .await;
        let config = &fixture.config.relays[0];
        let key = SecpTransportKeypair::from_secret_bytes(
            &hex::decode(&config.transport_key)
                .unwrap()
                .try_into()
                .unwrap(),
        )
        .unwrap();
        let receiver = fixture
            .wallet_manager
            .receiver_pubkey_hex(&config.name)
            .unwrap();
        let conn = connect_client_quic_secp(config.listen.parse().unwrap(), &key.pubkey()).await;
        let mut control = ControlSessionHarness::open(&conn).await;
        let initial = control.handshake().await;
        let ad = &initial.advertisements[0];
        let wallet = TestSigningWallet::new(
            fixture._mint_helper.mint(),
            receiver.clone(),
            ad.mint_url.clone(),
            fixture._mint_helper.keyset_id().to_string(),
            fixture._mint_helper.keyset_info_json().unwrap(),
        )
        .await;
        let channel = wallet.pre_create_channel(1000).await.unwrap();
        let offer = RelayPaymentOffer::from_advertisement(
            receiver,
            ad,
            &supported_cashu_spilman_keyset_versions(),
        );
        wallet
            .attach_channel_to_session(&channel, *conn.session_id())
            .unwrap();
        send_control_message(
            &mut control.send,
            &ClientMessage::ChannelLink {
                payment_json: wallet.build_link_request(&channel, &offer).unwrap(),
            },
            false,
        )
        .await;
        let linked = expect_session_status_struct(read_control_message(&mut control.recv).await);
        assert!(linked.paused);
        assert_eq!(linked.total_paid_millisats, 0);
        observer.state.lock().unwrap().armed = Some(*conn.session_id());
        send_control_message(
            &mut control.send,
            &ClientMessage::ChannelPayment {
                payment_json: wallet
                    .build_channel_payment(&channel, &offer, 0, 100)
                    .unwrap(),
            },
            false,
        )
        .await;
        // Drain through EOF/reset, retaining every byte so a status coalesced
        // with the error cannot be mistaken for successful funding.
        let mut buffer = Vec::new();
        let mut errors = 0;
        while let Some(chunk) = control.recv.data().await {
            match chunk {
                Ok(bytes) => {
                    control
                        .recv
                        .flow_control()
                        .release_capacity(bytes.len())
                        .unwrap();
                    buffer.extend_from_slice(&bytes);
                    while let Some(message) =
                        try_decode_json_line::<ServerMessage>(&mut buffer).unwrap()
                    {
                        assert!(
                            matches!(
                                message,
                                ServerMessage::Error {
                                    code: ServerErrorCode::PaymentConflict,
                                    ..
                                }
                            ),
                            "expected only PAYMENT_CONFLICT, got {message:?}"
                        );
                        errors += 1;
                    }
                }
                Err(_) => break,
            }
        }
        assert_eq!(errors, 1);
        assert!(buffer.is_empty());
        let durable = fixture.wallet_manager.list_channels(None).unwrap();
        assert_eq!(durable.len(), 1);
        assert_eq!(durable[0].balance_raw, 0);
        assert!(conn
            .open_tunnel(&fixture.upper_addr.to_string())
            .await
            .is_err());
        drop(control);
        drop(conn);
        fixture.shutdown().await;
    })
    .await
    .unwrap();
}
