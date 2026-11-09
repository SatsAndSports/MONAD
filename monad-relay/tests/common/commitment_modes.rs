use super::*;
use axum::response::IntoResponse;
use cdk_spilman::CommitmentMode;
use monad_common::commitment_modes::ModePolicy;

struct Fixture {
    mint: Arc<TestMintHelper>,
    manager: Arc<RelayWalletManager>,
    wallet: Arc<SqliteClientWallet>,
    offer: RelayPaymentOffer,
    payments: Arc<SpilmanRelayPayments>,
    capability_response: Arc<AtomicUsize>,
    addr: SocketAddr,
    pubkey: Secp256k1Pubkey,
    relay: JoinHandle<io::Result<()>>,
    stop: Option<tokio::sync::oneshot::Sender<()>>,
    mint_stop: Option<tokio::sync::oneshot::Sender<()>>,
    mint_task: JoinHandle<()>,
    _directory: tempfile::TempDir,
}

impl Fixture {
    async fn new(modes: ModePolicy, preference: Option<CommitmentMode>) -> Self {
        let mint = Arc::new(TestMintHelper::new().await.unwrap());
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let mint_url = format!("http://{}", listener.local_addr().unwrap());
        let keyset = mint.keyset_id().to_string();
        let capability_response = Arc::new(AtomicUsize::new(0));
        let response = capability_response.clone();
        let router = build_router(mint.mint())
            .await
            .unwrap()
            .layer(middleware::from_fn(
                move |request: axum::extract::Request, next: Next| {
                    let response = response.clone();
                    async move {
                        if request.uri().path() == "/v1/info" {
                            match response.load(Ordering::SeqCst) {
                                1 => {
                                    return axum::Json(
                                        serde_json::json!({"nuts":{"3":{"rerandomize":false}}}),
                                    )
                                    .into_response()
                                }
                                2 => return http::StatusCode::SERVICE_UNAVAILABLE.into_response(),
                                _ => {}
                            }
                        }
                        next.run(request).await
                    }
                },
            ));
        let (mint_stop, mint_stopped) = tokio::sync::oneshot::channel();
        let mint_shutdown = mint.clone();
        let mint_task = tokio::spawn(async move {
            axum::serve(listener, router)
                .with_graceful_shutdown(async {
                    let _ = mint_stopped.await;
                })
                .await
                .unwrap();
            mint_shutdown.mint().stop().await.unwrap();
        });
        let directory = tempfile::tempdir().unwrap();
        let receiver = cashu::nuts::SecretKey::generate();
        let manager = Arc::new(
            RelayWalletManager::open(
                directory
                    .path()
                    .join("relay.db")
                    .to_string_lossy()
                    .into_owned(),
            )
            .unwrap(),
        );
        manager
            .register_identity("modes", receiver.clone())
            .unwrap();
        let trusted = BTreeMap::from([(mint_url.clone(), BTreeSet::from(["sat".into()]))]);
        manager.set_trusted_mint_units(trusted.clone());
        manager.install_keyset_cache(mint_cache_with_keyset(
            &mint_url,
            "sat",
            &keyset,
            mint.keyset_info_json().unwrap(),
            true,
        ));
        let policy = monad_common::config::RelayChannelPolicyConfig {
            commitment_modes: modes,
            ..Default::default()
        };
        let payments = manager
            .spilman_payments_for_live_with_policy("modes", policy.clone())
            .unwrap();
        if let Some(cache) = payments.mint_mode_cache() {
            assert_eq!(cache.discover(&mint_url).await, Ok(true));
        }
        let loose = LooseProofWallet::open(directory.path().join("loose.db"), "modes").unwrap();
        let proofs = mint.mint_proofs(10_000).await.unwrap();
        loose
            .import_proofs(&loose_proofs_from_cashu_proofs(
                &mint_url, "sat", "modes", &proofs,
            ))
            .unwrap();
        let wallet = Arc::new(
            SqliteClientWallet::open(
                loose,
                directory.path().join("client.db"),
                &cashu::nuts::SecretKey::generate().to_secret_hex(),
            )
            .unwrap()
            .with_commitment_mode_preference(preference),
        );
        let offer = RelayPaymentOffer {
            commitment_modes: ModePolicy::dual_mode(),
            receiver_pubkey: receiver.public_key().to_hex(),
            mint_url,
            unit: "sat".into(),
            minimum_channel_lifetime_secs: 3600,
            funding_keyset_recovery_window_secs: 86400,
            negotiated_keyset_versions: supported_cashu_spilman_keyset_versions(),
            in_bytes_per_millisat: 1,
            out_bytes_per_millisat: 1,
        };
        let identity = QuicCertIdentity::generate().unwrap();
        let key = SecpTransportKeypair::generate();
        let pubkey = key.pubkey();
        let km = monad_quic::keygen::generate_from_seed(identity.seed()).unwrap();
        let (listener, endpoint, addr) = bind_tcp_and_quic_on_same_port(
            "127.0.0.1:0".parse().unwrap(),
            monad_quic::server::build_server_config(&km.cert_pem, &km.key_pem).unwrap(),
        )
        .await
        .unwrap();
        let config = Arc::new(ServerConfig {
            identity,
            transport_key: Some(key),
            receiver_pubkey_hex: offer.receiver_pubkey.clone(),
            trusted_mint_units: trusted,
            in_bytes_per_millisat: 1,
            out_bytes_per_millisat: 1,
            bootstrap_capabilities: None,
            relay_wallet_name: "modes".into(),
            spilman_storage_path: String::new(),
            channel_policy: policy,
            connect_limits: Default::default(),
        });
        let (stop, stopped) = tokio::sync::oneshot::channel();
        let relay = tokio::spawn(run_with_payments_and_registry_and_shutdown(
            listener,
            Some(endpoint),
            config,
            payments.clone(),
            manager.keyset_cache(),
            RelayRuntimeServices {
                session_registry: Arc::new(SessionRegistry::new()),
                keyset_refresh: None,
            },
            async {
                let _ = stopped.await;
            },
        ));
        Self {
            mint,
            manager,
            wallet,
            offer,
            payments,
            capability_response,
            addr,
            pubkey,
            relay,
            stop: Some(stop),
            mint_stop: Some(mint_stop),
            mint_task,
            _directory: directory,
        }
    }

    fn channel(&self, mode: CommitmentMode) -> String {
        self.wallet
            .provision_channel_in_mode(&self.offer, 100_000, mode)
            .unwrap()
    }

    async fn driver(&self) -> connector::RouteConnection {
        let runtime = connector::ConnectorRuntime::with_payment_policy(
            Some(self.wallet.clone()),
            PaymentPolicy {
                channel_funding_token_target_msats: 100_000,
                target_topup_buffer_msats: 10_000,
                minimum_topup_msats: 10_000,
            },
        )
        .unwrap();
        connector::connect_route_with_runtime(
            &Route::new(vec![cleartext_route_hop(
                self.addr.to_string(),
                self.pubkey,
                true,
            )])
            .unwrap(),
            &runtime,
        )
        .await
        .unwrap()
    }

    async fn shutdown(mut self) {
        let _ = self.stop.take().unwrap().send(());
        timeout(Duration::from_secs(8), &mut self.relay)
            .await
            .unwrap()
            .unwrap()
            .unwrap();
        let _ = self.mint_stop.take().unwrap().send(());
        timeout(Duration::from_secs(5), &mut self.mint_task)
            .await
            .unwrap()
            .unwrap();
    }

    async fn restart_without_trust(&mut self) {
        let _ = self.stop.take().unwrap().send(());
        timeout(Duration::from_secs(8), &mut self.relay)
            .await
            .unwrap()
            .unwrap()
            .unwrap();
        let (addr, pubkey, relay, stop, payments) = start_managed_persistent_relay(
            "127.0.0.1:0".parse().unwrap(),
            &SecpTransportKeypair::generate(),
            self.manager.receiver_secret("modes").unwrap(),
            "modes",
            self.manager.clone(),
            SpilmanMintCache::default(),
            BTreeMap::new(),
        )
        .await
        .unwrap();
        self.addr = addr;
        self.pubkey = pubkey;
        self.relay = relay;
        self.stop = Some(stop);
        self.payments = payments;
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        self.relay.abort();
        self.mint_task.abort();
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn disallowed_first_link_and_stored_relink_are_nonfatal_and_preserve_authority() {
    for accepted in [CommitmentMode::Ordinary, CommitmentMode::Rerandomized] {
        let rejected = if accepted == CommitmentMode::Ordinary {
            CommitmentMode::Rerandomized
        } else {
            CommitmentMode::Ordinary
        };
        let fixture = Fixture::new(
            ModePolicy {
                accepted: vec![accepted],
                preferred: accepted,
            },
            None,
        )
        .await;
        let good = fixture.channel(accepted);
        let bad = fixture.channel(rejected);
        let conn = connect_client_quic_secp(fixture.addr, &fixture.pubkey).await;
        let (mut send, mut recv) = conn.open_control().await.unwrap();
        let initial = control_handshake_status(&mut send, &mut recv).await;
        assert_eq!(
            initial.advertisements[0].commitment_modes.accepted,
            vec![accepted]
        );
        fixture
            .wallet
            .attach_channel_to_session(&good, *conn.session_id())
            .unwrap();
        let link = fixture
            .wallet
            .build_link_request(&good, &fixture.offer)
            .unwrap();
        send_control_message(&mut send, &channel_link_message(link), false).await;
        expect_session_status_struct(read_control_message(&mut recv).await);
        let payment = fixture
            .wallet
            .build_channel_payment(&good, &fixture.offer, 0, 10)
            .unwrap();
        send_control_message(&mut send, &channel_payment_message(payment), false).await;
        let before = expect_session_status_struct(read_control_message(&mut recv).await);
        assert_eq!(before.total_paid_millisats, 10_000);

        let owner = [9; 32];
        fixture
            .wallet
            .attach_channel_to_session(&bad, owner)
            .unwrap();
        let original = fixture
            .wallet
            .build_link_request(&bad, &fixture.offer)
            .unwrap();
        for stored in [false, true] {
            let mut request = original.clone();
            if stored {
                fixture
                    .payments
                    .link_channel(&supported_cashu_spilman_keyset_versions(), owner, &original)
                    .unwrap();
                // The caller lies about mode on relink. Stored funding wins.
                if rejected == CommitmentMode::Rerandomized {
                    request.params.remove("commitment_mode");
                } else {
                    request
                        .params
                        .insert("commitment_mode".into(), serde_json::json!("rerandomized"));
                }
            }
            send_control_message(&mut send, &channel_link_message(request), false).await;
            let ServerMessage::Error { code, message } = read_control_message(&mut recv).await
            else {
                panic!("expected mode rejection")
            };
            assert_eq!(code, ServerErrorCode::LinkCommitmentModeNotAccepted);
            assert!(!code.is_fatal());
            assert!(message.contains("accepted modes"));
            if !stored {
                assert_eq!(fixture.payments.channel_state(&bad).unwrap(), None);
            }
            let after = request_session_status_status(&mut send, &mut recv).await;
            assert_eq!(after.linked_channel.as_ref().unwrap().channel_id, good);
            assert_eq!(after.total_paid_millisats, before.total_paid_millisats);
            assert_eq!(after.remaining_milli_sats, before.remaining_milli_sats);
            assert_eq!(
                fixture.wallet.get_channel(&bad).unwrap().state,
                WalletChannelState::Open
            );
        }
        // Rejection did not transfer the other channel away from its owner.
        let payment = fixture
            .wallet
            .build_channel_payment(&bad, &fixture.offer, 0, 10)
            .unwrap();
        fixture
            .payments
            .apply_channel_payment(owner, &bad, &payment)
            .unwrap();
        send.send_data(Bytes::new(), true).unwrap();
        conn.close().await;
        fixture.shutdown().await;
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn production_driver_prefers_new_rerandomized_but_reuses_accepted_ordinary() {
    let fixture = Fixture::new(ModePolicy::dual_mode(), None).await;
    let ordinary = fixture.channel(CommitmentMode::Ordinary);
    let route = fixture.driver().await;
    let channels = fixture.wallet.list_channels().unwrap();
    assert_eq!(channels.len(), 1);
    assert_eq!(channels[0].channel_id, ordinary);
    assert_eq!(channels[0].commitment_mode, CommitmentMode::Ordinary);
    assert!(channels[0].current_signed_balance_msats > 0);
    route.close().await;
    fixture.wallet.mark_channel_unusable(&ordinary).unwrap();
    let route = fixture.driver().await;
    let channels = fixture.wallet.list_channels().unwrap();
    let funded = channels.iter().find(|c| c.channel_id != ordinary).unwrap();
    assert_eq!(funded.commitment_mode, CommitmentMode::Rerandomized);
    assert!(funded.current_signed_balance_msats > 0);
    route.close().await;
    fixture.shutdown().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn explicit_ordinary_client_override_constrains_new_provisioning() {
    let fixture = Fixture::new(ModePolicy::dual_mode(), Some(CommitmentMode::Ordinary)).await;
    let route = fixture.driver().await;
    let channels = fixture.wallet.list_channels().unwrap();
    assert_eq!(channels.len(), 1);
    assert_eq!(channels[0].commitment_mode, CommitmentMode::Ordinary);
    assert!(channels[0].current_signed_balance_msats > 0);
    route.close().await;
    fixture.shutdown().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn one_session_can_replace_exhausted_ordinary_funding_with_rerandomized() {
    let fixture = Fixture::new(ModePolicy::dual_mode(), None).await;
    let ordinary = fixture
        .wallet
        .provision_channel_in_mode(&fixture.offer, 1000, CommitmentMode::Ordinary)
        .unwrap();
    let route = fixture.driver().await;
    let session_id = *route.final_connection_arc().session_id();
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let target = listener.local_addr().unwrap().to_string();
    let echo = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        for _ in 0..2 {
            let mut data = [0; 2000];
            stream.read_exact(&mut data).await.unwrap();
            stream.write_all(&data).await.unwrap();
        }
    });
    let mut tunnel = route
        .final_connection_arc()
        .open_tunnel(&target)
        .await
        .unwrap();
    timeout(Duration::from_secs(10), async {
        // Two separate exchanges ensure a bounded first-operation overshoot
        // cannot finish the workload using only the old 1000 msat credit.
        for _ in 0..2 {
            tunnel.write_all(&[7; 2000]).await.unwrap();
            let mut data = [0; 2000];
            tunnel.read_exact(&mut data).await.unwrap();
            assert_eq!(data, [7; 2000]);
        }
    })
    .await
    .unwrap();
    drop(tunnel);
    echo.await.unwrap();
    let channels = fixture.wallet.list_channels().unwrap();
    let replacement = channels
        .iter()
        .find(|channel| channel.channel_id != ordinary)
        .unwrap();
    assert_eq!(replacement.commitment_mode, CommitmentMode::Rerandomized);
    assert_eq!(replacement.attached_session_id, Some(session_id));
    assert!(replacement.current_signed_balance_msats > 0);
    assert_eq!(
        fixture
            .wallet
            .get_channel(&ordinary)
            .unwrap()
            .commitment_mode,
        CommitmentMode::Ordinary
    );
    route.close().await;
    fixture.shutdown().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn client_discovers_capability_independently_and_does_not_downgrade_on_unknown() {
    for response in [1, 2] {
        let fixture = Fixture::new(ModePolicy::dual_mode(), None).await;
        // Relay already has confirmed support in its cache. Only the client's
        // independent discovery sees this changed response.
        fixture
            .capability_response
            .store(response, Ordering::SeqCst);
        let runtime = connector::ConnectorRuntime::with_payment_policy(
            Some(fixture.wallet.clone()),
            PaymentPolicy {
                channel_funding_token_target_msats: 100_000,
                target_topup_buffer_msats: 10_000,
                minimum_topup_msats: 10_000,
            },
        )
        .unwrap();
        let route = connector::connect_route_with_runtime(
            &Route::new(vec![cleartext_route_hop(
                fixture.addr.to_string(),
                fixture.pubkey,
                true,
            )])
            .unwrap(),
            &runtime,
        )
        .await;
        if response == 1 {
            let route = route.unwrap();
            let channels = fixture.wallet.list_channels().unwrap();
            assert_eq!(channels.len(), 1);
            assert_eq!(channels[0].commitment_mode, CommitmentMode::Ordinary);
            route.close().await;
        } else {
            assert!(route.is_err());
            assert!(fixture.wallet.list_channels().unwrap().is_empty());
        }
        runtime.wait_for_setup_cleanup().await;
        drop(runtime);
        fixture.shutdown().await;
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn explicit_mode_outside_relay_acceptance_fails_before_provisioning() {
    let fixture = Fixture::new(ModePolicy::default(), Some(CommitmentMode::Rerandomized)).await;
    let runtime = connector::ConnectorRuntime::with_payment_policy(
        Some(fixture.wallet.clone()),
        PaymentPolicy {
            channel_funding_token_target_msats: 100_000,
            target_topup_buffer_msats: 10_000,
            minimum_topup_msats: 10_000,
        },
    )
    .unwrap();
    let result = connector::connect_route_with_runtime(
        &Route::new(vec![cleartext_route_hop(
            fixture.addr.to_string(),
            fixture.pubkey,
            true,
        )])
        .unwrap(),
        &runtime,
    )
    .await;
    assert!(result.is_err());
    assert!(fixture.wallet.list_channels().unwrap().is_empty());
    runtime.wait_for_setup_cleanup().await;
    drop(runtime);
    fixture.shutdown().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn mixed_ordinary_and_rerandomized_nested_route_forwards_data() {
    let entry = Fixture::new(ModePolicy::default(), None).await;
    let exit = Fixture::new(
        ModePolicy {
            accepted: vec![CommitmentMode::Rerandomized],
            preferred: CommitmentMode::Rerandomized,
        },
        None,
    )
    .await;
    let proofs = exit.mint.mint_proofs(1000).await.unwrap();
    entry
        .wallet
        .loose_wallet()
        .import_proofs(&loose_proofs_from_cashu_proofs(
            &exit.offer.mint_url,
            "sat",
            "mixed-modes",
            &proofs,
        ))
        .unwrap();
    let runtime = connector::ConnectorRuntime::with_payment_policy(
        Some(entry.wallet.clone()),
        PaymentPolicy {
            channel_funding_token_target_msats: 100_000,
            target_topup_buffer_msats: 10_000,
            minimum_topup_msats: 10_000,
        },
    )
    .unwrap();
    let route = connector::connect_route_with_runtime(
        &Route::new(vec![
            cleartext_route_hop(entry.addr.to_string(), entry.pubkey, true),
            cleartext_route_hop(exit.addr.to_string(), exit.pubkey, true),
        ])
        .unwrap(),
        &runtime,
    )
    .await
    .unwrap();
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let target = listener.local_addr().unwrap().to_string();
    let echo = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        let mut bytes = [0; 9];
        stream.read_exact(&mut bytes).await.unwrap();
        stream.write_all(&bytes).await.unwrap();
    });
    let mut tunnel = route
        .final_connection_arc()
        .open_tunnel(&target)
        .await
        .unwrap();
    tunnel.write_all(b"dual-mode").await.unwrap();
    let mut received = [0; 9];
    timeout(Duration::from_secs(5), tunnel.read_exact(&mut received))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(&received, b"dual-mode");
    drop(tunnel);
    echo.await.unwrap();
    let channels = entry.wallet.list_channels().unwrap();
    assert_eq!(channels.len(), 2);
    assert_eq!(
        channels
            .iter()
            .find(|c| c.receiver_pubkey == entry.offer.receiver_pubkey)
            .unwrap()
            .commitment_mode,
        CommitmentMode::Ordinary
    );
    assert_eq!(
        channels
            .iter()
            .find(|c| c.receiver_pubkey == exit.offer.receiver_pubkey)
            .unwrap()
            .commitment_mode,
        CommitmentMode::Rerandomized
    );
    assert!(channels.iter().all(|c| c.current_signed_balance_msats > 0));
    route.close().await;
    runtime.wait_for_setup_cleanup().await;
    drop(runtime);
    entry.shutdown().await;
    exit.shutdown().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn stored_rerandomized_channel_relinks_after_trusted_mint_is_removed() {
    let mut fixture = Fixture::new(ModePolicy::dual_mode(), None).await;
    let route = fixture.driver().await;
    let channel = fixture.wallet.list_channels().unwrap().pop().unwrap();
    assert_eq!(channel.commitment_mode, CommitmentMode::Rerandomized);
    route.close().await;
    fixture.restart_without_trust().await;
    let conn = connect_client_quic_secp(fixture.addr, &fixture.pubkey).await;
    let (mut send, mut recv) = conn.open_control().await.unwrap();
    let initial = control_handshake_status(&mut send, &mut recv).await;
    assert!(initial.advertisements.is_empty());
    fixture
        .wallet
        .attach_channel_to_session(&channel.channel_id, *conn.session_id())
        .unwrap();
    let link = fixture
        .wallet
        .build_link_request(&channel.channel_id, &fixture.offer)
        .unwrap();
    send_control_message(&mut send, &channel_link_message(link), false).await;
    let linked = expect_session_status_struct(read_control_message(&mut recv).await)
        .linked_channel
        .unwrap();
    assert_eq!(linked.channel_id, channel.channel_id);
    let payment = fixture
        .wallet
        .build_channel_payment(
            &channel.channel_id,
            &fixture.offer,
            linked.balance_raw,
            linked.balance_raw + 1,
        )
        .unwrap();
    send_control_message(&mut send, &channel_payment_message(payment), false).await;
    let paid = expect_session_status_struct(read_control_message(&mut recv).await);
    assert_eq!(paid.total_paid_millisats, 1000);
    send.send_data(Bytes::new(), true).unwrap();
    conn.close().await;
    fixture.shutdown().await;
}
