use super::*;
use monad_common::rejection::{Rejection, RejectionCode};
use monad_relay::session_registry::RelayControls;

struct Relay {
    addr: SocketAddr,
    pubkey: Secp256k1Pubkey,
    registry: Arc<SessionRegistry>,
    stop: tokio::sync::oneshot::Sender<()>,
    task: tokio::task::JoinHandle<io::Result<()>>,
}

impl Relay {
    async fn start() -> Self {
        let identity = QuicCertIdentity::generate().unwrap();
        let key = SecpTransportKeypair::generate();
        let pubkey = key.pubkey();
        let km = monad_quic::keygen::generate_from_seed(identity.seed()).unwrap();
        let quic = monad_quic::server::build_server_config(&km.cert_pem, &km.key_pem).unwrap();
        let (listener, endpoint, addr) =
            bind_tcp_and_quic_on_same_port("127.0.0.1:0".parse().unwrap(), quic)
                .await
                .unwrap();
        let config = Arc::new(ServerConfig {
            identity,
            transport_key: Some(key),
            receiver_pubkey_hex: "receiver".into(),
            trusted_mint_units: synthetic_trusted_mint_units(),
            in_bytes_per_millisat: 1,
            out_bytes_per_millisat: 1,
            bootstrap_capabilities: None,
            relay_wallet_name: "admission".into(),
            spilman_storage_path: String::new(),
            channel_policy: Default::default(),
        });
        let registry = Arc::new(SessionRegistry::new());
        let (stop, stopped) = tokio::sync::oneshot::channel();
        let task = tokio::spawn(run_with_payments_and_registry_and_shutdown(
            listener,
            Some(endpoint),
            config,
            Arc::new(InMemoryRelayPayments::new()),
            shared_spilman_mint_cache(synthetic_test_mint_cache()),
            RelayRuntimeServices::new(registry.clone()),
            async {
                let _ = stopped.await;
            },
        ));
        Self {
            addr,
            pubkey,
            registry,
            stop,
            task,
        }
    }
    async fn finish(self) {
        self.stop.send(()).unwrap();
        timeout(Duration::from_secs(8), self.task)
            .await
            .unwrap()
            .unwrap()
            .unwrap();
    }
    fn hop(&self, quic: bool) -> monad_client::route::RouteHop {
        monad_client::route::RouteHop::Cleartext {
            addr: self.addr.to_string(),
            pubkey: self.pubkey,
            use_quic: quic,
        }
    }
}

#[tokio::test]
async fn administrative_bootstrap_rejections_work_on_tcp_and_reused_quic() {
    let relay = Relay::start().await;
    let pool = monad_quic::pool::QuicPool::new().unwrap();
    // Establish authentication and a reusable underlying connection first.
    let mut warm = pool
        .open_stream(
            &relay.addr.to_string(),
            monad_quic::client::ClientAuthMode::Secp256k1(relay.pubkey),
        )
        .await
        .unwrap();
    noise_secp256k1::handshake_initiator(&mut warm, &relay.pubkey)
        .await
        .unwrap();
    drop(warm);
    for (controls, expected) in [
        (
            RelayControls {
                accept_new_sessions: false,
                ..Default::default()
            },
            RejectionCode::SessionAdmissionDisabled,
        ),
        (
            RelayControls {
                enabled: false,
                ..Default::default()
            },
            RejectionCode::RelayDisabled,
        ),
    ] {
        relay.registry.set_controls(controls).unwrap();
        let mut tcp = TcpStream::connect(relay.addr).await.unwrap();
        let error = noise_secp256k1::handshake_initiator(&mut tcp, &relay.pubkey)
            .await
            .err()
            .unwrap();
        assert_eq!(Rejection::from_io(&error).unwrap().code, expected);
        let mut quic = pool
            .open_stream(
                &relay.addr.to_string(),
                monad_quic::client::ClientAuthMode::Secp256k1(relay.pubkey),
            )
            .await
            .unwrap();
        let error = noise_secp256k1::handshake_initiator(&mut quic, &relay.pubkey)
            .await
            .err()
            .unwrap();
        assert_eq!(Rejection::from_io(&error).unwrap().code, expected);
    }
    relay.registry.wait_disabled().await.unwrap();
    assert!(relay.registry.snapshots().await.is_empty());
    drop(pool);
    relay.finish().await;
}

#[tokio::test]
async fn administrative_wait_preserves_prefix_and_outlives_setup_budget() {
    use monad_client::{
        connector::{connect_route_with_runtime, ConnectorRuntime},
        management::ClientManagement,
        route::Route,
        session_driver::PaymentPolicy,
        wallet::{MockWallet, MonadWallet},
    };
    for (first_quic, next_quic, refuse_session) in [(false, true, true), (true, false, false)] {
        let first = Relay::start().await;
        let second = Relay::start().await;
        if refuse_session {
            second
                .registry
                .set_controls(RelayControls {
                    accept_new_sessions: false,
                    ..Default::default()
                })
                .unwrap();
        } else {
            first
                .registry
                .set_controls(RelayControls {
                    accept_new_tunnels: false,
                    ..Default::default()
                })
                .unwrap();
        }
        let wallet = Arc::new(MockWallet::new());
        let management = Arc::new(ClientManagement::default());
        let runtime = ConnectorRuntime::with_payment_policy(
            Some(wallet.clone()),
            PaymentPolicy {
                channel_funding_token_target_msats: 10_000_000,
                target_topup_buffer_msats: 1_000_000,
                minimum_topup_msats: 0,
            },
        )
        .unwrap()
        .with_management(management.clone())
        .with_setup_timeout(Duration::from_secs(1));
        let route = Route::new(vec![first.hop(first_quic), second.hop(next_quic)]).unwrap();
        let rt = runtime.clone();
        let task = tokio::spawn(async move { connect_route_with_runtime(&route, &rt).await });
        let mut changes = management.changes();
        let waiting = timeout(Duration::from_secs(3), async {
            loop {
                changes.borrow_and_update();
                if let monad_client::management::ClientLifecycle::WaitingForAdmission {
                    wait, ..
                } = management.runtime_snapshot().lifecycle
                {
                    break wait;
                }
                changes.changed().await.unwrap();
            }
        })
        .await
        .unwrap();
        assert_eq!(
            waiting.refusal.refusing_hop,
            if refuse_session { 2 } else { 1 }
        );
        assert_eq!(waiting.refusal.target_hop, 2);
        assert_eq!(
            waiting.refusal.operation,
            if refuse_session { "session" } else { "connect" }
        );
        let prefix = management.hops()[0].session_id.clone();
        assert_eq!(wallet.list_channels().unwrap().len(), 1);
        tokio::time::sleep(Duration::from_millis(1200)).await;
        assert!(!task.is_finished());
        first.registry.set_controls(Default::default()).unwrap();
        second.registry.set_controls(Default::default()).unwrap();
        let route = timeout(Duration::from_secs(6), task)
            .await
            .unwrap()
            .unwrap()
            .unwrap();
        assert!(!matches!(
            management.runtime_snapshot().lifecycle,
            monad_client::management::ClientLifecycle::WaitingForAdmission { .. }
        ));
        assert!(management.hops().iter().any(|h| h.session_id == prefix));
        assert_eq!(wallet.list_channels().unwrap().len(), 2);
        route.close().await;
        drop(route);
        drop(runtime);
        first.finish().await;
        second.finish().await;
    }
}

#[tokio::test]
async fn prefix_failure_interrupts_administrative_wait_and_releases_attachments() {
    use monad_client::{
        connector::{connect_route_with_runtime, ConnectorRuntime},
        management::ClientManagement,
        route::Route,
        wallet::{MockWallet, MonadWallet},
    };
    let first = Relay::start().await;
    let second = Relay::start().await;
    second
        .registry
        .set_controls(RelayControls {
            accept_new_sessions: false,
            ..Default::default()
        })
        .unwrap();
    let wallet = Arc::new(MockWallet::new());
    let management = Arc::new(ClientManagement::default());
    let runtime = ConnectorRuntime::new(Some(wallet.clone()))
        .unwrap()
        .with_management(management.clone());
    let route = Route::new(vec![first.hop(false), second.hop(true)]).unwrap();
    let rt = runtime.clone();
    let task = tokio::spawn(async move { connect_route_with_runtime(&route, &rt).await });
    let mut changes = management.changes();
    timeout(Duration::from_secs(3), async {
        loop {
            changes.borrow_and_update();
            if matches!(
                management.runtime_snapshot().lifecycle,
                monad_client::management::ClientLifecycle::WaitingForAdmission { .. }
            ) {
                break;
            }
            changes.changed().await.unwrap();
        }
    })
    .await
    .unwrap();
    first
        .registry
        .set_controls(RelayControls {
            enabled: false,
            ..Default::default()
        })
        .unwrap();
    assert!(timeout(Duration::from_secs(2), task)
        .await
        .unwrap()
        .unwrap()
        .is_err());
    assert!(!matches!(
        management.runtime_snapshot().lifecycle,
        monad_client::management::ClientLifecycle::WaitingForAdmission { .. }
    ));
    assert!(management.hops().is_empty());
    assert!(matches!(
        management.runtime_snapshot().lifecycle,
        monad_client::management::ClientLifecycle::Connecting { .. }
    ));
    assert!(wallet
        .list_channels()
        .unwrap()
        .iter()
        .all(|c| c.attached_session_id.is_none()));
    drop(runtime);
    first.finish().await;
    second.finish().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn management_disable_cancels_administrative_wait_promptly() {
    use serde_json::{json, Value};
    let relay = Relay::start().await;
    relay
        .registry
        .set_controls(RelayControls {
            enabled: false,
            ..Default::default()
        })
        .unwrap();
    let dir = tempfile::tempdir().unwrap();
    let socks = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = socks.local_addr().unwrap();
    drop(socks);
    let socket = dir.path().join("management.sock");
    let config: MonadConfig = serde_json::from_value(json!({
        "client_wallet": {"loose_db_path": dir.path().join("loose.db"), "channel_db_path": dir.path().join("channels.db"), "sender_secret_hex": hex::encode([9u8;32])},
        "clients": [{"name":"local", "socks": addr.to_string(), "route": [format!("{}::{}", relay.pubkey.to_hex(), relay.addr)]}],
        "management": {"listen":"127.0.0.1:0", "client_socket": socket},
    })).unwrap();
    config.validate().unwrap();
    let (stop, stopped) = tokio::sync::oneshot::channel();
    let task = tokio::spawn(monad_client::runtime::run_configured_client_until_shutdown(
        config,
        None,
        async {
            let _ = stopped.await;
        },
    ));
    let client = monad_management::unix_client(socket).unwrap();
    let snapshot: Value = timeout(Duration::from_secs(5), async {
        loop {
            if let Ok(response) = client.get("http://localhost/v1/snapshot").send().await {
                let view: Value = response.json().await.unwrap();
                if view["data"]["instances"]["local"]["runtime"]["lifecycle"]["state"]
                    == "waiting_for_admission"
                {
                    break view;
                }
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .unwrap();
    assert_eq!(
        snapshot["data"]["instances"]["local"]["runtime"]["lifecycle"]["wait"]["refusal"]
            ["rejection"]["code"],
        "RELAY_DISABLED"
    );
    let response = client.post("http://localhost/v1/commands").json(&json!({
        "generation": snapshot["generation"], "request_id":"disable", "instance":"local", "action":"set_enabled", "arguments":{"enabled":false}
    })).send().await.unwrap();
    assert_eq!(response.status(), 202);
    timeout(Duration::from_secs(2), async {
        loop {
            let op: Value = client
                .get("http://localhost/v1/operations/disable")
                .send()
                .await
                .unwrap()
                .json()
                .await
                .unwrap();
            if op["state"] == "succeeded" {
                break;
            }
            assert_ne!(op["state"], "failed");
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .unwrap();
    let view: Value = client
        .get("http://localhost/v1/snapshot")
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(
        view["data"]["instances"]["local"]["runtime"]["lifecycle"]["state"],
        "disabled"
    );
    assert_eq!(view["data"]["instances"]["local"]["hops"], json!([]));
    stop.send(()).unwrap();
    timeout(Duration::from_secs(3), task)
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    relay.finish().await;
}

#[tokio::test]
async fn channel_admission_wait_retains_funding_in_automatic_mode() {
    use monad_client::{
        connector::{connect_route_with_runtime, ConnectorRuntime},
        management::ClientManagement,
        route::Route,
        wallet::{MockWallet, MonadWallet},
    };
    let relay = Relay::start().await;
    relay
        .registry
        .set_controls(RelayControls {
            accept_new_channels: false,
            ..Default::default()
        })
        .unwrap();
    let wallet = Arc::new(MockWallet::new());
    let management = Arc::new(ClientManagement::default());
    let runtime = ConnectorRuntime::new(Some(wallet.clone()))
        .unwrap()
        .with_management(management.clone())
        .with_setup_timeout(Duration::from_secs(1));
    let route = Route::new(vec![relay.hop(true)]).unwrap();
    let rt = runtime.clone();
    let task = tokio::spawn(async move { connect_route_with_runtime(&route, &rt).await });
    let mut changes = management.changes();
    timeout(Duration::from_secs(3), async {
        loop {
            changes.borrow_and_update();
            if management.hops().iter().any(|h| {
                matches!(
                    h.funding,
                    monad_client::management::HopFundingState::WaitingForRelayAdmission { .. }
                )
            }) {
                break;
            }
            changes.changed().await.unwrap();
        }
    })
    .await
    .unwrap();
    let funded_id = wallet.list_channels().unwrap()[0].channel_id.clone();
    assert!(matches!(
        management.hops()[0].funding,
        monad_client::management::HopFundingState::WaitingForRelayAdmission { ref rejection }
            if rejection.code == RejectionCode::ChannelAdmissionDisabled
    ));
    tokio::time::sleep(Duration::from_millis(1200)).await;
    assert!(!task.is_finished());
    relay.registry.set_controls(Default::default()).unwrap();
    let route = timeout(Duration::from_secs(6), task)
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    assert_eq!(wallet.list_channels().unwrap().len(), 1);
    assert_eq!(
        management.hops()[0]
            .linked_channel
            .as_ref()
            .unwrap()
            .channel_id,
        funded_id
    );
    assert!(!matches!(
        management.hops()[0].funding,
        monad_client::management::HopFundingState::WaitingForRelayAdmission { .. }
    ));
    route.close().await;
    drop(route);
    drop(runtime);
    relay.finish().await;
}

async fn policy_peer() -> (
    SocketAddr,
    Secp256k1Pubkey,
    Arc<std::sync::atomic::AtomicUsize>,
    tokio::task::JoinHandle<()>,
) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let key = SecpTransportKeypair::generate();
    let pubkey = key.pubkey();
    let count = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let observed = count.clone();
    let task = tokio::spawn(async move {
        let (mut tcp, _) = listener.accept().await.unwrap();
        let (send, recv, id) = noise_secp256k1::handshake_responder_with_secret_key_bytes(
            &mut tcp,
            key.normalized_secret_bytes(),
        )
        .await
        .unwrap();
        let stream = noise_secp256k1::SecpNoiseStream::new(tcp, send, recv, id, "policy fixture");
        let mut server = h2::server::handshake(stream).await.unwrap();
        let mut bodies = Vec::new();
        while let Some(Ok((request, mut respond))) = server.accept().await {
            let number = observed.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            bodies.push(request.into_body());
            if number == 0 {
                let code = RejectionCode::DestinationPolicyDenied;
                respond
                    .send_response(
                        http::Response::builder()
                            .status(403)
                            .header(
                                monad_common::rejection::CONNECT_REJECTION_HEADER,
                                code.header_value(),
                            )
                            .body(())
                            .unwrap(),
                        true,
                    )
                    .unwrap();
            } else {
                let mut send = respond
                    .send_response(http::Response::new(()), false)
                    .unwrap();
                send.send_data(Bytes::from_static(b"ok"), true).unwrap();
            }
        }
    });
    (addr, pubkey, count, task)
}

#[tokio::test]
async fn onward_destination_policy_denial_is_typed_and_not_retried() {
    use monad_client::{
        admission::RouteRefusal,
        connector::{connect_route_with_runtime, ConnectorRuntime},
        route::{Route, RouteHop},
    };
    for use_quic in [false, true] {
        let (addr, pubkey, count, task) = policy_peer().await;
        let route = Route::new(vec![
            RouteHop::Cleartext {
                addr: addr.to_string(),
                pubkey,
                use_quic: false,
            },
            RouteHop::Cleartext {
                addr: "127.0.0.1:1".into(),
                pubkey,
                use_quic,
            },
        ])
        .unwrap();
        let runtime = ConnectorRuntime::new(None).unwrap();
        let error = timeout(
            Duration::from_secs(2),
            connect_route_with_runtime(&route, &runtime),
        )
        .await
        .unwrap()
        .err()
        .unwrap();
        assert!(RouteRefusal::is_policy_denial(&error));
        let refusal = RouteRefusal::from_io(&error).unwrap();
        assert_eq!(
            (refusal.refusing_hop, refusal.target_hop, refusal.operation),
            (1, 2, "connect")
        );
        assert_eq!(count.load(std::sync::atomic::Ordering::SeqCst), 1);
        timeout(Duration::from_secs(2), task)
            .await
            .unwrap()
            .unwrap();
    }
}

#[tokio::test]
async fn exit_policy_denial_returns_socks_failure_and_preserves_connection() {
    let (addr, pubkey, count, task) = policy_peer().await;
    let conn = connect_client_tcp(addr, &pubkey).await;
    let local = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let mut peer = TcpStream::connect(local.local_addr().unwrap())
        .await
        .unwrap();
    let (mut socket, _) = local.accept().await.unwrap();
    let error = monad_client::tunnel::open_tunnel(&conn, "denied.example:443", &mut socket)
        .await
        .unwrap_err();
    assert_eq!(
        Rejection::from_io(&error).unwrap().code,
        RejectionCode::DestinationPolicyDenied
    );
    let mut reply = [0; 10];
    peer.read_exact(&mut reply).await.unwrap();
    assert_eq!(reply[1], 0x02);
    let mut allowed = conn.open_tunnel("allowed.example:443").await.unwrap();
    let mut body = [0; 2];
    allowed.read_exact(&mut body).await.unwrap();
    assert_eq!(&body, b"ok");
    assert_eq!(count.load(std::sync::atomic::Ordering::SeqCst), 2);
    drop(allowed);
    conn.close().await;
    timeout(Duration::from_secs(2), task)
        .await
        .unwrap()
        .unwrap();
}
