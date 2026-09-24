mod support;
use cdk::nuts::{CurrencyUnit, SecretKey};
use monad_client::{
    connector::{connect_route_with_runtime, ConnectorRuntime},
    loose_proof_wallet::{LooseProofWallet, NewLooseProof},
    route::{Route, RouteHop},
    session_driver::PaymentPolicy,
    sqlite_client_wallet::{ChannelFundRecoveryResult, SqliteClientWallet},
    wallet::{MonadWallet, RelayPaymentOffer},
    wallet_lock::{ClientWalletLocks, WalletLockMode},
};
use monad_common::{
    config::RelayChannelPolicyConfig, quic_cert_identity::QuicCertIdentity,
    secp_identity::SecpTransportKeypair,
};
use monad_relay::{
    listener::{run_with_wallet_manager_registry_and_shutdown, ServerConfig},
    payments::CloseOutcome,
    session_registry::SessionRegistry,
    wallet_manager::RelayWalletManager,
};
use std::{
    collections::{BTreeMap, BTreeSet},
    sync::Arc,
    time::Duration,
};
use support::*;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpListener,
};

struct MintConnection {
    client: reqwest::Client,
    url: String,
}
impl MintConnection {
    async fn post<T: serde::de::DeserializeOwned>(
        &self,
        path: &str,
        body: impl serde::Serialize,
    ) -> anyhow::Result<T> {
        Ok(self
            .client
            .post(format!("{}{path}", self.url))
            .json(&body)
            .send()
            .await?
            .error_for_status()?
            .json()
            .await?)
    }
}
#[async_trait::async_trait]
impl cdk_spilman::MintConnection for MintConnection {
    async fn process_swap(
        &self,
        request: cdk::nuts::SwapRequest,
    ) -> anyhow::Result<cdk::nuts::SwapResponse> {
        self.post("/v1/swap", request).await
    }
    async fn post_restore(
        &self,
        request: cdk::nuts::RestoreRequest,
    ) -> anyhow::Result<cdk::nuts::RestoreResponse> {
        self.post("/v1/restore", request).await
    }
    async fn check_state(
        &self,
        ys: Vec<cdk::nuts::PublicKey>,
    ) -> anyhow::Result<cdk::nuts::CheckStateResponse> {
        self.post("/v1/checkstate", serde_json::json!({"Ys":ys}))
            .await
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn mixed_sat_msat_route_survives_rotation_and_recovers_old_and_new_channels() {
    tokio::time::timeout(Duration::from_secs(90), exercise())
        .await
        .unwrap();
}

async fn exercise() {
    let _ = tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "warn".into()),
        )
        .with_test_writer()
        .try_init();
    let dir = tempfile::tempdir().unwrap();
    let mint_group = Running::start(config(dir.path(), &["mint"])).await;
    let view = view(&mint_group.client).await;
    let url = view["data"]["instances"]["mint"]["base_url"]
        .as_str()
        .unwrap()
        .to_owned();
    let http = reqwest::Client::builder()
        .timeout(Duration::from_secs(15))
        .build()
        .unwrap();
    let loose_path = dir.path().join("loose.db");
    let channel_path = dir.path().join("channels.db");
    let authority =
        ClientWalletLocks::acquire(&loose_path, &channel_path, WalletLockMode::Runtime).unwrap();
    let loose = LooseProofWallet::open(&loose_path, "mixed-units").unwrap();
    let mut initial = BTreeMap::new();
    for (unit, label, amount) in [
        (CurrencyUnit::Sat, "sat", 8192),
        (CurrencyUnit::Msat, "msat", 1_048_576),
    ] {
        let proofs = mint_proofs(&http, &url, unit, &[amount]).await;
        initial.insert(label, proofs[0].keyset_id.to_string());
        loose
            .import_proofs(
                &proofs
                    .into_iter()
                    .map(|proof| NewLooseProof {
                        proof_id: proof.y().unwrap().to_hex(),
                        mint_url: url.clone(),
                        unit: label.into(),
                        keyset_id: proof.keyset_id.to_string(),
                        amount_raw: proof.amount.to_u64(),
                        proof_json: serde_json::to_string(&proof).unwrap(),
                        source_quote_id: None,
                        source_batch_id: None,
                    })
                    .collect::<Vec<_>>(),
            )
            .unwrap();
    }
    let wallet = Arc::new(
        SqliteClientWallet::open(loose, &channel_path, &SecretKey::generate().to_secret_hex())
            .unwrap(),
    );
    let relay_wallet = Arc::new(
        RelayWalletManager::open(dir.path().join("relay.db").display().to_string()).unwrap(),
    );
    let trusted = BTreeMap::from([(url.clone(), BTreeSet::from(["sat".into(), "msat".into()]))]);
    relay_wallet
        .refresh_trusted_mint_cache(&trusted)
        .await
        .unwrap();
    let mut stops = Vec::new();
    let mut relays = Vec::new();
    let mut hops = Vec::new();
    let mut offers = BTreeMap::new();
    for unit in ["sat", "msat"] {
        let name = format!("relay-{unit}");
        let secret = SecretKey::generate();
        relay_wallet
            .register_identity(&name, secret.clone())
            .unwrap();
        let transport = SecpTransportKeypair::generate();
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        hops.push(RouteHop::Cleartext {
            addr: listener.local_addr().unwrap().to_string(),
            pubkey: transport.pubkey(),
            use_quic: false,
        });
        let config = Arc::new(ServerConfig {
            identity: QuicCertIdentity::generate().unwrap(),
            transport_key: Some(transport),
            receiver_pubkey_hex: secret.public_key().to_hex(),
            trusted_mint_units: BTreeMap::from([(url.clone(), BTreeSet::from([unit.into()]))]),
            in_bytes_per_millisat: 1,
            out_bytes_per_millisat: 1,
            bootstrap_capabilities: None,
            relay_wallet_name: name,
            spilman_storage_path: relay_wallet.db_path().into(),
            channel_policy: RelayChannelPolicyConfig::default(),
        });
        offers.insert(
            unit,
            RelayPaymentOffer {
                funding_keyset_recovery_window_secs: 86_400,
                receiver_pubkey: secret.public_key().to_hex(),
                mint_url: url.clone(),
                unit: unit.into(),
                preferred_keyset_ids: vec![initial[unit].clone()],
                negotiated_keyset_versions: BTreeSet::from(["v1".into(), "v2".into()]),
                in_bytes_per_millisat: 1,
                out_bytes_per_millisat: 1,
            },
        );
        let (stop, stopped) = tokio::sync::oneshot::channel();
        stops.push(stop);
        relays.push(tokio::spawn(run_with_wallet_manager_registry_and_shutdown(
            listener,
            None,
            config,
            relay_wallet.clone(),
            Arc::new(SessionRegistry::new()),
            async {
                let _ = stopped.await;
            },
        )));
    }
    let runtime = ConnectorRuntime::with_payment_policy(
        Some(wallet.clone()),
        PaymentPolicy {
            channel_funding_token_target_msats: 100_000,
            target_topup_buffer_msats: 20_000,
            minimum_topup_msats: 0,
        },
    )
    .unwrap();
    let route = connect_route_with_runtime(&Route::new(hops.clone()).unwrap(), &runtime)
        .await
        .unwrap();
    assert_eq!(wallet.list_channels().unwrap().len(), 2);
    let old_sessions = route.hops().to_vec();
    let mut new_keys = BTreeMap::new();
    for (unit, fee) in [("sat", 750), ("msat", 900)] {
        let rotated = rotate(
            &mint_group.client,
            &view["generation"],
            unit,
            "mint",
            unit,
            fee,
        )
        .await;
        new_keys.insert(
            unit,
            rotated["active_keyset_id"].as_str().unwrap().to_owned(),
        );
    }
    let target = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let target_addr = target.local_addr().unwrap();
    let echo = tokio::spawn(async move {
        let (mut peer, _) = target.accept().await.unwrap();
        let mut bytes = [0; 256];
        loop {
            let n = peer.read(&mut bytes).await.unwrap();
            if n == 0 {
                break;
            }
            peer.write_all(&bytes[..n]).await.unwrap();
        }
    });
    let mut tunnel = route
        .final_connection_arc()
        .open_tunnel(&target_addr.to_string())
        .await
        .unwrap();
    tunnel.write_all(b"fractional msat check").await.unwrap();
    let mut reply = [0; 21];
    tunnel.read_exact(&mut reply).await.unwrap();
    assert_eq!(&reply, b"fractional msat check");
    tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            let channels = wallet.list_channels().unwrap();
            if channels
                .iter()
                .any(|c| c.unit == "msat" && c.current_signed_balance_msats % 1000 != 0)
            {
                break;
            }
            tokio::time::sleep(Duration::from_millis(25)).await;
        }
    })
    .await
    .unwrap();
    assert_eq!(
        route
            .hops()
            .iter()
            .map(|h| h.session_id)
            .collect::<Vec<_>>(),
        old_sessions
            .iter()
            .map(|h| h.session_id)
            .collect::<Vec<_>>()
    );
    let mut new_routes = Vec::new();
    for (i, unit) in ["sat", "msat"].into_iter().enumerate() {
        // Intentionally keep the pre-rotation offer/cache. Normal wallet retry
        // and relay unknown-keyset discovery must handle the new active keyset.
        // Use a deliberately distinct funding intent, rather than relying on
        // the expiry clock advancing to avoid an identical channel identifier.
        let id = wallet.provision_channel(&offers[unit], 120_000).unwrap();
        let channel = wallet.get_channel(&id).unwrap();
        assert_eq!(channel.keyset_id, new_keys[unit]);
        let fresh =
            connect_route_with_runtime(&Route::new(vec![hops[i].clone()]).unwrap(), &runtime)
                .await
                .unwrap();
        let stored = relay_wallet
            .list_channels(Some(&format!("relay-{unit}")))
            .unwrap()
            .into_iter()
            .find(|c| c.channel_id == id)
            .unwrap();
        assert_eq!(
            stored.capacity_raw * if unit == "sat" { 1000 } else { 1 },
            channel.capacity_msats
        );
        assert_eq!(
            stored.balance_raw * if unit == "sat" { 1000 } else { 1 },
            20_000
        );
        new_routes.push(fresh);
    }
    assert_eq!(wallet.list_channels().unwrap().len(), 4);
    drop(tunnel);
    route.close().await;
    for route in new_routes {
        route.close().await;
    }
    echo.await.unwrap();
    let network = MintConnection {
        client: http,
        url: url.clone(),
    };
    for channel in wallet.list_channels().unwrap() {
        let net = relay_wallet
            .mint_client_for_channel(&channel.channel_id)
            .unwrap();
        let closed = match relay_wallet
            .close_channel(&channel.channel_id, &net)
            .await
            .unwrap()
        {
            CloseOutcome::Closed(closed) => closed,
            _ => panic!("expected receiver close"),
        };
        let keys = [new_keys[channel.unit.as_str()].clone()];
        let before = wallet
            .loose_wallet()
            .available_balance_raw(&url, &channel.unit, &keys)
            .unwrap();
        let recovered = wallet
            .recover_channel_funds(
                &authority.exclusive_access().unwrap(),
                &channel.channel_id,
                &network,
            )
            .await
            .unwrap();
        let amount = match recovered {
            ChannelFundRecoveryResult::RelayCloseRecovered {
                recovered_amount_raw,
                ..
            } => recovered_amount_raw,
            _ => panic!("expected sender recovery"),
        };
        assert_eq!(amount, closed.sender_sum);
        assert_eq!(
            wallet
                .loose_wallet()
                .available_balance_raw(&url, &channel.unit, &keys)
                .unwrap()
                - before,
            amount
        );
    }
    drop(route);
    drop(runtime);
    for stop in stops {
        stop.send(()).unwrap();
    }
    for relay in relays {
        relay.await.unwrap().unwrap();
    }
    mint_group.stop().await;
}
