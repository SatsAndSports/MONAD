use super::*;
use serde_json::{json, Value};

async fn snapshot(client: &reqwest::Client) -> Value {
    timeout(Duration::from_secs(10), async {
        loop {
            if let Ok(response) = client.get("http://localhost/v1/snapshot").send().await {
                if response.status().is_success() {
                    return response.json().await.unwrap();
                }
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .unwrap()
}

async fn command(
    client: &reqwest::Client,
    generation: &Value,
    id: &str,
    instance: &str,
    action: &str,
    arguments: Value,
) -> Value {
    let response = client.post("http://localhost/v1/commands").json(&json!({
        "generation": generation, "request_id": id, "instance": instance, "action": action, "arguments": arguments,
    })).send().await.unwrap();
    assert_eq!(response.status(), 202);
    timeout(Duration::from_secs(30), async {
        loop {
            let result: Value = client
                .get(format!("http://localhost/v1/operations/{id}"))
                .send()
                .await
                .unwrap()
                .json()
                .await
                .unwrap();
            match result["state"].as_str().unwrap() {
                "succeeded" => return result["result"].clone(),
                "failed" => panic!("management command failed: {result}"),
                _ => tokio::time::sleep(Duration::from_millis(10)).await,
            }
        }
    })
    .await
    .unwrap()
}

#[tokio::test(flavor = "multi_thread")]
async fn unix_api_drives_real_manual_funding_disable_and_channel_close() {
    let fixture = ConfiguredRouteFixture::start(ConfiguredRouteFixtureConfig {
        subnet: 80,
        hop_count: 1,
        proof_batches: 1,
        wallet_seed: 80,
        channel_funding_token_target_msats: 5_000_000,
        label: "management-api",
    })
    .await;
    let socket_dir = tempfile::tempdir().unwrap();
    let client_socket = socket_dir.path().join("client.sock");
    let relay_socket = socket_dir.path().join("relay.sock");
    let mut config = fixture.config.clone();
    config.management = Some(
        serde_json::from_value(json!({
            "listen": "127.0.0.1:0", "client_socket": client_socket,
            "manual_funding_clients": ["local"],
        }))
        .unwrap(),
    );
    let (stop_client, stopped_client) = tokio::sync::oneshot::channel();
    let client_task = tokio::spawn(monad_client::runtime::run_configured_client_until_shutdown(
        config,
        Some("local"),
        async {
            let _ = stopped_client.await;
        },
    ));
    let client = monad_management::unix_client(client_socket).unwrap();
    let initial = snapshot(&client).await;
    let generation = initial["generation"].clone();
    let session = timeout(Duration::from_secs(10), async {
        loop {
            let view = snapshot(&client).await;
            if let Some(hops) = view["data"]["instances"]["local"]["hops"].as_array() {
                if let Some(hop) = hops
                    .iter()
                    .find(|h| h["waiting_for_manual_funding"] == true)
                {
                    return hop["session_id"].as_str().unwrap().to_owned();
                }
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .unwrap();
    assert!(fixture
        .wallet_manager
        .list_channels(None)
        .unwrap()
        .is_empty());
    let funded = command(
        &client,
        &generation,
        "fund",
        "local",
        "provision_channel",
        json!({"session_id": session}),
    )
    .await;
    let channel = funded["linked_channel_id"].as_str().unwrap();
    let payload = b"management api";
    assert_eq!(
        timeout(
            Duration::from_secs(10),
            configured_client_socks_roundtrip(fixture.socks_listen, fixture.upper_addr, payload)
        )
        .await
        .unwrap()
        .unwrap(),
        b"MANAGEMENT API"
    );
    command(
        &client,
        &generation,
        "disable",
        "local",
        "set_enabled",
        json!({"enabled": false}),
    )
    .await;
    let view = snapshot(&client).await;
    assert_eq!(view["data"]["instances"]["local"]["running"], false);
    assert_eq!(view["data"]["instances"]["local"]["hops"], json!([]));
    let public = view.to_string();
    assert!(!public.contains(&fixture.sender_secret_hex));
    assert!(!public.contains("proof_json"));
    let name = fixture.relay_names[0].clone();
    // Reuse the actual wallet's close path. Admission controls are exercised by
    // the listener-specific integration test; this endpoint tests wallet actions.
    let backend = Arc::new(monad_relay::management::RelayBackend::new(
        BTreeMap::from([(name.clone(), Arc::new(SessionRegistry::new()))]),
        fixture.wallet_manager.clone(),
    ));
    let (stop_relay_api, stopped_relay_api) = tokio::sync::oneshot::channel();
    let relay_task = tokio::spawn(monad_management::serve_unix(
        relay_socket.clone(),
        backend,
        async {
            let _ = stopped_relay_api.await;
        },
    ));
    let relay = monad_management::unix_client(relay_socket).unwrap();
    let view = snapshot(&relay).await;
    let closed = command(
        &relay,
        &view["generation"],
        "close",
        &name,
        "close_channel",
        json!({"channel_id": channel}),
    )
    .await;
    assert_eq!(closed["outcome"], "closed");
    assert_eq!(
        fixture.wallet_manager.list_channels(Some(&name)).unwrap()[0].state,
        cdk_spilman::ChannelState::Closed
    );
    stop_client.send(()).unwrap();
    client_task.await.unwrap().unwrap();
    stop_relay_api.send(()).unwrap();
    relay_task.await.unwrap().unwrap();
    fixture.shutdown().await;
}
