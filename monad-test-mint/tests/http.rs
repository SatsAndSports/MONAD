mod support;
use cdk::nuts::CurrencyUnit;
use serde_json::{json, Value};
use support::*;

#[tokio::test(flavor = "multi_thread")]
async fn http_mints_rotate_per_unit_and_charge_old_and_new_fees_with_rounding() {
    let dir = tempfile::tempdir().unwrap();
    let config = config(dir.path(), &["one", "two"]);
    let group = Running::start(config.clone()).await;
    let aggregate =
        monad_management::aggregate::Aggregator::new(std::collections::BTreeMap::from([(
            "test-mints".into(),
            config
                .management
                .as_ref()
                .unwrap()
                .test_mint_socket
                .clone()
                .unwrap(),
        )]))
        .unwrap();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let api = format!("http://{}", listener.local_addr().unwrap());
    let (stop_api, stopped_api) = tokio::sync::oneshot::channel();
    let api_task = tokio::spawn(monad_management::aggregate::serve(
        listener,
        aggregate,
        async {
            let _ = stopped_api.await;
        },
    ));
    let before = view(&group.client).await;
    let url = before["data"]["instances"]["one"]["base_url"]
        .as_str()
        .unwrap();
    let client = reqwest::Client::new();
    let mut events = client
        .get(format!("{api}/v1/events?process=test-mints"))
        .send()
        .await
        .unwrap();
    for (unit, label, new_fee, expected_fee) in [
        (CurrencyUnit::Sat, "sat", 750u64, 4u64),
        (CurrencyUnit::Msat, "msat", 900, 5),
    ] {
        let old = mint_proofs(&client, url, unit.clone(), &[1024; 5]).await;
        let rotation = rotate_at(
            &client,
            &format!("{api}/v1/processes/test-mints"),
            &before["generation"],
            label,
            "one",
            label,
            new_fee,
        )
        .await;
        assert_eq!(rotation["previous_keyset_id"], old[0].keyset_id.to_string());
        let new = mint_proofs(&client, url, unit.clone(), &[1024; 3]).await;
        assert_eq!(rotation["active_keyset_id"], new[0].keyset_id.to_string());
        let inputs = old[..2].iter().cloned().chain(new).collect::<Vec<_>>();
        let (id, keys) = active(&client, url, unit.clone()).await;
        // Underpay by one raw unit. This must fail without spending the inputs;
        // the subsequent correctly rounded request must still work.
        let amount = 5 * 1024 - expected_fee + 1;
        let amounts = (0..32)
            .filter_map(|i| {
                if amount & (1u64 << i) != 0 {
                    Some(1u64 << i)
                } else {
                    None
                }
            })
            .collect::<Vec<_>>();
        let output = premint(id, &keys, &amounts);
        let bad = cdk::nuts::SwapRequest::new(inputs.clone(), output.blinded_messages());
        assert!(client
            .post(format!("{url}/v1/swap"))
            .json(&bad)
            .send()
            .await
            .unwrap()
            .status()
            .is_client_error());
        swap(&client, url, unit, inputs, expected_fee).await;
    }
    let after = view(&group.client).await;
    tokio::time::timeout(std::time::Duration::from_secs(5), async {
        let mut received = String::new();
        while !received.contains("event: keyset_rotated") {
            received
                .push_str(std::str::from_utf8(&events.chunk().await.unwrap().unwrap()).unwrap());
        }
    })
    .await
    .unwrap();
    assert_eq!(
        after["data"]["instances"]["one"]["keysets"]
            .as_array()
            .unwrap()
            .len(),
        4,
        "duplicate commands must not rotate twice"
    );
    assert_eq!(
        after["data"]["instances"]["two"]["keysets"],
        before["data"]["instances"]["two"]["keysets"]
    );
    let mut invalid = json!({"generation":before["generation"], "request_id":"invalid", "instance":"one", "action":"rotate_keyset", "arguments":{"unit":"usd","input_fee_ppk":0}});
    assert_eq!(
        group
            .client
            .post("http://localhost/v1/commands")
            .json(&invalid)
            .send()
            .await
            .unwrap()
            .status(),
        202
    );
    tokio::time::timeout(std::time::Duration::from_secs(3), async {
        loop {
            let status: Value = group
                .client
                .get("http://localhost/v1/operations/invalid")
                .send()
                .await
                .unwrap()
                .json()
                .await
                .unwrap();
            if status["state"] == "failed" {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }
    })
    .await
    .unwrap();
    invalid["arguments"]["unit"] = json!("sat");
    assert_eq!(
        group
            .client
            .post("http://localhost/v1/commands")
            .json(&invalid)
            .send()
            .await
            .unwrap()
            .status(),
        409
    );
    group.stop().await;
    stop_api.send(()).unwrap();
    api_task.await.unwrap().unwrap();
    let restarted = Running::start(config).await;
    let current = view(&restarted.client).await;
    assert_ne!(current["generation"], before["generation"]);
    assert_eq!(
        restarted
            .client
            .post("http://localhost/v1/commands")
            .json(&invalid)
            .send()
            .await
            .unwrap()
            .status(),
        409
    );
    assert_eq!(
        current["data"]["instances"]["one"]["keysets"]
            .as_array()
            .unwrap()
            .len(),
        4
    );
    restarted.stop().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn aborting_caller_requests_owned_cleanup_before_database_reuse() {
    use monad_common::wallet_lock::{WalletLockMode, WalletLocks};
    let dir = tempfile::tempdir().unwrap();
    let config = config(dir.path(), &["one", "two"]);
    let socket = config
        .management
        .as_ref()
        .unwrap()
        .test_mint_socket
        .clone()
        .unwrap();
    let task = tokio::spawn(monad_test_mint::run(
        config.clone(),
        None,
        std::future::pending(),
    ));
    let client = monad_management::unix_client(socket.clone()).unwrap();
    let live = view(&client).await;
    task.abort();
    assert!(task.await.unwrap_err().is_cancelled());
    let paths: Vec<_> = config
        .test_mints
        .iter()
        .map(|m| std::path::Path::new(&m.db_path))
        .collect();
    // Dropping the caller requests cancellation; its owning supervisor awaits
    // CDK shutdown. Retry lock acquisition to observe that asynchronous boundary.
    let locks = tokio::time::timeout(std::time::Duration::from_secs(10), async {
        loop {
            if let Ok(locks) =
                WalletLocks::acquire(paths.iter().copied(), WalletLockMode::Runtime, "test")
            {
                return locks;
            }
            tokio::time::sleep(std::time::Duration::from_millis(5)).await;
        }
    })
    .await
    .unwrap();
    assert!(!std::path::Path::new(&socket).exists());
    for name in ["one", "two"] {
        let address = live["data"]["instances"][name]["base_url"]
            .as_str()
            .unwrap()
            .strip_prefix("http://")
            .unwrap();
        let _listener = tokio::net::TcpListener::bind(address).await.unwrap();
    }
    drop(locks);
}
