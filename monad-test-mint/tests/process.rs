mod support;
use cdk::nuts::CurrencyUnit;
use serde_json::{json, Value};
use std::{path::Path, process::Stdio};
use support::*;

fn start(path: &Path) -> tokio::process::Child {
    tokio::process::Command::new(env!("CARGO_BIN_EXE_monad-test-mint"))
        .args(["run", "--config"])
        .arg(path)
        .args(["--mint", "demo"])
        .kill_on_drop(true)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .unwrap()
}

#[tokio::test(flavor = "multi_thread")]
async fn process_restart_preserves_keys_fees_and_spent_state() {
    let dir = tempfile::tempdir().unwrap();
    let socket = dir.path().join("mints.sock");
    let config_path = dir.path().join("mint.yaml");
    let mut config = json!({"test_mints":[{
        "name":"demo", "listen":"127.0.0.1:0", "db_path":dir.path().join("mint.db"),
        "units":{"sat":{"input_fee_ppk":400},"msat":{"input_fee_ppk":700}}
    }, {
        "name":"unused", "listen":"127.0.0.1:0", "db_path":dir.path().join("unused.db"),
        "units":{"sat":{"input_fee_ppk":0}}
    }],"management":{"listen":"127.0.0.1:0","test_mint_socket":socket}});
    std::fs::write(&config_path, config.to_string()).unwrap();
    let client = monad_management::unix_client(socket.clone()).unwrap();
    let http = reqwest::Client::new();
    let mut process = start(&config_path);
    let initial = view(&client).await;
    assert_eq!(initial["data"]["instances"].as_object().unwrap().len(), 1);
    assert!(!dir.path().join("unused.db").exists());
    let url = initial["data"]["instances"]["demo"]["base_url"]
        .as_str()
        .unwrap();
    let proofs = mint_proofs(&http, url, CurrencyUnit::Msat, &[1024, 1024]).await;
    let rotated = rotate(
        &client,
        &initial["generation"],
        "rotate",
        "demo",
        "msat",
        900,
    )
    .await;
    swap(&http, url, CurrencyUnit::Msat, vec![proofs[0].clone()], 1).await;
    let before = view(&client).await;
    process.kill().await.unwrap();
    // Only the socket created inside this test's private directory is removed,
    // after the child has exited. The database and its seed are preserved.
    std::fs::remove_file(&socket).unwrap();
    config["test_mints"][0]["units"]["sat"]["input_fee_ppk"] = json!(999);
    config["test_mints"][0]["units"]["msat"]["input_fee_ppk"] = json!(999);
    std::fs::write(&config_path, config.to_string()).unwrap();
    let mut process = start(&config_path);
    let after = view(&client).await;
    assert_ne!(initial["generation"], after["generation"]);
    let index = |view: &Value| -> std::collections::BTreeMap<String, Value> {
        view["data"]["instances"]["demo"]["keysets"]
            .as_array()
            .unwrap()
            .iter()
            .cloned()
            .map(|k| (k["id"].as_str().unwrap().into(), k))
            .collect()
    };
    assert_eq!(index(&before), index(&after));
    let url = after["data"]["instances"]["demo"]["base_url"]
        .as_str()
        .unwrap();
    let state: Value = http
        .post(format!("{url}/v1/checkstate"))
        .json(&json!({"Ys":[proofs[0].y().unwrap().to_hex()]}))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(state["states"][0]["state"], "SPENT");
    let recovered = swap(&http, url, CurrencyUnit::Msat, vec![proofs[1].clone()], 1).await;
    assert!(recovered
        .iter()
        .all(|p| p.keyset_id.to_string() == rotated["active_keyset_id"].as_str().unwrap()));
    process.kill().await.unwrap();
}
