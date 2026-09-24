#![allow(dead_code)]
use cdk::{
    amount::SplitTarget,
    dhke::construct_proofs,
    nuts::{
        CurrencyUnit, Id, Keys, KeysResponse, KeysetResponse, MintQuoteBolt11Response, MintRequest,
        MintResponse, PreMintSecrets, Proof,
    },
};
use monad_common::config::MonadConfig;
use reqwest::Client;
use serde_json::{json, Value};
use std::{path::Path, time::Duration};

pub fn config(dir: &Path, names: &[&str]) -> MonadConfig {
    serde_json::from_value(json!({
        "test_mints": names.iter().map(|name| json!({
            "name": name, "listen": "127.0.0.1:0", "db_path": dir.join(format!("{name}.db")),
            "units": {"sat":{"input_fee_ppk":400}, "msat":{"input_fee_ppk":700}}
        })).collect::<Vec<_>>(),
        "management": {"listen":"127.0.0.1:0", "test_mint_socket":dir.join("mints.sock")}
    }))
    .unwrap()
}

pub async fn view(client: &Client) -> Value {
    tokio::time::timeout(Duration::from_secs(15), async {
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

pub struct Running {
    pub client: Client,
    stop: tokio::sync::oneshot::Sender<()>,
    task: tokio::task::JoinHandle<anyhow::Result<()>>,
}
impl Running {
    pub async fn start(config: MonadConfig) -> Self {
        let client = monad_management::unix_client(
            config
                .management
                .as_ref()
                .unwrap()
                .test_mint_socket
                .clone()
                .unwrap(),
        )
        .unwrap();
        let (stop, stopped) = tokio::sync::oneshot::channel();
        let task = tokio::spawn(monad_test_mint::run(config, None, async {
            let _ = stopped.await;
        }));
        view(&client).await;
        Self { client, stop, task }
    }
    pub async fn stop(self) {
        self.stop.send(()).unwrap();
        tokio::time::timeout(Duration::from_secs(10), self.task)
            .await
            .unwrap()
            .unwrap()
            .unwrap();
    }
}

pub async fn rotate(
    client: &Client,
    generation: &Value,
    request_id: &str,
    mint: &str,
    unit: &str,
    fee: u64,
) -> Value {
    rotate_at(
        client,
        "http://localhost/v1",
        generation,
        request_id,
        mint,
        unit,
        fee,
    )
    .await
}

pub async fn rotate_at(
    client: &Client,
    base: &str,
    generation: &Value,
    request_id: &str,
    mint: &str,
    unit: &str,
    fee: u64,
) -> Value {
    let command = json!({"generation":generation, "request_id":request_id, "instance":mint,
        "action":"rotate_keyset", "arguments":{"unit":unit,"input_fee_ppk":fee}});
    for _ in 0..2 {
        assert_eq!(
            client
                .post(format!("{base}/commands"))
                .json(&command)
                .send()
                .await
                .unwrap()
                .status(),
            202
        );
    }
    tokio::time::timeout(Duration::from_secs(10), async {
        loop {
            let op: Value = client
                .get(format!("{base}/operations/{request_id}"))
                .send()
                .await
                .unwrap()
                .json()
                .await
                .unwrap();
            if op["state"] == "succeeded" {
                return op["result"].clone();
            }
            assert_ne!(op["state"], "failed", "rotation failed: {op}");
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .unwrap()
}

pub async fn active(client: &Client, url: &str, unit: CurrencyUnit) -> (Id, Keys) {
    let keysets: KeysetResponse = client
        .get(format!("{url}/v1/keysets"))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let id = keysets
        .keysets
        .iter()
        .find(|k| k.active && k.unit == unit)
        .unwrap()
        .id;
    let keys: KeysResponse = client
        .get(format!("{url}/v1/keys/{id}"))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    (id, keys.keysets[0].keys.clone())
}

pub fn premint(id: Id, keys: &Keys, amounts: &[u64]) -> PreMintSecrets {
    PreMintSecrets::random(
        id,
        amounts.iter().sum::<u64>().into(),
        &SplitTarget::Values(amounts.iter().copied().map(Into::into).collect()),
        &(
            0u64,
            keys.iter().map(|(a, _)| a.to_u64()).collect::<Vec<_>>(),
        )
            .into(),
    )
    .unwrap()
}

pub async fn mint_proofs(
    client: &Client,
    url: &str,
    unit: CurrencyUnit,
    amounts: &[u64],
) -> Vec<Proof> {
    let quote: MintQuoteBolt11Response<String> = client
        .post(format!("{url}/v1/mint/quote/bolt11"))
        .json(&json!({"amount":amounts.iter().sum::<u64>(), "unit":unit}))
        .send()
        .await
        .unwrap()
        .error_for_status()
        .unwrap()
        .json()
        .await
        .unwrap();
    tokio::time::timeout(Duration::from_secs(10), async {
        loop {
            let status: Value = client
                .get(format!("{url}/v1/mint/quote/bolt11/{}", quote.quote))
                .send()
                .await
                .unwrap()
                .json()
                .await
                .unwrap();
            if status["state"] == "PAID" {
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .unwrap();
    let (id, keys) = active(client, url, unit).await;
    let secrets = premint(id, &keys, amounts);
    let request = MintRequest {
        quote: quote.quote,
        outputs: secrets.blinded_messages(),
        signature: None,
    };
    let minted: MintResponse = client
        .post(format!("{url}/v1/mint/bolt11"))
        .json(&request)
        .send()
        .await
        .unwrap()
        .error_for_status()
        .unwrap()
        .json()
        .await
        .unwrap();
    construct_proofs(minted.signatures, secrets.rs(), secrets.secrets(), &keys).unwrap()
}

pub async fn swap(
    client: &Client,
    url: &str,
    unit: CurrencyUnit,
    inputs: Vec<Proof>,
    fee: u64,
) -> Vec<Proof> {
    let total = inputs.iter().map(|p| p.amount.to_u64()).sum::<u64>();
    let (id, keys) = active(client, url, unit).await;
    let output = total - fee;
    let denominations = (0..32)
        .filter_map(|i| {
            if output & (1u64 << i) != 0 {
                Some(1u64 << i)
            } else {
                None
            }
        })
        .collect::<Vec<_>>();
    let secrets = premint(id, &keys, &denominations);
    let request = cdk::nuts::SwapRequest::new(inputs, secrets.blinded_messages());
    let response = client
        .post(format!("{url}/v1/swap"))
        .json(&request)
        .send()
        .await
        .unwrap();
    assert!(
        response.status().is_success(),
        "swap rejected with status {}",
        response.status()
    );
    let response: cdk::nuts::SwapResponse = response.json().await.unwrap();
    let proofs =
        construct_proofs(response.signatures, secrets.rs(), secrets.secrets(), &keys).unwrap();
    assert_eq!(
        proofs.iter().map(|p| p.amount.to_u64()).sum::<u64>(),
        output
    );
    proofs
}
