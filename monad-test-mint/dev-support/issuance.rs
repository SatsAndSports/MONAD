//! Fake-Lightning mint issuance shared by local demos and integration tests.
//! Callers supply an HTTP client with bounded request timeouts.
use cdk::{
    amount::SplitTarget,
    dhke::construct_proofs,
    nuts::{
        CurrencyUnit, Id, Keys, KeysResponse, KeysetResponse, MintQuoteBolt11Response, MintRequest,
        MintResponse, PreMintSecrets, Proof,
    },
};
use reqwest::Client;
use serde_json::{json, Value};
use std::time::Duration;

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
