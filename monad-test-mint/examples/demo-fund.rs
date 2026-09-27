//! Disposable local demo funding only. Reuses the real CDK test-mint issuance
//! helper rather than fabricating balances or proof signatures.
#[path = "../dev-support/issuance.rs"]
mod issuance;

use monad_client::loose_proof_wallet::{LooseProofWallet, NewLooseProof};
use monad_client::wallet_lock::ClientWalletLocks;
use monad_common::wallet_lock::WalletLockMode;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let args: Vec<_> = std::env::args().collect();
    anyhow::ensure!(
        args.len() == 5,
        "usage: demo-fund MINT_URL LOOSE_DB CHANNEL_DB SATS"
    );
    let url = reqwest::Url::parse(&args[1])?;
    anyhow::ensure!(
        url.scheme() == "http"
            && url
                .host_str()
                .and_then(|s| s.parse::<std::net::IpAddr>().ok())
                .is_some_and(|ip| ip.is_loopback()),
        "demo mint must be HTTP loopback"
    );
    let amount: u64 = args[4].parse()?;
    anyhow::ensure!(
        amount <= 100_000_000,
        "demo funding limit is 100 million test sats"
    );
    let _authority = ClientWalletLocks::acquire(&args[2], &args[3], WalletLockMode::Maintenance)?;
    let wallet = LooseProofWallet::open(&args[2], "default")?;
    if amount == 0 {
        return Ok(());
    }
    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(15))
        .build()?;
    // Split the requested sat-equivalent purse between the two units.
    for (unit, raw) in [
        (cdk::nuts::CurrencyUnit::Sat, amount / 2),
        (cdk::nuts::CurrencyUnit::Msat, (amount - amount / 2) * 1000),
    ] {
        if raw == 0 {
            continue;
        }
        let amounts = (0..63)
            .filter_map(|bit| {
                let value = 1u64 << bit;
                (raw & value != 0).then_some(value)
            })
            .collect::<Vec<_>>();
        let proofs = issuance::mint_proofs(
            &client,
            args[1].trim_end_matches('/'),
            unit.clone(),
            &amounts,
        )
        .await;
        let records = proofs
            .into_iter()
            .map(|proof| {
                Ok(NewLooseProof {
                    proof_id: proof.y()?.to_hex(),
                    mint_url: args[1].trim_end_matches('/').into(),
                    unit: unit.to_string(),
                    keyset_id: proof.keyset_id.to_string(),
                    amount_raw: proof.amount.to_u64(),
                    proof_json: serde_json::to_string(&proof)?,
                    source_quote_id: None,
                    source_batch_id: None,
                })
            })
            .collect::<anyhow::Result<Vec<_>>>()?;
        wallet.import_proofs(&records)?;
    }
    println!("Imported {amount} local test sats equivalent, split across SAT/MSAT");
    Ok(())
}
