use crate::{
    loose_proof_wallet::LooseProofSummary,
    management::ClientManagement,
    sqlite_client_wallet::SqliteClientWallet,
    wallet::{MonadWallet, WalletChannel, WalletChannelState},
};
use monad_management::{Backend, Command};
use serde_json::{json, Value};
use std::{
    collections::BTreeMap,
    sync::Arc,
    time::{Duration, Instant},
};

fn wallet_summary(
    proofs: &[LooseProofSummary],
    channels: &[WalletChannel],
) -> Result<Value, String> {
    let mut proof_totals = BTreeMap::from([
        ("sat".to_string(), (0_u64, 0_u64)),
        ("msat".to_string(), (0_u64, 0_u64)),
    ]);
    for proof in proofs {
        let total = proof_totals.entry(proof.unit.clone()).or_default();
        total.0 = total
            .0
            .checked_add(proof.amount_raw)
            .ok_or("available proof amount overflow")?;
        total.1 = total
            .1
            .checked_add(proof.proof_count)
            .ok_or("available proof count overflow")?;
    }
    let available_loose_proofs = proof_totals
        .into_iter()
        .map(|(unit, (amount, count))| {
            (
                unit,
                json!({"amount_raw": amount.to_string(), "proof_count": count}),
            )
        })
        .collect::<BTreeMap<_, _>>();
    let mut open = 0_u64;
    let mut closing = 0_u64;
    let mut closed = 0_u64;
    for channel in channels {
        let count = match channel.state {
            WalletChannelState::Open => &mut open,
            WalletChannelState::Closing => &mut closing,
            WalletChannelState::Closed => &mut closed,
        };
        *count = count.checked_add(1).ok_or("channel count overflow")?;
    }
    Ok(json!({
        "available_loose_proofs": available_loose_proofs,
        "channel_state_counts": {"open": open, "closing": closing, "closed": closed},
    }))
}

pub struct ClientBackend {
    controls: BTreeMap<String, Arc<ClientManagement>>,
    socks_listens: BTreeMap<String, String>,
    wallet: Arc<SqliteClientWallet>,
    inventory: tokio::sync::Mutex<Option<(Instant, Value)>>,
}

impl ClientBackend {
    pub fn new(
        controls: BTreeMap<String, Arc<ClientManagement>>,
        socks_listens: BTreeMap<String, String>,
        wallet: Arc<SqliteClientWallet>,
    ) -> Self {
        Self {
            controls,
            socks_listens,
            wallet,
            inventory: Default::default(),
        }
    }
}

#[async_trait::async_trait]
impl Backend for ClientBackend {
    async fn snapshot(&self) -> Result<Value, String> {
        let mut cache = self.inventory.lock().await;
        if cache
            .as_ref()
            .is_none_or(|(at, _)| at.elapsed() >= Duration::from_secs(1))
        {
            let wallet = self.wallet.clone();
            let inventory = tokio::task::spawn_blocking(move || {
                let channels = wallet.list_channels().map_err(|_| "channel inventory unavailable")?;
                let proofs = wallet.loose_wallet().list_available_proof_summaries().map_err(|_| "proof inventory unavailable")?;
                let custody = wallet.loose_wallet().list_custody_summaries().map_err(|_| "custody inventory unavailable")?;
                let summary = wallet_summary(&proofs, &channels)?;
                Ok::<_, String>(json!({
                    "summary": summary,
                    "proof_custody": custody,
                    "channels": channels.into_iter().map(|c| json!({
                        "channel_id": c.channel_id, "state": format!("{:?}", c.state),
                        "receiver_pubkey": c.receiver_pubkey, "mint_url": c.mint_url, "unit": c.unit,
                        "capacity_msats": c.capacity_msats, "signed_balance_msats": c.current_signed_balance_msats,
                        "expiry_timestamp": c.expiry_timestamp, "session_id": c.attached_session_id.map(hex::encode),
                    })).collect::<Vec<_>>(),
                    "available_proofs": proofs.into_iter().map(|p| json!({
                        "mint_url": p.mint_url, "unit": p.unit, "amount_raw": p.amount_raw, "proof_count": p.proof_count,
                    })).collect::<Vec<_>>()
                }))
            }).await.map_err(|_| "inventory task failed")??;
            *cache = Some((Instant::now(), inventory));
        }
        let clients: BTreeMap<_, _> = self
            .controls
            .iter()
            .map(|(name, c)| {
                (
                    name,
                    json!({
            "socks_listen": self.socks_listens.get(name),
            "controls": c.controls(), "runtime": c.runtime_snapshot(), "hops": c.hops(), "events": c.events.snapshot(),
                    }),
                )
            })
            .collect();
        Ok(json!({"kind": "clients", "instances": clients, "wallet": cache.as_ref().unwrap().1}))
    }

    async fn execute(&self, command: &Command) -> Result<Value, String> {
        let controls = self
            .controls
            .get(&command.instance)
            .ok_or("unknown client")?;
        match command.action.as_str() {
            "set_enabled" => {
                let enabled = command
                    .arguments
                    .get("enabled")
                    .and_then(Value::as_bool)
                    .ok_or("enabled boolean required")?;
                controls.set_enabled(enabled)?;
                if !enabled {
                    let mut changes = controls.changes();
                    loop {
                        changes.borrow_and_update();
                        if !controls.is_running() {
                            break;
                        }
                        if controls.controls().enabled {
                            return Err("disable completed and was superseded by re-enable".into());
                        }
                        changes.changed().await.map_err(|_| "client stopped")?;
                    }
                }
            }
            "set_automatic_provisioning" => {
                let enabled = command
                    .arguments
                    .get("enabled")
                    .and_then(Value::as_bool)
                    .ok_or("enabled boolean required")?;
                controls.set_automatic_provisioning(enabled);
            }
            "provision_channel" => {
                let session = command
                    .arguments
                    .get("session_id")
                    .and_then(Value::as_str)
                    .ok_or("session_id required")?;
                let previous = controls
                    .hops()
                    .into_iter()
                    .find(|h| h.session_id == session)
                    .ok_or("session is no longer active")?
                    .linked_channel
                    .map(|c| c.channel_id);
                let mut changes = controls.changes();
                controls.provision_once(session)?;
                loop {
                    changes.borrow_and_update();
                    let hop = controls
                        .hops()
                        .into_iter()
                        .find(|h| h.session_id == session)
                        .ok_or("session ended before funding completed")?;
                    let funding_error = match hop.funding {
                        crate::management::HopFundingState::WaitingForManualFunding { error } => {
                            error
                        }
                        crate::management::HopFundingState::Blocked { message } => Some(message),
                        _ => None,
                    };
                    if let Some(error) = funding_error {
                        return Err(error);
                    }
                    if let Some(channel) = hop.linked_channel {
                        if Some(&channel.channel_id) != previous.as_ref() {
                            return Ok(json!({"linked_channel_id": channel.channel_id}));
                        }
                    }
                    changes.changed().await.map_err(|_| "client stopped")?;
                }
            }
            _ => return Err("unknown client action".into()),
        }
        Ok(json!({"controls": controls.controls()}))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wallet_summary_groups_available_proofs_and_channel_states() {
        let proofs = [
            LooseProofSummary {
                mint_url: "mint-a".into(),
                unit: "sat".into(),
                keyset_id: "a".into(),
                proof_count: 2,
                amount_raw: 30,
            },
            LooseProofSummary {
                mint_url: "mint-b".into(),
                unit: "sat".into(),
                keyset_id: "b".into(),
                proof_count: 3,
                amount_raw: 40,
            },
            LooseProofSummary {
                mint_url: "mint-a".into(),
                unit: "msat".into(),
                keyset_id: "c".into(),
                proof_count: 1,
                amount_raw: 500,
            },
        ];
        let channel = |state| WalletChannel {
            channel_id: String::new(),
            state,
            receiver_pubkey: String::new(),
            mint_url: String::new(),
            unit: String::new(),
            capacity_msats: 0,
            current_signed_balance_msats: 0,
            expiry_timestamp: 0,
            attached_session_id: None,
            keyset_id: String::new(),
        };
        let channels = [
            channel(WalletChannelState::Open),
            channel(WalletChannelState::Open),
            channel(WalletChannelState::Closed),
        ];
        assert_eq!(
            wallet_summary(&proofs, &channels).unwrap(),
            json!({
                "available_loose_proofs": {
                    "msat": {"amount_raw": "500", "proof_count": 1},
                    "sat": {"amount_raw": "70", "proof_count": 5},
                },
                "channel_state_counts": {"open": 2, "closing": 0, "closed": 1},
            })
        );
    }

    #[test]
    fn wallet_summary_rejects_amount_overflow() {
        let proof = |amount_raw| LooseProofSummary {
            mint_url: String::new(),
            unit: "sat".into(),
            keyset_id: String::new(),
            proof_count: 1,
            amount_raw,
        };
        assert_eq!(
            wallet_summary(&[proof(u64::MAX), proof(1)], &[]).unwrap_err(),
            "available proof amount overflow"
        );
    }
}
