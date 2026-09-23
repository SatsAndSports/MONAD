use crate::{
    management::ClientManagement, sqlite_client_wallet::SqliteClientWallet, wallet::MonadWallet,
};
use monad_management::{Backend, Command};
use serde_json::{json, Value};
use std::{
    collections::BTreeMap,
    sync::Arc,
    time::{Duration, Instant},
};

pub struct ClientBackend {
    controls: BTreeMap<String, Arc<ClientManagement>>,
    wallet: Arc<SqliteClientWallet>,
    inventory: tokio::sync::Mutex<Option<(Instant, Value)>>,
}

impl ClientBackend {
    pub fn new(
        controls: BTreeMap<String, Arc<ClientManagement>>,
        wallet: Arc<SqliteClientWallet>,
    ) -> Self {
        Self {
            controls,
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
                Ok::<_, String>(json!({
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
            "controls": c.controls(), "running": c.is_running(), "hops": c.hops(), "events": c.events.snapshot(),
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
                    if let Some(error) = hop.funding_error {
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
