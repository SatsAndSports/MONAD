use crate::{
    payments::CloseOutcome,
    session_registry::{RelayControls, SessionRegistry},
    wallet_manager::RelayWalletManager,
};
use monad_management::{Backend, Command};
use serde_json::{json, Value};
use std::{
    collections::BTreeMap,
    sync::Arc,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

pub struct RelayBackend {
    pub registries: BTreeMap<String, Arc<SessionRegistry>>,
    wallet: Arc<RelayWalletManager>,
    inventory: tokio::sync::Mutex<Option<(Instant, Value)>>,
}

impl RelayBackend {
    pub fn new(
        registries: BTreeMap<String, Arc<SessionRegistry>>,
        wallet: Arc<RelayWalletManager>,
    ) -> Self {
        Self {
            registries,
            wallet,
            inventory: Default::default(),
        }
    }
}

#[async_trait::async_trait]
impl Backend for RelayBackend {
    async fn snapshot(&self) -> Result<Value, String> {
        let mut cache = self.inventory.lock().await;
        if cache
            .as_ref()
            .is_none_or(|(at, _)| at.elapsed() >= Duration::from_secs(1))
        {
            let wallet = self.wallet.clone();
            let names: Vec<_> = self.registries.keys().cloned().collect();
            let inventory = tokio::task::spawn_blocking(move || {
                let now = SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .map_err(|_| "clock unavailable")?
                    .as_secs();
                let mut channels = Vec::new();
                let mut expiring = Vec::new();
                for name in &names {
                    channels.extend(
                        wallet
                            .list_channels(Some(name))
                            .map_err(|_| "channel inventory unavailable")?,
                    );
                    expiring.extend(
                        wallet
                            .find_expiring_channels(Some(name), now, u64::MAX)
                            .map_err(|_| "expiry inventory unavailable")?,
                    );
                }
                let drains = wallet
                    .list_drains()
                    .map_err(|_| "drain inventory unavailable")?
                    .into_iter()
                    .filter(|d| names.contains(&d.relay_name))
                    .collect::<Vec<_>>();
                Ok::<_, String>(
                    json!({"channels": channels, "expiring_channels": expiring, "drains": drains}),
                )
            })
            .await
            .map_err(|_| "inventory task failed")??;
            *cache = Some((Instant::now(), inventory));
        }
        let mut instances = BTreeMap::new();
        for (name, registry) in &self.registries {
            instances.insert(
                name,
                json!({"controls": registry.controls(), "disabling": registry.is_disabling(),
                "sessions": registry.snapshots().await, "events": registry.events.snapshot()}),
            );
        }
        let mut wallet = cache.as_ref().unwrap().1.clone();
        if let Some(channels) = wallet["channels"].as_array_mut() {
            for channel in channels {
                let registry = channel["relay_name"]
                    .as_str()
                    .and_then(|name| self.registries.get(name));
                let linked_at = registry.and_then(|registry| {
                    channel["channel_id"]
                        .as_str()
                        .and_then(|id| registry.last_linked_at(id))
                });
                channel["last_linked_at_unix_ms"] = json!(linked_at);
                let retired = channel["channel_id"]
                    .as_str()
                    .map(|id| self.wallet.channel_is_retired(id))
                    .unwrap_or(false);
                channel["retired"] = json!(retired);
            }
        }
        Ok(json!({"kind": "relays", "instances": instances, "wallet": wallet}))
    }

    async fn execute(&self, command: &Command) -> Result<Value, String> {
        let registry = self
            .registries
            .get(&command.instance)
            .ok_or("unknown relay")?;
        match command.action.as_str() {
            "set_controls" => {
                let controls: RelayControls = serde_json::from_value(command.arguments.clone())
                    .map_err(|_| "all four relay control booleans are required")?;
                registry.set_controls(controls)?;
                if !controls.enabled {
                    registry.wait_disabled().await?;
                }
                Ok(json!({"controls": registry.controls()}))
            }
            "request_channel_unlink" => {
                let channel = command
                    .arguments
                    .get("channel_id")
                    .and_then(Value::as_str)
                    .ok_or("channel_id required")?;
                let owner = self
                    .wallet
                    .relay_name_for_channel(channel)
                    .map_err(|_| "channel lookup failed")?;
                if owner.as_deref() != Some(&command.instance) {
                    return Err("channel is not owned by this relay".into());
                }
                let payments = self
                    .wallet
                    .payments_for(&command.instance)
                    .map_err(|_| "relay payments unavailable")?;
                // Persist retirement first so the channel cannot be relinked by
                // another session, then politely ask the owning session to
                // release it. The channel stays Open until closed separately.
                let linked_session = payments.retire_channel(channel, false).map_err(|error| {
                    if error == "unknown channel" {
                        "unknown channel".to_string()
                    } else {
                        "channel retirement failed".to_string()
                    }
                })?;
                let Some(session_id) = linked_session else {
                    return Ok(json!({"channel_id": channel, "unlinked": true, "retired": true}));
                };
                *self.inventory.lock().await = None;
                registry.events.record(
                    "channel_release_requested",
                    json!({"channel_id": channel, "session_id": hex::encode(session_id)}),
                );
                let released = registry.notify(
                    &session_id,
                    monad_common::protocol::ServerMessage::ChannelReleaseRequested {
                        channel_id: channel.to_string(),
                    },
                );
                Ok(json!({
                    "channel_id": channel,
                    "session_id": hex::encode(session_id),
                    "retired": true,
                    "release_requested": released,
                }))
            }
            "close_channel" => {
                let channel = command
                    .arguments
                    .get("channel_id")
                    .and_then(Value::as_str)
                    .ok_or("channel_id required")?;
                let owner = self
                    .wallet
                    .relay_name_for_channel(channel)
                    .map_err(|_| "channel lookup failed")?;
                if owner.as_deref() != Some(&command.instance) {
                    return Err("channel is not owned by this relay".into());
                }
                let payments = self
                    .wallet
                    .payments_for(&command.instance)
                    .map_err(|_| "relay payments unavailable")?;
                // Atomically retire and require that no session still owns the
                // channel. Linked channels must go through request_channel_unlink
                // first; this also reserves the channel against concurrent relink.
                payments.retire_channel(channel, true).map_err(|error| {
                    if error == "channel is linked; request unlink first" {
                        "channel is linked; request unlink first".to_string()
                    } else if error == "unknown channel" {
                        "unknown channel".to_string()
                    } else {
                        "channel retirement failed".to_string()
                    }
                })?;
                let net = self
                    .wallet
                    .mint_client_for_channel(channel)
                    .map_err(|_| "channel mint unavailable")?;
                let outcome = self
                    .wallet
                    .close_channel(channel, &net)
                    .await
                    .map_err(|_| "channel closure failed; inspect channel recovery state")?;
                let outcome = match outcome {
                    CloseOutcome::Closed(_) => "closed",
                    CloseOutcome::SenderRefundedAfterExpiry { .. } => "sender_refunded",
                    CloseOutcome::UnknownSpent { .. } => "unresolved_spent",
                };
                *self.inventory.lock().await = None;
                registry.events.record(
                    "channel_close",
                    json!({"channel_id": channel, "outcome": outcome}),
                );
                Ok(json!({"channel_id": channel, "outcome": outcome}))
            }
            _ => Err("unknown relay action".into()),
        }
    }
}
