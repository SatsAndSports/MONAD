use crate::{
    loose_proof_wallet::LooseProofSummary,
    management::ClientManagement,
    sqlite_client_wallet::SqliteClientWallet,
    traffic_engine::{TrafficController, TrafficRunParams},
    wallet::{MonadWallet, WalletChannel, WalletChannelState},
};
use monad_management::{Backend, Command};
use serde_json::{json, Value};
use std::{
    collections::BTreeMap,
    sync::Arc,
    time::{Duration, Instant},
};

#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct StartTraffic {
    expected_run_id: u64,
    server_url: String,
    total_rate_bytes_per_second: u64,
    upload_ratio: u8,
    download_ratio: u8,
}
#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct StopTraffic {
    expected_run_id: u64,
}
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
    traffic_controllers: BTreeMap<String, TrafficController>,
    inventory: tokio::sync::Mutex<Option<(Instant, Value)>>,
}

impl ClientBackend {
    pub fn new(
        controls: BTreeMap<String, Arc<ClientManagement>>,
        socks_listens: BTreeMap<String, String>,
        wallet: Arc<SqliteClientWallet>,
        traffic_controllers: BTreeMap<String, TrafficController>,
    ) -> Self {
        Self {
            controls,
            socks_listens,
            wallet,
            traffic_controllers,
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
                let traffic_test = self
                    .traffic_controllers
                    .get(name)
                    .map(|controller| controller.snapshot())
                    .unwrap_or_default();
                (
                    name,
                    json!({
                        "socks_listen": self.socks_listens.get(name),
                        "controls": c.controls(),
                        "runtime": c.runtime_snapshot(),
                        "hops": c.hops(),
                        "events": c.events.snapshot(),
                        "traffic_test": traffic_test,
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
                    // Best-effort prompt stop only: the serve_managed controls
                    // watch stops traffic authoritatively. Commands execute
                    // concurrently, so a parallel start/stop may legitimately
                    // change the run ID before this stop is processed; that
                    // must not fail a disable that already took effect.
                    if let Some(traffic) = self.traffic_controllers.get(&command.instance) {
                        let _ = traffic.stop(traffic.snapshot().run_id).await;
                    }
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
            "start_traffic_test" => {
                let controller = self
                    .traffic_controllers
                    .get(&command.instance)
                    .ok_or("client has no traffic controller")?;
                if !controls.controls().enabled {
                    return Err("client is disabled".into());
                }
                let args: StartTraffic = serde_json::from_value(command.arguments.clone())
                    .map_err(|_| "invalid start traffic arguments")?;
                let params = TrafficRunParams {
                    server_url: args.server_url,
                    total_rate_bytes_per_second: args.total_rate_bytes_per_second,
                    upload_ratio: args.upload_ratio,
                    download_ratio: args.download_ratio,
                };
                controller.start(params, args.expected_run_id).await?;
                return Ok(json!({"traffic_test": controller.snapshot()}));
            }
            "stop_traffic_test" => {
                let controller = self
                    .traffic_controllers
                    .get(&command.instance)
                    .ok_or("client has no traffic controller")?;
                let args: StopTraffic = serde_json::from_value(command.arguments.clone())
                    .map_err(|_| "invalid stop traffic arguments")?;
                controller.stop(args.expected_run_id).await?;
                return Ok(json!({"traffic_test": controller.snapshot()}));
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

    fn test_wallet() -> Arc<SqliteClientWallet> {
        let dir = tempfile::tempdir().unwrap();
        let loose_db = dir.path().join("loose.db");
        let channel_db = dir.path().join("channels.db");
        let loose =
            crate::loose_proof_wallet::LooseProofWallet::open(&loose_db, "test-wallet").unwrap();
        Arc::new(SqliteClientWallet::open(loose, &channel_db, &hex::encode([1u8; 32])).unwrap())
    }

    fn test_backend() -> (ClientBackend, TrafficController) {
        let mut controls = BTreeMap::new();
        controls.insert("test".into(), Arc::new(ClientManagement::default()));
        let mut socks_listens = BTreeMap::new();
        socks_listens.insert("test".into(), "127.0.0.1:0".into());
        let mut traffic_controllers = BTreeMap::new();
        let controller = TrafficController::new("127.0.0.1:1".parse().unwrap());
        traffic_controllers.insert("test".into(), controller.clone());
        (
            ClientBackend::new(controls, socks_listens, test_wallet(), traffic_controllers),
            controller,
        )
    }

    fn command(instance: &str, action: &str, arguments: Value) -> Command {
        Command {
            generation: "test-gen".into(),
            request_id: format!("{}-{}", action, rand::random::<u64>()),
            instance: instance.into(),
            action: action.into(),
            arguments,
        }
    }

    #[tokio::test]
    async fn start_traffic_test_validates_arguments() {
        let (backend, _) = test_backend();
        for mut arguments in [
            json!({"server_url": "https://127.0.0.1:80", "total_rate_bytes_per_second": 1024, "upload_ratio": 1, "download_ratio": 1}),
            json!({"server_url": "http://user@127.0.0.1:80", "total_rate_bytes_per_second": 1024, "upload_ratio": 1, "download_ratio": 1}),
            json!({"server_url": "http://127.0.0.1:80?x=1", "total_rate_bytes_per_second": 1024, "upload_ratio": 1, "download_ratio": 1}),
            json!({"server_url": "http://127.0.0.1:80", "total_rate_bytes_per_second": 512, "upload_ratio": 1, "download_ratio": 1}),
            json!({"server_url": "http://127.0.0.1:80", "total_rate_bytes_per_second": 1024, "upload_ratio": 2, "download_ratio": 3}),
            json!({"server_url": "http://127.0.0.1:80", "total_rate_bytes_per_second": 1024, "upload_ratio": 101, "download_ratio": 1}),
        ] {
            arguments["expected_run_id"] = json!(0);
            let result = backend
                .execute(&command("test", "start_traffic_test", arguments))
                .await;
            assert!(
                result.is_err(),
                "expected validation failure, got {result:?}"
            );
        }
    }

    #[tokio::test]
    async fn snapshot_includes_traffic_test_shape() {
        let (backend, _) = test_backend();
        let snapshot = backend.snapshot().await.unwrap();
        let instance = &snapshot["instances"]["test"];
        assert!(instance["traffic_test"].is_object());
        let traffic = &instance["traffic_test"];
        assert!(traffic["revision"].is_u64());
        assert!(traffic["run_id"].is_u64());
        assert_eq!(traffic["state"], "stopped");
        assert!(traffic["latency"].is_object());
        assert!(traffic["latency"]["samples"].is_u64());
        assert!(traffic["failures"].is_u64());
    }

    #[tokio::test]
    async fn traffic_arguments_reject_unknown_fields_and_wrong_shapes() {
        let (backend, _) = test_backend();
        for arguments in [
            json!(null),
            json!({}),
            json!({"expected_run_id":0,"force":true}),
            json!({"expected_run_id":"0"}),
        ] {
            assert!(backend
                .execute(&command("test", "stop_traffic_test", arguments))
                .await
                .unwrap_err()
                .contains("arguments"));
        }
        let args = json!({"expected_run_id":0,"server_url":"http://localhost","total_rate_bytes_per_second":1024,"upload_ratio":1,"download_ratio":1,"typo":true});
        assert!(backend
            .execute(&command("test", "start_traffic_test", args))
            .await
            .unwrap_err()
            .contains("arguments"));
    }

    #[tokio::test]
    async fn traffic_commands_serialize_concurrent_starts_and_stops() {
        let (backend, controller) = test_backend();
        let (stop, stopped) = tokio::sync::oneshot::channel::<()>();
        let owner = controller.clone();
        let owner = tokio::spawn(async move {
            owner
                .serve(async {
                    let _ = stopped.await;
                })
                .await
        });
        let backend = Arc::new(backend);
        let mut tasks: tokio::task::JoinSet<Result<Value, String>> = tokio::task::JoinSet::new();
        for i in 0u64..8 {
            let backend = backend.clone();
            let is_start = i % 2 == 0;
            tasks.spawn(async move {
                if is_start {
                    let args = json!({
                        "server_url": "http://127.0.0.1:8080",
                        "total_rate_bytes_per_second": 1024,
                        "upload_ratio": 1,
                        "download_ratio": 1,
                        "expected_run_id": 0,
                    });
                    backend
                        .execute(&command("test", "start_traffic_test", args))
                        .await
                } else {
                    backend
                        .execute(&command(
                            "test",
                            "stop_traffic_test",
                            json!({"expected_run_id":0}),
                        ))
                        .await
                }
            });
        }
        while let Some(result) = tasks.join_next().await {
            let _ = result.unwrap();
        }
        // Final controller state must be coherent: stopped or a valid run id.
        let snap = controller.snapshot();
        assert_eq!(
            snap.run_id, 1,
            "only one start with expected run 0 may succeed"
        );
        // Stop once more to leave a deterministic stopped state.
        backend
            .execute(&command(
                "test",
                "stop_traffic_test",
                json!({"expected_run_id":snap.run_id}),
            ))
            .await
            .unwrap();
        assert_eq!(controller.snapshot().state, "stopped");
        stop.send(()).unwrap();
        owner.await.unwrap();
    }

    #[tokio::test]
    async fn disable_succeeds_when_best_effort_traffic_stop_cannot_be_delivered() {
        let (backend, controller) = test_backend();
        // Fill the controller command channel with requests whose waiters are
        // then dropped, with no owner running. The best-effort stop inside
        // disable cannot even be queued; disable must still succeed because
        // the serve_managed controls watch is the authoritative traffic stop.
        for i in 0..16u64 {
            let mut start = Box::pin(controller.start(
                TrafficRunParams {
                    server_url: "http://127.0.0.1:8080".into(),
                    total_rate_bytes_per_second: 1024,
                    upload_ratio: 1,
                    download_ratio: 1,
                },
                i,
            ));
            assert!(futures_util::FutureExt::now_or_never(&mut start).is_none());
        }
        let value = backend
            .execute(&command("test", "set_enabled", json!({"enabled": false})))
            .await
            .unwrap();
        assert_eq!(value["controls"]["enabled"], json!(false));
    }
}
