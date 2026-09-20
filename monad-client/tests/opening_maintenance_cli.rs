use monad_client::wallet_lock::{ClientWalletLocks, WalletLockMode};
use std::path::Path;
use std::process::{Command, Output};
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use axum::{extract::Request, middleware::Next};
use cdk_spilman::{ConfigurableClientHost, ReqwestClientNetworking, SpilmanClientBridge};
use cdk_spilman_test_mint::{build_router, TestMintHelper};
use monad_client::loose_proof_wallet::{
    LooseProofState, LooseProofWallet, NewLooseProof, NewOpeningAttempt, OpeningAttemptState,
    OpeningSubmissionClaim,
};
use monad_client::runtime::{
    run_configured_client_until_shutdown_with_options, ConfiguredClientRuntimeOptions,
    SharedRouteRuntimeStats, CONFIGURED_CLIENT_WALLET_NAME,
};
use monad_common::config::{ClientConfig, ClientRouteHopConfig, ClientWalletConfig, MonadConfig};
use rusqlite::{types::Value, Connection, OpenFlags};
use tokio::sync::{oneshot, Notify, Semaphore};

// Read through SQLite so committed WAL contents, not just main-file bytes, are compared.
fn logical_snapshot(path: &Path) -> Vec<(String, Vec<Vec<Value>>)> {
    let mut conn = Connection::open_with_flags(path, OpenFlags::SQLITE_OPEN_READ_ONLY).unwrap();
    let tx = conn.transaction().unwrap();
    let schema = tx
        .prepare("SELECT name, sql FROM sqlite_schema ORDER BY name")
        .unwrap()
        .query_map([], |row| Ok(vec![row.get(0)?, row.get(1)?]))
        .unwrap()
        .collect::<Result<Vec<Vec<Value>>, _>>()
        .unwrap();
    let tables = tx
        .prepare("SELECT name FROM sqlite_schema WHERE type = 'table' ORDER BY name")
        .unwrap()
        .query_map([], |row| row.get::<_, String>(0))
        .unwrap()
        .collect::<Result<Vec<_>, _>>()
        .unwrap();
    let mut snapshot = vec![("schema".to_string(), schema)];
    for table in tables {
        let mut stmt = tx
            .prepare(&format!("SELECT * FROM \"{}\"", table.replace('"', "\"\"")))
            .unwrap();
        let columns = stmt.column_count();
        let mut rows = stmt
            .query_map([], |row| (0..columns).map(|i| row.get(i)).collect())
            .unwrap()
            .collect::<Result<Vec<Vec<Value>>, _>>()
            .unwrap();
        rows.sort_by_cached_key(|row| format!("{row:?}"));
        snapshot.push((table, rows));
    }
    snapshot
}

async fn bounded_maintenance(loose: &Path, channel: &Path, command: &str) -> Output {
    tokio::time::timeout(
        Duration::from_secs(10),
        tokio::process::Command::new(env!("CARGO_BIN_EXE_monad-client"))
            .arg("wallet")
            .arg("--loose-db")
            .arg(loose)
            .arg("--channel-db")
            .arg(channel)
            .args(["--sender-secret-hex", &"01".repeat(32), "--json", command])
            .env("RUST_LOG", "off")
            .kill_on_drop(true)
            .output(),
    )
    .await
    .expect("maintenance CLI timed out")
    .unwrap()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn configured_runtime_excludes_opening_maintenance_during_startup_and_steady_state() {
    let dir = tempfile::tempdir().unwrap();
    let loose_path = dir.path().join("loose.db");
    let channel_path = dir.path().join("channel.db");
    let mint = TestMintHelper::new().await.unwrap();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let mint_url = format!("http://{}", listener.local_addr().unwrap());
    let requests = Arc::new(Mutex::new(Vec::<String>::new()));
    let restore_entered = Arc::new(Notify::new());
    let restore_gate = Arc::new(Semaphore::new(0));
    let router = build_router(mint.mint())
        .await
        .unwrap()
        .layer(axum::middleware::from_fn({
            let requests = requests.clone();
            let restore_entered = restore_entered.clone();
            let restore_gate = restore_gate.clone();
            move |request: Request, next: Next| {
                let requests = requests.clone();
                let restore_entered = restore_entered.clone();
                let restore_gate = restore_gate.clone();
                async move {
                    let path = request.uri().path().to_string();
                    let first_restore = {
                        let mut calls = requests.lock().unwrap();
                        let first = path == "/v1/restore" && !calls.contains(&path);
                        calls.push(path);
                        first
                    };
                    if first_restore {
                        restore_entered.notify_one();
                        restore_gate.acquire().await.unwrap().forget();
                    }
                    next.run(request).await
                }
            }
        }));
    let (mint_shutdown_tx, mint_shutdown_rx) = oneshot::channel();
    let mint_task = tokio::spawn(async move {
        axum::serve(listener, router)
            .with_graceful_shutdown(async {
                let _ = mint_shutdown_rx.await;
            })
            .await
            .unwrap();
    });

    let proofs = mint.mint_proofs(128).await.unwrap();
    let proofs_json = serde_json::to_string(&proofs).unwrap();
    let keyset_id = mint.keyset_id().to_string();
    let mut host = ConfigurableClientHost::new_in_memory();
    let sender = host.add_key_from_hex(&"01".repeat(32)).unwrap();
    let receiver = "02a9acc1e48c25eeeb9289b5031cc57da9fe72f3fe2861d264bdc074209b107ba2";
    let bridge = SpilmanClientBridge::new(
        host,
        ReqwestClientNetworking::new(Duration::from_secs(10)).unwrap(),
    );
    let expiry = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs()
        + 86400;
    let prepared = bridge
        .prepare_open_channel_from_proofs_with_input_keysets(
            &mint_url,
            "sat",
            &proofs_json,
            &serde_json::json!([{
                "id": keyset_id, "unit": "sat", "active": true,
                "input_fee_ppk": mint.input_fee_ppk(),
            }])
            .to_string(),
            receiver,
            &sender,
            expiry,
            &mint.keyset_info_json().unwrap(),
            0,
            None,
            Some(32),
        )
        .unwrap();
    let attempt_id = prepared.channel_id.clone();
    let loose = LooseProofWallet::open(&loose_path, CONFIGURED_CLIENT_WALLET_NAME).unwrap();
    let imported = serde_json::from_str::<Vec<serde_json::Value>>(&proofs_json)
        .unwrap()
        .into_iter()
        .map(|proof| NewLooseProof {
            proof_id: format!("{}:{}", keyset_id, proof["secret"].as_str().unwrap()),
            mint_url: mint_url.clone(),
            unit: "sat".into(),
            keyset_id: keyset_id.clone(),
            amount_raw: proof["amount"].as_u64().unwrap(),
            proof_json: proof.to_string(),
            source_quote_id: None,
            source_batch_id: None,
        })
        .collect::<Vec<_>>();
    loose.import_proofs(&imported).unwrap();
    let proof_ids = imported
        .iter()
        .map(|proof| proof.proof_id.clone())
        .collect::<Vec<_>>();
    loose
        .reserve_selected_proofs_with_opening_attempt(
            &mint_url,
            "sat",
            &proof_ids,
            &NewOpeningAttempt {
                attempt_id: attempt_id.clone(),
                opening_id: attempt_id.clone(),
                predecessor_attempt_id: None,
                reservation_id: attempt_id.clone(),
                receiver_pubkey: receiver.into(),
                mint_url: mint_url.clone(),
                unit: "sat".into(),
                funding_token_target_msats: 32_000,
                expiry_timestamp: expiry,
                prepared_open_json: serde_json::to_string(&prepared).unwrap(),
                selected_proof_ids: proof_ids.clone(),
            },
        )
        .unwrap();
    let OpeningSubmissionClaim::Acquired(permit) =
        loose.claim_opening_attempt_submission(&attempt_id).unwrap()
    else {
        panic!("submission claim not acquired");
    };
    // Persist authorization without sending the swap: restore is genuinely empty,
    // and the real mint still knows all inputs as unspent.
    loose.authorize_opening_submission(permit).unwrap();
    assert_eq!(
        loose.opening_attempt(&attempt_id).unwrap().unwrap().state,
        OpeningAttemptState::Submitted
    );
    drop(loose);

    // Retain the UDP socket so QUIC cannot complete or fail via an unused-port ICMP reply.
    let blackhole = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let config = MonadConfig {
        relay_wallet: None,
        management: None,
        relays: vec![],
        client_wallet: Some(ClientWalletConfig {
            loose_db_path: loose_path.display().to_string(),
            channel_db_path: channel_path.display().to_string(),
            sender_secret_hex: "01".repeat(32),
            channel_funding_token_target_msats: 32_000,
            target_topup_buffer_msats: 1_000,
            minimum_topup_msats: 1,
        }),
        clients: vec![ClientConfig {
            name: "locking-test".into(),
            socks: "127.0.0.1:0".into(),
            route: vec![ClientRouteHopConfig {
                addr: blackhole.local_addr().unwrap().to_string(),
                pubkey: monad_common::secp_identity::SecpTransportKeypair::from_secret_bytes(
                    &[7; 32],
                )
                .unwrap()
                .pubkey()
                .to_hex(),
            }],
        }],
    };
    let stats = SharedRouteRuntimeStats::default();
    let (shutdown_tx, shutdown_rx) = oneshot::channel();
    let runtime = tokio::spawn(run_configured_client_until_shutdown_with_options(
        config,
        None,
        stats.clone(),
        ConfiguredClientRuntimeOptions {
            route_setup_timeout: Duration::from_secs(15),
        },
        async {
            let _ = shutdown_rx.await;
        },
    ));
    tokio::time::timeout(Duration::from_secs(10), restore_entered.notified())
        .await
        .expect("startup restore not reached");
    assert_eq!(stats.snapshot().route_connect_attempts_total, 0);
    let startup_deadline = tokio::time::Instant::now() + Duration::from_secs(8);

    for steady_state in [false, true] {
        if steady_state {
            assert!(tokio::time::Instant::now() < startup_deadline);
            assert_eq!(stats.snapshot().route_connect_attempts_total, 0);
            // Release startup before ever requesting shutdown; manager startup is synchronous.
            restore_gate.add_permits(1);
            tokio::time::timeout(Duration::from_secs(10), async {
                let mut poll = tokio::time::interval(Duration::from_millis(10));
                while stats.snapshot().route_connect_attempts_total == 0 {
                    assert!(!runtime.is_finished(), "runtime exited before steady state");
                    poll.tick().await;
                }
            })
            .await
            .expect("runtime did not enter steady state");
        }
        let checks = async {
            let before = (
                logical_snapshot(&loose_path),
                logical_snapshot(&channel_path),
            );
            let calls = requests.lock().unwrap().clone();
            // Funding and change outputs are restored separately once the gate opens.
            assert_eq!(calls, vec!["/v1/restore"; if steady_state { 2 } else { 1 }]);
            for command in ["recover-openings", "export-stale-opening-inputs"] {
                let output = bounded_maintenance(&loose_path, &channel_path, command).await;
                assert!(
                    !output.status.success(),
                    "steady={steady_state}, {command}: {output:?}"
                );
                assert!(output.stdout.is_empty(), "{command}: {output:?}");
                assert!(
                    String::from_utf8_lossy(&output.stderr)
                        .contains("client wallet Maintenance lock unavailable"),
                    "{command}: {output:?}"
                );
                assert_eq!(*requests.lock().unwrap(), calls);
                assert_eq!(
                    (
                        logical_snapshot(&loose_path),
                        logical_snapshot(&channel_path)
                    ),
                    before
                );
                assert!(!runtime.is_finished());
                if !steady_state {
                    assert_eq!(stats.snapshot().route_connect_attempts_total, 0);
                }
            }
        };
        if steady_state {
            checks.await;
        } else if tokio::time::timeout_at(startup_deadline, checks)
            .await
            .is_err()
        {
            // Do not leave synchronous startup recovery gated on a deadline failure.
            restore_gate.add_permits(1);
            shutdown_tx.send(()).unwrap();
            tokio::time::timeout(Duration::from_secs(30), runtime)
                .await
                .expect("runtime shutdown timed out")
                .unwrap()
                .unwrap();
            panic!("startup maintenance checks exceeded the shared 8-second deadline");
        }
    }
    shutdown_tx.send(()).unwrap();
    // The runtime awaits an in-flight setup attempt before observing shutdown.
    tokio::time::timeout(Duration::from_secs(30), runtime)
        .await
        .expect("runtime shutdown timed out")
        .unwrap()
        .unwrap();

    let output = bounded_maintenance(&loose_path, &channel_path, "recover-openings").await;
    assert!(output.status.success(), "{output:?}");
    let report: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(report["recovered_channel_ids"], serde_json::json!([]));
    assert_eq!(report["cancelled_attempt_ids"], serde_json::json!([]));
    assert_eq!(
        report["externally_spent_attempt_ids"],
        serde_json::json!([])
    );
    assert_eq!(report["unresolved"].as_array().unwrap().len(), 1);
    assert_eq!(report["unresolved"][0]["attempt_id"], attempt_id);
    assert_eq!(
        report["unresolved"][0]["reason"],
        "funding restore empty; opening attempt remains reserved"
    );
    assert_eq!(*requests.lock().unwrap(), vec!["/v1/restore"; 4]);

    // Age only the fixture, without exposing a production timestamp override.
    assert_eq!(Connection::open(&loose_path).unwrap().execute(
        "UPDATE monad_client_opening_attempts SET latest_submitted_at = 1 WHERE attempt_id = ?1",
        [&attempt_id],
    ).unwrap(), 1);
    let output =
        bounded_maintenance(&loose_path, &channel_path, "export-stale-opening-inputs").await;
    assert!(output.status.success(), "{output:?}");
    let report: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(report["unresolved"], serde_json::json!([]));
    assert_eq!(report["exports"].as_array().unwrap().len(), 1);
    assert_eq!(
        report["exports"][0]["attempt_ids"],
        serde_json::json!([attempt_id])
    );
    assert_eq!(report["exports"][0]["mint_url"], mint_url);
    assert_eq!(report["exports"][0]["unit"], "sat");
    assert_eq!(report["exports"][0]["amount_raw"], 128);
    assert_eq!(report["exports"][0]["proof_count"], imported.len());
    let token: cashu::nuts::Token = report["exports"][0]["token"]
        .as_str()
        .unwrap()
        .parse()
        .unwrap();
    assert_eq!(token.mint_url().unwrap().to_string(), mint_url);
    assert_eq!(token.unit(), Some(cashu::nuts::CurrencyUnit::Sat));
    let loose = LooseProofWallet::open(&loose_path, CONFIGURED_CLIENT_WALLET_NAME).unwrap();
    assert_eq!(
        loose.opening_attempt(&attempt_id).unwrap().unwrap().state,
        OpeningAttemptState::Exported
    );
    let reserved = loose.proofs_for_reservation(&attempt_id).unwrap();
    assert_eq!(reserved.len(), imported.len());
    assert!(reserved
        .iter()
        .all(|proof| proof.state == LooseProofState::Reserved));
    assert!(requests
        .lock()
        .unwrap()
        .iter()
        .any(|path| path == "/v1/checkstate"));
    mint_shutdown_tx.send(()).unwrap();
    tokio::time::timeout(Duration::from_secs(10), mint_task)
        .await
        .unwrap()
        .unwrap();
}

fn maintenance(loose: &Path, channel: &Path, command: &str) -> Output {
    Command::new(env!("CARGO_BIN_EXE_monad-client"))
        .arg("wallet")
        .arg("--loose-db")
        .arg(loose)
        .arg("--channel-db")
        .arg(channel)
        .args(["--sender-secret-hex", &"01".repeat(32), "--json", command])
        .env("RUST_LOG", "off")
        .output()
        .unwrap()
}

#[test]
fn opening_maintenance_cli_excludes_runtime_before_database_work() {
    for initialized in [false, true] {
        let dir = tempfile::tempdir().unwrap();
        let loose = dir.path().join("loose.db");
        let channel = dir.path().join("channel.db");
        if initialized {
            let output = maintenance(&loose, &channel, "recover-openings");
            assert!(output.status.success(), "{output:?}");
        }
        let before_loose = std::fs::read(&loose).ok();
        let before_channel = std::fs::read(&channel).ok();
        let mut runtime =
            ClientWalletLocks::acquire(&loose, &channel, WalletLockMode::Runtime).unwrap();
        assert!(runtime.holds_runtime_owner());

        // Startup holds exclusive maintenance access; steady state holds shared access.
        for steady_state in [false, true] {
            if steady_state {
                runtime.enter_steady_state().unwrap();
            }
            for command in ["recover-openings", "export-stale-opening-inputs"] {
                let output = maintenance(&loose, &channel, command);
                assert!(!output.status.success(), "{command}: {output:?}");
                assert!(output.stdout.is_empty(), "{command}: {output:?}");
                let error = String::from_utf8(output.stderr).unwrap();
                assert!(
                    error.contains("client wallet Maintenance lock unavailable"),
                    "{command}: {error}"
                );
                assert_eq!(std::fs::read(&loose).ok(), before_loose);
                assert_eq!(std::fs::read(&channel).ok(), before_channel);
            }
        }
        drop(runtime);

        // Positive controls ensure the same CLI invocations are otherwise valid.
        for (command, expected) in [
            (
                "recover-openings",
                serde_json::json!({
                    "recovered_channel_ids": [], "cancelled_attempt_ids": [],
                    "externally_spent_attempt_ids": [], "unresolved": []
                }),
            ),
            (
                "export-stale-opening-inputs",
                serde_json::json!({"exports": [], "unresolved": []}),
            ),
        ] {
            let output = maintenance(&loose, &channel, command);
            assert!(output.status.success(), "{command}: {output:?}");
            assert_eq!(
                serde_json::from_slice::<serde_json::Value>(&output.stdout).unwrap(),
                expected
            );
        }
    }
}
