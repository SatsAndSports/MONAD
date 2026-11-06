use super::*;
use cashu::nuts::SwapRequest;

struct Competing<'a> {
    inner: OpeningRecoveryHttpNetworking,
    mint: &'a TestMintHelper,
    fee: u64,
    a_wins: bool,
    hold_b: bool,
    reject_b: bool,
    requests: Mutex<Vec<String>>,
    snapshot: Mutex<Option<String>>,
    visible: AtomicBool,
}
impl SpilmanClientNetworking for Competing<'_> {
    fn call_mint_swap(&self, _: &str, _: &str) -> Result<String, MintRequestError> {
        panic!("checked transport required")
    }
    fn call_mint_restore(&self, mint: &str, request: &str) -> Result<String, MintRequestError> {
        if self.a_wins && !self.visible.load(Ordering::SeqCst) {
            return Ok(r#"{"outputs":[],"signatures":[]}"#.to_string());
        }
        self.inner.call_mint_restore(mint, request)
    }
    fn call_mint_keysets(&self, mint: &str) -> Result<String, MintRequestError> {
        self.inner.call_mint_keysets(mint)
    }
    fn call_mint_keys(&self, mint: &str, id: &str) -> Result<String, MintRequestError> {
        self.inner.call_mint_keys(mint, id)
    }
}
impl OpeningRecoveryNetworking for Competing<'_> {
    fn call_opening_swap(&self, mint: &str, request: &str) -> anyhow::Result<String> {
        let n = {
            let mut requests = self.requests.lock().unwrap();
            requests.push(request.to_string());
            requests.len()
        };
        match n {
            1 => {
                std::thread::sleep(Duration::from_millis(1100));
                anyhow::bail!("ambiguous A")
            }
            2 => {
                let parsed: SwapRequest = serde_json::from_str(request)?;
                let ys = parsed
                    .inputs()
                    .iter()
                    .map(Proof::y)
                    .collect::<Result<Vec<_>, _>>()?;
                *self.snapshot.lock().unwrap() = Some(
                    self.inner
                        .call_mint_check_state(mint, &serde_json::json!({"Ys":ys}).to_string())
                        .map_err(anyhow::Error::msg)?,
                );
                if self.a_wins {
                    self.inner.call_opening_swap(mint, request)?;
                }
                tokio::task::block_in_place(|| {
                    tokio::runtime::Handle::current()
                        .block_on(rotate_sat_keyset(&self.mint.mint(), self.fee))
                })?;
                Err(
                    MintHttpRejection::from_body(400, r#"{"code":12002,"detail":"inactive"}"#)
                        .into(),
                )
            }
            3 if self.a_wins => {
                self.visible.store(true, Ordering::SeqCst);
                self.inner.call_opening_swap(mint, request)
            }
            3 => {
                if self.reject_b {
                    tokio::task::block_in_place(|| {
                        tokio::runtime::Handle::current()
                            .block_on(rotate_sat_keyset(&self.mint.mint(), 500))
                    })?;
                    self.visible.store(true, Ordering::SeqCst);
                    return self.inner.call_opening_swap(mint, request);
                }
                std::thread::sleep(Duration::from_millis(1100));
                anyhow::bail!("ambiguous B")
            }
            4 => {
                self.visible.store(true, Ordering::SeqCst);
                if self.hold_b {
                    anyhow::bail!("B remains ambiguous");
                }
                self.inner.call_opening_swap(mint, request)
            }
            _ => panic!("too many opening executions"),
        }
    }
    fn call_mint_check_state(&self, mint: &str, request: &str) -> Result<String, String> {
        if !self.visible.load(Ordering::SeqCst) {
            if let Some(snapshot) = self.snapshot.lock().unwrap().clone() {
                return Ok(snapshot);
            }
        }
        self.inner.call_mint_check_state(mint, request)
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn opening_candidates_keep_fixed_funding_and_finalize_either_channel() {
    for a_wins in [true, false] {
        for target in [true, false] {
            for (initial_fee, next_fee) in [(0, 400), (400, 0)] {
                let ctx = open_short_expiry_test_channel(16, 86_400).await;
                let proofs = ctx.mint_helper.mint_proofs(64).await.unwrap();
                ctx.wallet
                    .loose_wallet
                    .import_proofs(&loose_proofs_from_json(
                        &ctx.mint_url,
                        "sat",
                        "competing",
                        "competing",
                        &serde_json::to_string(&proofs).unwrap(),
                    ))
                    .unwrap();
                let receiver = SecretKey::from_hex(hex::encode([2; 32]))
                    .unwrap()
                    .public_key()
                    .to_hex();
                let offer = offer(&ctx.mint_url, &receiver, &ctx.keyset_id);
                let expiry = SqliteClientWallet::now_seconds().unwrap() + CHANNEL_EXPIRY_SECONDS;
                if initial_fee != 0 {
                    rotate_sat_keyset(&ctx.mint_helper.mint(), initial_fee)
                        .await
                        .unwrap();
                    ctx.wallet.refresh_client_keysets(&offer).unwrap();
                }
                let keys = ctx
                    .wallet
                    .select_output_keyset_refreshing_client_first(&offer, expiry)
                    .unwrap();
                let attempt = if target {
                    ctx.wallet
                        .prepare_target_capacity_attempt(&offer, 32, keys, expiry)
                        .unwrap()
                } else {
                    ctx.wallet
                        .prepare_open_attempt(
                            &offer,
                            keys,
                            ProofReservation {
                                reservation_id: new_reservation_id(),
                                proofs: ctx
                                    .wallet
                                    .loose_wallet
                                    .list_available_proofs(&ctx.mint_url, "sat", &[])
                                    .unwrap(),
                                total_amount_raw: 64,
                            },
                            ClientOpenPlan {
                                expiry_timestamp: expiry,
                                requested_capacity_raw: None,
                                desired_funding_token_amount_raw: Some(32),
                                funding_token_target_msats: 32_000,
                                selected_input_msats: 64_000,
                            },
                            false,
                        )
                        .unwrap()
                };
                let original = attempt.prepared.clone();
                let reservation = attempt.reservation.reservation_id.clone();
                let net = Competing {
                    inner: OpeningRecoveryHttpNetworking::new().unwrap(),
                    mint: &ctx.mint_helper,
                    fee: next_fee,
                    a_wins,
                    hold_b: false,
                    reject_b: false,
                    requests: Mutex::new(vec![]),
                    snapshot: Mutex::new(None),
                    visible: AtomicBool::new(false),
                };
                let interrupt = a_wins && target && initial_fee == 0;
                if interrupt {
                    ctx.wallet.conn().unwrap().execute_batch("CREATE TRIGGER interrupt_winner BEFORE INSERT ON monad_client_channels BEGIN SELECT RAISE(ABORT,'interrupt winner metadata'); END;").unwrap();
                }
                let result = ctx
                    .wallet
                    .execute_open_attempt_with_networking(&offer, attempt, true, &net);
                let winner = if interrupt {
                    assert!(result.is_err());
                    let bound = ctx
                        .wallet
                        .loose_wallet
                        .opening_candidates(&original.channel_id)
                        .unwrap();
                    assert_eq!(bound[0].state, OpeningAttemptState::Finalizing);
                    assert_eq!(bound[1].state, OpeningAttemptState::Cancelled);
                    ctx.wallet
                        .conn()
                        .unwrap()
                        .execute_batch("DROP TRIGGER interrupt_winner")
                        .unwrap();
                    let report = reopen_wallet(&ctx)
                        .recover_pending_openings_with_networking(&net.inner)
                        .unwrap();
                    assert!(report.recovered_channel_ids.contains(&original.channel_id));
                    original.channel_id.clone()
                } else {
                    result.unwrap()
                };
                let candidates = ctx
                    .wallet
                    .loose_wallet
                    .opening_candidates(&original.channel_id)
                    .unwrap();
                assert_eq!(candidates.len(), 2);
                let b: PreparedOpenChannel =
                    serde_json::from_str(&candidates[1].prepared_open_json).unwrap();
                verify_opening_successor(&original, &b).unwrap();
                assert!(if next_fee > initial_fee {
                    b.opening.capacity < original.opening.capacity
                } else {
                    b.opening.capacity > original.opening.capacity
                });
                assert_eq!(
                    original.opening.funding_token_amount,
                    b.opening.funding_token_amount
                );
                assert_eq!(
                    original.opening.change_amount_raw,
                    b.opening.change_amount_raw
                );
                assert!(original.opening.change_amount_raw > 0);
                assert_eq!(
                    winner,
                    if a_wins {
                        original.channel_id.clone()
                    } else {
                        b.channel_id.clone()
                    }
                );
                assert_eq!(
                    candidates
                        .iter()
                        .filter(|a| a.state == OpeningAttemptState::Completed)
                        .count(),
                    1
                );
                assert_eq!(
                    candidates
                        .iter()
                        .filter(|a| a.state == OpeningAttemptState::Cancelled)
                        .count(),
                    1
                );
                let reserved = ctx
                    .wallet
                    .loose_wallet
                    .proofs_for_reservation(&reservation)
                    .unwrap();
                assert!(reserved.iter().all(|p| p.state == LooseProofState::Spent
                    && p.spent_channel_id.as_ref() == Some(&winner)));
                {
                    let requests = net.requests.lock().unwrap();
                    assert_eq!(requests.len(), if a_wins { 3 } else { 4 });
                    assert!(requests[0] == requests[1]);
                    if !a_wins {
                        assert!(requests[2] == requests[3]);
                    }
                }
                let reopened = reopen_wallet(&ctx);
                let info = reopened.get_channel(&winner).unwrap();
                assert_eq!(
                    info.capacity_msats,
                    if a_wins {
                        original.opening.capacity * 1000
                    } else {
                        b.opening.capacity * 1000
                    }
                );
                let loser = if a_wins {
                    &b.channel_id
                } else {
                    &original.channel_id
                };
                assert!(matches!(
                    reopened.get_channel(loser),
                    Err(WalletError::NotFound)
                ));
                // Exercise the winning channel funding at the real mint. Both
                // parties authorize a close; inactive A funding may spend into B.
                let funding = reopened
                    .bridge
                    .lock()
                    .unwrap()
                    .get_channel_funding(&winner)
                    .unwrap();
                let channel = EstablishedChannel::from_client_channel_funding(&funding).unwrap();
                let mut close = cdk_spilman::CommitmentOutputs::for_balance(5, &channel.params)
                    .unwrap()
                    .create_swap_request(channel.funding_proofs.clone(), None)
                    .unwrap();
                let mut request = serde_json::to_value(&close).unwrap();
                for output in request["outputs"].as_array_mut().unwrap() {
                    output["id"] = serde_json::json!(b.keyset_id);
                }
                close = serde_json::from_value(request).unwrap();
                close
                    .sign_sig_all(
                        channel
                            .params
                            .get_sender_blinded_secret_key_for_stage1(&reopened.sender_secret)
                            .unwrap(),
                    )
                    .unwrap();
                close
                    .sign_sig_all(
                        channel
                            .params
                            .get_receiver_blinded_secret_key_for_stage1(
                                &SecretKey::from_hex(hex::encode([2; 32])).unwrap(),
                            )
                            .unwrap(),
                    )
                    .unwrap();
                net.inner
                    .call_opening_swap(&ctx.mint_url, &serde_json::to_string(&close).unwrap())
                    .unwrap();
                let _ = ctx.shutdown_tx.send(());
                ctx.mint_task.await.unwrap().unwrap();
            }
        }
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn opening_candidates_startup_is_restore_only_and_export_deduplicates_reservation() {
    for reject_b in [false, true] {
        let ctx = open_short_expiry_test_channel(16, 86_400).await;
        let proofs = ctx.mint_helper.mint_proofs(64).await.unwrap();
        ctx.wallet
            .loose_wallet
            .import_proofs(&loose_proofs_from_json(
                &ctx.mint_url,
                "sat",
                "pending",
                "pending",
                &serde_json::to_string(&proofs).unwrap(),
            ))
            .unwrap();
        let receiver = SecretKey::from_hex(hex::encode([2; 32]))
            .unwrap()
            .public_key()
            .to_hex();
        let offer = offer(&ctx.mint_url, &receiver, &ctx.keyset_id);
        let expiry = SqliteClientWallet::now_seconds().unwrap() + CHANNEL_EXPIRY_SECONDS;
        let keys = ctx
            .wallet
            .select_output_keyset_refreshing_client_first(&offer, expiry)
            .unwrap();
        let attempt = ctx
            .wallet
            .prepare_target_capacity_attempt(&offer, 32, keys, expiry)
            .unwrap();
        let root = attempt.prepared.channel_id.clone();
        let net = Competing {
            inner: OpeningRecoveryHttpNetworking::new().unwrap(),
            mint: &ctx.mint_helper,
            fee: 400,
            a_wins: false,
            hold_b: true,
            reject_b,
            requests: Mutex::new(vec![]),
            snapshot: Mutex::new(None),
            visible: AtomicBool::new(false),
        };
        assert!(ctx
            .wallet
            .execute_open_attempt_with_networking(&offer, attempt, true, &net)
            .is_err());
        assert_eq!(
            net.requests.lock().unwrap().len(),
            if reject_b { 3 } else { 4 }
        );
        let reopened = reopen_wallet(&ctx);
        let report = reopened
            .recover_pending_openings_with_networking(&net)
            .unwrap();
        if reject_b {
            assert_eq!(net.requests.lock().unwrap().len(), 3);
            let candidates = reopened.loose_wallet.opening_candidates(&root).unwrap();
            assert_eq!(candidates.len(), 2);
            assert_eq!(candidates[0].state, OpeningAttemptState::Submitted);
            assert!(reopened
                .loose_wallet
                .proofs_for_reservation(&candidates[0].reservation_id)
                .unwrap()
                .iter()
                .all(|p| p.state == LooseProofState::Reserved));
            let _ = ctx.shutdown_tx.send(());
            ctx.mint_task.await.unwrap().unwrap();
            continue;
        }
        assert_eq!(report.unresolved.len(), 2);
        assert_eq!(
            net.requests.lock().unwrap().len(),
            4,
            "manual recovery must not submit"
        );
        let candidates = reopened.loose_wallet.opening_candidates(&root).unwrap();
        let conn = Connection::open(&ctx.loose_db).unwrap();
        conn.execute(
            "UPDATE monad_client_opening_attempts SET latest_submitted_at=?1 WHERE opening_id=?2",
            params![
                SqliteClientWallet::now_seconds().unwrap() - 7200,
                candidates[0].opening_id
            ],
        )
        .unwrap();
        let exported = reopened
            .export_stale_opening_inputs_with_networking(&net.inner)
            .unwrap();
        assert_eq!(exported.exports.len(), 1);
        assert_eq!(exported.exports[0].attempt_ids.len(), 2);
        assert_eq!(
            exported.exports[0].proof_count,
            candidates[0].selected_proof_ids.len()
        );
        let b: PreparedOpenChannel =
            serde_json::from_str(&candidates[1].prepared_open_json).unwrap();
        net.inner
            .call_opening_swap(&ctx.mint_url, &b.swap_request_json)
            .unwrap();
        let report = reopened
            .recover_pending_openings_with_networking(&net.inner)
            .unwrap();
        assert!(report.recovered_channel_ids.contains(&b.channel_id));
        let candidates = reopened.loose_wallet.opening_candidates(&root).unwrap();
        assert_eq!(candidates[0].state, OpeningAttemptState::Cancelled);
        assert_eq!(candidates[1].state, OpeningAttemptState::Completed);
        assert_eq!(net.requests.lock().unwrap().len(), 4);
        let _ = ctx.shutdown_tx.send(());
        ctx.mint_task.await.unwrap().unwrap();
    }
}
