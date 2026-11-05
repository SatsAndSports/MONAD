use super::*;
use cashu::nuts::{CheckStateResponse, RestoreRequest, RestoreResponse, SwapRequest, SwapResponse};

#[derive(Clone, Copy)]
enum Outcome {
    A,
    BReplay,
    BLost,
    Neither,
    BRejected,
    Close,
}

struct Candidates<'a> {
    ctx: &'a OpenedTestChannel,
    inner: DirectMintConnection,
    outcome: Outcome,
    requests: Mutex<Vec<SwapRequest>>,
    early: Mutex<Option<CheckStateResponse>>,
    visible: AtomicBool,
    accepted: AtomicUsize,
    pause: bool,
    entered: tokio::sync::Notify,
    close: SwapRequest,
}

impl<'a> Candidates<'a> {
    fn new(ctx: &'a OpenedTestChannel, outcome: Outcome, pause: bool) -> Self {
        let funding = ctx
            .wallet
            .bridge
            .lock()
            .unwrap()
            .get_channel_funding(&ctx.channel_id)
            .unwrap();
        let channel = EstablishedChannel::from_client_channel_funding(&funding).unwrap();
        let mut close = cdk_spilman::CommitmentOutputs::for_balance(5, &channel.params)
            .unwrap()
            .create_swap_request(channel.funding_proofs.clone(), None)
            .unwrap();
        close
            .sign_sig_all(
                channel
                    .params
                    .get_sender_blinded_secret_key_for_stage1(&ctx.wallet.sender_secret)
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
        Self {
            ctx,
            inner: direct_mint_connection(ctx),
            outcome,
            requests: Mutex::new(vec![]),
            early: Mutex::new(None),
            visible: AtomicBool::new(false),
            accepted: AtomicUsize::new(0),
            pause,
            entered: tokio::sync::Notify::new(),
            close,
        }
    }
    async fn accept(&self, request: SwapRequest) -> anyhow::Result<SwapResponse> {
        let response = self.inner.process_swap(request).await?;
        self.accepted.fetch_add(1, Ordering::SeqCst);
        Ok(response)
    }
}

#[async_trait::async_trait]
impl MintConnection for Candidates<'_> {
    async fn process_swap(&self, request: SwapRequest) -> anyhow::Result<SwapResponse> {
        let call = {
            let mut requests = self.requests.lock().unwrap();
            requests.push(request.clone());
            requests.len()
        };
        match call {
            1 => anyhow::bail!("ambiguous A delivery"),
            2 => {
                *self.early.lock().unwrap() = Some(
                    self.inner
                        .check_state(
                            request
                                .inputs()
                                .iter()
                                .map(Proof::y)
                                .collect::<Result<Vec<_>, _>>()?,
                        )
                        .await?,
                );
                if matches!(self.outcome, Outcome::A) {
                    self.accept(request).await?;
                }
                rotate_sat_keyset(&self.ctx.mint_helper.mint(), 400).await?;
                Err(
                    MintHttpRejection::from_body(400, r#"{"code":12002,"detail":"inactive"}"#)
                        .into(),
                )
            }
            3 => {
                if self.pause && !matches!(self.outcome, Outcome::BLost) {
                    self.entered.notify_one();
                    std::future::pending::<()>().await;
                }
                match self.outcome {
                    Outcome::A => {
                        self.visible.store(true, Ordering::SeqCst);
                        self.accept(request).await
                    }
                    Outcome::BReplay | Outcome::Neither => anyhow::bail!("ambiguous B delivery"),
                    Outcome::BLost => {
                        self.accept(request).await?;
                        if self.pause {
                            self.entered.notify_one();
                            std::future::pending::<()>().await;
                        }
                        self.visible.store(true, Ordering::SeqCst);
                        anyhow::bail!("lost B reply")
                    }
                    Outcome::BRejected => {
                        rotate_sat_keyset(&self.ctx.mint_helper.mint(), 500).await?;
                        self.visible.store(true, Ordering::SeqCst);
                        self.accept(request).await
                    }
                    Outcome::Close => {
                        // Alice has entered B submission. Charlie executes first;
                        // only the IDs change, retaining his existing signatures.
                        let mut json = serde_json::to_value(&self.close)?;
                        for output in json["outputs"].as_array_mut().unwrap() {
                            output["id"] = serde_json::to_value(request.outputs()[0].keyset_id)?;
                        }
                        self.accept(serde_json::from_value(json)?).await?;
                        self.visible.store(true, Ordering::SeqCst);
                        self.accept(request).await
                    }
                }
            }
            4 => {
                assert!(matches!(self.outcome, Outcome::BReplay | Outcome::Neither));
                self.visible.store(true, Ordering::SeqCst);
                if matches!(self.outcome, Outcome::Neither) {
                    anyhow::bail!("B replay uncertain");
                }
                self.accept(request).await
            }
            _ => panic!("exceeded refund budget"),
        }
    }
    async fn check_state(
        &self,
        ys: Vec<cashu::nuts::PublicKey>,
    ) -> anyhow::Result<CheckStateResponse> {
        if !self.visible.load(Ordering::SeqCst) {
            if let Some(snapshot) = self.early.lock().unwrap().clone() {
                return Ok(snapshot);
            }
        }
        self.inner.check_state(ys).await
    }
    async fn post_restore(&self, request: RestoreRequest) -> anyhow::Result<RestoreResponse> {
        self.inner.post_restore(request).await
    }
}

fn retained(ctx: &OpenedTestChannel) -> (String, String, Option<String>, String) {
    let conn = ctx.wallet.conn().unwrap();
    let a = conn
        .query_row(
            "SELECT prepared_json FROM monad_client_refund_predecessors WHERE channel_id=?1",
            [&ctx.channel_id],
            |r| r.get(0),
        )
        .unwrap();
    let (b, winner, kind) = conn.query_row("SELECT prepared_refund_json, winning_refund_json, kind FROM monad_client_channel_recoveries WHERE channel_id=?1", [&ctx.channel_id], |r| Ok((r.get(0)?,r.get(1)?,r.get(2)?))).unwrap();
    (a, b, winner, kind)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn refund_candidates_recover_either_winner_or_close_and_spend_imported_funds() {
    for outcome in [Outcome::A, Outcome::BReplay, Outcome::BLost, Outcome::Close] {
        let ctx = open_short_expiry_test_channel(32, 1).await;
        wait_until_expired(ctx.expiry_timestamp).await;
        let locks = refund_test_locks(&ctx);
        let net = Candidates::new(&ctx, outcome, false);
        // Verify durable finalization can resume offline, including close fallback.
        ctx.wallet.fail_next_recovered_proof_import_for_test();
        assert!(ctx
            .wallet
            .recover_channel_funds(&locks.exclusive_access().unwrap(), &ctx.channel_id, &net)
            .await
            .is_err());
        assert_eq!(
            recovery_row_status(&ctx.wallet, &ctx.channel_id),
            "finalizing"
        );
        assert_eq!(net.accepted.load(Ordering::SeqCst), 1);
        let (a, b, winner, kind) = retained(&ctx);
        let pa = PreparedSenderRefund::from_json(&a).unwrap();
        let pb = PreparedSenderRefund::from_json(&b).unwrap();
        assert!(pa.swap_request.inputs() == pb.swap_request.inputs());
        assert!(pa
            .outputs
            .iter()
            .zip(&pb.outputs)
            .all(|(a, b)| a.secret == b.secret && a.blinding_factor == b.blinding_factor));
        if matches!(outcome, Outcome::Close) {
            assert_eq!(kind, "relay_close");
            assert!(winner.is_none());
        } else {
            assert_eq!(kind, "post_expiry_refund");
            assert!(
                winner.as_ref()
                    == Some(if matches!(outcome, Outcome::A) {
                        &a
                    } else {
                        &b
                    })
            );
            // A wrong durable winner must fail before importing any funds.
            let wrong = if matches!(outcome, Outcome::A) {
                &b
            } else {
                &a
            };
            ctx.wallet.conn().unwrap().execute("UPDATE monad_client_channel_recoveries SET winning_refund_json=?1 WHERE channel_id=?2", params![wrong, ctx.channel_id]).unwrap();
            assert!(ctx
                .wallet
                .recover_channel_funds(
                    &locks.exclusive_access().unwrap(),
                    &ctx.channel_id,
                    &OfflineRefundMint
                )
                .await
                .is_err());
            ctx.wallet.conn().unwrap().execute("UPDATE monad_client_channel_recoveries SET winning_refund_json=?1 WHERE channel_id=?2", params![winner, ctx.channel_id]).unwrap();
        }
        let reopened = reopen_wallet(&ctx);
        let result = reopened
            .recover_channel_funds(
                &locks.exclusive_access().unwrap(),
                &ctx.channel_id,
                &OfflineRefundMint,
            )
            .await
            .unwrap();
        assert!(if matches!(outcome, Outcome::Close) {
            matches!(
                result,
                ChannelFundRecoveryResult::RelayCloseRecovered { .. }
            )
        } else {
            matches!(
                result,
                ChannelFundRecoveryResult::PostExpiryRefundRecovered { .. }
            )
        });
        assert!(matches!(
            reopened
                .recover_channel_funds(
                    &locks.exclusive_access().unwrap(),
                    &ctx.channel_id,
                    &OfflineRefundMint
                )
                .await
                .unwrap(),
            ChannelFundRecoveryResult::AlreadyRecovered { .. }
        ));
        let json: String = reopened.conn().unwrap().query_row("SELECT completed_proofs_json FROM monad_client_channel_recoveries WHERE channel_id=?1", [&ctx.channel_id], |r| r.get(0)).unwrap();
        let proofs: Vec<Proof> = serde_json::from_str(&json).unwrap();
        let sum: u64 = proofs.iter().map(|p| u64::from(p.amount)).sum();
        if matches!(outcome, Outcome::Close) {
            assert!(sum < pa.output_amount_raw);
        } else {
            assert_eq!(sum, pa.output_amount_raw);
        }
        assert_eq!(
            reopened
                .loose_wallet
                .list_available_proofs(&ctx.mint_url, "sat", &[])
                .unwrap()
                .iter()
                .map(|p| p.amount_raw)
                .sum::<u64>(),
            sum
        );
        // Real subsequent swap accounts for the winner's output-keyset input fees.
        let fee: u64 = proofs
            .iter()
            .map(|p| {
                ctx.mint_helper
                    .mint()
                    .keysets()
                    .keysets
                    .iter()
                    .find(|k| k.id == p.keyset_id)
                    .unwrap()
                    .input_fee_ppk
            })
            .sum::<u64>()
            .div_ceil(1000);
        let keys = pb.output_keyset.clone();
        let prepared: serde_json::Value = serde_json::from_str(&cdk_spilman::create_plain_blinded_messages(sum-fee,
            &serde_json::json!({"keysetId":keys.keyset_id.to_string(),"unit":"sat","keys":keys.active_keys,"inputFeePpk":keys.input_fee_ppk}).to_string()).unwrap()).unwrap();
        net.inner
            .process_swap(SwapRequest::new(
                proofs,
                serde_json::from_value(prepared["blinded_messages"].clone()).unwrap(),
            ))
            .await
            .unwrap();
        {
            let requests = net.requests.lock().unwrap();
            assert!(requests[0] == requests[1]);
            if matches!(outcome, Outcome::BReplay) {
                assert_eq!(requests.len(), 4);
                assert!(requests[2] == requests[3]);
            }
        }
        let _ = ctx.shutdown_tx.send(());
        ctx.mint_task.await.unwrap().unwrap();
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn refund_candidates_budget_exhaustion_and_b_rejection_retain_history() {
    for outcome in [Outcome::Neither, Outcome::BRejected] {
        let ctx = open_short_expiry_test_channel(32, 1).await;
        wait_until_expired(ctx.expiry_timestamp).await;
        let locks = refund_test_locks(&ctx);
        let net = Candidates::new(&ctx, outcome, false);
        assert!(matches!(
            ctx.wallet
                .recover_channel_funds(&locks.exclusive_access().unwrap(), &ctx.channel_id, &net)
                .await
                .unwrap(),
            ChannelFundRecoveryResult::RecoveryRetryLater { .. }
        ));
        let (a, b, winner, _) = retained(&ctx);
        assert!(winner.is_none());
        assert_eq!(
            recovery_row_status(&ctx.wallet, &ctx.channel_id),
            "submitting"
        );
        let reopened = reopen_wallet(&ctx);
        let result = reopened
            .recover_channel_funds(
                &locks.exclusive_access().unwrap(),
                &ctx.channel_id,
                &net.inner,
            )
            .await
            .unwrap();
        if matches!(outcome, Outcome::Neither) {
            assert!(matches!(
                result,
                ChannelFundRecoveryResult::PostExpiryRefundRecovered { .. }
            ));
        } else {
            assert!(matches!(
                result,
                ChannelFundRecoveryResult::RecoveryRetryLater { .. }
            ));
        }
        let (after_a, after_b, _, _) = retained(&ctx);
        assert!(a == after_a && b == after_b);
        let _ = ctx.shutdown_tx.send(());
        ctx.mint_task.await.unwrap().unwrap();
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn refund_candidates_cancel_after_b_recorded_then_restore_a_on_reopen() {
    for outcome in [Outcome::A, Outcome::BLost] {
        let ctx = open_short_expiry_test_channel(32, 1).await;
        wait_until_expired(ctx.expiry_timestamp).await;
        let locks = refund_test_locks(&ctx);
        let access = locks.exclusive_access().unwrap();
        let net = Candidates::new(&ctx, outcome, true);
        {
            let operation = ctx
                .wallet
                .recover_channel_funds(&access, &ctx.channel_id, &net);
            tokio::pin!(operation);
            tokio::select! { _ = net.entered.notified() => {}, _ = &mut operation => panic!("ended before B boundary"), _ = tokio::time::sleep(Duration::from_secs(15)) => panic!("boundary timeout") }
        }
        let (a, b, winner, _) = retained(&ctx);
        assert!(winner.is_none());
        let reopened = reopen_wallet(&ctx);
        assert!(matches!(
            reopened
                .recover_channel_funds(&access, &ctx.channel_id, &net.inner)
                .await
                .unwrap(),
            ChannelFundRecoveryResult::PostExpiryRefundRecovered { .. }
        ));
        assert!(
            retained(&ctx).2.as_ref()
                == Some(if matches!(outcome, Outcome::A) {
                    &a
                } else {
                    &b
                })
        );
        let _ = ctx.shutdown_tx.send(());
        ctx.mint_task.await.unwrap().unwrap();
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn refund_candidates_reject_corrupt_preparation_authority_and_v2_before_io() {
    let ctx = open_short_expiry_test_channel(32, 1).await;
    wait_until_expired(ctx.expiry_timestamp).await;
    let locks = refund_test_locks(&ctx);
    let net = Candidates::new(&ctx, Outcome::Neither, false);
    ctx.wallet
        .recover_channel_funds(&locks.exclusive_access().unwrap(), &ctx.channel_id, &net)
        .await
        .unwrap();
    let (a, b, _, _) = retained(&ctx);
    for change in 0..3 {
        let mut bad: serde_json::Value = serde_json::from_str(&b).unwrap();
        match change {
            0 => {
                bad.as_object_mut().unwrap().remove("derivation_keyset");
            }
            1 => {
                bad["derivation_context"][0] = serde_json::json!(999);
            }
            _ => {
                bad["swap_request"]["inputs"][0]["witness"] = serde_json::Value::Null;
            }
        }
        ctx.wallet.conn().unwrap().execute("UPDATE monad_client_channel_recoveries SET prepared_refund_json=?1 WHERE channel_id=?2",params![bad.to_string(),ctx.channel_id]).unwrap();
        assert!(ctx
            .wallet
            .recover_channel_funds(
                &locks.exclusive_access().unwrap(),
                &ctx.channel_id,
                &OfflineRefundMint
            )
            .await
            .is_err());
        ctx.wallet.conn().unwrap().execute("UPDATE monad_client_channel_recoveries SET prepared_refund_json=?1 WHERE channel_id=?2",params![b,ctx.channel_id]).unwrap();
    }
    ctx.wallet
        .conn()
        .unwrap()
        .execute(
            "UPDATE monad_client_refund_executions SET outcome='uncertain' WHERE prepared_json=?1",
            [&a],
        )
        .unwrap();
    assert!(ctx
        .wallet
        .recover_channel_funds(
            &locks.exclusive_access().unwrap(),
            &ctx.channel_id,
            &OfflineRefundMint
        )
        .await
        .is_err());
    ctx.wallet.conn().unwrap().execute_batch("PRAGMA ignore_check_constraints=ON; UPDATE monad_client_channel_recoveries SET journal_version=2;").unwrap();
    let loose = LooseProofWallet::open(&ctx.loose_db, "alice").unwrap();
    assert!(SqliteClientWallet::open(loose, &ctx.channel_db, &ctx.sender_secret).is_err());
    assert_eq!(retained(&ctx).0, a);
    assert_eq!(
        recovery_row_status(&ctx.wallet, &ctx.channel_id),
        "submitting"
    );
    let _ = ctx.shutdown_tx.send(());
    ctx.mint_task.await.unwrap().unwrap();
}
