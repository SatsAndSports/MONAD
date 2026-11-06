//! Competing drain candidates only. The real mint signs/spends; this adapter
//! controls delivery of replies/snapshots to exercise otherwise rare orderings.
use super::*;
use cashu::nuts::{CurrencyUnit, Proof, SwapRequest};
use rusqlite::params;

#[derive(Clone, Copy)]
enum Outcome {
    OriginalWins,
    OriginalWinsAfterState,
    SuccessorReplayWins,
    SuccessorReplyLost,
    Neither,
    SuccessorRejected,
}

#[derive(Clone, Copy)]
enum Pause {
    None,
    BeforeSuccessor,
    AfterSuccessorCommit,
}

struct CandidateNet<'a> {
    inner: &'a RelayWalletMintClient,
    mint: Arc<cdk::Mint>,
    outcome: Outcome,
    pause: Pause,
    requests: Mutex<Vec<String>>,
    // This is a real UNSPENT snapshot captured before any drain commit. For the
    // original-wins case it is deliberately delivered late, along with earlier
    // empty restore snapshots. It never changes the mint's spent-state database.
    early_state: Mutex<Option<String>>,
    early_restore: Mutex<Option<String>>,
    visible: std::sync::atomic::AtomicBool,
    state_calls: AtomicUsize,
    accepted: AtomicUsize,
    entered: tokio::sync::Notify,
}

impl<'a> CandidateNet<'a> {
    fn new(
        inner: &'a RelayWalletMintClient,
        mint: Arc<cdk::Mint>,
        outcome: Outcome,
        pause: Pause,
    ) -> Self {
        Self {
            inner,
            mint,
            outcome,
            pause,
            requests: Mutex::new(Vec::new()),
            early_state: Mutex::new(None),
            early_restore: Mutex::new(None),
            visible: std::sync::atomic::AtomicBool::new(false),
            state_calls: AtomicUsize::new(0),
            accepted: AtomicUsize::new(0),
            entered: tokio::sync::Notify::new(),
        }
    }

    async fn accept(&self, mint: &str, request: &str) -> anyhow::Result<String> {
        let response = self.inner.checked_swap(mint, request).await?;
        self.accepted.fetch_add(1, Ordering::SeqCst);
        Ok(response)
    }

    async fn execute(&self, mint: &str, request: &str) -> anyhow::Result<String> {
        let call = {
            let mut requests = self.requests.lock().unwrap();
            requests.push(request.to_string());
            requests.len()
        };
        match call {
            1 => anyhow::bail!("ambiguous original delivery"),
            2 => {
                let parsed: SwapRequest = serde_json::from_str(request)?;
                let ys = parsed
                    .inputs()
                    .iter()
                    .map(Proof::y)
                    .collect::<Result<Vec<_>, _>>()?;
                let snapshot = self
                    .inner
                    .checked_state(mint, &serde_json::json!({"Ys":ys}).to_string())
                    .await?;
                *self.early_state.lock().unwrap() = Some(snapshot);
                let empty = self
                    .inner
                    .call_mint_restore(
                        mint,
                        &serde_json::json!({"outputs":parsed.outputs()}).to_string(),
                    )
                    .await
                    .map_err(anyhow::Error::msg)?;
                *self.early_restore.lock().unwrap() = Some(empty);
                if matches!(
                    self.outcome,
                    Outcome::OriginalWins | Outcome::OriginalWinsAfterState
                ) {
                    self.accept(mint, request).await?; // The first reply is lost.
                }
                rotate_sat_keyset(&self.mint, 500).await?;
                Err(monad_common::mint_error::MintHttpRejection::from_body(
                    400,
                    r#"{"code":12002,"detail":"inactive output keyset"}"#,
                )
                .into())
            }
            3 => match self.outcome {
                Outcome::OriginalWins | Outcome::OriginalWinsAfterState => {
                    // B uses the now-active keyset, so the real mint rejects its
                    // inputs as spent. Reveal A only after this execution.
                    let error = self
                        .accept(mint, request)
                        .await
                        .map(|_| ())
                        .expect_err("only A can win");
                    assert!(
                        error
                            .downcast_ref::<monad_common::mint_error::MintHttpRejection>()
                            .is_some_and(|r| r.status == 400 && r.code == Some(11001)),
                        "B must lose because the identical inputs were spent"
                    );
                    if matches!(self.outcome, Outcome::OriginalWins) {
                        self.visible.store(true, Ordering::SeqCst);
                    }
                    Err(error)
                }
                Outcome::SuccessorReplayWins | Outcome::Neither => {
                    anyhow::bail!("ambiguous successor delivery")
                }
                Outcome::SuccessorReplyLost => {
                    self.accept(mint, request).await?;
                    if matches!(self.pause, Pause::AfterSuccessorCommit) {
                        self.entered.notify_one();
                        std::future::pending::<()>().await;
                    }
                    self.visible.store(true, Ordering::SeqCst);
                    anyhow::bail!("lost successor response")
                }
                Outcome::SuccessorRejected => {
                    rotate_sat_keyset(&self.mint, 700).await?;
                    self.visible.store(true, Ordering::SeqCst);
                    self.accept(mint, request).await // Real 12002; never create C.
                }
            },
            4 => {
                assert!(matches!(
                    self.outcome,
                    Outcome::SuccessorReplayWins | Outcome::Neither
                ));
                self.visible.store(true, Ordering::SeqCst);
                if matches!(self.outcome, Outcome::Neither) {
                    anyhow::bail!("successor replay uncertain");
                }
                self.accept(mint, request).await
            }
            _ => panic!("drain exceeded its candidate budgets"),
        }
    }
}

impl DrainSwapNetworking for CandidateNet<'_> {
    fn checked_swap<'a>(
        &'a self,
        mint: &'a str,
        request: &'a str,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = anyhow::Result<String>> + Send + 'a>>
    {
        Box::pin(self.execute(mint, request))
    }
    fn checked_state<'a>(
        &'a self,
        mint: &'a str,
        request: &'a str,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = anyhow::Result<String>> + Send + 'a>>
    {
        Box::pin(async move {
            let call = self.state_calls.fetch_add(1, Ordering::SeqCst);
            if matches!(self.outcome, Outcome::OriginalWinsAfterState)
                && self.requests.lock().unwrap().len() >= 3
            {
                self.visible.store(true, Ordering::SeqCst);
            }
            if matches!(self.pause, Pause::BeforeSuccessor) && call == 2 {
                self.entered.notify_one();
                std::future::pending::<()>().await;
            }
            if !self.visible.load(Ordering::SeqCst) {
                if let Some(snapshot) = self.early_state.lock().unwrap().clone() {
                    return Ok(snapshot);
                }
            }
            self.inner.checked_state(mint, request).await
        })
    }
    fn call_mint_swap<'a>(
        &'a self,
        _: &'a str,
        _: &'a str,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<String, String>> + Send + 'a>>
    {
        panic!("checked drain transport required")
    }
    fn call_mint_restore<'a>(
        &'a self,
        mint: &'a str,
        request: &'a str,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<String, String>> + Send + 'a>>
    {
        Box::pin(async move {
            if !self.visible.load(Ordering::SeqCst) {
                let original = self.requests.lock().unwrap().first().cloned();
                if let Some(original) = original {
                    let original: SwapRequest = serde_json::from_str(&original).unwrap();
                    let restore: cashu::nuts::RestoreRequest =
                        serde_json::from_str(request).unwrap();
                    if *original.outputs() == restore.outputs {
                        if let Some(snapshot) = self.early_restore.lock().unwrap().clone() {
                            return Ok(snapshot);
                        }
                    }
                }
                return self.inner.call_mint_restore(mint, request).await;
            }
            if matches!(self.outcome, Outcome::SuccessorReplyLost) {
                let original: SwapRequest =
                    serde_json::from_str(&self.requests.lock().unwrap()[0]).unwrap();
                let restore: cashu::nuts::RestoreRequest = serde_json::from_str(request).unwrap();
                if *original.outputs() == restore.outputs {
                    return Err("original restore temporarily unavailable".to_string());
                }
            }
            self.inner.call_mint_restore(mint, request).await
        })
    }
}

struct Offline;
impl DrainSwapNetworking for Offline {
    fn call_mint_swap<'a>(
        &'a self,
        _: &'a str,
        _: &'a str,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<String, String>> + Send + 'a>>
    {
        panic!("unexpected mint submission")
    }
    fn call_mint_restore<'a>(
        &'a self,
        _: &'a str,
        _: &'a str,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<String, String>> + Send + 'a>>
    {
        panic!("unexpected mint restore")
    }
    fn checked_state<'a>(
        &'a self,
        _: &'a str,
        _: &'a str,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = anyhow::Result<String>> + Send + 'a>>
    {
        panic!("unexpected mint state query")
    }
}

struct FailedRestores {
    calls: AtomicUsize,
    both_fail: bool,
}
impl DrainSwapNetworking for FailedRestores {
    fn call_mint_swap<'a>(
        &'a self,
        _: &'a str,
        _: &'a str,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<String, String>> + Send + 'a>>
    {
        panic!("restore errors must block submission")
    }
    fn call_mint_restore<'a>(
        &'a self,
        _: &'a str,
        _: &'a str,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<String, String>> + Send + 'a>>
    {
        Box::pin(async move {
            let call = self.calls.fetch_add(1, Ordering::SeqCst);
            if call == 0 || self.both_fail {
                Err("restore unavailable".to_string())
            } else {
                Ok(r#"{"outputs":[],"signatures":[]}"#.to_string())
            }
        })
    }
}

fn journal(ctx: &DrainTestContext) -> (String, serde_json::Value) {
    let conn = rusqlite::Connection::open(ctx._temp_db.path()).unwrap();
    let (id, json): (String, String) = conn
        .query_row(
            "SELECT drain_id,journal_json FROM monad_relay_drain_journals",
            [],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )
        .unwrap();
    (id, serde_json::from_str(&json).unwrap())
}

fn assert_candidates(journal: &serde_json::Value) {
    assert_eq!(journal["version"], 2);
    assert_eq!(journal["attempts"].as_array().unwrap().len(), 2);
    let a = &journal["attempts"][0];
    let b = &journal["attempts"][1];
    assert_eq!(a["submissions"], 2);
    assert_eq!(a["keyset_rejection"]["submission"], 2);
    assert_eq!(a["keyset_rejection"]["evidence"]["code"], 12002);
    let ar: SwapRequest =
        serde_json::from_str(a["prepared"]["swap_request_json"].as_str().unwrap()).unwrap();
    let br: SwapRequest =
        serde_json::from_str(b["prepared"]["swap_request_json"].as_str().unwrap()).unwrap();
    assert!(
        ar.inputs() == br.inputs(),
        "candidates must spend identical inputs"
    );
    assert!(
        ar.outputs() != br.outputs(),
        "successor must have distinct outputs"
    );
    assert!(
        a["prepared"]["output_secrets_json"] != b["prepared"]["output_secrets_json"],
        "retain both recovery payloads"
    );
    assert!(
        a["input_fees"] == b["input_fees"],
        "input fee snapshot changed"
    );
}

async fn verify_and_spend(
    ctx: &DrainTestContext,
    result: &monad_relay::wallet_manager::DrainSwapResult,
) {
    let proofs: Vec<Proof> = serde_json::from_str(&result.output_proofs_json).unwrap();
    assert_eq!(
        proofs.iter().map(|p| u64::from(p.amount)).sum::<u64>(),
        result.output_amount_raw
    );
    let sets = ctx.mint.keysets();
    for proof in &proofs {
        let keys = ctx
            .mint
            .keyset_pubkeys(&proof.keyset_id)
            .unwrap()
            .keysets
            .remove(0)
            .keys;
        proof
            .verify_dleq(keys.amount_key(proof.amount).unwrap())
            .unwrap();
    }
    let input_fee = proofs
        .iter()
        .map(|p| {
            sets.keysets
                .iter()
                .find(|k| k.id == p.keyset_id)
                .unwrap()
                .input_fee_ppk
        })
        .sum::<u64>()
        .div_ceil(1000);
    let active = *ctx
        .mint
        .get_active_keysets()
        .get(&CurrencyUnit::Sat)
        .unwrap();
    let keys = ctx
        .mint
        .keyset_pubkeys(&active)
        .unwrap()
        .keysets
        .remove(0)
        .keys;
    let info = serde_json::json!({"keysetId": active.to_string(), "unit":"sat", "keys":keys,"inputFeePpk":sets.keysets.iter().find(|k| k.id == active).unwrap().input_fee_ppk}).to_string();
    let outputs: serde_json::Value = serde_json::from_str(
        &cdk_spilman::create_plain_blinded_messages(result.output_amount_raw - input_fee, &info)
            .unwrap(),
    )
    .unwrap();
    let request = SwapRequest::new(
        proofs,
        serde_json::from_value(outputs["blinded_messages"].clone()).unwrap(),
    );
    let response = ctx.mint.process_swap_request(request).await.unwrap();
    let complete = cdk_spilman::complete_funding_swap(
        &serde_json::to_string(&response).unwrap(),
        &outputs["secrets_with_blinding"].to_string(),
        &info,
    )
    .unwrap();
    let complete: serde_json::Value = serde_json::from_str(&complete).unwrap();
    assert_eq!(
        sum_proof_amounts(complete["funding_proofs_json"].as_str().unwrap()),
        result.output_amount_raw - input_fee
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn competing_drain_candidates_recover_either_winner_and_successor_gets_its_own_replay() {
    for outcome in [
        Outcome::OriginalWins,
        Outcome::OriginalWinsAfterState,
        Outcome::SuccessorReplayWins,
        Outcome::SuccessorReplyLost,
    ] {
        let ctx = DrainTestContext::new("candidate-winner").await;
        // Close into a real nonzero-fee keyset, then drain its proofs. This
        // distinguishes immutable input fees from later output-keyset rotation.
        let channel = create_paid_open_channel_with_expiry(
            &ctx.payments,
            &ctx.wallet,
            &ctx.offer,
            [70; 32],
            450,
            cashu::util::unix_time() + 86_400,
        )
        .await;
        rotate_sat_keyset(&ctx.mint, 400).await.unwrap();
        cdk_spilman::SpilmanAsyncKeysetRefresher::refresh(&ctx.wallet_manager, &ctx.mint_url)
            .await
            .unwrap();
        ctx.wallet_manager
            .close_channel(&channel, &ctx.net_for(&channel))
            .await
            .unwrap()
            .into_closed()
            .unwrap();
        let inner = ctx.net_for(&channel);
        let net = CandidateNet::new(&inner, Arc::clone(&ctx.mint), outcome, Pause::None);
        let result = ctx
            .wallet_manager
            .drain_closed_channels_by_id_to_swap(
                "candidate-winner",
                std::slice::from_ref(&channel),
                &net,
            )
            .await
            .unwrap();
        assert_eq!(net.accepted.load(Ordering::SeqCst), 1);
        let (_, history) = journal(&ctx);
        assert_candidates(&history);
        let winner = if matches!(
            outcome,
            Outcome::OriginalWins | Outcome::OriginalWinsAfterState
        ) {
            0
        } else {
            1
        };
        assert_eq!(history["winner"], winner);
        let requests = net.requests.lock().unwrap().clone();
        assert!(requests[0] == requests[1], "A replay changed request");
        if matches!(outcome, Outcome::SuccessorReplayWins) {
            assert_eq!(requests.len(), 4);
            assert!(requests[2] == requests[3], "B replay changed request");
        } else {
            assert_eq!(requests.len(), 3);
        }
        let conn = rusqlite::Connection::open(ctx._temp_db.path()).unwrap();
        let selected: String = conn
            .query_row("SELECT output_keyset_id FROM monad_relay_drains", [], |r| {
                r.get(0)
            })
            .unwrap();
        let selected_request: SwapRequest = serde_json::from_str(
            history["attempts"][winner as usize]["prepared"]["swap_request_json"]
                .as_str()
                .unwrap(),
        )
        .unwrap();
        assert_eq!(
            selected,
            selected_request.outputs()[0].keyset_id.to_string()
        );
        let fees = result.input_amount_raw - result.output_amount_raw;
        assert!(fees > 0);
        let expected_fee = selected_request
            .inputs()
            .iter()
            .map(|p| {
                history["attempts"][0]["input_fees"][p.keyset_id.to_string()]
                    .as_u64()
                    .unwrap()
            })
            .sum::<u64>()
            .div_ceil(1000);
        assert_eq!(fees, expected_fee);
        assert_eq!(result.input_amount_raw, 450);
        let reopened = ctx.wallet_manager.reopen().unwrap();
        let again = reopened
            .recover_submitted_drain(&result.drain_id, &Offline)
            .await
            .unwrap();
        assert!(
            again.output_proofs_json == result.output_proofs_json,
            "offline completion changed payout"
        );
        if winner == 0 {
            let mut wrong_winner = history.clone();
            wrong_winner["winner"] = serde_json::json!(1);
            conn.execute(
                "UPDATE monad_relay_drain_journals SET journal_json=?1 WHERE drain_id=?2",
                params![wrong_winner.to_string(), result.drain_id],
            )
            .unwrap();
            assert!(
                reopened
                    .recover_submitted_drain(&result.drain_id, &Offline)
                    .await
                    .map(|_| ())
                    .expect_err("wrong winner must reject")
                    .contains("finalization proof conflict"),
                "A payout must not authenticate as B finalization"
            );
            conn.execute(
                "UPDATE monad_relay_drain_journals SET journal_json=?1 WHERE drain_id=?2",
                params![history.to_string(), result.drain_id],
            )
            .unwrap();
        }
        verify_and_spend(&ctx, &result).await;
        assert_eq!(ctx.wallet_manager.list_drains().unwrap().len(), 1);
        ctx.shutdown();
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn competing_drain_cancellation_reopens_before_b_submit_or_after_b_commit() {
    for (outcome, pause, winner) in [
        (Outcome::OriginalWins, Pause::BeforeSuccessor, 0),
        (Outcome::SuccessorReplyLost, Pause::AfterSuccessorCommit, 1),
    ] {
        let ctx = DrainTestContext::new("candidate-cancel").await;
        let channel = ctx.create_closed_channel([71; 32], 450).await;
        let inner = ctx.net_for(&channel);
        let net = CandidateNet::new(&inner, Arc::clone(&ctx.mint), outcome, pause);
        {
            let ids = vec![channel.clone()];
            let operation = ctx.wallet_manager.drain_closed_channels_by_id_to_swap(
                "candidate-cancel",
                &ids,
                &net,
            );
            tokio::pin!(operation);
            tokio::select! {
                _ = tokio::time::sleep(Duration::from_secs(15)) => panic!("drain did not reach boundary"),
                _ = net.entered.notified() => {},
                _ = &mut operation => panic!("operation completed before cancellation"),
            }
        }
        let (id, history) = journal(&ctx);
        assert_candidates(&history);
        assert!(history["winner"].is_null());
        assert_eq!(
            ctx.wallet_manager.list_drains().unwrap()[0].state,
            "Submitted"
        );
        if winner == 0 {
            assert_eq!(history["attempts"][1]["submissions"], 0);
        }
        let reopened = ctx.wallet_manager.reopen().unwrap();
        let result = reopened.recover_submitted_drain(&id, &inner).await.unwrap();
        let (_, history) = journal(&ctx);
        assert_eq!(history["winner"], winner);
        verify_and_spend(&ctx, &result).await;
        ctx.shutdown();
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn competing_drain_budget_exhaustion_retains_both_candidates_and_reopens() {
    let ctx = DrainTestContext::new("candidate-unresolved").await;
    let channel = ctx.create_closed_channel([72; 32], 450).await;
    let inner = ctx.net_for(&channel);
    let net = CandidateNet::new(&inner, Arc::clone(&ctx.mint), Outcome::Neither, Pause::None);
    let error = ctx
        .wallet_manager
        .drain_closed_channels_by_id_to_swap(
            "candidate-unresolved",
            std::slice::from_ref(&channel),
            &net,
        )
        .await
        .map(|_| ())
        .expect_err("drain must retain unresolved candidates");
    assert!(error.contains("budget exhausted"));
    assert_eq!(net.requests.lock().unwrap().len(), 4);
    let (id, history) = journal(&ctx);
    assert_candidates(&history);
    assert_eq!(history["attempts"][1]["submissions"], 2);
    assert!(history["winner"].is_null());
    for both_fail in [false, true] {
        let failure = FailedRestores {
            calls: AtomicUsize::new(0),
            both_fail,
        };
        assert!(ctx
            .wallet_manager
            .recover_submitted_drain(&id, &failure)
            .await
            .is_err());
        assert_eq!(failure.calls.load(Ordering::SeqCst), 2);
        assert!(
            journal(&ctx).1 == history,
            "restore failure changed retained journal"
        );
    }
    let reopened = ctx.wallet_manager.reopen().unwrap();
    let result = reopened.recover_submitted_drain(&id, &inner).await.unwrap();
    assert_eq!(journal(&ctx).1["winner"], 1);
    verify_and_spend(&ctx, &result).await;
    ctx.shutdown();
}

#[tokio::test(flavor = "multi_thread")]
async fn competing_drain_never_creates_a_third_candidate() {
    let ctx = DrainTestContext::new("candidate-limit").await;
    let channel = ctx.create_closed_channel([73; 32], 450).await;
    let inner = ctx.net_for(&channel);
    let net = CandidateNet::new(
        &inner,
        Arc::clone(&ctx.mint),
        Outcome::SuccessorRejected,
        Pause::None,
    );
    assert!(ctx
        .wallet_manager
        .drain_closed_channels_by_id_to_swap(
            "candidate-limit",
            std::slice::from_ref(&channel),
            &net
        )
        .await
        .map(|_| ())
        .expect_err("B rejection must stop without C")
        .contains("successor keyset rejected"));
    let (id, history) = journal(&ctx);
    assert_candidates(&history);
    assert_eq!(history["attempts"][1]["keyset_rejection"]["submission"], 1);
    assert_eq!(net.requests.lock().unwrap().len(), 3);
    let reopened = ctx.wallet_manager.reopen().unwrap();
    assert!(reopened
        .recover_submitted_drain(&id, &inner)
        .await
        .map(|_| ())
        .expect_err("recovery must not create C")
        .contains("successor keyset rejected"));
    assert_eq!(journal(&ctx).1["attempts"].as_array().unwrap().len(), 2);
    ctx.shutdown();
}

#[tokio::test(flavor = "multi_thread")]
async fn competing_drain_rejects_changed_inputs_and_invalid_winner_before_io() {
    let ctx = DrainTestContext::new("candidate-binding").await;
    let channel = ctx.create_closed_channel([74; 32], 450).await;
    let inner = ctx.net_for(&channel);
    let net = CandidateNet::new(&inner, Arc::clone(&ctx.mint), Outcome::Neither, Pause::None);
    assert!(ctx
        .wallet_manager
        .drain_closed_channels_by_id_to_swap(
            "candidate-binding",
            std::slice::from_ref(&channel),
            &net
        )
        .await
        .is_err());
    let (id, original) = journal(&ctx);
    let conn = rusqlite::Connection::open(ctx._temp_db.path()).unwrap();
    for change in 0..9 {
        let mut broken = original.clone();
        let request = &mut broken["attempts"][1]["prepared"]["swap_request_json"];
        let mut parsed: serde_json::Value =
            serde_json::from_str(request.as_str().unwrap()).unwrap();
        match change {
            0 => {
                parsed["inputs"].as_array_mut().unwrap().pop();
            }
            1 => {
                parsed["inputs"][0]["secret"] = serde_json::json!("different input identity");
            }
            2 => {
                let added = parsed["inputs"][0].clone();
                parsed["inputs"].as_array_mut().unwrap().push(added);
            }
            _ => {}
        }
        *request = serde_json::json!(parsed.to_string());
        match change {
            3 => broken["winner"] = serde_json::json!(0),
            4 => broken["attempts"][0]["keyset_rejection"]["submission"] = serde_json::json!(0),
            5 => broken["attempts"][0]["keyset_rejection"]["submission"] = serde_json::json!(3),
            6 => {
                let extra = broken["attempts"][1].clone();
                broken["attempts"].as_array_mut().unwrap().push(extra);
            }
            7 => broken["attempts"][1] = broken["attempts"][0].clone(),
            8 => broken["attempts"][1]["input_fees"] = serde_json::json!({"bad":999}),
            _ => {}
        }
        conn.execute(
            "UPDATE monad_relay_drain_journals SET journal_json=?1 WHERE drain_id=?2",
            params![broken.to_string(), id],
        )
        .unwrap();
        assert!(ctx
            .wallet_manager
            .recover_submitted_drain(&id, &Offline)
            .await
            .is_err());
        assert_eq!(
            conn.query_row(
                "SELECT COUNT(*) FROM monad_relay_drained_channels WHERE drain_id=?1",
                [&id],
                |r| r.get::<_, u64>(0)
            )
            .unwrap(),
            1
        );
    }
    conn.execute(
        "UPDATE monad_relay_drain_journals SET journal_json=?1 WHERE drain_id=?2",
        params![original.to_string(), id],
    )
    .unwrap();
    let keyset: String = conn
        .query_row(
            "SELECT output_keyset_id FROM monad_relay_drains WHERE drain_id=?1",
            [&id],
            |r| r.get(0),
        )
        .unwrap();
    conn.execute(
        "UPDATE monad_relay_drains SET output_keyset_id='wrong' WHERE drain_id=?1",
        [&id],
    )
    .unwrap();
    let failure = ctx
        .wallet_manager
        .recover_submitted_drain(&id, &Offline)
        .await
        .map(|_| ())
        .expect_err("mirror conflict must reject");
    assert!(failure.contains("metadata/journal conflict"));
    conn.execute(
        "UPDATE monad_relay_drains SET output_keyset_id=?2 WHERE drain_id=?1",
        params![id, keyset],
    )
    .unwrap();
    let result = ctx
        .wallet_manager
        .recover_submitted_drain(&id, &inner)
        .await
        .unwrap();
    verify_and_spend(&ctx, &result).await;
    ctx.shutdown();
}
