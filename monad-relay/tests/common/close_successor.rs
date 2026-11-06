//! Real mint commits and spends, with controlled transport outcomes/snapshots.
use super::*;
use cashu::nuts::{RestoreResponse, SpendingConditionVerification, SwapRequest};
use monad_relay::mint_recovery::RecoveryMintClient;

#[derive(Clone, Copy)]
enum Outcome {
    Original,
    SuccessorReplay,
    SuccessorLost,
    Neither,
    RejectSuccessor,
}

#[derive(Clone, Copy)]
enum Pause {
    None,
    BeforeSuccessor,
    AfterSuccessorCommit,
}

struct CandidateMint<'a> {
    inner: &'a RelayWalletMintClient,
    mint: Arc<cdk::Mint>,
    outcome: Outcome,
    pause: Pause,
    requests: Mutex<Vec<String>>,
    restores: Mutex<Vec<String>>,
    early_state: Mutex<Option<String>>,
    visible: std::sync::atomic::AtomicBool,
    accepted: AtomicUsize,
    states: AtomicUsize,
    entered: tokio::sync::Notify,
    // Exercise responses to A that carry B's signature IDs, and the converse.
    unavailable_original: bool,
}

impl<'a> CandidateMint<'a> {
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
            restores: Mutex::new(Vec::new()),
            early_state: Mutex::new(None),
            visible: std::sync::atomic::AtomicBool::new(false),
            accepted: AtomicUsize::new(0),
            states: AtomicUsize::new(0),
            entered: tokio::sync::Notify::new(),
            unavailable_original: false,
        }
    }

    async fn accept(&self, mint: &str, request: &str) -> anyhow::Result<String> {
        let response = self.inner.swap_checked(mint, request).await?;
        self.accepted.fetch_add(1, Ordering::SeqCst);
        Ok(response)
    }
}

#[async_trait::async_trait]
impl cdk_spilman::SpilmanAsyncMintClient for CandidateMint<'_> {
    async fn call_mint_swap(
        &self,
        _: &str,
        _: &str,
    ) -> Result<String, cdk_spilman::MintRequestError> {
        panic!("checked close transport required")
    }
}

#[async_trait::async_trait]
impl RecoveryMintClient for CandidateMint<'_> {
    async fn swap_checked(&self, mint: &str, request: &str) -> anyhow::Result<String> {
        let call = {
            let mut requests = self.requests.lock().unwrap();
            requests.push(request.to_string());
            requests.len()
        };
        match call {
            1 => anyhow::bail!("ambiguous A delivery"),
            2 => {
                let request_json: SwapRequest = serde_json::from_str(request)?;
                let ys = request_json
                    .inputs()
                    .iter()
                    .map(cashu::nuts::Proof::y)
                    .collect::<Result<Vec<_>, _>>()?;
                *self.early_state.lock().unwrap() = Some(
                    self.inner
                        .check_state(mint, &serde_json::json!({"Ys":ys}).to_string())
                        .await?,
                );
                if matches!(self.outcome, Outcome::Original) {
                    self.accept(mint, request).await?;
                }
                rotate_sat_keyset(&self.mint, 500).await?;
                Err(monad_common::mint_error::MintHttpRejection::from_body(
                    400,
                    r#"{"code":12002,"detail":"inactive output keyset"}"#,
                )
                .into())
            }
            3 => match self.outcome {
                Outcome::Original => {
                    let failure = self
                        .accept(mint, request)
                        .await
                        .map(|_| ())
                        .expect_err("only A may win");
                    assert!(failure
                        .downcast_ref::<monad_common::mint_error::MintHttpRejection>()
                        .is_some_and(|r| r.status == 400 && r.code == Some(11001)));
                    self.visible.store(true, Ordering::SeqCst);
                    Err(failure)
                }
                Outcome::SuccessorReplay | Outcome::Neither => {
                    anyhow::bail!("ambiguous B delivery")
                }
                Outcome::SuccessorLost => {
                    self.accept(mint, request).await?;
                    if matches!(self.pause, Pause::AfterSuccessorCommit) {
                        self.entered.notify_one();
                        std::future::pending::<()>().await;
                    }
                    self.visible.store(true, Ordering::SeqCst);
                    anyhow::bail!("lost B response")
                }
                Outcome::RejectSuccessor => {
                    rotate_sat_keyset(&self.mint, 700).await?;
                    self.visible.store(true, Ordering::SeqCst);
                    self.accept(mint, request).await
                }
            },
            4 => {
                assert!(matches!(
                    self.outcome,
                    Outcome::SuccessorReplay | Outcome::Neither
                ));
                self.visible.store(true, Ordering::SeqCst);
                if matches!(self.outcome, Outcome::Neither) {
                    anyhow::bail!("uncertain B replay");
                }
                self.accept(mint, request).await
            }
            _ => panic!("exceeded close candidate budgets"),
        }
    }

    async fn restore(&self, mint: &str, request: &str) -> anyhow::Result<String> {
        self.restores.lock().unwrap().push(request.to_string());
        let query: cashu::nuts::RestoreRequest = serde_json::from_str(request)?;
        let original: SwapRequest = serde_json::from_str(&self.requests.lock().unwrap()[0])?;
        if self.unavailable_original
            && query.outputs[0].keyset_id == original.outputs()[0].keyset_id
        {
            anyhow::bail!("A restore unavailable; B query may still restore A");
        }
        self.inner.restore(mint, request).await
    }

    async fn check_state(&self, mint: &str, request: &str) -> anyhow::Result<String> {
        let call = self.states.fetch_add(1, Ordering::SeqCst);
        if matches!(self.pause, Pause::BeforeSuccessor) && call == 3 {
            self.entered.notify_one();
            std::future::pending::<()>().await;
        }
        if !self.visible.load(Ordering::SeqCst) {
            if let Some(snapshot) = self.early_state.lock().unwrap().clone() {
                return Ok(snapshot);
            }
        }
        self.inner.check_state(mint, request).await
    }
}

struct Offline;
#[async_trait::async_trait]
impl cdk_spilman::SpilmanAsyncMintClient for Offline {
    async fn call_mint_swap(
        &self,
        _: &str,
        _: &str,
    ) -> Result<String, cdk_spilman::MintRequestError> {
        panic!("offline swap")
    }
}
#[async_trait::async_trait]
impl RecoveryMintClient for Offline {
    async fn swap_checked(&self, _: &str, _: &str) -> anyhow::Result<String> {
        panic!("offline swap")
    }
    async fn restore(&self, _: &str, _: &str) -> anyhow::Result<String> {
        panic!("offline restore")
    }
    async fn check_state(&self, _: &str, _: &str) -> anyhow::Result<String> {
        panic!("offline state")
    }
}

fn journal(ctx: &DrainTestContext, channel: &str) -> serde_json::Value {
    serde_json::from_str(
        &ctx.wallet_manager
            .spilman_storage()
            .get_close_journal(channel)
            .unwrap()
            .unwrap(),
    )
    .unwrap()
}

fn save_journal(
    ctx: &DrainTestContext,
    channel: &str,
    previous: &serde_json::Value,
    next: &serde_json::Value,
) {
    // Use the storage CAS rather than overwriting unrelated channel state.
    let stored = ctx
        .wallet_manager
        .spilman_storage()
        .get_close_journal(channel)
        .unwrap()
        .unwrap();
    assert!(serde_json::from_str::<serde_json::Value>(&stored).unwrap() == *previous);
    ctx.wallet_manager
        .spilman_storage()
        .advance_close(channel, &stored, &next.to_string(), None)
        .unwrap();
}

fn assert_candidates(history: &serde_json::Value) {
    assert_eq!(history["version"], 6);
    assert_eq!(history["attempts"].as_array().unwrap().len(), 2);
    assert_eq!(history["attempts"][0]["submissions"], 2);
    assert_eq!(history["attempts"][0]["keyset_rejection"]["submission"], 2);
    let a = &history["attempts"][0]["prepared"];
    let b = &history["attempts"][1]["prepared"];
    let ar: SwapRequest = serde_json::from_value(a["swap_request"].clone()).unwrap();
    let br: SwapRequest = serde_json::from_value(b["swap_request"].clone()).unwrap();
    assert!(ar.inputs() == br.inputs(), "funding or witness changed");
    assert!(
        ar.sig_all_message_hash() == br.sig_all_message_hash(),
        "SIG_ALL changed"
    );
    assert!(
        a["secrets_with_blinding"] == b["secrets_with_blinding"],
        "commitment secrets changed"
    );
    assert!(ar.outputs()[0].keyset_id != br.outputs()[0].keyset_id);
    assert!(ar
        .outputs()
        .iter()
        .zip(br.outputs())
        .all(|(a, b)| a.amount == b.amount && a.blinded_secret == b.blinded_secret));
}

async fn open(ctx: &DrainTestContext) -> String {
    create_paid_open_channel_with_expiry(
        &ctx.payments,
        &ctx.wallet,
        &ctx.offer,
        [80; 32],
        450,
        cashu::util::unix_time() + 86_400,
    )
    .await
}

#[tokio::test(flavor = "multi_thread")]
async fn competing_close_candidates_recover_both_winners_and_reuse_signatures() {
    for outcome in [
        Outcome::Original,
        Outcome::SuccessorReplay,
        Outcome::SuccessorLost,
    ] {
        for unavailable_original in [false, true] {
            let ctx = DrainTestContext::new("close-candidates").await;
            let channel = open(&ctx).await;
            let inner = ctx.net_for(&channel);
            let mut net = CandidateMint::new(&inner, ctx.mint.clone(), outcome, Pause::None);
            net.unavailable_original = unavailable_original;
            let result = ctx
                .wallet_manager
                .close_channel(&channel, &net)
                .await
                .unwrap()
                .into_closed()
                .unwrap();
            let saved = journal(&ctx, &channel);
            assert_candidates(&saved);
            let winner = if matches!(outcome, Outcome::Original) {
                0
            } else {
                1
            };
            assert_eq!(saved["winner"], winner);
            assert_eq!(saved["completed"], true);
            assert_eq!(net.accepted.load(Ordering::SeqCst), 1);
            assert_eq!(result.receiver_sum, 450);
            let requests = net.requests.lock().unwrap().clone();
            assert!(requests[0] == requests[1], "A replay changed");
            if matches!(outcome, Outcome::SuccessorReplay) {
                assert_eq!(requests.len(), 4);
                assert!(requests[2] == requests[3], "B replay changed");
            }
            if matches!(outcome, Outcome::SuccessorLost) && !unavailable_original {
                assert_eq!(
                    net.restores.lock().unwrap().len(),
                    1,
                    "A query must recover B"
                );
            }
            let reopened = ctx.wallet_manager.reopen().unwrap();
            let again = reopened
                .close_channel(&channel, &Offline)
                .await
                .unwrap()
                .into_closed()
                .unwrap();
            assert!(again.already_closed);
            assert_eq!(again.receiver_sum, result.receiver_sum);
            assert!(again.sender_proofs == result.sender_proofs);
            // Stage-2 receiver payout is really spendable, including inactive
            // historical A keys and fee-bearing B keys. The mint validates it.
            let drain = reopened
                .drain_closed_channels_by_id_to_swap(
                    "close-candidates",
                    std::slice::from_ref(&channel),
                    &inner,
                )
                .await
                .unwrap();
            assert_eq!(drain.input_amount_raw, result.receiver_sum);
            assert!(drain.output_amount_raw <= result.receiver_sum);
            assert_eq!(
                ctx.payments.channel_state(&channel).unwrap(),
                Some(ChannelState::Closed)
            );
            ctx.shutdown();
        }
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn competing_close_cancellation_reopens_before_b_submit_and_after_b_commit() {
    for (outcome, pause, winner) in [
        (Outcome::Original, Pause::BeforeSuccessor, 0),
        (Outcome::SuccessorLost, Pause::AfterSuccessorCommit, 1),
    ] {
        let ctx = DrainTestContext::new("close-cancel-candidates").await;
        let channel = open(&ctx).await;
        let inner = ctx.net_for(&channel);
        let net = CandidateMint::new(&inner, ctx.mint.clone(), outcome, pause);
        {
            let operation = ctx.wallet_manager.close_channel(&channel, &net);
            tokio::pin!(operation);
            tokio::select! {
                _ = net.entered.notified() => {},
                _ = tokio::time::sleep(Duration::from_secs(15)) => panic!("close boundary not reached"),
                _ = &mut operation => panic!("close ended before cancellation"),
            }
        }
        let saved = journal(&ctx, &channel);
        assert_candidates(&saved);
        assert!(saved["winner"].is_null());
        if winner == 0 {
            assert_eq!(saved["attempts"][1]["submissions"], 0);
        }
        assert_eq!(
            ctx.payments.channel_state(&channel).unwrap(),
            Some(ChannelState::Closing)
        );
        let reopened = ctx.wallet_manager.reopen().unwrap();
        let result = reopened
            .close_channel(&channel, &inner)
            .await
            .unwrap()
            .into_closed()
            .unwrap();
        assert_eq!(result.receiver_sum, 450);
        assert_eq!(journal(&ctx, &channel)["winner"], winner);
        ctx.shutdown();
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn competing_close_budgets_resume_and_b_rejection_never_creates_c() {
    for outcome in [Outcome::Neither, Outcome::RejectSuccessor] {
        let ctx = DrainTestContext::new("close-budgets").await;
        let channel = open(&ctx).await;
        let inner = ctx.net_for(&channel);
        let net = CandidateMint::new(&inner, ctx.mint.clone(), outcome, Pause::None);
        assert!(ctx
            .wallet_manager
            .close_channel(&channel, &net)
            .await
            .is_err());
        let saved = journal(&ctx, &channel);
        assert_candidates(&saved);
        assert!(saved["winner"].is_null());
        assert_eq!(
            ctx.payments.channel_state(&channel).unwrap(),
            Some(ChannelState::Closing)
        );
        let reopened = ctx.wallet_manager.reopen().unwrap();
        if matches!(outcome, Outcome::Neither) {
            assert_eq!(net.requests.lock().unwrap().len(), 4);
            assert_eq!(saved["attempts"][1]["submissions"], 2);
            assert!(reopened
                .close_channel(&channel, &inner)
                .await
                .unwrap()
                .into_closed()
                .is_ok());
            assert_eq!(journal(&ctx, &channel)["winner"], 1);
        } else {
            assert_eq!(saved["attempts"][1]["keyset_rejection"]["submission"], 1);
            assert!(reopened.close_channel(&channel, &inner).await.is_err());
            assert_eq!(
                journal(&ctx, &channel)["attempts"]
                    .as_array()
                    .unwrap()
                    .len(),
                2
            );
        }
        ctx.shutdown();
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn competing_close_rejects_mutated_requests_history_and_old_journals_before_io() {
    let ctx = DrainTestContext::new("close-bindings").await;
    let channel = open(&ctx).await;
    let inner = ctx.net_for(&channel);
    let net = CandidateMint::new(&inner, ctx.mint.clone(), Outcome::Neither, Pause::None);
    assert!(ctx
        .wallet_manager
        .close_channel(&channel, &net)
        .await
        .is_err());
    let original = journal(&ctx, &channel);
    for change in 0..10 {
        let mut broken = original.clone();
        match change {
            0 => broken["version"] = serde_json::json!(5),
            1 => broken["winner"] = serde_json::json!(1),
            2 => {
                broken["attempts"][1]["prepared"]["swap_request"]["inputs"][0]["secret"] =
                    serde_json::json!("changed")
            }
            3 => {
                broken["attempts"][1]["prepared"]["swap_request"]["outputs"][0]["amount"] =
                    serde_json::json!(1_000_000)
            }
            4 => broken["attempts"][0]["keyset_rejection"]["submission"] = serde_json::json!(0),
            5 => broken["attempts"][0]["keyset_rejection"]["submission"] = serde_json::json!(3),
            6 => {
                broken["attempts"][1]["prepared"]["swap_request"]["inputs"][0]["witness"] =
                    serde_json::Value::Null
            }
            7 => broken["attempts"] = serde_json::json!([]),
            8 => {
                let extra = broken["attempts"][1].clone();
                broken["attempts"].as_array_mut().unwrap().push(extra);
            }
            _ => broken["attempts"][1]["prepared"] = broken["attempts"][0]["prepared"].clone(),
        }
        save_journal(&ctx, &channel, &original, &broken);
        assert!(ctx
            .wallet_manager
            .close_channel(&channel, &Offline)
            .await
            .is_err());
        assert!(
            journal(&ctx, &channel) == broken,
            "invalid journal was rewritten"
        );
        assert_eq!(
            ctx.payments.channel_state(&channel).unwrap(),
            Some(ChannelState::Closing)
        );
        save_journal(&ctx, &channel, &broken, &original);
    }
    ctx.wallet_manager
        .close_channel(&channel, &inner)
        .await
        .unwrap()
        .into_closed()
        .unwrap();
    let completed = journal(&ctx, &channel);
    for change in 0..6 {
        let mut broken = completed.clone();
        match change {
            0 => broken["winner"] = serde_json::json!(0),
            1 => broken["finalizing"]["receiver_sum"] = serde_json::json!(1),
            2 => broken["finalizing"]["sender_proofs_json"] = serde_json::json!("[]"),
            3 => broken["attempts"][1]["submissions"] = serde_json::json!(0),
            4 => {
                let mut proofs: Vec<cashu::nuts::Proof> = serde_json::from_str(
                    broken["finalizing"]["receiver_proofs_json"]
                        .as_str()
                        .unwrap(),
                )
                .unwrap();
                proofs[0].witness = None;
                broken["finalizing"]["receiver_proofs_json"] =
                    serde_json::json!(serde_json::to_string(&proofs).unwrap());
            }
            _ => broken["collection_abandoned"] = serde_json::json!(true),
        }
        // Completed rows are immutable through the production CAS. Corrupt the
        // owned test fixture directly to verify offline read validation.
        let conn = rusqlite::Connection::open(ctx._temp_db.path()).unwrap();
        conn.execute(
            "UPDATE spilman_close_journals SET journal=?1 WHERE channel_id=?2",
            rusqlite::params![broken.to_string(), channel],
        )
        .unwrap();
        let failure = ctx
            .wallet_manager
            .close_channel(&channel, &Offline)
            .await
            .map(|_| ())
            .expect_err("corrupt completion must reject");
        if change == 3 {
            assert!(failure.to_string().contains("unsubmitted close winner"));
        }
        if change == 4 {
            assert!(failure.to_string().contains("proof/winner conflict"));
        }
        conn.execute(
            "UPDATE spilman_close_journals SET journal=?1 WHERE channel_id=?2",
            rusqlite::params![completed.to_string(), channel],
        )
        .unwrap();
    }
    ctx.shutdown();
}

// Response corruption is applied only after a real B commitment. None of these
// payloads may finalize a channel or authorize another submission.
struct BadRestore<'a> {
    inner: &'a RelayWalletMintClient,
    change: usize,
    calls: AtomicUsize,
}
#[async_trait::async_trait]
impl cdk_spilman::SpilmanAsyncMintClient for BadRestore<'_> {
    async fn call_mint_swap(
        &self,
        _: &str,
        _: &str,
    ) -> Result<String, cdk_spilman::MintRequestError> {
        panic!("unexpected swap")
    }
}
#[async_trait::async_trait]
impl RecoveryMintClient for BadRestore<'_> {
    async fn swap_checked(&self, _: &str, _: &str) -> anyhow::Result<String> {
        panic!("spent inputs must not replay")
    }
    async fn check_state(&self, mint: &str, request: &str) -> anyhow::Result<String> {
        self.inner.check_state(mint, request).await
    }
    async fn restore(&self, mint: &str, request: &str) -> anyhow::Result<String> {
        let call = self.calls.fetch_add(1, Ordering::SeqCst);
        if self.change >= 4 {
            if call == 0 || self.change == 5 {
                anyhow::bail!("restore unavailable");
            }
            return Ok(r#"{"outputs":[],"signatures":[]}"#.to_string());
        }
        let response = self.inner.restore(mint, request).await?;
        let mut parsed: RestoreResponse = serde_json::from_str(&response)?;
        assert!(parsed.outputs.len() > 1);
        match self.change {
            0 => {
                parsed.outputs.pop();
                parsed.signatures.pop();
            }
            1 => {
                parsed.outputs[1] = parsed.outputs[0].clone();
                parsed.signatures[1] = parsed.signatures[0].clone();
            }
            2 => {
                parsed.signatures[0].keyset_id = "001234567890abcd".parse().unwrap();
            }
            _ => {
                parsed.signatures[0].dleq = None;
            }
        }
        Ok(serde_json::to_string(&parsed)?)
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn competing_close_incomplete_mixed_duplicate_or_unverified_restore_stays_closing() {
    let ctx = DrainTestContext::new("close-restore-binding").await;
    let channel = open(&ctx).await;
    let inner = ctx.net_for(&channel);
    let net = CandidateMint::new(
        &inner,
        ctx.mint.clone(),
        Outcome::SuccessorLost,
        Pause::AfterSuccessorCommit,
    );
    {
        let operation = ctx.wallet_manager.close_channel(&channel, &net);
        tokio::pin!(operation);
        tokio::select! {
            _ = net.entered.notified() => {},
            _ = tokio::time::sleep(Duration::from_secs(15)) => panic!("commit not reached"),
            _ = &mut operation => panic!("completed before cancellation"),
        }
    }
    let saved = journal(&ctx, &channel);
    for change in 0..6 {
        let bad = BadRestore {
            inner: &inner,
            change,
            calls: AtomicUsize::new(0),
        };
        assert!(ctx
            .wallet_manager
            .close_channel(&channel, &bad)
            .await
            .is_err());
        assert_eq!(bad.calls.load(Ordering::SeqCst), 2);
        assert!(
            journal(&ctx, &channel) == saved,
            "invalid restore mutated recovery state"
        );
        assert_eq!(
            ctx.payments.channel_state(&channel).unwrap(),
            Some(ChannelState::Closing)
        );
    }
    ctx.wallet_manager
        .close_channel(&channel, &inner)
        .await
        .unwrap()
        .into_closed()
        .unwrap();
    assert_eq!(journal(&ctx, &channel)["winner"], 1);
    ctx.shutdown();
}
