use super::*;
use crate::mint_recovery::RecoveryMintClient;
use cashu::nuts::{Proof, RestoreResponse, SpendingConditionVerification, SwapRequest};
use cdk_spilman::{ChannelRecovery, CompletedClose, EstablishedChannel, FundingState};
use monad_common::mint_error::MintHttpRejection;
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::sync::{Mutex, OnceLock};

// Secret-bearing payloads intentionally have no Debug implementation.
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct CloseJournal {
    version: u32,
    binding: String,
    receiver: String,
    funding: ChannelFunding,
    payment: PaymentProof,
    attempts: Vec<CloseAttempt>,
    finalizing: Option<CompletedClose>,
    winner: Option<usize>,
    completed: bool,
    collection_abandoned: bool,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct CloseAttempt {
    prepared: PreparedClose,
    submissions: u64,
    keyset_rejection: Option<ExecutionRejection>,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ExecutionRejection {
    submission: u64,
    evidence: MintHttpRejection,
}

// A successor changes mint keyset IDs only. SIG_ALL does not cover those IDs;
// retain both Alice's and Charlie's witnesses byte-for-byte, not fresh signatures.
fn close_successor(
    original: &PreparedClose,
    selected: SelectedOutputKeyset,
) -> Result<PreparedClose, CloseError> {
    let keys = cdk_spilman::parse_keyset_info_from_json(&selected.info_json).map_err(error)?;
    if keys.keyset_id.to_string() != selected.id
        || original.output_keyset_info["keysetId"].as_str() == Some(selected.id.as_str())
    {
        return Err(error("close output keyset unchanged or inconsistent"));
    }
    let mut successor = original.clone();
    successor.output_keyset_info = serde_json::from_str(&selected.info_json)
        .map_err(|_| error("invalid close output keys"))?;
    let outputs = successor.swap_request["outputs"]
        .as_array_mut()
        .ok_or_else(|| error("missing close outputs"))?;
    for output in outputs {
        output["id"] = serde_json::Value::String(selected.id.clone());
    }
    Ok(successor)
}

fn verify_successor(a: &PreparedClose, b: &PreparedClose) -> Result<(), CloseError> {
    let ar: SwapRequest = serde_json::from_value(a.swap_request.clone())
        .map_err(|_| error("invalid original close request"))?;
    let br: SwapRequest = serde_json::from_value(b.swap_request.clone())
        .map_err(|_| error("invalid successor close request"))?;
    // Comparing a normalized copy also binds every other preparation field,
    // including frozen payment, secrets, funding metadata and authorization.
    let mut normalized = b.clone();
    normalized.output_keyset_info = a.output_keyset_info.clone();
    let outputs = normalized.swap_request["outputs"]
        .as_array_mut()
        .ok_or_else(|| error("missing close successor outputs"))?;
    for output in outputs {
        output["id"] = a.output_keyset_info["keysetId"].clone();
    }
    if ar.sig_all_msg_to_sign() != br.sig_all_msg_to_sign()
        || ar.inputs() != br.inputs()
        || serde_json::to_value(a).map_err(|_| error("close encoding"))?
            != serde_json::to_value(normalized).map_err(|_| error("close encoding"))?
    {
        return Err(error("close successor differs beyond output keyset"));
    }
    Ok(())
}

// Recheck retained finalizing payloads offline against the actual winner. The
// preparations have already been authenticated by the upstream bridge.
fn verify_payout(
    journal: &CloseJournal,
    winner: usize,
    payout: &CompletedClose,
    expiry: u64,
) -> Result<(), CloseError> {
    let prepared = &journal
        .attempts
        .get(winner)
        .ok_or_else(|| error("invalid close winner"))?
        .prepared;
    let keys = cdk_spilman::parse_keyset_info_from_json(&prepared.output_keyset_info.to_string())
        .map_err(error)?;
    let slots = prepared
        .secrets_with_blinding
        .as_array()
        .ok_or_else(|| error("invalid close output secrets"))?;
    if payout.channel_id != prepared.channel_id
        || payout.balance != journal.payment.balance
        || payout.expiry_timestamp != expiry
    {
        return Err(error("close finalization binding mismatch"));
    }
    let mut count = 0;
    for (receiver, json, sum) in [
        (true, &payout.receiver_proofs_json, payout.receiver_sum),
        (false, &payout.sender_proofs_json, payout.sender_sum),
    ] {
        let proofs: Vec<Proof> =
            serde_json::from_str(json).map_err(|_| error("invalid close finalization proofs"))?;
        let expected = slots
            .iter()
            .filter(|s| s["is_receiver"].as_bool() == Some(receiver))
            .collect::<Vec<_>>();
        let total = proofs
            .iter()
            .try_fold(0u64, |n, p| n.checked_add(u64::from(p.amount)));
        if proofs.len() != expected.len()
            || total != Some(sum)
            || proofs.iter().zip(expected).any(|(proof, slot)| {
                proof.keyset_id != keys.keyset_id
                    || Some(u64::from(proof.amount)) != slot["amount"].as_u64()
                    || Some(proof.secret.to_string().as_str()) != slot["secret"].as_str()
                    || !proof.dleq.as_ref().is_some_and(|d| {
                        Some(d.r.to_secret_hex().as_str()) == slot["blinding_factor"].as_str()
                    })
                    || keys
                        .active_keys
                        .amount_key(proof.amount)
                        .is_none_or(|key| proof.verify_dleq(key).is_err())
            })
        {
            return Err(error("close finalization proof/winner conflict"));
        }
        count += proofs.len();
    }
    if count == 0 {
        return Err(error("empty close payout"));
    }
    Ok(())
}

static ACTIVE: OnceLock<Mutex<HashSet<String>>> = OnceLock::new();
struct CloseFlight(String);
fn error(reason: impl Into<String>) -> CloseError {
    CloseError::storage_failed(reason)
}
impl Drop for CloseFlight {
    fn drop(&mut self) {
        if let Ok(mut active) = ACTIVE.get_or_init(Default::default).lock() {
            active.remove(&self.0);
        }
    }
}

impl SpilmanRelayPayments {
    pub(crate) fn collection_abandoned(json: &str) -> Result<bool, String> {
        Self::validate_close_schema(json)?;
        let journal: CloseJournal =
            serde_json::from_str(json).map_err(|_| "invalid close journal")?;
        Ok(journal.collection_abandoned && journal.finalizing.is_none() && !journal.completed)
    }
    pub(crate) fn validate_close_schema(json: &str) -> Result<(), String> {
        let journal: CloseJournal = serde_json::from_str(json)
            .map_err(|_| "incompatible close journal; database retained")?;
        if journal.version != 5 || journal.attempts.is_empty() || journal.attempts.len() > 2 {
            return Err("incompatible close journal version; database retained".to_string());
        }
        Ok(())
    }

    pub(super) async fn recover_close<M: RecoveryMintClient, R: SpilmanAsyncKeysetRefresher>(
        &self,
        channel_id: &str,
        mint: &M,
        refresh: &R,
    ) -> Result<CloseOutcome, CloseError> {
        let binding = self.store.journal_binding().map_err(error)?;
        let flight_key = format!(
            "{binding}:{}:{channel_id}",
            self.receiver_secret.public_key()
        );
        if !ACTIVE
            .get_or_init(Default::default)
            .lock()
            .map_err(|_| error("close singleflight poisoned"))?
            .insert(flight_key.clone())
        {
            return Err(error("close operation already active"));
        }
        let _flight = CloseFlight(flight_key);
        let storage = self.store.storage();
        let existing = storage.get_close_journal(channel_id).map_err(error)?;
        let mut journal = match existing.as_ref() {
            Some(json) => serde_json::from_str::<CloseJournal>(json)
                .map_err(|_| error("incompatible or corrupt close journal; database retained"))?,
            None => {
                if storage.get_state(channel_id).map_err(error)? != Some(ChannelState::Open) {
                    return Err(error(
                        "non-open channel lacks exact close journal; database retained",
                    ));
                }
                self.ensure_close_keysets_cached_async(channel_id, refresh)
                    .await?;
                let transition = self
                    .bridge
                    .prepare_unilateral_close_transition(channel_id)
                    .map_err(CloseError::from_preparation_error)?;
                let funding = storage
                    .get_funding(channel_id)
                    .ok_or_else(CloseError::unknown_channel)?;
                self.bridge.verify_prepared_close(
                    &transition.prepared_close,
                    &funding,
                    &transition.payment,
                    &self.receiver_secret.public_key(),
                )?;
                let journal = CloseJournal {
                    version: 5,
                    binding: binding.clone(),
                    receiver: self.receiver_secret.public_key().to_hex(),
                    funding,
                    payment: transition.payment.clone(),
                    attempts: vec![CloseAttempt {
                        prepared: transition.prepared_close,
                        submissions: 0,
                        keyset_rejection: None,
                    }],
                    finalizing: None,
                    winner: None,
                    completed: false,
                    collection_abandoned: false,
                };
                let json = serde_json::to_string(&journal)
                    .map_err(|_| error("serialize close journal"))?;
                storage
                    .freeze_close(
                        channel_id,
                        &transition.payment,
                        ClosingData {
                            expiry_timestamp: transition.expiry_timestamp,
                            balance: transition.payment.balance,
                            signature: transition.payment.signature.clone(),
                        },
                        &json,
                    )
                    .map_err(error)?;
                #[cfg(feature = "funds-lifecycle-test")]
                crate::lifecycle_test::boundary("close-prepared");
                journal
            }
        };
        if journal.version != 5
            || journal.binding != binding
            || journal.receiver != self.receiver_secret.public_key().to_hex()
            || journal.attempts.is_empty()
            || journal.attempts.len() > 2
        {
            return Err(error("close journal identity or version mismatch"));
        }
        let funding = storage
            .get_funding(channel_id)
            .ok_or_else(CloseError::unknown_channel)?;
        if serde_json::to_value(&funding).map_err(|_| error("funding encoding"))?
            != serde_json::to_value(&journal.funding)
                .map_err(|_| error("journal funding encoding"))?
        {
            return Err(error("close journal funding mismatch"));
        }
        for (index, attempt) in journal.attempts.iter().enumerate() {
            if attempt.prepared.channel_id != channel_id
                || attempt.keyset_rejection.as_ref().is_some_and(|rejection| {
                    !rejection.evidence.inactive_output_keyset()
                        || rejection.submission == 0
                        || rejection.submission > attempt.submissions
                })
                || (index == 0 && journal.attempts.len() == 2 && attempt.keyset_rejection.is_none())
                || (index == 1
                    && attempt.prepared.output_keyset_info["keysetId"]
                        == journal.attempts[0].prepared.output_keyset_info["keysetId"])
            {
                return Err(error("invalid close execution history"));
            }
            self.bridge.verify_prepared_close(
                &attempt.prepared,
                &journal.funding,
                &journal.payment,
                &self.receiver_secret.public_key(),
            )?;
        }
        if journal.attempts.len() == 2 {
            verify_successor(&journal.attempts[0].prepared, &journal.attempts[1].prepared)?;
        }
        if journal.finalizing.is_some() != journal.winner.is_some()
            || (journal.completed && journal.finalizing.is_none())
            || (journal.collection_abandoned && journal.finalizing.is_some())
        {
            return Err(error("close winner/finalization mismatch"));
        }
        let secret: [u8; 32] = hex::decode(&journal.funding.channel_secret_hex)
            .map_err(|_| error("invalid channel secret"))?
            .try_into()
            .map_err(|_| error("invalid channel secret length"))?;
        let params = cdk_spilman::ChannelParameters::from_json_with_channel_secret(
            &journal.funding.params_json,
            cdk_spilman::parse_keyset_info_from_json(&journal.funding.keyset_info_json)
                .map_err(error)?,
            secret,
        )
        .map_err(|_| error("invalid funding parameters"))?;
        let channel = cdk_spilman::EstablishedChannel::new(
            params,
            serde_json::from_str(&journal.funding.funding_proofs_json)
                .map_err(|_| error("invalid funding proofs"))?,
        )
        .map_err(|_| error("invalid funding"))?;
        if !journal.completed {
            let closing = storage
                .get_closing_data(channel_id)
                .ok_or_else(|| error("close journal lacks frozen channel"))?;
            if closing.balance != journal.payment.balance
                || closing.signature != journal.payment.signature
            {
                return Err(error("close journal differs from frozen payment"));
            }
        }
        let mut durable =
            serde_json::to_string(&journal).map_err(|_| error("serialize close journal"))?;
        // Compare the original bytes, even when deserialization canonicalizes JSON.
        if let Some(original) = existing {
            durable = original;
        }
        let mut sent = [0_u8; 2];
        loop {
            if let Some(completed) = journal.finalizing.as_ref() {
                verify_payout(
                    &journal,
                    journal
                        .winner
                        .ok_or_else(|| error("missing close winner"))?,
                    completed,
                    channel.params.expiry_timestamp,
                )?;
                let total = completed
                    .receiver_sum
                    .checked_add(completed.sender_sum)
                    .ok_or_else(|| error("close payout overflow"))?;
                if completed.channel_id != channel_id
                    || completed.balance != journal.payment.balance
                {
                    return Err(error("close finalization binding mismatch"));
                }
                let result = CloseSuccess {
                    channel_id: channel_id.to_string(),
                    total_value: total,
                    receiver_sum: completed.receiver_sum,
                    sender_sum: completed.sender_sum,
                    sender_proofs: completed.sender_proofs_json.clone(),
                    already_closed: journal.completed,
                };
                let payout = ClosedDataView {
                    expiry_timestamp: completed.expiry_timestamp,
                    closed_amount: completed.balance,
                    value_after_stage1: total,
                    receiver_proofs_json: completed.receiver_proofs_json.clone(),
                    sender_proofs_json: completed.sender_proofs_json.clone(),
                    receiver_sum: completed.receiver_sum,
                    sender_sum: completed.sender_sum,
                };
                if journal.completed {
                    let stored = storage
                        .get_closed_data(channel_id)
                        .ok_or_else(|| error("completed journal lacks closed payout"))?;
                    if serde_json::to_value(&stored).map_err(|_| error("stored payout encoding"))?
                        != serde_json::to_value(&payout)
                            .map_err(|_| error("journal payout encoding"))?
                    {
                        return Err(error("completed journal payout conflict"));
                    }
                    return Ok(CloseOutcome::Closed(result));
                }
                journal.completed = true;
                let next = serde_json::to_string(&journal)
                    .map_err(|_| error("serialize close completion"))?;
                storage
                    .advance_close(channel_id, &durable, &next, Some(payout))
                    .map_err(error)?;
                #[cfg(feature = "funds-lifecycle-test")]
                crate::lifecycle_test::boundary("close-completed");
                return Ok(CloseOutcome::Closed(result));
            }
            if journal.completed {
                return Err(error("completed close journal lacks payout"));
            }
            let last = journal.attempts.len() - 1;
            let connection = crate::mint_recovery::ChannelMint {
                client: mint,
                mint: &channel.params.mint,
            };
            match self
                .inspect_close_candidates(&journal, &channel, &connection, mint)
                .await?
            {
                ChannelRecovery::Recovered {
                    payout: (winner, payout),
                    ..
                } => {
                    verify_payout(&journal, winner, &payout, channel.params.expiry_timestamp)?;
                    journal.winner = Some(winner);
                    journal.finalizing = Some(payout);
                    journal.collection_abandoned = false;
                    let next = serde_json::to_string(&journal)
                        .map_err(|_| error("serialize close finalization"))?;
                    storage
                        .advance_close(channel_id, &durable, &next, None)
                        .map_err(error)?;
                    durable = next;
                    #[cfg(feature = "funds-lifecycle-test")]
                    crate::lifecycle_test::boundary("close-finalizing");
                    continue;
                }
                ChannelRecovery::Unspent(_) if !journal.collection_abandoned => {}
                ChannelRecovery::Unspent(_) => {
                    return Err(error(
                        "abandoned channel reported unspent; journal retained",
                    ))
                }
                ChannelRecovery::Pending(_) => {
                    return Err(error("close funding pending; journal retained"))
                }
                ChannelRecovery::Mixed(_) | ChannelRecovery::SpentNoKnownPayout(_) => {
                    let now = std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .map_err(|_| error("system clock before epoch"))?
                        .as_secs();
                    if now > channel.params.expiry_timestamp {
                        journal.collection_abandoned = true;
                        let next = serde_json::to_string(&journal)
                            .map_err(|_| error("serialize collection abandonment"))?;
                        storage
                            .advance_close(channel_id, &durable, &next, None)
                            .map_err(error)?;
                        return Ok(CloseOutcome::CollectionAbandoned {
                            channel_id: channel_id.to_string(),
                        });
                    }
                    return Ok(CloseOutcome::UnknownSpent {
                        channel_id: channel_id.to_string(),
                    });
                }
            }
            let prepared = &journal.attempts[last].prepared;
            // Expiry enables the sender's competing refund branch; it does not
            // invalidate this receiver-authorized close. The mint arbitrates
            // the spend atomically, including after expiry.
            if journal.attempts[last].keyset_rejection.is_some() {
                if last == 1 {
                    return Err(error(
                        "close successor keyset rejected; both candidates retained",
                    ));
                }
                refresh
                    .refresh(&prepared.mint_url)
                    .await
                    .map_err(|_| error("close refresh failed; rejected request retained"))?;
                let selected = self.select_close_output_keyset(channel_id)?;
                let successor = close_successor(prepared, selected)?;
                if successor.output_keyset_info["keysetId"]
                    == prepared.output_keyset_info["keysetId"]
                {
                    return Err(error("close output keyset unchanged"));
                }
                self.bridge.verify_prepared_close(
                    &successor,
                    &journal.funding,
                    &journal.payment,
                    &self.receiver_secret.public_key(),
                )?;
                verify_successor(prepared, &successor)?;
                journal.attempts.push(CloseAttempt {
                    prepared: successor,
                    submissions: 0,
                    keyset_rejection: None,
                });
                let next = serde_json::to_string(&journal)
                    .map_err(|_| error("serialize close successor"))?;
                storage
                    .advance_close(channel_id, &durable, &next, None)
                    .map_err(error)?;
                durable = next;
                #[cfg(feature = "funds-lifecycle-test")]
                crate::lifecycle_test::boundary("close-successor");
                continue;
            }
            if sent[last] >= 2 {
                return Err(error("close replay budget exhausted; outcome unresolved"));
            }
            journal.attempts[last].submissions = journal.attempts[last]
                .submissions
                .checked_add(1)
                .ok_or_else(|| error("close execution counter overflow"))?;
            let next =
                serde_json::to_string(&journal).map_err(|_| error("serialize close execution"))?;
            storage
                .advance_close(channel_id, &durable, &next, None)
                .map_err(error)?;
            durable = next;
            sent[last] += 1;
            #[cfg(feature = "funds-lifecycle-test")]
            crate::lifecycle_test::boundary("close-submitting");
            let prepared = &journal.attempts[last].prepared;
            match mint
                .swap_checked(&prepared.mint_url, &prepared.swap_request.to_string())
                .await
            {
                Ok(response) => {
                    let payout = self.bridge.complete_prepared_close(&response, prepared)?;
                    verify_payout(&journal, last, &payout, channel.params.expiry_timestamp)?;
                    journal.winner = Some(last);
                    journal.finalizing = Some(payout);
                    let next = serde_json::to_string(&journal)
                        .map_err(|_| error("serialize close finalization"))?;
                    storage
                        .advance_close(channel_id, &durable, &next, None)
                        .map_err(error)?;
                    durable = next;
                    #[cfg(feature = "funds-lifecycle-test")]
                    crate::lifecycle_test::boundary("close-finalizing");
                }
                Err(failure) => {
                    if let Some(rejection) = failure
                        .downcast_ref::<MintHttpRejection>()
                        .filter(|rejection| rejection.inactive_output_keyset())
                    {
                        journal.attempts[last].keyset_rejection = Some(ExecutionRejection {
                            submission: journal.attempts[last].submissions,
                            evidence: *rejection,
                        });
                        let next = serde_json::to_string(&journal)
                            .map_err(|_| error("serialize close rejection"))?;
                        storage
                            .advance_close(channel_id, &durable, &next, None)
                            .map_err(error)?;
                        durable = next;
                        #[cfg(feature = "funds-lifecycle-test")]
                        crate::lifecycle_test::boundary("close-rejected");
                    }
                }
            }
        }
    }

    // Keep NUT-07-first reconciliation, but route each NUT-09 response against
    // all retained candidates: querying A's points can return B's issuance.
    async fn inspect_close_candidates<M: RecoveryMintClient>(
        &self,
        journal: &CloseJournal,
        channel: &EstablishedChannel,
        connection: &crate::mint_recovery::ChannelMint<'_, M>,
        mint: &M,
    ) -> Result<ChannelRecovery<(usize, CompletedClose)>, CloseError> {
        let funding = channel
            .inspect_funding(connection)
            .await
            .map_err(|_| error("close funding inspection failed; journal retained"))?;
        match funding.state() {
            FundingState::Unspent => return Ok(ChannelRecovery::Unspent(funding)),
            FundingState::Pending => return Ok(ChannelRecovery::Pending(funding)),
            FundingState::Mixed => return Ok(ChannelRecovery::Mixed(funding)),
            FundingState::Spent => {}
        }
        let mut invalid = false;
        for query in &journal.attempts {
            let response = mint
                .restore(
                    &channel.params.mint,
                    &serde_json::json!({"outputs": query.prepared.swap_request["outputs"]})
                        .to_string(),
                )
                .await;
            let Ok(response) = response else {
                invalid = true;
                continue;
            };
            let Ok(mut restored) = serde_json::from_str::<RestoreResponse>(&response) else {
                invalid = true;
                continue;
            };
            if restored.outputs.len() != restored.signatures.len() {
                invalid = true;
                continue;
            }
            // NUT-09 looks up blinded points. CDK echoes the queried output ID,
            // which can be A's even when the issued signature belongs to B.
            // Route by signature ID; upstream still checks every amount/point,
            // the exact complete signature set, and DLEQ against retained keys.
            for (output, signature) in restored.outputs.iter_mut().zip(&restored.signatures) {
                output.keyset_id = signature.keyset_id;
            }
            let response =
                serde_json::to_string(&restored).map_err(|_| error("encode close restore"))?;
            // Even a response fetched with A may belong to B. Upstream completion
            // validates the complete output identities, signatures and split.
            let mut matched_empty = false;
            for (winner, candidate) in journal.attempts.iter().enumerate() {
                match self
                    .bridge
                    .complete_prepared_close_restore(&response, &candidate.prepared)
                {
                    Ok(Some(payout)) => {
                        return Ok(ChannelRecovery::Recovered {
                            funding,
                            payout: (winner, payout),
                        })
                    }
                    Ok(None) => matched_empty = true,
                    Err(_) => {}
                }
            }
            invalid |= !matched_empty;
        }
        if invalid {
            return Err(error(
                "close restore unavailable or invalid; journal retained",
            ));
        }
        Ok(ChannelRecovery::SpentNoKnownPayout(funding))
    }
}
