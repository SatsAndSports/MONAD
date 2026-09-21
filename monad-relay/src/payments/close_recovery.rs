use super::*;
use crate::mint_recovery::RecoveryMintClient;
use cashu::nuts::{CheckStateResponse, Proof, State, SwapRequest};
use cdk_spilman::CompletedClose;
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
    completed: bool,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct CloseAttempt {
    prepared: PreparedClose,
    submissions: u64,
    initial_rejection: Option<MintHttpRejection>,
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
    pub(super) async fn recover_close<M: RecoveryMintClient, R: SpilmanAsyncKeysetRefresher>(
        &self,
        channel_id: &str,
        mint: &M,
        refresh: &R,
    ) -> Result<CloseSuccess, CloseError> {
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
        let resumed = existing.is_some();
        let mut journal = match existing.as_ref() {
            Some(json) => serde_json::from_str::<CloseJournal>(json)
                .map_err(|_| error("incompatible or corrupt close journal; database retained"))?,
            None => {
                if storage.get_state(channel_id) != ChannelState::Open {
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
                    version: 1,
                    binding: binding.clone(),
                    receiver: self.receiver_secret.public_key().to_hex(),
                    funding,
                    payment: transition.payment.clone(),
                    attempts: vec![CloseAttempt {
                        prepared: transition.prepared_close,
                        submissions: 0,
                        initial_rejection: None,
                    }],
                    finalizing: None,
                    completed: false,
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
        if journal.version != 1
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
                || attempt.initial_rejection.is_some_and(|rejection| {
                    !rejection.inactive_output_keyset() || attempt.submissions != 1 || index != 0
                })
                || (index == 0
                    && journal.attempts.len() == 2
                    && attempt.initial_rejection.is_none())
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
        let mut sent = 0;
        let mut need_restore = resumed;
        loop {
            if let Some(completed) = journal.finalizing.as_ref() {
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
                    return Ok(result);
                }
                journal.completed = true;
                let next = serde_json::to_string(&journal)
                    .map_err(|_| error("serialize close completion"))?;
                storage
                    .advance_close(channel_id, &durable, &next, Some(payout))
                    .map_err(error)?;
                #[cfg(feature = "funds-lifecycle-test")]
                crate::lifecycle_test::boundary("close-completed");
                return Ok(result);
            }
            if journal.completed {
                return Err(error("completed close journal lacks payout"));
            }
            let last = journal.attempts.len() - 1;
            if need_restore || journal.attempts[last].submissions > 0 {
                // Every historical request is checked before any new I/O capable
                // of spending inputs, refreshing output keys, or applying expiry.
                let mut invalid_restore = false;
                for attempt in &journal.attempts {
                    let prepared = &attempt.prepared;
                    let response = mint
                        .restore(
                            &prepared.mint_url,
                            &serde_json::json!({"outputs": prepared.swap_request["outputs"]})
                                .to_string(),
                        )
                        .await
                        .map_err(|_| error("close restore failed; reservation retained"))?;
                    match self
                        .bridge
                        .complete_prepared_close_restore(&response, prepared)
                    {
                        Ok(Some(completed)) => {
                            journal.finalizing = Some(completed);
                            break;
                        }
                        Ok(None) => {}
                        Err(_) => invalid_restore = true,
                    }
                }
                if journal.finalizing.is_some() {
                    let next = serde_json::to_string(&journal)
                        .map_err(|_| error("serialize close finalization"))?;
                    storage
                        .advance_close(channel_id, &durable, &next, None)
                        .map_err(error)?;
                    durable = next;
                    continue;
                }
                // Deterministic predecessor/successor outputs may share blinded
                // points. A response for a different keyset can only be accepted
                // by authenticating another saved attempt, never as absence.
                if invalid_restore {
                    return Err(error("invalid close restore; outcome unresolved"));
                }
                let prepared = &journal.attempts[last].prepared;
                let request: SwapRequest = serde_json::from_value(prepared.swap_request.clone())
                    .map_err(|_| error("invalid close request"))?;
                let ys = request
                    .inputs()
                    .iter()
                    .map(Proof::y)
                    .collect::<Result<Vec<_>, _>>()
                    .map_err(|_| error("invalid close inputs"))?;
                let response = mint
                    .check_state(
                        &prepared.mint_url,
                        &serde_json::json!({"Ys": ys}).to_string(),
                    )
                    .await
                    .map_err(|_| error("close input state unavailable; reservation retained"))?;
                let response: CheckStateResponse = serde_json::from_str(&response)
                    .map_err(|_| error("invalid close input state"))?;
                if response.states.len() != ys.len()
                    || ys.iter().any(|y| {
                        response
                            .states
                            .iter()
                            .filter(|state| state.y == *y && state.state == State::Unspent)
                            .count()
                            != 1
                    })
                {
                    // A sender refund may have won. A spent observation is not
                    // proof of that outcome and never becomes a zero-value close.
                    let response = mint
                        .restore(
                            &prepared.mint_url,
                            &serde_json::json!({"outputs": prepared.swap_request["outputs"]})
                                .to_string(),
                        )
                        .await
                        .map_err(|_| error("final close restore failed; reservation retained"))?;
                    if let Some(completed) = self
                        .bridge
                        .complete_prepared_close_restore(&response, prepared)?
                    {
                        journal.finalizing = Some(completed);
                        let next = serde_json::to_string(&journal)
                            .map_err(|_| error("serialize close finalization"))?;
                        storage
                            .advance_close(channel_id, &durable, &next, None)
                            .map_err(error)?;
                        durable = next;
                        continue;
                    }
                    return Err(error(
                        "close inputs not conclusively unspent; outcome unresolved",
                    ));
                }
            }
            let prepared = &journal.attempts[last].prepared;
            // Expiry enables the sender's competing refund branch; it does not
            // invalidate this receiver-authorized close. The mint arbitrates
            // the spend atomically, including after expiry.
            if journal.attempts[last].initial_rejection.is_some() {
                refresh
                    .refresh(&prepared.mint_url)
                    .await
                    .map_err(|_| error("close refresh failed; rejected request retained"))?;
                let selected = self.select_close_output_keyset(channel_id)?;
                let successor = self
                    .bridge
                    .prepare_close_for_closing_channel_with_output_keyset(channel_id, selected)
                    .map_err(CloseError::from_preparation_error)?;
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
                journal.attempts.push(CloseAttempt {
                    prepared: successor,
                    submissions: 0,
                    initial_rejection: None,
                });
                let next = serde_json::to_string(&journal)
                    .map_err(|_| error("serialize close successor"))?;
                storage
                    .advance_close(channel_id, &durable, &next, None)
                    .map_err(error)?;
                durable = next;
                need_restore = false;
                #[cfg(feature = "funds-lifecycle-test")]
                crate::lifecycle_test::boundary("close-successor");
                continue;
            }
            if sent >= 2 {
                return Err(error("close replay budget exhausted; outcome unresolved"));
            }
            let initial = journal.attempts[last].submissions == 0 && last == 0;
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
            sent += 1;
            #[cfg(feature = "funds-lifecycle-test")]
            crate::lifecycle_test::boundary("close-submitting");
            let prepared = &journal.attempts[last].prepared;
            match mint
                .swap_checked(&prepared.mint_url, &prepared.swap_request.to_string())
                .await
            {
                Ok(response) => {
                    journal.finalizing =
                        Some(self.bridge.complete_prepared_close(&response, prepared)?);
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
                    if initial {
                        if let Some(rejection) = failure
                            .downcast_ref::<MintHttpRejection>()
                            .filter(|rejection| rejection.inactive_output_keyset())
                        {
                            journal.attempts[last].initial_rejection = Some(*rejection);
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
                    need_restore = true;
                }
            }
        }
    }
}
