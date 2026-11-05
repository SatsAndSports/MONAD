use super::*;
use crate::mint_recovery::RecoveryMintClient;
use cdk_spilman::{ChannelRecovery, CompletedClose};
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
    collection_abandoned: bool,
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
    pub(crate) fn collection_abandoned(json: &str) -> Result<bool, String> {
        Self::validate_close_schema(json)?;
        let journal: CloseJournal =
            serde_json::from_str(json).map_err(|_| "invalid close journal")?;
        Ok(journal.collection_abandoned && journal.finalizing.is_none() && !journal.completed)
    }
    pub(crate) fn validate_close_schema(json: &str) -> Result<(), String> {
        let journal: CloseJournal = serde_json::from_str(json)
            .map_err(|_| "incompatible close journal; database retained")?;
        if journal.version != 4 || journal.attempts.is_empty() || journal.attempts.len() > 2 {
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
                    version: 4,
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
        if journal.version != 4
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
        let mut sent = 0;
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
            let attempts = journal
                .attempts
                .iter()
                .map(|a| a.prepared.clone())
                .collect::<Vec<_>>();
            let connection = crate::mint_recovery::ChannelMint {
                client: mint,
                mint: &channel.params.mint,
            };
            match self
                .bridge
                .recover_close(channel_id, &attempts, &connection)
                .await
                .map_err(|_| {
                    error("close funding inspection or restore failed; journal retained")
                })? {
                ChannelRecovery::Recovered { payout, .. } => {
                    journal.finalizing = Some(payout);
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
                }
            }
        }
    }
}
