use super::*;
use cashu::nuts::{CheckStateResponse, State};
use monad_common::mint_error::MintHttpRejection;
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::sync::OnceLock;

// These payloads contain secrets and must never implement Debug or be logged.
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Journal {
    version: u32,
    db: String,
    drain_id: String,
    relay: String,
    receiver: String,
    mint: String,
    unit: String,
    inputs: Vec<DrainCandidate>,
    attempts: Vec<Attempt>,
    finalizing: Option<String>,
    completed: bool,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Attempt {
    prepared: PreparedDrainSwap,
    keys: String,
    input_fees: BTreeMap<String, u64>,
    output_amount: u64,
    submissions: u64,
    rejection: Option<MintHttpRejection>,
}

impl From<PreparedDrainAttempt> for Attempt {
    fn from(attempt: PreparedDrainAttempt) -> Self {
        Self {
            prepared: attempt.prepared,
            keys: attempt.drain_keysets.output_keyset_info_json,
            input_fees: attempt.drain_keysets.input_fee_ppk_by_keyset,
            output_amount: attempt.output_amount_raw,
            submissions: 0,
            rejection: None,
        }
    }
}

static ACTIVE: OnceLock<Mutex<HashSet<String>>> = OnceLock::new();
pub(super) struct Flight(String);
impl Flight {
    fn enter(key: String) -> Result<Self, String> {
        if !ACTIVE
            .get_or_init(Default::default)
            .lock()
            .map_err(|_| "drain singleflight lock")?
            .insert(key.clone())
        {
            return Err("drain operation already active".to_string());
        }
        Ok(Self(key))
    }
}
impl Drop for Flight {
    fn drop(&mut self) {
        if let Ok(mut active) = ACTIVE.get_or_init(Default::default).lock() {
            active.remove(&self.0);
        }
    }
}

fn encode<T: Serialize + ?Sized>(value: &T) -> Result<String, String> {
    serde_json::to_string(value).map_err(|_| "encode drain journal".to_string())
}

pub(super) fn validate_schema(json: &str) -> Result<(), String> {
    let journal: Journal =
        serde_json::from_str(json).map_err(|_| "incompatible drain journal; database retained")?;
    if journal.version != 1 {
        return Err("incompatible drain journal version; database retained".to_string());
    }
    Ok(())
}

impl RelayWalletManager {
    fn drain_binding(&self) -> Result<String, String> {
        monad_common::wallet_lock::normalize_path(std::path::Path::new(self.db_path()))
            .map(|p| p.to_string_lossy().into_owned())
            .map_err(|e| e.to_string())
    }

    pub(super) async fn start_exact_drain<N: DrainSwapNetworking>(
        &self,
        relay: &str,
        mint: &str,
        unit: &str,
        net: &N,
        limit: Option<usize>,
    ) -> Result<DrainSwapResult, String> {
        self.require_maintenance()?;
        let drain_id = new_drain_id();
        let flight = Flight::enter(format!("{}:{drain_id}", self.drain_binding()?))?;
        let inputs = self.closed_drain_candidates(relay, mint, unit, limit)?;
        if inputs.is_empty() {
            return Err("no closed channels available to drain".to_string());
        }
        let proofs = inputs
            .iter()
            .map(|input| {
                serde_json::from_str::<Vec<Proof>>(&input.receiver_proofs_json)
                    .map_err(|_| "invalid drain input snapshot".to_string())
            })
            .collect::<Result<Vec<_>, _>>()?
            .into_iter()
            .flatten()
            .collect::<Vec<_>>();
        let total = proofs
            .iter()
            .try_fold(0u64, |n, p| n.checked_add(u64::from(p.amount)))
            .ok_or("drain input overflow")?;
        if total == 0 {
            return Err("closed channels have no receiver proofs to drain".to_string());
        }
        self.ensure_drain_keysets_cached(mint, unit).await?;
        let attempt = self.prepare_drain_attempt_with_keysets(
            self.drain_keysets_from_shared_cache(mint, unit)?,
            &proofs,
            total,
        )?;
        let journal = Journal {
            version: 1,
            db: self.drain_binding()?,
            drain_id,
            relay: relay.to_string(),
            receiver: self.receiver_pubkey_hex(relay).map_err(|e| e.to_string())?,
            mint: mint.to_string(),
            unit: unit.to_string(),
            inputs,
            attempts: vec![attempt.into()],
            finalizing: None,
            completed: false,
        };
        self.verify_drain_journal(&journal)?;
        let mut conn = cdk_spilman::sqlite_durability::open_wallet_database(self.db_path())
            .map_err(|e| e.to_string())?;
        let tx = conn.transaction().map_err(|e| e.to_string())?;
        let attempt = &journal.attempts[0];
        let keyset = cdk_spilman::parse_keyset_info_from_json(&attempt.keys)?;
        tx.execute("INSERT INTO monad_relay_drains (drain_id,relay_name,mint_url,unit,state,input_amount_raw,output_amount_raw,swap_request_json,restore_request_json,output_secrets_json,output_keyset_id,output_keyset_info_json,created_at) VALUES (?1,?2,?3,?4,'Prepared',?5,?6,?7,?8,?9,?10,?11,?12)", params![journal.drain_id, relay, mint, unit, i64_from_u64(total)?, i64_from_u64(attempt.output_amount)?, attempt.prepared.swap_request_json, attempt.prepared.restore_request_json, attempt.prepared.output_secrets_json, keyset.keyset_id.to_string(), attempt.keys, i64_from_u64(now_seconds())?]).map_err(|e| e.to_string())?;
        tx.execute(
            "INSERT INTO monad_relay_drain_journals VALUES (?1, ?2)",
            params![journal.drain_id, encode(&journal)?],
        )
        .map_err(|e| e.to_string())?;
        for input in &journal.inputs {
            tx.execute(
                "INSERT INTO monad_relay_drain_inputs VALUES (?1,?2,?3,?4)",
                params![
                    journal.drain_id,
                    input.channel_id,
                    i64_from_u64(input.receiver_sum_raw)?,
                    input.receiver_proofs_json
                ],
            )
            .map_err(|e| e.to_string())?;
            tx.execute(
                "INSERT INTO monad_relay_drained_channels VALUES (?1,?2)",
                params![input.channel_id, journal.drain_id],
            )
            .map_err(|e| e.to_string())?;
        }
        tx.commit().map_err(|e| e.to_string())?;
        #[cfg(feature = "funds-lifecycle-test")]
        crate::lifecycle_test::boundary("drain-prepared");
        self.run_exact_drain(&journal.drain_id, net, false, Some(flight))
            .await
    }

    fn verify_drain_journal(&self, journal: &Journal) -> Result<(), String> {
        if journal.version != 1
            || journal.db != self.drain_binding()?
            || journal.receiver
                != self
                    .receiver_pubkey_hex(&journal.relay)
                    .map_err(|e| e.to_string())?
            || journal.attempts.is_empty()
            || journal.attempts.len() > 2
            || journal.inputs.is_empty()
            || (journal.completed && journal.finalizing.is_none())
        {
            return Err("drain journal binding/version mismatch".to_string());
        }
        let mut proofs = Vec::new();
        for input in &journal.inputs {
            let (receiver, mint, unit) = self.channel_owner_and_mint(&input.channel_id)?;
            let closed = self
                .storage
                .get_closed_data(&input.channel_id)
                .ok_or("drain source is not closed")?;
            if receiver.public_key().to_hex() != journal.receiver
                || mint != journal.mint
                || unit != journal.unit
                || self
                    .relay_name_for_channel(&input.channel_id)
                    .map_err(|e| e.to_string())?
                    .as_deref()
                    != Some(&journal.relay)
                || closed.receiver_proofs_json != input.receiver_proofs_json
                || closed.receiver_sum != input.receiver_sum_raw
            {
                return Err("drain source snapshot conflict".to_string());
            }
            let source = serde_json::from_str::<Vec<Proof>>(&input.receiver_proofs_json)
                .map_err(|_| "invalid drain input snapshot")?;
            if source
                .iter()
                .try_fold(0u64, |sum, proof| sum.checked_add(u64::from(proof.amount)))
                != Some(input.receiver_sum_raw)
            {
                return Err("drain source amount conflict".to_string());
            }
            proofs.extend(source);
        }
        let ys = proofs
            .iter()
            .map(Proof::y)
            .collect::<Result<HashSet<_>, _>>()
            .map_err(|_| "invalid drain input")?;
        if ys.len() != proofs.len() || proofs.is_empty() {
            return Err("duplicate or empty drain inputs".to_string());
        }
        let total = proofs
            .iter()
            .try_fold(0u64, |n, p| n.checked_add(u64::from(p.amount)))
            .ok_or("drain input overflow")?;
        for (index, attempt) in journal.attempts.iter().enumerate() {
            if attempt.rejection.is_some_and(|r| {
                !r.inactive_output_keyset() || index != 0 || attempt.submissions != 1
            }) || (journal.attempts.len() == 2 && journal.attempts[0].rejection.is_none())
            {
                return Err("invalid drain execution history".to_string());
            }
            let keys = cdk_spilman::parse_keyset_info_from_json(&attempt.keys)?;
            if index == 1
                && (attempt.input_fees != journal.attempts[0].input_fees
                    || keys.keyset_id
                        == cdk_spilman::parse_keyset_info_from_json(&journal.attempts[0].keys)?
                            .keyset_id)
            {
                return Err("invalid drain successor metadata".to_string());
            }
            if keys.unit.to_string() != journal.unit {
                return Err("drain output unit mismatch".to_string());
            }
            let request: SwapRequest = serde_json::from_str(&attempt.prepared.swap_request_json)
                .map_err(|_| "invalid drain request")?;
            // CDK omits input DLEQs on the wire; custody snapshots retain them.
            if request.inputs() != SwapRequest::new(proofs.clone(), Vec::new()).inputs() {
                return Err("drain request inputs differ from custody snapshot".to_string());
            }
            let fees = proofs
                .iter()
                .try_fold(0u64, |n, p| {
                    n.checked_add(*attempt.input_fees.get(&p.keyset_id.to_string())?)
                })
                .ok_or("missing or overflowing drain input fees")?
                .div_ceil(1000);
            if total.checked_sub(fees) != Some(attempt.output_amount) {
                return Err("drain amount/fee snapshot mismatch".to_string());
            }
            let expected = cdk_spilman::create_plain_change_restore_request(
                &attempt.prepared.output_secrets_json,
                &attempt.keys,
            )
            .map_err(|_| "invalid prepared drain outputs")?;
            let expected: serde_json::Value =
                serde_json::from_str(&expected).map_err(|_| "invalid derived drain outputs")?;
            let stored: serde_json::Value =
                serde_json::from_str(&attempt.prepared.restore_request_json)
                    .map_err(|_| "invalid drain restore")?;
            if expected != stored
                || expected["outputs"]
                    != serde_json::to_value(request.outputs())
                        .map_err(|_| "drain output encoding")?
                || request
                    .outputs()
                    .iter()
                    .try_fold(0u64, |n, o| n.checked_add(u64::from(o.amount)))
                    != Some(attempt.output_amount)
            {
                return Err("drain outputs differ from immutable secrets".to_string());
            }
        }
        if let Some(finalizing) = &journal.finalizing {
            let proofs: Vec<Proof> =
                serde_json::from_str(finalizing).map_err(|_| "invalid drain finalization")?;
            let valid = journal.attempts.iter().any(|attempt| {
                let Ok(keys) = cdk_spilman::parse_keyset_info_from_json(&attempt.keys) else {
                    return false;
                };
                let Ok(secrets) = serde_json::from_str::<Vec<serde_json::Value>>(
                    &attempt.prepared.output_secrets_json,
                ) else {
                    return false;
                };
                secrets.len() == proofs.len()
                    && secrets.iter().zip(&proofs).all(|(secret, proof)| {
                        proof.keyset_id == keys.keyset_id
                            && secret["secret"].as_str() == Some(proof.secret.to_string().as_str())
                            && secret["amount"].as_u64() == Some(u64::from(proof.amount))
                            && keys
                                .active_keys
                                .amount_key(proof.amount)
                                .is_some_and(|key| proof.verify_dleq(key).is_ok())
                    })
            });
            if !valid {
                return Err("drain finalization proof conflict".to_string());
            }
        }
        Ok(())
    }

    fn persist_exact_drain(&self, journal: &Journal, previous: &str) -> Result<String, String> {
        let next = encode(journal)?;
        let mut conn = cdk_spilman::sqlite_durability::open_wallet_database(self.db_path())
            .map_err(|e| e.to_string())?;
        let tx = conn.transaction().map_err(|e| e.to_string())?;
        let changed = tx.execute("UPDATE monad_relay_drain_journals SET journal_json=?3 WHERE drain_id=?1 AND journal_json=?2", params![journal.drain_id,previous,next]).map_err(|e| e.to_string())?;
        if changed != 1 {
            return Err("drain journal conflict".to_string());
        }
        let current = journal.attempts.last().ok_or("empty drain journal")?;
        let keys = cdk_spilman::parse_keyset_info_from_json(&current.keys)?;
        let state = if journal.completed {
            "Completed"
        } else if journal.finalizing.is_some() {
            "Finalizing"
        } else if current.submissions > 0 {
            "Submitted"
        } else {
            "Prepared"
        };
        let changed = tx.execute("UPDATE monad_relay_drains SET state=?2,output_amount_raw=?3,swap_request_json=?4,restore_request_json=?5,output_secrets_json=?6,output_keyset_id=?7,output_keyset_info_json=?8,output_proofs_json=?9,completed_at=CASE WHEN ?2='Completed' THEN COALESCE(completed_at,?10) ELSE completed_at END WHERE drain_id=?1 AND state!='Completed'", params![journal.drain_id,state,i64_from_u64(current.output_amount)?,current.prepared.swap_request_json,current.prepared.restore_request_json,current.prepared.output_secrets_json,keys.keyset_id.to_string(),current.keys,journal.finalizing,i64_from_u64(now_seconds())?]).map_err(|e| e.to_string())?;
        if changed != 1 {
            return Err("drain terminal state conflict".to_string());
        }
        tx.commit().map_err(|e| e.to_string())?;
        Ok(next)
    }

    pub(super) async fn run_exact_drain<N: DrainSwapNetworking>(
        &self,
        id: &str,
        net: &N,
        resumed: bool,
        flight: Option<Flight>,
    ) -> Result<DrainSwapResult, String> {
        self.require_maintenance()?;
        let _flight = match flight {
            Some(flight) => flight,
            None => Flight::enter(format!("{}:{id}", self.drain_binding()?))?,
        };
        let conn = cdk_spilman::sqlite_durability::open_wallet_database(self.db_path())
            .map_err(|e| e.to_string())?;
        let mut durable: String = conn
            .query_row(
                "SELECT journal_json FROM monad_relay_drain_journals WHERE drain_id=?1",
                [id],
                |r| r.get(0),
            )
            .map_err(|_| {
                "drain not found or lacks compatible immutable journal; database retained"
            })?;
        drop(conn);
        let mut journal: Journal = serde_json::from_str(&durable)
            .map_err(|_| "incompatible drain journal; database retained")?;
        if journal.drain_id != id {
            return Err("drain identity conflict".to_string());
        }
        self.verify_drain_journal(&journal)?;
        let stored = self.load_drain(id)?;
        let current = journal.attempts.last().ok_or("empty drain journal")?;
        let expected_state = if journal.completed {
            "Completed"
        } else if journal.finalizing.is_some() {
            "Finalizing"
        } else if current.submissions > 0 {
            "Submitted"
        } else {
            "Prepared"
        };
        if stored.state != expected_state
            || journal
                .inputs
                .iter()
                .try_fold(0u64, |sum, input| sum.checked_add(input.receiver_sum_raw))
                != Some(stored.input_amount_raw)
            || stored.relay_name != journal.relay
            || stored.mint_url != journal.mint
            || stored.unit != journal.unit
            || stored.output_amount_raw != current.output_amount
            || stored.restore_request_json != current.prepared.restore_request_json
            || stored.output_secrets_json != current.prepared.output_secrets_json
            || stored.output_keyset_info_json != current.keys
            || stored.output_proofs_json != journal.finalizing
        {
            return Err("drain metadata/journal conflict".to_string());
        }
        let conn = cdk_spilman::sqlite_durability::open_wallet_database(self.db_path())
            .map_err(|e| e.to_string())?;
        for input in &journal.inputs {
            let owner: String = conn
                .query_row(
                    "SELECT drain_id FROM monad_relay_drained_channels WHERE channel_id=?1",
                    [&input.channel_id],
                    |r| r.get(0),
                )
                .map_err(|_| "missing drain reservation")?;
            if owner != id {
                return Err("drain reservation conflict".to_string());
            }
        }
        drop(conn);
        let recovered = resumed && !journal.completed;
        let mut expected_channels = journal
            .inputs
            .iter()
            .map(|input| input.channel_id.clone())
            .collect::<Vec<_>>();
        expected_channels.sort();
        if self.drain_channel_ids(id)? != expected_channels {
            return Err("drain input membership conflict".to_string());
        }
        let mut sent = 0;
        let mut restore_first = resumed;
        loop {
            if journal.finalizing.is_some() {
                if !journal.completed {
                    journal.completed = true;
                    self.persist_exact_drain(&journal, &durable)?;
                    #[cfg(feature = "funds-lifecycle-test")]
                    crate::lifecycle_test::boundary("drain-completed");
                }
                return self.completed_drain_result(self.load_drain(id)?, recovered);
            }
            let last = journal.attempts.len() - 1;
            if restore_first || journal.attempts[last].submissions > 0 {
                for attempt in &journal.attempts {
                    let response = net
                        .call_mint_restore(&journal.mint, &attempt.prepared.restore_request_json)
                        .await
                        .map_err(|_| "drain restore unavailable; submitted outcome unresolved")?;
                    let parsed: cashu::nuts::RestoreResponse =
                        serde_json::from_str(&response).map_err(|_| "invalid drain restore")?;
                    if parsed.outputs.is_empty() && parsed.signatures.is_empty() {
                        continue;
                    }
                    let completed = complete_plain_change_restore(
                        &response,
                        &attempt.prepared.output_secrets_json,
                        &attempt.keys,
                    )
                    .map_err(|_| "invalid exact drain restore")?;
                    let completed: serde_json::Value =
                        serde_json::from_str(&completed).map_err(|_| "invalid completed drain")?;
                    journal.finalizing = Some(
                        completed["change_proofs_json"]
                            .as_str()
                            .ok_or("missing restored drain proofs")?
                            .to_string(),
                    );
                    break;
                }
                if journal.finalizing.is_some() {
                    durable = self.persist_exact_drain(&journal, &durable)?;
                    #[cfg(feature = "funds-lifecycle-test")]
                    crate::lifecycle_test::boundary("drain-finalizing");
                    continue;
                }
                let request: SwapRequest =
                    serde_json::from_str(&journal.attempts[last].prepared.swap_request_json)
                        .map_err(|_| "invalid drain request")?;
                let ys = request
                    .inputs()
                    .iter()
                    .map(Proof::y)
                    .collect::<Result<Vec<_>, _>>()
                    .map_err(|_| "invalid drain inputs")?;
                let response = net
                    .checked_state(&journal.mint, &serde_json::json!({"Ys":ys}).to_string())
                    .await
                    .map_err(|_| "drain input state unavailable; submitted outcome unresolved")?;
                let response: CheckStateResponse =
                    serde_json::from_str(&response).map_err(|_| "invalid drain input state")?;
                if response.states.len() != ys.len()
                    || ys.iter().any(|y| {
                        response
                            .states
                            .iter()
                            .filter(|s| s.y == *y && s.state == State::Unspent)
                            .count()
                            != 1
                    })
                {
                    let attempt = &journal.attempts[last];
                    let response = net
                        .call_mint_restore(&journal.mint, &attempt.prepared.restore_request_json)
                        .await
                        .map_err(|_| "final drain restore unavailable")?;
                    let parsed: cashu::nuts::RestoreResponse = serde_json::from_str(&response)
                        .map_err(|_| "invalid final drain restore")?;
                    if !parsed.outputs.is_empty() || !parsed.signatures.is_empty() {
                        let result = complete_plain_change_restore(
                            &response,
                            &attempt.prepared.output_secrets_json,
                            &attempt.keys,
                        )
                        .map_err(|_| "invalid final exact drain restore")?;
                        let result: serde_json::Value = serde_json::from_str(&result)
                            .map_err(|_| "invalid final drain completion")?;
                        journal.finalizing = Some(
                            result["change_proofs_json"]
                                .as_str()
                                .ok_or("missing final drain proofs")?
                                .to_string(),
                        );
                        durable = self.persist_exact_drain(&journal, &durable)?;
                        #[cfg(feature = "funds-lifecycle-test")]
                        crate::lifecycle_test::boundary("drain-finalizing");
                        continue;
                    }
                    return Err(
                        "drain inputs not conclusively unspent; submitted outcome unresolved"
                            .to_string(),
                    );
                }
            }
            if journal.attempts[last].rejection.is_some() {
                self.refresh_all_keysets_for_mint_into_shared_cache(&journal.mint)
                    .await?;
                let mut keys =
                    self.drain_keysets_from_shared_cache(&journal.mint, &journal.unit)?;
                if keys.output_keyset_id
                    == cdk_spilman::parse_keyset_info_from_json(&journal.attempts[last].keys)?
                        .keyset_id
                        .to_string()
                {
                    return Err(
                        "drain rejected output keyset unchanged; reservation retained".to_string(),
                    );
                }
                keys.input_fee_ppk_by_keyset = journal.attempts[last].input_fees.clone();
                let request: SwapRequest =
                    serde_json::from_str(&journal.attempts[last].prepared.swap_request_json)
                        .map_err(|_| "invalid drain request")?;
                let total = request
                    .inputs()
                    .iter()
                    .try_fold(0u64, |n, p| n.checked_add(u64::from(p.amount)))
                    .ok_or("drain overflow")?;
                let successor =
                    self.prepare_drain_attempt_with_keysets(keys, request.inputs(), total)?;
                journal.attempts.push(successor.into());
                durable = self.persist_exact_drain(&journal, &durable)?;
                restore_first = false;
                #[cfg(feature = "funds-lifecycle-test")]
                crate::lifecycle_test::boundary("drain-successor");
                continue;
            }
            if sent >= 2 {
                return Err("drain submitted; immutable replay budget exhausted".to_string());
            }
            let initial = last == 0 && journal.attempts[last].submissions == 0;
            journal.attempts[last].submissions = journal.attempts[last]
                .submissions
                .checked_add(1)
                .ok_or("drain execution overflow")?;
            durable = self.persist_exact_drain(&journal, &durable)?;
            sent += 1;
            #[cfg(feature = "funds-lifecycle-test")]
            crate::lifecycle_test::boundary("drain-submitting");
            let attempt = &journal.attempts[last];
            match net
                .checked_swap(&journal.mint, &attempt.prepared.swap_request_json)
                .await
            {
                Ok(response) => {
                    journal.finalizing = Some(
                        complete_plain_drain_swap(
                            &response,
                            &attempt.prepared.output_secrets_json,
                            &attempt.keys,
                        )
                        .map_err(|_| "invalid drain swap completion")?,
                    );
                    durable = self.persist_exact_drain(&journal, &durable)?;
                    #[cfg(feature = "funds-lifecycle-test")]
                    crate::lifecycle_test::boundary("drain-finalizing");
                }
                Err(error) => {
                    if initial {
                        if let Some(rejection) = error
                            .downcast_ref::<MintHttpRejection>()
                            .filter(|r| r.inactive_output_keyset())
                        {
                            journal.attempts[last].rejection = Some(*rejection);
                            durable = self.persist_exact_drain(&journal, &durable)?;
                            #[cfg(feature = "funds-lifecycle-test")]
                            crate::lifecycle_test::boundary("drain-rejected");
                        }
                    }
                    restore_first = true;
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn terminal_drain_cas_rejects_conflicting_completion_and_retains_reservations() {
        let db = tempfile::NamedTempFile::new().unwrap();
        let manager = RelayWalletManager::open(db.path().to_str().unwrap()).unwrap();
        let conn = Connection::open(db.path()).unwrap();
        conn.execute("INSERT INTO monad_relay_drains (drain_id,relay_name,mint_url,unit,state,input_amount_raw,output_amount_raw,swap_request_json,restore_request_json,output_secrets_json,output_keyset_id,output_keyset_info_json,created_at) VALUES ('drain','relay','mint','sat','Submitted',1,1,'{}','{}','[]','key','{}',1)", []).unwrap();
        conn.execute(
            "INSERT INTO monad_relay_drained_channels VALUES ('channel','drain')",
            [],
        )
        .unwrap();
        // An old row is rejected without conversion or deletion.
        assert!(manager.reopen().is_err());
        let keys = cashu::nuts::Keys::new(
            [(cashu::Amount::from(1), SecretKey::generate().public_key())]
                .into_iter()
                .collect(),
        );
        let keys = cdk_spilman::KeysetInfo::new(
            cashu::nuts::Id::v1_from_keys(&keys),
            cashu::nuts::CurrencyUnit::Sat,
            keys,
            0,
            None,
        );
        // This fixture exercises the private storage CAS, not crypto completion.
        let journal = Journal {
            version: 1,
            db: manager.drain_binding().unwrap(),
            drain_id: "drain".to_string(),
            relay: "relay".to_string(),
            receiver: "receiver".to_string(),
            mint: "mint".to_string(),
            unit: "sat".to_string(),
            inputs: Vec::new(),
            attempts: vec![Attempt {
                prepared: PreparedDrainSwap {
                    swap_request_json: "{}".to_string(),
                    restore_request_json: "{}".to_string(),
                    output_secrets_json: "[]".to_string(),
                },
                keys: encode(&keys).unwrap(),
                input_fees: BTreeMap::new(),
                output_amount: 1,
                submissions: 1,
                rejection: None,
            }],
            finalizing: None,
            completed: false,
        };
        let before = encode(&journal).unwrap();
        conn.execute(
            "INSERT INTO monad_relay_drain_journals VALUES ('drain',?1)",
            [&before],
        )
        .unwrap();
        let mut first = journal.clone();
        first.completed = true;
        first.finalizing = Some("first-fixture-payload".to_string());
        let mut second = first.clone();
        second.finalizing = Some("second-fixture-payload".to_string());
        let barrier = std::sync::Barrier::new(2);
        let (a, b) = std::thread::scope(|scope| {
            let a = scope.spawn(|| {
                barrier.wait();
                manager.persist_exact_drain(&first, &before)
            });
            let b = scope.spawn(|| {
                barrier.wait();
                manager.persist_exact_drain(&second, &before)
            });
            (a.join().unwrap(), b.join().unwrap())
        });
        assert_ne!(a.is_ok(), b.is_ok());
        let winning = if let Ok(json) = a { json } else { b.unwrap() };
        assert!(manager.persist_exact_drain(&journal, &winning).is_err());
        let stored: String = conn
            .query_row(
                "SELECT journal_json FROM monad_relay_drain_journals WHERE drain_id='drain'",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert!(stored == winning, "terminal journal overwritten");
        assert_eq!(
            conn.query_row(
                "SELECT COUNT(*) FROM monad_relay_drained_channels",
                [],
                |r| r.get::<_, u64>(0)
            )
            .unwrap(),
            1
        );
        let mut incompatible: serde_json::Value = serde_json::from_str(&stored).unwrap();
        incompatible["version"] = serde_json::json!(2);
        conn.execute(
            "UPDATE monad_relay_drain_journals SET journal_json=?1",
            [incompatible.to_string()],
        )
        .unwrap();
        assert!(manager.reopen().is_err());
        assert_eq!(
            conn.query_row("SELECT COUNT(*) FROM monad_relay_drains", [], |r| r
                .get::<_, u64>(0))
                .unwrap(),
            1
        );
    }
}
