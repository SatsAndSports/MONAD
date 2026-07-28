//! SQLite-backed MONAD client wallet.
//!
//! Bridges `LooseProofWallet` (bearer-proof custody) with upstream
//! `cdk-spilman` Spilman channel operations, implementing `MonadWallet`.

use crate::loose_proof_wallet::{
    LooseProofWallet, LooseProofWalletError, NewLooseProof, ProofReservation,
};
use crate::proof_selection::{select_mixed_fee_inputs_for_post_swap_target, ProofCandidate};
use crate::wallet::{
    msats_to_raw_units, raw_to_msats, MonadWallet, RelayPaymentOffer, WalletChannel,
    WalletChannelState, WalletError,
};
use cashu::nuts::{CurrencyUnit, Id, Proof, SecretKey, State};
use cdk_spilman::{
    compute_funding_token_amount, parse_keyset_info_from_json, with_active_keyset_retry,
    ClientChannelFunding, ClientChannelInfo, ClientKeysetCacheEntry, CompletedOpenChannel,
    ConfigurableClientHost, EstablishedChannel, FundingSpendKind, KeysetRetryError, MintConnection,
    OpenChannelError, OpenChannelFailureStage, OpenChannelResult, PreparedOpenChannel,
    PreparedSenderRefund, ReqwestClientNetworking, SelectedOutputKeyset, SpilmanClientBridge,
    SpilmanClientHost, SpilmanClientNetworking, SqliteClientStorage,
};
use rusqlite::{params, Connection, OptionalExtension};
use std::collections::HashMap;
use std::path::Path;
#[cfg(test)]
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Mutex;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

type ClientBridge =
    SpilmanClientBridge<ConfigurableClientHost<SqliteClientStorage>, ReqwestClientNetworking>;

const CHANNEL_EXPIRY_SECONDS: u64 = 24 * 3600;

const CREATE_CHANNELS_SQL: &str = r#"
    CREATE TABLE IF NOT EXISTS monad_client_channels (
        channel_id TEXT PRIMARY KEY,
        receiver_pubkey TEXT NOT NULL,
        mint_url TEXT NOT NULL,
        unit TEXT NOT NULL,
        keyset_id TEXT NOT NULL,
        capacity_msats INTEGER NOT NULL,
        attached_session_id TEXT,
        state TEXT NOT NULL,
        reservation_id TEXT,
        expiry_timestamp INTEGER NOT NULL,
        created_at INTEGER NOT NULL,
        updated_at INTEGER NOT NULL
    )
"#;

const CREATE_OPENING_RECOVERIES_SQL: &str = r#"
    CREATE TABLE IF NOT EXISTS monad_client_channel_opening_recoveries (
        channel_id TEXT PRIMARY KEY,
        reservation_id TEXT NOT NULL,
        receiver_pubkey TEXT NOT NULL,
        mint_url TEXT NOT NULL,
        unit TEXT NOT NULL,
        input_budget_msats INTEGER NOT NULL,
        error_stage TEXT NOT NULL,
        error_message TEXT NOT NULL,
        created_at INTEGER NOT NULL,
        updated_at INTEGER NOT NULL
    )
"#;

const CREATE_CHANNEL_RECOVERIES_SQL: &str = r#"
    CREATE TABLE IF NOT EXISTS monad_client_channel_recoveries (
        channel_id TEXT PRIMARY KEY,
        kind TEXT NOT NULL,
        status TEXT NOT NULL,
        recovered_amount_raw INTEGER,
        recovered_proof_count INTEGER,
        prepared_refund_json TEXT,
        completed_at INTEGER,
        created_at INTEGER NOT NULL,
        updated_at INTEGER NOT NULL
    )
"#;

/// Client wallet backed by SQLite.
///
/// `LooseProofWallet` holds bearer proofs; this layer manages Spilman channel
/// metadata and payment signing via `cdk-spilman`.
pub struct SqliteClientWallet {
    loose_wallet: LooseProofWallet,
    bridge: Mutex<ClientBridge>,
    sender_secret: SecretKey,
    sender_pubkey_hex: String,
    channel_db: Mutex<Connection>,
    #[cfg(test)]
    fail_next_recovered_proof_import: AtomicBool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ChannelFundRecoveryResult {
    AlreadyRecovered {
        channel_id: String,
        kind: String,
        recovered_amount_raw: u64,
        recovered_proof_count: usize,
    },
    NotExpiredOrSpentYet {
        expiry_timestamp: u64,
        now: u64,
    },
    FundingPending,
    PostExpiryRefundRecovered {
        channel_id: String,
        recovered_amount_raw: u64,
        recovered_proof_count: usize,
    },
    RelayCloseRecovered {
        channel_id: String,
        recovered_amount_raw: u64,
        recovered_proof_count: usize,
    },
    RecoveryRetryLater {
        channel_id: String,
        reason: String,
    },
    UnknownSpent,
}

#[derive(Debug, Clone)]
struct ClientOpenAttempt {
    output_keyset: SelectedOutputKeyset,
    reservation: ProofReservation,
    requested_capacity_raw: Option<u64>,
    desired_funding_token_amount_raw: Option<u64>,
    selected_input_msats: u64,
    expiry_timestamp: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum OutputKeysetSelection<T> {
    Selected(T),
    NoActiveAcceptedKeyset,
}

#[derive(Debug, Clone)]
struct ChannelRecoveryRow {
    status: ChannelRecoveryStatus,
    prepared_refund_json: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ChannelRecoveryStatus {
    Prepared,
    Submitting,
    Completed,
}

impl ChannelRecoveryStatus {
    fn from_db(value: &str) -> Result<Self, WalletError> {
        match value {
            "prepared" => Ok(Self::Prepared),
            "submitting" => Ok(Self::Submitting),
            "completed" => Ok(Self::Completed),
            other => Err(WalletError::Backend(format!(
                "unknown channel recovery status: {other}"
            ))),
        }
    }
}

impl SqliteClientWallet {
    /// Open or create a wallet.
    ///
    /// `loose_wallet` supplies bearer proofs. Channel metadata is stored in
    /// `channel_db_path` (which may be the same file as the loose-proof DB).
    /// `sender_secret_hex` is a 32-byte hex secret used to sign channel payments.
    ///
    /// This wallet uses the Arbitrary Input Model for provisioning: the caller
    /// commits a loose-proof input budget and upstream returns the actual usable
    /// channel capacity after applying Cashu input/output fees.
    pub fn open(
        loose_wallet: LooseProofWallet,
        channel_db_path: impl AsRef<Path>,
        sender_secret_hex: &str,
    ) -> Result<Self, WalletError> {
        let path = channel_db_path.as_ref();
        let path_str = path.to_str().ok_or_else(|| {
            WalletError::Backend("channel database path is not valid UTF-8".to_string())
        })?;

        let sender_secret = SecretKey::from_hex(sender_secret_hex)
            .map_err(|e| WalletError::Backend(format!("parse sender secret: {e}")))?;
        let mut host = ConfigurableClientHost::<SqliteClientStorage>::open_sqlite(path_str)
            .map_err(|e| {
                WalletError::Backend(format!("open upstream sqlite client storage: {e}"))
            })?;
        let sender_pubkey_hex = sender_secret.public_key().to_hex();
        host.add_key(sender_secret.clone());

        let bridge = SpilmanClientBridge::new(host, ReqwestClientNetworking::new());

        let channel_db = Connection::open(path)
            .map_err(|e| WalletError::Backend(format!("open channel metadata database: {e}")))?;
        channel_db
            .busy_timeout(Duration::from_secs(5))
            .map_err(|e| WalletError::Backend(format!("set channel db busy timeout: {e}")))?;
        channel_db
            .execute_batch(&format!(
                "{CREATE_CHANNELS_SQL};{CREATE_OPENING_RECOVERIES_SQL};{CREATE_CHANNEL_RECOVERIES_SQL};"
            ))
            .map_err(|e| WalletError::Backend(format!("create channel metadata schema: {e}")))?;

        Ok(Self {
            loose_wallet,
            bridge: Mutex::new(bridge),
            sender_secret,
            sender_pubkey_hex,
            channel_db: Mutex::new(channel_db),
            #[cfg(test)]
            fail_next_recovered_proof_import: AtomicBool::new(false),
        })
    }

    /// Access the underlying loose-proof wallet.
    pub fn loose_wallet(&self) -> &LooseProofWallet {
        &self.loose_wallet
    }

    #[cfg(test)]
    fn fail_next_recovered_proof_import_for_test(&self) {
        self.fail_next_recovered_proof_import
            .store(true, Ordering::SeqCst);
    }

    /// Try to advance recovery of any funds locked in a channel.
    ///
    /// This is the single library entrypoint for getting the client's money back
    /// from a channel, regardless of whether it is expired, relay-closed,
    /// already recovered, or not yet recoverable. It inspects the mint-observable
    /// funding-token state and any locally persisted refund attempt, then takes
    /// the safest next step and returns what happened.
    ///
    /// State summary:
    /// - no row / prepared + expired + unspent: persist and submit one refund
    /// - submitting + expired: restore first, submit only if still unspent
    /// - spent by relay close: restore deterministic sender close outputs
    /// - spent by refund or unknown witness: report unknown without probing
    pub async fn recover_channel_funds<M>(
        &self,
        channel_id: &str,
        mint_connection: &M,
    ) -> Result<ChannelFundRecoveryResult, WalletError>
    where
        M: MintConnection + ?Sized,
    {
        if let Some(completed) = self.completed_channel_recovery(channel_id)? {
            return Ok(completed);
        }

        let funding = {
            let bridge = self
                .bridge
                .lock()
                .map_err(|_| WalletError::Backend("bridge mutex poisoned".to_string()))?;
            bridge.get_channel_funding(channel_id)
        }
        .ok_or(WalletError::NotFound)?;
        let established = EstablishedChannel::from_client_channel_funding(&funding)
            .map_err(|e| WalletError::Backend(format!("reconstruct channel funding: {e}")))?;
        let now = Self::now_seconds()?;

        let proof_state = established
            .check_funding_token_state(mint_connection)
            .await
            .map_err(|e| WalletError::Backend(format!("check funding token state: {e}")))?;

        if proof_state.state == State::Pending {
            return Ok(ChannelFundRecoveryResult::FundingPending);
        }

        if proof_state.state == State::Unspent && now < established.params.expiry_timestamp {
            return Ok(ChannelFundRecoveryResult::NotExpiredOrSpentYet {
                expiry_timestamp: established.params.expiry_timestamp,
                now,
            });
        }

        let recovery = self.load_channel_recovery_row(channel_id)?;

        // If the channel is expired and we have already attempted to submit a
        // refund, try to restore the prepared refund outputs first. The mint may
        // have accepted the refund even though we lost the response.
        if established.params.expiry_timestamp <= now {
            if let Some(row) = recovery.as_ref() {
                if row.status == ChannelRecoveryStatus::Submitting {
                    if let Some(prepared) = self.prepared_refund_from_recovery_row(row)? {
                        if let Ok(proofs) =
                            EstablishedChannel::restore_prepared_sender_refund_outputs(
                                &prepared,
                                mint_connection,
                                &established.params.keyset_info.active_keys,
                            )
                            .await
                        {
                            return self.complete_channel_recovery(
                                channel_id,
                                &funding,
                                "post_expiry_refund",
                                proofs,
                                true,
                            );
                        }
                    }
                }
            }
        }

        if proof_state.state == State::Unspent {
            // At this point the channel is expired, otherwise we returned above.
            let prepared = match recovery {
                Some(row) => match self.prepared_refund_from_recovery_row(&row)? {
                    Some(prepared) => prepared,
                    None => {
                        self.prepare_and_persist_refund_recovery(channel_id, &established, now)?
                    }
                },
                None => self.prepare_and_persist_refund_recovery(channel_id, &established, now)?,
            };

            let is_submitting = self
                .load_channel_recovery_row(channel_id)?
                .map(|r| r.status == ChannelRecoveryStatus::Submitting)
                .unwrap_or(false);
            if !is_submitting {
                self.mark_refund_recovery_submitting(channel_id)?;
            }

            // Safe to retry from `submitting + Unspent`: the funding input is
            // mint-observable unspent and we reuse the same persisted refund.
            match EstablishedChannel::submit_prepared_sender_refund(
                &prepared,
                mint_connection,
                &established.params.keyset_info.active_keys,
            )
            .await
            {
                Ok(proofs) => {
                    return self.complete_channel_recovery(
                        channel_id,
                        &funding,
                        "post_expiry_refund",
                        proofs,
                        true,
                    );
                }
                Err(_) => {
                    if let Ok(proofs) = EstablishedChannel::restore_prepared_sender_refund_outputs(
                        &prepared,
                        mint_connection,
                        &established.params.keyset_info.active_keys,
                    )
                    .await
                    {
                        return self.complete_channel_recovery(
                            channel_id,
                            &funding,
                            "post_expiry_refund",
                            proofs,
                            true,
                        );
                    }
                    return Ok(ChannelFundRecoveryResult::RecoveryRetryLater {
                        channel_id: channel_id.to_string(),
                        reason: "refund submit failed and prepared outputs could not be restored"
                            .to_string(),
                    });
                }
            }
        }

        if proof_state.state == State::Spent {
            match EstablishedChannel::classify_funding_spend_witness(&proof_state) {
                FundingSpendKind::RelayClose => {
                    // Only the relay-close witness path may probe deterministic
                    // sender close outputs; refund/mystery spends stay unknown.
                    return self
                        .try_relay_close_recovery(channel_id, &funding, mint_connection)
                        .await;
                }
                FundingSpendKind::PostExpiryRefund | FundingSpendKind::Unknown => {
                    return Ok(ChannelFundRecoveryResult::UnknownSpent);
                }
            }
        }

        Ok(ChannelFundRecoveryResult::UnknownSpent)
    }

    async fn try_relay_close_recovery<M>(
        &self,
        channel_id: &str,
        funding: &ClientChannelFunding,
        mint_connection: &M,
    ) -> Result<ChannelFundRecoveryResult, WalletError>
    where
        M: MintConnection + ?Sized,
    {
        match EstablishedChannel::restore_sender_proofs_from_client_funding(
            funding,
            self.sender_secret.clone(),
            mint_connection,
        )
        .await
        {
            Ok(proofs) if !proofs.is_empty() => {
                self.complete_channel_recovery(channel_id, funding, "relay_close", proofs, false)
            }
            _ => Ok(ChannelFundRecoveryResult::UnknownSpent),
        }
    }

    /// Provision a channel with an exact requested capacity.
    ///
    /// This path selects loose proofs by their mixed input fees, reserves those
    /// exact proofs, and asks upstream to build a channel with exactly
    /// `target_capacity_msats`. If selected proofs provide slightly more funding
    /// than required, upstream keeps the full funding amount while setting the
    /// smaller requested channel capacity.
    pub fn provision_channel_with_target_capacity(
        &self,
        offer: &RelayPaymentOffer,
        target_capacity_msats: u64,
    ) -> Result<String, WalletError> {
        if offer.accepted_keyset_ids.is_empty() {
            return Err(WalletError::OfferMismatch(
                "offer has no accepted keysets".to_string(),
            ));
        }

        let target_capacity_raw = msats_to_raw_units(&offer.unit, target_capacity_msats)?;
        if target_capacity_raw == 0 {
            return Err(WalletError::OfferMismatch(
                "target capacity must be greater than zero".to_string(),
            ));
        }
        self.ensure_offer_keysets_cached(offer)?;
        let expiry_timestamp = Self::now_seconds()? + CHANNEL_EXPIRY_SECONDS;
        // Target-capacity provisioning computes the exact post-swap channel
        // capacity we want, selects loose proofs that can fund it after input
        // fees, and then asks the mint to swap those proofs into channel funding
        // outputs.  The output keyset info comes from the client's local mint
        // keyset cache.  Selection first tries the cached active keysets that
        // intersect with the relay offer, then refreshes the client cache before
        // deciding the relay offer is stale.  If a selected cached keyset becomes
        // stale before swap submission, the retry helper centralizes the safe
        // mint-rejection policy: refresh keysets, reselect, skip retry if refresh
        // still selects the same id, otherwise reprepare and submit once.
        let result = with_active_keyset_retry(
            // Select an active relay-accepted output keyset, refreshing the
            // client cache before reporting a stale relay offer.
            || self.select_output_keyset_refreshing_client_first(offer),
            // Prepare reserves a fresh set of loose proofs sized for the target
            // capacity and the selected output keyset's fee/amount structure.
            |output_keyset| {
                self.prepare_target_capacity_attempt(
                    offer,
                    target_capacity_raw,
                    output_keyset,
                    expiry_timestamp,
                )
            },
            // Submit the upstream channel-open swap using that reservation.
            |attempt| self.submit_open_attempt(offer, attempt),
            // Retry only safe keyset rejections; errors where inputs may be
            // spent are never retried automatically.
            |error| should_retry_open_after_keyset_rejection(error, false),
            // Refresh the client's keyset cache for the mint before retry
            // selection.
            || self.refresh_client_keysets(offer),
            // Target-capacity proof choice depends on the selected output
            // keyset.  Release the first reservation before reselecting/retrying
            // so the retry can choose a fresh proof set.
            |attempt, _error| {
                self.loose_wallet
                    .release_reservation(&attempt.reservation.reservation_id)
                    .map(|_| ())
                    .map_err(loose_proof_error)
            },
        );
        match result {
            Ok(success) => self.finish_open_channel(
                success.value,
                &success.attempt.reservation,
                success.attempt.expiry_timestamp,
            ),
            Err(KeysetRetryError::Submit { attempt, error, .. }) => self.handle_open_error(
                error,
                &attempt.reservation,
                offer,
                attempt.selected_input_msats,
            ),
            Err(KeysetRetryError::RetryKeysetUnchanged { attempt, error, .. }) => Err(
                open_channel_error(error, &offer.unit, attempt.selected_input_msats),
            ),
            Err(KeysetRetryError::Select {
                error: WalletError::StaleRelayKeysets { .. },
                ..
            }) => Err(WalletError::StaleRelayKeysets {
                mint_url: offer.mint_url.clone(),
                unit: offer.unit.clone(),
                accepted_keyset_ids: offer.accepted_keyset_ids.clone(),
            }),
            Err(error) => Err(WalletError::Backend(format!(
                "prepare channel open retry: {}",
                describe_keyset_retry_prepare_error(error)
            ))),
        }
    }

    /// Recover channel openings whose funding swap may have reached the mint.
    ///
    /// Ambiguous failures leave loose proofs reserved and an upstream
    /// `OpeningFromSwap` row behind. This method uses upstream NUT-09 restore to
    /// recover those openings, then marks the loose-proof reservation spent and
    /// stores normal MONAD channel metadata.
    pub fn recover_pending_openings(&self) -> Result<Vec<String>, WalletError> {
        let recoveries = self.list_opening_recoveries()?;
        let mut recovered = Vec::new();
        let networking = ReqwestClientNetworking::new();

        for recovery in recoveries {
            let result = self.recover_pending_opening(&recovery.channel_id, &networking);

            match result {
                Ok(open_result) => {
                    self.loose_wallet
                        .import_proofs(&change_proofs_to_loose_proofs(&open_result)?)
                        .map_err(loose_proof_error)?;
                    self.loose_wallet
                        .mark_reservation_spent(&recovery.reservation_id, &open_result.channel_id)
                        .map_err(loose_proof_error)?;
                    let expiry_timestamp = {
                        let bridge = self.bridge.lock().map_err(|_| {
                            WalletError::Backend("bridge mutex poisoned".to_string())
                        })?;
                        let funding = bridge
                            .get_channel_funding(&open_result.channel_id)
                            .ok_or_else(|| {
                                WalletError::Backend(format!(
                                    "recovered channel {} has no funding data",
                                    open_result.channel_id
                                ))
                            })?;
                        expiry_from_params_json(&funding.params_json)?
                    };
                    self.store_open_channel_metadata(
                        &open_result,
                        &recovery.reservation_id,
                        expiry_timestamp,
                    )?;
                    self.delete_opening_recovery(&recovery.channel_id)?;
                    recovered.push(open_result.channel_id);
                }
                Err(error) if !error.input_may_be_spent => {
                    let _ = self
                        .loose_wallet
                        .release_reservation(&recovery.reservation_id);
                    self.delete_opening_recovery(&recovery.channel_id)?;
                }
                Err(error) => {
                    return Err(open_channel_error(
                        error,
                        &recovery.unit,
                        recovery.input_budget_msats,
                    ));
                }
            }
        }

        Ok(recovered)
    }

    fn recover_pending_opening(
        &self,
        channel_id: &str,
        networking: &ReqwestClientNetworking,
    ) -> Result<OpenChannelResult, OpenChannelError> {
        let prepared = {
            let bridge = self.bridge.lock().map_err(|_| {
                open_channel_stage_error(
                    OpenChannelFailureStage::BeforeOpeningSaved,
                    Some(channel_id.to_string()),
                    "bridge mutex poisoned".to_string(),
                )
            })?;
            bridge.prepare_open_channel_recovery(channel_id)?
        };

        let funding_restore_response = networking
            .call_mint_restore(&prepared.mint_url, &prepared.funding_restore_request_json)
            .map_err(|e| {
                open_channel_stage_error(
                    OpenChannelFailureStage::RestoreVerification,
                    Some(prepared.channel_id.clone()),
                    e,
                )
            })?;
        let change_restore_response = match prepared.change_restore_request_json.as_ref() {
            Some(request) => Some(
                networking
                    .call_mint_restore(&prepared.mint_url, request)
                    .map_err(|e| {
                        open_channel_stage_error(
                            OpenChannelFailureStage::RestoreVerification,
                            Some(prepared.channel_id.clone()),
                            e,
                        )
                    })?,
            ),
            None => None,
        };

        let completed = {
            let bridge = self.bridge.lock().map_err(|_| {
                open_channel_stage_error(
                    OpenChannelFailureStage::RestoreVerification,
                    Some(prepared.channel_id.clone()),
                    "bridge mutex poisoned".to_string(),
                )
            })?;
            let completed = bridge.complete_prepared_open_recovery(
                &prepared,
                &funding_restore_response,
                change_restore_response.as_deref(),
            )?;
            bridge.mark_completed_open_recovery(&completed)?;
            completed
        };

        Ok(completed.result)
    }

    fn conn(&self) -> Result<std::sync::MutexGuard<'_, Connection>, WalletError> {
        self.channel_db
            .lock()
            .map_err(|_| WalletError::Backend("channel db mutex poisoned".to_string()))
    }

    fn mark_channel_metadata_closed(&self, channel_id: &str) -> Result<(), WalletError> {
        let now = Self::now_seconds()?;
        let conn = self.conn()?;
        conn.execute(
            "UPDATE monad_client_channels
             SET state = ?2, attached_session_id = NULL, updated_at = ?3
             WHERE channel_id = ?1",
            params![
                channel_id,
                channel_state_str(WalletChannelState::Closed),
                to_i64(now)?
            ],
        )
        .map_err(|e| WalletError::Backend(format!("mark channel closed: {e}")))?;
        Ok(())
    }

    fn load_channel_recovery_row(
        &self,
        channel_id: &str,
    ) -> Result<Option<ChannelRecoveryRow>, WalletError> {
        let conn = self.conn()?;
        let row = conn
            .query_row(
                "SELECT status, kind, prepared_refund_json, recovered_amount_raw, recovered_proof_count
                 FROM monad_client_channel_recoveries
                 WHERE channel_id = ?1",
                params![channel_id],
                |row| {
                    let status = row.get::<_, String>(0)?;
                    Ok(ChannelRecoveryRow {
                        status: ChannelRecoveryStatus::from_db(&status).map_err(|e| {
                            rusqlite::Error::FromSqlConversionFailure(
                                0,
                                rusqlite::types::Type::Text,
                                Box::new(e),
                            )
                        })?,
                        prepared_refund_json: row.get::<_, Option<String>>(2)?,
                    })
                },
            )
            .optional()
            .map_err(|e| WalletError::Backend(format!("query channel recovery row: {e}")))?;
        Ok(row)
    }

    fn prepared_refund_from_recovery_row(
        &self,
        row: &ChannelRecoveryRow,
    ) -> Result<Option<PreparedSenderRefund>, WalletError> {
        let Some(prepared_json) = row.prepared_refund_json.as_ref() else {
            if row.status == ChannelRecoveryStatus::Submitting {
                return Err(WalletError::Backend(
                    "submitting refund recovery is missing prepared refund json".to_string(),
                ));
            }
            return Ok(None);
        };

        PreparedSenderRefund::from_json(prepared_json)
            .map(Some)
            .map_err(|e| WalletError::Backend(format!("decode prepared refund: {e}")))
    }

    fn completed_channel_recovery(
        &self,
        channel_id: &str,
    ) -> Result<Option<ChannelFundRecoveryResult>, WalletError> {
        let conn = self.conn()?;
        let row = conn
            .query_row(
                "SELECT kind, recovered_amount_raw, recovered_proof_count
                 FROM monad_client_channel_recoveries
                 WHERE channel_id = ?1 AND status = 'completed'",
                params![channel_id],
                |row| {
                    Ok((
                        row.get::<_, String>(0)?,
                        from_i64(row.get::<_, i64>(1)?)?,
                        from_i64(row.get::<_, i64>(2)?)?,
                    ))
                },
            )
            .optional()
            .map_err(|e| WalletError::Backend(format!("query completed recovery: {e}")))?;

        Ok(
            row.map(|(kind, recovered_amount_raw, recovered_proof_count)| {
                ChannelFundRecoveryResult::AlreadyRecovered {
                    channel_id: channel_id.to_string(),
                    kind,
                    recovered_amount_raw,
                    recovered_proof_count: recovered_proof_count as usize,
                }
            }),
        )
    }

    fn prepare_and_persist_refund_recovery(
        &self,
        channel_id: &str,
        established: &EstablishedChannel,
        now: u64,
    ) -> Result<PreparedSenderRefund, WalletError> {
        let prepared = established
            .prepare_sender_refund_after_expiry(self.sender_secret.clone(), now)
            .map_err(|e| WalletError::Backend(format!("prepare sender refund: {e}")))?;
        self.persist_refund_recovery_prepared(channel_id, &prepared)?;
        Ok(prepared)
    }

    fn persist_refund_recovery_prepared(
        &self,
        channel_id: &str,
        prepared: &PreparedSenderRefund,
    ) -> Result<(), WalletError> {
        let now = Self::now_seconds()?;
        let prepared_json = prepared
            .to_json()
            .map_err(|e| WalletError::Backend(format!("encode prepared refund: {e}")))?;
        let conn = self.conn()?;
        conn.execute(
            "INSERT INTO monad_client_channel_recoveries
             (channel_id, kind, status, recovered_amount_raw, recovered_proof_count, prepared_refund_json, created_at, updated_at)
             VALUES (?1, 'post_expiry_refund', 'prepared', NULL, NULL, ?2, ?3, ?3)
             ON CONFLICT(channel_id) DO UPDATE SET
                kind = 'post_expiry_refund',
                status = CASE
                    WHEN monad_client_channel_recoveries.status = 'completed' THEN monad_client_channel_recoveries.status
                    WHEN monad_client_channel_recoveries.status = 'submitting' THEN monad_client_channel_recoveries.status
                    ELSE 'prepared'
                END,
                prepared_refund_json = CASE
                    WHEN monad_client_channel_recoveries.status = 'completed' THEN monad_client_channel_recoveries.prepared_refund_json
                    ELSE excluded.prepared_refund_json
                END,
                updated_at = excluded.updated_at",
            params![channel_id, prepared_json, to_i64(now)?],
        )
        .map_err(|e| WalletError::Backend(format!("insert channel recovery: {e}")))?;
        Ok(())
    }

    fn mark_refund_recovery_submitting(&self, channel_id: &str) -> Result<(), WalletError> {
        let now = Self::now_seconds()?;
        let conn = self.conn()?;
        conn.execute(
            "INSERT INTO monad_client_channel_recoveries
             (channel_id, kind, status, recovered_amount_raw, recovered_proof_count, prepared_refund_json, created_at, updated_at)
             VALUES (?1, 'post_expiry_refund', 'submitting', NULL, NULL, NULL, ?2, ?2)
             ON CONFLICT(channel_id) DO UPDATE SET
                kind = 'post_expiry_refund',
                status = CASE
                    WHEN monad_client_channel_recoveries.status = 'completed' THEN monad_client_channel_recoveries.status
                    ELSE 'submitting'
                END,
                updated_at = excluded.updated_at",
            params![channel_id, to_i64(now)?],
        )
        .map_err(|e| WalletError::Backend(format!("mark refund submitting: {e}")))?;
        Ok(())
    }

    fn complete_channel_recovery(
        &self,
        channel_id: &str,
        funding: &ClientChannelFunding,
        kind: &str,
        proofs: Vec<Proof>,
        full_refund: bool,
    ) -> Result<ChannelFundRecoveryResult, WalletError> {
        let recovered_amount_raw = proofs.iter().try_fold(0u64, |total, proof| {
            total
                .checked_add(u64::from(proof.amount))
                .ok_or_else(|| WalletError::Backend("recovered proof total overflow".to_string()))
        })?;
        let recovered_proof_count = proofs.len();
        let loose_proofs = proofs
            .iter()
            .map(|proof| proof_to_new_loose_proof(proof, funding))
            .collect::<Result<Vec<_>, WalletError>>()?;
        #[cfg(test)]
        if self
            .fail_next_recovered_proof_import
            .swap(false, Ordering::SeqCst)
        {
            return Err(WalletError::Backend(
                "injected recovered proof import failure".to_string(),
            ));
        }
        self.loose_wallet
            .import_proofs(&loose_proofs)
            .map_err(loose_proof_error)?;
        {
            let bridge = self
                .bridge
                .lock()
                .map_err(|_| WalletError::Backend("bridge mutex poisoned".to_string()))?;
            bridge
                .close_channel(channel_id)
                .map_err(|e| WalletError::Backend(format!("mark upstream channel closed: {e}")))?;
        }
        self.mark_channel_metadata_closed(channel_id)?;
        self.mark_channel_recovery_completed(
            channel_id,
            kind,
            recovered_amount_raw,
            recovered_proof_count,
        )?;

        if full_refund {
            Ok(ChannelFundRecoveryResult::PostExpiryRefundRecovered {
                channel_id: channel_id.to_string(),
                recovered_amount_raw,
                recovered_proof_count,
            })
        } else {
            Ok(ChannelFundRecoveryResult::RelayCloseRecovered {
                channel_id: channel_id.to_string(),
                recovered_amount_raw,
                recovered_proof_count,
            })
        }
    }

    fn mark_channel_recovery_completed(
        &self,
        channel_id: &str,
        kind: &str,
        recovered_amount_raw: u64,
        recovered_proof_count: usize,
    ) -> Result<(), WalletError> {
        let now = Self::now_seconds()?;
        let conn = self.conn()?;
        conn.execute(
            "INSERT INTO monad_client_channel_recoveries
             (channel_id, kind, status, recovered_amount_raw, recovered_proof_count, completed_at, created_at, updated_at)
             VALUES (?1, ?2, 'completed', ?3, ?4, ?5, ?5, ?5)
             ON CONFLICT(channel_id) DO UPDATE SET
                kind = excluded.kind,
                status = 'completed',
                recovered_amount_raw = excluded.recovered_amount_raw,
                recovered_proof_count = excluded.recovered_proof_count,
                completed_at = excluded.completed_at,
                updated_at = excluded.updated_at",
            params![
                channel_id,
                kind,
                to_i64(recovered_amount_raw)?,
                to_i64(recovered_proof_count as u64)?,
                to_i64(now)?,
            ],
        )
        .map_err(|e| WalletError::Backend(format!("mark channel recovery completed: {e}")))?;
        Ok(())
    }

    fn store_open_channel_metadata(
        &self,
        open_result: &OpenChannelResult,
        reservation_id: &str,
        expiry_timestamp: u64,
    ) -> Result<(), WalletError> {
        // Store the actual upstream capacity, not the input budget.
        let capacity_msats = raw_to_msats(&open_result.unit, open_result.capacity)
            .map_err(|e| WalletError::Backend(format!("convert capacity to msats: {e}")))?;
        let now = Self::now_seconds()?;
        let conn = self.conn()?;
        conn.execute(
            "INSERT INTO monad_client_channels
             (channel_id, receiver_pubkey, mint_url, unit, keyset_id,
              capacity_msats, attached_session_id, state, reservation_id,
              expiry_timestamp, created_at, updated_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, NULL, ?7, ?8, ?9, ?10, ?10)",
            params![
                open_result.channel_id,
                open_result.receiver_pubkey_hex,
                open_result.mint_url,
                open_result.unit,
                open_result.keyset_id,
                to_i64(capacity_msats)?,
                channel_state_str(WalletChannelState::Open),
                reservation_id,
                to_i64(expiry_timestamp)?,
                to_i64(now)?,
            ],
        )
        .map_err(|e| WalletError::Backend(format!("insert channel metadata: {e}")))?;
        Ok(())
    }

    fn store_opening_recovery(
        &self,
        channel_id: &str,
        reservation_id: &str,
        offer: &RelayPaymentOffer,
        input_budget_msats: u64,
        error: &OpenChannelError,
    ) -> Result<(), WalletError> {
        let now = Self::now_seconds()?;
        let conn = self.conn()?;
        conn.execute(
            "INSERT INTO monad_client_channel_opening_recoveries
             (channel_id, reservation_id, receiver_pubkey, mint_url, unit,
              input_budget_msats, error_stage, error_message, created_at, updated_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?9)
             ON CONFLICT(channel_id) DO UPDATE SET
                reservation_id = excluded.reservation_id,
                receiver_pubkey = excluded.receiver_pubkey,
                mint_url = excluded.mint_url,
                unit = excluded.unit,
                input_budget_msats = excluded.input_budget_msats,
                error_stage = excluded.error_stage,
                error_message = excluded.error_message,
                updated_at = excluded.updated_at",
            params![
                channel_id,
                reservation_id,
                offer.receiver_pubkey,
                offer.mint_url,
                offer.unit,
                to_i64(input_budget_msats)?,
                format!("{:?}", error.stage),
                error.message,
                to_i64(now)?,
            ],
        )
        .map_err(|e| WalletError::Backend(format!("store opening recovery: {e}")))?;
        Ok(())
    }

    fn list_opening_recoveries(&self) -> Result<Vec<OpeningRecovery>, WalletError> {
        let conn = self.conn()?;
        let mut stmt = conn
            .prepare(
                "SELECT channel_id, reservation_id, unit, input_budget_msats
                 FROM monad_client_channel_opening_recoveries
                 ORDER BY created_at ASC",
            )
            .map_err(|e| WalletError::Backend(format!("prepare opening recoveries: {e}")))?;
        let mut rows = stmt
            .query([])
            .map_err(|e| WalletError::Backend(format!("query opening recoveries: {e}")))?;
        let mut out = Vec::new();
        while let Some(row) = rows
            .next()
            .map_err(|e| WalletError::Backend(format!("read opening recovery row: {e}")))?
        {
            out.push(OpeningRecovery {
                channel_id: row.get(0).map_err(|e| {
                    WalletError::Backend(format!("decode recovery channel_id: {e}"))
                })?,
                reservation_id: row.get(1).map_err(|e| {
                    WalletError::Backend(format!("decode recovery reservation_id: {e}"))
                })?,
                unit: row
                    .get(2)
                    .map_err(|e| WalletError::Backend(format!("decode recovery unit: {e}")))?,
                input_budget_msats: from_i64(row.get(3).map_err(|e| {
                    WalletError::Backend(format!("decode recovery input budget: {e}"))
                })?)
                .map_err(|e| WalletError::Backend(format!("decode recovery input budget: {e}")))?,
            });
        }
        Ok(out)
    }

    fn delete_opening_recovery(&self, channel_id: &str) -> Result<(), WalletError> {
        let conn = self.conn()?;
        conn.execute(
            "DELETE FROM monad_client_channel_opening_recoveries WHERE channel_id = ?1",
            params![channel_id],
        )
        .map_err(|e| WalletError::Backend(format!("delete opening recovery: {e}")))?;
        Ok(())
    }

    fn now_seconds() -> Result<u64, WalletError> {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .map_err(|e| WalletError::Backend(format!("system time before unix epoch: {e}")))
    }

    fn submit_open_attempt(
        &self,
        offer: &RelayPaymentOffer,
        attempt: &ClientOpenAttempt,
    ) -> Result<OpenChannelResult, OpenChannelError> {
        self.submit_reserved_channel(
            offer,
            &attempt.output_keyset.info_json,
            &attempt.reservation,
            attempt.requested_capacity_raw,
            attempt.desired_funding_token_amount_raw,
            attempt.expiry_timestamp,
        )
    }

    fn submit_reserved_channel(
        &self,
        offer: &RelayPaymentOffer,
        output_keyset_info_json: &str,
        reservation: &ProofReservation,
        requested_capacity_raw: Option<u64>,
        desired_funding_token_amount_raw: Option<u64>,
        expiry_timestamp: u64,
    ) -> Result<OpenChannelResult, OpenChannelError> {
        let input_proofs_json = match proofs_json_from_reservation(reservation) {
            Ok(json) => json,
            Err(e) => {
                return Err(open_channel_stage_error(
                    OpenChannelFailureStage::BeforeOpeningSaved,
                    None,
                    e.to_string(),
                ));
            }
        };

        let networking = ReqwestClientNetworking::new();
        let input_keyset_lookup = {
            let bridge = self.bridge.lock().map_err(|_| {
                open_channel_stage_error(
                    OpenChannelFailureStage::BeforeOpeningSaved,
                    None,
                    "bridge mutex poisoned".to_string(),
                )
            })?;
            proof_input_keysets_from_cache(&bridge, &offer.mint_url, &offer.unit, reservation)?
        };
        let input_keysets_json =
            proof_input_keysets_json(input_keyset_lookup, &offer.mint_url, &networking)?;

        let prepared = {
            let bridge = self.bridge.lock().map_err(|_| {
                open_channel_stage_error(
                    OpenChannelFailureStage::BeforeOpeningSaved,
                    None,
                    "bridge mutex poisoned".to_string(),
                )
            })?;
            let prepared = bridge.prepare_open_channel_from_proofs_with_input_keysets(
                &offer.mint_url,
                &offer.unit,
                &input_proofs_json,
                &input_keysets_json,
                &offer.receiver_pubkey,
                &self.sender_pubkey_hex,
                expiry_timestamp,
                output_keyset_info_json,
                0,
                requested_capacity_raw,
                desired_funding_token_amount_raw,
            )?;
            bridge.mark_prepared_open_saved(&prepared)?;
            prepared
        };

        self.submit_prepared_open(prepared, &networking)
    }

    fn submit_prepared_open(
        &self,
        prepared: PreparedOpenChannel,
        networking: &ReqwestClientNetworking,
    ) -> Result<OpenChannelResult, OpenChannelError> {
        let swap_response_json = networking
            .call_mint_swap(&prepared.mint_url, &prepared.swap_request_json)
            .map_err(|e| {
                let message = normalize_mint_error_string(e);
                if cdk_spilman::extract_nut00_error_code(&message).is_some() {
                    return self
                        .mark_prepared_open_rejected(&prepared, message)
                        .unwrap_or_else(|error| error);
                }
                open_channel_stage_error(
                    OpenChannelFailureStage::SwapSubmitted,
                    Some(prepared.channel_id.clone()),
                    message,
                )
            })?;

        let completed = {
            let bridge = self.bridge.lock().map_err(|_| {
                open_channel_stage_error(
                    OpenChannelFailureStage::FundingProofsReceived,
                    Some(prepared.channel_id.clone()),
                    "bridge mutex poisoned".to_string(),
                )
            })?;
            bridge.complete_prepared_open_channel(&prepared, &swap_response_json)?
        };

        self.verify_prepared_open_restore(&prepared, &completed, networking)?;

        {
            let bridge = self.bridge.lock().map_err(|_| {
                open_channel_stage_error(
                    OpenChannelFailureStage::MarkOpen,
                    Some(prepared.channel_id.clone()),
                    "bridge mutex poisoned".to_string(),
                )
            })?;
            bridge.mark_completed_open(&completed)?;
        }

        Ok(completed.result)
    }

    fn mark_prepared_open_rejected(
        &self,
        prepared: &PreparedOpenChannel,
        message: String,
    ) -> Result<OpenChannelError, OpenChannelError> {
        let bridge = self.bridge.lock().map_err(|_| {
            open_channel_stage_error(
                OpenChannelFailureStage::MarkOpen,
                Some(prepared.channel_id.clone()),
                format!("bridge mutex poisoned while marking mint rejection: {message}"),
            )
        })?;
        bridge.mark_prepared_open_rejected(prepared, message)
    }

    fn verify_prepared_open_restore(
        &self,
        prepared: &PreparedOpenChannel,
        completed: &CompletedOpenChannel,
        networking: &ReqwestClientNetworking,
    ) -> Result<(), OpenChannelError> {
        let restore_request = {
            let bridge = self.bridge.lock().map_err(|_| {
                open_channel_stage_error(
                    OpenChannelFailureStage::RestoreVerification,
                    Some(prepared.channel_id.clone()),
                    "bridge mutex poisoned".to_string(),
                )
            })?;
            bridge.funding_restore_request_for_prepared_open(prepared)?
        };

        let restore_response = networking
            .call_mint_restore(&prepared.mint_url, &restore_request)
            .map_err(|e| {
                open_channel_stage_error(
                    OpenChannelFailureStage::RestoreVerification,
                    Some(prepared.channel_id.clone()),
                    e,
                )
            })?;

        let bridge = self.bridge.lock().map_err(|_| {
            open_channel_stage_error(
                OpenChannelFailureStage::RestoreVerification,
                Some(prepared.channel_id.clone()),
                "bridge mutex poisoned".to_string(),
            )
        })?;
        let restored_proofs_json =
            bridge.complete_funding_restore_for_prepared_open(prepared, &restore_response)?;
        bridge.verify_completed_open_matches_restore(completed, &restored_proofs_json)
    }

    fn finish_open_channel(
        &self,
        open_result: OpenChannelResult,
        reservation: &ProofReservation,
        expiry_timestamp: u64,
    ) -> Result<String, WalletError> {
        self.loose_wallet
            .import_proofs(&change_proofs_to_loose_proofs(&open_result)?)
            .map_err(loose_proof_error)?;
        self.loose_wallet
            .mark_reservation_spent(&reservation.reservation_id, &open_result.channel_id)
            .map_err(loose_proof_error)?;
        self.store_open_channel_metadata(
            &open_result,
            &reservation.reservation_id,
            expiry_timestamp,
        )?;
        Ok(open_result.channel_id)
    }

    fn handle_open_error(
        &self,
        error: OpenChannelError,
        reservation: &ProofReservation,
        offer: &RelayPaymentOffer,
        recovery_input_budget_msats: u64,
    ) -> Result<String, WalletError> {
        if error.input_may_be_spent {
            if let Some(channel_id) = error.channel_id.as_deref() {
                self.store_opening_recovery(
                    channel_id,
                    &reservation.reservation_id,
                    offer,
                    recovery_input_budget_msats,
                    &error,
                )?;
            }
        } else {
            let _ = self
                .loose_wallet
                .release_reservation(&reservation.reservation_id);
        }
        Err(open_channel_error(
            error,
            &offer.unit,
            recovery_input_budget_msats,
        ))
    }

    fn refresh_client_keysets(&self, offer: &RelayPaymentOffer) -> Result<(), WalletError> {
        let bridge = self
            .bridge
            .lock()
            .map_err(|_| WalletError::Backend("bridge mutex poisoned".to_string()))?;
        bridge
            .refresh_keysets_response(&offer.mint_url)
            .map(|_| ())
            .map_err(|e| WalletError::Backend(format!("refresh mint keysets: {e}")))
    }

    fn ensure_offer_keysets_cached(&self, offer: &RelayPaymentOffer) -> Result<(), WalletError> {
        let unit = parse_currency_unit(&offer.unit)?;
        let has_cached_keysets = {
            let bridge = self
                .bridge
                .lock()
                .map_err(|_| WalletError::Backend("bridge mutex poisoned".to_string()))?;
            !bridge
                .cached_keysets_for_unit(&offer.mint_url, &unit)
                .is_empty()
        };
        if !has_cached_keysets {
            self.refresh_client_keysets(offer)?;
        }
        Ok(())
    }

    fn select_output_keyset_refreshing_client_first(
        &self,
        offer: &RelayPaymentOffer,
    ) -> Result<SelectedOutputKeyset, WalletError> {
        match self.select_output_keyset_from_cache(offer)? {
            OutputKeysetSelection::Selected(output_keyset) => return Ok(output_keyset),
            OutputKeysetSelection::NoActiveAcceptedKeyset => {}
        }

        self.refresh_client_keysets(offer)?;
        match self.select_output_keyset_from_cache(offer)? {
            OutputKeysetSelection::Selected(output_keyset) => Ok(output_keyset),
            OutputKeysetSelection::NoActiveAcceptedKeyset => Err(WalletError::StaleRelayKeysets {
                mint_url: offer.mint_url.clone(),
                unit: offer.unit.clone(),
                accepted_keyset_ids: offer.accepted_keyset_ids.clone(),
            }),
        }
    }

    fn select_output_keyset_from_cache(
        &self,
        offer: &RelayPaymentOffer,
    ) -> Result<OutputKeysetSelection<SelectedOutputKeyset>, WalletError> {
        let bridge = self
            .bridge
            .lock()
            .map_err(|_| WalletError::Backend("bridge mutex poisoned".to_string()))?;
        let output_keyset_id = match active_output_keyset_id_from_cache(&bridge, offer)? {
            OutputKeysetSelection::Selected(output_keyset_id) => output_keyset_id,
            OutputKeysetSelection::NoActiveAcceptedKeyset => {
                return Ok(OutputKeysetSelection::NoActiveAcceptedKeyset);
            }
        };
        let info_json = cached_keyset_info_json(&bridge, &offer.mint_url, &output_keyset_id)?;
        Ok(OutputKeysetSelection::Selected(SelectedOutputKeyset {
            id: output_keyset_id,
            info_json,
        }))
    }

    fn prepare_target_capacity_attempt(
        &self,
        offer: &RelayPaymentOffer,
        target_capacity_raw: u64,
        output_keyset: SelectedOutputKeyset,
        expiry_timestamp: u64,
    ) -> Result<ClientOpenAttempt, WalletError> {
        let required_post_swap_raw =
            compute_funding_token_amount(target_capacity_raw, &output_keyset.info_json, 0)
                .map_err(|e| {
                    WalletError::Backend(format!("compute required funding amount: {e}"))
                })?;

        let available_proofs = self
            .loose_wallet
            .list_available_proofs(&offer.mint_url, &offer.unit, &[])
            .map_err(loose_proof_error)?;
        let input_fee_by_keyset = {
            let bridge = self
                .bridge
                .lock()
                .map_err(|_| WalletError::Backend("bridge mutex poisoned".to_string()))?;
            let mut out = HashMap::new();
            for proof in &available_proofs {
                if out.contains_key(&proof.keyset_id) {
                    continue;
                }
                let keyset_info_json =
                    cached_keyset_info_json(&bridge, &offer.mint_url, &proof.keyset_id)?;
                let keyset_info = parse_keyset_info_from_json(&keyset_info_json).map_err(|e| {
                    WalletError::Backend(format!(
                        "parse cached keyset info for {}: {e}",
                        proof.keyset_id
                    ))
                })?;
                out.insert(proof.keyset_id.clone(), keyset_info.input_fee_ppk);
            }
            out
        };

        let candidates = available_proofs
            .iter()
            .map(|proof| {
                let input_fee_ppk = input_fee_by_keyset
                    .get(&proof.keyset_id)
                    .copied()
                    .ok_or_else(|| {
                        WalletError::Backend(format!(
                            "missing input fee for keyset {}",
                            proof.keyset_id
                        ))
                    })?;
                Ok(ProofCandidate {
                    proof_id: proof.proof_id.clone(),
                    amount_raw: proof.amount_raw,
                    input_fee_ppk,
                })
            })
            .collect::<Result<Vec<_>, WalletError>>()?;
        let selection =
            select_mixed_fee_inputs_for_post_swap_target(candidates, required_post_swap_raw)
                .map_err(|e| WalletError::Backend(format!("select loose proofs: {e}")))?;

        let reservation = self
            .loose_wallet
            .reserve_selected_proofs(&offer.mint_url, &offer.unit, &selection.proof_ids)
            .map_err(loose_proof_error)?;
        let selected_input_msats = raw_to_msats(&offer.unit, reservation.total_amount_raw)?;

        Ok(ClientOpenAttempt {
            output_keyset,
            reservation,
            requested_capacity_raw: Some(target_capacity_raw),
            desired_funding_token_amount_raw: Some(required_post_swap_raw),
            selected_input_msats,
            expiry_timestamp,
        })
    }
}

impl MonadWallet for SqliteClientWallet {
    fn list_channels(&self) -> Result<Vec<WalletChannel>, WalletError> {
        let conn = self.conn()?;
        let mut stmt = conn
            .prepare(
                "SELECT channel_id, receiver_pubkey, mint_url, unit, keyset_id,
                        capacity_msats, attached_session_id, state, expiry_timestamp
                 FROM monad_client_channels
                 ORDER BY created_at ASC",
            )
            .map_err(|e| WalletError::Backend(format!("prepare list channels: {e}")))?;
        let mut rows = stmt
            .query([])
            .map_err(|e| WalletError::Backend(format!("query channels: {e}")))?;
        let mut channels = Vec::new();
        while let Some(row) = rows
            .next()
            .map_err(|e| WalletError::Backend(format!("read channel row: {e}")))?
        {
            channels.push(self.row_to_wallet_channel(&conn, row)?);
        }
        Ok(channels)
    }

    fn get_channel(&self, channel_id: &str) -> Result<WalletChannel, WalletError> {
        let conn = self.conn()?;
        let meta = conn
            .query_row(
                "SELECT channel_id, receiver_pubkey, mint_url, unit, keyset_id,
                        capacity_msats, attached_session_id, state, expiry_timestamp
                 FROM monad_client_channels
                 WHERE channel_id = ?1",
                params![channel_id],
                row_to_channel_meta,
            )
            .map_err(|e| match e {
                rusqlite::Error::QueryReturnedNoRows => WalletError::NotFound,
                _ => WalletError::Backend(format!("query channel: {e}")),
            })?;
        self.meta_to_wallet_channel(&conn, meta)
    }

    fn attach_channel_to_session(
        &self,
        channel_id: &str,
        session_id: [u8; 32],
    ) -> Result<(), WalletError> {
        let channel = self.get_channel(channel_id)?;
        if channel.state != WalletChannelState::Open {
            return Err(WalletError::NotOpen);
        }
        if let Some(current) = channel.attached_session_id {
            if current != session_id {
                return Err(WalletError::AttachedToDifferentSession { current });
            }
            return Ok(());
        }

        let now = Self::now_seconds()?;
        let session_hex = hex::encode(session_id);
        let conn = self.conn()?;
        let updated = conn
            .execute(
                "UPDATE monad_client_channels
                 SET attached_session_id = ?2, updated_at = ?3
                 WHERE channel_id = ?1 AND attached_session_id IS NULL",
                params![channel_id, session_hex, to_i64(now)?],
            )
            .map_err(|e| WalletError::Backend(format!("attach channel: {e}")))?;
        if updated != 1 {
            return Err(WalletError::Backend(
                "channel was concurrently attached".to_string(),
            ));
        }
        Ok(())
    }

    fn detach_channel_from_session(
        &self,
        channel_id: &str,
        session_id: [u8; 32],
    ) -> Result<(), WalletError> {
        let session_hex = hex::encode(session_id);
        let now = Self::now_seconds()?;
        let conn = self.conn()?;
        conn.execute(
            "UPDATE monad_client_channels
             SET attached_session_id = NULL, updated_at = ?3
             WHERE channel_id = ?1 AND attached_session_id = ?2",
            params![channel_id, session_hex, to_i64(now)?],
        )
        .map_err(|e| WalletError::Backend(format!("detach channel: {e}")))?;
        Ok(())
    }

    fn force_detach_channel(&self, channel_id: &str) -> Result<(), WalletError> {
        let now = Self::now_seconds()?;
        let conn = self.conn()?;
        conn.execute(
            "UPDATE monad_client_channels
             SET attached_session_id = NULL, updated_at = ?2
             WHERE channel_id = ?1",
            params![channel_id, to_i64(now)?],
        )
        .map_err(|e| WalletError::Backend(format!("force detach channel: {e}")))?;
        Ok(())
    }

    fn mark_channel_unusable(&self, channel_id: &str) -> Result<(), WalletError> {
        let now = Self::now_seconds()?;
        let conn = self.conn()?;
        conn.execute(
            "UPDATE monad_client_channels
             SET state = ?2, attached_session_id = NULL, updated_at = ?3
             WHERE channel_id = ?1",
            params![
                channel_id,
                channel_state_str(WalletChannelState::Closing),
                to_i64(now)?
            ],
        )
        .map_err(|e| WalletError::Backend(format!("mark channel unusable: {e}")))?;
        Ok(())
    }

    fn provision_channel(
        &self,
        offer: &RelayPaymentOffer,
        input_budget_msats: u64,
    ) -> Result<String, WalletError> {
        // Arbitrary Input Model: `input_budget_msats` is the loose-proof value
        // the caller is willing to commit. Upstream constructs the channel from
        // these proofs and returns the actual usable capacity, which may be lower
        // after Cashu input/output fees are applied.
        if offer.accepted_keyset_ids.is_empty() {
            return Err(WalletError::OfferMismatch(
                "offer has no accepted keysets".to_string(),
            ));
        }

        self.ensure_offer_keysets_cached(offer)?;
        let input_budget_raw = msats_to_raw_units(&offer.unit, input_budget_msats)?;
        let expiry_timestamp = Self::now_seconds()? + CHANNEL_EXPIRY_SECONDS;
        let mut reservation: Option<ProofReservation> = None;
        // Plain provisioning uses an input budget rather than an exact target
        // capacity.  We reserve an arbitrary set of available proofs once, then
        // let upstream compute the resulting channel capacity.  If the mint
        // rejects the first open because our cached output keyset is stale, the
        // input reservation can be reused: only the output keyset selection and
        // swap construction need to change. Selection refreshes the client cache
        // before reporting a stale relay offer; the retry helper handles the
        // mint-rejection refresh path and skips retry when refresh still selects
        // the same keyset.
        let result = with_active_keyset_retry(
            // Select an active relay-accepted output keyset, refreshing the
            // client cache before reporting a stale relay offer.
            || self.select_output_keyset_refreshing_client_first(offer),
            // Prepare lazily creates the proof reservation on the first attempt;
            // on retry, it reuses the same reserved proofs with the refreshed
            // output keyset.
            |output_keyset| {
                let reservation = match reservation.as_ref() {
                    Some(reservation) => reservation.clone(),
                    None => {
                        let new_reservation = self
                            .loose_wallet
                            .reserve_proofs_any_keyset(
                                &offer.mint_url,
                                &offer.unit,
                                input_budget_raw,
                            )
                            .map_err(loose_proof_error)?;
                        reservation = Some(new_reservation.clone());
                        new_reservation
                    }
                };
                Ok(ClientOpenAttempt {
                    output_keyset,
                    reservation,
                    requested_capacity_raw: None,
                    desired_funding_token_amount_raw: Some(input_budget_raw),
                    selected_input_msats: input_budget_msats,
                    expiry_timestamp,
                })
            },
            // Submit the upstream open-channel swap for this reservation.
            |attempt| self.submit_open_attempt(offer, attempt),
            // Retry only safe keyset rejections.
            |error| should_retry_open_after_keyset_rejection(error, false),
            // Refresh keyset cache before reselecting the output keyset.
            || self.refresh_client_keysets(offer),
            // No cleanup here: the same reservation is reused across a changed
            // keyset retry, and final error handling releases it if no open
            // succeeds.
            |_attempt, _error| Ok(()),
        );
        match result {
            Ok(success) => self.finish_open_channel(
                success.value,
                &success.attempt.reservation,
                success.attempt.expiry_timestamp,
            ),
            Err(KeysetRetryError::Submit { attempt, error, .. }) => self.handle_open_error(
                error,
                &attempt.reservation,
                offer,
                attempt.selected_input_msats,
            ),
            Err(KeysetRetryError::RetryKeysetUnchanged { attempt, error, .. }) => self
                .handle_open_error(
                    error,
                    &attempt.reservation,
                    offer,
                    attempt.selected_input_msats,
                ),
            Err(KeysetRetryError::Select {
                error: WalletError::StaleRelayKeysets { .. },
                ..
            }) => Err(WalletError::StaleRelayKeysets {
                mint_url: offer.mint_url.clone(),
                unit: offer.unit.clone(),
                accepted_keyset_ids: offer.accepted_keyset_ids.clone(),
            }),
            Err(error) => Err(WalletError::Backend(format!(
                "prepare channel open retry: {}",
                describe_keyset_retry_prepare_error(error)
            ))),
        }
    }

    fn build_link_request(
        &self,
        channel_id: &str,
        offer: &RelayPaymentOffer,
    ) -> Result<String, WalletError> {
        let channel = self.get_channel(channel_id)?;
        ensure_channel_matches_offer(&channel, offer)?;
        if channel.state != WalletChannelState::Open {
            return Err(WalletError::NotOpen);
        }
        if channel.attached_session_id.is_none() {
            return Err(WalletError::Backend(
                "channel must be attached before linking".to_string(),
            ));
        }

        let payment = {
            let bridge = self
                .bridge
                .lock()
                .map_err(|_| WalletError::Backend("bridge mutex poisoned".to_string()))?;
            bridge
                .sign_channel_registration(channel_id)
                .map_err(|e| map_create_payment_error(&channel, e, 0))?
        };
        serde_json::to_string(&payment)
            .map_err(|e| WalletError::Backend(format!("serialize link payment: {e}")))
    }

    fn build_channel_payment(
        &self,
        channel_id: &str,
        offer: &RelayPaymentOffer,
        _latest_server_balance_raw: u64,
        next_balance_raw: u64,
    ) -> Result<String, WalletError> {
        let channel = self.get_channel(channel_id)?;
        ensure_channel_matches_offer(&channel, offer)?;
        if channel.state != WalletChannelState::Open {
            return Err(WalletError::NotOpen);
        }
        if channel.attached_session_id.is_none() {
            return Err(WalletError::Backend(
                "channel must be attached before payment".to_string(),
            ));
        }

        let payment = {
            let bridge = self
                .bridge
                .lock()
                .map_err(|_| WalletError::Backend("bridge mutex poisoned".to_string()))?;
            let payment = bridge
                .sign_payment(channel_id, next_balance_raw)
                .map_err(|e| map_create_payment_error(&channel, e, next_balance_raw))?;
            let payment_json = serde_json::to_string(&payment)
                .map_err(|e| WalletError::Backend(format!("serialize channel payment: {e}")))?;
            bridge
                .record_signed_payment(&payment)
                .map_err(|e| WalletError::Backend(format!("record signed payment: {e}")))?;
            Ok(payment_json)
        };
        payment
    }
}

impl SqliteClientWallet {
    fn row_to_wallet_channel(
        &self,
        conn: &Connection,
        row: &rusqlite::Row<'_>,
    ) -> Result<WalletChannel, WalletError> {
        let meta = row_to_channel_meta(row)
            .map_err(|e| WalletError::Backend(format!("decode channel row: {e}")))?;
        self.meta_to_wallet_channel(conn, meta)
    }

    fn meta_to_wallet_channel(
        &self,
        _conn: &Connection,
        meta: ChannelMeta,
    ) -> Result<WalletChannel, WalletError> {
        let upstream = upstream_info(&self.bridge, &meta.channel_id);
        let current_balance_raw = upstream.as_ref().map(|i| i.current_balance).unwrap_or(0);
        let current_signed_balance_msats = raw_to_msats(&meta.unit, current_balance_raw)
            .map_err(|e| WalletError::Backend(format!("convert signed balance to msats: {e}")))?;

        let state = if upstream.as_ref().map(|i| i.state).is_some_and(|s| {
            matches!(
                s,
                cdk_spilman::ClientChannelState::Closing | cdk_spilman::ClientChannelState::Closed
            )
        }) {
            WalletChannelState::Closed
        } else {
            meta.state
        };

        Ok(WalletChannel {
            channel_id: meta.channel_id,
            state,
            receiver_pubkey: meta.receiver_pubkey,
            mint_url: meta.mint_url,
            unit: meta.unit,
            keyset_id: meta.keyset_id,
            attached_session_id: meta
                .attached_session_id_hex
                .as_deref()
                .and_then(|hex| hex_to_session_id(hex).ok()),
            capacity_msats: meta.capacity_msats,
            current_signed_balance_msats,
            expiry_timestamp: meta.expiry_timestamp,
        })
    }
}

fn upstream_info(
    bridge: &Mutex<
        SpilmanClientBridge<ConfigurableClientHost<SqliteClientStorage>, ReqwestClientNetworking>,
    >,
    channel_id: &str,
) -> Option<ClientChannelInfo> {
    bridge.lock().ok()?.get_channel_info(channel_id)
}

#[derive(Debug, Clone)]
struct OpeningRecovery {
    channel_id: String,
    reservation_id: String,
    unit: String,
    input_budget_msats: u64,
}

#[derive(Debug, Clone)]
struct ChannelMeta {
    channel_id: String,
    receiver_pubkey: String,
    mint_url: String,
    unit: String,
    keyset_id: String,
    capacity_msats: u64,
    attached_session_id_hex: Option<String>,
    state: WalletChannelState,
    expiry_timestamp: u64,
}

fn row_to_channel_meta(row: &rusqlite::Row<'_>) -> rusqlite::Result<ChannelMeta> {
    Ok(ChannelMeta {
        channel_id: row.get(0)?,
        receiver_pubkey: row.get(1)?,
        mint_url: row.get(2)?,
        unit: row.get(3)?,
        keyset_id: row.get(4)?,
        capacity_msats: from_i64(row.get(5)?)?,
        attached_session_id_hex: row.get(6)?,
        state: parse_channel_state(&row.get::<_, String>(7)?)?,
        expiry_timestamp: from_i64(row.get(8)?)?,
    })
}

fn parse_channel_state(value: &str) -> rusqlite::Result<WalletChannelState> {
    match value {
        "open" => Ok(WalletChannelState::Open),
        "closing" => Ok(WalletChannelState::Closing),
        "closed" => Ok(WalletChannelState::Closed),
        other => Err(sql_decode_error(format!("unknown channel state '{other}'"))),
    }
}

fn channel_state_str(state: WalletChannelState) -> &'static str {
    match state {
        WalletChannelState::Open => "open",
        WalletChannelState::Closing => "closing",
        WalletChannelState::Closed => "closed",
    }
}

fn hex_to_session_id(hex: &str) -> Result<[u8; 32], WalletError> {
    let bytes =
        hex::decode(hex).map_err(|e| WalletError::Backend(format!("invalid session hex: {e}")))?;
    bytes
        .try_into()
        .map_err(|_| WalletError::Backend("session id is not 32 bytes".to_string()))
}

fn expiry_from_params_json(params_json: &str) -> Result<u64, WalletError> {
    let value: serde_json::Value = serde_json::from_str(params_json)
        .map_err(|e| WalletError::Backend(format!("parse channel params json: {e}")))?;
    value
        .get("expiry_timestamp")
        .and_then(|v| v.as_u64())
        .ok_or_else(|| {
            WalletError::Backend("channel params json missing expiry_timestamp".to_string())
        })
}

fn proofs_json_from_reservation(
    reservation: &crate::loose_proof_wallet::ProofReservation,
) -> Result<String, WalletError> {
    let values: Result<Vec<serde_json::Value>, _> = reservation
        .proofs
        .iter()
        .map(|proof| serde_json::from_str(&proof.proof_json))
        .collect();
    let values =
        values.map_err(|e| WalletError::Backend(format!("parse reserved proof json: {e}")))?;
    serde_json::to_string(&values)
        .map_err(|e| WalletError::Backend(format!("serialize reserved proofs: {e}")))
}

fn proof_to_new_loose_proof(
    proof: &Proof,
    funding: &ClientChannelFunding,
) -> Result<NewLooseProof, WalletError> {
    let proof_id = proof
        .y()
        .map_err(|e| WalletError::Backend(format!("compute restored proof id: {e}")))?
        .to_hex();
    let proof_json = serde_json::to_string(proof)
        .map_err(|e| WalletError::Backend(format!("serialize restored proof: {e}")))?;
    let keyset_info = parse_keyset_info_from_json(&funding.keyset_info_json)
        .map_err(|e| WalletError::Backend(format!("parse funding keyset info: {e}")))?;
    Ok(NewLooseProof {
        proof_id,
        mint_url: funding.mint_url.clone(),
        unit: keyset_info.unit.to_string(),
        keyset_id: proof.keyset_id.to_string(),
        amount_raw: u64::from(proof.amount),
        proof_json,
        source_quote_id: None,
        source_batch_id: None,
    })
}

fn change_proofs_to_loose_proofs(
    open_result: &OpenChannelResult,
) -> Result<Vec<NewLooseProof>, WalletError> {
    let proofs: Vec<Proof> = serde_json::from_str(&open_result.change_proofs_json)
        .map_err(|e| WalletError::Backend(format!("parse channel-open change proofs: {e}")))?;
    proofs
        .iter()
        .map(|proof| {
            let proof_id = proof
                .y()
                .map_err(|e| WalletError::Backend(format!("compute change proof id: {e}")))?
                .to_hex();
            let proof_json = serde_json::to_string(proof)
                .map_err(|e| WalletError::Backend(format!("serialize change proof: {e}")))?;
            Ok(NewLooseProof {
                proof_id,
                mint_url: open_result.mint_url.clone(),
                unit: open_result.unit.clone(),
                keyset_id: proof.keyset_id.to_string(),
                amount_raw: u64::from(proof.amount),
                proof_json,
                source_quote_id: None,
                source_batch_id: None,
            })
        })
        .collect()
}

fn loose_proof_error(error: LooseProofWalletError) -> WalletError {
    WalletError::Backend(format!("loose proof wallet: {error}"))
}

fn active_output_keyset_id_from_cache<H, N>(
    bridge: &SpilmanClientBridge<H, N>,
    offer: &RelayPaymentOffer,
) -> Result<OutputKeysetSelection<String>, WalletError>
where
    H: SpilmanClientHost,
    N: SpilmanClientNetworking,
{
    let unit = parse_currency_unit(&offer.unit)?;
    let active_ids = bridge.cached_active_keyset_ids(&offer.mint_url, &unit);

    for accepted_id in &offer.accepted_keyset_ids {
        if active_ids.iter().any(|id| id.to_string() == *accepted_id) {
            return Ok(OutputKeysetSelection::Selected(accepted_id.clone()));
        }
    }

    Ok(OutputKeysetSelection::NoActiveAcceptedKeyset)
}

fn cached_keyset_info_json<H, N>(
    bridge: &SpilmanClientBridge<H, N>,
    mint_url: &str,
    keyset_id: &str,
) -> Result<String, WalletError>
where
    H: SpilmanClientHost,
    N: SpilmanClientNetworking,
{
    let keyset_id = parse_keyset_id(keyset_id)?;
    bridge
        .cached_keyset_info(mint_url, &keyset_id)
        .ok_or_else(|| WalletError::Backend(format!("cached keyset {keyset_id} not found")))
}

fn parse_keyset_id(keyset_id: &str) -> Result<Id, WalletError> {
    keyset_id
        .parse()
        .map_err(|e| WalletError::Backend(format!("invalid keyset id {keyset_id}: {e}")))
}

fn parse_currency_unit(unit: &str) -> Result<CurrencyUnit, WalletError> {
    unit.parse()
        .map_err(|e| WalletError::Backend(format!("invalid currency unit {unit}: {e}")))
}

fn open_channel_stage_error(
    stage: OpenChannelFailureStage,
    channel_id: Option<String>,
    message: String,
) -> OpenChannelError {
    let input_may_be_spent = matches!(
        stage,
        OpenChannelFailureStage::SwapSubmitted
            | OpenChannelFailureStage::FundingProofsReceived
            | OpenChannelFailureStage::RestoreVerification
            | OpenChannelFailureStage::MarkOpen
    );
    OpenChannelError {
        stage,
        channel_id,
        input_may_be_spent,
        message,
    }
}

fn normalize_mint_error_string(raw: String) -> String {
    serde_json::from_str::<serde_json::Value>(&raw)
        .map(|value| value.to_string())
        .unwrap_or(raw)
}

struct ProofInputKeysetLookup {
    unit: CurrencyUnit,
    summaries: Vec<serde_json::Value>,
    missing: Vec<Id>,
}

fn proof_input_keysets_from_cache<H, N>(
    bridge: &SpilmanClientBridge<H, N>,
    mint_url: &str,
    unit: &str,
    reservation: &ProofReservation,
) -> Result<ProofInputKeysetLookup, OpenChannelError>
where
    H: SpilmanClientHost,
    N: SpilmanClientNetworking,
{
    let expected_unit = unit.parse::<CurrencyUnit>().map_err(|e| {
        open_channel_stage_error(
            OpenChannelFailureStage::BeforeOpeningSaved,
            None,
            format!("invalid input proof unit: {e}"),
        )
    })?;
    if reservation.proofs.is_empty() {
        return Err(open_channel_stage_error(
            OpenChannelFailureStage::BeforeOpeningSaved,
            None,
            "input proofs are empty".to_string(),
        ));
    }

    let cached = bridge.cached_keysets_for_unit(mint_url, &expected_unit);
    let mut summaries = Vec::new();
    let mut missing = Vec::new();
    for proof in &reservation.proofs {
        if summaries
            .iter()
            .any(|summary: &serde_json::Value| summary["id"].as_str() == Some(&proof.keyset_id))
        {
            continue;
        }
        match cached
            .iter()
            .find(|(keyset_id, _)| keyset_id.to_string() == proof.keyset_id)
        {
            Some(entry) => summaries.push(keyset_summary_from_cache_entry(
                entry.0,
                &entry.1,
                &expected_unit,
            )?),
            None => {
                let missing_id = parse_keyset_id(&proof.keyset_id).map_err(|e| {
                    open_channel_stage_error(
                        OpenChannelFailureStage::BeforeOpeningSaved,
                        None,
                        e.to_string(),
                    )
                })?;
                if !missing.contains(&missing_id) {
                    missing.push(missing_id);
                }
            }
        }
    }

    Ok(ProofInputKeysetLookup {
        unit: expected_unit,
        summaries,
        missing,
    })
}

fn proof_input_keysets_json(
    mut lookup: ProofInputKeysetLookup,
    mint_url: &str,
    networking: &ReqwestClientNetworking,
) -> Result<String, OpenChannelError> {
    if !lookup.missing.is_empty() {
        lookup.summaries.extend(proof_input_keysets_from_mint(
            mint_url,
            &lookup.unit,
            &lookup.missing,
            networking,
        )?);
    }
    serde_json::to_string(&lookup.summaries).map_err(|e| {
        open_channel_stage_error(
            OpenChannelFailureStage::BeforeOpeningSaved,
            None,
            format!("serialize input keysets: {e}"),
        )
    })
}

fn proof_input_keysets_from_mint(
    mint_url: &str,
    unit: &CurrencyUnit,
    missing: &[Id],
    networking: &ReqwestClientNetworking,
) -> Result<Vec<serde_json::Value>, OpenChannelError> {
    let keysets_json = networking.call_mint_keysets(mint_url).map_err(|e| {
        open_channel_stage_error(OpenChannelFailureStage::BeforeOpeningSaved, None, e)
    })?;
    let keysets_resp: serde_json::Value = serde_json::from_str(&keysets_json).map_err(|e| {
        open_channel_stage_error(
            OpenChannelFailureStage::BeforeOpeningSaved,
            None,
            format!("parse /v1/keysets response: {e}"),
        )
    })?;
    let keysets = keysets_resp
        .get("keysets")
        .and_then(|keysets| keysets.as_array())
        .ok_or_else(|| {
            open_channel_stage_error(
                OpenChannelFailureStage::BeforeOpeningSaved,
                None,
                "invalid /v1/keysets response: missing keysets array".to_string(),
            )
        })?;

    let mut available = Vec::new();
    for keyset in keysets {
        if keyset.get("unit").and_then(|value| value.as_str()) != Some(&unit.to_string()) {
            continue;
        }
        let id = keyset
            .get("id")
            .and_then(|value| value.as_str())
            .ok_or_else(|| {
                open_channel_stage_error(
                    OpenChannelFailureStage::BeforeOpeningSaved,
                    None,
                    "missing id in /v1/keysets entry".to_string(),
                )
            })?;
        let active = keyset
            .get("active")
            .and_then(|value| value.as_bool())
            .unwrap_or(false);
        let input_fee_ppk = keyset
            .get("input_fee_ppk")
            .and_then(|value| value.as_u64())
            .unwrap_or(0);
        let mut value = serde_json::json!({
            "id": id,
            "unit": unit.to_string(),
            "active": active,
            "input_fee_ppk": input_fee_ppk,
        });
        if let Some(final_expiry) = keyset.get("final_expiry") {
            value["final_expiry"] = final_expiry.clone();
        }
        available.push(value);
    }

    let mut out = Vec::new();
    for missing_id in missing {
        let Some(keyset) = available.iter().find(|keyset: &&serde_json::Value| {
            keyset["id"].as_str() == Some(&missing_id.to_string())
        }) else {
            return Err(open_channel_stage_error(
                OpenChannelFailureStage::BeforeOpeningSaved,
                None,
                format!("missing input keyset metadata for proof keyset {missing_id}"),
            ));
        };
        out.push(keyset.clone());
    }

    Ok(out)
}

fn keyset_summary_from_cache_entry(
    keyset_id: Id,
    entry: &ClientKeysetCacheEntry,
    expected_unit: &CurrencyUnit,
) -> Result<serde_json::Value, OpenChannelError> {
    if &entry.unit != expected_unit {
        return Err(open_channel_stage_error(
            OpenChannelFailureStage::BeforeOpeningSaved,
            None,
            format!(
                "cached keyset {keyset_id} unit mismatch: expected {expected_unit}, got {}",
                entry.unit
            ),
        ));
    }
    let info = parse_keyset_info_from_json(&entry.info_json).map_err(|e| {
        open_channel_stage_error(
            OpenChannelFailureStage::BeforeOpeningSaved,
            None,
            format!("parse cached keyset info for {keyset_id}: {e}"),
        )
    })?;
    if info.keyset_id != keyset_id {
        return Err(open_channel_stage_error(
            OpenChannelFailureStage::BeforeOpeningSaved,
            None,
            format!(
                "cached keyset id mismatch: requested {keyset_id}, cache entry has {}",
                info.keyset_id
            ),
        ));
    }
    if &info.unit != expected_unit {
        return Err(open_channel_stage_error(
            OpenChannelFailureStage::BeforeOpeningSaved,
            None,
            format!(
                "cached keyset {keyset_id} info unit mismatch: expected {expected_unit}, got {}",
                info.unit
            ),
        ));
    }

    let mut value = serde_json::json!({
        "id": keyset_id.to_string(),
        "unit": expected_unit.to_string(),
        "active": entry.active,
        "input_fee_ppk": info.input_fee_ppk,
    });
    if let Some(final_expiry) = info.final_expiry {
        value["final_expiry"] = serde_json::json!(final_expiry);
    }
    Ok(value)
}

fn open_channel_error(
    error: OpenChannelError,
    unit: &str,
    requested_input_budget_msats: u64,
) -> WalletError {
    if error.input_may_be_spent {
        WalletError::Backend(format!(
            "channel open failed (input may be spent, retry or recover): {} (input may be spent)",
            error.message
        ))
    } else {
        WalletError::Backend(format!(
            "channel open failed (input was not spent): {} (requested input budget {} msats in unit {})",
            error.message, requested_input_budget_msats, unit
        ))
    }
}

fn describe_keyset_retry_prepare_error(
    error: KeysetRetryError<ClientOpenAttempt, WalletError, OpenChannelError>,
) -> String {
    match error {
        KeysetRetryError::Select { error, .. }
        | KeysetRetryError::Prepare { error, .. }
        | KeysetRetryError::Refresh { error }
        | KeysetRetryError::Cleanup { error } => error.to_string(),
        KeysetRetryError::Submit { .. } | KeysetRetryError::RetryKeysetUnchanged { .. } => {
            "unexpected submit error".to_string()
        }
    }
}

fn should_retry_open_after_keyset_rejection(
    error: &OpenChannelError,
    already_retried: bool,
) -> bool {
    !already_retried && !error.input_may_be_spent && error.is_retryable_keyset_rejection()
}

fn map_create_payment_error(
    channel: &WalletChannel,
    error: String,
    requested_balance_raw: u64,
) -> WalletError {
    if error.starts_with("Channel not found") {
        return WalletError::NotFound;
    }
    if error.starts_with("Channel is not usable") {
        return WalletError::NotOpen;
    }
    if error.starts_with("Balance") && error.contains("exceeds channel capacity") {
        return WalletError::InsufficientCapacity {
            requested: raw_to_msats(&channel.unit, requested_balance_raw).unwrap_or(0),
            capacity: channel.capacity_msats,
        };
    }
    WalletError::Backend(format!("create payment: {error}"))
}

fn ensure_channel_matches_offer(
    channel: &WalletChannel,
    offer: &RelayPaymentOffer,
) -> Result<(), WalletError> {
    if channel.receiver_pubkey != offer.receiver_pubkey {
        return Err(WalletError::OfferMismatch(
            "receiver pubkey mismatch".to_string(),
        ));
    }
    if channel.mint_url != offer.mint_url {
        return Err(WalletError::OfferMismatch("mint URL mismatch".to_string()));
    }
    if channel.unit != offer.unit {
        return Err(WalletError::OfferMismatch("unit mismatch".to_string()));
    }
    if !offer
        .accepted_keyset_ids
        .iter()
        .any(|keyset| keyset == &channel.keyset_id)
    {
        return Err(WalletError::OfferMismatch(
            "keyset not accepted".to_string(),
        ));
    }
    Ok(())
}

fn to_i64(value: u64) -> Result<i64, WalletError> {
    i64::try_from(value)
        .map_err(|_| WalletError::Backend(format!("value {value} does not fit in i64")))
}

fn from_i64(value: i64) -> rusqlite::Result<u64> {
    u64::try_from(value)
        .map_err(|_| sql_decode_error(format!("negative integer in database: {value}")))
}

fn sql_decode_error(message: impl Into<String>) -> rusqlite::Error {
    rusqlite::Error::FromSqlConversionFailure(
        0,
        rusqlite::types::Type::Text,
        Box::new(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            message.into(),
        )),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::loose_proof_wallet::{LooseProofState, NewLooseProof};
    use crate::proof_selection::input_fee_raw_from_ppk_sum;
    use cdk_spilman::{
        channel_parameters_get_channel_id,
        compute_channel_from_proofs_with_input_keysets_and_funding_amount,
        compute_channel_secret_from_hex, construct_proofs, create_funding_swap_with_plain_change,
        create_plain_blinded_messages, ClientChannelOpeningFromSwap, ClientKeysetCacheEntry,
        ClientStorage, ConfigurableClientHost, FundingSpendKind, MemoryClientStorage,
        OpenChannelError, OpenChannelFailureStage, Payment, ReqwestClientNetworking,
        SpilmanClientBridge, SpilmanClientHost, SqliteClientStorage,
    };
    use cdk_spilman_test_mint::{
        rotate_sat_keyset, serve_existing_mint_with_shutdown, serve_mint_with_shutdown,
        TestMintConfig, TestMintHelper,
    };
    use rand::RngCore;
    use std::path::PathBuf;
    use tokio::sync::oneshot;

    struct DirectMintConnection {
        mint_url: String,
        client: reqwest::Client,
    }

    struct FailingRefundMintConnection {
        inner: DirectMintConnection,
    }

    #[async_trait::async_trait]
    impl MintConnection for DirectMintConnection {
        async fn process_swap(
            &self,
            request: cashu::nuts::SwapRequest,
        ) -> anyhow::Result<cashu::nuts::SwapResponse> {
            self.client
                .post(format!("{}/v1/swap", self.mint_url))
                .json(&request)
                .send()
                .await
                .map_err(|e| anyhow::anyhow!(e.to_string()))?
                .error_for_status()
                .map_err(|e| anyhow::anyhow!(e.to_string()))?
                .json()
                .await
                .map_err(|e| anyhow::anyhow!(e.to_string()))
        }

        async fn post_restore(
            &self,
            request: cashu::nuts::RestoreRequest,
        ) -> anyhow::Result<cashu::nuts::RestoreResponse> {
            self.client
                .post(format!("{}/v1/restore", self.mint_url))
                .json(&request)
                .send()
                .await
                .map_err(|e| anyhow::anyhow!(e.to_string()))?
                .error_for_status()
                .map_err(|e| anyhow::anyhow!(e.to_string()))?
                .json()
                .await
                .map_err(|e| anyhow::anyhow!(e.to_string()))
        }

        async fn check_state(
            &self,
            ys: Vec<cashu::nuts::PublicKey>,
        ) -> anyhow::Result<cashu::nuts::CheckStateResponse> {
            self.client
                .post(format!("{}/v1/checkstate", self.mint_url))
                .json(&cashu::nuts::CheckStateRequest { ys })
                .send()
                .await
                .map_err(|e| anyhow::anyhow!(e.to_string()))?
                .error_for_status()
                .map_err(|e| anyhow::anyhow!(e.to_string()))?
                .json()
                .await
                .map_err(|e| anyhow::anyhow!(e.to_string()))
        }
    }

    #[async_trait::async_trait]
    impl MintConnection for FailingRefundMintConnection {
        async fn process_swap(
            &self,
            _: cashu::nuts::SwapRequest,
        ) -> anyhow::Result<cashu::nuts::SwapResponse> {
            Err(anyhow::anyhow!("injected swap failure"))
        }

        async fn post_restore(
            &self,
            _: cashu::nuts::RestoreRequest,
        ) -> anyhow::Result<cashu::nuts::RestoreResponse> {
            Err(anyhow::anyhow!("injected restore failure"))
        }

        async fn check_state(
            &self,
            ys: Vec<cashu::nuts::PublicKey>,
        ) -> anyhow::Result<cashu::nuts::CheckStateResponse> {
            self.inner.check_state(ys).await
        }
    }

    struct OpenedTestChannel {
        _temp: tempfile::TempDir,
        wallet: SqliteClientWallet,
        loose_db: PathBuf,
        channel_db: PathBuf,
        sender_secret: String,
        channel_id: String,
        mint_url: String,
        keyset_id: String,
        expiry_timestamp: u64,
        shutdown_tx: oneshot::Sender<()>,
        mint_task: tokio::task::JoinHandle<anyhow::Result<()>>,
    }

    struct NoopClientNetworking;

    impl SpilmanClientNetworking for NoopClientNetworking {
        fn call_mint_swap(&self, _: &str, _: &str) -> Result<String, String> {
            Err("not used".to_string())
        }

        fn call_mint_restore(&self, _: &str, _: &str) -> Result<String, String> {
            Err("not used".to_string())
        }

        fn call_mint_keysets(&self, _: &str) -> Result<String, String> {
            Err("not used".to_string())
        }

        fn call_mint_keys(&self, _: &str, _: &str) -> Result<String, String> {
            Err("not used".to_string())
        }
    }

    fn free_loopback_port() -> u16 {
        std::net::TcpListener::bind("127.0.0.1:0")
            .unwrap()
            .local_addr()
            .unwrap()
            .port()
    }

    async fn wait_for_mint(client: &reqwest::Client, mint_url: &str) {
        for _ in 0..80 {
            if client
                .get(format!("{mint_url}/v1/info"))
                .send()
                .await
                .is_ok_and(|resp| resp.status().is_success())
            {
                return;
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
        panic!("test mint did not become ready at {mint_url}");
    }

    async fn active_keyset_id(client: &reqwest::Client, mint_url: &str, unit: &str) -> String {
        let keysets: serde_json::Value = client
            .get(format!("{mint_url}/v1/keysets"))
            .send()
            .await
            .unwrap()
            .error_for_status()
            .unwrap()
            .json()
            .await
            .unwrap();
        keysets["keysets"]
            .as_array()
            .unwrap()
            .iter()
            .find(|keyset| {
                keyset["unit"].as_str() == Some(unit) && keyset["active"].as_bool().unwrap_or(false)
            })
            .and_then(|keyset| keyset["id"].as_str())
            .unwrap()
            .to_string()
    }

    async fn request_mint_quote(
        client: &reqwest::Client,
        mint_url: &str,
        amount_raw: u64,
        unit: &str,
    ) -> serde_json::Value {
        client
            .post(format!("{mint_url}/v1/mint/quote/bolt11"))
            .json(&serde_json::json!({
                "amount": amount_raw,
                "unit": unit,
            }))
            .send()
            .await
            .unwrap()
            .error_for_status()
            .unwrap()
            .json()
            .await
            .unwrap()
    }

    async fn wait_for_quote_paid(client: &reqwest::Client, mint_url: &str, quote_id: &str) {
        for _ in 0..80 {
            let status: serde_json::Value = client
                .get(format!("{mint_url}/v1/mint/quote/bolt11/{quote_id}"))
                .send()
                .await
                .unwrap()
                .error_for_status()
                .unwrap()
                .json()
                .await
                .unwrap();
            if status["state"].as_str() == Some("PAID") || status["paid"].as_bool() == Some(true) {
                return;
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
        panic!("quote {quote_id} was not paid by test mint");
    }

    fn loose_proofs_from_json(
        mint_url: &str,
        unit: &str,
        quote_id: &str,
        batch_id: &str,
        proofs_json: &str,
    ) -> Vec<NewLooseProof> {
        let proofs: Vec<serde_json::Value> = serde_json::from_str(proofs_json).unwrap();
        proofs
            .into_iter()
            .enumerate()
            .map(|(idx, proof)| {
                let keyset_id = proof["id"].as_str().unwrap().to_string();
                let amount_raw = proof["amount"].as_u64().unwrap();
                let proof_id = proof["secret"]
                    .as_str()
                    .map(|secret| format!("{keyset_id}:{secret}"))
                    .unwrap_or_else(|| format!("{quote_id}:{idx}"));
                NewLooseProof {
                    proof_id,
                    mint_url: mint_url.to_string(),
                    unit: unit.to_string(),
                    keyset_id,
                    amount_raw,
                    proof_json: proof.to_string(),
                    source_quote_id: Some(quote_id.to_string()),
                    source_batch_id: Some(batch_id.to_string()),
                }
            })
            .collect()
    }

    fn sender_secret_hex() -> String {
        let mut bytes = [0u8; 32];
        rand::rng().fill_bytes(&mut bytes);
        hex::encode(bytes)
    }

    fn offer(mint_url: &str, receiver_pubkey: &str, keyset_id: &str) -> RelayPaymentOffer {
        RelayPaymentOffer {
            receiver_pubkey: receiver_pubkey.to_string(),
            mint_url: mint_url.to_string(),
            unit: "sat".to_string(),
            accepted_keyset_ids: vec![keyset_id.to_string()],
            in_bytes_per_millisat: 1,
            out_bytes_per_millisat: 1,
        }
    }

    async fn open_short_expiry_test_channel(
        amount_raw: u64,
        expiry_delay_secs: u64,
    ) -> OpenedTestChannel {
        let mint_helper = TestMintHelper::new().await.unwrap();
        let mint = mint_helper.mint();
        let keyset_id = mint_helper.keyset_id().to_string();
        let input_proofs = mint_helper.mint_proofs(amount_raw).await.unwrap();

        let port = free_loopback_port();
        let mint_url = format!("http://127.0.0.1:{port}");
        let config = TestMintConfig::for_port(port);
        let (shutdown_tx, shutdown_rx) = oneshot::channel::<()>();
        let mint_for_server = mint.clone();
        let mint_task = tokio::spawn(async move {
            serve_existing_mint_with_shutdown(mint_for_server, config, async {
                let _ = shutdown_rx.await;
            })
            .await
        });
        let client = reqwest::Client::new();
        wait_for_mint(&client, &mint_url).await;

        let bridge = SpilmanClientBridge::new(
            ConfigurableClientHost::new_in_memory(),
            ReqwestClientNetworking::new(),
        );
        let keyset_info_json = bridge.fetch_keyset_info(&mint_url, &keyset_id).unwrap();

        let input_proofs_json = serde_json::to_string(&input_proofs).unwrap();
        let loose_proofs = loose_proofs_from_json(
            &mint_url,
            "sat",
            "short-expiry-quote",
            "short-expiry-batch",
            &input_proofs_json,
        );
        let temp = tempfile::tempdir().unwrap();
        let loose_db = temp.path().join("loose.sqlite");
        let channel_db = temp.path().join("channels.sqlite");
        let loose_wallet = LooseProofWallet::open(&loose_db, "alice").unwrap();
        loose_wallet.import_proofs(&loose_proofs).unwrap();
        let sender_secret = sender_secret_hex();
        let wallet = SqliteClientWallet::open(loose_wallet, &channel_db, &sender_secret).unwrap();

        let receiver_pubkey =
            "02a9acc1e48c25eeeb9289b5031cc57da9fe72f3fe2861d264bdc074209b107ba2".to_string();
        let offer = offer(&mint_url, &receiver_pubkey, &keyset_id);
        let reservation = wallet
            .loose_wallet()
            .reserve_proofs(
                &mint_url,
                "sat",
                std::slice::from_ref(&keyset_id),
                amount_raw,
            )
            .unwrap();
        let expiry_timestamp = SqliteClientWallet::now_seconds().unwrap() + expiry_delay_secs;
        let open_result = wallet
            .submit_reserved_channel(
                &offer,
                &keyset_info_json,
                &reservation,
                None,
                None,
                expiry_timestamp,
            )
            .unwrap();
        let channel_id = wallet
            .finish_open_channel(open_result, &reservation, expiry_timestamp)
            .unwrap();

        OpenedTestChannel {
            _temp: temp,
            wallet,
            loose_db,
            channel_db,
            sender_secret,
            channel_id,
            mint_url,
            keyset_id,
            expiry_timestamp,
            shutdown_tx,
            mint_task,
        }
    }

    fn direct_mint_connection(ctx: &OpenedTestChannel) -> DirectMintConnection {
        DirectMintConnection {
            mint_url: ctx.mint_url.clone(),
            client: reqwest::Client::new(),
        }
    }

    async fn wait_until_expired(expiry_timestamp: u64) {
        loop {
            let now = SqliteClientWallet::now_seconds().unwrap();
            if now > expiry_timestamp {
                return;
            }
            tokio::time::sleep(Duration::from_millis(200)).await;
        }
    }

    fn recovery_row(wallet: &SqliteClientWallet, channel_id: &str) -> (String, String, u64, u64) {
        wallet
            .conn()
            .unwrap()
            .query_row(
                "SELECT kind, status, recovered_amount_raw, recovered_proof_count
                 FROM monad_client_channel_recoveries WHERE channel_id = ?1",
                params![channel_id],
                |row| {
                    Ok((
                        row.get::<_, String>(0)?,
                        row.get::<_, String>(1)?,
                        from_i64(row.get::<_, i64>(2)?)?,
                        from_i64(row.get::<_, i64>(3)?)?,
                    ))
                },
            )
            .unwrap()
    }

    fn prepared_refund_json(wallet: &SqliteClientWallet, channel_id: &str) -> Option<String> {
        wallet
            .conn()
            .unwrap()
            .query_row(
                "SELECT prepared_refund_json FROM monad_client_channel_recoveries WHERE channel_id = ?1",
                params![channel_id],
                |row| row.get(0),
            )
            .unwrap()
    }

    fn recovery_row_count(wallet: &SqliteClientWallet, channel_id: &str) -> u64 {
        let count: i64 = wallet
            .conn()
            .unwrap()
            .query_row(
                "SELECT COUNT(*) FROM monad_client_channel_recoveries WHERE channel_id = ?1",
                params![channel_id],
                |row| row.get(0),
            )
            .unwrap();
        u64::try_from(count).unwrap()
    }

    fn completed_recovery_row_count(wallet: &SqliteClientWallet, channel_id: &str) -> u64 {
        let count: i64 = wallet
            .conn()
            .unwrap()
            .query_row(
                "SELECT COUNT(*) FROM monad_client_channel_recoveries
                 WHERE channel_id = ?1 AND status = 'completed'",
                params![channel_id],
                |row| row.get(0),
            )
            .unwrap();
        u64::try_from(count).unwrap()
    }

    fn completed_recovery_timestamp(wallet: &SqliteClientWallet, channel_id: &str) -> Option<u64> {
        wallet
            .conn()
            .unwrap()
            .query_row(
                "SELECT completed_at FROM monad_client_channel_recoveries WHERE channel_id = ?1",
                params![channel_id],
                |row| row.get::<_, Option<i64>>(0),
            )
            .unwrap()
            .map(|value| u64::try_from(value).unwrap())
    }

    fn recovery_row_status(wallet: &SqliteClientWallet, channel_id: &str) -> String {
        wallet
            .conn()
            .unwrap()
            .query_row(
                "SELECT status FROM monad_client_channel_recoveries WHERE channel_id = ?1",
                params![channel_id],
                |row| row.get::<_, String>(0),
            )
            .unwrap()
    }

    fn reopen_wallet(ctx: &OpenedTestChannel) -> SqliteClientWallet {
        let loose_wallet = LooseProofWallet::open(&ctx.loose_db, "alice").unwrap();
        SqliteClientWallet::open(loose_wallet, &ctx.channel_db, &ctx.sender_secret).unwrap()
    }

    fn test_keyset_id(secret_hex: &str) -> Id {
        use cashu::nuts::{Keys, SecretKey};
        use cashu::Amount;
        use std::collections::BTreeMap;

        let pubkey = SecretKey::from_hex(secret_hex).unwrap().public_key();
        let mut keys = BTreeMap::new();
        keys.insert(Amount::from(1), pubkey);
        Id::v1_from_keys(&Keys::new(keys))
    }

    fn bridge_with_cached_keysets(
        entries: Vec<(Id, CurrencyUnit, bool)>,
    ) -> SpilmanClientBridge<ConfigurableClientHost<MemoryClientStorage>, NoopClientNetworking>
    {
        let host = ConfigurableClientHost::new_in_memory();
        for (id, unit, active) in entries {
            host.set_keyset(
                "http://mint",
                id,
                ClientKeysetCacheEntry {
                    info_json: "{}".to_string(),
                    active,
                    unit,
                },
            )
            .unwrap();
        }
        SpilmanClientBridge::new(host, NoopClientNetworking)
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn expired_unspent_channel_recovers_full_refund_into_loose_wallet() {
        let ctx = open_short_expiry_test_channel(16, 2).await;
        wait_until_expired(ctx.expiry_timestamp).await;

        let mint_connection = direct_mint_connection(&ctx);
        let result = ctx
            .wallet
            .recover_channel_funds(&ctx.channel_id, &mint_connection)
            .await
            .unwrap();

        let ChannelFundRecoveryResult::PostExpiryRefundRecovered {
            channel_id,
            recovered_amount_raw,
            recovered_proof_count,
        } = result
        else {
            panic!("expected full refund recovery, got {result:?}");
        };
        assert_eq!(channel_id, ctx.channel_id);
        assert!(recovered_amount_raw > 0);
        assert!(recovered_proof_count > 0);
        assert_eq!(
            ctx.wallet.get_channel(&ctx.channel_id).unwrap().state,
            WalletChannelState::Closed
        );
        assert_eq!(
            ctx.wallet
                .loose_wallet()
                .available_balance_raw(&ctx.mint_url, "sat", std::slice::from_ref(&ctx.keyset_id))
                .unwrap(),
            recovered_amount_raw
        );
        assert_eq!(
            recovery_row(&ctx.wallet, &ctx.channel_id),
            (
                "post_expiry_refund".to_string(),
                "completed".to_string(),
                recovered_amount_raw,
                recovered_proof_count as u64,
            )
        );
        assert!(completed_recovery_timestamp(&ctx.wallet, &ctx.channel_id).is_some());
        let prepared_json = prepared_refund_json(&ctx.wallet, &ctx.channel_id).unwrap();
        let prepared = PreparedSenderRefund::from_json(&prepared_json).unwrap();
        assert_eq!(prepared.channel_id, ctx.channel_id);
        assert!(!prepared.outputs.is_empty());
        let funding = {
            let bridge = ctx.wallet.bridge.lock().unwrap();
            bridge.get_channel_funding(&ctx.channel_id).unwrap()
        };
        let established = EstablishedChannel::from_client_channel_funding(&funding).unwrap();
        let funding_state = established
            .check_funding_token_state(&mint_connection)
            .await
            .unwrap();
        assert_eq!(funding_state.state, State::Spent);
        assert_eq!(
            EstablishedChannel::classify_funding_spend_witness(&funding_state),
            FundingSpendKind::PostExpiryRefund
        );

        let rerun = ctx
            .wallet
            .recover_channel_funds(&ctx.channel_id, &mint_connection)
            .await
            .unwrap();
        assert_eq!(
            rerun,
            ChannelFundRecoveryResult::AlreadyRecovered {
                channel_id: ctx.channel_id.clone(),
                kind: "post_expiry_refund".to_string(),
                recovered_amount_raw,
                recovered_proof_count,
            }
        );
        assert_eq!(
            ctx.wallet
                .loose_wallet()
                .available_balance_raw(&ctx.mint_url, "sat", std::slice::from_ref(&ctx.keyset_id))
                .unwrap(),
            recovered_amount_raw
        );

        let _ = ctx.shutdown_tx.send(());
        ctx.mint_task.await.unwrap().unwrap();
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn recovery_with_unknown_status_is_rejected() {
        let ctx = open_short_expiry_test_channel(16, 2).await;
        wait_until_expired(ctx.expiry_timestamp).await;
        let now = SqliteClientWallet::now_seconds().unwrap();
        ctx.wallet
            .conn()
            .unwrap()
            .execute(
                "INSERT INTO monad_client_channel_recoveries
                 (channel_id, kind, status, recovered_amount_raw, recovered_proof_count, prepared_refund_json, created_at, updated_at)
                 VALUES (?1, 'post_expiry_refund', 'bogus', NULL, NULL, NULL, ?2, ?2)",
                params![ctx.channel_id, to_i64(now).unwrap()],
            )
            .unwrap();

        let mint_connection = direct_mint_connection(&ctx);
        let err = ctx
            .wallet
            .recover_channel_funds(&ctx.channel_id, &mint_connection)
            .await
            .unwrap_err();
        assert!(err
            .to_string()
            .contains("unknown channel recovery status: bogus"));
        assert_eq!(
            ctx.wallet.get_channel(&ctx.channel_id).unwrap().state,
            WalletChannelState::Open
        );

        let _ = ctx.shutdown_tx.send(());
        ctx.mint_task.await.unwrap().unwrap();
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn spent_by_refund_without_local_attempt_returns_unknown_spent() {
        let ctx = open_short_expiry_test_channel(16, 2).await;
        wait_until_expired(ctx.expiry_timestamp).await;

        let funding = {
            let bridge = ctx.wallet.bridge.lock().unwrap();
            bridge.get_channel_funding(&ctx.channel_id).unwrap()
        };
        let established = EstablishedChannel::from_client_channel_funding(&funding).unwrap();
        let now = SqliteClientWallet::now_seconds().unwrap();
        let prepared = established
            .prepare_sender_refund_after_expiry(ctx.wallet.sender_secret.clone(), now)
            .unwrap();
        let mint_connection = direct_mint_connection(&ctx);
        let proofs = EstablishedChannel::submit_prepared_sender_refund(
            &prepared,
            &mint_connection,
            &established.params.keyset_info.active_keys,
        )
        .await
        .unwrap();
        assert!(!proofs.is_empty());
        assert_eq!(recovery_row_count(&ctx.wallet, &ctx.channel_id), 0);

        let funding_state = established
            .check_funding_token_state(&mint_connection)
            .await
            .unwrap();
        assert_eq!(funding_state.state, State::Spent);
        assert_eq!(
            EstablishedChannel::classify_funding_spend_witness(&funding_state),
            FundingSpendKind::PostExpiryRefund
        );

        let result = ctx
            .wallet
            .recover_channel_funds(&ctx.channel_id, &mint_connection)
            .await
            .unwrap();
        assert_eq!(result, ChannelFundRecoveryResult::UnknownSpent);
        assert_eq!(
            ctx.wallet.get_channel(&ctx.channel_id).unwrap().state,
            WalletChannelState::Open
        );
        assert_eq!(recovery_row_count(&ctx.wallet, &ctx.channel_id), 0);

        let _ = ctx.shutdown_tx.send(());
        ctx.mint_task.await.unwrap().unwrap();
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn recovered_proof_import_failure_does_not_complete_recovery() {
        let ctx = open_short_expiry_test_channel(16, 2).await;
        wait_until_expired(ctx.expiry_timestamp).await;

        let mint_connection = direct_mint_connection(&ctx);
        ctx.wallet.fail_next_recovered_proof_import_for_test();
        let err = ctx
            .wallet
            .recover_channel_funds(&ctx.channel_id, &mint_connection)
            .await
            .unwrap_err();
        assert!(err
            .to_string()
            .contains("injected recovered proof import failure"));
        assert_eq!(
            ctx.wallet.get_channel(&ctx.channel_id).unwrap().state,
            WalletChannelState::Open
        );
        assert_eq!(
            completed_recovery_row_count(&ctx.wallet, &ctx.channel_id),
            0
        );
        assert!(prepared_refund_json(&ctx.wallet, &ctx.channel_id).is_some());
        // The refund was prepared and marked submitting before the import failure.
        assert_eq!(
            recovery_row_status(&ctx.wallet, &ctx.channel_id),
            "submitting"
        );

        let retry = ctx
            .wallet
            .recover_channel_funds(&ctx.channel_id, &mint_connection)
            .await
            .unwrap();
        assert!(matches!(
            retry,
            ChannelFundRecoveryResult::PostExpiryRefundRecovered { .. }
        ));
        assert_eq!(
            ctx.wallet.get_channel(&ctx.channel_id).unwrap().state,
            WalletChannelState::Closed
        );
        assert_eq!(
            completed_recovery_row_count(&ctx.wallet, &ctx.channel_id),
            1
        );

        let _ = ctx.shutdown_tx.send(());
        ctx.mint_task.await.unwrap().unwrap();
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn not_expired_recovery_leaves_channel_state_unchanged() {
        let ctx = open_short_expiry_test_channel(16, 60).await;
        let mint_connection = direct_mint_connection(&ctx);

        let result = ctx
            .wallet
            .recover_channel_funds(&ctx.channel_id, &mint_connection)
            .await
            .unwrap();

        let ChannelFundRecoveryResult::NotExpiredOrSpentYet {
            expiry_timestamp,
            now,
        } = result
        else {
            panic!("expected not-expired recovery result, got {result:?}");
        };
        assert_eq!(expiry_timestamp, ctx.expiry_timestamp);
        assert!(now < expiry_timestamp);
        assert_eq!(
            ctx.wallet.get_channel(&ctx.channel_id).unwrap().state,
            WalletChannelState::Open
        );
        assert_eq!(recovery_row_count(&ctx.wallet, &ctx.channel_id), 0);

        let _ = ctx.shutdown_tx.send(());
        ctx.mint_task.await.unwrap().unwrap();
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn recover_channel_funds_unspent_channel_returns_not_expired_or_spent_yet() {
        let ctx = open_short_expiry_test_channel(16, 60).await;
        let mint_connection = direct_mint_connection(&ctx);

        let result = ctx
            .wallet
            .recover_channel_funds(&ctx.channel_id, &mint_connection)
            .await
            .unwrap();

        let ChannelFundRecoveryResult::NotExpiredOrSpentYet {
            expiry_timestamp,
            now,
        } = result
        else {
            panic!("expected not-expired-or-spent-yet result, got {result:?}");
        };
        assert_eq!(expiry_timestamp, ctx.expiry_timestamp);
        assert!(now < expiry_timestamp);
        assert_eq!(
            ctx.wallet.get_channel(&ctx.channel_id).unwrap().state,
            WalletChannelState::Open
        );
        assert_eq!(recovery_row_count(&ctx.wallet, &ctx.channel_id), 0);

        let _ = ctx.shutdown_tx.send(());
        ctx.mint_task.await.unwrap().unwrap();
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn expired_channel_with_submitting_refund_restores_after_reopen() {
        let ctx = open_short_expiry_test_channel(16, 2).await;
        wait_until_expired(ctx.expiry_timestamp).await;

        let funding = {
            let bridge = ctx.wallet.bridge.lock().unwrap();
            bridge.get_channel_funding(&ctx.channel_id).unwrap()
        };
        let established = EstablishedChannel::from_client_channel_funding(&funding).unwrap();
        let now = SqliteClientWallet::now_seconds().unwrap();
        let prepared = established
            .prepare_sender_refund_after_expiry(ctx.wallet.sender_secret.clone(), now)
            .unwrap();
        ctx.wallet
            .persist_refund_recovery_prepared(&ctx.channel_id, &prepared)
            .unwrap();
        let stored_before_submit = prepared_refund_json(&ctx.wallet, &ctx.channel_id).unwrap();
        assert_eq!(
            PreparedSenderRefund::from_json(&stored_before_submit)
                .unwrap()
                .channel_id,
            ctx.channel_id
        );

        let mint_connection = direct_mint_connection(&ctx);
        let submitted = EstablishedChannel::submit_prepared_sender_refund(
            &prepared,
            &mint_connection,
            &established.params.keyset_info.active_keys,
        )
        .await
        .unwrap();
        assert!(!submitted.is_empty());

        // Mark the row as submitting to simulate a crash/loss after the refund
        // reached the mint but before we could record the result.
        ctx.wallet
            .mark_refund_recovery_submitting(&ctx.channel_id)
            .unwrap();

        let reopened_wallet = reopen_wallet(&ctx);

        let result = reopened_wallet
            .recover_channel_funds(&ctx.channel_id, &mint_connection)
            .await
            .unwrap();

        let ChannelFundRecoveryResult::PostExpiryRefundRecovered {
            recovered_amount_raw,
            recovered_proof_count,
            ..
        } = result
        else {
            panic!("expected restored full refund recovery, got {result:?}");
        };
        assert!(recovered_amount_raw > 0);
        assert!(recovered_proof_count > 0);
        assert_eq!(
            reopened_wallet.get_channel(&ctx.channel_id).unwrap().state,
            WalletChannelState::Closed
        );
        assert_eq!(
            recovery_row(&reopened_wallet, &ctx.channel_id),
            (
                "post_expiry_refund".to_string(),
                "completed".to_string(),
                recovered_amount_raw,
                recovered_proof_count as u64,
            )
        );
        assert_eq!(
            prepared_refund_json(&reopened_wallet, &ctx.channel_id).unwrap(),
            stored_before_submit
        );

        let _ = ctx.shutdown_tx.send(());
        ctx.mint_task.await.unwrap().unwrap();
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn expired_channel_with_submitting_unspent_refund_retries_same_prepared_attempt() {
        let ctx = open_short_expiry_test_channel(16, 2).await;
        wait_until_expired(ctx.expiry_timestamp).await;

        let funding = {
            let bridge = ctx.wallet.bridge.lock().unwrap();
            bridge.get_channel_funding(&ctx.channel_id).unwrap()
        };
        let established = EstablishedChannel::from_client_channel_funding(&funding).unwrap();
        let now = SqliteClientWallet::now_seconds().unwrap();
        let prepared = established
            .prepare_sender_refund_after_expiry(ctx.wallet.sender_secret.clone(), now)
            .unwrap();
        ctx.wallet
            .persist_refund_recovery_prepared(&ctx.channel_id, &prepared)
            .unwrap();
        let stored_before_recovery = prepared_refund_json(&ctx.wallet, &ctx.channel_id).unwrap();
        ctx.wallet
            .mark_refund_recovery_submitting(&ctx.channel_id)
            .unwrap();

        let mint_connection = direct_mint_connection(&ctx);
        let funding_state_before = established
            .check_funding_token_state(&mint_connection)
            .await
            .unwrap();
        assert_eq!(funding_state_before.state, State::Unspent);

        let result = ctx
            .wallet
            .recover_channel_funds(&ctx.channel_id, &mint_connection)
            .await
            .unwrap();

        let ChannelFundRecoveryResult::PostExpiryRefundRecovered {
            recovered_amount_raw,
            recovered_proof_count,
            ..
        } = result
        else {
            panic!("expected retried full refund recovery, got {result:?}");
        };
        assert!(recovered_amount_raw > 0);
        assert!(recovered_proof_count > 0);
        assert_eq!(
            ctx.wallet.get_channel(&ctx.channel_id).unwrap().state,
            WalletChannelState::Closed
        );
        assert_eq!(
            prepared_refund_json(&ctx.wallet, &ctx.channel_id).unwrap(),
            stored_before_recovery
        );
        assert_eq!(
            recovery_row(&ctx.wallet, &ctx.channel_id),
            (
                "post_expiry_refund".to_string(),
                "completed".to_string(),
                recovered_amount_raw,
                recovered_proof_count as u64,
            )
        );

        let funding_state_after = established
            .check_funding_token_state(&mint_connection)
            .await
            .unwrap();
        assert_eq!(funding_state_after.state, State::Spent);
        assert_eq!(
            EstablishedChannel::classify_funding_spend_witness(&funding_state_after),
            FundingSpendKind::PostExpiryRefund
        );

        let _ = ctx.shutdown_tx.send(());
        ctx.mint_task.await.unwrap().unwrap();
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn expired_channel_with_prepared_refund_submits_same_prepared_attempt() {
        let ctx = open_short_expiry_test_channel(16, 2).await;
        wait_until_expired(ctx.expiry_timestamp).await;

        let funding = {
            let bridge = ctx.wallet.bridge.lock().unwrap();
            bridge.get_channel_funding(&ctx.channel_id).unwrap()
        };
        let established = EstablishedChannel::from_client_channel_funding(&funding).unwrap();
        let now = SqliteClientWallet::now_seconds().unwrap();
        let prepared = established
            .prepare_sender_refund_after_expiry(ctx.wallet.sender_secret.clone(), now)
            .unwrap();
        ctx.wallet
            .persist_refund_recovery_prepared(&ctx.channel_id, &prepared)
            .unwrap();
        let stored_before_recovery = prepared_refund_json(&ctx.wallet, &ctx.channel_id).unwrap();
        assert_eq!(
            recovery_row_status(&ctx.wallet, &ctx.channel_id),
            "prepared"
        );

        let mint_connection = direct_mint_connection(&ctx);
        let result = ctx
            .wallet
            .recover_channel_funds(&ctx.channel_id, &mint_connection)
            .await
            .unwrap();

        let ChannelFundRecoveryResult::PostExpiryRefundRecovered {
            recovered_amount_raw,
            recovered_proof_count,
            ..
        } = result
        else {
            panic!("expected prepared refund recovery, got {result:?}");
        };
        assert!(recovered_amount_raw > 0);
        assert!(recovered_proof_count > 0);
        assert_eq!(
            prepared_refund_json(&ctx.wallet, &ctx.channel_id).unwrap(),
            stored_before_recovery
        );
        assert_eq!(
            recovery_row(&ctx.wallet, &ctx.channel_id),
            (
                "post_expiry_refund".to_string(),
                "completed".to_string(),
                recovered_amount_raw,
                recovered_proof_count as u64,
            )
        );

        let _ = ctx.shutdown_tx.send(());
        ctx.mint_task.await.unwrap().unwrap();
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn submitting_refund_without_prepared_json_is_rejected() {
        let ctx = open_short_expiry_test_channel(16, 2).await;
        wait_until_expired(ctx.expiry_timestamp).await;
        let now = SqliteClientWallet::now_seconds().unwrap();
        ctx.wallet
            .conn()
            .unwrap()
            .execute(
                "INSERT INTO monad_client_channel_recoveries
                 (channel_id, kind, status, recovered_amount_raw, recovered_proof_count, prepared_refund_json, created_at, updated_at)
                 VALUES (?1, 'post_expiry_refund', 'submitting', NULL, NULL, NULL, ?2, ?2)",
                params![ctx.channel_id, to_i64(now).unwrap()],
            )
            .unwrap();

        let mint_connection = direct_mint_connection(&ctx);
        let err = ctx
            .wallet
            .recover_channel_funds(&ctx.channel_id, &mint_connection)
            .await
            .unwrap_err();
        assert!(err
            .to_string()
            .contains("submitting refund recovery is missing prepared refund json"));
        assert_eq!(
            ctx.wallet.get_channel(&ctx.channel_id).unwrap().state,
            WalletChannelState::Open
        );
        assert_eq!(
            recovery_row_status(&ctx.wallet, &ctx.channel_id),
            "submitting"
        );

        let _ = ctx.shutdown_tx.send(());
        ctx.mint_task.await.unwrap().unwrap();
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn refund_submit_and_restore_failure_returns_retry_later() {
        let ctx = open_short_expiry_test_channel(16, 2).await;
        wait_until_expired(ctx.expiry_timestamp).await;
        let mint_connection = FailingRefundMintConnection {
            inner: direct_mint_connection(&ctx),
        };

        let result = ctx
            .wallet
            .recover_channel_funds(&ctx.channel_id, &mint_connection)
            .await
            .unwrap();
        let ChannelFundRecoveryResult::RecoveryRetryLater { channel_id, reason } = result else {
            panic!("expected retry-later recovery result, got {result:?}");
        };
        assert_eq!(channel_id, ctx.channel_id);
        assert!(reason.contains("refund submit failed"));
        assert_eq!(
            recovery_row_status(&ctx.wallet, &ctx.channel_id),
            "submitting"
        );
        assert!(prepared_refund_json(&ctx.wallet, &ctx.channel_id).is_some());
        assert_eq!(
            completed_recovery_row_count(&ctx.wallet, &ctx.channel_id),
            0
        );
        assert_eq!(
            ctx.wallet.get_channel(&ctx.channel_id).unwrap().state,
            WalletChannelState::Open
        );

        let _ = ctx.shutdown_tx.send(());
        ctx.mint_task.await.unwrap().unwrap();
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn provisions_real_channel_from_loose_proofs() {
        let port = free_loopback_port();
        let mint_url = format!("http://127.0.0.1:{port}");
        let config = TestMintConfig::for_port(port);
        let (shutdown_tx, shutdown_rx) = oneshot::channel::<()>();
        let mint_task = tokio::spawn(async move {
            serve_mint_with_shutdown(config, async {
                let _ = shutdown_rx.await;
            })
            .await
        });

        let client = reqwest::Client::new();
        wait_for_mint(&client, &mint_url).await;

        let unit = "sat";
        let keyset_id = active_keyset_id(&client, &mint_url, unit).await;
        let bridge = SpilmanClientBridge::new(
            ConfigurableClientHost::new_in_memory(),
            ReqwestClientNetworking::new(),
        );
        let keyset_info_json = bridge.fetch_keyset_info(&mint_url, &keyset_id).unwrap();

        let minted_amount_raw = 1024u64;
        let input_budget_raw = 1000u64;
        let quote_response = request_mint_quote(&client, &mint_url, minted_amount_raw, unit).await;
        let quote_id = quote_response["quote"].as_str().unwrap().to_string();

        wait_for_quote_paid(&client, &mint_url, &quote_id).await;

        let premint_json =
            create_plain_blinded_messages(minted_amount_raw, &keyset_info_json).unwrap();
        let premint: serde_json::Value = serde_json::from_str(&premint_json).unwrap();
        let secrets_with_blinding_json = premint["secrets_with_blinding"].to_string();
        let batch_id = format!("batch-{quote_id}");

        let mint_response: serde_json::Value = client
            .post(format!("{mint_url}/v1/mint/bolt11"))
            .json(&serde_json::json!({
                "quote": quote_id,
                "outputs": premint["blinded_messages"],
            }))
            .send()
            .await
            .unwrap()
            .error_for_status()
            .unwrap()
            .json()
            .await
            .unwrap();
        let signatures_json = mint_response["signatures"].to_string();
        let proofs_json = construct_proofs(
            &signatures_json,
            &secrets_with_blinding_json,
            &keyset_info_json,
        )
        .unwrap();
        let loose_proofs =
            loose_proofs_from_json(&mint_url, unit, &quote_id, &batch_id, &proofs_json);
        let keyset_info: serde_json::Value = serde_json::from_str(&keyset_info_json).unwrap();
        let input_fee_ppk = keyset_info["input_fee_ppk"]
            .as_u64()
            .or_else(|| keyset_info["inputFeePpk"].as_u64())
            .unwrap_or(0);
        let input_fee_raw = input_fee_raw_from_ppk_sum(input_fee_ppk * loose_proofs.len() as u64);
        let expected_change_raw = minted_amount_raw - input_fee_raw - input_budget_raw;

        let temp = tempfile::tempdir().unwrap();
        let loose_db = temp.path().join("loose.sqlite");
        let channel_db = temp.path().join("channels.sqlite");
        let loose_wallet = LooseProofWallet::open(&loose_db, "alice").unwrap();
        loose_wallet.import_proofs(&loose_proofs).unwrap();

        let wallet =
            SqliteClientWallet::open(loose_wallet, &channel_db, &sender_secret_hex()).unwrap();

        // Use a valid dummy receiver pubkey (relay would provide a real one).
        let receiver_pubkey =
            "02a9acc1e48c25eeeb9289b5031cc57da9fe72f3fe2861d264bdc074209b107ba2".to_string();

        let input_budget_msats = input_budget_raw * 1000;
        let offer = offer(&mint_url, &receiver_pubkey, &keyset_id);
        let before_open = SqliteClientWallet::now_seconds().unwrap();
        let channel_id = wallet
            .provision_channel(&offer, input_budget_msats)
            .expect("provision channel from loose proofs");
        let after_open = SqliteClientWallet::now_seconds().unwrap();

        let channel = wallet.get_channel(&channel_id).unwrap();
        assert_eq!(channel.receiver_pubkey, receiver_pubkey);
        assert_eq!(channel.mint_url, mint_url);
        assert_eq!(channel.unit, "sat");
        assert_eq!(channel.keyset_id, keyset_id);
        assert_eq!(channel.state, WalletChannelState::Open);
        // Actual usable capacity is what upstream returned after fees; it must be
        // positive and not exceed the loose-proof input budget we committed.
        assert!(channel.capacity_msats > 0);
        assert!(channel.capacity_msats <= input_budget_msats);

        // The channel expiry timestamp is stored in local metadata.
        let stored_expiry: i64 = wallet
            .conn()
            .unwrap()
            .query_row(
                "SELECT expiry_timestamp FROM monad_client_channels WHERE channel_id = ?1",
                params![channel_id],
                |row| row.get(0),
            )
            .unwrap();
        let stored_expiry = u64::try_from(stored_expiry).unwrap();
        assert_eq!(channel.expiry_timestamp, stored_expiry);
        assert!(
            stored_expiry >= before_open + CHANNEL_EXPIRY_SECONDS,
            "stored expiry should be no earlier than before_open + CHANNEL_EXPIRY_SECONDS"
        );
        assert!(
            stored_expiry <= after_open + CHANNEL_EXPIRY_SECONDS,
            "stored expiry should be no later than after_open + CHANNEL_EXPIRY_SECONDS"
        );

        // Surplus reserved input should come back as plain loose change.
        let available = wallet
            .loose_wallet()
            .available_balance_raw(&mint_url, unit, std::slice::from_ref(&keyset_id))
            .unwrap();
        assert_eq!(available, expected_change_raw);

        // Attach, build link request, then build a channel payment.
        let session_id = [7u8; 32];
        wallet
            .attach_channel_to_session(&channel_id, session_id)
            .unwrap();
        let link_json = wallet.build_link_request(&channel_id, &offer).unwrap();
        let link_payment: Payment = serde_json::from_str(&link_json).unwrap();
        assert_eq!(link_payment.channel_id, channel_id);
        assert_eq!(link_payment.balance, 0);
        assert!(link_payment.params.is_some());
        assert!(link_payment.funding_proofs.is_some());

        // Use the actual upstream-reported capacity for payment planning, not the
        // original input budget.
        let capacity_raw = msats_to_raw_units(&channel.unit, channel.capacity_msats).unwrap();
        let next_balance_raw = capacity_raw / 2;
        let payment_json = wallet
            .build_channel_payment(&channel_id, &offer, 0, next_balance_raw)
            .unwrap();
        let payment: Payment = serde_json::from_str(&payment_json).unwrap();
        assert_eq!(payment.channel_id, channel_id);
        assert_eq!(payment.balance, next_balance_raw);
        assert!(payment.params.is_none());
        assert!(payment.funding_proofs.is_none());

        let _ = shutdown_tx.send(());
        mint_task.await.unwrap().unwrap();
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn provisions_from_non_relay_accepted_input_keyset() {
        let mint_helper = TestMintHelper::new().await.unwrap();
        let mint = mint_helper.mint();
        let input_keyset_id = mint_helper.keyset_id().to_string();
        let amount_raw = 16u64;
        let input_proofs = mint_helper.mint_proofs(amount_raw).await.unwrap();

        let output_keyset_id = rotate_sat_keyset(&mint, 400).await.unwrap().to_string();
        assert_ne!(input_keyset_id, output_keyset_id);

        let port = free_loopback_port();
        let mint_url = format!("http://127.0.0.1:{port}");
        let config = TestMintConfig::for_port(port);
        let (shutdown_tx, shutdown_rx) = oneshot::channel::<()>();
        let mint_task = tokio::spawn(async move {
            serve_existing_mint_with_shutdown(mint, config, async {
                let _ = shutdown_rx.await;
            })
            .await
        });
        let client = reqwest::Client::new();
        wait_for_mint(&client, &mint_url).await;

        let input_proofs_json = serde_json::to_string(&input_proofs).unwrap();
        let loose_proofs = loose_proofs_from_json(
            &mint_url,
            "sat",
            "pre-rotation-quote",
            "pre-rotation-batch",
            &input_proofs_json,
        );
        assert!(loose_proofs
            .iter()
            .all(|proof| proof.keyset_id == input_keyset_id));

        let temp = tempfile::tempdir().unwrap();
        let loose_db = temp.path().join("loose.sqlite");
        let channel_db = temp.path().join("channels.sqlite");
        let loose_wallet = LooseProofWallet::open(&loose_db, "alice").unwrap();
        loose_wallet.import_proofs(&loose_proofs).unwrap();
        let wallet =
            SqliteClientWallet::open(loose_wallet, &channel_db, &sender_secret_hex()).unwrap();

        let receiver_pubkey =
            "02a9acc1e48c25eeeb9289b5031cc57da9fe72f3fe2861d264bdc074209b107ba2".to_string();
        let mut offer = offer(&mint_url, &receiver_pubkey, &input_keyset_id);
        offer.accepted_keyset_ids.push(output_keyset_id.clone());
        assert_eq!(offer.accepted_keyset_ids[0], input_keyset_id);

        let channel_id = wallet
            .provision_channel(&offer, amount_raw * 1000)
            .expect("provision channel from non-accepted input keyset proofs");
        let channel = wallet.get_channel(&channel_id).unwrap();
        assert_eq!(channel.keyset_id, output_keyset_id);
        assert_eq!(channel.receiver_pubkey, receiver_pubkey);
        assert_eq!(channel.state, WalletChannelState::Open);

        let available_input = wallet
            .loose_wallet()
            .available_balance_raw(&mint_url, "sat", std::slice::from_ref(&input_keyset_id))
            .unwrap();
        assert_eq!(available_input, 0);

        wallet
            .attach_channel_to_session(&channel_id, [9u8; 32])
            .unwrap();
        let link_json = wallet.build_link_request(&channel_id, &offer).unwrap();
        let link_payment: Payment = serde_json::from_str(&link_json).unwrap();
        assert_eq!(link_payment.channel_id, channel_id);
        assert!(link_payment.params.is_some());
        assert!(link_payment.funding_proofs.is_some());

        let _ = shutdown_tx.send(());
        mint_task.await.unwrap().unwrap();
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn provisions_exact_target_capacity_from_spare_input_value() {
        let mint_helper = TestMintHelper::new().await.unwrap();
        let mint = mint_helper.mint();
        let input_keyset_id = mint_helper.keyset_id().to_string();
        let amount_raw = 128u64;
        let input_proofs = mint_helper.mint_proofs(amount_raw).await.unwrap();
        let extra_input_proofs = mint_helper.mint_proofs(1).await.unwrap();

        let output_keyset_id = rotate_sat_keyset(&mint, 400).await.unwrap().to_string();
        assert_ne!(input_keyset_id, output_keyset_id);

        let port = free_loopback_port();
        let mint_url = format!("http://127.0.0.1:{port}");
        let config = TestMintConfig::for_port(port);
        let (shutdown_tx, shutdown_rx) = oneshot::channel::<()>();
        let mint_task = tokio::spawn(async move {
            serve_existing_mint_with_shutdown(mint, config, async {
                let _ = shutdown_rx.await;
            })
            .await
        });
        let client = reqwest::Client::new();
        wait_for_mint(&client, &mint_url).await;

        let mut all_input_proofs: Vec<serde_json::Value> =
            serde_json::from_str(&serde_json::to_string(&input_proofs).unwrap()).unwrap();
        let extra_input_proofs: Vec<serde_json::Value> =
            serde_json::from_str(&serde_json::to_string(&extra_input_proofs).unwrap()).unwrap();
        all_input_proofs.extend(extra_input_proofs);
        let input_proofs_json = serde_json::to_string(&all_input_proofs).unwrap();
        let loose_proofs = loose_proofs_from_json(
            &mint_url,
            "sat",
            "target-capacity-quote",
            "target-capacity-batch",
            &input_proofs_json,
        );
        assert!(loose_proofs
            .iter()
            .all(|proof| proof.keyset_id == input_keyset_id));

        let temp = tempfile::tempdir().unwrap();
        let loose_db = temp.path().join("loose.sqlite");
        let channel_db = temp.path().join("channels.sqlite");
        let loose_wallet = LooseProofWallet::open(&loose_db, "alice").unwrap();
        loose_wallet.import_proofs(&loose_proofs).unwrap();
        let wallet =
            SqliteClientWallet::open(loose_wallet, &channel_db, &sender_secret_hex()).unwrap();

        let receiver_pubkey =
            "02a9acc1e48c25eeeb9289b5031cc57da9fe72f3fe2861d264bdc074209b107ba2".to_string();
        let offer = offer(&mint_url, &receiver_pubkey, &output_keyset_id);
        assert!(!offer.accepted_keyset_ids.contains(&input_keyset_id));

        let target_capacity_raw = 32u64;
        let target_capacity_msats = target_capacity_raw * 1000;
        let channel_id = wallet
            .provision_channel_with_target_capacity(&offer, target_capacity_msats)
            .expect("provision exact target capacity channel");

        let channel = wallet.get_channel(&channel_id).unwrap();
        assert_eq!(channel.receiver_pubkey, receiver_pubkey);
        assert_eq!(channel.mint_url, mint_url);
        assert_eq!(channel.unit, "sat");
        assert_eq!(channel.keyset_id, output_keyset_id);
        assert_eq!(channel.capacity_msats, target_capacity_msats);

        let reservation_id: String = wallet
            .channel_db
            .lock()
            .unwrap()
            .query_row(
                "SELECT reservation_id FROM monad_client_channels WHERE channel_id = ?1",
                rusqlite::params![channel_id],
                |row| row.get(0),
            )
            .unwrap();
        let reserved_proofs = wallet
            .loose_wallet()
            .proofs_for_reservation(&reservation_id)
            .unwrap();
        let reserved_total = reserved_proofs
            .iter()
            .map(|proof| proof.amount_raw)
            .sum::<u64>();
        assert!(reserved_total > target_capacity_raw);
        assert!(reserved_proofs
            .iter()
            .all(|proof| proof.state == LooseProofState::Spent));
        let remaining_available = wallet
            .loose_wallet()
            .available_balance_raw(&mint_url, "sat", std::slice::from_ref(&input_keyset_id))
            .unwrap();
        assert!(remaining_available > 0);

        let _ = shutdown_tx.send(());
        mint_task.await.unwrap().unwrap();
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn target_capacity_insufficient_funds_leaves_state_unchanged() {
        let port = free_loopback_port();
        let mint_url = format!("http://127.0.0.1:{port}");
        let config = TestMintConfig::for_port(port);
        let (shutdown_tx, shutdown_rx) = oneshot::channel::<()>();
        let mint_task = tokio::spawn(async move {
            serve_mint_with_shutdown(config, async {
                let _ = shutdown_rx.await;
            })
            .await
        });

        let client = reqwest::Client::new();
        wait_for_mint(&client, &mint_url).await;

        let unit = "sat";
        let keyset_id = active_keyset_id(&client, &mint_url, unit).await;
        let bridge = SpilmanClientBridge::new(
            ConfigurableClientHost::new_in_memory(),
            ReqwestClientNetworking::new(),
        );
        let keyset_info_json = bridge.fetch_keyset_info(&mint_url, &keyset_id).unwrap();

        let amount_raw = 1u64;
        let quote_response = request_mint_quote(&client, &mint_url, amount_raw, unit).await;
        let quote_id = quote_response["quote"].as_str().unwrap().to_string();
        wait_for_quote_paid(&client, &mint_url, &quote_id).await;

        let premint_json = create_plain_blinded_messages(amount_raw, &keyset_info_json).unwrap();
        let premint: serde_json::Value = serde_json::from_str(&premint_json).unwrap();
        let secrets_with_blinding_json = premint["secrets_with_blinding"].to_string();
        let batch_id = format!("batch-{quote_id}");
        let mint_response: serde_json::Value = client
            .post(format!("{mint_url}/v1/mint/bolt11"))
            .json(&serde_json::json!({
                "quote": quote_id,
                "outputs": premint["blinded_messages"],
            }))
            .send()
            .await
            .unwrap()
            .error_for_status()
            .unwrap()
            .json()
            .await
            .unwrap();
        let proofs_json = construct_proofs(
            &mint_response["signatures"].to_string(),
            &secrets_with_blinding_json,
            &keyset_info_json,
        )
        .unwrap();
        let loose_proofs =
            loose_proofs_from_json(&mint_url, unit, &quote_id, &batch_id, &proofs_json);

        let temp = tempfile::tempdir().unwrap();
        let loose_db = temp.path().join("loose.sqlite");
        let channel_db = temp.path().join("channels.sqlite");
        let loose_wallet = LooseProofWallet::open(&loose_db, "alice").unwrap();
        loose_wallet.import_proofs(&loose_proofs).unwrap();
        let wallet =
            SqliteClientWallet::open(loose_wallet, &channel_db, &sender_secret_hex()).unwrap();

        let receiver_pubkey =
            "02a9acc1e48c25eeeb9289b5031cc57da9fe72f3fe2861d264bdc074209b107ba2".to_string();
        let offer = offer(&mint_url, &receiver_pubkey, &keyset_id);
        let err = wallet
            .provision_channel_with_target_capacity(&offer, 1_000_000)
            .unwrap_err();
        assert!(matches!(err, WalletError::Backend(_)));

        assert_eq!(
            wallet
                .loose_wallet()
                .available_balance_raw(&mint_url, unit, std::slice::from_ref(&keyset_id))
                .unwrap(),
            amount_raw
        );
        let channel_count: u64 = wallet
            .channel_db
            .lock()
            .unwrap()
            .query_row("SELECT COUNT(*) FROM monad_client_channels", [], |row| {
                row.get(0)
            })
            .unwrap();
        assert_eq!(channel_count, 0);

        let _ = shutdown_tx.send(());
        mint_task.await.unwrap().unwrap();
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn recovers_persisted_ambiguous_opening() {
        let port = free_loopback_port();
        let mint_url = format!("http://127.0.0.1:{port}");
        let config = TestMintConfig::for_port(port);
        let (shutdown_tx, shutdown_rx) = oneshot::channel::<()>();
        let mint_task = tokio::spawn(async move {
            serve_mint_with_shutdown(config, async {
                let _ = shutdown_rx.await;
            })
            .await
        });

        let client = reqwest::Client::new();
        wait_for_mint(&client, &mint_url).await;

        let unit = "sat";
        let keyset_id = active_keyset_id(&client, &mint_url, unit).await;
        let helper_bridge = SpilmanClientBridge::new(
            ConfigurableClientHost::new_in_memory(),
            ReqwestClientNetworking::new(),
        );
        let keyset_info_json = helper_bridge
            .fetch_keyset_info(&mint_url, &keyset_id)
            .unwrap();

        let amount_raw = 1024u64;
        let desired_funding_raw = 1000u64;
        let quote_response = request_mint_quote(&client, &mint_url, amount_raw, unit).await;
        let quote_id = quote_response["quote"].as_str().unwrap().to_string();
        wait_for_quote_paid(&client, &mint_url, &quote_id).await;

        let premint_json = create_plain_blinded_messages(amount_raw, &keyset_info_json).unwrap();
        let premint: serde_json::Value = serde_json::from_str(&premint_json).unwrap();
        let secrets_with_blinding_json = premint["secrets_with_blinding"].to_string();
        let batch_id = format!("batch-{quote_id}");
        let mint_response: serde_json::Value = client
            .post(format!("{mint_url}/v1/mint/bolt11"))
            .json(&serde_json::json!({
                "quote": quote_id,
                "outputs": premint["blinded_messages"],
            }))
            .send()
            .await
            .unwrap()
            .error_for_status()
            .unwrap()
            .json()
            .await
            .unwrap();
        let signatures_json = mint_response["signatures"].to_string();
        let proofs_json = construct_proofs(
            &signatures_json,
            &secrets_with_blinding_json,
            &keyset_info_json,
        )
        .unwrap();
        let loose_proofs =
            loose_proofs_from_json(&mint_url, unit, &quote_id, &batch_id, &proofs_json);

        let temp = tempfile::tempdir().unwrap();
        let loose_db = temp.path().join("loose.sqlite");
        let channel_db = temp.path().join("channels.sqlite");
        let loose_wallet = LooseProofWallet::open(&loose_db, "alice").unwrap();
        loose_wallet.import_proofs(&loose_proofs).unwrap();

        let sender_secret = sender_secret_hex();
        let wallet = SqliteClientWallet::open(loose_wallet, &channel_db, &sender_secret).unwrap();
        let receiver_pubkey =
            "02a9acc1e48c25eeeb9289b5031cc57da9fe72f3fe2861d264bdc074209b107ba2".to_string();
        let offer = offer(&mint_url, &receiver_pubkey, &keyset_id);
        let input_budget_msats = desired_funding_raw * 1000;
        let input_budget_raw = msats_to_raw_units(unit, input_budget_msats).unwrap();
        let reservation = wallet
            .loose_wallet()
            .reserve_proofs(
                &mint_url,
                unit,
                std::slice::from_ref(&keyset_id),
                input_budget_raw,
            )
            .unwrap();
        let input_proofs_json = proofs_json_from_reservation(&reservation).unwrap();

        let channel_secret_hex =
            compute_channel_secret_from_hex(&sender_secret, &receiver_pubkey).unwrap();
        let expiry_timestamp = SqliteClientWallet::now_seconds().unwrap() + CHANNEL_EXPIRY_SECONDS;
        let keyset_info: serde_json::Value = serde_json::from_str(&keyset_info_json).unwrap();
        let input_fee_ppk = keyset_info["inputFeePpk"].as_u64().unwrap();
        let input_keysets_json = serde_json::to_string(&vec![serde_json::json!({
            "id": keyset_id,
            "unit": unit,
            "active": true,
            "input_fee_ppk": input_fee_ppk,
        })])
        .unwrap();
        let input_fee_raw =
            input_fee_raw_from_ppk_sum(input_fee_ppk * reservation.proofs.len() as u64);
        let expected_change_raw = amount_raw - input_fee_raw - desired_funding_raw;

        let compute_result = compute_channel_from_proofs_with_input_keysets_and_funding_amount(
            &mint_url,
            unit,
            &input_proofs_json,
            &input_keysets_json,
            &receiver_pubkey,
            &wallet.sender_pubkey_hex,
            &channel_secret_hex,
            expiry_timestamp,
            &keyset_info_json,
            0,
            None,
            Some(desired_funding_raw),
        )
        .unwrap();
        let compute_json: serde_json::Value = serde_json::from_str(&compute_result).unwrap();
        assert_eq!(
            compute_json["change_amount_raw"].as_u64(),
            Some(expected_change_raw)
        );
        let params_json = compute_json["params_json"].as_str().unwrap().to_string();
        let swap_input_proofs_json = compute_json["proofs_json"].as_str().unwrap().to_string();
        let capacity = compute_json["capacity"].as_u64().unwrap();
        let funding_token_amount = compute_json["funding_token_amount"].as_u64().unwrap();
        let change_amount_raw = compute_json["change_amount_raw"].as_u64().unwrap();

        let channel_id =
            channel_parameters_get_channel_id(&params_json, &channel_secret_hex, &keyset_info_json)
                .unwrap();
        let mut storage =
            SqliteClientStorage::open(channel_db.to_str().unwrap()).expect("open client storage");
        let swap_result = create_funding_swap_with_plain_change(
            &params_json,
            &channel_secret_hex,
            &keyset_info_json,
            &swap_input_proofs_json,
            change_amount_raw,
        )
        .unwrap();
        let swap_json: serde_json::Value = serde_json::from_str(&swap_result).unwrap();
        let change_secrets_json = swap_json["change_secrets_json"]
            .as_str()
            .unwrap()
            .to_string();
        storage
            .save_opening_from_swap(
                &channel_id,
                ClientChannelOpeningFromSwap {
                    params_json: params_json.clone(),
                    channel_secret_hex: channel_secret_hex.clone(),
                    keyset_info_json: keyset_info_json.clone(),
                    sender_pubkey_hex: wallet.sender_pubkey_hex.clone(),
                    receiver_pubkey_hex: receiver_pubkey.clone(),
                    capacity,
                    funding_token_amount,
                    mint_url: mint_url.clone(),
                    unit: unit.to_string(),
                    input_token: input_proofs_json.clone(),
                    change_secrets_json,
                    change_amount_raw,
                    created_at: SqliteClientWallet::now_seconds().unwrap(),
                },
            )
            .unwrap();
        let swap_request_json = swap_json["swap_request_json"].as_str().unwrap();
        let swap_response = client
            .post(format!("{mint_url}/v1/swap"))
            .header("Content-Type", "application/json")
            .body(swap_request_json.to_string())
            .send()
            .await
            .unwrap();
        if !swap_response.status().is_success() {
            let status = swap_response.status();
            let body = swap_response.text().await.unwrap_or_default();
            panic!("swap failed with {status}: {body}");
        }

        let simulated_error = OpenChannelError {
            stage: OpenChannelFailureStage::RestoreVerification,
            channel_id: Some(channel_id.clone()),
            input_may_be_spent: true,
            message: "simulated crash after swap".to_string(),
        };
        wallet
            .store_opening_recovery(
                &channel_id,
                &reservation.reservation_id,
                &offer,
                input_budget_msats,
                &simulated_error,
            )
            .unwrap();
        drop(storage);
        drop(wallet);

        let loose_wallet = LooseProofWallet::open(&loose_db, "alice").unwrap();
        let wallet = SqliteClientWallet::open(loose_wallet, &channel_db, &sender_secret).unwrap();
        let recovered = wallet.recover_pending_openings().unwrap();
        assert_eq!(recovered, vec![channel_id.clone()]);

        let channel = wallet.get_channel(&channel_id).unwrap();
        assert_eq!(channel.state, WalletChannelState::Open);
        assert!(channel.capacity_msats > 0);
        assert!(channel.capacity_msats <= input_budget_msats);

        let reserved = wallet
            .loose_wallet()
            .proofs_for_reservation(&reservation.reservation_id)
            .unwrap();
        assert!(!reserved.is_empty());
        assert!(reserved
            .iter()
            .all(|proof| proof.state == LooseProofState::Spent));

        let available_change = wallet
            .loose_wallet()
            .available_balance_raw(&mint_url, unit, std::slice::from_ref(&keyset_id))
            .unwrap();
        assert_eq!(available_change, expected_change_raw);
        assert!(wallet.recover_pending_openings().unwrap().is_empty());

        let _ = shutdown_tx.send(());
        mint_task.await.unwrap().unwrap();
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn output_keyset_selection_refreshes_stale_client_when_relay_offer_is_fresh() {
        let mint_helper = TestMintHelper::new().await.unwrap();
        let mint = mint_helper.mint();
        let first_keyset_id = mint_helper.keyset_id().to_string();

        let port = free_loopback_port();
        let mint_url = format!("http://127.0.0.1:{port}");
        let config = TestMintConfig::for_port(port);
        let (shutdown_tx, shutdown_rx) = oneshot::channel::<()>();
        let mint_for_server = mint.clone();
        let mint_task = tokio::spawn(async move {
            serve_existing_mint_with_shutdown(mint_for_server, config, async {
                let _ = shutdown_rx.await;
            })
            .await
        });
        let client = reqwest::Client::new();
        wait_for_mint(&client, &mint_url).await;

        let temp = tempfile::tempdir().unwrap();
        let loose_wallet =
            LooseProofWallet::open(temp.path().join("loose.sqlite"), "alice").unwrap();
        let wallet = SqliteClientWallet::open(
            loose_wallet,
            temp.path().join("channels.sqlite"),
            &sender_secret_hex(),
        )
        .unwrap();
        let receiver_pubkey = "02a9acc1e48c25eeeb9289b5031cc57da9fe72f3fe2861d264bdc074209b107ba2";

        let first_offer = offer(&mint_url, receiver_pubkey, &first_keyset_id);
        let selected = wallet
            .select_output_keyset_refreshing_client_first(&first_offer)
            .unwrap();
        assert_eq!(selected.id, first_keyset_id);

        let second_keyset_id = rotate_sat_keyset(&mint, 0).await.unwrap().to_string();
        // The relay offer is already fresh, but this wallet has only cached the
        // old keyset. Selection must refresh the client cache and pick the
        // relay-advertised active keyset instead of reporting a stale relay.
        let second_offer = offer(&mint_url, receiver_pubkey, &second_keyset_id);
        let selected = wallet
            .select_output_keyset_refreshing_client_first(&second_offer)
            .unwrap();
        assert_eq!(selected.id, second_keyset_id);

        let _ = shutdown_tx.send(());
        mint_task.await.unwrap().unwrap();
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn output_keyset_selection_reports_stale_relay_only_after_client_refresh() {
        let mint_helper = TestMintHelper::new().await.unwrap();
        let mint = mint_helper.mint();
        let first_keyset_id = mint_helper.keyset_id().to_string();
        let unknown_keyset_id =
            "010000000000000000000000000000000000000000000000000000000000000000".to_string();
        assert_ne!(first_keyset_id, unknown_keyset_id);

        let port = free_loopback_port();
        let mint_url = format!("http://127.0.0.1:{port}");
        let config = TestMintConfig::for_port(port);
        let (shutdown_tx, shutdown_rx) = oneshot::channel::<()>();
        let mint_for_server = mint.clone();
        let mint_task = tokio::spawn(async move {
            serve_existing_mint_with_shutdown(mint_for_server, config, async {
                let _ = shutdown_rx.await;
            })
            .await
        });
        let client = reqwest::Client::new();
        wait_for_mint(&client, &mint_url).await;

        let temp = tempfile::tempdir().unwrap();
        let loose_wallet =
            LooseProofWallet::open(temp.path().join("loose.sqlite"), "alice").unwrap();
        let wallet = SqliteClientWallet::open(
            loose_wallet,
            temp.path().join("channels.sqlite"),
            &sender_secret_hex(),
        )
        .unwrap();
        let receiver_pubkey = "02a9acc1e48c25eeeb9289b5031cc57da9fe72f3fe2861d264bdc074209b107ba2";

        let first_offer = offer(&mint_url, receiver_pubkey, &unknown_keyset_id);
        let error = wallet
            .select_output_keyset_refreshing_client_first(&first_offer)
            .unwrap_err();
        let cached_keysets = wallet
            .bridge
            .lock()
            .unwrap()
            .cached_keysets_for_unit(&mint_url, &CurrencyUnit::Sat);
        assert!(cached_keysets
            .iter()
            .any(|(keyset_id, _entry)| keyset_id.to_string() == first_keyset_id));
        assert!(matches!(
            error,
            WalletError::StaleRelayKeysets {
                mint_url: error_mint_url,
                unit,
                accepted_keyset_ids,
            } if error_mint_url == mint_url
                && unit == "sat"
                && accepted_keyset_ids == vec![unknown_keyset_id]
        ));

        let _ = shutdown_tx.send(());
        mint_task.await.unwrap().unwrap();
    }

    #[test]
    fn active_output_keyset_selection_skips_inactive_accepted_keysets() {
        let old =
            test_keyset_id("0101010101010101010101010101010101010101010101010101010101010101");
        let new =
            test_keyset_id("0202020202020202020202020202020202020202020202020202020202020202");
        let offer = RelayPaymentOffer {
            receiver_pubkey: "receiver".to_string(),
            mint_url: "http://mint".to_string(),
            unit: "sat".to_string(),
            accepted_keyset_ids: vec![old.to_string(), new.to_string()],
            in_bytes_per_millisat: 1,
            out_bytes_per_millisat: 1,
        };
        let bridge = bridge_with_cached_keysets(vec![
            (old, CurrencyUnit::Sat, false),
            (new, CurrencyUnit::Sat, true),
        ]);

        let selected = active_output_keyset_id_from_cache(&bridge, &offer).unwrap();
        assert_eq!(selected, OutputKeysetSelection::Selected(new.to_string()));
    }

    #[test]
    fn active_output_keyset_selection_rejects_without_active_accepted_keyset() {
        let old =
            test_keyset_id("0101010101010101010101010101010101010101010101010101010101010101");
        let other_unit =
            test_keyset_id("0202020202020202020202020202020202020202020202020202020202020202");
        let offer = RelayPaymentOffer {
            receiver_pubkey: "receiver".to_string(),
            mint_url: "http://mint".to_string(),
            unit: "sat".to_string(),
            accepted_keyset_ids: vec![old.to_string(), other_unit.to_string()],
            in_bytes_per_millisat: 1,
            out_bytes_per_millisat: 1,
        };
        let bridge = bridge_with_cached_keysets(vec![
            (old, CurrencyUnit::Sat, false),
            (other_unit, CurrencyUnit::Msat, true),
        ]);

        let selected = active_output_keyset_id_from_cache(&bridge, &offer).unwrap();
        assert_eq!(selected, OutputKeysetSelection::NoActiveAcceptedKeyset);
    }

    #[test]
    fn open_retry_gate_allows_only_first_safe_keyset_rejection() {
        let error = OpenChannelError {
            stage: OpenChannelFailureStage::MintRejected,
            channel_id: Some("channel".to_string()),
            input_may_be_spent: false,
            message: r#"{"code":12001,"detail":"keyset is not known"}"#.to_string(),
        };

        assert!(should_retry_open_after_keyset_rejection(&error, false));
        assert!(!should_retry_open_after_keyset_rejection(&error, true));
    }

    #[test]
    fn open_retry_gate_rejects_ambiguous_or_non_keyset_errors() {
        let ambiguous = OpenChannelError {
            stage: OpenChannelFailureStage::SwapSubmitted,
            channel_id: Some("channel".to_string()),
            input_may_be_spent: true,
            message: r#"{"code":12001,"detail":"keyset is not known"}"#.to_string(),
        };
        assert!(!should_retry_open_after_keyset_rejection(&ambiguous, false));

        let non_keyset = OpenChannelError {
            stage: OpenChannelFailureStage::MintRejected,
            channel_id: Some("channel".to_string()),
            input_may_be_spent: false,
            message: r#"{"code":11001,"detail":"proofs already spent"}"#.to_string(),
        };
        assert!(!should_retry_open_after_keyset_rejection(
            &non_keyset,
            false
        ));
    }
}
