//! SQLite-backed MONAD client wallet.
//!
//! Bridges `LooseProofWallet` (bearer-proof custody) with upstream
//! `cdk-spilman` Spilman channel operations, implementing `MonadWallet`.

use crate::loose_proof_wallet::{LooseProofWallet, LooseProofWalletError, ProofReservation};
use crate::proof_selection::{select_mixed_fee_inputs_for_post_swap_target, ProofCandidate};
use crate::wallet::{
    msats_to_raw_units, raw_to_msats, MonadWallet, RelayPaymentOffer, WalletChannel,
    WalletChannelState, WalletError,
};
use cashu::nuts::{CurrencyUnit, Id};
use cdk_spilman::{
    compute_funding_token_amount, parse_keyset_info_from_json, ClientChannelInfo,
    ConfigurableClientHost, OpenChannelError, OpenChannelFailureStage, OpenChannelResult,
    ReqwestClientNetworking, SpilmanClientBridge, SpilmanClientHost, SpilmanClientNetworking,
    SqliteClientStorage,
};
use rusqlite::{params, Connection};
use std::collections::HashMap;
use std::path::Path;
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

/// Client wallet backed by SQLite.
///
/// `LooseProofWallet` holds bearer proofs; this layer manages Spilman channel
/// metadata and payment signing via `cdk-spilman`.
pub struct SqliteClientWallet {
    loose_wallet: LooseProofWallet,
    bridge: Mutex<ClientBridge>,
    sender_pubkey_hex: String,
    channel_db: Mutex<Connection>,
}

struct TargetCapacityAttempt {
    output_keyset_id: String,
    reservation: ProofReservation,
    requested_capacity_raw: u64,
    selected_input_msats: u64,
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

        let mut host = ConfigurableClientHost::<SqliteClientStorage>::open_sqlite(path_str)
            .map_err(|e| {
                WalletError::Backend(format!("open upstream sqlite client storage: {e}"))
            })?;
        let sender_pubkey_hex = host
            .add_key_from_hex(sender_secret_hex)
            .map_err(|e| WalletError::Backend(format!("add sender key: {e}")))?;

        let bridge = SpilmanClientBridge::new(host, ReqwestClientNetworking::new());

        let channel_db = Connection::open(path)
            .map_err(|e| WalletError::Backend(format!("open channel metadata database: {e}")))?;
        channel_db
            .busy_timeout(Duration::from_secs(5))
            .map_err(|e| WalletError::Backend(format!("set channel db busy timeout: {e}")))?;
        channel_db
            .execute_batch(&format!(
                "{CREATE_CHANNELS_SQL};{CREATE_OPENING_RECOVERIES_SQL};"
            ))
            .map_err(|e| WalletError::Backend(format!("create channel metadata schema: {e}")))?;

        Ok(Self {
            loose_wallet,
            bridge: Mutex::new(bridge),
            sender_pubkey_hex,
            channel_db: Mutex::new(channel_db),
        })
    }

    /// Access the underlying loose-proof wallet.
    pub fn loose_wallet(&self) -> &LooseProofWallet {
        &self.loose_wallet
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
        let mut retried = false;
        loop {
            let attempt = self.prepare_target_capacity_attempt(offer, target_capacity_raw)?;
            match self.submit_reserved_channel(
                offer,
                &attempt.output_keyset_id,
                &attempt.reservation,
                Some(attempt.requested_capacity_raw),
            ) {
                Ok(open_result) => {
                    return self.finish_open_channel(open_result, &attempt.reservation);
                }
                Err(error) if should_retry_open_after_keyset_rejection(&error, retried) => {
                    retried = true;
                    let _ = self
                        .loose_wallet
                        .release_reservation(&attempt.reservation.reservation_id);
                    continue;
                }
                Err(error) => {
                    return self.handle_open_error(
                        error,
                        &attempt.reservation,
                        offer,
                        attempt.selected_input_msats,
                    );
                }
            }
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

        for recovery in recoveries {
            let result = {
                let bridge = self
                    .bridge
                    .lock()
                    .map_err(|_| WalletError::Backend("bridge mutex poisoned".to_string()))?;
                bridge.recover_open_channel_from_swap(&recovery.channel_id)
            };

            match result {
                Ok(open_result) => {
                    self.loose_wallet
                        .mark_reservation_spent(&recovery.reservation_id, &open_result.channel_id)
                        .map_err(loose_proof_error)?;
                    self.store_open_channel_metadata(&open_result, &recovery.reservation_id)?;
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

    fn conn(&self) -> Result<std::sync::MutexGuard<'_, Connection>, WalletError> {
        self.channel_db
            .lock()
            .map_err(|_| WalletError::Backend("channel db mutex poisoned".to_string()))
    }

    fn store_open_channel_metadata(
        &self,
        open_result: &OpenChannelResult,
        reservation_id: &str,
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
              created_at, updated_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, NULL, ?7, ?8, ?9, ?9)",
            params![
                open_result.channel_id,
                open_result.receiver_pubkey_hex,
                open_result.mint_url,
                open_result.unit,
                open_result.keyset_id,
                to_i64(capacity_msats)?,
                channel_state_str(WalletChannelState::Open),
                reservation_id,
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

    fn submit_reserved_channel(
        &self,
        offer: &RelayPaymentOffer,
        output_keyset_id: &str,
        reservation: &ProofReservation,
        requested_capacity_raw: Option<u64>,
    ) -> Result<OpenChannelResult, OpenChannelError> {
        let input_proofs_json = match proofs_json_from_reservation(reservation) {
            Ok(json) => json,
            Err(e) => {
                return Err(OpenChannelError {
                    stage: OpenChannelFailureStage::BeforeOpeningSaved,
                    channel_id: None,
                    input_may_be_spent: false,
                    message: e.to_string(),
                });
            }
        };

        let expiry_timestamp = Self::now_seconds().map_err(|e| OpenChannelError {
            stage: OpenChannelFailureStage::BeforeOpeningSaved,
            channel_id: None,
            input_may_be_spent: false,
            message: e.to_string(),
        })? + CHANNEL_EXPIRY_SECONDS;
        {
            let bridge = self.bridge.lock().map_err(|_| OpenChannelError {
                stage: OpenChannelFailureStage::BeforeOpeningSaved,
                channel_id: None,
                input_may_be_spent: false,
                message: "bridge mutex poisoned".to_string(),
            })?;
            bridge.open_channel_from_proofs_with_keyset_id(
                &offer.mint_url,
                &offer.unit,
                &input_proofs_json,
                &offer.receiver_pubkey,
                &self.sender_pubkey_hex,
                expiry_timestamp,
                output_keyset_id,
                0,
                requested_capacity_raw,
            )
        }
    }

    fn finish_open_channel(
        &self,
        open_result: OpenChannelResult,
        reservation: &ProofReservation,
    ) -> Result<String, WalletError> {
        self.loose_wallet
            .mark_reservation_spent(&reservation.reservation_id, &open_result.channel_id)
            .map_err(loose_proof_error)?;
        self.store_open_channel_metadata(&open_result, &reservation.reservation_id)?;
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

    fn refresh_keysets_and_select_output_keyset(
        &self,
        offer: &RelayPaymentOffer,
    ) -> Result<String, WalletError> {
        let bridge = self
            .bridge
            .lock()
            .map_err(|_| WalletError::Backend("bridge mutex poisoned".to_string()))?;
        bridge
            .refresh_keysets_response(&offer.mint_url)
            .map_err(|e| WalletError::Backend(format!("refresh mint keysets: {e}")))?;
        active_output_keyset_id_from_cache(&bridge, offer)
    }

    fn prepare_target_capacity_attempt(
        &self,
        offer: &RelayPaymentOffer,
        target_capacity_raw: u64,
    ) -> Result<TargetCapacityAttempt, WalletError> {
        let (output_keyset_id, output_keyset_info_json) = {
            let bridge = self
                .bridge
                .lock()
                .map_err(|_| WalletError::Backend("bridge mutex poisoned".to_string()))?;
            bridge
                .refresh_keysets_response(&offer.mint_url)
                .map_err(|e| WalletError::Backend(format!("refresh mint keysets: {e}")))?;
            let output_keyset_id = active_output_keyset_id_from_cache(&bridge, offer)?;
            let output_keyset_info_json =
                cached_keyset_info_json(&bridge, &offer.mint_url, &output_keyset_id)?;
            (output_keyset_id, output_keyset_info_json)
        };

        let required_post_swap_raw =
            compute_funding_token_amount(target_capacity_raw, &output_keyset_info_json, 0)
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

        Ok(TargetCapacityAttempt {
            output_keyset_id,
            reservation,
            requested_capacity_raw: target_capacity_raw,
            selected_input_msats,
        })
    }
}

impl MonadWallet for SqliteClientWallet {
    fn list_channels(&self) -> Result<Vec<WalletChannel>, WalletError> {
        let conn = self.conn()?;
        let mut stmt = conn
            .prepare(
                "SELECT channel_id, receiver_pubkey, mint_url, unit, keyset_id,
                        capacity_msats, attached_session_id, state
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
                        capacity_msats, attached_session_id, state
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

        let input_budget_raw = msats_to_raw_units(&offer.unit, input_budget_msats)?;
        let output_keyset_id = self.refresh_keysets_and_select_output_keyset(offer)?;
        let reservation = self
            .loose_wallet
            .reserve_proofs_any_keyset(&offer.mint_url, &offer.unit, input_budget_raw)
            .map_err(loose_proof_error)?;
        match self.submit_reserved_channel(offer, &output_keyset_id, &reservation, None) {
            Ok(open_result) => self.finish_open_channel(open_result, &reservation),
            Err(error) if should_retry_open_after_keyset_rejection(&error, false) => {
                let retry_output_keyset_id =
                    self.refresh_keysets_and_select_output_keyset(offer)?;
                match self.submit_reserved_channel(
                    offer,
                    &retry_output_keyset_id,
                    &reservation,
                    None,
                ) {
                    Ok(open_result) => self.finish_open_channel(open_result, &reservation),
                    Err(error) => {
                        self.handle_open_error(error, &reservation, offer, input_budget_msats)
                    }
                }
            }
            Err(error) => self.handle_open_error(error, &reservation, offer, input_budget_msats),
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
                .create_payment_with_funding(channel_id, 0)
                .map_err(|e| map_create_payment_error(&channel, e, 0))
        };
        let payment = payment?;
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
            bridge
                .create_payment(channel_id, next_balance_raw)
                .map_err(|e| map_create_payment_error(&channel, e, next_balance_raw))
        };
        let payment = payment?;
        serde_json::to_string(&payment)
            .map_err(|e| WalletError::Backend(format!("serialize channel payment: {e}")))
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

fn loose_proof_error(error: LooseProofWalletError) -> WalletError {
    WalletError::Backend(format!("loose proof wallet: {error}"))
}

fn active_output_keyset_id_from_cache<H, N>(
    bridge: &SpilmanClientBridge<H, N>,
    offer: &RelayPaymentOffer,
) -> Result<String, WalletError>
where
    H: SpilmanClientHost,
    N: SpilmanClientNetworking,
{
    let unit = parse_currency_unit(&offer.unit)?;
    let active_ids = bridge.cached_active_keyset_ids(&offer.mint_url, &unit);

    for accepted_id in &offer.accepted_keyset_ids {
        if active_ids.iter().any(|id| id.to_string() == *accepted_id) {
            return Ok(accepted_id.clone());
        }
    }

    Err(WalletError::OfferMismatch(
        "offer has no active accepted keyset".to_string(),
    ))
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
    use cdk_spilman::{
        channel_parameters_get_channel_id, compute_channel_from_proofs_with_input_keysets,
        compute_channel_secret_from_hex, construct_proofs, create_funding_swap,
        create_plain_blinded_messages, ClientChannelOpeningFromSwap, ClientKeysetCacheEntry,
        ClientStorage, ConfigurableClientHost, MemoryClientStorage, OpenChannelError,
        OpenChannelFailureStage, Payment, ReqwestClientNetworking, SpilmanClientBridge,
        SpilmanClientHost, SqliteClientStorage,
    };
    use cdk_spilman_test_mint::{
        rotate_sat_keyset, serve_existing_mint_with_shutdown, serve_mint_with_shutdown,
        TestMintConfig, TestMintHelper,
    };
    use rand::RngCore;
    use tokio::sync::oneshot;

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

        let amount_raw = 16u64;
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

        let wallet =
            SqliteClientWallet::open(loose_wallet, &channel_db, &sender_secret_hex()).unwrap();

        // Use a valid dummy receiver pubkey (relay would provide a real one).
        let receiver_pubkey =
            "02a9acc1e48c25eeeb9289b5031cc57da9fe72f3fe2861d264bdc074209b107ba2".to_string();

        let input_budget_msats = amount_raw * 1000;
        let offer = offer(&mint_url, &receiver_pubkey, &keyset_id);
        let channel_id = wallet
            .provision_channel(&offer, input_budget_msats)
            .expect("provision channel from loose proofs");

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

        // Loose proofs used for the channel should be spent.
        let available = wallet
            .loose_wallet()
            .available_balance_raw(&mint_url, unit, std::slice::from_ref(&keyset_id))
            .unwrap();
        assert_eq!(available, 0);

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

        let amount_raw = 16u64;
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
        let input_budget_msats = amount_raw * 1000;
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
        let compute_result = compute_channel_from_proofs_with_input_keysets(
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
        )
        .unwrap();
        let compute_json: serde_json::Value = serde_json::from_str(&compute_result).unwrap();
        let params_json = compute_json["params_json"].as_str().unwrap().to_string();
        let swap_input_proofs_json = compute_json["proofs_json"].as_str().unwrap().to_string();
        let capacity = compute_json["capacity"].as_u64().unwrap();
        let funding_token_amount = compute_json["funding_token_amount"].as_u64().unwrap();

        let channel_id =
            channel_parameters_get_channel_id(&params_json, &channel_secret_hex, &keyset_info_json)
                .unwrap();
        let mut storage =
            SqliteClientStorage::open(channel_db.to_str().unwrap()).expect("open client storage");
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
                    created_at: SqliteClientWallet::now_seconds().unwrap(),
                },
            )
            .unwrap();

        let swap_result = create_funding_swap(
            &params_json,
            &channel_secret_hex,
            &keyset_info_json,
            &swap_input_proofs_json,
        )
        .unwrap();
        let swap_json: serde_json::Value = serde_json::from_str(&swap_result).unwrap();
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
        assert_eq!(selected, new.to_string());
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

        let error = active_output_keyset_id_from_cache(&bridge, &offer).unwrap_err();
        assert!(matches!(error, WalletError::OfferMismatch(_)));
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
