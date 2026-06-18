//! SQLite-backed wallet for loose Cashu proofs.
//!
//! This module intentionally stops before Spilman channel provisioning. It owns
//! the durable state needed to mint bearer proofs safely, then reserve those
//! proofs for a later channel-opening step.

use rand::RngCore;
use rusqlite::types::Value;
use rusqlite::{params, params_from_iter, Connection, OptionalExtension, TransactionBehavior};
use std::collections::HashSet;
use std::fmt;
use std::io;
use std::path::Path;
use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};

pub type Result<T> = std::result::Result<T, LooseProofWalletError>;

const CREATE_MINT_QUOTES_SQL: &str = r#"
    CREATE TABLE IF NOT EXISTS monad_client_mint_quotes (
        quote_id TEXT PRIMARY KEY,
        wallet_name TEXT NOT NULL,
        mint_url TEXT NOT NULL,
        unit TEXT NOT NULL,
        amount_raw INTEGER NOT NULL,
        invoice TEXT NOT NULL,
        state TEXT NOT NULL,
        created_at INTEGER NOT NULL,
        updated_at INTEGER NOT NULL,
        expires_at INTEGER
    )
"#;

const CREATE_PREMINT_BATCHES_SQL: &str = r#"
    CREATE TABLE IF NOT EXISTS monad_client_premint_batches (
        batch_id TEXT PRIMARY KEY,
        quote_id TEXT NOT NULL UNIQUE,
        wallet_name TEXT NOT NULL,
        mint_url TEXT NOT NULL,
        unit TEXT NOT NULL,
        keyset_id TEXT NOT NULL,
        amount_raw INTEGER NOT NULL,
        blinded_messages_json TEXT NOT NULL,
        secrets_with_blinding_json TEXT NOT NULL,
        state TEXT NOT NULL,
        created_at INTEGER NOT NULL,
        updated_at INTEGER NOT NULL
    )
"#;

const CREATE_LOOSE_PROOFS_SQL: &str = r#"
    CREATE TABLE IF NOT EXISTS monad_client_loose_proofs (
        proof_id TEXT NOT NULL,
        wallet_name TEXT NOT NULL,
        mint_url TEXT NOT NULL,
        unit TEXT NOT NULL,
        keyset_id TEXT NOT NULL,
        amount_raw INTEGER NOT NULL,
        proof_json TEXT NOT NULL,
        state TEXT NOT NULL,
        source_quote_id TEXT,
        source_batch_id TEXT,
        reserved_by TEXT,
        spent_channel_id TEXT,
        created_at INTEGER NOT NULL,
        updated_at INTEGER NOT NULL,
        PRIMARY KEY (wallet_name, proof_id)
    )
"#;

const CREATE_LOOSE_PROOF_INDEX_SQL: &str = r#"
    CREATE INDEX IF NOT EXISTS idx_monad_client_loose_proofs_available
    ON monad_client_loose_proofs(wallet_name, mint_url, unit, state, keyset_id)
"#;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MintQuoteState {
    Pending,
    Paid,
    Completed,
    Expired,
}

impl MintQuoteState {
    fn as_str(self) -> &'static str {
        match self {
            Self::Pending => "pending",
            Self::Paid => "paid",
            Self::Completed => "completed",
            Self::Expired => "expired",
        }
    }

    fn parse(value: &str) -> rusqlite::Result<Self> {
        match value {
            "pending" => Ok(Self::Pending),
            "paid" => Ok(Self::Paid),
            "completed" => Ok(Self::Completed),
            "expired" => Ok(Self::Expired),
            other => Err(sql_decode_error(format!(
                "unknown mint quote state '{other}'"
            ))),
        }
    }
}

impl fmt::Display for MintQuoteState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PremintBatchState {
    Prepared,
    Submitted,
    Completed,
}

impl PremintBatchState {
    fn as_str(self) -> &'static str {
        match self {
            Self::Prepared => "prepared",
            Self::Submitted => "submitted",
            Self::Completed => "completed",
        }
    }

    fn parse(value: &str) -> rusqlite::Result<Self> {
        match value {
            "prepared" => Ok(Self::Prepared),
            "submitted" => Ok(Self::Submitted),
            "completed" => Ok(Self::Completed),
            other => Err(sql_decode_error(format!(
                "unknown premint batch state '{other}'"
            ))),
        }
    }
}

impl fmt::Display for PremintBatchState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LooseProofState {
    Available,
    Reserved,
    Spent,
}

impl LooseProofState {
    fn as_str(self) -> &'static str {
        match self {
            Self::Available => "available",
            Self::Reserved => "reserved",
            Self::Spent => "spent",
        }
    }

    fn parse(value: &str) -> rusqlite::Result<Self> {
        match value {
            "available" => Ok(Self::Available),
            "reserved" => Ok(Self::Reserved),
            "spent" => Ok(Self::Spent),
            other => Err(sql_decode_error(format!(
                "unknown loose proof state '{other}'"
            ))),
        }
    }
}

impl fmt::Display for LooseProofState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MintQuoteRecord {
    pub quote_id: String,
    pub wallet_name: String,
    pub mint_url: String,
    pub unit: String,
    pub amount_raw: u64,
    pub invoice: String,
    pub state: MintQuoteState,
    pub created_at: u64,
    pub updated_at: u64,
    pub expires_at: Option<u64>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NewMintQuote {
    pub quote_id: String,
    pub mint_url: String,
    pub unit: String,
    pub amount_raw: u64,
    pub invoice: String,
    pub expires_at: Option<u64>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PremintBatchRecord {
    pub batch_id: String,
    pub quote_id: String,
    pub wallet_name: String,
    pub mint_url: String,
    pub unit: String,
    pub keyset_id: String,
    pub amount_raw: u64,
    pub blinded_messages_json: String,
    pub secrets_with_blinding_json: String,
    pub state: PremintBatchState,
    pub created_at: u64,
    pub updated_at: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NewPremintBatch {
    pub batch_id: String,
    pub quote_id: String,
    pub mint_url: String,
    pub unit: String,
    pub keyset_id: String,
    pub amount_raw: u64,
    pub blinded_messages_json: String,
    pub secrets_with_blinding_json: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LooseProofRecord {
    pub proof_id: String,
    pub wallet_name: String,
    pub mint_url: String,
    pub unit: String,
    pub keyset_id: String,
    pub amount_raw: u64,
    pub proof_json: String,
    pub state: LooseProofState,
    pub source_quote_id: Option<String>,
    pub source_batch_id: Option<String>,
    pub reserved_by: Option<String>,
    pub spent_channel_id: Option<String>,
    pub created_at: u64,
    pub updated_at: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NewLooseProof {
    pub proof_id: String,
    pub mint_url: String,
    pub unit: String,
    pub keyset_id: String,
    pub amount_raw: u64,
    pub proof_json: String,
    pub source_quote_id: Option<String>,
    pub source_batch_id: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProofReservation {
    pub reservation_id: String,
    pub proofs: Vec<LooseProofRecord>,
    pub total_amount_raw: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LooseProofWalletError {
    InvalidInput(String),
    NotFound(String),
    InsufficientBalance {
        requested: u64,
        available: u64,
    },
    ReservationConflict {
        expected: usize,
        updated: usize,
    },
    InvalidStateTransition {
        entity: &'static str,
        id: String,
        expected: &'static str,
        actual: String,
        requested: &'static str,
    },
    Backend(String),
}

impl fmt::Display for LooseProofWalletError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidInput(message) => write!(f, "invalid input: {message}"),
            Self::NotFound(message) => write!(f, "not found: {message}"),
            Self::InsufficientBalance { requested, available } => write!(
                f,
                "insufficient loose proofs: requested={requested} available={available}"
            ),
            Self::ReservationConflict { expected, updated } => write!(
                f,
                "proof reservation conflict: expected to reserve {expected} proofs, reserved {updated}"
            ),
            Self::InvalidStateTransition {
                entity,
                id,
                expected,
                actual,
                requested,
            } => write!(
                f,
                "invalid {entity} state transition for {id}: expected {expected}, actual {actual}, requested {requested}"
            ),
            Self::Backend(message) => write!(f, "loose proof wallet backend error: {message}"),
        }
    }
}

impl std::error::Error for LooseProofWalletError {}

impl From<io::Error> for LooseProofWalletError {
    fn from(error: io::Error) -> Self {
        Self::Backend(error.to_string())
    }
}

impl From<rusqlite::Error> for LooseProofWalletError {
    fn from(error: rusqlite::Error) -> Self {
        Self::Backend(error.to_string())
    }
}

#[derive(Debug, Clone)]
pub struct LooseProofWallet {
    wallet_name: String,
    conn: Arc<Mutex<Connection>>,
}

impl LooseProofWallet {
    pub fn open(path: impl AsRef<Path>, wallet_name: impl Into<String>) -> Result<Self> {
        let conn = Connection::open(path).map_err(|e| {
            LooseProofWalletError::Backend(format!("open loose proof wallet db: {e}"))
        })?;
        conn.busy_timeout(std::time::Duration::from_secs(5))
            .map_err(|e| {
                LooseProofWalletError::Backend(format!("set loose proof wallet busy timeout: {e}"))
            })?;
        conn.execute_batch(&format!(
            "{CREATE_MINT_QUOTES_SQL};{CREATE_PREMINT_BATCHES_SQL};{CREATE_LOOSE_PROOFS_SQL};{CREATE_LOOSE_PROOF_INDEX_SQL};"
        ))
        .map_err(|e| LooseProofWalletError::Backend(format!("create loose proof wallet schema: {e}")))?;
        Ok(Self {
            wallet_name: wallet_name.into(),
            conn: Arc::new(Mutex::new(conn)),
        })
    }

    #[cfg(test)]
    fn open_in_memory(wallet_name: impl Into<String>) -> Result<Self> {
        let conn = Connection::open_in_memory().map_err(|e| {
            LooseProofWalletError::Backend(format!("open loose proof wallet db: {e}"))
        })?;
        conn.execute_batch(&format!(
            "{CREATE_MINT_QUOTES_SQL};{CREATE_PREMINT_BATCHES_SQL};{CREATE_LOOSE_PROOFS_SQL};{CREATE_LOOSE_PROOF_INDEX_SQL};"
        ))
        .map_err(|e| LooseProofWalletError::Backend(format!("create loose proof wallet schema: {e}")))?;
        Ok(Self {
            wallet_name: wallet_name.into(),
            conn: Arc::new(Mutex::new(conn)),
        })
    }

    pub fn store_mint_quote(&self, quote: NewMintQuote) -> Result<()> {
        validate_nonempty("quote_id", &quote.quote_id)?;
        validate_nonempty("mint_url", &quote.mint_url)?;
        validate_nonempty("unit", &quote.unit)?;
        validate_nonempty("invoice", &quote.invoice)?;
        let now = now_seconds()?;
        let conn = self.conn()?;
        conn.execute(
            "INSERT INTO monad_client_mint_quotes
             (quote_id, wallet_name, mint_url, unit, amount_raw, invoice, state, created_at, updated_at, expires_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?8, ?9)",
            params![
                quote.quote_id,
                self.wallet_name,
                quote.mint_url,
                quote.unit,
                to_i64(quote.amount_raw)?,
                quote.invoice,
                MintQuoteState::Pending.as_str(),
                to_i64(now)?,
                optional_to_i64(quote.expires_at)?,
            ],
        )
        .map_err(|e| LooseProofWalletError::Backend(format!("store mint quote: {e}")))?;
        Ok(())
    }

    pub fn mint_quote(&self, quote_id: &str) -> Result<Option<MintQuoteRecord>> {
        let conn = self.conn()?;
        conn.query_row(
            "SELECT quote_id, wallet_name, mint_url, unit, amount_raw, invoice, state, created_at, updated_at, expires_at
             FROM monad_client_mint_quotes
             WHERE quote_id = ?1 AND wallet_name = ?2",
            params![quote_id, self.wallet_name],
            row_to_mint_quote,
        )
        .optional()
        .map_err(|e| LooseProofWalletError::Backend(format!("query mint quote: {e}")))
    }

    pub fn mark_quote_paid(&self, quote_id: &str) -> Result<()> {
        self.transition_mint_quote(quote_id, MintQuoteState::Pending, MintQuoteState::Paid)
    }

    pub fn mark_quote_completed(&self, quote_id: &str) -> Result<()> {
        self.transition_mint_quote(quote_id, MintQuoteState::Paid, MintQuoteState::Completed)
    }

    pub fn mark_quote_expired(&self, quote_id: &str) -> Result<()> {
        self.transition_mint_quote(quote_id, MintQuoteState::Pending, MintQuoteState::Expired)
    }

    pub fn store_premint_batch(&self, batch: NewPremintBatch) -> Result<()> {
        validate_nonempty("batch_id", &batch.batch_id)?;
        validate_nonempty("quote_id", &batch.quote_id)?;
        validate_nonempty("mint_url", &batch.mint_url)?;
        validate_nonempty("unit", &batch.unit)?;
        validate_nonempty("keyset_id", &batch.keyset_id)?;
        let now = now_seconds()?;
        let conn = self.conn()?;
        conn.execute(
            "INSERT INTO monad_client_premint_batches
             (batch_id, quote_id, wallet_name, mint_url, unit, keyset_id, amount_raw,
              blinded_messages_json, secrets_with_blinding_json, state, created_at, updated_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?11)",
            params![
                batch.batch_id,
                batch.quote_id,
                self.wallet_name,
                batch.mint_url,
                batch.unit,
                batch.keyset_id,
                to_i64(batch.amount_raw)?,
                batch.blinded_messages_json,
                batch.secrets_with_blinding_json,
                PremintBatchState::Prepared.as_str(),
                to_i64(now)?,
            ],
        )
        .map_err(|e| LooseProofWalletError::Backend(format!("store premint batch: {e}")))?;
        Ok(())
    }

    pub fn premint_batch_for_quote(&self, quote_id: &str) -> Result<Option<PremintBatchRecord>> {
        let conn = self.conn()?;
        conn.query_row(
            "SELECT batch_id, quote_id, wallet_name, mint_url, unit, keyset_id, amount_raw,
                    blinded_messages_json, secrets_with_blinding_json, state, created_at, updated_at
             FROM monad_client_premint_batches
             WHERE quote_id = ?1 AND wallet_name = ?2",
            params![quote_id, self.wallet_name],
            row_to_premint_batch,
        )
        .optional()
        .map_err(|e| LooseProofWalletError::Backend(format!("query premint batch: {e}")))
    }

    pub fn mark_premint_submitted(&self, batch_id: &str) -> Result<()> {
        self.transition_premint_batch(
            batch_id,
            PremintBatchState::Prepared,
            PremintBatchState::Submitted,
        )
    }

    pub fn mark_premint_completed(&self, batch_id: &str) -> Result<()> {
        self.transition_premint_batch(
            batch_id,
            PremintBatchState::Submitted,
            PremintBatchState::Completed,
        )
    }

    pub fn import_proofs(&self, proofs: &[NewLooseProof]) -> Result<()> {
        let mut conn = self.conn()?;
        let tx = conn.transaction().map_err(|e| {
            LooseProofWalletError::Backend(format!("start proof import transaction: {e}"))
        })?;
        let now = now_seconds()?;
        for proof in proofs {
            validate_nonempty("proof_id", &proof.proof_id)?;
            validate_nonempty("mint_url", &proof.mint_url)?;
            validate_nonempty("unit", &proof.unit)?;
            validate_nonempty("keyset_id", &proof.keyset_id)?;
            validate_nonempty("proof_json", &proof.proof_json)?;
            tx.execute(
                "INSERT INTO monad_client_loose_proofs
                 (proof_id, wallet_name, mint_url, unit, keyset_id, amount_raw, proof_json, state,
                  source_quote_id, source_batch_id, reserved_by, spent_channel_id, created_at, updated_at)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, NULL, NULL, ?11, ?11)
                  ON CONFLICT(wallet_name, proof_id) DO NOTHING",
                params![
                    proof.proof_id,
                    self.wallet_name,
                    proof.mint_url,
                    proof.unit,
                    proof.keyset_id,
                    to_i64(proof.amount_raw)?,
                    proof.proof_json,
                    LooseProofState::Available.as_str(),
                    proof.source_quote_id,
                    proof.source_batch_id,
                    to_i64(now)?,
                ],
            )
            .map_err(|e| LooseProofWalletError::Backend(format!("insert loose proof: {e}")))?;
        }
        tx.commit().map_err(|e| {
            LooseProofWalletError::Backend(format!("commit proof import transaction: {e}"))
        })?;
        Ok(())
    }

    pub fn list_available_proofs(
        &self,
        mint_url: &str,
        unit: &str,
        accepted_keyset_ids: &[String],
    ) -> Result<Vec<LooseProofRecord>> {
        let conn = self.conn()?;
        let (sql, values) = available_proofs_query(
            &self.wallet_name,
            mint_url,
            unit,
            accepted_keyset_ids,
            "prepare loose proof query",
        )?;
        let mut stmt = conn.prepare(&sql).map_err(|e| {
            LooseProofWalletError::Backend(format!("prepare loose proof query: {e}"))
        })?;
        let mut rows = stmt
            .query(params_from_iter(values))
            .map_err(|e| LooseProofWalletError::Backend(format!("query loose proofs: {e}")))?;
        let mut out = Vec::new();
        while let Some(row) = rows
            .next()
            .map_err(|e| LooseProofWalletError::Backend(format!("read loose proof row: {e}")))?
        {
            out.push(row_to_loose_proof(row).map_err(|e| {
                LooseProofWalletError::Backend(format!("decode loose proof row: {e}"))
            })?);
        }
        Ok(out)
    }

    pub fn available_balance_raw(
        &self,
        mint_url: &str,
        unit: &str,
        accepted_keyset_ids: &[String],
    ) -> Result<u64> {
        self.list_available_proofs(mint_url, unit, accepted_keyset_ids)?
            .into_iter()
            .try_fold(0u64, |total, proof| {
                total.checked_add(proof.amount_raw).ok_or_else(|| {
                    LooseProofWalletError::Backend(
                        "available loose proof balance overflow".to_string(),
                    )
                })
            })
    }

    pub fn reserve_proofs(
        &self,
        mint_url: &str,
        unit: &str,
        accepted_keyset_ids: &[String],
        amount_raw: u64,
    ) -> Result<ProofReservation> {
        if amount_raw == 0 {
            return Err(LooseProofWalletError::InvalidInput(
                "reservation amount must be greater than zero".to_string(),
            ));
        }
        let reservation_id = new_reservation_id();
        let now = now_seconds()?;
        let mut conn = self.conn()?;
        let tx = conn
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|e| {
                LooseProofWalletError::Backend(format!("start proof reservation transaction: {e}"))
            })?;

        let candidates = available_proofs_in_transaction(
            &tx,
            &self.wallet_name,
            mint_url,
            unit,
            accepted_keyset_ids,
        )?;
        let mut selected = Vec::new();
        let mut total = 0u64;
        for proof in candidates {
            total = total.checked_add(proof.amount_raw).ok_or_else(|| {
                LooseProofWalletError::Backend("reservation total overflow".to_string())
            })?;
            selected.push(proof);
            if total >= amount_raw {
                break;
            }
        }
        if total < amount_raw {
            return Err(LooseProofWalletError::InsufficientBalance {
                requested: amount_raw,
                available: total,
            });
        }

        let expected = selected.len();
        let placeholders = std::iter::repeat_n("?", expected)
            .collect::<Vec<_>>()
            .join(", ");
        let sql = format!(
            "UPDATE monad_client_loose_proofs
             SET state = ?, reserved_by = ?, updated_at = ?
             WHERE wallet_name = ? AND state = ? AND proof_id IN ({placeholders})"
        );
        let mut values = vec![
            Value::Text(LooseProofState::Reserved.as_str().to_string()),
            Value::Text(reservation_id.clone()),
            Value::Integer(to_i64(now)?),
            Value::Text(self.wallet_name.clone()),
            Value::Text(LooseProofState::Available.as_str().to_string()),
        ];
        values.extend(
            selected
                .iter()
                .map(|proof| Value::Text(proof.proof_id.clone())),
        );
        let updated = tx
            .execute(&sql, params_from_iter(values))
            .map_err(|e| LooseProofWalletError::Backend(format!("reserve loose proofs: {e}")))?;
        if updated != expected {
            return Err(LooseProofWalletError::ReservationConflict { expected, updated });
        }
        tx.commit().map_err(|e| {
            LooseProofWalletError::Backend(format!("commit proof reservation transaction: {e}"))
        })?;

        for proof in &mut selected {
            proof.state = LooseProofState::Reserved;
            proof.reserved_by = Some(reservation_id.clone());
            proof.updated_at = now;
        }

        Ok(ProofReservation {
            reservation_id,
            proofs: selected,
            total_amount_raw: total,
        })
    }

    pub fn reserve_proofs_any_keyset(
        &self,
        mint_url: &str,
        unit: &str,
        amount_raw: u64,
    ) -> Result<ProofReservation> {
        self.reserve_proofs(mint_url, unit, &[], amount_raw)
    }

    pub fn reserve_selected_proofs(
        &self,
        mint_url: &str,
        unit: &str,
        proof_ids: &[String],
    ) -> Result<ProofReservation> {
        validate_nonempty("mint_url", mint_url)?;
        validate_nonempty("unit", unit)?;
        if proof_ids.is_empty() {
            return Err(LooseProofWalletError::InvalidInput(
                "selected proof ids must not be empty".to_string(),
            ));
        }
        if proof_ids.len() + 5 > 999 {
            return Err(LooseProofWalletError::InvalidInput(format!(
                "too many selected proof ids ({})",
                proof_ids.len()
            )));
        }

        let mut unique = HashSet::with_capacity(proof_ids.len());
        for proof_id in proof_ids {
            validate_nonempty("proof_id", proof_id)?;
            if !unique.insert(proof_id) {
                return Err(LooseProofWalletError::InvalidInput(format!(
                    "duplicate selected proof id '{proof_id}'"
                )));
            }
        }

        let reservation_id = new_reservation_id();
        let now = now_seconds()?;
        let mut conn = self.conn()?;
        let tx = conn
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|e| {
                LooseProofWalletError::Backend(format!("start proof reservation transaction: {e}"))
            })?;

        let placeholders = std::iter::repeat_n("?", proof_ids.len())
            .collect::<Vec<_>>()
            .join(", ");
        let sql = format!(
            "SELECT proof_id, wallet_name, mint_url, unit, keyset_id, amount_raw, proof_json, state,
                    source_quote_id, source_batch_id, reserved_by, spent_channel_id, created_at, updated_at
             FROM monad_client_loose_proofs
             WHERE wallet_name = ? AND mint_url = ? AND unit = ? AND state = ? AND proof_id IN ({placeholders})
             ORDER BY amount_raw ASC, proof_id ASC"
        );
        let mut values = vec![
            Value::Text(self.wallet_name.clone()),
            Value::Text(mint_url.to_string()),
            Value::Text(unit.to_string()),
            Value::Text(LooseProofState::Available.as_str().to_string()),
        ];
        values.extend(
            proof_ids
                .iter()
                .map(|proof_id| Value::Text(proof_id.clone())),
        );

        let mut stmt = tx.prepare(&sql).map_err(|e| {
            LooseProofWalletError::Backend(format!("prepare selected proof query: {e}"))
        })?;
        let mut rows = stmt.query(params_from_iter(values)).map_err(|e| {
            LooseProofWalletError::Backend(format!("query selected loose proofs: {e}"))
        })?;
        let mut selected = Vec::new();
        while let Some(row) = rows.next().map_err(|e| {
            LooseProofWalletError::Backend(format!("read selected loose proof row: {e}"))
        })? {
            selected.push(row_to_loose_proof(row).map_err(|e| {
                LooseProofWalletError::Backend(format!("decode selected loose proof row: {e}"))
            })?);
        }
        drop(rows);
        drop(stmt);

        if selected.len() != proof_ids.len() {
            let available = selected.iter().try_fold(0u64, |total, proof| {
                total.checked_add(proof.amount_raw).ok_or_else(|| {
                    LooseProofWalletError::Backend(
                        "selected proof available total overflow".to_string(),
                    )
                })
            })?;
            return Err(LooseProofWalletError::InsufficientBalance {
                requested: proof_ids.len() as u64,
                available,
            });
        }

        let total_amount_raw = selected.iter().try_fold(0u64, |total, proof| {
            total.checked_add(proof.amount_raw).ok_or_else(|| {
                LooseProofWalletError::Backend("selected proof total overflow".to_string())
            })
        })?;

        let expected = selected.len();
        let update_placeholders = std::iter::repeat_n("?", expected)
            .collect::<Vec<_>>()
            .join(", ");
        let update_sql = format!(
            "UPDATE monad_client_loose_proofs
             SET state = ?, reserved_by = ?, updated_at = ?
             WHERE wallet_name = ? AND mint_url = ? AND unit = ? AND state = ? AND proof_id IN ({update_placeholders})"
        );
        let mut update_values = vec![
            Value::Text(LooseProofState::Reserved.as_str().to_string()),
            Value::Text(reservation_id.clone()),
            Value::Integer(to_i64(now)?),
            Value::Text(self.wallet_name.clone()),
            Value::Text(mint_url.to_string()),
            Value::Text(unit.to_string()),
            Value::Text(LooseProofState::Available.as_str().to_string()),
        ];
        update_values.extend(
            proof_ids
                .iter()
                .map(|proof_id| Value::Text(proof_id.clone())),
        );
        let updated = tx
            .execute(&update_sql, params_from_iter(update_values))
            .map_err(|e| {
                LooseProofWalletError::Backend(format!("reserve selected loose proofs: {e}"))
            })?;
        if updated != expected {
            return Err(LooseProofWalletError::ReservationConflict { expected, updated });
        }
        tx.commit().map_err(|e| {
            LooseProofWalletError::Backend(format!("commit selected proof reservation: {e}"))
        })?;

        for proof in &mut selected {
            proof.state = LooseProofState::Reserved;
            proof.reserved_by = Some(reservation_id.clone());
            proof.updated_at = now;
        }

        Ok(ProofReservation {
            reservation_id,
            proofs: selected,
            total_amount_raw,
        })
    }

    pub fn release_reservation(&self, reservation_id: &str) -> Result<usize> {
        let now = now_seconds()?;
        let conn = self.conn()?;
        conn.execute(
            "UPDATE monad_client_loose_proofs
             SET state = ?4, reserved_by = NULL, updated_at = ?5
             WHERE wallet_name = ?1 AND reserved_by = ?2 AND state = ?3",
            params![
                self.wallet_name,
                reservation_id,
                LooseProofState::Reserved.as_str(),
                LooseProofState::Available.as_str(),
                to_i64(now)?,
            ],
        )
        .map_err(|e| LooseProofWalletError::Backend(format!("release proof reservation: {e}")))
    }

    pub fn mark_reservation_spent(&self, reservation_id: &str, channel_id: &str) -> Result<usize> {
        validate_nonempty("channel_id", channel_id)?;
        let now = now_seconds()?;
        let conn = self.conn()?;
        conn.execute(
            "UPDATE monad_client_loose_proofs
             SET state = ?4, spent_channel_id = ?5, updated_at = ?6
             WHERE wallet_name = ?1 AND reserved_by = ?2 AND state = ?3",
            params![
                self.wallet_name,
                reservation_id,
                LooseProofState::Reserved.as_str(),
                LooseProofState::Spent.as_str(),
                channel_id,
                to_i64(now)?,
            ],
        )
        .map_err(|e| LooseProofWalletError::Backend(format!("mark proof reservation spent: {e}")))
    }

    pub fn proofs_for_reservation(&self, reservation_id: &str) -> Result<Vec<LooseProofRecord>> {
        let conn = self.conn()?;
        let mut stmt = conn
            .prepare(
                "SELECT proof_id, wallet_name, mint_url, unit, keyset_id, amount_raw, proof_json, state,
                        source_quote_id, source_batch_id, reserved_by, spent_channel_id, created_at, updated_at
                 FROM monad_client_loose_proofs
                 WHERE wallet_name = ?1 AND reserved_by = ?2
                 ORDER BY amount_raw ASC, proof_id ASC",
            )
            .map_err(|e| LooseProofWalletError::Backend(format!("prepare reservation proof query: {e}")))?;
        let mut rows = stmt
            .query(params![self.wallet_name, reservation_id])
            .map_err(|e| {
                LooseProofWalletError::Backend(format!("query reservation proofs: {e}"))
            })?;
        let mut out = Vec::new();
        while let Some(row) = rows.next().map_err(|e| {
            LooseProofWalletError::Backend(format!("read reservation proof row: {e}"))
        })? {
            out.push(row_to_loose_proof(row).map_err(|e| {
                LooseProofWalletError::Backend(format!("decode reservation proof row: {e}"))
            })?);
        }
        Ok(out)
    }

    fn transition_mint_quote(
        &self,
        quote_id: &str,
        expected: MintQuoteState,
        next: MintQuoteState,
    ) -> Result<()> {
        let now = now_seconds()?;
        let conn = self.conn()?;
        let changed = conn
            .execute(
                "UPDATE monad_client_mint_quotes
                 SET state = ?4, updated_at = ?5
                 WHERE quote_id = ?1 AND wallet_name = ?2 AND state = ?3",
                params![
                    quote_id,
                    self.wallet_name,
                    expected.as_str(),
                    next.as_str(),
                    to_i64(now)?
                ],
            )
            .map_err(|e| LooseProofWalletError::Backend(format!("update mint quote state: {e}")))?;
        if changed == 1 {
            return Ok(());
        }
        drop(conn);

        match self.mint_quote(quote_id)? {
            Some(record) => Err(LooseProofWalletError::InvalidStateTransition {
                entity: "mint quote",
                id: quote_id.to_string(),
                expected: expected.as_str(),
                actual: record.state.as_str().to_string(),
                requested: next.as_str(),
            }),
            None => Err(LooseProofWalletError::NotFound(format!(
                "mint quote '{quote_id}'"
            ))),
        }
    }

    fn transition_premint_batch(
        &self,
        batch_id: &str,
        expected: PremintBatchState,
        next: PremintBatchState,
    ) -> Result<()> {
        let now = now_seconds()?;
        let conn = self.conn()?;
        let changed = conn
            .execute(
                "UPDATE monad_client_premint_batches
                 SET state = ?4, updated_at = ?5
                 WHERE batch_id = ?1 AND wallet_name = ?2 AND state = ?3",
                params![
                    batch_id,
                    self.wallet_name,
                    expected.as_str(),
                    next.as_str(),
                    to_i64(now)?
                ],
            )
            .map_err(|e| {
                LooseProofWalletError::Backend(format!("update premint batch state: {e}"))
            })?;
        if changed == 1 {
            return Ok(());
        }
        drop(conn);

        match self.premint_batch_by_id(batch_id)? {
            Some(record) => Err(LooseProofWalletError::InvalidStateTransition {
                entity: "premint batch",
                id: batch_id.to_string(),
                expected: expected.as_str(),
                actual: record.state.as_str().to_string(),
                requested: next.as_str(),
            }),
            None => Err(LooseProofWalletError::NotFound(format!(
                "premint batch '{batch_id}'"
            ))),
        }
    }

    fn premint_batch_by_id(&self, batch_id: &str) -> Result<Option<PremintBatchRecord>> {
        let conn = self.conn()?;
        conn.query_row(
            "SELECT batch_id, quote_id, wallet_name, mint_url, unit, keyset_id, amount_raw,
                    blinded_messages_json, secrets_with_blinding_json, state, created_at, updated_at
             FROM monad_client_premint_batches
             WHERE batch_id = ?1 AND wallet_name = ?2",
            params![batch_id, self.wallet_name],
            row_to_premint_batch,
        )
        .optional()
        .map_err(|e| LooseProofWalletError::Backend(format!("query premint batch: {e}")))
    }

    fn conn(&self) -> Result<std::sync::MutexGuard<'_, Connection>> {
        self.conn.lock().map_err(|_| {
            LooseProofWalletError::Backend("loose proof wallet db mutex poisoned".to_string())
        })
    }
}

fn row_to_mint_quote(row: &rusqlite::Row<'_>) -> rusqlite::Result<MintQuoteRecord> {
    let state: String = row.get(6)?;
    Ok(MintQuoteRecord {
        quote_id: row.get(0)?,
        wallet_name: row.get(1)?,
        mint_url: row.get(2)?,
        unit: row.get(3)?,
        amount_raw: from_i64(row.get(4)?)?,
        invoice: row.get(5)?,
        state: MintQuoteState::parse(&state)?,
        created_at: from_i64(row.get(7)?)?,
        updated_at: from_i64(row.get(8)?)?,
        expires_at: optional_from_i64(row.get(9)?)?,
    })
}

fn row_to_premint_batch(row: &rusqlite::Row<'_>) -> rusqlite::Result<PremintBatchRecord> {
    let state: String = row.get(9)?;
    Ok(PremintBatchRecord {
        batch_id: row.get(0)?,
        quote_id: row.get(1)?,
        wallet_name: row.get(2)?,
        mint_url: row.get(3)?,
        unit: row.get(4)?,
        keyset_id: row.get(5)?,
        amount_raw: from_i64(row.get(6)?)?,
        blinded_messages_json: row.get(7)?,
        secrets_with_blinding_json: row.get(8)?,
        state: PremintBatchState::parse(&state)?,
        created_at: from_i64(row.get(10)?)?,
        updated_at: from_i64(row.get(11)?)?,
    })
}

fn row_to_loose_proof(row: &rusqlite::Row<'_>) -> rusqlite::Result<LooseProofRecord> {
    let state: String = row.get(7)?;
    Ok(LooseProofRecord {
        proof_id: row.get(0)?,
        wallet_name: row.get(1)?,
        mint_url: row.get(2)?,
        unit: row.get(3)?,
        keyset_id: row.get(4)?,
        amount_raw: from_i64(row.get(5)?)?,
        proof_json: row.get(6)?,
        state: LooseProofState::parse(&state)?,
        source_quote_id: row.get(8)?,
        source_batch_id: row.get(9)?,
        reserved_by: row.get(10)?,
        spent_channel_id: row.get(11)?,
        created_at: from_i64(row.get(12)?)?,
        updated_at: from_i64(row.get(13)?)?,
    })
}

fn available_proofs_in_transaction(
    tx: &rusqlite::Transaction<'_>,
    wallet_name: &str,
    mint_url: &str,
    unit: &str,
    accepted_keyset_ids: &[String],
) -> Result<Vec<LooseProofRecord>> {
    let (sql, values) = available_proofs_query(
        wallet_name,
        mint_url,
        unit,
        accepted_keyset_ids,
        "prepare transaction loose proof query",
    )?;
    let mut stmt = tx.prepare(&sql).map_err(|e| {
        LooseProofWalletError::Backend(format!("prepare transaction loose proof query: {e}"))
    })?;
    let mut rows = stmt.query(params_from_iter(values)).map_err(|e| {
        LooseProofWalletError::Backend(format!("query transaction loose proofs: {e}"))
    })?;
    let mut out = Vec::new();
    while let Some(row) = rows.next().map_err(|e| {
        LooseProofWalletError::Backend(format!("read transaction loose proof row: {e}"))
    })? {
        out.push(row_to_loose_proof(row).map_err(|e| {
            LooseProofWalletError::Backend(format!("decode transaction loose proof row: {e}"))
        })?);
    }
    Ok(out)
}

fn available_proofs_query(
    wallet_name: &str,
    mint_url: &str,
    unit: &str,
    accepted_keyset_ids: &[String],
    context: &str,
) -> Result<(String, Vec<Value>)> {
    let mut values = vec![
        Value::Text(wallet_name.to_string()),
        Value::Text(mint_url.to_string()),
        Value::Text(unit.to_string()),
        Value::Text(LooseProofState::Available.as_str().to_string()),
    ];
    let keyset_filter = if accepted_keyset_ids.is_empty() {
        String::new()
    } else {
        let placeholders = std::iter::repeat_n("?", accepted_keyset_ids.len())
            .collect::<Vec<_>>()
            .join(", ");
        values.extend(
            accepted_keyset_ids
                .iter()
                .map(|keyset_id| Value::Text(keyset_id.clone())),
        );
        format!(" AND keyset_id IN ({placeholders})")
    };
    let sql = format!(
        "SELECT proof_id, wallet_name, mint_url, unit, keyset_id, amount_raw, proof_json, state,
                source_quote_id, source_batch_id, reserved_by, spent_channel_id, created_at, updated_at
         FROM monad_client_loose_proofs
         WHERE wallet_name = ? AND mint_url = ? AND unit = ? AND state = ?{keyset_filter}
         ORDER BY amount_raw ASC, proof_id ASC"
    );
    if values.len() > 999 {
        return Err(LooseProofWalletError::InvalidInput(format!(
            "{context}: too many accepted keysets ({})",
            accepted_keyset_ids.len()
        )));
    }
    Ok((sql, values))
}

fn now_seconds() -> Result<u64> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .map_err(|e| LooseProofWalletError::Backend(format!("system time before unix epoch: {e}")))
}

fn new_reservation_id() -> String {
    let mut bytes = [0u8; 16];
    rand::rng().fill_bytes(&mut bytes);
    format!("proof-res-{}", hex::encode(bytes))
}

fn validate_nonempty(name: &str, value: &str) -> Result<()> {
    if value.trim().is_empty() {
        return Err(LooseProofWalletError::InvalidInput(format!(
            "{name} must not be empty"
        )));
    }
    Ok(())
}

fn to_i64(value: u64) -> Result<i64> {
    i64::try_from(value).map_err(|_| {
        LooseProofWalletError::InvalidInput(format!("value {value} does not fit in i64"))
    })
}

fn optional_to_i64(value: Option<u64>) -> Result<Option<i64>> {
    value.map(to_i64).transpose()
}

fn from_i64(value: i64) -> rusqlite::Result<u64> {
    u64::try_from(value)
        .map_err(|_| sql_decode_error(format!("negative integer in database: {value}")))
}

fn optional_from_i64(value: Option<i64>) -> rusqlite::Result<Option<u64>> {
    value.map(from_i64).transpose()
}

fn sql_decode_error(message: impl Into<String>) -> rusqlite::Error {
    rusqlite::Error::FromSqlConversionFailure(
        0,
        rusqlite::types::Type::Text,
        Box::new(io::Error::new(io::ErrorKind::InvalidData, message.into())),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use cdk_spilman::{
        construct_proofs, create_plain_blinded_messages, ConfigurableClientHost,
        ReqwestClientNetworking, SpilmanClientBridge,
    };
    use cdk_spilman_test_mint::{serve_mint_with_shutdown, TestMintConfig};
    use tokio::sync::oneshot;

    const MINT: &str = "http://127.0.0.1:3338";

    fn wallet() -> LooseProofWallet {
        LooseProofWallet::open_in_memory("alice").unwrap()
    }

    fn quote(id: &str, amount_raw: u64) -> NewMintQuote {
        NewMintQuote {
            quote_id: id.to_string(),
            mint_url: MINT.to_string(),
            unit: "sat".to_string(),
            amount_raw,
            invoice: format!("lnbc-{id}"),
            expires_at: Some(123_456),
        }
    }

    fn batch(id: &str, quote_id: &str, amount_raw: u64) -> NewPremintBatch {
        NewPremintBatch {
            batch_id: id.to_string(),
            quote_id: quote_id.to_string(),
            mint_url: MINT.to_string(),
            unit: "sat".to_string(),
            keyset_id: "keyset-a".to_string(),
            amount_raw,
            blinded_messages_json: "[{\"amount\":1}]".to_string(),
            secrets_with_blinding_json: "[{\"secret\":\"secret\",\"blinding_factor\":\"blind\"}]"
                .to_string(),
        }
    }

    fn proof(id: &str, amount_raw: u64, keyset_id: &str) -> NewLooseProof {
        NewLooseProof {
            proof_id: id.to_string(),
            mint_url: MINT.to_string(),
            unit: "sat".to_string(),
            keyset_id: keyset_id.to_string(),
            amount_raw,
            proof_json: format!(r#"{{"id":"{keyset_id}","amount":{amount_raw}}}"#),
            source_quote_id: Some("quote-a".to_string()),
            source_batch_id: Some("batch-a".to_string()),
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
            tokio::time::sleep(std::time::Duration::from_millis(100)).await;
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
            tokio::time::sleep(std::time::Duration::from_millis(100)).await;
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

    #[test]
    fn stores_quote_before_later_state_transitions() {
        let wallet = wallet();
        wallet.store_mint_quote(quote("quote-a", 100)).unwrap();

        let stored = wallet.mint_quote("quote-a").unwrap().unwrap();
        assert_eq!(stored.state, MintQuoteState::Pending);
        assert_eq!(stored.amount_raw, 100);
        assert_eq!(stored.invoice, "lnbc-quote-a");

        wallet.mark_quote_paid("quote-a").unwrap();
        assert_eq!(
            wallet.mint_quote("quote-a").unwrap().unwrap().state,
            MintQuoteState::Paid
        );
    }

    #[test]
    fn quote_transitions_reject_out_of_order_updates() {
        let wallet = wallet();
        wallet.store_mint_quote(quote("quote-a", 100)).unwrap();

        let err = wallet.mark_quote_completed("quote-a").unwrap_err();
        assert_eq!(
            err,
            LooseProofWalletError::InvalidStateTransition {
                entity: "mint quote",
                id: "quote-a".to_string(),
                expected: "paid",
                actual: "pending".to_string(),
                requested: "completed",
            }
        );

        wallet.mark_quote_paid("quote-a").unwrap();
        wallet.mark_quote_completed("quote-a").unwrap();
        assert_eq!(
            wallet.mint_quote("quote-a").unwrap().unwrap().state,
            MintQuoteState::Completed
        );
    }

    #[test]
    fn stores_premint_batch_before_submit_state() {
        let wallet = wallet();
        wallet.store_mint_quote(quote("quote-a", 100)).unwrap();
        wallet
            .store_premint_batch(batch("batch-a", "quote-a", 100))
            .unwrap();

        let stored = wallet.premint_batch_for_quote("quote-a").unwrap().unwrap();
        assert_eq!(stored.state, PremintBatchState::Prepared);
        assert_eq!(stored.blinded_messages_json, "[{\"amount\":1}]");

        wallet.mark_premint_submitted("batch-a").unwrap();
        assert_eq!(
            wallet
                .premint_batch_for_quote("quote-a")
                .unwrap()
                .unwrap()
                .state,
            PremintBatchState::Submitted
        );
    }

    #[test]
    fn premint_transitions_reject_out_of_order_updates() {
        let wallet = wallet();
        wallet.store_mint_quote(quote("quote-a", 100)).unwrap();
        wallet
            .store_premint_batch(batch("batch-a", "quote-a", 100))
            .unwrap();

        let err = wallet.mark_premint_completed("batch-a").unwrap_err();
        assert_eq!(
            err,
            LooseProofWalletError::InvalidStateTransition {
                entity: "premint batch",
                id: "batch-a".to_string(),
                expected: "submitted",
                actual: "prepared".to_string(),
                requested: "completed",
            }
        );

        wallet.mark_premint_submitted("batch-a").unwrap();
        wallet.mark_premint_completed("batch-a").unwrap();
        assert_eq!(
            wallet
                .premint_batch_for_quote("quote-a")
                .unwrap()
                .unwrap()
                .state,
            PremintBatchState::Completed
        );
    }

    #[test]
    fn imports_and_lists_available_proofs_by_offer_shape() {
        let wallet = wallet();
        wallet
            .import_proofs(&[
                proof("proof-a", 1, "keyset-a"),
                proof("proof-b", 2, "keyset-b"),
            ])
            .unwrap();

        let proofs = wallet
            .list_available_proofs(MINT, "sat", &["keyset-b".to_string()])
            .unwrap();
        assert_eq!(proofs.len(), 1);
        assert_eq!(proofs[0].proof_id, "proof-b");
        assert_eq!(proofs[0].state, LooseProofState::Available);

        let balance = wallet
            .available_balance_raw(
                MINT,
                "sat",
                &["keyset-a".to_string(), "keyset-b".to_string()],
            )
            .unwrap();
        assert_eq!(balance, 3);
    }

    #[test]
    fn reserve_release_and_spend_are_stateful() {
        let wallet = wallet();
        wallet
            .import_proofs(&[
                proof("proof-a", 1, "keyset-a"),
                proof("proof-b", 2, "keyset-a"),
                proof("proof-c", 4, "keyset-a"),
            ])
            .unwrap();

        let reservation = wallet
            .reserve_proofs(MINT, "sat", &["keyset-a".to_string()], 3)
            .unwrap();
        assert_eq!(reservation.total_amount_raw, 3);
        assert_eq!(reservation.proofs.len(), 2);
        assert_eq!(
            wallet
                .available_balance_raw(MINT, "sat", &["keyset-a".to_string()])
                .unwrap(),
            4
        );

        let reserved = wallet
            .proofs_for_reservation(&reservation.reservation_id)
            .unwrap();
        assert_eq!(reserved.len(), 2);
        assert!(reserved
            .iter()
            .all(|proof| proof.state == LooseProofState::Reserved));

        assert_eq!(
            wallet
                .release_reservation(&reservation.reservation_id)
                .unwrap(),
            2
        );
        assert_eq!(
            wallet
                .available_balance_raw(MINT, "sat", &["keyset-a".to_string()])
                .unwrap(),
            7
        );

        let reservation = wallet
            .reserve_proofs(MINT, "sat", &["keyset-a".to_string()], 4)
            .unwrap();
        assert_eq!(
            wallet
                .mark_reservation_spent(&reservation.reservation_id, "chan-a")
                .unwrap(),
            3
        );
        assert_eq!(
            wallet
                .available_balance_raw(MINT, "sat", &["keyset-a".to_string()])
                .unwrap(),
            0
        );

        assert_eq!(
            wallet
                .release_reservation(&reservation.reservation_id)
                .unwrap(),
            0
        );
    }

    #[test]
    fn spend_after_release_is_idempotent_zero() {
        let wallet = wallet();
        wallet
            .import_proofs(&[proof("proof-a", 1, "keyset-a")])
            .unwrap();
        let reservation = wallet
            .reserve_proofs(MINT, "sat", &["keyset-a".to_string()], 1)
            .unwrap();

        assert_eq!(
            wallet
                .release_reservation(&reservation.reservation_id)
                .unwrap(),
            1
        );
        assert_eq!(
            wallet
                .mark_reservation_spent(&reservation.reservation_id, "chan-a")
                .unwrap(),
            0
        );
        assert_eq!(
            wallet
                .available_balance_raw(MINT, "sat", &["keyset-a".to_string()])
                .unwrap(),
            1
        );
    }

    #[test]
    fn separate_wallet_handles_do_not_double_reserve_proofs() {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("wallet.sqlite");
        let wallet_a = LooseProofWallet::open(&path, "alice").unwrap();
        let wallet_b = LooseProofWallet::open(&path, "alice").unwrap();
        wallet_a
            .import_proofs(&[proof("proof-a", 1, "keyset-a")])
            .unwrap();

        wallet_a
            .reserve_proofs(MINT, "sat", &["keyset-a".to_string()], 1)
            .unwrap();
        let err = wallet_b
            .reserve_proofs(MINT, "sat", &["keyset-a".to_string()], 1)
            .unwrap_err();
        assert_eq!(
            err,
            LooseProofWalletError::InsufficientBalance {
                requested: 1,
                available: 0
            }
        );
        assert_eq!(
            wallet_b
                .available_balance_raw(MINT, "sat", &["keyset-a".to_string()])
                .unwrap(),
            0
        );
    }

    #[test]
    fn insufficient_balance_does_not_reserve_partial_set() {
        let wallet = wallet();
        wallet
            .import_proofs(&[proof("proof-a", 1, "keyset-a")])
            .unwrap();

        let err = wallet
            .reserve_proofs(MINT, "sat", &["keyset-a".to_string()], 2)
            .unwrap_err();
        assert_eq!(
            err,
            LooseProofWalletError::InsufficientBalance {
                requested: 2,
                available: 1
            }
        );
        assert_eq!(
            wallet
                .available_balance_raw(MINT, "sat", &["keyset-a".to_string()])
                .unwrap(),
            1
        );
    }

    #[test]
    fn unavailable_proof_does_not_cause_partial_reservation() {
        let wallet = wallet();
        wallet
            .import_proofs(&[
                proof("proof-a", 2, "keyset-a"),
                proof("proof-b", 3, "keyset-a"),
                proof("proof-c", 4, "keyset-a"),
            ])
            .unwrap();

        let first_reservation = wallet
            .reserve_proofs(MINT, "sat", &["keyset-a".to_string()], 2)
            .unwrap();
        assert_eq!(
            wallet
                .mark_reservation_spent(&first_reservation.reservation_id, "chan-a")
                .unwrap(),
            1
        );

        let err = wallet
            .reserve_proofs(MINT, "sat", &["keyset-a".to_string()], 8)
            .unwrap_err();
        assert_eq!(
            err,
            LooseProofWalletError::InsufficientBalance {
                requested: 8,
                available: 7
            }
        );

        let proofs = wallet
            .list_available_proofs(MINT, "sat", &["keyset-a".to_string()])
            .unwrap();
        assert_eq!(proofs.len(), 2);
        assert_eq!(proofs[0].proof_id, "proof-b");
        assert_eq!(proofs[1].proof_id, "proof-c");
        assert!(proofs
            .iter()
            .all(|proof| proof.state == LooseProofState::Available));
    }

    #[test]
    fn reserve_selected_proofs_reserves_exact_ids() {
        let wallet = wallet();
        wallet
            .import_proofs(&[
                proof("proof-small", 1, "keyset-a"),
                proof("proof-medium", 2, "keyset-a"),
                proof("proof-large", 4, "keyset-a"),
            ])
            .unwrap();

        let reservation = wallet
            .reserve_selected_proofs(
                MINT,
                "sat",
                &["proof-large".to_string(), "proof-small".to_string()],
            )
            .unwrap();

        assert_eq!(reservation.total_amount_raw, 5);
        let mut reserved_ids = reservation
            .proofs
            .iter()
            .map(|proof| proof.proof_id.as_str())
            .collect::<Vec<_>>();
        reserved_ids.sort_unstable();
        assert_eq!(reserved_ids, vec!["proof-large", "proof-small"]);
        assert!(reservation
            .proofs
            .iter()
            .all(|proof| proof.state == LooseProofState::Reserved));

        let available = wallet
            .list_available_proofs(MINT, "sat", &["keyset-a".to_string()])
            .unwrap();
        assert_eq!(available.len(), 1);
        assert_eq!(available[0].proof_id, "proof-medium");
    }

    #[test]
    fn reserve_selected_proofs_rejects_duplicate_ids() {
        let wallet = wallet();
        wallet
            .import_proofs(&[proof("proof-a", 1, "keyset-a")])
            .unwrap();

        let err = wallet
            .reserve_selected_proofs(MINT, "sat", &["proof-a".to_string(), "proof-a".to_string()])
            .unwrap_err();

        assert!(matches!(err, LooseProofWalletError::InvalidInput(_)));
        assert_eq!(wallet.available_balance_raw(MINT, "sat", &[]).unwrap(), 1);
    }

    #[test]
    fn reserve_selected_proofs_rejects_wrong_mint_unit_without_partial_reservation() {
        let wallet = wallet();
        wallet
            .import_proofs(&[
                proof("proof-a", 1, "keyset-a"),
                NewLooseProof {
                    mint_url: "https://other-mint".to_string(),
                    ..proof("proof-b", 2, "keyset-a")
                },
            ])
            .unwrap();

        let err = wallet
            .reserve_selected_proofs(MINT, "sat", &["proof-a".to_string(), "proof-b".to_string()])
            .unwrap_err();

        assert!(matches!(
            err,
            LooseProofWalletError::InsufficientBalance { .. }
        ));
        let proofs = wallet.list_available_proofs(MINT, "sat", &[]).unwrap();
        assert_eq!(proofs.len(), 1);
        assert_eq!(proofs[0].proof_id, "proof-a");
        assert_eq!(proofs[0].state, LooseProofState::Available);
    }

    #[test]
    fn reserve_selected_proofs_rejects_unavailable_without_partial_reservation() {
        let wallet = wallet();
        wallet
            .import_proofs(&[
                proof("proof-a", 1, "keyset-a"),
                proof("proof-b", 2, "keyset-a"),
            ])
            .unwrap();
        let first = wallet
            .reserve_selected_proofs(MINT, "sat", &["proof-a".to_string()])
            .unwrap();
        wallet
            .mark_reservation_spent(&first.reservation_id, "chan-a")
            .unwrap();

        let err = wallet
            .reserve_selected_proofs(MINT, "sat", &["proof-a".to_string(), "proof-b".to_string()])
            .unwrap_err();

        assert!(matches!(
            err,
            LooseProofWalletError::InsufficientBalance { .. }
        ));
        let available = wallet.list_available_proofs(MINT, "sat", &[]).unwrap();
        assert_eq!(available.len(), 1);
        assert_eq!(available[0].proof_id, "proof-b");
        assert_eq!(available[0].state, LooseProofState::Available);
    }

    #[test]
    fn separate_wallet_handles_do_not_double_reserve_selected_proofs() {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("wallet.sqlite");
        let wallet_a = LooseProofWallet::open(&path, "alice").unwrap();
        let wallet_b = LooseProofWallet::open(&path, "alice").unwrap();
        wallet_a
            .import_proofs(&[proof("proof-a", 1, "keyset-a")])
            .unwrap();

        wallet_a
            .reserve_selected_proofs(MINT, "sat", &["proof-a".to_string()])
            .unwrap();
        let err = wallet_b
            .reserve_selected_proofs(MINT, "sat", &["proof-a".to_string()])
            .unwrap_err();

        assert!(matches!(
            err,
            LooseProofWalletError::InsufficientBalance { .. }
        ));
        assert_eq!(wallet_b.available_balance_raw(MINT, "sat", &[]).unwrap(), 0);
    }

    #[test]
    fn duplicate_proof_import_is_idempotent() {
        let wallet = wallet();
        wallet
            .import_proofs(&[proof("proof-a", 1, "keyset-a")])
            .unwrap();
        wallet
            .import_proofs(&[proof("proof-a", 1, "keyset-a")])
            .unwrap();

        let proofs = wallet
            .list_available_proofs(MINT, "sat", &["keyset-a".to_string()])
            .unwrap();
        assert_eq!(proofs.len(), 1);
        assert_eq!(proofs[0].amount_raw, 1);
    }

    #[test]
    fn persists_across_reopen() {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("wallet.sqlite");
        {
            let wallet = LooseProofWallet::open(&path, "alice").unwrap();
            wallet.store_mint_quote(quote("quote-a", 100)).unwrap();
            wallet
                .store_premint_batch(batch("batch-a", "quote-a", 100))
                .unwrap();
            wallet
                .import_proofs(&[proof("proof-a", 1, "keyset-a")])
                .unwrap();
        }

        let wallet = LooseProofWallet::open(&path, "alice").unwrap();
        assert!(wallet.mint_quote("quote-a").unwrap().is_some());
        assert!(wallet.premint_batch_for_quote("quote-a").unwrap().is_some());
        assert_eq!(
            wallet
                .available_balance_raw(MINT, "sat", &["keyset-a".to_string()])
                .unwrap(),
            1
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn http_test_mint_flow_persists_quote_premint_and_loose_proofs() {
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

        let wallet = LooseProofWallet::open_in_memory("alice").unwrap();
        let amount_raw = 8;
        let unit = "sat";
        let keyset_id = active_keyset_id(&client, &mint_url, unit).await;
        let bridge = SpilmanClientBridge::new(
            ConfigurableClientHost::new_in_memory(),
            ReqwestClientNetworking::new(),
        );
        let keyset_info_json = bridge.fetch_keyset_info(&mint_url, &keyset_id).unwrap();

        let quote_response = request_mint_quote(&client, &mint_url, amount_raw, unit).await;
        let quote_id = quote_response["quote"].as_str().unwrap().to_string();
        let invoice = quote_response["request"].as_str().unwrap_or("").to_string();
        wallet
            .store_mint_quote(NewMintQuote {
                quote_id: quote_id.clone(),
                mint_url: mint_url.clone(),
                unit: unit.to_string(),
                amount_raw,
                invoice,
                expires_at: None,
            })
            .unwrap();

        let stored_quote = wallet.mint_quote(&quote_id).unwrap().unwrap();
        assert_eq!(stored_quote.state, MintQuoteState::Pending);
        assert_eq!(
            wallet
                .available_balance_raw(&mint_url, unit, std::slice::from_ref(&keyset_id))
                .unwrap(),
            0
        );

        wait_for_quote_paid(&client, &mint_url, &quote_id).await;
        wallet.mark_quote_paid(&quote_id).unwrap();

        let premint_json = create_plain_blinded_messages(amount_raw, &keyset_info_json).unwrap();
        let premint: serde_json::Value = serde_json::from_str(&premint_json).unwrap();
        let blinded_messages_json = premint["blinded_messages"].to_string();
        let secrets_with_blinding_json = premint["secrets_with_blinding"].to_string();
        let batch_id = format!("batch-{quote_id}");
        wallet
            .store_premint_batch(NewPremintBatch {
                batch_id: batch_id.clone(),
                quote_id: quote_id.clone(),
                mint_url: mint_url.clone(),
                unit: unit.to_string(),
                keyset_id: keyset_id.clone(),
                amount_raw,
                blinded_messages_json: blinded_messages_json.clone(),
                secrets_with_blinding_json: secrets_with_blinding_json.clone(),
            })
            .unwrap();
        assert_eq!(
            wallet
                .premint_batch_for_quote(&quote_id)
                .unwrap()
                .unwrap()
                .state,
            PremintBatchState::Prepared
        );

        wallet.mark_premint_submitted(&batch_id).unwrap();
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
        wallet.import_proofs(&loose_proofs).unwrap();
        wallet.mark_quote_completed(&quote_id).unwrap();
        wallet.mark_premint_completed(&batch_id).unwrap();

        assert_eq!(
            wallet.mint_quote(&quote_id).unwrap().unwrap().state,
            MintQuoteState::Completed
        );
        assert_eq!(
            wallet
                .premint_batch_for_quote(&quote_id)
                .unwrap()
                .unwrap()
                .state,
            PremintBatchState::Completed
        );
        assert_eq!(
            wallet
                .available_balance_raw(&mint_url, unit, std::slice::from_ref(&keyset_id))
                .unwrap(),
            amount_raw
        );

        let reservation = wallet
            .reserve_proofs(
                &mint_url,
                unit,
                std::slice::from_ref(&keyset_id),
                amount_raw,
            )
            .unwrap();
        assert_eq!(reservation.total_amount_raw, amount_raw);

        let _ = shutdown_tx.send(());
        mint_task.await.unwrap().unwrap();
    }
}
