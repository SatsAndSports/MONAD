//! SQLite-backed wallet for loose Cashu proofs.
//!
//! This module intentionally stops before Spilman channel provisioning. It owns
//! the durable state needed to mint bearer proofs safely, then reserve those
//! proofs for a later channel-opening step.

use rand::RngCore;
use rusqlite::types::Value;
use rusqlite::{
    params, params_from_iter, Connection, OpenFlags, OptionalExtension, TransactionBehavior,
};
use std::collections::HashSet;
use std::fmt;
use std::io;
use std::path::{Path, PathBuf};
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

const CREATE_OPENING_ATTEMPTS_SQL: &str = r#"
    CREATE TABLE IF NOT EXISTS monad_client_opening_attempts (
        attempt_id TEXT PRIMARY KEY,
        opening_id TEXT NOT NULL,
        predecessor_attempt_id TEXT,
        wallet_name TEXT NOT NULL,
        reservation_id TEXT NOT NULL,
        receiver_pubkey TEXT NOT NULL,
        mint_url TEXT NOT NULL,
        unit TEXT NOT NULL,
        funding_token_target_msats INTEGER NOT NULL,
        expiry_timestamp INTEGER NOT NULL,
        prepared_open_json TEXT NOT NULL,
        selected_proof_ids_json TEXT NOT NULL,
        completed_open_json TEXT,
        state TEXT NOT NULL,
        rejection_code INTEGER,
        rejection_message TEXT,
        latest_submitted_at INTEGER,
        created_at INTEGER NOT NULL,
        updated_at INTEGER NOT NULL,
        UNIQUE(wallet_name, opening_id, attempt_id)
    )
"#;

const CREATE_OPENING_EXECUTIONS_SQL: &str = r#"
    CREATE TABLE IF NOT EXISTS monad_client_opening_executions (
        wallet_name TEXT NOT NULL,
        attempt_id TEXT NOT NULL,
        execution_sequence INTEGER NOT NULL,
        kind TEXT NOT NULL,
        status TEXT NOT NULL,
        error_message TEXT,
        claimed_at INTEGER NOT NULL,
        authorized_at INTEGER,
        updated_at INTEGER NOT NULL,
        PRIMARY KEY (wallet_name, attempt_id, execution_sequence),
        FOREIGN KEY (attempt_id) REFERENCES monad_client_opening_attempts(attempt_id)
    )
"#;

const CREATE_OPENING_EXECUTIONS_INDEX_SQL: &str = r#"
    CREATE UNIQUE INDEX IF NOT EXISTS idx_monad_client_opening_executions_active
    ON monad_client_opening_executions(wallet_name, attempt_id)
    WHERE status IN ('claimed', 'authorized')
"#;

const CREATE_OPENING_JOURNAL_META_SQL: &str = r#"
    CREATE TABLE IF NOT EXISTS monad_client_opening_journal_meta (
        singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
        schema_version INTEGER NOT NULL,
        authority_marker TEXT NOT NULL
    )
"#;

const OPENING_JOURNAL_SCHEMA_VERSION: i64 = 3;
const OPENING_JOURNAL_AUTHORITY_MARKER: &str = "exact-input-two-step-execution-authority";

const CREATE_OPENING_ATTEMPTS_INDEX_SQL: &str = r#"
    CREATE INDEX IF NOT EXISTS idx_monad_client_opening_attempts_recovery
    ON monad_client_opening_attempts(wallet_name, state, created_at);
    CREATE UNIQUE INDEX IF NOT EXISTS idx_monad_client_opening_attempts_successor
    ON monad_client_opening_attempts(wallet_name, predecessor_attempt_id)
    WHERE predecessor_attempt_id IS NOT NULL;
    CREATE UNIQUE INDEX IF NOT EXISTS idx_monad_client_opening_attempts_operation_successor
    ON monad_client_opening_attempts(wallet_name, opening_id)
    WHERE predecessor_attempt_id IS NOT NULL;
    CREATE UNIQUE INDEX IF NOT EXISTS idx_monad_client_opening_attempts_operation_root
    ON monad_client_opening_attempts(wallet_name, opening_id)
    WHERE predecessor_attempt_id IS NULL
"#;

pub const OPENING_EXPORT_MIN_AGE_SECONDS: u64 = 3600;

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
pub struct LooseProofSummary {
    pub mint_url: String,
    pub unit: String,
    pub keyset_id: String,
    pub proof_count: u64,
    pub amount_raw: u64,
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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OpeningAttemptState {
    Prepared,
    Submitted,
    Rejected,
    Finalizing,
    Completed,
    Cancelled,
    Exported,
    ExternallySpent,
}

impl OpeningAttemptState {
    fn as_str(self) -> &'static str {
        match self {
            Self::Prepared => "prepared",
            Self::Submitted => "submitted",
            Self::Rejected => "rejected",
            Self::Finalizing => "finalizing",
            Self::Completed => "completed",
            Self::Cancelled => "cancelled",
            Self::Exported => "exported",
            Self::ExternallySpent => "externally_spent",
        }
    }

    fn parse(value: &str) -> rusqlite::Result<Self> {
        match value {
            "prepared" => Ok(Self::Prepared),
            "submitted" => Ok(Self::Submitted),
            "rejected" => Ok(Self::Rejected),
            "finalizing" => Ok(Self::Finalizing),
            "completed" => Ok(Self::Completed),
            "cancelled" => Ok(Self::Cancelled),
            "exported" => Ok(Self::Exported),
            "externally_spent" => Ok(Self::ExternallySpent),
            other => Err(sql_decode_error(format!(
                "unknown opening attempt state '{other}'"
            ))),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NewOpeningAttempt {
    pub attempt_id: String,
    pub opening_id: String,
    pub predecessor_attempt_id: Option<String>,
    pub reservation_id: String,
    pub receiver_pubkey: String,
    pub mint_url: String,
    pub unit: String,
    pub funding_token_target_msats: u64,
    pub expiry_timestamp: u64,
    pub prepared_open_json: String,
    pub selected_proof_ids: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OpeningAttemptRecord {
    pub attempt_id: String,
    pub opening_id: String,
    pub predecessor_attempt_id: Option<String>,
    pub reservation_id: String,
    pub receiver_pubkey: String,
    pub mint_url: String,
    pub unit: String,
    pub funding_token_target_msats: u64,
    pub expiry_timestamp: u64,
    pub prepared_open_json: String,
    pub selected_proof_ids: Vec<String>,
    pub completed_open_json: Option<String>,
    pub state: OpeningAttemptState,
    pub rejection_code: Option<u64>,
    pub rejection_message: Option<String>,
    pub latest_submitted_at: Option<u64>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OpeningExecutionKind {
    Initial,
    Replay,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OpeningExecutionStatus {
    Claimed,
    Authorized,
    ResponseReceived,
    Rejected,
    Uncertain,
    Cancelled,
}

impl OpeningExecutionStatus {
    fn as_str(self) -> &'static str {
        match self {
            Self::Claimed => "claimed",
            Self::Authorized => "authorized",
            Self::ResponseReceived => "response_received",
            Self::Rejected => "rejected",
            Self::Uncertain => "uncertain",
            Self::Cancelled => "cancelled",
        }
    }

    fn parse(value: &str) -> rusqlite::Result<Self> {
        match value {
            "claimed" => Ok(Self::Claimed),
            "authorized" => Ok(Self::Authorized),
            "response_received" => Ok(Self::ResponseReceived),
            "rejected" => Ok(Self::Rejected),
            "uncertain" => Ok(Self::Uncertain),
            "cancelled" => Ok(Self::Cancelled),
            other => Err(sql_decode_error(format!(
                "unknown opening execution status '{other}'"
            ))),
        }
    }
}

impl OpeningExecutionKind {
    fn as_str(self) -> &'static str {
        match self {
            Self::Initial => "initial",
            Self::Replay => "replay",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OpeningExecutionRecord {
    pub attempt_id: String,
    pub execution_sequence: u64,
    pub kind: OpeningExecutionKind,
    pub status: OpeningExecutionStatus,
    pub error_message: Option<String>,
    pub authorized_at: Option<u64>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct OpeningExportEvidence {
    attempt_id: String,
    reservation_id: String,
    selected_proof_ids: Vec<String>,
    latest_submitted_at: u64,
    execution_sequence: u64,
    state: OpeningAttemptState,
}

impl OpeningExportEvidence {
    pub(crate) fn is_aged_at(&self, now: u64) -> bool {
        now >= self.latest_submitted_at
            && now - self.latest_submitted_at >= OPENING_EXPORT_MIN_AGE_SECONDS
    }
}

#[derive(Debug, PartialEq, Eq)]
pub struct OpeningSubmissionPermit {
    attempt_id: String,
    execution_sequence: u64,
    kind: OpeningExecutionKind,
}

#[derive(Debug, PartialEq, Eq)]
pub struct AuthorizedOpeningSubmission {
    attempt_id: String,
    execution_sequence: u64,
    kind: OpeningExecutionKind,
}

impl AuthorizedOpeningSubmission {
    pub fn kind(&self) -> OpeningExecutionKind {
        self.kind
    }
}

impl OpeningSubmissionPermit {
    pub fn attempt_id(&self) -> &str {
        &self.attempt_id
    }

    pub fn kind(&self) -> OpeningExecutionKind {
        self.kind
    }
}

#[derive(Debug, PartialEq, Eq)]
pub enum OpeningSubmissionClaim {
    Acquired(OpeningSubmissionPermit),
    NotReplayable { state: OpeningAttemptState },
    InProgress,
    NotFound,
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
    TooManyInputProofs {
        selected: usize,
        maximum: usize,
    },
    AlreadyOpen(String),
    OpeningInProgress(String),
    OpeningConflict(String),
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
            Self::TooManyInputProofs { selected, maximum } => write!(
                f,
                "too many input proofs: selected={selected} maximum={maximum}"
            ),
            Self::AlreadyOpen(channel_id) => write!(f, "channel already open: {channel_id}"),
            Self::OpeningInProgress(channel_id) => {
                write!(f, "channel opening already in progress: {channel_id}")
            }
            Self::OpeningConflict(channel_id) => {
                write!(f, "conflicting channel opening: {channel_id}")
            }
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
    db_path: Option<PathBuf>,
    conn: Arc<Mutex<Connection>>,
}

fn sqlite_object_exists(tx: &rusqlite::Transaction<'_>, name: &str) -> Result<bool> {
    tx.query_row(
        "SELECT EXISTS(SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = ?1)",
        params![name],
        |row| row.get(0),
    )
    .map_err(Into::into)
}

fn sqlite_index_exists(tx: &rusqlite::Transaction<'_>, name: &str) -> Result<bool> {
    tx.query_row(
        "SELECT EXISTS(SELECT 1 FROM sqlite_master WHERE type = 'index' AND name = ?1)",
        params![name],
        |row| row.get(0),
    )
    .map_err(Into::into)
}

fn table_is_nonempty(tx: &rusqlite::Transaction<'_>, table: &str) -> Result<bool> {
    let count: i64 = tx.query_row(&format!("SELECT COUNT(*) FROM {table}"), [], |row| {
        row.get(0)
    })?;
    Ok(count != 0)
}

fn table_columns(tx: &rusqlite::Transaction<'_>, table: &str) -> Result<HashSet<String>> {
    tx.prepare(&format!("PRAGMA table_info({table})"))?
        .query_map([], |row| row.get(1))?
        .collect::<rusqlite::Result<_>>()
        .map_err(Into::into)
}

fn initialize_schema(conn: &mut Connection) -> Result<()> {
    initialize_schema_with_migration_hook(conn, || Ok(()))
}

fn initialize_schema_with_migration_hook(
    conn: &mut Connection,
    _migration_hook: impl FnOnce() -> Result<()>,
) -> Result<()> {
    let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
    let attempts_exist = sqlite_object_exists(&tx, "monad_client_opening_attempts")?;
    let executions_exist = sqlite_object_exists(&tx, "monad_client_opening_executions")?;
    let meta_exists = sqlite_object_exists(&tx, "monad_client_opening_journal_meta")?;
    let nonempty = (attempts_exist && table_is_nonempty(&tx, "monad_client_opening_attempts")?)
        || (executions_exist && table_is_nonempty(&tx, "monad_client_opening_executions")?);
    let marker = if meta_exists {
        tx.query_row(
            "SELECT schema_version, authority_marker FROM monad_client_opening_journal_meta
             WHERE singleton = 1",
            [],
            |row| Ok((row.get::<_, i64>(0)?, row.get::<_, String>(1)?)),
        )
        .optional()?
    } else {
        None
    };
    let attempt_columns = if attempts_exist {
        table_columns(&tx, "monad_client_opening_attempts")?
    } else {
        HashSet::new()
    };
    let execution_columns = if executions_exist {
        table_columns(&tx, "monad_client_opening_executions")?
    } else {
        HashSet::new()
    };
    let attempts_v3_valid = attempts_exist
        && [
            "attempt_id",
            "opening_id",
            "predecessor_attempt_id",
            "wallet_name",
            "reservation_id",
            "receiver_pubkey",
            "mint_url",
            "unit",
            "funding_token_target_msats",
            "expiry_timestamp",
            "prepared_open_json",
            "selected_proof_ids_json",
            "completed_open_json",
            "state",
            "rejection_code",
            "rejection_message",
            "latest_submitted_at",
            "created_at",
            "updated_at",
        ]
        .into_iter()
        .all(|column| attempt_columns.contains(column));
    let executions_valid = executions_exist
        && [
            "wallet_name",
            "attempt_id",
            "execution_sequence",
            "kind",
            "status",
            "error_message",
            "claimed_at",
            "authorized_at",
            "updated_at",
        ]
        .into_iter()
        .all(|column| execution_columns.contains(column));
    let active_index_valid =
        sqlite_index_exists(&tx, "idx_monad_client_opening_executions_active")?;
    let v3_valid = marker.as_ref().is_some_and(|(version, authority)| {
        *version == OPENING_JOURNAL_SCHEMA_VERSION && authority == OPENING_JOURNAL_AUTHORITY_MARKER
    }) && attempts_v3_valid
        && executions_valid
        && active_index_valid;

    if !v3_valid {
        if nonempty {
            return Err(LooseProofWalletError::Backend(
                "client opening journal schema is incompatible; export or reset the wallet database before upgrading"
                    .to_string(),
            ));
        }
        tx.execute_batch(
            "DROP TABLE IF EXISTS monad_client_opening_executions;
             DROP TABLE IF EXISTS monad_client_opening_attempts;
             DROP TABLE IF EXISTS monad_client_opening_journal_meta;",
        )?;
    }
    tx.execute_batch(&format!(
        "{CREATE_MINT_QUOTES_SQL};{CREATE_PREMINT_BATCHES_SQL};{CREATE_LOOSE_PROOFS_SQL};
         {CREATE_LOOSE_PROOF_INDEX_SQL};{CREATE_OPENING_ATTEMPTS_SQL};
         {CREATE_OPENING_EXECUTIONS_SQL};{CREATE_OPENING_EXECUTIONS_INDEX_SQL};
         {CREATE_OPENING_ATTEMPTS_INDEX_SQL};{CREATE_OPENING_JOURNAL_META_SQL};"
    ))?;
    tx.execute(
        "INSERT INTO monad_client_opening_journal_meta
         (singleton, schema_version, authority_marker) VALUES (1, ?1, ?2)
         ON CONFLICT(singleton) DO UPDATE SET schema_version = excluded.schema_version,
             authority_marker = excluded.authority_marker",
        params![
            OPENING_JOURNAL_SCHEMA_VERSION,
            OPENING_JOURNAL_AUTHORITY_MARKER
        ],
    )?;
    tx.commit()?;
    Ok(())
}

impl LooseProofWallet {
    pub fn open(path: impl AsRef<Path>, wallet_name: impl Into<String>) -> Result<Self> {
        let db_path = crate::wallet_lock::normalize_path(path.as_ref())?;
        let mut conn = Connection::open(path).map_err(|e| {
            LooseProofWalletError::Backend(format!("open loose proof wallet db: {e}"))
        })?;
        conn.busy_timeout(std::time::Duration::from_secs(5))
            .map_err(|e| {
                LooseProofWalletError::Backend(format!("set loose proof wallet busy timeout: {e}"))
            })?;
        initialize_schema(&mut conn)?;
        Ok(Self {
            wallet_name: wallet_name.into(),
            db_path: Some(db_path),
            conn: Arc::new(Mutex::new(conn)),
        })
    }

    /// Open an existing wallet without creating files, changing pragmas, or migrating schema.
    pub fn open_read_only(path: impl AsRef<Path>, wallet_name: impl Into<String>) -> Result<Self> {
        let db_path = crate::wallet_lock::normalize_path(path.as_ref())?;
        let conn =
            Connection::open_with_flags(path, OpenFlags::SQLITE_OPEN_READ_ONLY).map_err(|e| {
                LooseProofWalletError::Backend(format!("open read-only loose proof wallet db: {e}"))
            })?;
        conn.busy_timeout(std::time::Duration::from_secs(5))
            .map_err(|e| {
                LooseProofWalletError::Backend(format!(
                    "set read-only loose proof wallet busy timeout: {e}"
                ))
            })?;
        Ok(Self {
            wallet_name: wallet_name.into(),
            db_path: Some(db_path),
            conn: Arc::new(Mutex::new(conn)),
        })
    }

    #[cfg(test)]
    fn open_in_memory(wallet_name: impl Into<String>) -> Result<Self> {
        let mut conn = Connection::open_in_memory().map_err(|e| {
            LooseProofWalletError::Backend(format!("open loose proof wallet db: {e}"))
        })?;
        initialize_schema(&mut conn)?;
        Ok(Self {
            wallet_name: wallet_name.into(),
            db_path: None,
            conn: Arc::new(Mutex::new(conn)),
        })
    }

    pub(crate) fn database_path(&self) -> Option<&Path> {
        self.db_path.as_deref()
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

    pub fn list_available_proof_summaries(&self) -> Result<Vec<LooseProofSummary>> {
        let conn = self.conn()?;
        let mut stmt = conn
            .prepare(
                "SELECT mint_url, unit, keyset_id, COUNT(*), SUM(amount_raw)
                 FROM monad_client_loose_proofs
                 WHERE wallet_name = ?1 AND state = ?2
                 GROUP BY mint_url, unit, keyset_id
                 ORDER BY mint_url, unit, keyset_id",
            )
            .map_err(|e| {
                LooseProofWalletError::Backend(format!("prepare proof summary query: {e}"))
            })?;
        let rows = stmt
            .query_map(
                params![self.wallet_name, LooseProofState::Available.as_str()],
                |row| {
                    Ok(LooseProofSummary {
                        mint_url: row.get(0)?,
                        unit: row.get(1)?,
                        keyset_id: row.get(2)?,
                        proof_count: from_i64(row.get::<_, i64>(3)?)?,
                        amount_raw: from_i64(row.get::<_, i64>(4)?)?,
                    })
                },
            )
            .map_err(|e| LooseProofWalletError::Backend(format!("query proof summaries: {e}")))?;
        rows.collect::<rusqlite::Result<Vec<_>>>()
            .map_err(|e| LooseProofWalletError::Backend(format!("decode proof summaries: {e}")))
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
        self.reserve_selected_proofs_inner(mint_url, unit, proof_ids, None)
    }

    /// Atomically reserve exact proofs and persist the mint-visible channel-open attempt.
    pub fn reserve_selected_proofs_with_opening_attempt(
        &self,
        mint_url: &str,
        unit: &str,
        proof_ids: &[String],
        attempt: &NewOpeningAttempt,
    ) -> Result<ProofReservation> {
        self.reserve_selected_proofs_inner(mint_url, unit, proof_ids, Some(attempt))
    }

    fn reserve_selected_proofs_inner(
        &self,
        mint_url: &str,
        unit: &str,
        proof_ids: &[String],
        attempt: Option<&NewOpeningAttempt>,
    ) -> Result<ProofReservation> {
        validate_nonempty("mint_url", mint_url)?;
        validate_nonempty("unit", unit)?;
        if proof_ids.is_empty() {
            return Err(LooseProofWalletError::InvalidInput(
                "selected proof ids must not be empty".to_string(),
            ));
        }
        if proof_ids.len() > crate::proof_selection::MAX_SELECTED_INPUT_PROOFS {
            return Err(LooseProofWalletError::TooManyInputProofs {
                selected: proof_ids.len(),
                maximum: crate::proof_selection::MAX_SELECTED_INPUT_PROOFS,
            });
        }
        if attempt.is_some_and(|attempt| attempt.predecessor_attempt_id.is_some()) {
            return Err(LooseProofWalletError::InvalidInput(
                "initial opening attempt cannot have a predecessor".to_string(),
            ));
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

        let reservation_id = attempt
            .map(|attempt| attempt.reservation_id.clone())
            .unwrap_or_else(new_reservation_id);
        let now = now_seconds()?;
        let mut conn = self.conn()?;
        let tx = conn
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|e| {
                LooseProofWalletError::Backend(format!("start proof reservation transaction: {e}"))
            })?;

        if let Some(attempt) = attempt {
            let selected_json = canonical_proof_ids_json(proof_ids)?;
            let existing = tx
                .query_row(
                    "SELECT attempt_id, opening_id, reservation_id, receiver_pubkey, mint_url,
                            unit, funding_token_target_msats, expiry_timestamp, prepared_open_json,
                            selected_proof_ids_json, state
                     FROM monad_client_opening_attempts
                     WHERE wallet_name = ?1 AND (attempt_id = ?2 OR opening_id = ?3)",
                    params![self.wallet_name, attempt.attempt_id, attempt.opening_id],
                    |row| {
                        Ok((
                            row.get::<_, String>(0)?,
                            row.get::<_, String>(1)?,
                            row.get::<_, String>(2)?,
                            row.get::<_, String>(3)?,
                            row.get::<_, String>(4)?,
                            row.get::<_, String>(5)?,
                            row.get::<_, i64>(6)?,
                            row.get::<_, i64>(7)?,
                            row.get::<_, String>(8)?,
                            row.get::<_, String>(9)?,
                            OpeningAttemptState::parse(&row.get::<_, String>(10)?)?,
                        ))
                    },
                )
                .optional()?;
            if let Some(existing) = existing {
                let identity_matches = existing.0 == attempt.attempt_id
                    && existing.1 == attempt.opening_id
                    && existing.2 == attempt.reservation_id
                    && existing.3 == attempt.receiver_pubkey
                    && existing.4 == attempt.mint_url
                    && existing.5 == attempt.unit
                    && existing.6 == to_i64(attempt.funding_token_target_msats)?
                    && existing.7 == to_i64(attempt.expiry_timestamp)?
                    && existing.8 == attempt.prepared_open_json
                    && existing.9 == selected_json;
                if !identity_matches {
                    return Err(LooseProofWalletError::OpeningConflict(
                        attempt.attempt_id.clone(),
                    ));
                }
                return Err(match existing.10 {
                    OpeningAttemptState::Completed => {
                        LooseProofWalletError::AlreadyOpen(attempt.attempt_id.clone())
                    }
                    OpeningAttemptState::Prepared
                    | OpeningAttemptState::Submitted
                    | OpeningAttemptState::Finalizing => {
                        LooseProofWalletError::OpeningInProgress(attempt.attempt_id.clone())
                    }
                    _ => LooseProofWalletError::OpeningConflict(attempt.attempt_id.clone()),
                });
            }
        }

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
        if let Some(attempt) = attempt {
            validate_opening_attempt(attempt, &reservation_id, mint_url, unit)?;
            let selected_proof_ids_json = canonical_proof_ids_json(proof_ids)?;
            if selected_proof_ids_json != canonical_proof_ids_json(&attempt.selected_proof_ids)? {
                return Err(LooseProofWalletError::InvalidInput(
                    "opening attempt selected proofs do not match the reservation".to_string(),
                ));
            }
            tx.execute(
                "INSERT INTO monad_client_opening_attempts
                 (attempt_id, opening_id, predecessor_attempt_id, wallet_name,
                   reservation_id, receiver_pubkey, mint_url, unit, funding_token_target_msats,
                   expiry_timestamp, prepared_open_json, selected_proof_ids_json,
                   completed_open_json, state, rejection_code, rejection_message,
                   latest_submitted_at, created_at, updated_at)
                  VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12,
                          NULL, ?13, NULL, NULL, NULL, ?14, ?14)",
                params![
                    attempt.attempt_id,
                    attempt.opening_id,
                    attempt.predecessor_attempt_id,
                    self.wallet_name,
                    reservation_id,
                    attempt.receiver_pubkey,
                    attempt.mint_url,
                    attempt.unit,
                    to_i64(attempt.funding_token_target_msats)?,
                    to_i64(attempt.expiry_timestamp)?,
                    attempt.prepared_open_json,
                    selected_proof_ids_json,
                    OpeningAttemptState::Prepared.as_str(),
                    to_i64(now)?,
                ],
            )
            .map_err(|e| LooseProofWalletError::Backend(format!("insert opening attempt: {e}")))?;
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

    pub fn opening_attempts_for_recovery(&self) -> Result<Vec<OpeningAttemptRecord>> {
        let conn = self.conn()?;
        let mut stmt = conn.prepare(
            "SELECT attempt_id, opening_id, predecessor_attempt_id, reservation_id,
                     receiver_pubkey, mint_url, unit, funding_token_target_msats, expiry_timestamp,
                     prepared_open_json, selected_proof_ids_json, completed_open_json, state,
                     rejection_code, rejection_message, latest_submitted_at
             FROM monad_client_opening_attempts
             WHERE wallet_name = ?1
               AND (
                     state IN ('prepared', 'submitted', 'exported', 'finalizing')
                    OR (
                        state = 'rejected'
                        AND NOT EXISTS (
                            SELECT 1 FROM monad_client_opening_attempts successor
                            WHERE successor.wallet_name = monad_client_opening_attempts.wallet_name
                              AND successor.predecessor_attempt_id = monad_client_opening_attempts.attempt_id
                        )
                    )
               )
             ORDER BY created_at ASC",
        )?;
        let rows = stmt.query_map(params![self.wallet_name], row_to_opening_attempt)?;
        rows.collect::<rusqlite::Result<Vec<_>>>()
            .map_err(Into::into)
    }

    pub fn opening_attempt(&self, attempt_id: &str) -> Result<Option<OpeningAttemptRecord>> {
        let conn = self.conn()?;
        conn.query_row(
            "SELECT attempt_id, opening_id, predecessor_attempt_id, reservation_id,
                     receiver_pubkey, mint_url, unit, funding_token_target_msats, expiry_timestamp,
                     prepared_open_json, selected_proof_ids_json, completed_open_json, state,
                     rejection_code, rejection_message, latest_submitted_at
             FROM monad_client_opening_attempts
             WHERE wallet_name = ?1 AND attempt_id = ?2",
            params![self.wallet_name, attempt_id],
            row_to_opening_attempt,
        )
        .optional()
        .map_err(Into::into)
    }

    pub fn claim_opening_attempt_submission(
        &self,
        attempt_id: &str,
    ) -> Result<OpeningSubmissionClaim> {
        let now = now_seconds()?;
        let mut conn = self.conn()?;
        let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let Some(state) = opening_attempt_state_in_transaction(&tx, &self.wallet_name, attempt_id)?
        else {
            return Ok(OpeningSubmissionClaim::NotFound);
        };
        if state != OpeningAttemptState::Prepared {
            return Ok(OpeningSubmissionClaim::NotReplayable { state });
        }
        if has_active_opening_execution(&tx, &self.wallet_name, attempt_id)? {
            return Ok(OpeningSubmissionClaim::InProgress);
        }
        let sequence: i64 = tx.query_row(
            "SELECT COALESCE(MAX(execution_sequence), 0) + 1
             FROM monad_client_opening_executions
             WHERE wallet_name = ?1 AND attempt_id = ?2",
            params![self.wallet_name, attempt_id],
            |row| row.get(0),
        )?;
        tx.execute(
            "INSERT INTO monad_client_opening_executions
             (wallet_name, attempt_id, execution_sequence, kind, status, error_message,
              claimed_at, authorized_at, updated_at)
             VALUES (?1, ?2, ?3, ?4, 'claimed', NULL, ?5, NULL, ?5)",
            params![
                self.wallet_name,
                attempt_id,
                sequence,
                OpeningExecutionKind::Initial.as_str(),
                to_i64(now)?
            ],
        )?;
        tx.commit()?;
        Ok(OpeningSubmissionClaim::Acquired(OpeningSubmissionPermit {
            attempt_id: attempt_id.to_string(),
            execution_sequence: from_i64(sequence)?,
            kind: OpeningExecutionKind::Initial,
        }))
    }

    pub fn claim_opening_attempt_replay(&self, attempt_id: &str) -> Result<OpeningSubmissionClaim> {
        let now = now_seconds()?;
        let mut conn = self.conn()?;
        let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let state = tx
            .query_row(
                "SELECT state FROM monad_client_opening_attempts
                 WHERE wallet_name = ?1 AND attempt_id = ?2",
                params![self.wallet_name, attempt_id],
                |row| OpeningAttemptState::parse(&row.get::<_, String>(0)?),
            )
            .optional()?;
        let Some(state) = state else {
            return Ok(OpeningSubmissionClaim::NotFound);
        };
        if state != OpeningAttemptState::Submitted {
            return Ok(OpeningSubmissionClaim::NotReplayable { state });
        }
        if has_active_opening_execution(&tx, &self.wallet_name, attempt_id)? {
            return Ok(OpeningSubmissionClaim::InProgress);
        }
        let replay_exists: bool = tx.query_row(
            "SELECT EXISTS(
                SELECT 1 FROM monad_client_opening_executions
                WHERE wallet_name = ?1 AND attempt_id = ?2 AND kind = 'replay'
                  AND status != 'cancelled')",
            params![self.wallet_name, attempt_id],
            |row| row.get(0),
        )?;
        if replay_exists {
            return Ok(OpeningSubmissionClaim::NotReplayable { state });
        }
        let sequence: i64 = tx.query_row(
            "SELECT COALESCE(MAX(execution_sequence), 0) + 1
             FROM monad_client_opening_executions
             WHERE wallet_name = ?1 AND attempt_id = ?2",
            params![self.wallet_name, attempt_id],
            |row| row.get(0),
        )?;
        tx.execute(
            "INSERT INTO monad_client_opening_executions
             (wallet_name, attempt_id, execution_sequence, kind, status, error_message,
              claimed_at, authorized_at, updated_at)
             VALUES (?1, ?2, ?3, ?4, 'claimed', NULL, ?5, NULL, ?5)",
            params![
                self.wallet_name,
                attempt_id,
                sequence,
                OpeningExecutionKind::Replay.as_str(),
                to_i64(now)?
            ],
        )?;
        tx.commit()?;
        Ok(OpeningSubmissionClaim::Acquired(OpeningSubmissionPermit {
            attempt_id: attempt_id.to_string(),
            execution_sequence: from_i64(sequence)?,
            kind: OpeningExecutionKind::Replay,
        }))
    }

    pub fn authorize_opening_submission(
        &self,
        permit: OpeningSubmissionPermit,
    ) -> Result<AuthorizedOpeningSubmission> {
        self.authorize_opening_submission_at(permit, now_seconds()?)
    }

    pub(crate) fn authorize_opening_submission_at(
        &self,
        permit: OpeningSubmissionPermit,
        now: u64,
    ) -> Result<AuthorizedOpeningSubmission> {
        let mut conn = self.conn()?;
        let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let expected_state = match permit.kind {
            OpeningExecutionKind::Initial => OpeningAttemptState::Prepared,
            OpeningExecutionKind::Replay => OpeningAttemptState::Submitted,
        };
        let execution_matches: bool = tx.query_row(
            "SELECT EXISTS(
                SELECT 1 FROM monad_client_opening_executions
                WHERE wallet_name = ?1 AND attempt_id = ?2 AND execution_sequence = ?3
                  AND kind = ?4 AND status = 'claimed')",
            params![
                self.wallet_name,
                permit.attempt_id,
                to_i64(permit.execution_sequence)?,
                permit.kind.as_str(),
            ],
            |row| row.get(0),
        )?;
        let state =
            opening_attempt_state_in_transaction(&tx, &self.wallet_name, &permit.attempt_id)?;
        if !execution_matches || state != Some(expected_state) {
            return Err(LooseProofWalletError::InvalidStateTransition {
                entity: "opening submission claim",
                id: format!("{}#{}", permit.attempt_id, permit.execution_sequence),
                expected: expected_state.as_str(),
                actual: state
                    .map(|state| state.as_str().to_string())
                    .unwrap_or_else(|| "missing or stale claim".to_string()),
                requested: "authorized",
            });
        }
        let latest_submitted_at = tx.query_row(
            "SELECT latest_submitted_at FROM monad_client_opening_attempts
             WHERE wallet_name = ?1 AND attempt_id = ?2",
            params![self.wallet_name, permit.attempt_id],
            |row| optional_from_i64(row.get(0)?),
        )?;
        if latest_submitted_at.is_some_and(|latest| now <= latest) {
            let changed = tx.execute(
                "UPDATE monad_client_opening_executions
                 SET status = 'cancelled', error_message = ?5, updated_at = ?6
                 WHERE wallet_name = ?1 AND attempt_id = ?2 AND execution_sequence = ?3
                   AND kind = ?4 AND status = 'claimed'",
                params![
                    self.wallet_name,
                    permit.attempt_id,
                    to_i64(permit.execution_sequence)?,
                    permit.kind.as_str(),
                    "wall clock did not advance beyond latest submission",
                    to_i64(now)?,
                ],
            )?;
            if changed != 1 {
                return Err(LooseProofWalletError::ReservationConflict {
                    expected: 1,
                    updated: changed,
                });
            }
            tx.commit()?;
            return Err(LooseProofWalletError::InvalidStateTransition {
                entity: "opening submission claim",
                id: format!("{}#{}", permit.attempt_id, permit.execution_sequence),
                expected: "wall clock later than the previous authorized submission",
                actual: format!(
                    "timestamp {now} did not advance past latest {latest_submitted_at:?}"
                ),
                requested: "authorized",
            });
        }
        if permit.kind == OpeningExecutionKind::Initial {
            tx.execute(
                "UPDATE monad_client_opening_attempts
                 SET state = 'submitted', latest_submitted_at = ?3, updated_at = ?3
                 WHERE wallet_name = ?1 AND attempt_id = ?2 AND state = 'prepared'",
                params![self.wallet_name, permit.attempt_id, to_i64(now)?],
            )?;
        } else {
            tx.execute(
                "UPDATE monad_client_opening_attempts
                 SET latest_submitted_at = ?3, updated_at = ?3
                 WHERE wallet_name = ?1 AND attempt_id = ?2 AND state = 'submitted'",
                params![self.wallet_name, permit.attempt_id, to_i64(now)?],
            )?;
        }
        let changed = tx.execute(
            "UPDATE monad_client_opening_executions
             SET status = 'authorized', authorized_at = ?5, updated_at = ?5
             WHERE wallet_name = ?1 AND attempt_id = ?2 AND execution_sequence = ?3
               AND kind = ?4 AND status = 'claimed'",
            params![
                self.wallet_name,
                permit.attempt_id,
                to_i64(permit.execution_sequence)?,
                permit.kind.as_str(),
                to_i64(now)?,
            ],
        )?;
        if changed != 1 {
            return Err(LooseProofWalletError::InvalidStateTransition {
                entity: "opening submission claim",
                id: format!("{}#{}", permit.attempt_id, permit.execution_sequence),
                expected: "claimed",
                actual: "missing or stale claim".to_string(),
                requested: "authorized",
            });
        }
        tx.commit()?;
        Ok(AuthorizedOpeningSubmission {
            attempt_id: permit.attempt_id,
            execution_sequence: permit.execution_sequence,
            kind: permit.kind,
        })
    }

    pub fn cancel_opening_submission_claim(&self, permit: OpeningSubmissionPermit) -> Result<()> {
        let now = now_seconds()?;
        let conn = self.conn()?;
        let changed = conn.execute(
            "UPDATE monad_client_opening_executions
             SET status = 'cancelled', updated_at = ?5
             WHERE wallet_name = ?1 AND attempt_id = ?2 AND execution_sequence = ?3
               AND kind = ?4 AND status = 'claimed'",
            params![
                self.wallet_name,
                permit.attempt_id,
                to_i64(permit.execution_sequence)?,
                permit.kind.as_str(),
                to_i64(now)?,
            ],
        )?;
        if changed != 1 {
            return Err(LooseProofWalletError::InvalidStateTransition {
                entity: "opening submission claim",
                id: format!("{}#{}", permit.attempt_id, permit.execution_sequence),
                expected: "claimed",
                actual: "missing or stale claim".to_string(),
                requested: "cancelled",
            });
        }
        Ok(())
    }

    pub fn finish_opening_execution(
        &self,
        permit: AuthorizedOpeningSubmission,
        status: OpeningExecutionStatus,
        error_message: Option<&str>,
    ) -> Result<()> {
        if matches!(
            status,
            OpeningExecutionStatus::Claimed
                | OpeningExecutionStatus::Authorized
                | OpeningExecutionStatus::Rejected
                | OpeningExecutionStatus::Cancelled
        ) {
            return Err(LooseProofWalletError::InvalidInput(format!(
                "invalid terminal opening execution status '{status:?}'"
            )));
        }
        let now = now_seconds()?;
        let conn = self.conn()?;
        let changed = conn.execute(
            "UPDATE monad_client_opening_executions
             SET status = ?4, error_message = ?5, updated_at = ?6
             WHERE wallet_name = ?1 AND attempt_id = ?2 AND execution_sequence = ?3
               AND kind = ?7 AND status = 'authorized'",
            params![
                self.wallet_name,
                permit.attempt_id,
                to_i64(permit.execution_sequence)?,
                status.as_str(),
                error_message,
                to_i64(now)?,
                permit.kind.as_str(),
            ],
        )?;
        if changed != 1 {
            return Err(LooseProofWalletError::InvalidStateTransition {
                entity: "opening execution",
                id: format!("{}#{}", permit.attempt_id, permit.execution_sequence),
                expected: "authorized",
                actual: "missing or already completed".to_string(),
                requested: "terminal execution status",
            });
        }
        Ok(())
    }

    /// Atomically records a definitive mint rejection and, for the first
    /// execution only, makes the attempt safe to replace or cancel.
    pub(crate) fn record_definitive_opening_rejection(
        &self,
        permit: AuthorizedOpeningSubmission,
        code: u64,
        message: &str,
    ) -> Result<bool> {
        let mut conn = self.conn()?;
        let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let execution_matches: bool = tx.query_row(
            "SELECT EXISTS(
                SELECT 1 FROM monad_client_opening_executions
                WHERE wallet_name = ?1 AND attempt_id = ?2 AND execution_sequence = ?3
                  AND kind = ?4 AND status = 'authorized')",
            params![
                self.wallet_name,
                permit.attempt_id,
                to_i64(permit.execution_sequence)?,
                permit.kind.as_str(),
            ],
            |row| row.get(0),
        )?;
        if !execution_matches {
            return Err(LooseProofWalletError::InvalidStateTransition {
                entity: "opening execution",
                id: format!("{}#{}", permit.attempt_id, permit.execution_sequence),
                expected: "authorized",
                actual: "missing or already completed".to_string(),
                requested: "definitive rejection",
            });
        }

        let reject_attempt = permit.kind == OpeningExecutionKind::Initial;
        if reject_attempt {
            let prior_ambiguous_execution: bool = tx.query_row(
                "SELECT EXISTS(
                    SELECT 1 FROM monad_client_opening_executions
                    WHERE wallet_name = ?1 AND attempt_id = ?2
                      AND execution_sequence < ?3
                      AND status IN ('authorized', 'response_received', 'uncertain'))",
                params![
                    self.wallet_name,
                    permit.attempt_id,
                    to_i64(permit.execution_sequence)?
                ],
                |row| row.get(0),
            )?;
            if permit.execution_sequence != 1 || prior_ambiguous_execution {
                return Err(LooseProofWalletError::InvalidStateTransition {
                    entity: "opening attempt",
                    id: permit.attempt_id,
                    expected: "first authoritative execution without prior ambiguity",
                    actual: "prior mint-visible execution exists".to_string(),
                    requested: OpeningAttemptState::Rejected.as_str(),
                });
            }
        }

        let now = now_seconds()?;
        let changed = tx.execute(
            "UPDATE monad_client_opening_executions
             SET status = 'rejected', error_message = ?5, updated_at = ?6
             WHERE wallet_name = ?1 AND attempt_id = ?2 AND execution_sequence = ?3
               AND kind = ?4 AND status = 'authorized'",
            params![
                self.wallet_name,
                permit.attempt_id,
                to_i64(permit.execution_sequence)?,
                permit.kind.as_str(),
                message,
                to_i64(now)?,
            ],
        )?;
        if changed != 1 {
            return Err(LooseProofWalletError::ReservationConflict {
                expected: 1,
                updated: changed,
            });
        }
        if reject_attempt {
            let changed = tx.execute(
                "UPDATE monad_client_opening_attempts
                 SET state = 'rejected', rejection_code = ?3, rejection_message = ?4,
                     updated_at = ?5
                 WHERE wallet_name = ?1 AND attempt_id = ?2 AND state = 'submitted'",
                params![
                    self.wallet_name,
                    permit.attempt_id,
                    to_i64(code)?,
                    message,
                    to_i64(now)?,
                ],
            )?;
            if changed != 1 {
                return Err(LooseProofWalletError::ReservationConflict {
                    expected: 1,
                    updated: changed,
                });
            }
        }
        tx.commit()?;
        Ok(reject_attempt)
    }

    pub fn opening_executions(&self, attempt_id: &str) -> Result<Vec<OpeningExecutionRecord>> {
        let conn = self.conn()?;
        let mut stmt = conn.prepare(
            "SELECT attempt_id, execution_sequence, kind, status, error_message, authorized_at
             FROM monad_client_opening_executions
             WHERE wallet_name = ?1 AND attempt_id = ?2 ORDER BY execution_sequence",
        )?;
        let rows = stmt.query_map(params![self.wallet_name, attempt_id], |row| {
            let kind = match row.get::<_, String>(2)?.as_str() {
                "initial" => OpeningExecutionKind::Initial,
                "replay" => OpeningExecutionKind::Replay,
                other => {
                    return Err(sql_decode_error(format!(
                        "unknown execution kind '{other}'"
                    )))
                }
            };
            Ok(OpeningExecutionRecord {
                attempt_id: row.get(0)?,
                execution_sequence: from_i64(row.get(1)?)?,
                kind,
                status: OpeningExecutionStatus::parse(&row.get::<_, String>(3)?)?,
                error_message: row.get(4)?,
                authorized_at: optional_from_i64(row.get(5)?)?,
            })
        })?;
        rows.collect::<rusqlite::Result<Vec<_>>>()
            .map_err(Into::into)
    }

    /// Persist a successor attempt while retaining the operation-owned reservation.
    pub fn store_opening_attempt_for_reservation(&self, attempt: &NewOpeningAttempt) -> Result<()> {
        validate_opening_attempt(
            attempt,
            &attempt.reservation_id,
            &attempt.mint_url,
            &attempt.unit,
        )?;
        let now = now_seconds()?;
        let mut conn = self.conn()?;
        let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let proof_count: i64 = tx.query_row(
            "SELECT COUNT(*) FROM monad_client_loose_proofs
             WHERE wallet_name = ?1 AND reserved_by = ?2 AND state = ?3",
            params![
                self.wallet_name,
                attempt.reservation_id,
                LooseProofState::Reserved.as_str()
            ],
            |row| row.get(0),
        )?;
        if proof_count == 0 {
            return Err(LooseProofWalletError::NotFound(format!(
                "active reservation '{}'",
                attempt.reservation_id
            )));
        }
        let predecessor = attempt.predecessor_attempt_id.as_deref().ok_or_else(|| {
            LooseProofWalletError::InvalidInput(
                "successor opening attempt requires a predecessor".to_string(),
            )
        })?;
        {
            let predecessor_record = tx
                .query_row(
                    "SELECT state, rejection_code, opening_id, reservation_id, receiver_pubkey,
                            mint_url, unit, funding_token_target_msats, expiry_timestamp,
                            predecessor_attempt_id, selected_proof_ids_json
                     FROM monad_client_opening_attempts
                     WHERE wallet_name = ?1 AND attempt_id = ?2",
                    params![self.wallet_name, predecessor],
                    |row| {
                        Ok((
                            row.get::<_, String>(0)?,
                            row.get::<_, Option<i64>>(1)?,
                            row.get::<_, String>(2)?,
                            row.get::<_, String>(3)?,
                            row.get::<_, String>(4)?,
                            row.get::<_, String>(5)?,
                            row.get::<_, String>(6)?,
                            row.get::<_, i64>(7)?,
                            row.get::<_, i64>(8)?,
                            row.get::<_, Option<String>>(9)?,
                            row.get::<_, String>(10)?,
                        ))
                    },
                )
                .optional()?;
            let expected = (
                OpeningAttemptState::Rejected.as_str().to_string(),
                Some(12_002_i64),
                attempt.opening_id.clone(),
                attempt.reservation_id.clone(),
                attempt.receiver_pubkey.clone(),
                attempt.mint_url.clone(),
                attempt.unit.clone(),
                to_i64(attempt.funding_token_target_msats)?,
                to_i64(attempt.expiry_timestamp)?,
                None,
                canonical_proof_ids_json(&attempt.selected_proof_ids)?,
            );
            if predecessor_record != Some(expected) {
                return Err(LooseProofWalletError::InvalidInput(format!(
                    "opening predecessor '{predecessor}' is not an equivalent code-12002 rejection"
                )));
            }
        }
        let selected_proof_ids_json = canonical_proof_ids_json(&attempt.selected_proof_ids)?;
        let reserved_ids = proof_ids_for_reservation_in_transaction(
            &tx,
            &self.wallet_name,
            &attempt.reservation_id,
        )?;
        if canonical_proof_ids_json(&reserved_ids)? != selected_proof_ids_json {
            return Err(LooseProofWalletError::InvalidInput(
                "successor selected proofs do not exactly match its reservation".to_string(),
            ));
        }
        tx.execute(
            "INSERT INTO monad_client_opening_attempts
             (attempt_id, opening_id, predecessor_attempt_id, wallet_name,
              reservation_id, receiver_pubkey, mint_url, unit, funding_token_target_msats,
               expiry_timestamp, prepared_open_json, selected_proof_ids_json,
               completed_open_json, state, rejection_code, rejection_message,
               latest_submitted_at, created_at, updated_at)
              VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12,
                      NULL, ?13, NULL, NULL, NULL, ?14, ?14)",
            params![
                attempt.attempt_id,
                attempt.opening_id,
                attempt.predecessor_attempt_id,
                self.wallet_name,
                attempt.reservation_id,
                attempt.receiver_pubkey,
                attempt.mint_url,
                attempt.unit,
                to_i64(attempt.funding_token_target_msats)?,
                to_i64(attempt.expiry_timestamp)?,
                attempt.prepared_open_json,
                selected_proof_ids_json,
                OpeningAttemptState::Prepared.as_str(),
                to_i64(now)?,
            ],
        )?;
        tx.commit()?;
        Ok(())
    }

    pub fn mark_opening_attempt_finalizing(
        &self,
        attempt_id: &str,
        completed_open_json: &str,
    ) -> Result<()> {
        let now = now_seconds()?;
        let conn = self.conn()?;
        let changed = conn.execute(
            "UPDATE monad_client_opening_attempts
             SET state = ?3, completed_open_json = ?4, updated_at = ?5
             WHERE wallet_name = ?1 AND attempt_id = ?2 AND state IN (?6, ?7)",
            params![
                self.wallet_name,
                attempt_id,
                OpeningAttemptState::Finalizing.as_str(),
                completed_open_json,
                to_i64(now)?,
                OpeningAttemptState::Submitted.as_str(),
                OpeningAttemptState::Exported.as_str(),
            ],
        )?;
        if changed == 1 {
            Ok(())
        } else {
            drop(conn);
            match self.opening_attempt(attempt_id)? {
                Some(record)
                    if record.state == OpeningAttemptState::Finalizing
                        && record.completed_open_json.as_deref() == Some(completed_open_json) =>
                {
                    Ok(())
                }
                Some(record) if record.state == OpeningAttemptState::Finalizing => {
                    Err(LooseProofWalletError::InvalidInput(format!(
                        "opening attempt '{attempt_id}' has a different completion payload"
                    )))
                }
                _ => self.ensure_opening_attempt_state(attempt_id, OpeningAttemptState::Finalizing),
            }
        }
    }

    pub fn complete_opening_attempt_exact(&self, attempt_id: &str) -> Result<()> {
        let now = now_seconds()?;
        let mut conn = self.conn()?;
        let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let row = tx
            .query_row(
                "SELECT state, reservation_id, selected_proof_ids_json, prepared_open_json,
                        completed_open_json
                 FROM monad_client_opening_attempts
                 WHERE wallet_name = ?1 AND attempt_id = ?2",
                params![self.wallet_name, attempt_id],
                |row| {
                    Ok((
                        OpeningAttemptState::parse(&row.get::<_, String>(0)?)?,
                        row.get::<_, String>(1)?,
                        row.get::<_, String>(2)?,
                        row.get::<_, String>(3)?,
                        row.get::<_, Option<String>>(4)?,
                    ))
                },
            )
            .optional()?
            .ok_or_else(|| {
                LooseProofWalletError::NotFound(format!("opening attempt '{attempt_id}'"))
            })?;
        let (state, reservation_id, selected_json, prepared_json, completed_json) = row;
        if !matches!(
            state,
            OpeningAttemptState::Finalizing | OpeningAttemptState::Completed
        ) {
            return Err(LooseProofWalletError::InvalidStateTransition {
                entity: "opening attempt",
                id: attempt_id.to_string(),
                expected: OpeningAttemptState::Finalizing.as_str(),
                actual: state.as_str().to_string(),
                requested: OpeningAttemptState::Completed.as_str(),
            });
        }
        let expected: Vec<String> = serde_json::from_str(&selected_json).map_err(|e| {
            LooseProofWalletError::Backend(format!(
                "decode selected proofs for opening attempt '{attempt_id}': {e}"
            ))
        })?;
        let expected_json = canonical_proof_ids_json(&expected)?;
        if expected_json != selected_json || expected.is_empty() {
            return Err(LooseProofWalletError::Backend(format!(
                "opening attempt '{attempt_id}' has invalid selected proof ids"
            )));
        }
        let completed_json = completed_json.ok_or_else(|| {
            LooseProofWalletError::Backend(format!(
                "opening attempt '{attempt_id}' has no authoritative completion payload"
            ))
        })?;
        let channel_id = authoritative_completed_channel_id(&completed_json)?;
        let prepared_channel_id = authoritative_prepared_channel_id(&prepared_json)?;
        if channel_id != attempt_id || prepared_channel_id != attempt_id {
            return Err(LooseProofWalletError::Backend(format!(
                "opening attempt '{attempt_id}' has conflicting prepared/completed channel identity"
            )));
        }

        let mut stmt = tx.prepare(
            "SELECT proof_id, state, reserved_by, spent_channel_id
             FROM monad_client_loose_proofs
             WHERE wallet_name = ?1 AND (reserved_by = ?2 OR spent_channel_id = ?3)",
        )?;
        let rows = stmt
            .query_map(
                params![self.wallet_name, reservation_id, channel_id],
                |row| {
                    Ok((
                        row.get::<_, String>(0)?,
                        row.get::<_, String>(1)?,
                        row.get::<_, Option<String>>(2)?,
                        row.get::<_, Option<String>>(3)?,
                    ))
                },
            )?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        drop(stmt);
        if rows.len() != expected.len() {
            return Err(LooseProofWalletError::ReservationConflict {
                expected: expected.len(),
                updated: rows.len(),
            });
        }
        let expected_set = expected.iter().collect::<HashSet<_>>();
        for (proof_id, proof_state, reserved_by, spent_channel_id) in &rows {
            let reserved_for_attempt = proof_state == "reserved"
                && reserved_by.as_deref() == Some(reservation_id.as_str())
                && spent_channel_id.is_none();
            let spent_for_channel = proof_state == "spent"
                && reserved_by.as_deref() == Some(reservation_id.as_str())
                && spent_channel_id.as_deref() == Some(channel_id.as_str());
            if !expected_set.contains(proof_id) || !(reserved_for_attempt || spent_for_channel) {
                return Err(LooseProofWalletError::InvalidInput(format!(
                    "proof '{proof_id}' conflicts with exact completion of opening '{attempt_id}'"
                )));
            }
        }
        tx.execute(
            "UPDATE monad_client_loose_proofs
             SET state = 'spent', spent_channel_id = ?3, updated_at = ?4
             WHERE wallet_name = ?1 AND reserved_by = ?2 AND state = 'reserved'",
            params![self.wallet_name, reservation_id, channel_id, to_i64(now)?],
        )?;
        if state == OpeningAttemptState::Finalizing {
            let changed = tx.execute(
                "UPDATE monad_client_opening_attempts SET state = 'completed', updated_at = ?3
                 WHERE wallet_name = ?1 AND attempt_id = ?2 AND state = 'finalizing'",
                params![self.wallet_name, attempt_id, to_i64(now)?],
            )?;
            if changed != 1 {
                return Err(LooseProofWalletError::ReservationConflict {
                    expected: 1,
                    updated: changed,
                });
            }
        }
        tx.commit()?;
        Ok(())
    }

    pub fn cancel_rejected_opening_attempt(&self, attempt_id: &str) -> Result<()> {
        self.cancel_opening_attempt(attempt_id, OpeningAttemptState::Rejected)
    }

    pub fn cancel_prepared_opening_attempt(&self, attempt_id: &str) -> Result<()> {
        self.cancel_opening_attempt(attempt_id, OpeningAttemptState::Prepared)
    }

    pub(crate) fn opening_export_evidence(
        &self,
        attempt_id: &str,
        state: OpeningAttemptState,
    ) -> Result<Option<OpeningExportEvidence>> {
        let conn = self.conn()?;
        let row = conn
            .query_row(
                "SELECT reservation_id, selected_proof_ids_json, latest_submitted_at,
                        (SELECT COALESCE(MAX(execution_sequence), 0)
                         FROM monad_client_opening_executions executions
                         WHERE executions.wallet_name = attempts.wallet_name
                           AND executions.attempt_id = attempts.attempt_id)
                 FROM monad_client_opening_attempts attempts
                 WHERE wallet_name = ?1 AND attempt_id = ?2 AND state = ?3",
                params![self.wallet_name, attempt_id, state.as_str()],
                |row| {
                    Ok((
                        row.get::<_, String>(0)?,
                        row.get::<_, String>(1)?,
                        row.get::<_, Option<i64>>(2)?,
                        row.get::<_, i64>(3)?,
                    ))
                },
            )
            .optional()?;
        let Some((reservation_id, selected_json, Some(latest_submitted_at), sequence)) = row else {
            return Ok(None);
        };
        let selected_proof_ids: Vec<String> =
            serde_json::from_str(&selected_json).map_err(|e| {
                LooseProofWalletError::Backend(format!(
                    "decode selected proofs for opening attempt '{attempt_id}': {e}"
                ))
            })?;
        if selected_proof_ids.is_empty()
            || canonical_proof_ids_json(&selected_proof_ids)? != selected_json
            || sequence <= 0
        {
            return Err(LooseProofWalletError::Backend(format!(
                "opening attempt '{attempt_id}' has invalid export evidence"
            )));
        }
        Ok(Some(OpeningExportEvidence {
            attempt_id: attempt_id.to_string(),
            reservation_id,
            selected_proof_ids,
            latest_submitted_at: from_i64(latest_submitted_at)?,
            execution_sequence: from_i64(sequence)?,
            state,
        }))
    }

    #[cfg(test)]
    pub(crate) fn mark_opening_attempt_exported_if_evidence_current(
        &self,
        evidence: &OpeningExportEvidence,
        now: u64,
    ) -> Result<bool> {
        self.mark_opening_attempts_exported_if_evidence_current(std::slice::from_ref(evidence), now)
    }

    pub(crate) fn mark_opening_attempts_exported_if_evidence_current(
        &self,
        evidences: &[OpeningExportEvidence],
        now: u64,
    ) -> Result<bool> {
        if evidences.is_empty() {
            return Ok(false);
        }
        if evidences.iter().any(|evidence| {
            !matches!(
                evidence.state,
                OpeningAttemptState::Submitted | OpeningAttemptState::Exported
            ) || (evidence.state == OpeningAttemptState::Submitted && !evidence.is_aged_at(now))
        }) {
            return Ok(false);
        }
        let mut conn = self.conn()?;
        let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
        for evidence in evidences {
            let selected_json = canonical_proof_ids_json(&evidence.selected_proof_ids)?;
            let attempt_matches: bool = tx.query_row(
                "SELECT EXISTS(
                    SELECT 1 FROM monad_client_opening_attempts attempts
                    WHERE wallet_name = ?1 AND attempt_id = ?2 AND state = ?3
                      AND reservation_id = ?4 AND selected_proof_ids_json = ?5
                      AND latest_submitted_at = ?6
                      AND NOT EXISTS (
                          SELECT 1 FROM monad_client_opening_attempts successor
                          WHERE successor.wallet_name = attempts.wallet_name
                            AND successor.predecessor_attempt_id = attempts.attempt_id)
                      AND (SELECT COALESCE(MAX(execution_sequence), 0)
                           FROM monad_client_opening_executions executions
                           WHERE executions.wallet_name = attempts.wallet_name
                             AND executions.attempt_id = attempts.attempt_id) = ?7)",
                params![
                    self.wallet_name,
                    evidence.attempt_id,
                    evidence.state.as_str(),
                    evidence.reservation_id,
                    selected_json,
                    to_i64(evidence.latest_submitted_at)?,
                    to_i64(evidence.execution_sequence)?,
                ],
                |row| row.get(0),
            )?;
            if !attempt_matches {
                return Ok(false);
            }
            let reservation_rows = tx
                .prepare(
                    "SELECT proof_id, state, spent_channel_id
                     FROM monad_client_loose_proofs
                     WHERE wallet_name = ?1 AND reserved_by = ?2",
                )?
                .query_map(params![self.wallet_name, evidence.reservation_id], |row| {
                    Ok((
                        row.get::<_, String>(0)?,
                        row.get::<_, String>(1)?,
                        row.get::<_, Option<String>>(2)?,
                    ))
                })?
                .collect::<rusqlite::Result<Vec<_>>>()?;
            let reserved_ids = reservation_rows
                .iter()
                .map(|(proof_id, _, _)| proof_id.clone())
                .collect::<Vec<_>>();
            if canonical_proof_ids_json(&reserved_ids)? != selected_json
                || reservation_rows.iter().any(|(_, state, spent_channel_id)| {
                    state != LooseProofState::Reserved.as_str() || spent_channel_id.is_some()
                })
            {
                return Ok(false);
            }
        }
        for evidence in evidences
            .iter()
            .filter(|evidence| evidence.state == OpeningAttemptState::Submitted)
        {
            let changed = tx.execute(
                "UPDATE monad_client_opening_attempts
                 SET state = 'exported', updated_at = ?4
                 WHERE wallet_name = ?1 AND attempt_id = ?2 AND state = 'submitted'
                    AND latest_submitted_at = ?3",
                params![
                    self.wallet_name,
                    evidence.attempt_id,
                    to_i64(evidence.latest_submitted_at)?,
                    to_i64(now)?,
                ],
            )?;
            if changed != 1 {
                return Ok(false);
            }
        }
        tx.commit()?;
        Ok(true)
    }

    pub(crate) fn mark_opening_attempt_externally_spent_if_evidence_current(
        &self,
        evidence: &OpeningExportEvidence,
        now: u64,
    ) -> Result<bool> {
        if evidence.state != OpeningAttemptState::Exported {
            return Ok(false);
        }
        let mut conn = self.conn()?;
        let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let selected_json = canonical_proof_ids_json(&evidence.selected_proof_ids)?;
        let attempt_matches: bool = tx.query_row(
            "SELECT EXISTS(
                SELECT 1 FROM monad_client_opening_attempts attempts
                WHERE wallet_name = ?1 AND attempt_id = ?2 AND state = 'exported'
                  AND reservation_id = ?3 AND selected_proof_ids_json = ?4
                  AND latest_submitted_at = ?5
                  AND (SELECT COALESCE(MAX(execution_sequence), 0)
                       FROM monad_client_opening_executions executions
                       WHERE executions.wallet_name = attempts.wallet_name
                         AND executions.attempt_id = attempts.attempt_id) = ?6)",
            params![
                self.wallet_name,
                evidence.attempt_id,
                evidence.reservation_id,
                selected_json,
                to_i64(evidence.latest_submitted_at)?,
                to_i64(evidence.execution_sequence)?,
            ],
            |row| row.get(0),
        )?;
        if !attempt_matches {
            return Ok(false);
        }
        let proof_ids = proof_ids_for_reservation_in_transaction(
            &tx,
            &self.wallet_name,
            &evidence.reservation_id,
        )?;
        if canonical_proof_ids_json(&proof_ids)? != selected_json {
            return Ok(false);
        }
        let changed = tx.execute(
            "UPDATE monad_client_opening_attempts
             SET state = 'externally_spent', updated_at = ?3
             WHERE wallet_name = ?1 AND attempt_id = ?2 AND state = 'exported'",
            params![self.wallet_name, evidence.attempt_id, to_i64(now)?],
        )?;
        if changed != 1 {
            return Ok(false);
        }
        let changed = tx.execute(
            "UPDATE monad_client_loose_proofs
             SET state = 'spent', reserved_by = NULL, updated_at = ?3
             WHERE wallet_name = ?1 AND reserved_by = ?2 AND state = 'reserved'
               AND spent_channel_id IS NULL",
            params![self.wallet_name, evidence.reservation_id, to_i64(now)?],
        )?;
        if changed != evidence.selected_proof_ids.len() {
            return Err(LooseProofWalletError::ReservationConflict {
                expected: evidence.selected_proof_ids.len(),
                updated: changed,
            });
        }
        tx.commit()?;
        Ok(true)
    }

    fn cancel_opening_attempt(
        &self,
        attempt_id: &str,
        expected_state: OpeningAttemptState,
    ) -> Result<()> {
        let now = now_seconds()?;
        let mut conn = self.conn()?;
        let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let attempt: Option<(String, String)> = tx
            .query_row(
                "SELECT reservation_id, selected_proof_ids_json
                 FROM monad_client_opening_attempts
                 WHERE wallet_name = ?1 AND attempt_id = ?2 AND state = ?3
                   AND NOT EXISTS (
                       SELECT 1 FROM monad_client_opening_attempts successor
                       WHERE successor.wallet_name = monad_client_opening_attempts.wallet_name
                         AND successor.predecessor_attempt_id = monad_client_opening_attempts.attempt_id
                   )",
                params![
                    self.wallet_name,
                    attempt_id,
                    expected_state.as_str()
                ],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .optional()?;
        let Some((reservation_id, selected_json)) = attempt else {
            return Ok(());
        };
        let expected: Vec<String> = serde_json::from_str(&selected_json).map_err(|e| {
            LooseProofWalletError::Backend(format!(
                "decode selected proofs for opening attempt '{attempt_id}': {e}"
            ))
        })?;
        if expected.is_empty() || canonical_proof_ids_json(&expected)? != selected_json {
            return Err(LooseProofWalletError::Backend(format!(
                "opening attempt '{attempt_id}' has invalid selected proof ids"
            )));
        }
        let mut stmt = tx.prepare(
            "SELECT proof_id, state, spent_channel_id FROM monad_client_loose_proofs
             WHERE wallet_name = ?1 AND reserved_by = ?2",
        )?;
        let rows = stmt
            .query_map(params![self.wallet_name, reservation_id], |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, Option<String>>(2)?,
                ))
            })?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        drop(stmt);
        let expected_set = expected.iter().collect::<HashSet<_>>();
        if rows.len() != expected.len()
            || rows.iter().any(|(proof_id, state, spent_channel_id)| {
                !expected_set.contains(proof_id)
                    || state != LooseProofState::Reserved.as_str()
                    || spent_channel_id.is_some()
            })
        {
            return Err(LooseProofWalletError::ReservationConflict {
                expected: expected.len(),
                updated: rows.len(),
            });
        }
        let changed = tx.execute(
            "UPDATE monad_client_opening_attempts
             SET state = ?3, updated_at = ?4
             WHERE wallet_name = ?1 AND attempt_id = ?2 AND state = ?5",
            params![
                self.wallet_name,
                attempt_id,
                OpeningAttemptState::Cancelled.as_str(),
                to_i64(now)?,
                expected_state.as_str(),
            ],
        )?;
        if changed != 1 {
            return Err(LooseProofWalletError::ReservationConflict {
                expected: 1,
                updated: changed,
            });
        }
        for proof_id in &expected {
            let changed = tx.execute(
                "UPDATE monad_client_loose_proofs
                 SET state = 'available', reserved_by = NULL, updated_at = ?4
                 WHERE wallet_name = ?1 AND proof_id = ?2 AND reserved_by = ?3
                   AND state = 'reserved' AND spent_channel_id IS NULL",
                params![self.wallet_name, proof_id, reservation_id, to_i64(now)?],
            )?;
            if changed != 1 {
                return Err(LooseProofWalletError::ReservationConflict {
                    expected: expected.len(),
                    updated: 0,
                });
            }
        }
        tx.execute(
            "UPDATE monad_client_opening_executions
             SET status = 'cancelled', updated_at = ?3
             WHERE wallet_name = ?1 AND attempt_id = ?2 AND status = 'claimed'",
            params![self.wallet_name, attempt_id, to_i64(now)?],
        )?;
        tx.commit()?;
        Ok(())
    }

    fn ensure_opening_attempt_state(
        &self,
        attempt_id: &str,
        expected: OpeningAttemptState,
    ) -> Result<()> {
        match self.opening_attempt(attempt_id)? {
            Some(record) if record.state == expected => Ok(()),
            Some(record) => Err(LooseProofWalletError::InvalidStateTransition {
                entity: "opening attempt",
                id: attempt_id.to_string(),
                expected: expected.as_str(),
                actual: record.state.as_str().to_string(),
                requested: expected.as_str(),
            }),
            None => Err(LooseProofWalletError::NotFound(format!(
                "opening attempt '{attempt_id}'"
            ))),
        }
    }

    pub fn release_reservation(&self, reservation_id: &str) -> Result<usize> {
        let now = now_seconds()?;
        let conn = self.conn()?;
        conn.execute(
            "UPDATE monad_client_loose_proofs
             SET state = ?4, reserved_by = NULL, updated_at = ?5
             WHERE wallet_name = ?1 AND reserved_by = ?2 AND state = ?3
               AND NOT EXISTS (
                   SELECT 1 FROM monad_client_opening_attempts
                   WHERE wallet_name = ?1 AND reservation_id = ?2
                      AND state IN ('prepared', 'submitted', 'exported', 'finalizing')
               )",
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

pub(crate) fn new_reservation_id() -> String {
    let mut bytes = [0u8; 16];
    rand::rng().fill_bytes(&mut bytes);
    format!("proof-res-{}", hex::encode(bytes))
}

fn validate_opening_attempt(
    attempt: &NewOpeningAttempt,
    reservation_id: &str,
    mint_url: &str,
    unit: &str,
) -> Result<()> {
    validate_nonempty("attempt_id", &attempt.attempt_id)?;
    validate_nonempty("opening_id", &attempt.opening_id)?;
    validate_nonempty("receiver_pubkey", &attempt.receiver_pubkey)?;
    validate_nonempty("prepared_open_json", &attempt.prepared_open_json)?;
    if attempt.selected_proof_ids.is_empty() {
        return Err(LooseProofWalletError::InvalidInput(
            "opening attempt selected proofs must not be empty".to_string(),
        ));
    }
    if attempt.selected_proof_ids.len() > crate::proof_selection::MAX_SELECTED_INPUT_PROOFS {
        return Err(LooseProofWalletError::TooManyInputProofs {
            selected: attempt.selected_proof_ids.len(),
            maximum: crate::proof_selection::MAX_SELECTED_INPUT_PROOFS,
        });
    }
    if attempt.reservation_id != reservation_id
        || attempt.mint_url != mint_url
        || attempt.unit != unit
    {
        return Err(LooseProofWalletError::InvalidInput(
            "opening attempt does not match its proof reservation".to_string(),
        ));
    }
    Ok(())
}

fn canonical_proof_ids_json(proof_ids: &[String]) -> Result<String> {
    let mut ids = proof_ids.to_vec();
    ids.sort();
    if ids.iter().any(|id| id.trim().is_empty()) {
        return Err(LooseProofWalletError::InvalidInput(
            "selected proof id must not be empty".to_string(),
        ));
    }
    if ids.windows(2).any(|pair| pair[0] == pair[1]) {
        return Err(LooseProofWalletError::InvalidInput(
            "selected proof ids contain a duplicate".to_string(),
        ));
    }
    serde_json::to_string(&ids)
        .map_err(|e| LooseProofWalletError::Backend(format!("serialize selected proof ids: {e}")))
}

fn authoritative_completed_channel_id(completed_json: &str) -> Result<String> {
    let completed: serde_json::Value = serde_json::from_str(completed_json).map_err(|e| {
        LooseProofWalletError::Backend(format!(
            "decode authoritative completed opening payload: {e}"
        ))
    })?;
    let channel_id = completed
        .get("channel_id")
        .and_then(serde_json::Value::as_str)
        .ok_or_else(|| {
            LooseProofWalletError::Backend(
                "authoritative completed opening payload has no channel_id".to_string(),
            )
        })?;
    let result_channel_id = completed
        .get("result")
        .and_then(|result| result.get("channel_id"))
        .and_then(serde_json::Value::as_str)
        .ok_or_else(|| {
            LooseProofWalletError::Backend(
                "authoritative completed opening result has no channel_id".to_string(),
            )
        })?;
    if channel_id != result_channel_id {
        return Err(LooseProofWalletError::Backend(format!(
            "authoritative completed opening channel ids conflict: '{channel_id}' and '{result_channel_id}'"
        )));
    }
    Ok(channel_id.to_string())
}

fn authoritative_prepared_channel_id(prepared_json: &str) -> Result<String> {
    serde_json::from_str::<serde_json::Value>(prepared_json)
        .map_err(|e| {
            LooseProofWalletError::Backend(format!(
                "decode authoritative prepared opening payload: {e}"
            ))
        })?
        .get("channel_id")
        .and_then(serde_json::Value::as_str)
        .map(str::to_string)
        .ok_or_else(|| {
            LooseProofWalletError::Backend(
                "authoritative prepared opening payload has no channel_id".to_string(),
            )
        })
}

fn proof_ids_for_reservation_in_transaction(
    tx: &rusqlite::Transaction<'_>,
    wallet_name: &str,
    reservation_id: &str,
) -> Result<Vec<String>> {
    let mut stmt = tx.prepare(
        "SELECT proof_id FROM monad_client_loose_proofs
         WHERE wallet_name = ?1 AND reserved_by = ?2 AND state = 'reserved'",
    )?;
    let ids = stmt
        .query_map(params![wallet_name, reservation_id], |row| row.get(0))?
        .collect::<rusqlite::Result<Vec<_>>>()?;
    Ok(ids)
}

fn opening_attempt_state_in_transaction(
    tx: &rusqlite::Transaction<'_>,
    wallet_name: &str,
    attempt_id: &str,
) -> Result<Option<OpeningAttemptState>> {
    tx.query_row(
        "SELECT state FROM monad_client_opening_attempts
         WHERE wallet_name = ?1 AND attempt_id = ?2",
        params![wallet_name, attempt_id],
        |row| OpeningAttemptState::parse(&row.get::<_, String>(0)?),
    )
    .optional()
    .map_err(Into::into)
}

fn has_active_opening_execution(
    tx: &rusqlite::Transaction<'_>,
    wallet_name: &str,
    attempt_id: &str,
) -> Result<bool> {
    tx.query_row(
        "SELECT EXISTS(
            SELECT 1 FROM monad_client_opening_executions
            WHERE wallet_name = ?1 AND attempt_id = ?2
              AND status IN ('claimed', 'authorized'))",
        params![wallet_name, attempt_id],
        |row| row.get(0),
    )
    .map_err(Into::into)
}

fn row_to_opening_attempt(row: &rusqlite::Row<'_>) -> rusqlite::Result<OpeningAttemptRecord> {
    Ok(OpeningAttemptRecord {
        attempt_id: row.get(0)?,
        opening_id: row.get(1)?,
        predecessor_attempt_id: row.get(2)?,
        reservation_id: row.get(3)?,
        receiver_pubkey: row.get(4)?,
        mint_url: row.get(5)?,
        unit: row.get(6)?,
        funding_token_target_msats: from_i64(row.get(7)?)?,
        expiry_timestamp: from_i64(row.get(8)?)?,
        prepared_open_json: row.get(9)?,
        selected_proof_ids: serde_json::from_str(&row.get::<_, String>(10)?).map_err(|e| {
            sql_decode_error(format!(
                "invalid selected proof ids in opening journal: {e}"
            ))
        })?,
        completed_open_json: row.get(11)?,
        state: OpeningAttemptState::parse(&row.get::<_, String>(12)?)?,
        rejection_code: row.get::<_, Option<i64>>(13)?.map(from_i64).transpose()?,
        rejection_message: row.get(14)?,
        latest_submitted_at: optional_from_i64(row.get(15)?)?,
    })
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

    fn opening_attempt(
        attempt_id: &str,
        reservation_id: &str,
        proof_ids: &[&str],
    ) -> NewOpeningAttempt {
        NewOpeningAttempt {
            attempt_id: attempt_id.to_string(),
            opening_id: attempt_id.to_string(),
            predecessor_attempt_id: None,
            reservation_id: reservation_id.to_string(),
            receiver_pubkey: "receiver".to_string(),
            mint_url: MINT.to_string(),
            unit: "sat".to_string(),
            funding_token_target_msats: 8_000,
            expiry_timestamp: 123_456,
            prepared_open_json: format!(r#"{{"channel_id":"{attempt_id}"}}"#),
            selected_proof_ids: proof_ids.iter().map(|id| (*id).to_string()).collect(),
        }
    }

    fn claim_and_authorize(
        wallet: &LooseProofWallet,
        attempt_id: &str,
    ) -> AuthorizedOpeningSubmission {
        let OpeningSubmissionClaim::Acquired(permit) =
            wallet.claim_opening_attempt_submission(attempt_id).unwrap()
        else {
            panic!("opening submission claim was not acquired");
        };
        wallet.authorize_opening_submission(permit).unwrap()
    }

    fn authorize_replay_after_latest(
        wallet: &LooseProofWallet,
        permit: OpeningSubmissionPermit,
    ) -> AuthorizedOpeningSubmission {
        let latest = wallet
            .opening_attempt(&permit.attempt_id)
            .unwrap()
            .unwrap()
            .latest_submitted_at
            .unwrap();
        wallet
            .authorize_opening_submission_at(permit, latest + 1)
            .unwrap()
    }

    fn completed_payload(channel_id: &str) -> String {
        format!(r#"{{"channel_id":"{channel_id}","result":{{"channel_id":"{channel_id}"}}}}"#)
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

        let summaries = wallet.list_available_proof_summaries().unwrap();
        assert_eq!(summaries.len(), 2);
        assert_eq!(summaries[0].mint_url, MINT);
        assert_eq!(summaries[0].unit, "sat");
        assert_eq!(summaries[0].keyset_id, "keyset-a");
        assert_eq!(summaries[0].proof_count, 1);
        assert_eq!(summaries[0].amount_raw, 1);
        assert_eq!(summaries[1].keyset_id, "keyset-b");
        assert_eq!(summaries[1].proof_count, 1);
        assert_eq!(summaries[1].amount_raw, 2);
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
    fn reserve_selected_proofs_enforces_portable_992_id_limit() {
        let wallet = wallet();
        let proofs = (0..crate::proof_selection::MAX_SELECTED_INPUT_PROOFS)
            .map(|i| proof(&format!("proof-{i:04}"), 1, "keyset-a"))
            .collect::<Vec<_>>();
        let ids = proofs
            .iter()
            .map(|proof| proof.proof_id.clone())
            .collect::<Vec<_>>();
        wallet.import_proofs(&proofs).unwrap();
        assert_eq!(
            wallet
                .reserve_selected_proofs(MINT, "sat", &ids)
                .unwrap()
                .proofs
                .len(),
            crate::proof_selection::MAX_SELECTED_INPUT_PROOFS
        );

        let oversized_wallet = LooseProofWallet::open_in_memory("bob").unwrap();
        let oversized = (0..=crate::proof_selection::MAX_SELECTED_INPUT_PROOFS)
            .map(|i| format!("proof-{i:04}"))
            .collect::<Vec<_>>();
        assert_eq!(
            oversized_wallet
                .reserve_selected_proofs(MINT, "sat", &oversized)
                .unwrap_err(),
            LooseProofWalletError::TooManyInputProofs {
                selected: crate::proof_selection::MAX_SELECTED_INPUT_PROOFS + 1,
                maximum: crate::proof_selection::MAX_SELECTED_INPUT_PROOFS,
            }
        );
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
    fn opening_attempt_is_atomic_with_selected_proof_reservation() {
        let wallet = wallet();
        wallet
            .import_proofs(&[proof("proof-a", 8, "keyset-a")])
            .unwrap();
        let reservation_id = new_reservation_id();
        let attempt = NewOpeningAttempt {
            attempt_id: "channel-a".to_string(),
            opening_id: "opening-a".to_string(),
            predecessor_attempt_id: None,
            reservation_id: reservation_id.clone(),
            receiver_pubkey: "receiver".to_string(),
            mint_url: MINT.to_string(),
            unit: "sat".to_string(),
            funding_token_target_msats: 8_000,
            expiry_timestamp: 123_456,
            prepared_open_json: r#"{"channel_id":"channel-a"}"#.to_string(),
            selected_proof_ids: vec!["proof-a".to_string()],
        };

        let reservation = wallet
            .reserve_selected_proofs_with_opening_attempt(
                MINT,
                "sat",
                &["proof-a".to_string()],
                &attempt,
            )
            .unwrap();
        assert_eq!(reservation.reservation_id, reservation_id);
        let stored = wallet.opening_attempt("channel-a").unwrap().unwrap();
        assert_eq!(stored.state, OpeningAttemptState::Prepared);
        assert_eq!(stored.reservation_id, reservation_id);
        assert_eq!(
            wallet.proofs_for_reservation(&reservation_id).unwrap()[0].state,
            LooseProofState::Reserved
        );

        let permit = match wallet
            .claim_opening_attempt_submission("channel-a")
            .unwrap()
        {
            OpeningSubmissionClaim::Acquired(permit) => permit,
            other => panic!("unexpected submission claim: {other:?}"),
        };
        assert_eq!(
            wallet.opening_attempt("channel-a").unwrap().unwrap().state,
            OpeningAttemptState::Prepared
        );
        assert_eq!(
            wallet
                .opening_attempt("channel-a")
                .unwrap()
                .unwrap()
                .latest_submitted_at,
            None
        );
        let claimed = wallet.opening_executions("channel-a").unwrap();
        assert_eq!(claimed[0].status, OpeningExecutionStatus::Claimed);
        assert_eq!(claimed[0].authorized_at, None);
        assert_eq!(
            wallet
                .claim_opening_attempt_submission("channel-a")
                .unwrap(),
            OpeningSubmissionClaim::InProgress
        );
        let permit = wallet.authorize_opening_submission(permit).unwrap();
        wallet
            .finish_opening_execution(permit, OpeningExecutionStatus::ResponseReceived, None)
            .unwrap();
        wallet
            .mark_opening_attempt_finalizing("channel-a", &completed_payload("channel-a"))
            .unwrap();
        wallet
            .mark_opening_attempt_finalizing("channel-a", &completed_payload("channel-a"))
            .unwrap();
        assert!(wallet
            .mark_opening_attempt_finalizing("channel-a", r#"{"result":"different"}"#)
            .is_err());
        wallet.complete_opening_attempt_exact("channel-a").unwrap();
        assert_eq!(
            wallet.opening_attempt("channel-a").unwrap().unwrap().state,
            OpeningAttemptState::Completed
        );
        wallet.complete_opening_attempt_exact("channel-a").unwrap();
    }

    #[test]
    fn opening_attempt_rejects_selected_proof_id_mismatch_atomically() {
        let wallet = wallet();
        wallet
            .import_proofs(&[proof("proof-a", 8, "keyset-a")])
            .unwrap();
        let attempt = opening_attempt("channel-a", "reservation-a", &["proof-b"]);
        assert!(wallet
            .reserve_selected_proofs_with_opening_attempt(
                MINT,
                "sat",
                &["proof-a".to_string()],
                &attempt,
            )
            .is_err());
        assert_eq!(
            wallet
                .list_available_proofs(MINT, "sat", &[])
                .unwrap()
                .len(),
            1
        );
        assert!(wallet.opening_attempt("channel-a").unwrap().is_none());
    }

    #[test]
    fn submission_claim_and_replay_are_typed_and_durably_sequenced() {
        let wallet = wallet();
        wallet
            .import_proofs(&[proof("proof-a", 8, "keyset-a")])
            .unwrap();
        let attempt = opening_attempt("channel-a", "reservation-a", &["proof-a"]);
        wallet
            .reserve_selected_proofs_with_opening_attempt(
                MINT,
                "sat",
                &["proof-a".to_string()],
                &attempt,
            )
            .unwrap();
        let initial = match wallet
            .claim_opening_attempt_submission("channel-a")
            .unwrap()
        {
            OpeningSubmissionClaim::Acquired(permit) => permit,
            other => panic!("unexpected claim: {other:?}"),
        };
        assert_eq!(
            wallet
                .opening_attempt("channel-a")
                .unwrap()
                .unwrap()
                .latest_submitted_at,
            None
        );
        assert_eq!(
            wallet.claim_opening_attempt_replay("channel-a").unwrap(),
            OpeningSubmissionClaim::NotReplayable {
                state: OpeningAttemptState::Prepared
            }
        );
        let initial = wallet.authorize_opening_submission(initial).unwrap();
        assert!(wallet
            .opening_attempt("channel-a")
            .unwrap()
            .unwrap()
            .latest_submitted_at
            .is_some());
        assert_eq!(wallet.release_reservation("reservation-a").unwrap(), 0);
        assert_eq!(
            wallet.proofs_for_reservation("reservation-a").unwrap()[0].state,
            LooseProofState::Reserved
        );
        assert_eq!(
            wallet
                .claim_opening_attempt_submission("channel-a")
                .unwrap(),
            OpeningSubmissionClaim::NotReplayable {
                state: OpeningAttemptState::Submitted
            }
        );
        wallet
            .finish_opening_execution(initial, OpeningExecutionStatus::Uncertain, Some("timeout"))
            .unwrap();
        let replay = match wallet.claim_opening_attempt_replay("channel-a").unwrap() {
            OpeningSubmissionClaim::Acquired(permit) => permit,
            other => panic!("unexpected replay claim: {other:?}"),
        };
        assert_eq!(
            wallet.claim_opening_attempt_replay("channel-a").unwrap(),
            OpeningSubmissionClaim::InProgress
        );
        let replay = authorize_replay_after_latest(&wallet, replay);
        wallet
            .finish_opening_execution(replay, OpeningExecutionStatus::ResponseReceived, None)
            .unwrap();
        let executions = wallet.opening_executions("channel-a").unwrap();
        assert_eq!(executions.len(), 2);
        assert_eq!(executions[0].kind, OpeningExecutionKind::Initial);
        assert_eq!(executions[0].status, OpeningExecutionStatus::Uncertain);
        assert_eq!(executions[1].kind, OpeningExecutionKind::Replay);
        assert_eq!(executions[1].execution_sequence, 2);
        assert_eq!(
            wallet.claim_opening_attempt_replay("channel-a").unwrap(),
            OpeningSubmissionClaim::NotReplayable {
                state: OpeningAttemptState::Submitted
            }
        );
    }

    #[test]
    fn export_enforces_age_boundary_and_clock_rollback() {
        for (age, expected) in [
            (0, false),
            (OPENING_EXPORT_MIN_AGE_SECONDS - 1, false),
            (OPENING_EXPORT_MIN_AGE_SECONDS, true),
        ] {
            let wallet = wallet();
            wallet
                .import_proofs(&[proof("proof-a", 8, "keyset-a")])
                .unwrap();
            wallet
                .reserve_selected_proofs_with_opening_attempt(
                    MINT,
                    "sat",
                    &["proof-a".to_string()],
                    &opening_attempt("channel-a", "reservation-a", &["proof-a"]),
                )
                .unwrap();
            let authorized = claim_and_authorize(&wallet, "channel-a");
            wallet
                .finish_opening_execution(
                    authorized,
                    OpeningExecutionStatus::Uncertain,
                    Some("timeout"),
                )
                .unwrap();
            let evidence = wallet
                .opening_export_evidence("channel-a", OpeningAttemptState::Submitted)
                .unwrap()
                .unwrap();
            assert_eq!(
                wallet
                    .mark_opening_attempt_exported_if_evidence_current(
                        &evidence,
                        evidence.latest_submitted_at + age,
                    )
                    .unwrap(),
                expected
            );
        }

        let wallet = wallet();
        wallet
            .import_proofs(&[proof("proof-a", 8, "keyset-a")])
            .unwrap();
        wallet
            .reserve_selected_proofs_with_opening_attempt(
                MINT,
                "sat",
                &["proof-a".to_string()],
                &opening_attempt("channel-a", "reservation-a", &["proof-a"]),
            )
            .unwrap();
        let authorized = claim_and_authorize(&wallet, "channel-a");
        wallet
            .finish_opening_execution(authorized, OpeningExecutionStatus::Uncertain, None)
            .unwrap();
        let evidence = wallet
            .opening_export_evidence("channel-a", OpeningAttemptState::Submitted)
            .unwrap()
            .unwrap();
        assert!(!wallet
            .mark_opening_attempt_exported_if_evidence_current(
                &evidence,
                evidence.latest_submitted_at - 1,
            )
            .unwrap());
    }

    #[test]
    fn grouped_export_transition_is_atomic_and_idempotent() {
        let wallet = wallet();
        wallet
            .import_proofs(&[
                proof("proof-a", 8, "keyset-a"),
                proof("proof-b", 8, "keyset-a"),
            ])
            .unwrap();
        for (attempt_id, reservation_id, proof_id) in [
            ("channel-a", "reservation-a", "proof-a"),
            ("channel-b", "reservation-b", "proof-b"),
        ] {
            wallet
                .reserve_selected_proofs_with_opening_attempt(
                    MINT,
                    "sat",
                    &[proof_id.to_string()],
                    &opening_attempt(attempt_id, reservation_id, &[proof_id]),
                )
                .unwrap();
            let authorized = claim_and_authorize(&wallet, attempt_id);
            wallet
                .finish_opening_execution(authorized, OpeningExecutionStatus::Uncertain, None)
                .unwrap();
        }

        let first = wallet
            .opening_export_evidence("channel-a", OpeningAttemptState::Submitted)
            .unwrap()
            .unwrap();
        let stale_second = wallet
            .opening_export_evidence("channel-b", OpeningAttemptState::Submitted)
            .unwrap()
            .unwrap();
        let OpeningSubmissionClaim::Acquired(replay) =
            wallet.claim_opening_attempt_replay("channel-b").unwrap()
        else {
            panic!("replay claim not acquired");
        };
        let replay = authorize_replay_after_latest(&wallet, replay);
        wallet
            .finish_opening_execution(replay, OpeningExecutionStatus::Uncertain, None)
            .unwrap();
        let now = wallet
            .opening_attempt("channel-b")
            .unwrap()
            .unwrap()
            .latest_submitted_at
            .unwrap()
            + OPENING_EXPORT_MIN_AGE_SECONDS;

        assert!(
            !wallet
                .mark_opening_attempts_exported_if_evidence_current(
                    &[first.clone(), stale_second],
                    now,
                )
                .unwrap()
        );
        assert_eq!(
            wallet.opening_attempt("channel-a").unwrap().unwrap().state,
            OpeningAttemptState::Submitted
        );
        assert_eq!(
            wallet.opening_attempt("channel-b").unwrap().unwrap().state,
            OpeningAttemptState::Submitted
        );

        let second = wallet
            .opening_export_evidence("channel-b", OpeningAttemptState::Submitted)
            .unwrap()
            .unwrap();
        wallet
            .conn
            .lock()
            .unwrap()
            .execute_batch(
                "CREATE TRIGGER fail_grouped_export
                 BEFORE UPDATE ON monad_client_opening_attempts
                 WHEN OLD.attempt_id = 'channel-b' AND NEW.state = 'exported'
                 BEGIN SELECT RAISE(ABORT, 'injected grouped export failure'); END;",
            )
            .unwrap();
        assert!(wallet
            .mark_opening_attempts_exported_if_evidence_current(
                &[first.clone(), second.clone()],
                now,
            )
            .is_err());
        assert_eq!(
            wallet.opening_attempt("channel-a").unwrap().unwrap().state,
            OpeningAttemptState::Submitted
        );
        assert_eq!(
            wallet.opening_attempt("channel-b").unwrap().unwrap().state,
            OpeningAttemptState::Submitted
        );
        wallet
            .conn
            .lock()
            .unwrap()
            .execute_batch("DROP TRIGGER fail_grouped_export;")
            .unwrap();
        assert!(wallet
            .mark_opening_attempts_exported_if_evidence_current(&[first.clone(), second], now,)
            .unwrap());
        let exported = ["channel-a", "channel-b"].map(|attempt_id| {
            wallet
                .opening_export_evidence(attempt_id, OpeningAttemptState::Exported)
                .unwrap()
                .unwrap()
        });
        assert!(wallet
            .mark_opening_attempts_exported_if_evidence_current(&exported, now)
            .unwrap());
    }

    #[test]
    fn replay_authorization_requires_strictly_advancing_wall_clock() {
        let wallet = wallet();
        wallet
            .import_proofs(&[proof("proof-a", 8, "keyset-a")])
            .unwrap();
        wallet
            .reserve_selected_proofs_with_opening_attempt(
                MINT,
                "sat",
                &["proof-a".to_string()],
                &opening_attempt("channel-a", "reservation-a", &["proof-a"]),
            )
            .unwrap();
        let OpeningSubmissionClaim::Acquired(initial) = wallet
            .claim_opening_attempt_submission("channel-a")
            .unwrap()
        else {
            panic!("initial claim not acquired");
        };
        let initial = wallet
            .authorize_opening_submission_at(initial, 1_000)
            .unwrap();
        wallet
            .finish_opening_execution(initial, OpeningExecutionStatus::Uncertain, None)
            .unwrap();

        for now in [1_000, 999] {
            let OpeningSubmissionClaim::Acquired(replay) =
                wallet.claim_opening_attempt_replay("channel-a").unwrap()
            else {
                panic!("replay claim not acquired");
            };
            assert!(wallet.authorize_opening_submission_at(replay, now).is_err());
            let attempt = wallet.opening_attempt("channel-a").unwrap().unwrap();
            assert_eq!(attempt.latest_submitted_at, Some(1_000));
            assert_eq!(attempt.state, OpeningAttemptState::Submitted);
            assert_eq!(
                wallet.proofs_for_reservation("reservation-a").unwrap()[0].state,
                LooseProofState::Reserved
            );
            assert_eq!(
                wallet
                    .opening_executions("channel-a")
                    .unwrap()
                    .last()
                    .unwrap()
                    .status,
                OpeningExecutionStatus::Cancelled
            );
        }

        let OpeningSubmissionClaim::Acquired(replay) =
            wallet.claim_opening_attempt_replay("channel-a").unwrap()
        else {
            panic!("replay claim not acquired after clock recovery");
        };
        wallet
            .authorize_opening_submission_at(replay, 1_001)
            .unwrap();
        assert_eq!(
            wallet
                .opening_attempt("channel-a")
                .unwrap()
                .unwrap()
                .latest_submitted_at,
            Some(1_001)
        );
    }

    #[test]
    fn newer_replay_invalidates_export_evidence_and_resets_age() {
        let wallet = wallet();
        wallet
            .import_proofs(&[proof("proof-a", 8, "keyset-a")])
            .unwrap();
        wallet
            .reserve_selected_proofs_with_opening_attempt(
                MINT,
                "sat",
                &["proof-a".to_string()],
                &opening_attempt("channel-a", "reservation-a", &["proof-a"]),
            )
            .unwrap();
        let initial = claim_and_authorize(&wallet, "channel-a");
        wallet
            .finish_opening_execution(initial, OpeningExecutionStatus::Uncertain, None)
            .unwrap();
        let old = wallet
            .opening_export_evidence("channel-a", OpeningAttemptState::Submitted)
            .unwrap()
            .unwrap();
        let OpeningSubmissionClaim::Acquired(replay) =
            wallet.claim_opening_attempt_replay("channel-a").unwrap()
        else {
            panic!("replay claim not acquired");
        };
        let replay = authorize_replay_after_latest(&wallet, replay);
        wallet
            .finish_opening_execution(replay, OpeningExecutionStatus::Uncertain, None)
            .unwrap();
        assert!(!wallet
            .mark_opening_attempt_exported_if_evidence_current(
                &old,
                old.latest_submitted_at + OPENING_EXPORT_MIN_AGE_SECONDS,
            )
            .unwrap());
        let current = wallet
            .opening_export_evidence("channel-a", OpeningAttemptState::Submitted)
            .unwrap()
            .unwrap();
        assert_eq!(current.execution_sequence, old.execution_sequence + 1);
        assert!(!wallet
            .mark_opening_attempt_exported_if_evidence_current(
                &current,
                current.latest_submitted_at + OPENING_EXPORT_MIN_AGE_SECONDS - 1,
            )
            .unwrap());
        assert!(wallet
            .mark_opening_attempt_exported_if_evidence_current(
                &current,
                current.latest_submitted_at + OPENING_EXPORT_MIN_AGE_SECONDS,
            )
            .unwrap());
    }

    #[test]
    fn exact_duplicate_opening_is_typed_across_wallet_handles() {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("wallet.sqlite");
        let first = LooseProofWallet::open(&path, "alice").unwrap();
        let second = LooseProofWallet::open(&path, "alice").unwrap();
        first
            .import_proofs(&[proof("proof-a", 8, "keyset-a")])
            .unwrap();
        let attempt = opening_attempt("channel-a", "reservation-a", &["proof-a"]);
        first
            .reserve_selected_proofs_with_opening_attempt(
                MINT,
                "sat",
                &["proof-a".to_string()],
                &attempt,
            )
            .unwrap();
        assert_eq!(
            second
                .reserve_selected_proofs_with_opening_attempt(
                    MINT,
                    "sat",
                    &["proof-a".to_string()],
                    &attempt,
                )
                .unwrap_err(),
            LooseProofWalletError::OpeningInProgress("channel-a".to_string())
        );

        let mut conflicting = attempt.clone();
        conflicting.receiver_pubkey = "different".to_string();
        assert_eq!(
            second
                .reserve_selected_proofs_with_opening_attempt(
                    MINT,
                    "sat",
                    &["proof-a".to_string()],
                    &conflicting,
                )
                .unwrap_err(),
            LooseProofWalletError::OpeningConflict("channel-a".to_string())
        );

        let authorized = claim_and_authorize(&first, "channel-a");
        first
            .finish_opening_execution(authorized, OpeningExecutionStatus::ResponseReceived, None)
            .unwrap();
        first
            .mark_opening_attempt_finalizing("channel-a", &completed_payload("channel-a"))
            .unwrap();
        first.complete_opening_attempt_exact("channel-a").unwrap();
        assert_eq!(
            second
                .reserve_selected_proofs_with_opening_attempt(
                    MINT,
                    "sat",
                    &["proof-a".to_string()],
                    &attempt,
                )
                .unwrap_err(),
            LooseProofWalletError::AlreadyOpen("channel-a".to_string())
        );
    }

    #[test]
    fn submission_claim_rolls_back_state_and_timestamp_if_execution_insert_fails() {
        let wallet = wallet();
        wallet
            .import_proofs(&[proof("proof-a", 8, "keyset-a")])
            .unwrap();
        wallet
            .reserve_selected_proofs_with_opening_attempt(
                MINT,
                "sat",
                &["proof-a".to_string()],
                &opening_attempt("channel-a", "reservation-a", &["proof-a"]),
            )
            .unwrap();
        wallet
            .conn()
            .unwrap()
            .execute_batch(
                "CREATE TRIGGER fail_execution_insert BEFORE INSERT ON monad_client_opening_executions
                 BEGIN SELECT RAISE(ABORT, 'injected execution insert fault'); END;",
            )
            .unwrap();
        assert!(wallet
            .claim_opening_attempt_submission("channel-a")
            .is_err());
        let attempt = wallet.opening_attempt("channel-a").unwrap().unwrap();
        assert_eq!(attempt.state, OpeningAttemptState::Prepared);
        assert_eq!(attempt.latest_submitted_at, None);
        assert!(wallet.opening_executions("channel-a").unwrap().is_empty());
    }

    #[test]
    fn generic_execution_completion_cannot_bypass_rejection_authority() {
        let wallet = wallet();
        wallet
            .import_proofs(&[proof("proof-a", 8, "keyset-a")])
            .unwrap();
        wallet
            .reserve_selected_proofs_with_opening_attempt(
                MINT,
                "sat",
                &["proof-a".to_string()],
                &opening_attempt("channel-a", "reservation-a", &["proof-a"]),
            )
            .unwrap();
        let authorized = claim_and_authorize(&wallet, "channel-a");

        assert!(wallet
            .finish_opening_execution(
                authorized,
                OpeningExecutionStatus::Rejected,
                Some("forged rejection"),
            )
            .is_err());
        assert_eq!(
            wallet.opening_attempt("channel-a").unwrap().unwrap().state,
            OpeningAttemptState::Submitted
        );
        assert_eq!(
            wallet.opening_executions("channel-a").unwrap()[0].status,
            OpeningExecutionStatus::Authorized
        );
        assert_eq!(wallet.release_reservation("reservation-a").unwrap(), 0);
    }

    #[test]
    fn definitive_initial_rejection_is_atomic_across_fault() {
        let wallet = wallet();
        wallet
            .import_proofs(&[proof("proof-a", 8, "keyset-a")])
            .unwrap();
        wallet
            .reserve_selected_proofs_with_opening_attempt(
                MINT,
                "sat",
                &["proof-a".to_string()],
                &opening_attempt("channel-a", "reservation-a", &["proof-a"]),
            )
            .unwrap();
        let authorized = claim_and_authorize(&wallet, "channel-a");
        wallet
            .conn()
            .unwrap()
            .execute_batch(
                "CREATE TRIGGER fail_attempt_rejection BEFORE UPDATE
                 ON monad_client_opening_attempts WHEN NEW.state = 'rejected'
                 BEGIN SELECT RAISE(ABORT, 'injected rejection fault'); END;",
            )
            .unwrap();

        assert!(wallet
            .record_definitive_opening_rejection(authorized, 12_002, "inactive keyset")
            .is_err());
        let attempt = wallet.opening_attempt("channel-a").unwrap().unwrap();
        assert_eq!(attempt.state, OpeningAttemptState::Submitted);
        assert_eq!(attempt.rejection_code, None);
        let executions = wallet.opening_executions("channel-a").unwrap();
        assert_eq!(executions[0].status, OpeningExecutionStatus::Authorized);
        assert_eq!(executions[0].error_message, None);
    }

    #[test]
    fn definitive_replay_rejection_preserves_prior_ambiguity() {
        let wallet = wallet();
        wallet
            .import_proofs(&[proof("proof-a", 8, "keyset-a")])
            .unwrap();
        wallet
            .reserve_selected_proofs_with_opening_attempt(
                MINT,
                "sat",
                &["proof-a".to_string()],
                &opening_attempt("channel-a", "reservation-a", &["proof-a"]),
            )
            .unwrap();
        let initial = claim_and_authorize(&wallet, "channel-a");
        wallet
            .finish_opening_execution(initial, OpeningExecutionStatus::Uncertain, Some("timeout"))
            .unwrap();
        let OpeningSubmissionClaim::Acquired(replay) =
            wallet.claim_opening_attempt_replay("channel-a").unwrap()
        else {
            panic!("replay claim not acquired");
        };
        let replay = authorize_replay_after_latest(&wallet, replay);

        assert!(!wallet
            .record_definitive_opening_rejection(replay, 12_002, "inactive keyset")
            .unwrap());
        let attempt = wallet.opening_attempt("channel-a").unwrap().unwrap();
        assert_eq!(attempt.state, OpeningAttemptState::Submitted);
        assert_eq!(attempt.rejection_code, None);
        let executions = wallet.opening_executions("channel-a").unwrap();
        assert_eq!(executions[0].status, OpeningExecutionStatus::Uncertain);
        assert_eq!(executions[1].status, OpeningExecutionStatus::Rejected);
        assert_eq!(wallet.release_reservation("reservation-a").unwrap(), 0);
    }

    #[test]
    fn reopen_preserves_recovery_states_for_terminal_executions() {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("wallet.sqlite");
        let wallet = LooseProofWallet::open(&path, "alice").unwrap();
        wallet
            .import_proofs(&[
                proof("proof-rejected", 8, "keyset-a"),
                proof("proof-response", 8, "keyset-a"),
                proof("proof-replay", 8, "keyset-a"),
            ])
            .unwrap();
        for (attempt_id, proof_id) in [
            ("rejected", "proof-rejected"),
            ("response", "proof-response"),
            ("replay", "proof-replay"),
        ] {
            wallet
                .reserve_selected_proofs_with_opening_attempt(
                    MINT,
                    "sat",
                    &[proof_id.to_string()],
                    &opening_attempt(attempt_id, attempt_id, &[proof_id]),
                )
                .unwrap();
        }
        let rejected = claim_and_authorize(&wallet, "rejected");
        wallet
            .record_definitive_opening_rejection(rejected, 12_002, "inactive keyset")
            .unwrap();
        let response = claim_and_authorize(&wallet, "response");
        wallet
            .finish_opening_execution(response, OpeningExecutionStatus::ResponseReceived, None)
            .unwrap();
        let initial = claim_and_authorize(&wallet, "replay");
        wallet
            .finish_opening_execution(initial, OpeningExecutionStatus::Uncertain, Some("timeout"))
            .unwrap();
        let OpeningSubmissionClaim::Acquired(replay) =
            wallet.claim_opening_attempt_replay("replay").unwrap()
        else {
            panic!("replay claim not acquired");
        };
        let replay = authorize_replay_after_latest(&wallet, replay);
        wallet
            .record_definitive_opening_rejection(replay, 12_002, "inactive keyset")
            .unwrap();
        drop(wallet);

        let reopened = LooseProofWallet::open(&path, "alice").unwrap();
        let recovered = reopened.opening_attempts_for_recovery().unwrap();
        assert_eq!(recovered.len(), 3);
        assert_eq!(
            recovered
                .iter()
                .find(|attempt| attempt.attempt_id == "rejected")
                .unwrap()
                .state,
            OpeningAttemptState::Rejected
        );
        assert!(recovered
            .iter()
            .filter(|attempt| attempt.attempt_id != "rejected")
            .all(|attempt| attempt.state == OpeningAttemptState::Submitted));
        assert_eq!(
            reopened.opening_executions("response").unwrap()[0].status,
            OpeningExecutionStatus::ResponseReceived
        );
        assert_eq!(
            reopened.opening_executions("replay").unwrap()[1].status,
            OpeningExecutionStatus::Rejected
        );
    }

    #[test]
    fn exact_completion_is_atomic_across_fault_and_idempotent() {
        let wallet = wallet();
        wallet
            .import_proofs(&[proof("proof-a", 8, "keyset-a")])
            .unwrap();
        let attempt = opening_attempt("channel-a", "reservation-a", &["proof-a"]);
        wallet
            .reserve_selected_proofs_with_opening_attempt(
                MINT,
                "sat",
                &["proof-a".to_string()],
                &attempt,
            )
            .unwrap();
        let _authorized = claim_and_authorize(&wallet, "channel-a");
        wallet
            .mark_opening_attempt_finalizing("channel-a", &completed_payload("channel-a"))
            .unwrap();
        wallet.conn().unwrap().execute_batch(
            "CREATE TRIGGER fail_exact_completion BEFORE UPDATE ON monad_client_opening_attempts
             WHEN NEW.state = 'completed' BEGIN SELECT RAISE(ABORT, 'injected fault'); END;",
        ).unwrap();
        assert!(wallet.complete_opening_attempt_exact("channel-a").is_err());
        assert_eq!(
            wallet.proofs_for_reservation("reservation-a").unwrap()[0].state,
            LooseProofState::Reserved
        );
        wallet
            .conn()
            .unwrap()
            .execute_batch("DROP TRIGGER fail_exact_completion")
            .unwrap();
        wallet.complete_opening_attempt_exact("channel-a").unwrap();
        wallet.complete_opening_attempt_exact("channel-a").unwrap();
    }

    #[test]
    fn exact_completion_rejects_every_conflicting_proof_state() {
        for conflict in [
            "missing",
            "available",
            "reassigned",
            "extra",
            "differently-spent",
        ] {
            let wallet = wallet();
            wallet
                .import_proofs(&[
                    proof("proof-a", 8, "keyset-a"),
                    proof("proof-extra", 1, "keyset-a"),
                ])
                .unwrap();
            let attempt = opening_attempt("channel-a", "reservation-a", &["proof-a"]);
            wallet
                .reserve_selected_proofs_with_opening_attempt(
                    MINT,
                    "sat",
                    &["proof-a".to_string()],
                    &attempt,
                )
                .unwrap();
            let _authorized = claim_and_authorize(&wallet, "channel-a");
            wallet
                .mark_opening_attempt_finalizing("channel-a", &completed_payload("channel-a"))
                .unwrap();
            let sql = match conflict {
                "missing" => "DELETE FROM monad_client_loose_proofs WHERE proof_id = 'proof-a'",
                "available" => "UPDATE monad_client_loose_proofs SET state = 'available', reserved_by = NULL WHERE proof_id = 'proof-a'",
                "reassigned" => "UPDATE monad_client_loose_proofs SET reserved_by = 'other' WHERE proof_id = 'proof-a'",
                "extra" => "UPDATE monad_client_loose_proofs SET state = 'reserved', reserved_by = 'reservation-a' WHERE proof_id = 'proof-extra'",
                "differently-spent" => "UPDATE monad_client_loose_proofs SET state = 'spent', spent_channel_id = 'other-channel' WHERE proof_id = 'proof-a'",
                _ => unreachable!(),
            };
            wallet.conn().unwrap().execute_batch(sql).unwrap();
            assert!(
                wallet.complete_opening_attempt_exact("channel-a").is_err(),
                "conflict {conflict} was accepted"
            );
            assert_eq!(
                wallet.opening_attempt("channel-a").unwrap().unwrap().state,
                OpeningAttemptState::Finalizing
            );
        }
    }

    #[test]
    fn failed_opening_attempt_insert_rolls_back_reservation() {
        let wallet = wallet();
        wallet
            .import_proofs(&[proof("proof-a", 8, "keyset-a")])
            .unwrap();
        let attempt = NewOpeningAttempt {
            attempt_id: String::new(),
            opening_id: "opening-a".to_string(),
            predecessor_attempt_id: None,
            reservation_id: new_reservation_id(),
            receiver_pubkey: "receiver".to_string(),
            mint_url: MINT.to_string(),
            unit: "sat".to_string(),
            funding_token_target_msats: 8_000,
            expiry_timestamp: 123_456,
            prepared_open_json: "{}".to_string(),
            selected_proof_ids: vec!["proof-a".to_string()],
        };
        assert!(wallet
            .reserve_selected_proofs_with_opening_attempt(
                MINT,
                "sat",
                &["proof-a".to_string()],
                &attempt,
            )
            .is_err());
        assert_eq!(
            wallet
                .list_available_proofs(MINT, "sat", &[])
                .unwrap()
                .len(),
            1
        );
        assert!(wallet
            .proofs_for_reservation(&attempt.reservation_id)
            .unwrap()
            .is_empty());
    }

    #[test]
    fn rejected_opening_without_successor_releases_its_reservation() {
        let wallet = wallet();
        wallet
            .import_proofs(&[proof("proof-a", 8, "keyset-a")])
            .unwrap();
        let reservation_id = new_reservation_id();
        let attempt = NewOpeningAttempt {
            attempt_id: "channel-a".to_string(),
            opening_id: "opening-a".to_string(),
            predecessor_attempt_id: None,
            reservation_id: reservation_id.clone(),
            receiver_pubkey: "receiver".to_string(),
            mint_url: MINT.to_string(),
            unit: "sat".to_string(),
            funding_token_target_msats: 8_000,
            expiry_timestamp: 123_456,
            prepared_open_json: r#"{"channel_id":"channel-a"}"#.to_string(),
            selected_proof_ids: vec!["proof-a".to_string()],
        };
        wallet
            .reserve_selected_proofs_with_opening_attempt(
                MINT,
                "sat",
                &["proof-a".to_string()],
                &attempt,
            )
            .unwrap();
        let authorized = claim_and_authorize(&wallet, "channel-a");
        wallet
            .record_definitive_opening_rejection(authorized, 12_002, "inactive keyset")
            .unwrap();

        assert_eq!(
            wallet.opening_attempts_for_recovery().unwrap()[0].state,
            OpeningAttemptState::Rejected
        );
        wallet.cancel_rejected_opening_attempt("channel-a").unwrap();

        assert_eq!(
            wallet.opening_attempt("channel-a").unwrap().unwrap().state,
            OpeningAttemptState::Cancelled
        );
        assert_eq!(
            wallet
                .list_available_proofs(MINT, "sat", &[])
                .unwrap()
                .len(),
            1
        );
        assert!(wallet
            .proofs_for_reservation(&reservation_id)
            .unwrap()
            .is_empty());
    }

    #[test]
    fn prepared_opening_recovery_cancels_before_submission() {
        let wallet = wallet();
        wallet
            .import_proofs(&[proof("proof-a", 8, "keyset-a")])
            .unwrap();
        let reservation_id = new_reservation_id();
        let attempt = NewOpeningAttempt {
            attempt_id: "channel-a".to_string(),
            opening_id: "opening-a".to_string(),
            predecessor_attempt_id: None,
            reservation_id: reservation_id.clone(),
            receiver_pubkey: "receiver".to_string(),
            mint_url: MINT.to_string(),
            unit: "sat".to_string(),
            funding_token_target_msats: 8_000,
            expiry_timestamp: 123_456,
            prepared_open_json: "not needed to cancel".to_string(),
            selected_proof_ids: vec!["proof-a".to_string()],
        };
        wallet
            .reserve_selected_proofs_with_opening_attempt(
                MINT,
                "sat",
                &["proof-a".to_string()],
                &attempt,
            )
            .unwrap();

        wallet.cancel_prepared_opening_attempt("channel-a").unwrap();

        assert_eq!(
            wallet.opening_attempt("channel-a").unwrap().unwrap().state,
            OpeningAttemptState::Cancelled
        );
        assert_eq!(
            wallet
                .list_available_proofs(MINT, "sat", &[])
                .unwrap()
                .len(),
            1
        );
        assert!(wallet
            .proofs_for_reservation(&reservation_id)
            .unwrap()
            .is_empty());
    }

    #[test]
    fn cancellation_rejects_exact_id_mismatch_without_releasing_any_proof() {
        for expected_state in [OpeningAttemptState::Prepared, OpeningAttemptState::Rejected] {
            let wallet = wallet();
            wallet
                .import_proofs(&[
                    proof("proof-a", 8, "keyset-a"),
                    proof("proof-b", 1, "keyset-a"),
                ])
                .unwrap();
            wallet
                .reserve_selected_proofs_with_opening_attempt(
                    MINT,
                    "sat",
                    &["proof-a".to_string()],
                    &opening_attempt("channel-a", "reservation-a", &["proof-a"]),
                )
                .unwrap();
            if expected_state == OpeningAttemptState::Rejected {
                let authorized = claim_and_authorize(&wallet, "channel-a");
                wallet
                    .record_definitive_opening_rejection(authorized, 12_002, "rejected")
                    .unwrap();
            }
            wallet
                .conn()
                .unwrap()
                .execute(
                    "UPDATE monad_client_loose_proofs
                     SET state = 'reserved', reserved_by = 'reservation-a'
                     WHERE wallet_name = 'alice' AND proof_id = 'proof-b'",
                    [],
                )
                .unwrap();

            let result = if expected_state == OpeningAttemptState::Prepared {
                wallet.cancel_prepared_opening_attempt("channel-a")
            } else {
                wallet.cancel_rejected_opening_attempt("channel-a")
            };
            assert!(result.is_err());
            assert_eq!(
                wallet.opening_attempt("channel-a").unwrap().unwrap().state,
                expected_state
            );
            assert!(wallet
                .proofs_for_reservation("reservation-a")
                .unwrap()
                .iter()
                .all(|proof| proof.state == LooseProofState::Reserved));
        }
    }

    #[test]
    fn cancelled_claim_cannot_later_authorize() {
        let wallet = wallet();
        wallet
            .import_proofs(&[proof("proof-a", 8, "keyset-a")])
            .unwrap();
        wallet
            .reserve_selected_proofs_with_opening_attempt(
                MINT,
                "sat",
                &["proof-a".to_string()],
                &opening_attempt("channel-a", "reservation-a", &["proof-a"]),
            )
            .unwrap();
        let OpeningSubmissionClaim::Acquired(permit) = wallet
            .claim_opening_attempt_submission("channel-a")
            .unwrap()
        else {
            panic!("claim not acquired");
        };
        wallet.cancel_prepared_opening_attempt("channel-a").unwrap();

        assert!(wallet.authorize_opening_submission(permit).is_err());
        let attempt = wallet.opening_attempt("channel-a").unwrap().unwrap();
        assert_eq!(attempt.state, OpeningAttemptState::Cancelled);
        assert_eq!(attempt.latest_submitted_at, None);
        assert_eq!(
            wallet.opening_executions("channel-a").unwrap()[0].status,
            OpeningExecutionStatus::Cancelled
        );
    }

    #[test]
    fn external_spend_is_atomic_and_never_releases_proofs() {
        let wallet = wallet();
        wallet
            .import_proofs(&[proof("proof-a", 8, "keyset-a")])
            .unwrap();
        let attempt = NewOpeningAttempt {
            attempt_id: "channel-a".to_string(),
            opening_id: "opening-a".to_string(),
            predecessor_attempt_id: None,
            reservation_id: new_reservation_id(),
            receiver_pubkey: "receiver".to_string(),
            mint_url: MINT.to_string(),
            unit: "sat".to_string(),
            funding_token_target_msats: 8_000,
            expiry_timestamp: 123_456,
            prepared_open_json: "immutable prepared request".to_string(),
            selected_proof_ids: vec!["proof-a".to_string()],
        };
        wallet
            .reserve_selected_proofs_with_opening_attempt(
                MINT,
                "sat",
                &["proof-a".to_string()],
                &attempt,
            )
            .unwrap();
        let _authorized = claim_and_authorize(&wallet, &attempt.attempt_id);
        let submitted = wallet
            .opening_export_evidence(&attempt.attempt_id, OpeningAttemptState::Submitted)
            .unwrap()
            .unwrap();
        assert!(wallet
            .mark_opening_attempt_exported_if_evidence_current(
                &submitted,
                submitted.latest_submitted_at + OPENING_EXPORT_MIN_AGE_SECONDS,
            )
            .unwrap());
        let exported = wallet
            .opening_export_evidence(&attempt.attempt_id, OpeningAttemptState::Exported)
            .unwrap()
            .unwrap();
        // Fail after the journal UPDATE, proving the proof and attempt changes roll back together.
        wallet.conn().unwrap().execute_batch("CREATE TRIGGER fail_external_spend BEFORE UPDATE ON monad_client_loose_proofs WHEN NEW.state = 'spent' BEGIN SELECT RAISE(ABORT, 'injected crash'); END;").unwrap();
        assert!(wallet
            .mark_opening_attempt_externally_spent_if_evidence_current(&exported, 123_456)
            .is_err());
        assert_eq!(
            wallet
                .opening_attempt(&attempt.attempt_id)
                .unwrap()
                .unwrap()
                .state,
            OpeningAttemptState::Exported
        );
        assert_eq!(
            wallet
                .proofs_for_reservation(&attempt.reservation_id)
                .unwrap()[0]
                .state,
            LooseProofState::Reserved
        );
        wallet
            .conn()
            .unwrap()
            .execute_batch("DROP TRIGGER fail_external_spend;")
            .unwrap();
        wallet
            .mark_opening_attempt_externally_spent_if_evidence_current(&exported, 123_456)
            .unwrap();
        let record = wallet
            .opening_attempt(&attempt.attempt_id)
            .unwrap()
            .unwrap();
        assert_eq!(record.state, OpeningAttemptState::ExternallySpent);
        assert!(wallet.opening_attempts_for_recovery().unwrap().is_empty());
        let proof_state: String = wallet
            .conn()
            .unwrap()
            .query_row(
                "SELECT state FROM monad_client_loose_proofs WHERE proof_id = 'proof-a'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(proof_state, "spent");
    }

    #[test]
    fn rejected_predecessor_cannot_release_successor_reservation() {
        let wallet = wallet();
        wallet
            .import_proofs(&[proof("proof-a", 8, "keyset-a")])
            .unwrap();
        let reservation_id = new_reservation_id();
        let predecessor = NewOpeningAttempt {
            attempt_id: "channel-a".to_string(),
            opening_id: "opening-a".to_string(),
            predecessor_attempt_id: None,
            reservation_id: reservation_id.clone(),
            receiver_pubkey: "receiver".to_string(),
            mint_url: MINT.to_string(),
            unit: "sat".to_string(),
            funding_token_target_msats: 8_000,
            expiry_timestamp: 123_456,
            prepared_open_json: r#"{"channel_id":"channel-a"}"#.to_string(),
            selected_proof_ids: vec!["proof-a".to_string()],
        };
        wallet
            .reserve_selected_proofs_with_opening_attempt(
                MINT,
                "sat",
                &["proof-a".to_string()],
                &predecessor,
            )
            .unwrap();
        let authorized = claim_and_authorize(&wallet, "channel-a");
        wallet
            .record_definitive_opening_rejection(authorized, 12_002, "inactive keyset")
            .unwrap();
        let mut successor = NewOpeningAttempt {
            attempt_id: "channel-b".to_string(),
            opening_id: "wrong-opening".to_string(),
            predecessor_attempt_id: Some("channel-a".to_string()),
            reservation_id: reservation_id.clone(),
            receiver_pubkey: "receiver".to_string(),
            mint_url: MINT.to_string(),
            unit: "sat".to_string(),
            funding_token_target_msats: 8_000,
            expiry_timestamp: 123_456,
            prepared_open_json: r#"{"channel_id":"channel-b"}"#.to_string(),
            selected_proof_ids: vec!["proof-a".to_string()],
        };
        assert!(wallet
            .store_opening_attempt_for_reservation(&successor)
            .is_err());
        successor.opening_id = "opening-a".to_string();
        wallet
            .store_opening_attempt_for_reservation(&successor)
            .unwrap();

        wallet.cancel_rejected_opening_attempt("channel-a").unwrap();

        assert_eq!(
            wallet.opening_attempt("channel-a").unwrap().unwrap().state,
            OpeningAttemptState::Rejected
        );
        assert_eq!(
            wallet.opening_attempts_for_recovery().unwrap()[0].attempt_id,
            "channel-b"
        );
        assert_eq!(
            wallet.proofs_for_reservation(&reservation_id).unwrap()[0].state,
            LooseProofState::Reserved
        );
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
    fn separate_wallet_handles_only_allow_one_initial_submission_claim() {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("wallet.sqlite");
        let wallet_a = LooseProofWallet::open(&path, "alice").unwrap();
        wallet_a
            .import_proofs(&[proof("proof-a", 8, "keyset-a")])
            .unwrap();
        wallet_a
            .reserve_selected_proofs_with_opening_attempt(
                MINT,
                "sat",
                &["proof-a".to_string()],
                &opening_attempt("channel-a", "reservation-a", &["proof-a"]),
            )
            .unwrap();
        let wallet_b = LooseProofWallet::open(&path, "alice").unwrap();
        let barrier = std::sync::Arc::new(std::sync::Barrier::new(3));
        let spawn_claim = |wallet: LooseProofWallet| {
            let barrier = barrier.clone();
            std::thread::spawn(move || {
                barrier.wait();
                wallet
                    .claim_opening_attempt_submission("channel-a")
                    .unwrap()
            })
        };
        let first = spawn_claim(wallet_a.clone());
        let second = spawn_claim(wallet_b);
        barrier.wait();
        let outcomes = [first.join().unwrap(), second.join().unwrap()];
        assert_eq!(
            outcomes
                .iter()
                .filter(|outcome| matches!(outcome, OpeningSubmissionClaim::Acquired(_)))
                .count(),
            1
        );
        assert_eq!(wallet_a.opening_executions("channel-a").unwrap().len(), 1);
    }

    #[test]
    fn concurrent_replay_claims_allow_only_one_nonterminal_execution() {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("wallet.sqlite");
        let wallet_a = LooseProofWallet::open(&path, "alice").unwrap();
        wallet_a
            .import_proofs(&[proof("proof-a", 8, "keyset-a")])
            .unwrap();
        wallet_a
            .reserve_selected_proofs_with_opening_attempt(
                MINT,
                "sat",
                &["proof-a".to_string()],
                &opening_attempt("channel-a", "reservation-a", &["proof-a"]),
            )
            .unwrap();
        let authorized = claim_and_authorize(&wallet_a, "channel-a");
        wallet_a
            .finish_opening_execution(
                authorized,
                OpeningExecutionStatus::Uncertain,
                Some("timeout"),
            )
            .unwrap();
        let wallet_b = LooseProofWallet::open(&path, "alice").unwrap();
        let barrier = std::sync::Arc::new(std::sync::Barrier::new(3));
        let spawn = |wallet: LooseProofWallet| {
            let barrier = barrier.clone();
            std::thread::spawn(move || {
                barrier.wait();
                wallet.claim_opening_attempt_replay("channel-a").unwrap()
            })
        };
        let first = spawn(wallet_a.clone());
        let second = spawn(wallet_b);
        barrier.wait();
        let outcomes = [first.join().unwrap(), second.join().unwrap()];
        assert_eq!(
            outcomes
                .iter()
                .filter(|outcome| matches!(outcome, OpeningSubmissionClaim::Acquired(_)))
                .count(),
            1
        );
        assert_eq!(
            outcomes
                .iter()
                .filter(|outcome| matches!(outcome, OpeningSubmissionClaim::InProgress))
                .count(),
            1
        );
    }

    fn create_populated_obsolete_opening_journal(conn: &Connection) {
        conn.execute_batch(
            "CREATE TABLE monad_client_opening_attempts (
                attempt_id TEXT PRIMARY KEY, opening_id TEXT NOT NULL,
                predecessor_attempt_id TEXT, wallet_name TEXT NOT NULL,
                reservation_id TEXT NOT NULL, receiver_pubkey TEXT NOT NULL,
                mint_url TEXT NOT NULL, unit TEXT NOT NULL,
                input_budget_msats INTEGER NOT NULL, expiry_timestamp INTEGER NOT NULL,
                prepared_open_json TEXT NOT NULL, selected_proof_ids_json TEXT NOT NULL,
                completed_open_json TEXT, state TEXT NOT NULL, rejection_code INTEGER,
                rejection_message TEXT, latest_submitted_at INTEGER,
                abandonment_reason TEXT, abandoned_at INTEGER,
                created_at INTEGER NOT NULL, updated_at INTEGER NOT NULL,
                UNIQUE(wallet_name, opening_id, attempt_id));
             CREATE TABLE monad_client_opening_executions (
                wallet_name TEXT NOT NULL, attempt_id TEXT NOT NULL,
                execution_sequence INTEGER NOT NULL, kind TEXT NOT NULL,
                status TEXT NOT NULL, error_message TEXT, claimed_at INTEGER NOT NULL,
                authorized_at INTEGER, updated_at INTEGER NOT NULL,
                PRIMARY KEY (wallet_name, attempt_id, execution_sequence),
                FOREIGN KEY (attempt_id) REFERENCES monad_client_opening_attempts(attempt_id));
             CREATE UNIQUE INDEX idx_monad_client_opening_executions_active
                ON monad_client_opening_executions(wallet_name, attempt_id)
                WHERE status IN ('claimed', 'authorized');
             CREATE INDEX idx_monad_client_opening_attempts_recovery
                ON monad_client_opening_attempts(wallet_name, state, created_at);
             CREATE UNIQUE INDEX idx_monad_client_opening_attempts_successor
                ON monad_client_opening_attempts(wallet_name, predecessor_attempt_id)
                WHERE predecessor_attempt_id IS NOT NULL;
             CREATE UNIQUE INDEX idx_monad_client_opening_attempts_operation_successor
                ON monad_client_opening_attempts(wallet_name, opening_id)
                WHERE predecessor_attempt_id IS NOT NULL;
             CREATE UNIQUE INDEX idx_monad_client_opening_attempts_operation_root
                ON monad_client_opening_attempts(wallet_name, opening_id)
                WHERE predecessor_attempt_id IS NULL;
             CREATE TABLE monad_client_opening_journal_meta (
                singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
                schema_version INTEGER NOT NULL, authority_marker TEXT NOT NULL);
             INSERT INTO monad_client_opening_journal_meta VALUES
                (1, 1, 'exact-input-two-step-execution-authority');
             INSERT INTO monad_client_opening_attempts VALUES
                ('root', 'opening', NULL, 'alice', 'reservation', 'receiver',
                 'https://mint.invalid', 'sat', 8000, 123456, '{\"root\":true}',
                 '[\"proof-a\",\"proof-b\"]', NULL, 'rejected', 12002, 'stale',
                 100, NULL, NULL, 10, 101),
                ('successor', 'opening', 'root', 'alice', 'reservation', 'receiver',
                 'https://mint.invalid', 'sat', 8000, 123456, '{\"successor\":true}',
                 '[\"proof-a\",\"proof-b\"]', '{\"complete\":true}', 'submitted',
                 NULL, NULL, 200, NULL, NULL, 102, 201);
             INSERT INTO monad_client_opening_executions VALUES
                ('alice', 'root', 1, 'initial', 'rejected', 'stale', 90, 100, 101),
                ('alice', 'successor', 1, 'initial', 'authorized', NULL, 190, 200, 201);",
        )
        .unwrap();
    }

    #[test]
    fn populated_obsolete_opening_journal_requires_export_or_reset() {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("wallet.sqlite");
        let conn = Connection::open(&path).unwrap();
        create_populated_obsolete_opening_journal(&conn);
        drop(conn);

        let error = LooseProofWallet::open(&path, "alice").unwrap_err();
        assert!(error
            .to_string()
            .contains("export or reset the wallet database before upgrading"));
    }

    #[test]
    fn nonempty_obsolete_opening_journal_is_rejected() {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("wallet.sqlite");
        let conn = Connection::open(&path).unwrap();
        conn.execute_batch(
            "CREATE TABLE monad_client_opening_attempts (
                attempt_id TEXT PRIMARY KEY, opening_id TEXT NOT NULL,
                predecessor_attempt_id TEXT, wallet_name TEXT NOT NULL,
                reservation_id TEXT NOT NULL, receiver_pubkey TEXT NOT NULL,
                mint_url TEXT NOT NULL, unit TEXT NOT NULL,
                funding_token_target_msats INTEGER NOT NULL, expiry_timestamp INTEGER NOT NULL,
                prepared_open_json TEXT NOT NULL, completed_open_json TEXT,
                state TEXT NOT NULL, rejection_code INTEGER, rejection_message TEXT,
                created_at INTEGER NOT NULL, updated_at INTEGER NOT NULL,
                UNIQUE(wallet_name, opening_id, attempt_id));
             INSERT INTO monad_client_opening_attempts VALUES
                ('attempt', 'opening', NULL, 'alice', 'reservation', 'receiver',
                 'https://mint.invalid', 'sat', 1, 2, '{}', NULL, 'prepared',
                 NULL, NULL, 3, 3);",
        )
        .unwrap();
        drop(conn);
        let error = LooseProofWallet::open(&path, "alice").unwrap_err();
        assert!(error
            .to_string()
            .contains("export or reset the wallet database before upgrading"));
    }

    #[test]
    fn nonempty_partial_authority_schema_is_rejected_without_mutation() {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("wallet.sqlite");
        let conn = Connection::open(&path).unwrap();
        conn.execute_batch(
            "CREATE TABLE monad_client_opening_attempts (
                attempt_id TEXT PRIMARY KEY, opening_id TEXT NOT NULL,
                predecessor_attempt_id TEXT, wallet_name TEXT NOT NULL,
                reservation_id TEXT NOT NULL, receiver_pubkey TEXT NOT NULL,
                mint_url TEXT NOT NULL, unit TEXT NOT NULL,
                funding_token_target_msats INTEGER NOT NULL, expiry_timestamp INTEGER NOT NULL,
                prepared_open_json TEXT NOT NULL, selected_proof_ids_json TEXT NOT NULL,
                completed_open_json TEXT, state TEXT NOT NULL, rejection_code INTEGER,
                rejection_message TEXT, created_at INTEGER NOT NULL, updated_at INTEGER NOT NULL);
             INSERT INTO monad_client_opening_attempts VALUES
                ('attempt', 'opening', NULL, 'alice', 'reservation', 'receiver',
                 'https://mint.invalid', 'sat', 1, 2, '{}', '[\"proof-a\"]', NULL,
                 'prepared', NULL, NULL, 3, 3);",
        )
        .unwrap();
        drop(conn);

        let error = LooseProofWallet::open(&path, "alice").unwrap_err();
        assert!(error
            .to_string()
            .contains("export or reset the wallet database before upgrading"));
        let conn = Connection::open(&path).unwrap();
        let columns = conn
            .prepare("PRAGMA table_info(monad_client_opening_attempts)")
            .unwrap()
            .query_map([], |row| row.get::<_, String>(1))
            .unwrap()
            .collect::<rusqlite::Result<Vec<_>>>()
            .unwrap();
        assert!(!columns.iter().any(|column| column == "latest_submitted_at"));
        let executions_exist: bool = conn
            .query_row(
                "SELECT EXISTS(SELECT 1 FROM sqlite_master WHERE type = 'table'
                 AND name = 'monad_client_opening_executions')",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert!(!executions_exist);
    }

    #[test]
    fn empty_obsolete_opening_journal_migrates_to_authoritative_schema() {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("wallet.sqlite");
        let conn = Connection::open(&path).unwrap();
        conn.execute_batch(
            "CREATE TABLE monad_client_opening_attempts (
                attempt_id TEXT PRIMARY KEY, opening_id TEXT NOT NULL,
                predecessor_attempt_id TEXT, wallet_name TEXT NOT NULL,
                reservation_id TEXT NOT NULL, receiver_pubkey TEXT NOT NULL,
                mint_url TEXT NOT NULL, unit TEXT NOT NULL,
                funding_token_target_msats INTEGER NOT NULL, expiry_timestamp INTEGER NOT NULL,
                prepared_open_json TEXT NOT NULL, completed_open_json TEXT,
                state TEXT NOT NULL, rejection_code INTEGER, rejection_message TEXT,
                created_at INTEGER NOT NULL, updated_at INTEGER NOT NULL,
                UNIQUE(wallet_name, opening_id, attempt_id));",
        )
        .unwrap();
        drop(conn);
        let wallet = LooseProofWallet::open(&path, "alice").unwrap();
        let conn = wallet.conn().unwrap();
        let columns = conn
            .prepare("PRAGMA table_info(monad_client_opening_attempts)")
            .unwrap()
            .query_map([], |row| row.get::<_, String>(1))
            .unwrap()
            .collect::<rusqlite::Result<Vec<_>>>()
            .unwrap();
        assert!(columns
            .iter()
            .any(|column| column == "selected_proof_ids_json"));
        assert!(columns.iter().any(|column| column == "latest_submitted_at"));
        let execution_table: bool = conn
            .query_row(
                "SELECT EXISTS(SELECT 1 FROM sqlite_master WHERE name =
                        'monad_client_opening_executions')",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert!(execution_table);
        let marker: (i64, String) = conn
            .query_row(
                "SELECT schema_version, authority_marker
                 FROM monad_client_opening_journal_meta WHERE singleton = 1",
                [],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .unwrap();
        assert_eq!(marker.0, OPENING_JOURNAL_SCHEMA_VERSION);
        assert_eq!(marker.1, OPENING_JOURNAL_AUTHORITY_MARKER);
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
            ReqwestClientNetworking::new(std::time::Duration::from_secs(15))
                .expect("construct bridge HTTP networking"),
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
