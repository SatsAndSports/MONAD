//! SQLite-backed MONAD client wallet.
//!
//! Bridges `LooseProofWallet` (bearer-proof custody) with upstream
//! `cdk-spilman` Spilman channel operations, implementing `MonadWallet`.

use crate::loose_proof_wallet::{
    new_reservation_id, LooseProofRecord, LooseProofWallet, LooseProofWalletError, NewLooseProof,
    NewOpeningAttempt, OpeningAttemptRecord, OpeningAttemptState, OpeningExecutionStatus,
    OpeningSubmissionClaim, OpeningSubmissionPermit, ProofReservation,
};
use crate::proof_selection::{
    select_mixed_fee_inputs_for_post_swap_target, select_smallest_first_inputs_for_funding_target,
    ProofCandidate, ProofSelection, ProofSelectionError, SmallestFirstProofCandidate,
};
use crate::wallet::{
    msats_to_raw_units, raw_to_msats, MonadWallet, RelayPaymentOffer, WalletChannel,
    WalletChannelState, WalletError,
};
use crate::wallet_lock::{ExclusiveWalletAccess, WalletLockIdentity};
use cashu::nuts::{
    CheckStateRequest, CheckStateResponse, CurrencyUnit, Id, Proof, RestoreResponse, SecretKey,
    State, Token,
};
use cdk_spilman::{
    compute_funding_token_amount, parse_keyset_info_from_json, ClientChannelFunding,
    ClientChannelInfo, ClientChannelState, ClientKeysetCacheEntry, ClientPaymentState,
    CompletedOpenChannel, ConfigurableClientHost, EstablishedChannel, FundingSpendKind,
    MintConnection, OpenChannelError, OpenChannelFailureStage, OpenChannelResult,
    PreparedOpenChannel, PreparedSenderRefund, ReqwestClientNetworking, SelectedOutputKeyset,
    SpilmanClientBridge, SpilmanClientHost, SpilmanClientNetworking, SqliteClientStorage,
};
use rusqlite::{params, Connection, OpenFlags, OptionalExtension};
use std::collections::{BTreeMap, HashMap, HashSet};
use std::path::Path;
#[cfg(test)]
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Mutex, OnceLock};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

type ClientBridge =
    SpilmanClientBridge<ConfigurableClientHost<SqliteClientStorage>, ReqwestClientNetworking>;

const CHANNEL_EXPIRY_SECONDS: u64 = 24 * 3600;

#[cfg(feature = "funds-lifecycle-test")]
mod lifecycle_test {
    use std::io::{Read, Write};
    use std::time::Duration;

    pub fn boundary(name: &str) {
        if std::env::var("MONAD_FUNDS_BOUNDARY").ok().as_deref() != Some(name) {
            return;
        }
        let address: std::net::SocketAddr = std::env::var("MONAD_FUNDS_IPC")
            .expect("test IPC address")
            .parse()
            .expect("test IPC socket");
        assert!(address.ip().is_loopback());
        let timeout = Duration::from_secs(45);
        let mut stream =
            std::net::TcpStream::connect_timeout(&address, timeout).expect("test IPC connect");
        stream.set_read_timeout(Some(timeout)).unwrap();
        stream.set_write_timeout(Some(timeout)).unwrap();
        stream.write_all(name.as_bytes()).unwrap();
        stream.write_all(b"\n").unwrap();
        let mut ack = [0];
        stream
            .read_exact(&mut ack)
            .expect("test boundary acknowledgement");
        assert_eq!(ack, [1]);
    }

    pub fn lifetime(default: u64) -> u64 {
        std::env::var("MONAD_FUNDS_LIFETIME")
            .map(|value| {
                let seconds = value.parse::<u64>().expect("test lifetime");
                assert!((5..=60).contains(&seconds));
                seconds
            })
            .unwrap_or(default)
    }
}
const MINT_HTTP_REQUEST_TIMEOUT: Duration = Duration::from_secs(15);

pub use monad_common::mint_error::MintHttpRejection;

static ACTIVE_OPENINGS: OnceLock<Mutex<HashSet<String>>> = OnceLock::new();

struct ActiveOpeningGuard(String);

impl Drop for ActiveOpeningGuard {
    fn drop(&mut self) {
        if let Ok(mut active) = ACTIVE_OPENINGS.get_or_init(Default::default).lock() {
            active.remove(&self.0);
        }
    }
}

fn enter_active_opening(channel_id: &str) -> Result<ActiveOpeningGuard, WalletError> {
    let mut active = ACTIVE_OPENINGS
        .get_or_init(Default::default)
        .lock()
        .map_err(|_| WalletError::Backend("opening singleflight mutex poisoned".to_string()))?;
    if !active.insert(channel_id.to_string()) {
        return Err(WalletError::OpeningInProgress {
            channel_id: channel_id.to_string(),
        });
    }
    Ok(ActiveOpeningGuard(channel_id.to_string()))
}

trait OpeningRecoveryNetworking: SpilmanClientNetworking {
    // String-only upstream failures carry no definitive HTTP rejection evidence.
    fn call_opening_swap(&self, mint_url: &str, request: &str) -> anyhow::Result<String> {
        self.call_mint_swap(mint_url, request)
            .map_err(anyhow::Error::msg)
    }

    fn call_mint_check_state(
        &self,
        mint_url: &str,
        check_state_request_json: &str,
    ) -> Result<String, String>;
}

struct OpeningRecoveryHttpNetworking {
    client: reqwest::Client,
    runtime: tokio::runtime::Handle,
}

impl OpeningRecoveryHttpNetworking {
    fn new() -> Result<Self, String> {
        Ok(Self {
            client: reqwest::Client::builder()
                .timeout(MINT_HTTP_REQUEST_TIMEOUT)
                .build()
                .map_err(|e| format!("build opening recovery HTTP client: {e}"))?,
            runtime: tokio::runtime::Handle::current(),
        })
    }

    fn blocking_get(&self, url: &str) -> Result<String, String> {
        let client = self.client.clone();
        let url = url.to_string();
        tokio::task::block_in_place(|| {
            self.runtime.block_on(async {
                let response = client
                    .get(&url)
                    .send()
                    .await
                    .map_err(|e| format!("GET {url} failed: {e}"))?;
                if !response.status().is_success() {
                    let status = response.status();
                    let body = response.text().await.unwrap_or_default();
                    return Err(MintHttpRejection::from_body(status.as_u16(), &body).to_string());
                }
                response
                    .text()
                    .await
                    .map_err(|e| format!("GET {url} read body: {e}"))
            })
        })
    }

    fn blocking_post(&self, url: &str, body: &str) -> anyhow::Result<String> {
        let client = self.client.clone();
        let url = url.to_string();
        let body = body.to_string();
        tokio::task::block_in_place(|| {
            self.runtime.block_on(async {
                let response = client
                    .post(&url)
                    .header("Content-Type", "application/json")
                    .body(body)
                    .send()
                    .await?;
                if !response.status().is_success() {
                    let status = response.status();
                    let body = response.text().await.unwrap_or_default();
                    return Err(MintHttpRejection::from_body(status.as_u16(), &body).into());
                }
                response.text().await.map_err(anyhow::Error::from)
            })
        })
    }
}

impl SpilmanClientNetworking for OpeningRecoveryHttpNetworking {
    fn call_mint_swap(&self, mint_url: &str, swap_request_json: &str) -> Result<String, String> {
        self.blocking_post(&format!("{mint_url}/v1/swap"), swap_request_json)
            .map_err(|e| e.to_string())
    }

    fn call_mint_restore(
        &self,
        mint_url: &str,
        restore_request_json: &str,
    ) -> Result<String, String> {
        self.blocking_post(&format!("{mint_url}/v1/restore"), restore_request_json)
            .map_err(|e| e.to_string())
    }

    fn call_mint_keysets(&self, mint_url: &str) -> Result<String, String> {
        self.blocking_get(&format!("{mint_url}/v1/keysets"))
    }

    fn call_mint_keys(&self, mint_url: &str, keyset_id: &str) -> Result<String, String> {
        self.blocking_get(&format!("{mint_url}/v1/keys/{keyset_id}"))
    }
}

impl OpeningRecoveryNetworking for OpeningRecoveryHttpNetworking {
    fn call_opening_swap(&self, mint_url: &str, request: &str) -> anyhow::Result<String> {
        self.blocking_post(&format!("{mint_url}/v1/swap"), request)
    }

    fn call_mint_check_state(
        &self,
        mint_url: &str,
        check_state_request_json: &str,
    ) -> Result<String, String> {
        self.blocking_post(
            &format!("{mint_url}/v1/checkstate"),
            check_state_request_json,
        )
        .map_err(|e| e.to_string())
    }
}

enum OpeningRestoreOutcome {
    Completed(Box<CompletedOpenChannel>),
    FundingOutputsAbsent,
}

/// Outcomes of an exclusive startup or manual opening recovery pass.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct OpeningRecoveryReport {
    pub recovered_channel_ids: Vec<String>,
    pub cancelled_attempt_ids: Vec<String>,
    pub externally_spent_attempt_ids: Vec<String>,
    pub unresolved: Vec<UnresolvedOpening>,
}

#[derive(Debug, PartialEq, Eq)]
pub struct UnresolvedOpening {
    pub attempt_id: String,
    pub state: OpeningAttemptState,
    pub latest_submitted_at: Option<u64>,
    pub reason: String,
}

impl OpeningRecoveryReport {
    pub fn is_empty(&self) -> bool {
        self.recovered_channel_ids.is_empty()
            && self.cancelled_attempt_ids.is_empty()
            && self.externally_spent_attempt_ids.is_empty()
            && self.unresolved.is_empty()
    }
}

#[derive(Debug)]
enum OpeningRecoveryOutcome {
    Recovered(String),
    Cancelled,
    ExternallySpent,
    Unresolved,
}

/// A bearer token exported from stale ambiguous opening inputs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExportedOpeningInputsToken {
    pub mint_url: String,
    pub unit: String,
    pub amount_raw: u64,
    pub proof_count: usize,
    pub attempt_ids: Vec<String>,
    pub token: String,
}

/// Results of one stale-opening input export scan.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct OpeningInputExportReport {
    pub exports: Vec<ExportedOpeningInputsToken>,
    pub unresolved: Vec<UnresolvedOpeningExport>,
}

impl OpeningInputExportReport {
    pub fn is_empty(&self) -> bool {
        self.exports.is_empty() && self.unresolved.is_empty()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UnresolvedOpeningExport {
    pub attempt_id: String,
    pub state: OpeningAttemptState,
    pub reason: String,
}

struct OpeningExportCandidate {
    attempt_id: String,
    state: OpeningAttemptState,
    evidence: crate::loose_proof_wallet::OpeningExportEvidence,
    proofs: Vec<(String, Proof)>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ExactInputState {
    AllUnspent,
    AllSpent,
    MixedOrPending,
}

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

#[cfg(test)]
const CREATE_OPENING_RECOVERIES_SQL_FOR_TEST: &str = r#"
    CREATE TABLE monad_client_channel_opening_recoveries (
        channel_id TEXT PRIMARY KEY,
        reservation_id TEXT NOT NULL,
        receiver_pubkey TEXT NOT NULL,
        mint_url TEXT NOT NULL,
        unit TEXT NOT NULL,
        funding_token_target_msats INTEGER NOT NULL,
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
        journal_version INTEGER NOT NULL DEFAULT 2 CHECK(journal_version = 2),
        custody_db TEXT NOT NULL,
        custody_wallet TEXT NOT NULL,
        custody_sender TEXT NOT NULL,
        completed_proofs_json TEXT,
        completed_at INTEGER,
        created_at INTEGER NOT NULL,
        updated_at INTEGER NOT NULL
    );
    CREATE TABLE IF NOT EXISTS monad_client_refund_executions (
        execution_id INTEGER PRIMARY KEY,
        channel_id TEXT NOT NULL,
        prepared_json TEXT NOT NULL,
        outcome TEXT NOT NULL,
        created_at INTEGER NOT NULL
    );
    CREATE TABLE IF NOT EXISTS monad_client_refund_predecessors (
        channel_id TEXT PRIMARY KEY,
        prepared_json TEXT NOT NULL,
        rejection TEXT NOT NULL
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
    opening_scope: String,
    wallet_lock_identity: WalletLockIdentity,
    channel_db: Mutex<Connection>,
    #[cfg(test)]
    fail_next_recovered_proof_import: AtomicBool,
}

/// Read-only channel/proof inspection without sender signing material or schema writes.
pub struct ClientWalletInspection {
    loose_wallet: LooseProofWallet,
    channel_db: Mutex<Connection>,
}

impl ClientWalletInspection {
    pub fn open(
        loose_db_path: impl AsRef<Path>,
        channel_db_path: impl AsRef<Path>,
        wallet_name: &str,
    ) -> Result<Self, WalletError> {
        let channel_path = channel_db_path.as_ref();
        let channel_db =
            Connection::open_with_flags(channel_path, OpenFlags::SQLITE_OPEN_READ_ONLY).map_err(
                |e| WalletError::Backend(format!("open channel metadata read-only: {e}")),
            )?;
        channel_db
            .busy_timeout(Duration::from_secs(5))
            .map_err(|e| WalletError::Backend(format!("set channel db busy timeout: {e}")))?;
        Ok(Self {
            loose_wallet: LooseProofWallet::open_read_only(loose_db_path, wallet_name)
                .map_err(loose_proof_error)?,
            channel_db: Mutex::new(channel_db),
        })
    }

    pub fn list_available_proof_summaries(
        &self,
    ) -> Result<Vec<crate::loose_proof_wallet::LooseProofSummary>, WalletError> {
        self.loose_wallet
            .list_available_proof_summaries()
            .map_err(loose_proof_error)
    }

    pub fn list_channels(&self) -> Result<Vec<WalletChannel>, WalletError> {
        let conn = self
            .channel_db
            .lock()
            .map_err(|_| WalletError::Backend("channel db mutex poisoned".to_string()))?;
        let mut stmt = conn
            .prepare(
                "SELECT channel_id, receiver_pubkey, mint_url, unit, keyset_id,
                        capacity_msats, attached_session_id, state, expiry_timestamp
                 FROM monad_client_channels
                 ORDER BY created_at ASC",
            )
            .map_err(|e| WalletError::Backend(format!("prepare list channels: {e}")))?;
        let rows = stmt
            .query_map([], row_to_channel_meta)
            .map_err(|e| WalletError::Backend(format!("query channels: {e}")))?;
        rows.map(|row| {
            let mut meta =
                row.map_err(|e| WalletError::Backend(format!("decode channel row: {e}")))?;
            apply_channel_recovery_state(&conn, &mut meta)?;
            let upstream = checked_upstream_info(&conn, &meta.channel_id)?;
            wallet_channel_from_meta(meta, Some(upstream))
        })
        .collect()
    }
}

fn checked_upstream_info(
    conn: &Connection,
    channel_id: &str,
) -> Result<ClientChannelInfo, WalletError> {
    let row: Option<(String, Option<String>, Option<String>)> = conn
        .query_row(
            "SELECT state, funding_json, payment_json
             FROM spilman_client_channels WHERE channel_id = ?1",
            [channel_id],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )
        .optional()
        .map_err(|e| WalletError::Backend(format!("query upstream channel {channel_id}: {e}")))?;
    let (state, funding_json, payment_json) = row
        .ok_or_else(|| WalletError::Backend(format!("upstream channel {channel_id} is missing")))?;
    let state = match state.as_str() {
        "Open" => ClientChannelState::Open,
        "Closing" => ClientChannelState::Closing,
        "Closed" => ClientChannelState::Closed,
        other => {
            return Err(WalletError::Backend(format!(
                "upstream channel {channel_id} has invalid inspection state '{other}'"
            )))
        }
    };
    let funding: ClientChannelFunding =
        serde_json::from_str(funding_json.as_deref().ok_or_else(|| {
            WalletError::Backend(format!("upstream channel {channel_id} has no funding data"))
        })?)
        .map_err(|e| {
            WalletError::Backend(format!("decode upstream channel {channel_id} funding: {e}"))
        })?;
    let payment = payment_json
        .as_deref()
        .map(serde_json::from_str::<ClientPaymentState>)
        .transpose()
        .map_err(|e| {
            WalletError::Backend(format!("decode upstream channel {channel_id} payment: {e}"))
        })?;
    Ok(ClientChannelInfo {
        channel_id: channel_id.to_string(),
        capacity: funding.capacity,
        funding_token_amount: funding.funding_token_amount,
        mint_url: funding.mint_url,
        current_balance: payment.as_ref().map_or(0, |payment| payment.balance),
        payment_count: payment.map_or(0, |payment| payment.payment_count),
        state,
    })
}

fn reject_and_remove_legacy_opening_recoveries(conn: &Connection) -> Result<(), WalletError> {
    let exists: bool = conn
        .query_row(
            "SELECT EXISTS(SELECT 1 FROM sqlite_master WHERE type = 'table' AND name =
                    'monad_client_channel_opening_recoveries')",
            [],
            |row| row.get(0),
        )
        .map_err(|e| {
            WalletError::Backend(format!("inspect obsolete opening recovery table: {e}"))
        })?;
    if !exists {
        return Ok(());
    }
    let rows: i64 = conn
        .query_row(
            "SELECT COUNT(*) FROM monad_client_channel_opening_recoveries",
            [],
            |row| row.get(0),
        )
        .map_err(|e| {
            WalletError::Backend(format!("inspect obsolete opening recovery rows: {e}"))
        })?;
    if rows != 0 {
        return Err(WalletError::Backend(
            "obsolete nonempty monad_client_channel_opening_recoveries state is unsupported"
                .to_string(),
        ));
    }
    conn.execute_batch("DROP TABLE monad_client_channel_opening_recoveries")
        .map_err(|e| WalletError::Backend(format!("remove obsolete opening recovery table: {e}")))
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
    opening_id: String,
    output_keyset: SelectedOutputKeyset,
    reservation: ProofReservation,
    prepared: PreparedOpenChannel,
    requested_capacity_raw: Option<u64>,
    desired_funding_token_amount_raw: Option<u64>,
    funding_token_target_msats: u64,
    selected_input_msats: u64,
    expiry_timestamp: u64,
}

enum SubmitOpenAttemptError {
    Authority(WalletError),
    Open(OpenChannelError),
}

#[derive(Debug, Clone, Copy)]
struct ClientOpenPlan {
    requested_capacity_raw: Option<u64>,
    desired_funding_token_amount_raw: Option<u64>,
    funding_token_target_msats: u64,
    selected_input_msats: u64,
    expiry_timestamp: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum OutputKeysetSelection<T> {
    Selected(T),
    NoCompatibleActiveKeyset,
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
    Finalizing,
    Completed,
}

impl ChannelRecoveryStatus {
    fn from_db(value: &str) -> Result<Self, WalletError> {
        match value {
            "prepared" => Ok(Self::Prepared),
            "submitting" => Ok(Self::Submitting),
            "finalizing" => Ok(Self::Finalizing),
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
    /// requests a funding-token value, input fees are added on top, and upstream
    /// returns usable channel capacity after applying output fees.
    pub fn open(
        loose_wallet: LooseProofWallet,
        channel_db_path: impl AsRef<Path>,
        sender_secret_hex: &str,
    ) -> Result<Self, WalletError> {
        let path = channel_db_path.as_ref();
        let loose_db_path = loose_wallet.database_path().ok_or_else(|| {
            WalletError::Backend("in-memory loose proof wallets are unsupported here".to_string())
        })?;
        let wallet_lock_identity = WalletLockIdentity::new([loose_db_path, path]).map_err(|e| {
            WalletError::Backend(format!("normalize wallet database identity: {e}"))
        })?;
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

        let networking = ReqwestClientNetworking::new(MINT_HTTP_REQUEST_TIMEOUT)
            .map_err(|e| WalletError::Backend(format!("create bridge HTTP networking: {e}")))?;
        let bridge = SpilmanClientBridge::new(host, networking);

        let channel_db = cdk_spilman::sqlite_durability::open_wallet_database(path)
            .map_err(|e| WalletError::Backend(format!("open channel metadata database: {e}")))?;
        channel_db
            .busy_timeout(Duration::from_secs(5))
            .map_err(|e| WalletError::Backend(format!("set channel db busy timeout: {e}")))?;
        let old_schema: bool = channel_db.query_row(
            "SELECT EXISTS(SELECT 1 FROM sqlite_master WHERE name = 'monad_client_channel_recoveries') AND NOT EXISTS(SELECT 1 FROM pragma_table_info('monad_client_channel_recoveries') WHERE name = 'custody_db')",
            [], |r| r.get(0),
        ).map_err(|e| WalletError::Backend(format!("inspect refund schema: {e}")))?;
        if old_schema {
            let count: i64 = channel_db
                .query_row(
                    "SELECT COUNT(*) FROM monad_client_channel_recoveries",
                    [],
                    |r| r.get(0),
                )
                .map_err(|e| WalletError::Backend(format!("inspect legacy refunds: {e}")))?;
            if count != 0 {
                return Err(WalletError::Backend(
                    "incompatible nonempty refund journal; no automatic migration".to_string(),
                ));
            }
            channel_db
                .execute_batch("DROP TABLE monad_client_channel_recoveries")
                .map_err(|e| WalletError::Backend(format!("replace empty refund schema: {e}")))?;
        }
        channel_db
            .execute_batch(&format!(
                "{CREATE_CHANNELS_SQL};{CREATE_CHANNEL_RECOVERIES_SQL};"
            ))
            .map_err(|e| WalletError::Backend(format!("create channel metadata schema: {e}")))?;
        let incompatible: bool = channel_db.query_row("SELECT EXISTS(SELECT 1 FROM monad_client_channel_recoveries WHERE journal_version != 2)", [], |r| r.get(0))
            .map_err(|e| WalletError::Backend(format!("validate refund journal version: {e}")))?;
        if incompatible {
            return Err(WalletError::Backend(
                "incompatible refund journal version".to_string(),
            ));
        }
        reject_and_remove_legacy_opening_recoveries(&channel_db)?;
        let opening_scope = std::fs::canonicalize(path)
            .unwrap_or_else(|_| path.to_path_buf())
            .display()
            .to_string();

        Ok(Self {
            loose_wallet,
            bridge: Mutex::new(bridge),
            sender_secret,
            sender_pubkey_hex,
            opening_scope,
            wallet_lock_identity,
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
    /// Requires matching exclusive maintenance access. Each invocation submits at
    /// most once plus one exact replay per request. Only an initial, definitive
    /// inactive-output rejection may produce one immutable successor.
    /// - no row / prepared + expired + unspent: persist and submit one refund
    /// - submitting: restore before clock/state checks; retry only after valid absence
    /// - finalizing: finish local proof import and closure without mint IO
    /// - spent with a submitted refund: final exact restore before discovery
    /// - relay-close or unknown witness: checked deterministic sender discovery
    pub async fn recover_channel_funds<M>(
        &self,
        access: &ExclusiveWalletAccess<'_>,
        channel_id: &str,
        mint_connection: &M,
    ) -> Result<ChannelFundRecoveryResult, WalletError>
    where
        M: MintConnection + ?Sized,
    {
        if !access.authorizes(&self.wallet_lock_identity) {
            return Err(WalletError::Backend(
                "exclusive wallet maintenance access belongs to a different wallet".to_string(),
            ));
        }
        let _singleflight =
            enter_active_opening(&format!("refund:{}:{channel_id}", self.opening_scope))?;
        self.validate_recovery_custody(channel_id)?;
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
        if established.params.sender_pubkey != self.sender_secret.public_key() {
            return Err(WalletError::Backend(
                "channel recovery sender mismatch".to_string(),
            ));
        }
        let recovery = self.load_channel_recovery_row(channel_id)?;
        if recovery
            .as_ref()
            .is_some_and(|r| r.status == ChannelRecoveryStatus::Finalizing)
        {
            let (kind, json): (String, String) = self.conn()?.query_row(
                "SELECT kind, completed_proofs_json FROM monad_client_channel_recoveries WHERE channel_id = ?1",
                [channel_id], |r| Ok((r.get(0)?, r.get(1)?)),
            ).map_err(|e| WalletError::Backend(format!("read finalizing recovery: {e}")))?;
            let proofs = serde_json::from_str(&json)
                .map_err(|e| WalletError::Backend(format!("decode completed proofs: {e}")))?;
            return self.complete_channel_recovery(
                channel_id,
                &funding,
                &kind,
                proofs,
                kind == "post_expiry_refund",
            );
        }
        let mut prepared = recovery
            .as_ref()
            .map(|r| self.prepared_refund_from_recovery_row(r))
            .transpose()?
            .flatten();
        if let Some(p) = &prepared {
            p.verify(&established, &self.sender_secret)
                .map_err(|e| WalletError::Backend(format!("verify refund: {e}")))?;
        }
        let mut restore_first = recovery
            .as_ref()
            .is_some_and(|r| r.status == ChannelRecoveryStatus::Submitting);
        let mut executions = 0;
        let mut refreshed_rejection = false;
        loop {
            if restore_first {
                let p = prepared.as_ref().ok_or_else(|| {
                    WalletError::Backend("submitted refund missing immutable request".to_string())
                })?;
                match established
                    .restore_prepared_sender_refund_outputs(p, &self.sender_secret, mint_connection)
                    .await
                {
                    Ok(Some(proofs)) => {
                        return self.complete_channel_recovery(
                            channel_id,
                            &funding,
                            "post_expiry_refund",
                            proofs,
                            true,
                        )
                    }
                    Ok(None) => {}
                    Err(_) => return Ok(ChannelFundRecoveryResult::RecoveryRetryLater {
                        channel_id: channel_id.to_string(),
                        reason:
                            "refund restore failed or returned invalid outputs; request retained"
                                .to_string(),
                    }),
                }
            }
            let proof_state = established
                .check_funding_token_state(mint_connection)
                .await
                .map_err(|_| {
                    WalletError::Backend(
                        "check funding token state failed; refund journal retained".to_string(),
                    )
                })?;
            if proof_state.state == State::Pending {
                return Ok(ChannelFundRecoveryResult::FundingPending);
            }
            if proof_state.state == State::Spent {
                // The original swap may complete between an empty restore and
                // checkstate. One final exact restore closes that observation gap.
                if restore_first {
                    match established
                        .restore_prepared_sender_refund_outputs(
                            prepared.as_ref().unwrap(),
                            &self.sender_secret,
                            mint_connection,
                        )
                        .await
                    {
                        Ok(Some(proofs)) => {
                            return self.complete_channel_recovery(
                                channel_id,
                                &funding,
                                "post_expiry_refund",
                                proofs,
                                true,
                            )
                        }
                        Ok(None) => {}
                        Err(_) => {
                            return Ok(ChannelFundRecoveryResult::RecoveryRetryLater {
                                channel_id: channel_id.to_string(),
                                reason:
                                    "final exact refund restore failed or returned invalid outputs"
                                        .to_string(),
                            })
                        }
                    }
                }
                // Witness cardinality is advisory: a valid close may include
                // irrelevant signatures. Discovery still verifies every output.
                let kind = EstablishedChannel::classify_funding_spend_witness(&proof_state);
                let result = if kind != FundingSpendKind::PostExpiryRefund {
                    self.try_relay_close_recovery(channel_id, &funding, mint_connection)
                        .await?
                } else {
                    ChannelFundRecoveryResult::UnknownSpent
                };
                return Ok(
                    if restore_first && result == ChannelFundRecoveryResult::UnknownSpent {
                        ChannelFundRecoveryResult::RecoveryRetryLater {
                        channel_id: channel_id.to_string(),
                        reason: "spent funding with unresolved submitted refund; immutable request retained".to_string(),
                    }
                    } else {
                        result
                    },
                );
            }
            let now = Self::now_seconds()?;
            if now <= established.params.expiry_timestamp {
                return Ok(ChannelFundRecoveryResult::NotExpiredOrSpentYet {
                    expiry_timestamp: established.params.expiry_timestamp,
                    now,
                });
            }
            if executions >= 2 {
                return Ok(ChannelFundRecoveryResult::RecoveryRetryLater {
                    channel_id: channel_id.to_string(),
                    reason: "refund remains unresolved after bounded exact replay".to_string(),
                });
            }
            if prepared.is_none() {
                prepared = Some(self.prepare_and_persist_refund_recovery(
                    channel_id,
                    &established,
                    now,
                )?);
            }
            // Resume a durable initial rejection even if the previous invocation
            // died during refresh. No ambiguous execution may precede this grant.
            if !refreshed_rejection && self.refund_has_initial_rejection(channel_id)? {
                refreshed_rejection = true;
                let p = prepared.as_ref().unwrap();
                let output = self.select_refund_output_keyset(&established, true)?;
                if output.keyset_id != p.output_keyset.keyset_id {
                    let successor = established
                        .prepare_sender_refund_after_expiry(
                            self.sender_secret.clone(),
                            now,
                            output,
                            rand::random(),
                        )
                        .map_err(|e| {
                            WalletError::Backend(format!("prepare successor refund: {e}"))
                        })?;
                    self.persist_refund_successor(channel_id, p, &successor)?;
                    prepared = Some(successor);
                    executions = 0;
                }
            }
            let p = prepared.as_ref().unwrap();
            let execution = self.record_refund_execution(channel_id, p)?;
            executions += 1;
            match established
                .submit_prepared_sender_refund(p, &self.sender_secret, now, mint_connection)
                .await
            {
                Ok(proofs) => {
                    return self.complete_channel_recovery(
                        channel_id,
                        &funding,
                        "post_expiry_refund",
                        proofs,
                        true,
                    )
                }
                Err(error) => {
                    // Only a typed, direct initial rejection may authorize new outputs.
                    // Pending execution records are uncertainty, including process death.
                    if error
                        .downcast_ref::<MintHttpRejection>()
                        .is_some_and(|e| e.inactive_output_keyset())
                        && self.refund_can_replace(channel_id, execution)?
                    {
                        self.conn()?.execute("UPDATE monad_client_refund_executions SET outcome = 'inactive_output_keyset' WHERE execution_id = ?1", [execution])
                            .map_err(|e| WalletError::Backend(format!("record refund rejection: {e}")))?;
                    }
                    restore_first = true;
                }
            }
        }
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
        let established = EstablishedChannel::from_client_channel_funding(funding)
            .map_err(|_| WalletError::Backend("invalid persisted channel funding".to_string()))?;
        let mut result = Err(anyhow::anyhow!("sender discovery not attempted"));
        for refresh in [false, true] {
            let keysets = {
                let bridge = self
                    .bridge
                    .lock()
                    .map_err(|_| WalletError::Backend("bridge mutex poisoned".to_string()))?;
                if refresh
                    && bridge
                        .refresh_keysets_response(&established.params.mint)
                        .is_err()
                {
                    break;
                }
                let mut keys = vec![established.params.keyset_info.clone()];
                for (_, entry) in bridge
                    .cached_keysets_for_unit(&established.params.mint, &established.params.unit)
                {
                    keys.push(parse_keyset_info_from_json(&entry.info_json).map_err(|_| {
                        WalletError::Backend("invalid sender discovery keys".to_string())
                    })?);
                }
                keys
            };
            result = cdk_spilman::SpilmanChannelSender::new(
                self.sender_secret.clone(),
                established.clone(),
            )
            .restore_sender_proofs_with_keysets(mint_connection, &keysets)
            .await;
            if !result
                .as_ref()
                .is_err_and(|e| e.is::<cdk_spilman::SenderCloseKeysetMissing>())
            {
                break;
            }
        }
        match result {
            Ok(proofs) if !proofs.is_empty() => {
                self.complete_channel_recovery(channel_id, funding, "relay_close", proofs, false)
            }
            Ok(_) => Ok(ChannelFundRecoveryResult::UnknownSpent),
            Err(_) => Ok(ChannelFundRecoveryResult::RecoveryRetryLater {
                channel_id: channel_id.to_string(),
                reason: "sender close discovery failed or returned invalid outputs".to_string(),
            }),
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
        let target_capacity_raw = msats_to_raw_units(&offer.unit, target_capacity_msats)
            .map_err(|error| preflight_offer_error(offer, error))?;
        if target_capacity_raw == 0 {
            return Err(WalletError::OfferMismatch(
                "target capacity must be greater than zero".to_string(),
            ));
        }
        self.ensure_offer_keysets_cached(offer)?;
        #[cfg(not(feature = "funds-lifecycle-test"))]
        let expiry_timestamp = Self::now_seconds()? + CHANNEL_EXPIRY_SECONDS;
        #[cfg(feature = "funds-lifecycle-test")]
        let expiry_timestamp =
            Self::now_seconds()? + lifecycle_test::lifetime(CHANNEL_EXPIRY_SECONDS);
        // Target-capacity provisioning computes the exact post-swap channel
        // capacity we want, selects loose proofs that can fund it after input
        // fees, and then asks the mint to swap those proofs into channel funding
        // outputs.  The output keyset info comes from the client's local mint
        // keyset cache. Selection prefers relay-listed IDs and then falls back to
        // any active keyset whose format was negotiated. The client cache is
        // refreshed once before concluding no compatible output exists. If a
        // selected cached keyset becomes
        // stale before swap submission, the retry helper centralizes the safe
        // mint-rejection policy: refresh keysets, reselect, skip retry if refresh
        // still selects the same id, otherwise reprepare and submit once.
        let output_keyset = self.select_output_keyset_refreshing_client_first(offer)?;
        let attempt = self.prepare_target_capacity_attempt(
            offer,
            target_capacity_raw,
            output_keyset,
            expiry_timestamp,
        )?;
        self.execute_open_attempt(offer, attempt, true)
    }

    /// Recover channel openings whose funding swap may have reached the mint.
    ///
    /// Ambiguous failures leave loose proofs reserved and an upstream
    /// `OpeningFromSwap` row behind. This method first uses NUT-09 restore. If a
    /// valid response has no funding or change outputs, submitted attempts remain
    /// reserved. Exported attempts whose inputs are all spent receive a final exact
    /// restore check before being marked externally spent. This method never submits
    /// swaps. Callers must hold exclusive wallet-manager maintenance access for the
    /// entire pass.
    pub fn recover_pending_openings(
        &self,
        access: &ExclusiveWalletAccess<'_>,
    ) -> Result<OpeningRecoveryReport, WalletError> {
        if !access.authorizes(&self.wallet_lock_identity) {
            return Err(WalletError::Backend(
                "exclusive wallet maintenance access belongs to a different wallet".to_string(),
            ));
        }
        self.recover_pending_openings_inner()
    }

    fn recover_pending_openings_inner(&self) -> Result<OpeningRecoveryReport, WalletError> {
        let networking = OpeningRecoveryHttpNetworking::new().map_err(WalletError::Backend)?;
        self.recover_pending_openings_with_networking(&networking)
    }

    fn recover_pending_openings_with_networking<N: OpeningRecoveryNetworking>(
        &self,
        networking: &N,
    ) -> Result<OpeningRecoveryReport, WalletError> {
        let attempts = self
            .loose_wallet
            .opening_attempts_for_recovery()
            .map_err(loose_proof_error)?;
        let mut report = OpeningRecoveryReport::default();
        for attempt in attempts {
            match self.recover_journaled_opening(&attempt, networking) {
                Ok(OpeningRecoveryOutcome::Recovered(channel_id)) => {
                    report.recovered_channel_ids.push(channel_id)
                }
                Ok(OpeningRecoveryOutcome::Cancelled) => report
                    .cancelled_attempt_ids
                    .push(attempt.attempt_id.clone()),
                Ok(OpeningRecoveryOutcome::ExternallySpent) => report
                    .externally_spent_attempt_ids
                    .push(attempt.attempt_id.clone()),
                Ok(OpeningRecoveryOutcome::Unresolved) => {
                    report.unresolved.push(UnresolvedOpening {
                        attempt_id: attempt.attempt_id.clone(),
                        state: attempt.state,
                        latest_submitted_at: attempt.latest_submitted_at,
                        reason: "funding restore empty; opening attempt remains reserved"
                            .to_string(),
                    })
                }
                Err(error) => {
                    // Recovery is best effort per attempt. Keep its reservation and
                    // journal state so one unavailable mint does not discard funds.
                    tracing::warn!(
                        attempt_id = %attempt.attempt_id,
                        "channel opening remains pending recovery: {error}"
                    );
                    report.unresolved.push(UnresolvedOpening {
                        attempt_id: attempt.attempt_id.clone(),
                        state: attempt.state,
                        latest_submitted_at: attempt.latest_submitted_at,
                        reason: error.to_string(),
                    });
                }
            }
        }

        Ok(report)
    }

    fn recover_journaled_opening<N: OpeningRecoveryNetworking>(
        &self,
        attempt: &OpeningAttemptRecord,
        networking: &N,
    ) -> Result<OpeningRecoveryOutcome, WalletError> {
        if attempt.state == OpeningAttemptState::Rejected {
            self.loose_wallet
                .cancel_rejected_opening_attempt(&attempt.attempt_id)
                .map_err(loose_proof_error)?;
            return Ok(OpeningRecoveryOutcome::Cancelled);
        }
        if attempt.state == OpeningAttemptState::Prepared {
            self.loose_wallet
                .cancel_prepared_opening_attempt(&attempt.attempt_id)
                .map_err(loose_proof_error)?;
            return Ok(OpeningRecoveryOutcome::Cancelled);
        }
        let prepared: PreparedOpenChannel = serde_json::from_str(&attempt.prepared_open_json)
            .map_err(|e| WalletError::Backend(format!("decode opening attempt: {e}")))?;
        let reserved_proofs = self
            .loose_wallet
            .proofs_for_reservation(&attempt.reservation_id)
            .map_err(loose_proof_error)?;
        verify_prepared_inputs_match_selected_proofs(
            &prepared,
            &attempt.selected_proof_ids,
            &reserved_proofs,
        )?;
        let completed = if attempt.state == OpeningAttemptState::Finalizing {
            let json = attempt.completed_open_json.as_deref().ok_or_else(|| {
                WalletError::Backend(format!(
                    "finalizing opening attempt {} has no completion payload",
                    attempt.attempt_id
                ))
            })?;
            serde_json::from_str::<CompletedOpenChannel>(json).map_err(|e| {
                WalletError::Backend(format!("decode completed opening attempt: {e}"))
            })?
        } else {
            {
                let bridge = self
                    .bridge
                    .lock()
                    .map_err(|_| WalletError::Backend("bridge mutex poisoned".to_string()))?;
                if bridge.get_channel_funding(&prepared.channel_id).is_none() {
                    bridge.mark_prepared_open_saved(&prepared).map_err(|e| {
                        open_channel_error(e, &attempt.unit, attempt.funding_token_target_msats)
                    })?;
                }
            }
            match self
                .restore_journaled_opening(&prepared, networking)
                .map_err(|error| {
                    open_channel_error(error, &attempt.unit, attempt.funding_token_target_msats)
                })? {
                OpeningRestoreOutcome::Completed(completed) => {
                    let json = serde_json::to_string(&completed).map_err(|e| {
                        WalletError::Backend(format!("serialize recovered opening: {e}"))
                    })?;
                    self.loose_wallet
                        .mark_opening_attempt_finalizing(&attempt.attempt_id, &json)
                        .map_err(loose_proof_error)?;
                    *completed
                }
                OpeningRestoreOutcome::FundingOutputsAbsent => {
                    if attempt.state != OpeningAttemptState::Exported {
                        return Ok(OpeningRecoveryOutcome::Unresolved);
                    }
                    if prepared_input_state(&prepared, networking).map_err(|error| {
                        open_channel_error(error, &attempt.unit, attempt.funding_token_target_msats)
                    })? != ExactInputState::AllSpent
                    {
                        return Ok(OpeningRecoveryOutcome::Unresolved);
                    }
                    // Check the exact original outputs once more after the spent
                    // observation before recording the external-spend outcome.
                    match self
                        .restore_journaled_opening(&prepared, networking)
                        .map_err(|error| {
                            open_channel_error(
                                error,
                                &attempt.unit,
                                attempt.funding_token_target_msats,
                            )
                        })? {
                        OpeningRestoreOutcome::Completed(completed) => {
                            let json = serde_json::to_string(&completed).map_err(|e| {
                                WalletError::Backend(format!("serialize recovered opening: {e}"))
                            })?;
                            self.loose_wallet
                                .mark_opening_attempt_finalizing(&attempt.attempt_id, &json)
                                .map_err(loose_proof_error)?;
                            *completed
                        }
                        OpeningRestoreOutcome::FundingOutputsAbsent => {
                            let Some(evidence) = self
                                .loose_wallet
                                .opening_export_evidence(
                                    &attempt.attempt_id,
                                    OpeningAttemptState::Exported,
                                )
                                .map_err(loose_proof_error)?
                            else {
                                return Ok(OpeningRecoveryOutcome::Unresolved);
                            };
                            if self
                                .loose_wallet
                                .mark_opening_attempt_externally_spent_if_evidence_current(
                                    &evidence,
                                    Self::now_seconds()?,
                                )
                                .map_err(loose_proof_error)?
                            {
                                return Ok(OpeningRecoveryOutcome::ExternallySpent);
                            }
                            return Ok(OpeningRecoveryOutcome::Unresolved);
                        }
                    }
                }
            }
        };

        // If finalization was interrupted before upstream storage advanced, replay it.
        {
            let bridge = self
                .bridge
                .lock()
                .map_err(|_| WalletError::Backend("bridge mutex poisoned".to_string()))?;
            if bridge.get_channel_funding(&completed.channel_id).is_none() {
                bridge.mark_prepared_open_saved(&prepared).map_err(|e| {
                    open_channel_error(e, &attempt.unit, attempt.funding_token_target_msats)
                })?;
                bridge.mark_completed_open(&completed).map_err(|e| {
                    open_channel_error(e, &attempt.unit, attempt.funding_token_target_msats)
                })?;
            }
        }
        self.finish_open_channel(
            completed.result,
            &ProofReservation {
                reservation_id: attempt.reservation_id.clone(),
                proofs: self
                    .loose_wallet
                    .proofs_for_reservation(&attempt.reservation_id)
                    .map_err(loose_proof_error)?,
                total_amount_raw: 0,
            },
            attempt.expiry_timestamp,
        )?;
        Ok(OpeningRecoveryOutcome::Recovered(completed.channel_id))
    }

    /// Export bearer tokens for ambiguous opening inputs that have remained
    /// unspent for at least one hour. Exported inputs remain reserved until the
    /// opening recovers or later evidence records them as externally spent.
    pub fn export_stale_opening_inputs(
        &self,
        access: &ExclusiveWalletAccess<'_>,
    ) -> Result<OpeningInputExportReport, WalletError> {
        if !access.authorizes(&self.wallet_lock_identity) {
            return Err(WalletError::Backend(
                "exclusive wallet maintenance access belongs to a different wallet".to_string(),
            ));
        }
        let networking = OpeningRecoveryHttpNetworking::new().map_err(WalletError::Backend)?;
        self.export_stale_opening_inputs_with_networking(&networking)
    }

    fn export_stale_opening_inputs_with_networking<N: OpeningRecoveryNetworking>(
        &self,
        networking: &N,
    ) -> Result<OpeningInputExportReport, WalletError> {
        let now = Self::now_seconds()?;
        let mut report = OpeningInputExportReport::default();
        let mut grouped = BTreeMap::new();
        for attempt in self
            .loose_wallet
            .opening_attempts_for_recovery()
            .map_err(loose_proof_error)?
        {
            if !matches!(
                attempt.state,
                OpeningAttemptState::Submitted | OpeningAttemptState::Exported
            ) {
                continue;
            }
            grouped
                .entry((attempt.mint_url.clone(), attempt.unit.clone()))
                .or_insert_with(Vec::new)
                .push(attempt);
        }
        for ((mint_url, unit), attempts) in grouped {
            let mut candidates = Vec::new();
            for attempt in attempts {
                let evidence = match self
                    .loose_wallet
                    .opening_export_evidence(&attempt.attempt_id, attempt.state)
                {
                    Ok(Some(evidence)) => evidence,
                    Ok(None) => {
                        report.unresolved.push(UnresolvedOpeningExport {
                            attempt_id: attempt.attempt_id,
                            state: attempt.state,
                            reason: "opening export evidence changed during the scan".to_string(),
                        });
                        continue;
                    }
                    Err(error) => {
                        report.unresolved.push(UnresolvedOpeningExport {
                            attempt_id: attempt.attempt_id,
                            state: attempt.state,
                            reason: error.to_string(),
                        });
                        continue;
                    }
                };
                if attempt.state == OpeningAttemptState::Submitted && !evidence.is_aged_at(now) {
                    continue;
                }
                let prepared: PreparedOpenChannel =
                    match serde_json::from_str(&attempt.prepared_open_json) {
                        Ok(prepared) => prepared,
                        Err(error) => {
                            report.unresolved.push(UnresolvedOpeningExport {
                                attempt_id: attempt.attempt_id,
                                state: attempt.state,
                                reason: format!("decode opening attempt: {error}"),
                            });
                            continue;
                        }
                    };
                let reserved_proofs = match self
                    .loose_wallet
                    .proofs_for_reservation(&attempt.reservation_id)
                {
                    Ok(proofs) => proofs,
                    Err(error) => {
                        report.unresolved.push(UnresolvedOpeningExport {
                            attempt_id: attempt.attempt_id,
                            state: attempt.state,
                            reason: error.to_string(),
                        });
                        continue;
                    }
                };
                if let Err(error) = verify_prepared_inputs_match_selected_proofs(
                    &prepared,
                    &attempt.selected_proof_ids,
                    &reserved_proofs,
                ) {
                    report.unresolved.push(UnresolvedOpeningExport {
                        attempt_id: attempt.attempt_id,
                        state: attempt.state,
                        reason: error.to_string(),
                    });
                    continue;
                }
                match self.restore_journaled_opening(&prepared, networking) {
                    Ok(OpeningRestoreOutcome::FundingOutputsAbsent) => {}
                    Ok(OpeningRestoreOutcome::Completed(_)) => {
                        report.unresolved.push(UnresolvedOpeningExport {
                            attempt_id: attempt.attempt_id,
                            state: attempt.state,
                            reason: "opening completion is restorable; run recover-openings"
                                .to_string(),
                        });
                        continue;
                    }
                    Err(error) => {
                        report.unresolved.push(UnresolvedOpeningExport {
                            attempt_id: attempt.attempt_id,
                            state: attempt.state,
                            reason: open_channel_error(
                                error,
                                &attempt.unit,
                                attempt.funding_token_target_msats,
                            )
                            .to_string(),
                        });
                        continue;
                    }
                }
                match prepared_input_state(&prepared, networking) {
                    Ok(ExactInputState::AllUnspent) => {}
                    Ok(ExactInputState::AllSpent) => {
                        report.unresolved.push(UnresolvedOpeningExport {
                            attempt_id: attempt.attempt_id,
                            state: attempt.state,
                            reason: "exact inputs are spent; run recover-openings".to_string(),
                        });
                        continue;
                    }
                    Ok(ExactInputState::MixedOrPending) => {
                        report.unresolved.push(UnresolvedOpeningExport {
                            attempt_id: attempt.attempt_id,
                            state: attempt.state,
                            reason: "exact inputs are not all unspent".to_string(),
                        });
                        continue;
                    }
                    Err(error) => {
                        report.unresolved.push(UnresolvedOpeningExport {
                            attempt_id: attempt.attempt_id,
                            state: attempt.state,
                            reason: open_channel_error(
                                error,
                                &attempt.unit,
                                attempt.funding_token_target_msats,
                            )
                            .to_string(),
                        });
                        continue;
                    }
                }
                let proofs = match reserved_proofs
                    .iter()
                    .map(|proof| {
                        serde_json::from_str::<Proof>(&proof.proof_json)
                            .map(|parsed| (proof.proof_id.clone(), parsed))
                    })
                    .collect::<Result<Vec<_>, _>>()
                {
                    Ok(proofs) => proofs,
                    Err(error) => {
                        report.unresolved.push(UnresolvedOpeningExport {
                            attempt_id: attempt.attempt_id,
                            state: attempt.state,
                            reason: format!("decode reserved proof for export: {error}"),
                        });
                        continue;
                    }
                };
                candidates.push(OpeningExportCandidate {
                    attempt_id: attempt.attempt_id,
                    state: attempt.state,
                    evidence,
                    proofs,
                });
            }
            if candidates.is_empty() {
                continue;
            }
            candidates.sort_by(|left, right| left.attempt_id.cmp(&right.attempt_id));
            let attempt_ids = candidates
                .iter()
                .map(|candidate| candidate.attempt_id.clone())
                .collect::<Vec<_>>();
            let mut proofs = candidates
                .iter_mut()
                .flat_map(|candidate| std::mem::take(&mut candidate.proofs))
                .collect::<Vec<_>>();
            proofs.sort_by(|left, right| left.0.cmp(&right.0));
            let proof_count = proofs.len();
            let amount_raw = proofs.iter().try_fold(0u64, |total, (_, proof)| {
                total.checked_add(proof.amount.to_u64())
            });
            let token = amount_raw
                .ok_or_else(|| "exported proof amount overflow".to_string())
                .and_then(|amount_raw| {
                    let currency = unit
                        .parse::<CurrencyUnit>()
                        .map_err(|error| format!("parse exported token unit '{unit}': {error}"))?;
                    let mint = mint_url.parse().map_err(|error| {
                        format!("parse exported token mint '{mint_url}': {error}")
                    })?;
                    let mut token = Token::new(
                        mint,
                        proofs.into_iter().map(|(_, proof)| proof).collect(),
                        None,
                        currency,
                    );
                    if let Token::TokenV4(token) = &mut token {
                        token
                            .token
                            .sort_by(|left, right| left.keyset_id.cmp(&right.keyset_id));
                    }
                    Ok((amount_raw, token.to_string()))
                });
            let (amount_raw, token) =
                match token {
                    Ok(token) => token,
                    Err(reason) => {
                        report
                            .unresolved
                            .extend(candidates.into_iter().map(|candidate| {
                                UnresolvedOpeningExport {
                                    attempt_id: candidate.attempt_id,
                                    state: candidate.state,
                                    reason: reason.clone(),
                                }
                            }));
                        continue;
                    }
                };
            let evidences = candidates
                .iter()
                .map(|candidate| candidate.evidence.clone())
                .collect::<Vec<_>>();
            match self
                .loose_wallet
                .mark_opening_attempts_exported_if_evidence_current(&evidences, now)
            {
                Ok(true) => report.exports.push(ExportedOpeningInputsToken {
                    mint_url,
                    unit,
                    amount_raw,
                    proof_count,
                    attempt_ids,
                    token,
                }),
                Ok(false) => report
                    .unresolved
                    .extend(candidates.into_iter().map(|candidate| {
                        UnresolvedOpeningExport {
                            attempt_id: candidate.attempt_id,
                            state: candidate.state,
                            reason: "opening export evidence changed before the durable transition"
                                .to_string(),
                        }
                    })),
                Err(error) => report
                    .unresolved
                    .extend(
                        candidates
                            .into_iter()
                            .map(|candidate| UnresolvedOpeningExport {
                                attempt_id: candidate.attempt_id,
                                state: candidate.state,
                                reason: error.to_string(),
                            }),
                    ),
            }
        }
        report
            .unresolved
            .sort_by(|left, right| left.attempt_id.cmp(&right.attempt_id));
        Ok(report)
    }

    fn recover_or_replay_submitted_opening<N: OpeningRecoveryNetworking>(
        &self,
        prepared: &PreparedOpenChannel,
        networking: &N,
    ) -> Result<Option<OpenChannelResult>, OpenChannelError> {
        match self.restore_journaled_opening(prepared, networking)? {
            OpeningRestoreOutcome::Completed(completed) => self
                .complete_live_restored_opening(prepared, *completed)
                .map(Some),
            OpeningRestoreOutcome::FundingOutputsAbsent => {
                if !prepared_inputs_are_all_unspent(prepared, networking)? {
                    return Ok(None);
                }
                let permit = match self
                    .loose_wallet
                    .claim_opening_attempt_replay(&prepared.channel_id)
                    .map_err(|e| {
                        open_channel_stage_error(
                            OpenChannelFailureStage::SwapSubmitted,
                            Some(prepared.channel_id.clone()),
                            format!("claim immutable opening replay: {e}"),
                        )
                    })? {
                    OpeningSubmissionClaim::Acquired(permit) => permit,
                    OpeningSubmissionClaim::NotReplayable { state } => {
                        return Err(open_channel_stage_error(
                            OpenChannelFailureStage::SwapSubmitted,
                            Some(prepared.channel_id.clone()),
                            format!("opening replay authority unavailable in state {state:?}"),
                        ));
                    }
                    OpeningSubmissionClaim::NotFound => {
                        return Err(open_channel_stage_error(
                            OpenChannelFailureStage::SwapSubmitted,
                            Some(prepared.channel_id.clone()),
                            "opening replay authority is missing".to_string(),
                        ));
                    }
                    OpeningSubmissionClaim::InProgress => {
                        return Err(open_channel_stage_error(
                            OpenChannelFailureStage::SwapSubmitted,
                            Some(prepared.channel_id.clone()),
                            "opening replay is already in progress".to_string(),
                        ));
                    }
                };
                match self.submit_prepared_open(prepared.clone(), permit, networking) {
                    Ok(result) => Ok(Some(result)),
                    Err(_replay_error) => {
                        match self.restore_journaled_opening(prepared, networking)? {
                            OpeningRestoreOutcome::Completed(completed) => self
                                .complete_live_restored_opening(prepared, *completed)
                                .map(Some),
                            OpeningRestoreOutcome::FundingOutputsAbsent => Ok(None),
                        }
                    }
                }
            }
        }
    }

    fn complete_live_restored_opening(
        &self,
        prepared: &PreparedOpenChannel,
        completed: CompletedOpenChannel,
    ) -> Result<OpenChannelResult, OpenChannelError> {
        let completed_json = serde_json::to_string(&completed).map_err(|e| {
            open_channel_stage_error(
                OpenChannelFailureStage::FundingProofsReceived,
                Some(prepared.channel_id.clone()),
                format!("serialize recovered opening: {e}"),
            )
        })?;
        self.loose_wallet
            .mark_opening_attempt_finalizing(&prepared.channel_id, &completed_json)
            .map_err(|e| {
                open_channel_stage_error(
                    OpenChannelFailureStage::FundingProofsReceived,
                    Some(prepared.channel_id.clone()),
                    format!("persist recovered opening: {e}"),
                )
            })?;
        let bridge = self.bridge.lock().map_err(|_| {
            open_channel_stage_error(
                OpenChannelFailureStage::MarkOpen,
                Some(prepared.channel_id.clone()),
                "bridge mutex poisoned".to_string(),
            )
        })?;
        bridge.mark_completed_open(&completed)?;
        Ok(completed.result)
    }

    fn restore_journaled_opening<N: OpeningRecoveryNetworking>(
        &self,
        prepared: &PreparedOpenChannel,
        networking: &N,
    ) -> Result<OpeningRestoreOutcome, OpenChannelError> {
        let recovery = {
            let bridge = self.bridge.lock().map_err(|_| {
                open_channel_stage_error(
                    OpenChannelFailureStage::RestoreVerification,
                    Some(prepared.channel_id.clone()),
                    "bridge mutex poisoned".to_string(),
                )
            })?;
            bridge.prepare_open_channel_recovery(&prepared.channel_id)?
        };
        let funding_response = networking
            .call_mint_restore(&recovery.mint_url, &recovery.funding_restore_request_json)
            .map_err(|e| {
                open_channel_stage_error(
                    OpenChannelFailureStage::RestoreVerification,
                    Some(prepared.channel_id.clone()),
                    e,
                )
            })?;
        if restore_response_is_absent(&funding_response).map_err(|e| {
            open_channel_stage_error(
                OpenChannelFailureStage::RestoreVerification,
                Some(prepared.channel_id.clone()),
                format!("validate funding restore response: {e}"),
            )
        })? {
            if let Some(request) = recovery.change_restore_request_json.as_deref() {
                let response = networking
                    .call_mint_restore(&recovery.mint_url, request)
                    .map_err(|e| {
                        open_channel_stage_error(
                            OpenChannelFailureStage::RestoreVerification,
                            Some(prepared.channel_id.clone()),
                            e,
                        )
                    })?;
                if !restore_response_is_absent(&response).map_err(|e| {
                    open_channel_stage_error(
                        OpenChannelFailureStage::RestoreVerification,
                        Some(prepared.channel_id.clone()),
                        format!("validate change restore response: {e}"),
                    )
                })? {
                    return Err(open_channel_stage_error(
                        OpenChannelFailureStage::RestoreVerification,
                        Some(prepared.channel_id.clone()),
                        "funding outputs were absent but change outputs were present".to_string(),
                    ));
                }
            }
            return Ok(OpeningRestoreOutcome::FundingOutputsAbsent);
        };
        let change_response = match recovery.change_restore_request_json.as_deref() {
            None => None,
            Some(request) => {
                let response = networking
                    .call_mint_restore(&recovery.mint_url, request)
                    .map_err(|e| {
                        open_channel_stage_error(
                            OpenChannelFailureStage::RestoreVerification,
                            Some(prepared.channel_id.clone()),
                            e,
                        )
                    })?;
                if restore_response_is_absent(&response).map_err(|e| {
                    open_channel_stage_error(
                        OpenChannelFailureStage::RestoreVerification,
                        Some(prepared.channel_id.clone()),
                        format!("validate change restore response: {e}"),
                    )
                })? {
                    return Err(open_channel_stage_error(
                        OpenChannelFailureStage::RestoreVerification,
                        Some(prepared.channel_id.clone()),
                        "funding outputs were restored but change outputs were absent".to_string(),
                    ));
                }
                Some(response)
            }
        };
        let completed = {
            let bridge = self.bridge.lock().map_err(|_| {
                open_channel_stage_error(
                    OpenChannelFailureStage::RestoreVerification,
                    Some(prepared.channel_id.clone()),
                    "bridge mutex poisoned".to_string(),
                )
            })?;
            bridge.complete_prepared_open_recovery(
                &recovery,
                &funding_response,
                change_response.as_deref(),
            )?
        };
        Ok(OpeningRestoreOutcome::Completed(Box::new(
            CompletedOpenChannel {
                channel_id: completed.channel_id,
                funding_proofs_json: completed.funding_proofs_json,
                change_proofs_json: completed.change_proofs_json,
                result: completed.result,
            },
        )))
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

    fn recovery_custody(&self) -> Result<(&str, &str, &str), WalletError> {
        let db = self
            .loose_wallet
            .database_path()
            .and_then(Path::to_str)
            .ok_or_else(|| {
                WalletError::Backend("custody database path is not valid UTF-8".to_string())
            })?;
        Ok((db, self.loose_wallet.wallet_name(), &self.sender_pubkey_hex))
    }

    fn validate_recovery_custody(&self, channel_id: &str) -> Result<(), WalletError> {
        let stored: Option<(String, String, String)> = self.conn()?.query_row(
            "SELECT custody_db, custody_wallet, custody_sender FROM monad_client_channel_recoveries WHERE channel_id = ?1",
            [channel_id], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
        ).optional().map_err(|e| WalletError::Backend(format!("read recovery custody: {e}")))?;
        if let Some((db, wallet, sender)) = stored {
            if (db.as_str(), wallet.as_str(), sender.as_str()) != self.recovery_custody()? {
                return Err(WalletError::Backend(
                    "channel recovery custody destination mismatch".to_string(),
                ));
            }
        }
        Ok(())
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
            .prepare_sender_refund_after_expiry(
                self.sender_secret.clone(),
                now,
                self.select_refund_output_keyset(established, false)?,
                rand::random(),
            )
            .map_err(|e| WalletError::Backend(format!("prepare sender refund: {e}")))?;
        self.persist_refund_recovery_prepared(channel_id, &prepared)?;
        Ok(prepared)
    }

    fn select_refund_output_keyset(
        &self,
        established: &EstablishedChannel,
        refresh: bool,
    ) -> Result<cdk_spilman::KeysetInfo, WalletError> {
        let bridge = self
            .bridge
            .lock()
            .map_err(|_| WalletError::Backend("bridge mutex poisoned".to_string()))?;
        let mint = &established.params.mint;
        for pass in 0..2 {
            if (refresh && pass == 0) || (!refresh && pass == 1) {
                bridge.refresh_keysets_response(mint).map_err(|_| {
                    WalletError::Backend("refresh refund output keysets failed".to_string())
                })?;
            }
            let mut entries = bridge.cached_keysets_for_unit(mint, &established.params.unit);
            entries.sort_by_key(|(id, _)| id.to_string());
            if let Some((_, entry)) = entries.into_iter().find(|(_, entry)| entry.active) {
                return parse_keyset_info_from_json(&entry.info_json).map_err(WalletError::Backend);
            }
            if refresh {
                break;
            }
        }
        Err(WalletError::Backend(
            "no active same-unit refund output keyset".to_string(),
        ))
    }

    fn record_refund_execution(
        &self,
        channel_id: &str,
        prepared: &PreparedSenderRefund,
    ) -> Result<i64, WalletError> {
        let json = prepared
            .to_json()
            .map_err(|e| WalletError::Backend(e.to_string()))?;
        let mut conn = self.conn()?;
        let tx = conn
            .transaction()
            .map_err(|e| WalletError::Backend(e.to_string()))?;
        let now = to_i64(Self::now_seconds()?)?;
        let changed = tx.execute("UPDATE monad_client_channel_recoveries SET status = 'submitting', updated_at = ?3 WHERE channel_id = ?1 AND prepared_refund_json = ?2 AND status IN ('prepared', 'submitting')", params![channel_id, json, now])
            .map_err(|e| WalletError::Backend(e.to_string()))?;
        if changed != 1 {
            return Err(WalletError::Backend(
                "refund execution phase conflict".to_string(),
            ));
        }
        tx.execute("INSERT INTO monad_client_refund_executions(channel_id, prepared_json, outcome, created_at) VALUES (?1, ?2, 'uncertain', ?3)", params![channel_id, json, now])
            .map_err(|e| WalletError::Backend(e.to_string()))?;
        let id = tx.last_insert_rowid();
        tx.commit()
            .map_err(|e| WalletError::Backend(e.to_string()))?;
        Ok(id)
    }

    fn refund_can_replace(&self, channel_id: &str, execution: i64) -> Result<bool, WalletError> {
        self.conn()?.query_row(
            "SELECT NOT EXISTS(SELECT 1 FROM monad_client_refund_executions WHERE channel_id = ?1 AND execution_id != ?2) AND NOT EXISTS(SELECT 1 FROM monad_client_refund_predecessors WHERE channel_id = ?1)",
            params![channel_id, execution], |r| r.get(0),
        ).map_err(|e| WalletError::Backend(e.to_string()))
    }

    fn refund_has_initial_rejection(&self, channel_id: &str) -> Result<bool, WalletError> {
        self.conn()?.query_row(
            "SELECT (SELECT COUNT(*) FROM monad_client_refund_executions WHERE channel_id = ?1) = 1 AND EXISTS(SELECT 1 FROM monad_client_refund_executions WHERE channel_id = ?1 AND outcome = 'inactive_output_keyset') AND NOT EXISTS(SELECT 1 FROM monad_client_refund_predecessors WHERE channel_id = ?1)",
            [channel_id], |r| r.get(0),
        ).map_err(|e| WalletError::Backend(e.to_string()))
    }

    fn persist_refund_successor(
        &self,
        channel_id: &str,
        old: &PreparedSenderRefund,
        new: &PreparedSenderRefund,
    ) -> Result<(), WalletError> {
        if old.output_keyset.keyset_id == new.output_keyset.keyset_id {
            return Err(WalletError::Backend(
                "refund successor requires a different output keyset".to_string(),
            ));
        }
        let old = old
            .to_json()
            .map_err(|e| WalletError::Backend(e.to_string()))?;
        let new = new
            .to_json()
            .map_err(|e| WalletError::Backend(e.to_string()))?;
        let mut conn = self.conn()?;
        let tx = conn
            .transaction()
            .map_err(|e| WalletError::Backend(e.to_string()))?;
        let authorized: bool = tx.query_row(
            "SELECT (SELECT COUNT(*) FROM monad_client_refund_executions WHERE channel_id = ?1) = 1 AND EXISTS(SELECT 1 FROM monad_client_refund_executions WHERE channel_id = ?1 AND prepared_json = ?2 AND outcome = 'inactive_output_keyset')",
            params![channel_id, old], |r| r.get(0),
        ).map_err(|e| WalletError::Backend(e.to_string()))?;
        if !authorized {
            return Err(WalletError::Backend(
                "refund successor lacks definitive initial rejection".to_string(),
            ));
        }
        tx.execute(
            "INSERT INTO monad_client_refund_predecessors VALUES (?1, ?2, '12002')",
            params![channel_id, old],
        )
        .map_err(|e| WalletError::Backend(e.to_string()))?;
        let changed = tx.execute("UPDATE monad_client_channel_recoveries SET prepared_refund_json = ?3, status = 'prepared', updated_at = ?4 WHERE channel_id = ?1 AND prepared_refund_json = ?2 AND status = 'submitting'", params![channel_id, old, new, to_i64(Self::now_seconds()?)?])
            .map_err(|e| WalletError::Backend(e.to_string()))?;
        if changed != 1 {
            return Err(WalletError::Backend(
                "refund successor phase conflict".to_string(),
            ));
        }
        tx.commit().map_err(|e| WalletError::Backend(e.to_string()))
    }

    fn persist_refund_recovery_prepared(
        &self,
        channel_id: &str,
        prepared: &PreparedSenderRefund,
    ) -> Result<(), WalletError> {
        self.validate_recovery_custody(channel_id)?;
        let (db, wallet, sender) = self.recovery_custody()?;
        let now = Self::now_seconds()?;
        let prepared_json = prepared
            .to_json()
            .map_err(|e| WalletError::Backend(format!("encode prepared refund: {e}")))?;
        let conn = self.conn()?;
        conn.execute(
            "INSERT INTO monad_client_channel_recoveries
             (channel_id, kind, status, recovered_amount_raw, recovered_proof_count, prepared_refund_json, created_at, updated_at, custody_db, custody_wallet, custody_sender)
             VALUES (?1, 'post_expiry_refund', 'prepared', NULL, NULL, ?2, ?3, ?3, ?4, ?5, ?6)
              ON CONFLICT(channel_id) DO NOTHING",
            params![channel_id, prepared_json, to_i64(now)?, db, wallet, sender],
        )
        .map_err(|e| WalletError::Backend(format!("insert channel recovery: {e}")))?;
        let stored: String = conn.query_row("SELECT prepared_refund_json FROM monad_client_channel_recoveries WHERE channel_id = ?1", [channel_id], |r| r.get(0))
            .map_err(|e| WalletError::Backend(e.to_string()))?;
        if stored != prepared_json {
            return Err(WalletError::Backend(
                "immutable refund request conflict".to_string(),
            ));
        }
        Ok(())
    }

    #[cfg(test)]
    fn mark_refund_recovery_submitting(&self, channel_id: &str) -> Result<(), WalletError> {
        let row = self.load_channel_recovery_row(channel_id)?.unwrap();
        let prepared = self.prepared_refund_from_recovery_row(&row)?.unwrap();
        self.record_refund_execution(channel_id, &prepared)
            .map(|_| ())
    }

    fn complete_channel_recovery(
        &self,
        channel_id: &str,
        funding: &ClientChannelFunding,
        kind: &str,
        proofs: Vec<Proof>,
        full_refund: bool,
    ) -> Result<ChannelFundRecoveryResult, WalletError> {
        self.validate_recovery_custody(channel_id)?;
        let (db, wallet, sender) = self.recovery_custody()?;
        let json =
            serde_json::to_string(&proofs).map_err(|e| WalletError::Backend(e.to_string()))?;
        let now = to_i64(Self::now_seconds()?)?;
        {
            let conn = self.conn()?;
            conn.execute("INSERT INTO monad_client_channel_recoveries(channel_id, kind, status, completed_proofs_json, created_at, updated_at, custody_db, custody_wallet, custody_sender) VALUES (?1, ?2, 'finalizing', ?3, ?4, ?4, ?5, ?6, ?7) ON CONFLICT(channel_id) DO UPDATE SET kind = excluded.kind, status = 'finalizing', completed_proofs_json = excluded.completed_proofs_json WHERE monad_client_channel_recoveries.status IN ('prepared', 'submitting') AND monad_client_channel_recoveries.completed_proofs_json IS NULL", params![channel_id, kind, json, now, db, wallet, sender])
                .map_err(|e| WalletError::Backend(format!("persist verified recovery proofs: {e}")))?;
            let stored: (String, String) = conn.query_row("SELECT kind, completed_proofs_json FROM monad_client_channel_recoveries WHERE channel_id = ?1 AND status = 'finalizing'", [channel_id], |r| Ok((r.get(0)?, r.get(1)?)))
                .map_err(|e| WalletError::Backend(format!("check finalization: {e}")))?;
            if stored != (kind.to_string(), json) {
                return Err(WalletError::Backend(
                    "immutable completed proofs conflict".to_string(),
                ));
            }
        }
        #[cfg(feature = "funds-lifecycle-test")]
        lifecycle_test::boundary("refund-finalizing");
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
        #[cfg(feature = "funds-lifecycle-test")]
        lifecycle_test::boundary("refund-import");
        {
            let bridge = self
                .bridge
                .lock()
                .map_err(|_| WalletError::Backend("bridge mutex poisoned".to_string()))?;
            let info = bridge
                .get_channel_info(channel_id)
                .ok_or(WalletError::NotFound)?;
            if info.state != ClientChannelState::Closed {
                bridge.close_channel(channel_id).map_err(|e| {
                    WalletError::Backend(format!("mark upstream channel closed: {e}"))
                })?;
            }
        }
        #[cfg(feature = "funds-lifecycle-test")]
        lifecycle_test::boundary("refund-upstream");
        self.mark_channel_metadata_closed(channel_id)?;
        #[cfg(feature = "funds-lifecycle-test")]
        lifecycle_test::boundary("refund-metadata");
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
        let changed = conn
            .execute(
                "UPDATE monad_client_channel_recoveries SET
                status = 'completed',
                recovered_amount_raw = ?3,
                recovered_proof_count = ?4,
                completed_at = ?5,
                updated_at = ?5
             WHERE channel_id = ?1 AND kind = ?2 AND status = 'finalizing'
                AND completed_proofs_json IS NOT NULL",
                params![
                    channel_id,
                    kind,
                    to_i64(recovered_amount_raw)?,
                    to_i64(recovered_proof_count as u64)?,
                    to_i64(now)?,
                ],
            )
            .map_err(|e| WalletError::Backend(format!("mark channel recovery completed: {e}")))?;
        if changed != 1 {
            return Err(WalletError::Backend(
                "refund completion phase conflict".to_string(),
            ));
        }
        Ok(())
    }

    fn store_open_channel_metadata(
        &self,
        open_result: &OpenChannelResult,
        reservation_id: &str,
        expiry_timestamp: u64,
    ) -> Result<(), WalletError> {
        // Store the actual upstream capacity, not the funding-token target.
        let capacity_msats = raw_to_msats(&open_result.unit, open_result.capacity)
            .map_err(|e| WalletError::Backend(format!("convert capacity to msats: {e}")))?;
        let now = Self::now_seconds()?;
        let conn = self.conn()?;
        let capacity_msats = to_i64(capacity_msats)?;
        let expiry_timestamp = to_i64(expiry_timestamp)?;
        let inserted = conn
            .execute(
                "INSERT INTO monad_client_channels
             (channel_id, receiver_pubkey, mint_url, unit, keyset_id,
              capacity_msats, attached_session_id, state, reservation_id,
              expiry_timestamp, created_at, updated_at)
              VALUES (?1, ?2, ?3, ?4, ?5, ?6, NULL, ?7, ?8, ?9, ?10, ?10)
              ON CONFLICT(channel_id) DO NOTHING",
                params![
                    open_result.channel_id,
                    open_result.receiver_pubkey_hex,
                    open_result.mint_url,
                    open_result.unit,
                    open_result.keyset_id,
                    capacity_msats,
                    channel_state_str(WalletChannelState::Open),
                    reservation_id,
                    expiry_timestamp,
                    to_i64(now)?,
                ],
            )
            .map_err(|e| WalletError::Backend(format!("insert channel metadata: {e}")))?;
        if inserted == 0 {
            let existing = conn
                .query_row(
                    "SELECT receiver_pubkey, mint_url, unit, keyset_id, capacity_msats,
                            reservation_id, expiry_timestamp
                     FROM monad_client_channels WHERE channel_id = ?1",
                    params![open_result.channel_id],
                    |row| {
                        Ok((
                            row.get::<_, String>(0)?,
                            row.get::<_, String>(1)?,
                            row.get::<_, String>(2)?,
                            row.get::<_, String>(3)?,
                            row.get::<_, i64>(4)?,
                            row.get::<_, String>(5)?,
                            row.get::<_, i64>(6)?,
                        ))
                    },
                )
                .map_err(|e| WalletError::Backend(format!("verify channel metadata: {e}")))?;
            let expected = (
                open_result.receiver_pubkey_hex.clone(),
                open_result.mint_url.clone(),
                open_result.unit.clone(),
                open_result.keyset_id.clone(),
                capacity_msats,
                reservation_id.to_string(),
                expiry_timestamp,
            );
            if existing != expected {
                return Err(WalletError::Backend(format!(
                    "existing channel metadata conflicts with recovered opening {}",
                    open_result.channel_id
                )));
            }
        }
        Ok(())
    }

    fn now_seconds() -> Result<u64, WalletError> {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .map_err(|e| WalletError::Backend(format!("system time before unix epoch: {e}")))
    }

    fn submit_open_attempt_with_networking<N: OpeningRecoveryNetworking>(
        &self,
        attempt: &ClientOpenAttempt,
        networking: &N,
    ) -> Result<OpenChannelResult, SubmitOpenAttemptError> {
        let claim = self
            .loose_wallet
            .claim_opening_attempt_submission(&attempt.prepared.channel_id)
            .map_err(|e| {
                SubmitOpenAttemptError::Authority(WalletError::Backend(format!(
                    "claim opening submission authority: {e}"
                )))
            })?;
        let permit = match claim {
            OpeningSubmissionClaim::Acquired(permit) => permit,
            OpeningSubmissionClaim::NotReplayable { state } => {
                let error = match state {
                    OpeningAttemptState::Completed => WalletError::AlreadyOpen {
                        channel_id: attempt.prepared.channel_id.clone(),
                    },
                    OpeningAttemptState::Prepared
                    | OpeningAttemptState::Submitted
                    | OpeningAttemptState::Finalizing => WalletError::OpeningInProgress {
                        channel_id: attempt.prepared.channel_id.clone(),
                    },
                    _ => WalletError::Conflict {
                        channel_id: attempt.prepared.channel_id.clone(),
                    },
                };
                return Err(SubmitOpenAttemptError::Authority(error));
            }
            OpeningSubmissionClaim::NotFound => {
                return Err(SubmitOpenAttemptError::Authority(WalletError::Backend(
                    "opening submission authority is missing".to_string(),
                )));
            }
            OpeningSubmissionClaim::InProgress => {
                return Err(SubmitOpenAttemptError::Authority(WalletError::Backend(
                    "opening submission is already in progress".to_string(),
                )));
            }
        };
        self.submit_prepared_open(attempt.prepared.clone(), permit, networking)
            .map_err(SubmitOpenAttemptError::Open)
    }

    fn prepare_open_attempt(
        &self,
        offer: &RelayPaymentOffer,
        output_keyset: SelectedOutputKeyset,
        reservation: ProofReservation,
        plan: ClientOpenPlan,
        classify_preflight_as_offer_unavailable: bool,
    ) -> Result<ClientOpenAttempt, WalletError> {
        // Only preparation failures before the atomic reservation/journal boundary
        // can safely make this offer unavailable. Later failures may need recovery.
        let preflight_error = |error: WalletError| {
            if classify_preflight_as_offer_unavailable {
                WalletError::ProvisioningOfferUnavailable {
                    mint_url: offer.mint_url.clone(),
                    unit: offer.unit.clone(),
                    reason: error.to_string(),
                }
            } else {
                error
            }
        };
        let input_proofs_json =
            proofs_json_from_reservation(&reservation).map_err(&preflight_error)?;

        let networking = OpeningRecoveryHttpNetworking::new()
            .map_err(WalletError::Backend)
            .map_err(&preflight_error)?;
        let input_keyset_lookup = {
            let bridge = self
                .bridge
                .lock()
                .map_err(|_| WalletError::Backend("bridge mutex poisoned".to_string()))
                .map_err(&preflight_error)?;
            proof_input_keysets_from_cache(&bridge, &offer.mint_url, &offer.unit, &reservation)
                .map_err(|e| open_channel_error(e, &offer.unit, plan.selected_input_msats))
                .map_err(&preflight_error)?
        };
        let input_keysets_json =
            proof_input_keysets_json(input_keyset_lookup, &offer.mint_url, &networking)
                .map_err(|e| open_channel_error(e, &offer.unit, plan.selected_input_msats))
                .map_err(&preflight_error)?;

        let prepared = {
            let bridge = self
                .bridge
                .lock()
                .map_err(|_| WalletError::Backend("bridge mutex poisoned".to_string()))
                .map_err(&preflight_error)?;
            bridge
                .prepare_open_channel_from_proofs_with_input_keysets(
                    &offer.mint_url,
                    &offer.unit,
                    &input_proofs_json,
                    &input_keysets_json,
                    &offer.receiver_pubkey,
                    &self.sender_pubkey_hex,
                    plan.expiry_timestamp,
                    &output_keyset.info_json,
                    0,
                    plan.requested_capacity_raw,
                    plan.desired_funding_token_amount_raw,
                )
                .map_err(|e| open_channel_error(e, &offer.unit, plan.selected_input_msats))
                .map_err(&preflight_error)?
        };
        let prepared_open_json = serde_json::to_string(&prepared)
            .map_err(|e| WalletError::Backend(format!("serialize opening attempt: {e}")))
            .map_err(&preflight_error)?;
        let selected_proof_ids = reservation
            .proofs
            .iter()
            .map(|proof| proof.proof_id.clone())
            .collect::<Vec<_>>();
        verify_prepared_inputs_match_selected_proofs(
            &prepared,
            &selected_proof_ids,
            &reservation.proofs,
        )
        .map_err(&preflight_error)?;
        let journal = NewOpeningAttempt {
            attempt_id: prepared.channel_id.clone(),
            opening_id: prepared.channel_id.clone(),
            predecessor_attempt_id: None,
            reservation_id: reservation.reservation_id.clone(),
            receiver_pubkey: offer.receiver_pubkey.clone(),
            mint_url: offer.mint_url.clone(),
            unit: offer.unit.clone(),
            funding_token_target_msats: plan.funding_token_target_msats,
            expiry_timestamp: plan.expiry_timestamp,
            prepared_open_json,
            selected_proof_ids,
        };
        let proof_ids = reservation
            .proofs
            .iter()
            .map(|proof| proof.proof_id.clone())
            .collect::<Vec<_>>();
        let reservation = self
            .loose_wallet
            .reserve_selected_proofs_with_opening_attempt(
                &offer.mint_url,
                &offer.unit,
                &proof_ids,
                &journal,
            )
            .map_err(loose_proof_error)?;
        let save_result = self
            .bridge
            .lock()
            .map_err(|_| WalletError::Backend("bridge mutex poisoned".to_string()))
            .and_then(|bridge| {
                bridge
                    .mark_prepared_open_saved(&prepared)
                    .map_err(|e| open_channel_error(e, &offer.unit, plan.selected_input_msats))
            });
        if let Err(error) = save_result {
            let _ = self
                .loose_wallet
                .cancel_prepared_opening_attempt(&prepared.channel_id);
            return Err(error);
        }
        Ok(ClientOpenAttempt {
            opening_id: prepared.channel_id.clone(),
            output_keyset,
            reservation,
            prepared,
            requested_capacity_raw: plan.requested_capacity_raw,
            desired_funding_token_amount_raw: plan.desired_funding_token_amount_raw,
            funding_token_target_msats: plan.funding_token_target_msats,
            selected_input_msats: plan.selected_input_msats,
            expiry_timestamp: plan.expiry_timestamp,
        })
    }

    fn submit_prepared_open<N: OpeningRecoveryNetworking>(
        &self,
        prepared: PreparedOpenChannel,
        permit: OpeningSubmissionPermit,
        networking: &N,
    ) -> Result<OpenChannelResult, OpenChannelError> {
        let authority_check = (|| {
            if permit.attempt_id() != prepared.channel_id {
                return Err(open_channel_stage_error(
                    OpenChannelFailureStage::SwapSubmitted,
                    Some(prepared.channel_id.clone()),
                    "submission permit does not match prepared opening".to_string(),
                ));
            }
            let journal = self
                .loose_wallet
                .opening_attempt(permit.attempt_id())
                .map_err(|e| {
                    open_channel_stage_error(
                        OpenChannelFailureStage::SwapSubmitted,
                        Some(prepared.channel_id.clone()),
                        format!("load authoritative opening journal: {e}"),
                    )
                })?
                .ok_or_else(|| {
                    open_channel_stage_error(
                        OpenChannelFailureStage::SwapSubmitted,
                        Some(prepared.channel_id.clone()),
                        "authoritative opening journal is missing".to_string(),
                    )
                })?;
            let prepared_json = serde_json::to_string(&prepared).map_err(|e| {
                open_channel_stage_error(
                    OpenChannelFailureStage::SwapSubmitted,
                    Some(prepared.channel_id.clone()),
                    format!("serialize prepared opening for authority check: {e}"),
                )
            })?;
            if prepared_json != journal.prepared_open_json {
                return Err(open_channel_stage_error(
                    OpenChannelFailureStage::SwapSubmitted,
                    Some(prepared.channel_id.clone()),
                    "prepared opening differs from the authoritative journal".to_string(),
                ));
            }
            let reserved_proofs = self
                .loose_wallet
                .proofs_for_reservation(&journal.reservation_id)
                .map_err(|e| {
                    open_channel_stage_error(
                        OpenChannelFailureStage::SwapSubmitted,
                        Some(prepared.channel_id.clone()),
                        format!("load exact reserved opening proofs: {e}"),
                    )
                })?;
            verify_prepared_inputs_match_selected_proofs(
                &prepared,
                &journal.selected_proof_ids,
                &reserved_proofs,
            )
            .map_err(|e| {
                open_channel_stage_error(
                    OpenChannelFailureStage::SwapSubmitted,
                    Some(prepared.channel_id.clone()),
                    e.to_string(),
                )
            })?;
            Ok(())
        })();
        if let Err(error) = authority_check {
            self.loose_wallet
                .cancel_opening_submission_claim(permit)
                .map_err(|cancel_error| {
                    open_channel_stage_error(
                        OpenChannelFailureStage::BeforeOpeningSaved,
                        Some(prepared.channel_id.clone()),
                        format!(
                            "release unsubmitted opening claim after preflight failure: {cancel_error}; original error: {error}"
                        ),
                    )
                })?;
            return Err(error);
        }
        let authorized = self
            .loose_wallet
            .authorize_opening_submission(permit)
            .map_err(|e| {
                open_channel_stage_error(
                    OpenChannelFailureStage::BeforeOpeningSaved,
                    Some(prepared.channel_id.clone()),
                    format!("authorize opening immediately before submission: {e}"),
                )
            })?;
        let swap_response_json = match networking
            .call_opening_swap(&prepared.mint_url, &prepared.swap_request_json)
        {
            Ok(response) => {
                self.loose_wallet
                    .finish_opening_execution(
                        authorized,
                        OpeningExecutionStatus::ResponseReceived,
                        None,
                    )
                    .map_err(|e| {
                        open_channel_stage_error(
                            OpenChannelFailureStage::SwapSubmitted,
                            Some(prepared.channel_id.clone()),
                            format!("persist opening execution response: {e}"),
                        )
                    })?;
                response
            }
            Err(error) => {
                let definitive = error
                    .downcast_ref::<MintHttpRejection>()
                    .is_some_and(MintHttpRejection::inactive_output_keyset);
                let message = error.to_string();
                let attempt_rejected = if definitive {
                    self.loose_wallet
                        .record_definitive_opening_rejection(authorized, 12_002, &message)
                } else {
                    self.loose_wallet
                        .finish_opening_execution(
                            authorized,
                            OpeningExecutionStatus::Uncertain,
                            Some(&message),
                        )
                        .map(|_| false)
                }
                .map_err(|e| {
                    open_channel_stage_error(
                        OpenChannelFailureStage::SwapSubmitted,
                        Some(prepared.channel_id.clone()),
                        format!("persist opening execution failure: {e}; mint error: {message}"),
                    )
                })?;
                if attempt_rejected {
                    return Err(self
                        .mark_prepared_open_rejected(&prepared, message)
                        .unwrap_or_else(|error| error));
                }
                return Err(open_channel_stage_error(
                    OpenChannelFailureStage::SwapSubmitted,
                    Some(prepared.channel_id.clone()),
                    message,
                ));
            }
        };

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

        // Verify restore deterministically recreates the funding proofs before
        // moving upstream storage out of OpeningFromSwap.
        self.verify_prepared_open_restore(&prepared, &completed, networking)?;

        let completed_json = serde_json::to_string(&completed).map_err(|e| {
            open_channel_stage_error(
                OpenChannelFailureStage::FundingProofsReceived,
                Some(prepared.channel_id.clone()),
                format!("serialize completed opening: {e}"),
            )
        })?;
        if self
            .loose_wallet
            .opening_attempt(&prepared.channel_id)
            .map_err(|e| {
                open_channel_stage_error(
                    OpenChannelFailureStage::FundingProofsReceived,
                    Some(prepared.channel_id.clone()),
                    format!("query opening attempt: {e}"),
                )
            })?
            .is_some()
        {
            self.loose_wallet
                .mark_opening_attempt_finalizing(&prepared.channel_id, &completed_json)
                .map_err(|e| {
                    open_channel_stage_error(
                        OpenChannelFailureStage::FundingProofsReceived,
                        Some(prepared.channel_id.clone()),
                        format!("persist completed opening: {e}"),
                    )
                })?;
        }

        #[cfg(feature = "funds-lifecycle-test")]
        lifecycle_test::boundary("opening-finalizing");
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

        #[cfg(feature = "funds-lifecycle-test")]
        lifecycle_test::boundary("opening-upstream");
        Ok(completed.result)
    }

    fn mark_prepared_open_rejected(
        &self,
        prepared: &PreparedOpenChannel,
        message: String,
    ) -> Result<OpenChannelError, OpenChannelError> {
        let fallback = OpenChannelError {
            stage: OpenChannelFailureStage::MintRejected,
            channel_id: Some(prepared.channel_id.clone()),
            input_may_be_spent: false,
            message: message.clone(),
        };
        let Ok(bridge) = self.bridge.lock() else {
            tracing::warn!(
                channel_id = %prepared.channel_id,
                "opening rejection was journaled but upstream bridge mutex is poisoned"
            );
            return Ok(fallback);
        };
        match bridge.mark_prepared_open_rejected(prepared, message) {
            Ok(error) => Ok(error),
            Err(error) => {
                tracing::warn!(
                    channel_id = %prepared.channel_id,
                    "opening rejection was journaled but upstream rejection bookkeeping failed: {error}"
                );
                Ok(fallback)
            }
        }
    }

    fn verify_prepared_open_restore<N: SpilmanClientNetworking>(
        &self,
        prepared: &PreparedOpenChannel,
        completed: &CompletedOpenChannel,
        networking: &N,
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
        #[cfg(feature = "funds-lifecycle-test")]
        lifecycle_test::boundary("opening-change");
        self.store_open_channel_metadata(
            &open_result,
            &reservation.reservation_id,
            expiry_timestamp,
        )?;
        #[cfg(feature = "funds-lifecycle-test")]
        lifecycle_test::boundary("opening-metadata");
        self.loose_wallet
            .complete_opening_attempt_exact(&open_result.channel_id)
            .map_err(loose_proof_error)?;
        Ok(open_result.channel_id)
    }

    #[cfg(test)]
    fn submit_reserved_channel(
        &self,
        offer: &RelayPaymentOffer,
        output_keyset_info_json: &str,
        reservation: &ProofReservation,
        requested_capacity_raw: Option<u64>,
        desired_funding_token_amount_raw: Option<u64>,
        expiry_timestamp: u64,
    ) -> Result<OpenChannelResult, OpenChannelError> {
        let input_proofs_json = proofs_json_from_reservation(reservation).map_err(|e| {
            open_channel_stage_error(
                OpenChannelFailureStage::BeforeOpeningSaved,
                None,
                e.to_string(),
            )
        })?;
        let networking = OpeningRecoveryHttpNetworking::new().map_err(|error| {
            open_channel_stage_error(OpenChannelFailureStage::BeforeOpeningSaved, None, error)
        })?;
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
        let proof_ids = reservation
            .proofs
            .iter()
            .map(|proof| proof.proof_id.clone())
            .collect::<Vec<_>>();
        self.loose_wallet
            .release_reservation(&reservation.reservation_id)
            .map_err(|e| {
                open_channel_stage_error(
                    OpenChannelFailureStage::BeforeOpeningSaved,
                    Some(prepared.channel_id.clone()),
                    e.to_string(),
                )
            })?;
        self.loose_wallet
            .reserve_selected_proofs_with_opening_attempt(
                &offer.mint_url,
                &offer.unit,
                &proof_ids,
                &NewOpeningAttempt {
                    attempt_id: prepared.channel_id.clone(),
                    opening_id: prepared.channel_id.clone(),
                    predecessor_attempt_id: None,
                    reservation_id: reservation.reservation_id.clone(),
                    receiver_pubkey: offer.receiver_pubkey.clone(),
                    mint_url: offer.mint_url.clone(),
                    unit: offer.unit.clone(),
                    funding_token_target_msats: desired_funding_token_amount_raw
                        .unwrap_or(reservation.total_amount_raw)
                        .saturating_mul(1000),
                    expiry_timestamp,
                    prepared_open_json: serde_json::to_string(&prepared).map_err(|e| {
                        open_channel_stage_error(
                            OpenChannelFailureStage::BeforeOpeningSaved,
                            Some(prepared.channel_id.clone()),
                            e.to_string(),
                        )
                    })?,
                    selected_proof_ids: proof_ids.clone(),
                },
            )
            .map_err(|e| {
                open_channel_stage_error(
                    OpenChannelFailureStage::BeforeOpeningSaved,
                    Some(prepared.channel_id.clone()),
                    e.to_string(),
                )
            })?;
        let OpeningSubmissionClaim::Acquired(permit) = self
            .loose_wallet
            .claim_opening_attempt_submission(&prepared.channel_id)
            .map_err(|e| {
                open_channel_stage_error(
                    OpenChannelFailureStage::BeforeOpeningSaved,
                    Some(prepared.channel_id.clone()),
                    e.to_string(),
                )
            })?
        else {
            return Err(open_channel_stage_error(
                OpenChannelFailureStage::BeforeOpeningSaved,
                Some(prepared.channel_id.clone()),
                "test opening submission claim lost".to_string(),
            ));
        };
        self.submit_prepared_open(prepared, permit, &networking)
    }

    fn execute_open_attempt(
        &self,
        offer: &RelayPaymentOffer,
        attempt: ClientOpenAttempt,
        allow_keyset_successor: bool,
    ) -> Result<String, WalletError> {
        let networking = match OpeningRecoveryHttpNetworking::new() {
            Ok(networking) => networking,
            Err(error) => {
                self.loose_wallet
                    .cancel_prepared_opening_attempt(&attempt.prepared.channel_id)
                    .map_err(loose_proof_error)?;
                return Err(WalletError::Backend(error));
            }
        };
        self.execute_open_attempt_with_networking(
            offer,
            attempt,
            allow_keyset_successor,
            &networking,
        )
    }

    fn execute_open_attempt_with_networking<N: OpeningRecoveryNetworking>(
        &self,
        offer: &RelayPaymentOffer,
        attempt: ClientOpenAttempt,
        allow_keyset_successor: bool,
        networking: &N,
    ) -> Result<String, WalletError> {
        let flight_key = format!("{}:{}", self.opening_scope, attempt.prepared.channel_id);
        let _active_opening = enter_active_opening(&flight_key).map_err(|error| match error {
            WalletError::OpeningInProgress { .. } => WalletError::OpeningInProgress {
                channel_id: attempt.prepared.channel_id.clone(),
            },
            error => error,
        })?;
        let result = match self.submit_open_attempt_with_networking(&attempt, networking) {
            Err(SubmitOpenAttemptError::Authority(error)) => return Err(error),
            Err(SubmitOpenAttemptError::Open(error)) if error.input_may_be_spent => {
                match self.recover_or_replay_submitted_opening(&attempt.prepared, networking) {
                    Ok(Some(result)) => Ok(result),
                    Ok(None) => Err(error),
                    // The original execution remains authoritative if later local
                    // recovery fails; never downgrade its remote uncertainty.
                    Err(recovery_error) => {
                        tracing::warn!(
                            channel_id = %attempt.prepared.channel_id,
                            "live opening recovery failed after uncertain submission: {recovery_error}"
                        );
                        Err(error)
                    }
                }
            }
            Err(SubmitOpenAttemptError::Open(error)) => Err(error),
            Ok(result) => Ok(result),
        };
        match result {
            Ok(result) => {
                self.finish_open_channel(result, &attempt.reservation, attempt.expiry_timestamp)
            }
            Err(error)
                if allow_keyset_successor
                    && !error.input_may_be_spent
                    && error.stage == OpenChannelFailureStage::MintRejected
                    && self
                        .loose_wallet
                        .opening_attempt(&attempt.prepared.channel_id)
                        .map_err(loose_proof_error)?
                        .is_some_and(|record| {
                            record.state == OpeningAttemptState::Rejected
                                && record.rejection_code == Some(12002)
                        }) =>
            {
                if let Err(refresh_error) = self.refresh_client_keysets(offer) {
                    let _ = self
                        .loose_wallet
                        .cancel_rejected_opening_attempt(&attempt.prepared.channel_id);
                    return Err(refresh_error);
                }
                let output_keyset = match self.select_output_keyset_from_cache(offer) {
                    Ok(output_keyset) => output_keyset,
                    Err(select_error) => {
                        let _ = self
                            .loose_wallet
                            .cancel_rejected_opening_attempt(&attempt.prepared.channel_id);
                        return Err(select_error);
                    }
                };
                let OutputKeysetSelection::Selected(output_keyset) = output_keyset else {
                    self.loose_wallet
                        .cancel_rejected_opening_attempt(&attempt.prepared.channel_id)
                        .map_err(loose_proof_error)?;
                    return Err(WalletError::NoCompatibleActiveKeyset {
                        mint_url: offer.mint_url.clone(),
                        unit: offer.unit.clone(),
                    });
                };
                if output_keyset.id == attempt.output_keyset.id {
                    let _ = self
                        .loose_wallet
                        .cancel_rejected_opening_attempt(&attempt.prepared.channel_id);
                    return Err(open_channel_error(
                        error,
                        &offer.unit,
                        attempt.selected_input_msats,
                    ));
                }
                let successor = match self.prepare_open_successor(offer, &attempt, output_keyset) {
                    Ok(successor) => successor,
                    Err(error) => {
                        let _ = self
                            .loose_wallet
                            .cancel_rejected_opening_attempt(&attempt.prepared.channel_id);
                        return Err(error);
                    }
                };
                self.execute_open_attempt_with_networking(offer, successor, false, networking)
            }
            Err(error) => self.handle_open_error(
                error,
                &attempt.reservation,
                offer,
                attempt.selected_input_msats,
            ),
        }
    }

    fn prepare_open_successor(
        &self,
        offer: &RelayPaymentOffer,
        predecessor: &ClientOpenAttempt,
        output_keyset: SelectedOutputKeyset,
    ) -> Result<ClientOpenAttempt, WalletError> {
        let input_proofs_json = proofs_json_from_reservation(&predecessor.reservation)?;
        let networking = OpeningRecoveryHttpNetworking::new().map_err(WalletError::Backend)?;
        let input_keyset_lookup = {
            let bridge = self
                .bridge
                .lock()
                .map_err(|_| WalletError::Backend("bridge mutex poisoned".to_string()))?;
            proof_input_keysets_from_cache(
                &bridge,
                &offer.mint_url,
                &offer.unit,
                &predecessor.reservation,
            )
            .map_err(|e| open_channel_error(e, &offer.unit, predecessor.selected_input_msats))?
        };
        let input_keysets_json =
            proof_input_keysets_json(input_keyset_lookup, &offer.mint_url, &networking).map_err(
                |e| open_channel_error(e, &offer.unit, predecessor.selected_input_msats),
            )?;
        let desired_funding_token_amount_raw = match predecessor.requested_capacity_raw {
            Some(target) => Some(
                compute_funding_token_amount(target, &output_keyset.info_json, 0).map_err(|e| {
                    WalletError::Backend(format!("compute successor funding amount: {e}"))
                })?,
            ),
            None => predecessor.desired_funding_token_amount_raw,
        };
        let prepared = {
            let bridge = self
                .bridge
                .lock()
                .map_err(|_| WalletError::Backend("bridge mutex poisoned".to_string()))?;
            bridge
                .prepare_open_channel_from_proofs_with_input_keysets(
                    &offer.mint_url,
                    &offer.unit,
                    &input_proofs_json,
                    &input_keysets_json,
                    &offer.receiver_pubkey,
                    &self.sender_pubkey_hex,
                    predecessor.expiry_timestamp,
                    &output_keyset.info_json,
                    0,
                    predecessor.requested_capacity_raw,
                    desired_funding_token_amount_raw,
                )
                .map_err(|e| open_channel_error(e, &offer.unit, predecessor.selected_input_msats))?
        };
        let journal = NewOpeningAttempt {
            attempt_id: prepared.channel_id.clone(),
            opening_id: predecessor.opening_id.clone(),
            predecessor_attempt_id: Some(predecessor.prepared.channel_id.clone()),
            reservation_id: predecessor.reservation.reservation_id.clone(),
            receiver_pubkey: offer.receiver_pubkey.clone(),
            mint_url: offer.mint_url.clone(),
            unit: offer.unit.clone(),
            funding_token_target_msats: predecessor.funding_token_target_msats,
            expiry_timestamp: predecessor.expiry_timestamp,
            prepared_open_json: serde_json::to_string(&prepared).map_err(|e| {
                WalletError::Backend(format!("serialize successor opening attempt: {e}"))
            })?,
            selected_proof_ids: predecessor
                .reservation
                .proofs
                .iter()
                .map(|proof| proof.proof_id.clone())
                .collect(),
        };
        self.loose_wallet
            .store_opening_attempt_for_reservation(&journal)
            .map_err(loose_proof_error)?;
        let save_result = self
            .bridge
            .lock()
            .map_err(|_| WalletError::Backend("bridge mutex poisoned".to_string()))
            .and_then(|bridge| {
                bridge.mark_prepared_open_saved(&prepared).map_err(|e| {
                    open_channel_error(e, &offer.unit, predecessor.selected_input_msats)
                })
            });
        if let Err(error) = save_result {
            let _ = self
                .loose_wallet
                .cancel_prepared_opening_attempt(&prepared.channel_id);
            return Err(error);
        }
        Ok(ClientOpenAttempt {
            opening_id: predecessor.opening_id.clone(),
            output_keyset,
            reservation: predecessor.reservation.clone(),
            prepared,
            requested_capacity_raw: predecessor.requested_capacity_raw,
            desired_funding_token_amount_raw,
            funding_token_target_msats: predecessor.funding_token_target_msats,
            selected_input_msats: predecessor.selected_input_msats,
            expiry_timestamp: predecessor.expiry_timestamp,
        })
    }

    fn handle_open_error(
        &self,
        error: OpenChannelError,
        reservation: &ProofReservation,
        offer: &RelayPaymentOffer,
        recovery_funding_token_target_msats: u64,
    ) -> Result<String, WalletError> {
        if error.input_may_be_spent {
            // The pre-submit journal is already the authoritative recovery index.
        } else if error.stage == OpenChannelFailureStage::MintRejected {
            let channel_id = error.channel_id.as_deref().ok_or_else(|| {
                WalletError::Backend("mint-rejected opening has no channel id".to_string())
            })?;
            self.loose_wallet
                .cancel_rejected_opening_attempt(channel_id)
                .map_err(loose_proof_error)?;
        } else {
            let _ = self
                .loose_wallet
                .release_reservation(&reservation.reservation_id);
        }
        Err(open_channel_error(
            error,
            &offer.unit,
            recovery_funding_token_target_msats,
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
            OutputKeysetSelection::Selected(output_keyset)
                if offer.preferred_keyset_ids.is_empty()
                    || offer
                        .preferred_keyset_ids
                        .iter()
                        .any(|id| id == &output_keyset.id) =>
            {
                return Ok(output_keyset);
            }
            // The cache has a compatible fallback but not a preferred active
            // keyset. Refresh once before using the fallback in case the relay
            // knows about a newer active keyset than this client does.
            OutputKeysetSelection::Selected(_) => {}
            OutputKeysetSelection::NoCompatibleActiveKeyset => {}
        }

        self.refresh_client_keysets(offer)?;
        match self.select_output_keyset_from_cache(offer)? {
            OutputKeysetSelection::Selected(output_keyset) => Ok(output_keyset),
            OutputKeysetSelection::NoCompatibleActiveKeyset => {
                Err(WalletError::NoCompatibleActiveKeyset {
                    mint_url: offer.mint_url.clone(),
                    unit: offer.unit.clone(),
                })
            }
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
            OutputKeysetSelection::NoCompatibleActiveKeyset => {
                return Ok(OutputKeysetSelection::NoCompatibleActiveKeyset);
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
                .map_err(|error| {
                    preflight_offer_error(
                        offer,
                        format!("compute required funding amount: {error}"),
                    )
                })?;

        let available_proofs = self
            .loose_wallet
            .list_available_proofs(&offer.mint_url, &offer.unit, &[])
            .map_err(loose_proof_error)?;
        let input_fee_by_keyset = self.cached_input_fees(offer, &available_proofs)?;
        let selection = select_exact_inputs_refreshing_once(
            &available_proofs,
            input_fee_by_keyset,
            required_post_swap_raw,
            || {
                self.refresh_client_keysets(offer)
                    .map_err(|error| error.to_string())?;
                self.cached_input_fees(offer, &available_proofs)
                    .map_err(|error| error.to_string())
            },
        )
        .map_err(|error| map_proof_selection_error(error, offer))?;

        let selected_set = selection
            .proof_ids
            .iter()
            .collect::<std::collections::HashSet<_>>();
        let selected_proofs = available_proofs
            .into_iter()
            .filter(|proof| selected_set.contains(&proof.proof_id))
            .collect::<Vec<_>>();
        let total_amount_raw = selected_proofs.iter().try_fold(0u64, |total, proof| {
            total
                .checked_add(proof.amount_raw)
                .ok_or_else(|| preflight_offer_error(offer, "selected input total overflow"))
        })?;
        let reservation = ProofReservation {
            reservation_id: new_reservation_id(),
            proofs: selected_proofs,
            total_amount_raw,
        };
        let selected_input_msats = raw_to_msats(&offer.unit, reservation.total_amount_raw)
            .map_err(|error| preflight_offer_error(offer, error))?;
        self.prepare_open_attempt(
            offer,
            output_keyset,
            reservation,
            ClientOpenPlan {
                requested_capacity_raw: Some(target_capacity_raw),
                desired_funding_token_amount_raw: Some(required_post_swap_raw),
                funding_token_target_msats: raw_to_msats(&offer.unit, required_post_swap_raw)
                    .map_err(|error| preflight_offer_error(offer, error))?,
                selected_input_msats,
                expiry_timestamp,
            },
            false,
        )
    }

    fn cached_input_fees(
        &self,
        offer: &RelayPaymentOffer,
        proofs: &[LooseProofRecord],
    ) -> Result<HashMap<String, u64>, WalletError> {
        let unit = parse_currency_unit(&offer.unit)
            .map_err(|error| preflight_offer_error(offer, error))?;
        let bridge = self
            .bridge
            .lock()
            .map_err(|_| WalletError::Backend("bridge mutex poisoned".to_string()))?;
        let cached = bridge.cached_keysets_for_unit(&offer.mint_url, &unit);
        let wanted = proofs
            .iter()
            .map(|proof| proof.keyset_id.as_str())
            .collect::<HashSet<_>>();
        let mut fees = HashMap::new();
        for (id, entry) in cached {
            let id = id.to_string();
            if !wanted.contains(id.as_str()) {
                continue;
            }
            let info = parse_keyset_info_from_json(&entry.info_json).map_err(|error| {
                preflight_offer_error(
                    offer,
                    format!("parse cached input keyset info for {id}: {error}"),
                )
            })?;
            fees.insert(id, info.input_fee_ppk);
        }
        Ok(fees)
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
                 WHERE channel_id = ?1 AND attached_session_id IS NULL
                 AND NOT EXISTS(SELECT 1 FROM monad_client_channel_recoveries WHERE channel_id = ?1)",
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
        funding_token_target_msats: u64,
    ) -> Result<String, WalletError> {
        let funding_token_target_raw = msats_to_raw_units(&offer.unit, funding_token_target_msats)
            .map_err(|error| preflight_offer_error(offer, error))?;
        #[cfg(not(feature = "funds-lifecycle-test"))]
        let expiry_timestamp = Self::now_seconds()? + CHANNEL_EXPIRY_SECONDS;
        #[cfg(feature = "funds-lifecycle-test")]
        let expiry_timestamp =
            Self::now_seconds()? + lifecycle_test::lifetime(CHANNEL_EXPIRY_SECONDS);
        // Plain provisioning consumes strict smallest-first inputs until their
        // post-input-fee value covers the funding-token target. If the mint
        // rejects the first open because our cached output keyset is stale, the
        // input reservation can be reused: only the output keyset selection and
        // swap construction need to change. Selection refreshes the client cache
        // before reporting that no compatible active keyset exists; the retry
        // helper handles the mint-rejection refresh path and skips retry when
        // refresh still selects the same keyset.
        let available = self
            .loose_wallet
            .list_available_proofs(&offer.mint_url, &offer.unit, &[])
            .map_err(loose_proof_error)?;
        let gross_available = available.iter().try_fold(0u64, |total, proof| {
            total
                .checked_add(proof.amount_raw)
                .ok_or_else(|| preflight_offer_error(offer, "available input total overflow"))
        })?;
        if gross_available < funding_token_target_raw {
            return Err(WalletError::InsufficientLooseProofFunds {
                mint_url: offer.mint_url.clone(),
                unit: offer.unit.clone(),
                requested_raw: funding_token_target_raw,
                available_raw: gross_available,
            });
        }
        let input_fees = self.cached_input_fees(offer, &available)?;
        let selection = select_plain_inputs_refreshing_once(
            &available,
            input_fees,
            funding_token_target_raw,
            || {
                self.refresh_client_keysets(offer)
                    .map_err(|error| error.to_string())?;
                self.cached_input_fees(offer, &available)
                    .map_err(|error| error.to_string())
            },
        )
        .map_err(|error| map_proof_selection_error(error, offer))?;
        let selected_set = selection.proof_ids.iter().collect::<HashSet<_>>();
        let selected = available
            .into_iter()
            .filter(|proof| selected_set.contains(&proof.proof_id))
            .collect::<Vec<_>>();
        self.ensure_offer_keysets_cached(offer).map_err(|error| {
            WalletError::ProvisioningOfferUnavailable {
                mint_url: offer.mint_url.clone(),
                unit: offer.unit.clone(),
                reason: error.to_string(),
            }
        })?;
        let output_keyset = self
            .select_output_keyset_refreshing_client_first(offer)
            .map_err(|error| WalletError::ProvisioningOfferUnavailable {
                mint_url: offer.mint_url.clone(),
                unit: offer.unit.clone(),
                reason: error.to_string(),
            })?;
        let attempt = self.prepare_open_attempt(
            offer,
            output_keyset,
            ProofReservation {
                reservation_id: new_reservation_id(),
                proofs: selected,
                total_amount_raw: selection.input_value_raw,
            },
            ClientOpenPlan {
                requested_capacity_raw: None,
                desired_funding_token_amount_raw: Some(funding_token_target_raw),
                funding_token_target_msats,
                selected_input_msats: raw_to_msats(&offer.unit, selection.input_value_raw)
                    .map_err(|error| preflight_offer_error(offer, error))?,
                expiry_timestamp,
            },
            true,
        )?;
        self.execute_open_attempt(offer, attempt, true)
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
            // Serialize before recording so local state cannot advance for a
            // payment JSON that was never returned to the session driver.
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
        conn: &Connection,
        mut meta: ChannelMeta,
    ) -> Result<WalletChannel, WalletError> {
        apply_channel_recovery_state(conn, &mut meta)?;
        let upstream = upstream_info(&self.bridge, &meta.channel_id);
        wallet_channel_from_meta(meta, upstream)
    }
}

fn apply_channel_recovery_state(
    conn: &Connection,
    meta: &mut ChannelMeta,
) -> Result<(), WalletError> {
    let status: Option<String> = conn
        .query_row(
            "SELECT status FROM monad_client_channel_recoveries WHERE channel_id = ?1",
            [&meta.channel_id],
            |r| r.get(0),
        )
        .optional()
        .map_err(|e| WalletError::Backend(format!("check pending recovery: {e}")))?;
    if let Some(status) = status {
        meta.state = if status == "completed" {
            WalletChannelState::Closed
        } else {
            WalletChannelState::Closing
        };
    }
    Ok(())
}

fn wallet_channel_from_meta(
    meta: ChannelMeta,
    upstream: Option<ClientChannelInfo>,
) -> Result<WalletChannel, WalletError> {
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

fn upstream_info<N: SpilmanClientNetworking>(
    bridge: &Mutex<SpilmanClientBridge<ConfigurableClientHost<SqliteClientStorage>, N>>,
    channel_id: &str,
) -> Option<ClientChannelInfo> {
    bridge.lock().ok()?.get_channel_info(channel_id)
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

// Only empty paired arrays establish absence. Exact matching, ordering and proof
// verification belong to upstream checked completion for both opening and refund.
fn restore_response_is_absent(response_json: &str) -> Result<bool, String> {
    let response: RestoreResponse =
        serde_json::from_str(response_json).map_err(|e| format!("decode restore response: {e}"))?;
    if response.outputs.len() != response.signatures.len() {
        return Err("restore response output/signature counts differ".to_string());
    }
    Ok(response.outputs.is_empty())
}

fn prepared_inputs_are_all_unspent<N: OpeningRecoveryNetworking>(
    prepared: &PreparedOpenChannel,
    networking: &N,
) -> Result<bool, OpenChannelError> {
    Ok(prepared_input_state(prepared, networking)? == ExactInputState::AllUnspent)
}

fn prepared_input_state<N: OpeningRecoveryNetworking>(
    prepared: &PreparedOpenChannel,
    networking: &N,
) -> Result<ExactInputState, OpenChannelError> {
    let proofs: Vec<Proof> = serde_json::from_str(&prepared.opening.input_token).map_err(|e| {
        open_channel_stage_error(
            OpenChannelFailureStage::RestoreVerification,
            Some(prepared.channel_id.clone()),
            format!("decode prepared opening inputs: {e}"),
        )
    })?;
    if proofs.is_empty() {
        return Err(open_channel_stage_error(
            OpenChannelFailureStage::RestoreVerification,
            Some(prepared.channel_id.clone()),
            "prepared opening has no inputs".to_string(),
        ));
    }
    let ys = proofs
        .iter()
        .map(|proof| {
            proof.y().map_err(|e| {
                open_channel_stage_error(
                    OpenChannelFailureStage::RestoreVerification,
                    Some(prepared.channel_id.clone()),
                    format!("derive prepared input Y: {e}"),
                )
            })
        })
        .collect::<Result<Vec<_>, _>>()?;
    let mut requested = ys.iter().map(ToString::to_string).collect::<HashSet<_>>();
    if requested.len() != ys.len() {
        return Err(open_channel_stage_error(
            OpenChannelFailureStage::RestoreVerification,
            Some(prepared.channel_id.clone()),
            "prepared opening contains duplicate input Ys".to_string(),
        ));
    }
    let request_json = serde_json::to_string(&CheckStateRequest { ys }).map_err(|e| {
        open_channel_stage_error(
            OpenChannelFailureStage::RestoreVerification,
            Some(prepared.channel_id.clone()),
            format!("serialize opening input state request: {e}"),
        )
    })?;
    let response_json = networking
        .call_mint_check_state(&prepared.mint_url, &request_json)
        .map_err(|e| {
            open_channel_stage_error(
                OpenChannelFailureStage::RestoreVerification,
                Some(prepared.channel_id.clone()),
                format!("check prepared opening input states: {e}"),
            )
        })?;
    let response: CheckStateResponse = serde_json::from_str(&response_json).map_err(|e| {
        open_channel_stage_error(
            OpenChannelFailureStage::RestoreVerification,
            Some(prepared.channel_id.clone()),
            format!("decode opening input state response: {e}"),
        )
    })?;
    if response.states.len() != requested.len() {
        return Err(open_channel_stage_error(
            OpenChannelFailureStage::RestoreVerification,
            Some(prepared.channel_id.clone()),
            "opening input state response did not cover every input".to_string(),
        ));
    }
    let mut all_unspent = true;
    let mut all_spent = true;
    for proof_state in response.states {
        if !requested.remove(&proof_state.y.to_string()) {
            return Err(open_channel_stage_error(
                OpenChannelFailureStage::RestoreVerification,
                Some(prepared.channel_id.clone()),
                "opening input state response contained an unknown or duplicate Y".to_string(),
            ));
        }
        all_unspent &= proof_state.state == State::Unspent;
        all_spent &= proof_state.state == State::Spent;
    }
    if !requested.is_empty() {
        return Err(open_channel_stage_error(
            OpenChannelFailureStage::RestoreVerification,
            Some(prepared.channel_id.clone()),
            "opening input state response omitted an input Y".to_string(),
        ));
    }
    Ok(if all_unspent {
        ExactInputState::AllUnspent
    } else if all_spent {
        ExactInputState::AllSpent
    } else {
        ExactInputState::MixedOrPending
    })
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

fn prepared_input_ys(prepared: &PreparedOpenChannel) -> Result<Vec<String>, WalletError> {
    let proofs: Vec<Proof> = serde_json::from_str(&prepared.opening.input_token).map_err(|e| {
        WalletError::Backend(format!("decode immutable prepared opening inputs: {e}"))
    })?;
    if proofs.is_empty() {
        return Err(WalletError::Backend(
            "immutable prepared opening has no inputs".to_string(),
        ));
    }
    let mut ids = proofs
        .iter()
        .map(|proof| {
            proof
                .y()
                .map(|y| y.to_hex())
                .map_err(|e| WalletError::Backend(format!("derive prepared input proof id: {e}")))
        })
        .collect::<Result<Vec<_>, _>>()?;
    ids.sort();
    if ids.windows(2).any(|pair| pair[0] == pair[1]) {
        return Err(WalletError::Backend(
            "immutable prepared opening contains duplicate inputs".to_string(),
        ));
    }
    Ok(ids)
}

fn verify_prepared_inputs_match_selected_proofs(
    prepared: &PreparedOpenChannel,
    selected_proof_ids: &[String],
    selected_proofs: &[LooseProofRecord],
) -> Result<(), WalletError> {
    let mut expected_ids = selected_proof_ids.to_vec();
    expected_ids.sort();
    let mut actual_ids = selected_proofs
        .iter()
        .map(|proof| proof.proof_id.clone())
        .collect::<Vec<_>>();
    actual_ids.sort();
    if expected_ids.is_empty()
        || expected_ids.windows(2).any(|pair| pair[0] == pair[1])
        || actual_ids != expected_ids
    {
        return Err(WalletError::Backend(format!(
            "opening journal exact proof ids do not match reservation for {}",
            prepared.channel_id
        )));
    }
    let prepared_ys = prepared_input_ys(prepared)?;
    let mut selected_ys = selected_proofs
        .iter()
        .map(|record| {
            let proof: Proof = serde_json::from_str(&record.proof_json).map_err(|e| {
                WalletError::Backend(format!("decode selected proof '{}': {e}", record.proof_id))
            })?;
            proof.y().map(|y| y.to_hex()).map_err(|e| {
                WalletError::Backend(format!("derive selected proof '{}': {e}", record.proof_id))
            })
        })
        .collect::<Result<Vec<_>, _>>()?;
    selected_ys.sort();
    if selected_ys != prepared_ys {
        return Err(WalletError::Backend(format!(
            "opening journal selected proofs do not match immutable prepared token for {}",
            prepared.channel_id
        )));
    }
    Ok(())
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
    match error {
        LooseProofWalletError::AlreadyOpen(channel_id) => WalletError::AlreadyOpen { channel_id },
        LooseProofWalletError::OpeningInProgress(channel_id) => {
            WalletError::OpeningInProgress { channel_id }
        }
        LooseProofWalletError::OpeningConflict(channel_id) => WalletError::Conflict { channel_id },
        LooseProofWalletError::TooManyInputProofs { selected, maximum } => {
            WalletError::TooManyInputProofs { selected, maximum }
        }
        error => WalletError::Backend(format!("loose proof wallet: {error}")),
    }
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
    let mut compatible_ids = active_ids
        .into_iter()
        .map(|id| id.to_string())
        .filter(|id| offer.keyset_is_compatible(id))
        .collect::<Vec<_>>();
    compatible_ids.sort();

    for preferred_id in &offer.preferred_keyset_ids {
        if compatible_ids.iter().any(|id| id == preferred_id) {
            return Ok(OutputKeysetSelection::Selected(preferred_id.clone()));
        }
    }

    Ok(compatible_ids
        .into_iter()
        .next()
        .map(OutputKeysetSelection::Selected)
        .unwrap_or(OutputKeysetSelection::NoCompatibleActiveKeyset))
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

fn proof_input_keysets_json<N: SpilmanClientNetworking>(
    mut lookup: ProofInputKeysetLookup,
    mint_url: &str,
    networking: &N,
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

fn proof_input_keysets_from_mint<N: SpilmanClientNetworking>(
    mint_url: &str,
    unit: &CurrencyUnit,
    missing: &[Id],
    networking: &N,
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

fn select_plain_inputs(
    proofs: &[LooseProofRecord],
    input_fees: &HashMap<String, u64>,
    funding_token_target_raw: u64,
) -> Result<ProofSelection, ProofSelectionError> {
    select_smallest_first_inputs_for_funding_target(
        proofs
            .iter()
            .map(|proof| SmallestFirstProofCandidate {
                proof_id: proof.proof_id.clone(),
                keyset_id: proof.keyset_id.clone(),
                amount_raw: proof.amount_raw,
                input_fee_ppk: input_fees.get(&proof.keyset_id).copied(),
            })
            .collect(),
        funding_token_target_raw,
    )
}

fn select_plain_inputs_refreshing_once<F>(
    proofs: &[LooseProofRecord],
    input_fees: HashMap<String, u64>,
    funding_token_target_raw: u64,
    refresh: F,
) -> Result<ProofSelection, ProofSelectionError>
where
    F: FnOnce() -> Result<HashMap<String, u64>, String>,
{
    match select_plain_inputs(proofs, &input_fees, funding_token_target_raw) {
        Err(error @ ProofSelectionError::InputKeysetMetadataUnavailable { .. }) => {
            let refreshed = refresh().map_err(|_| error)?;
            select_plain_inputs(proofs, &refreshed, funding_token_target_raw)
        }
        result => result,
    }
}

fn select_exact_inputs_refreshing_once<F>(
    proofs: &[LooseProofRecord],
    mut input_fees: HashMap<String, u64>,
    target_post_swap_raw: u64,
    refresh: F,
) -> Result<ProofSelection, ProofSelectionError>
where
    F: FnOnce() -> Result<HashMap<String, u64>, String>,
{
    let mut missing = missing_input_keysets(proofs, &input_fees);
    if !missing.is_empty() {
        if let Ok(refreshed) = refresh() {
            input_fees = refreshed;
            missing = missing_input_keysets(proofs, &input_fees);
        }
    }
    let candidates = proofs
        .iter()
        .filter_map(|proof| {
            input_fees
                .get(&proof.keyset_id)
                .copied()
                .map(|input_fee_ppk| ProofCandidate {
                    proof_id: proof.proof_id.clone(),
                    amount_raw: proof.amount_raw,
                    input_fee_ppk,
                })
        })
        .collect();
    match select_mixed_fee_inputs_for_post_swap_target(candidates, target_post_swap_raw) {
        Err(ProofSelectionError::Insufficient { .. }) if !missing.is_empty() => {
            Err(ProofSelectionError::InputKeysetMetadataUnavailable {
                keyset_ids: missing,
            })
        }
        result => result,
    }
}

fn missing_input_keysets(
    proofs: &[LooseProofRecord],
    input_fees: &HashMap<String, u64>,
) -> Vec<String> {
    let mut missing = proofs
        .iter()
        .filter(|proof| !input_fees.contains_key(&proof.keyset_id))
        .map(|proof| proof.keyset_id.clone())
        .collect::<Vec<_>>();
    missing.sort();
    missing.dedup();
    missing
}

fn preflight_offer_error(offer: &RelayPaymentOffer, reason: impl ToString) -> WalletError {
    WalletError::ProvisioningPreflight {
        mint_url: offer.mint_url.clone(),
        unit: offer.unit.clone(),
        reason: reason.to_string(),
    }
}

fn map_proof_selection_error(error: ProofSelectionError, offer: &RelayPaymentOffer) -> WalletError {
    match error {
        ProofSelectionError::Insufficient {
            target_post_swap_raw,
            available_post_swap_raw,
        } => WalletError::InsufficientLooseProofFunds {
            mint_url: offer.mint_url.clone(),
            unit: offer.unit.clone(),
            requested_raw: target_post_swap_raw,
            available_raw: available_post_swap_raw,
        },
        ProofSelectionError::InputKeysetMetadataUnavailable { keyset_ids } => {
            WalletError::InputKeysetMetadataUnavailable {
                mint_url: offer.mint_url.clone(),
                unit: offer.unit.clone(),
                keyset_ids,
            }
        }
        ProofSelectionError::TooManyInputProofs { selected, maximum } => {
            WalletError::TooManyInputProofs { selected, maximum }
        }
        ProofSelectionError::Overflow => {
            preflight_offer_error(offer, "proof selection total overflow")
        }
    }
}

fn open_channel_error(
    error: OpenChannelError,
    unit: &str,
    funding_token_target_msats: u64,
) -> WalletError {
    if error.input_may_be_spent {
        WalletError::Backend(format!(
            "channel open failed (input may be spent, retry or recover): {} (input may be spent)",
            error.message
        ))
    } else {
        WalletError::Backend(format!(
            "channel open failed (input was not spent): {} (funding-token target {} msats in unit {})",
            error.message, funding_token_target_msats, unit
        ))
    }
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
    if !offer.keyset_is_compatible(&channel.keyset_id) {
        return Err(WalletError::OfferMismatch(
            "keyset format was not negotiated".to_string(),
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
    use crate::loose_proof_wallet::OpeningExecutionKind;
    use crate::loose_proof_wallet::{LooseProofState, NewLooseProof};
    use crate::proof_selection::input_fee_raw_from_ppk_sum;
    use crate::wallet_lock::{ClientWalletLocks, WalletLockMode};
    use cashu::nuts::RestoreRequest;
    use cdk_spilman::{
        channel_parameters_get_channel_id,
        compute_channel_from_proofs_with_input_keysets_and_funding_amount,
        compute_channel_secret_from_hex, construct_proofs, create_funding_swap_with_plain_change,
        create_plain_blinded_messages, ClientChannelOpeningFromSwap, ClientKeysetCacheEntry,
        ClientStorage, ConfigurableClientHost, FundingSpendKind, MemoryClientStorage, Payment,
        ReqwestClientNetworking, SpilmanClientBridge, SpilmanClientHost, SqliteClientStorage,
    };
    use cdk_spilman_test_mint::{
        rotate_sat_keyset, serve_existing_mint_with_shutdown, serve_mint_with_shutdown,
        TestMintConfig, TestMintHelper,
    };
    use rand::RngCore;
    use std::collections::BTreeSet;
    use std::path::PathBuf;
    use tokio::sync::oneshot;

    struct DirectMintConnection {
        mint_url: String,
        client: reqwest::Client,
    }

    struct FailingRefundMintConnection {
        inner: DirectMintConnection,
    }

    struct OfflineRefundMint;

    #[async_trait::async_trait]
    impl MintConnection for OfflineRefundMint {
        async fn process_swap(
            &self,
            _: cashu::nuts::SwapRequest,
        ) -> anyhow::Result<cashu::nuts::SwapResponse> {
            panic!("unexpected swap IO")
        }
        async fn post_restore(&self, _: RestoreRequest) -> anyhow::Result<RestoreResponse> {
            panic!("unexpected restore IO")
        }
        async fn check_state(
            &self,
            _: Vec<cashu::nuts::PublicKey>,
        ) -> anyhow::Result<CheckStateResponse> {
            panic!("unexpected state IO")
        }
    }

    struct ScriptedRefundMint {
        inner: DirectMintConnection,
        requests: Mutex<Vec<String>>,
        lose_response: bool,
        reject_replay: bool,
        invalid_restore: bool,
        fail_state: bool,
        fail_second_submit: bool,
        complete_on_state: Mutex<Option<cashu::nuts::SwapRequest>>,
        close_on_submit: Mutex<Option<cashu::nuts::SwapRequest>>,
        empty_restore: bool,
        restore_calls: AtomicUsize,
        hide_funding_witness: bool,
    }

    struct BlockingRefundMint {
        inner: DirectMintConnection,
        entered: tokio::sync::Notify,
    }

    #[async_trait::async_trait]
    impl MintConnection for BlockingRefundMint {
        async fn process_swap(
            &self,
            _: cashu::nuts::SwapRequest,
        ) -> anyhow::Result<cashu::nuts::SwapResponse> {
            self.entered.notify_one();
            std::future::pending().await
        }
        async fn post_restore(&self, request: RestoreRequest) -> anyhow::Result<RestoreResponse> {
            self.inner.post_restore(request).await
        }
        async fn check_state(
            &self,
            ys: Vec<cashu::nuts::PublicKey>,
        ) -> anyhow::Result<CheckStateResponse> {
            self.inner.check_state(ys).await
        }
    }

    #[async_trait::async_trait]
    impl MintConnection for ScriptedRefundMint {
        async fn process_swap(
            &self,
            request: cashu::nuts::SwapRequest,
        ) -> anyhow::Result<cashu::nuts::SwapResponse> {
            let count = {
                let mut requests = self.requests.lock().unwrap();
                requests.push(serde_json::to_string(&request).unwrap());
                requests.len()
            };
            if self.fail_second_submit && count == 2 {
                anyhow::bail!("ambiguous successor submission");
            }
            if self.reject_replay {
                if count == 1 {
                    anyhow::bail!("ambiguous initial execution");
                }
                return Err(MintHttpRejection {
                    status: 400,
                    code: Some(12002),
                }
                .into());
            }
            let close = self.close_on_submit.lock().unwrap().take();
            if let Some(close) = close {
                self.inner.process_swap(close).await?;
            }
            let result = self.inner.process_swap(request).await?;
            if self.lose_response {
                anyhow::bail!("lost successful response");
            }
            Ok(result)
        }
        async fn post_restore(&self, request: RestoreRequest) -> anyhow::Result<RestoreResponse> {
            self.restore_calls.fetch_add(1, Ordering::SeqCst);
            if self.empty_restore {
                return Ok(RestoreResponse {
                    outputs: vec![],
                    signatures: vec![],
                });
            }
            if self.invalid_restore {
                return Ok(RestoreResponse {
                    outputs: request.outputs,
                    signatures: vec![],
                });
            }
            self.inner.post_restore(request).await
        }
        async fn check_state(
            &self,
            ys: Vec<cashu::nuts::PublicKey>,
        ) -> anyhow::Result<CheckStateResponse> {
            if self.fail_state {
                anyhow::bail!("state endpoint unavailable");
            }
            let pending = self.complete_on_state.lock().unwrap().take();
            if let Some(request) = pending {
                self.inner.process_swap(request).await?;
            }
            let mut response = self.inner.check_state(ys).await?;
            if self.hide_funding_witness {
                for state in &mut response.states {
                    state.witness = None;
                }
            }
            Ok(response)
        }
    }

    #[async_trait::async_trait]
    impl MintConnection for DirectMintConnection {
        async fn process_swap(
            &self,
            request: cashu::nuts::SwapRequest,
        ) -> anyhow::Result<cashu::nuts::SwapResponse> {
            let response = self
                .client
                .post(format!("{}/v1/swap", self.mint_url))
                .json(&request)
                .send()
                .await
                .map_err(|e| anyhow::anyhow!(e.to_string()))?;
            let status = response.status();
            if !status.is_success() {
                return Err(
                    MintHttpRejection::from_body(status.as_u16(), &response.text().await?).into(),
                );
            }
            response
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
        mint_helper: TestMintHelper,
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

    struct CountingSwapNetworking {
        calls: Mutex<usize>,
    }

    struct BlockingSwapNetworking {
        calls: AtomicUsize,
        entered: (Mutex<bool>, std::sync::Condvar),
        release: (Mutex<bool>, std::sync::Condvar),
    }

    impl BlockingSwapNetworking {
        fn new() -> Self {
            Self {
                calls: AtomicUsize::new(0),
                entered: (Mutex::new(false), std::sync::Condvar::new()),
                release: (Mutex::new(false), std::sync::Condvar::new()),
            }
        }
    }

    impl SpilmanClientNetworking for BlockingSwapNetworking {
        fn call_mint_swap(&self, _: &str, _: &str) -> Result<String, String> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            *self.entered.0.lock().unwrap() = true;
            self.entered.1.notify_one();
            let mut release = self.release.0.lock().unwrap();
            while !*release {
                release = self.release.1.wait(release).unwrap();
            }
            Err("injected ambiguous submission".to_string())
        }

        fn call_mint_restore(&self, _: &str, _: &str) -> Result<String, String> {
            Ok(r#"{"outputs":[],"signatures":[]}"#.to_string())
        }

        fn call_mint_keysets(&self, _: &str) -> Result<String, String> {
            Err("not used".to_string())
        }

        fn call_mint_keys(&self, _: &str, _: &str) -> Result<String, String> {
            Err("not used".to_string())
        }
    }

    impl OpeningRecoveryNetworking for BlockingSwapNetworking {
        fn call_mint_check_state(&self, _: &str, _: &str) -> Result<String, String> {
            Err("not used".to_string())
        }
    }

    impl SpilmanClientNetworking for CountingSwapNetworking {
        fn call_mint_swap(&self, _: &str, _: &str) -> Result<String, String> {
            *self.calls.lock().unwrap() += 1;
            Ok("{}".to_string())
        }

        fn call_mint_restore(&self, _: &str, _: &str) -> Result<String, String> {
            panic!("restore is not expected")
        }

        fn call_mint_keysets(&self, _: &str) -> Result<String, String> {
            panic!("keyset lookup is not expected")
        }

        fn call_mint_keys(&self, _: &str, _: &str) -> Result<String, String> {
            panic!("key lookup is not expected")
        }
    }

    impl OpeningRecoveryNetworking for CountingSwapNetworking {
        fn call_mint_check_state(&self, _: &str, _: &str) -> Result<String, String> {
            panic!("state check is not expected")
        }
    }

    #[derive(Clone)]
    enum CheckStateMode {
        States(Vec<State>),
        MissingLast,
        DuplicateFirst,
        NetworkError,
    }

    struct StateCheckNetworking {
        mode: CheckStateMode,
        requested_y_count: Mutex<Option<usize>>,
        restore_response: Result<String, String>,
    }

    impl StateCheckNetworking {
        fn new(mode: CheckStateMode) -> Self {
            Self {
                mode,
                requested_y_count: Mutex::new(None),
                restore_response: Ok(r#"{"outputs":[],"signatures":[]}"#.to_string()),
            }
        }
    }

    impl SpilmanClientNetworking for StateCheckNetworking {
        fn call_mint_swap(&self, _: &str, _: &str) -> Result<String, String> {
            panic!("startup recovery must never submit a swap")
        }

        fn call_mint_restore(&self, _: &str, _: &str) -> Result<String, String> {
            self.restore_response.clone()
        }

        fn call_mint_keysets(&self, _: &str) -> Result<String, String> {
            Err("not used".to_string())
        }

        fn call_mint_keys(&self, _: &str, _: &str) -> Result<String, String> {
            Err("not used".to_string())
        }
    }

    impl OpeningRecoveryNetworking for StateCheckNetworking {
        fn call_mint_check_state(&self, _: &str, request_json: &str) -> Result<String, String> {
            if matches!(self.mode, CheckStateMode::NetworkError) {
                return Err("injected checkstate network failure".to_string());
            }
            let request: CheckStateRequest =
                serde_json::from_str(request_json).map_err(|e| e.to_string())?;
            *self.requested_y_count.lock().unwrap() = Some(request.ys.len());
            let mut states = request
                .ys
                .into_iter()
                .enumerate()
                .map(|(index, y)| cashu::nuts::ProofState {
                    y,
                    state: match &self.mode {
                        CheckStateMode::States(states) => states[index],
                        CheckStateMode::MissingLast
                        | CheckStateMode::DuplicateFirst
                        | CheckStateMode::NetworkError => State::Unspent,
                    },
                    witness: None,
                })
                .collect::<Vec<_>>();
            match self.mode {
                CheckStateMode::States(_) | CheckStateMode::NetworkError => {}
                CheckStateMode::MissingLast => {
                    states.pop();
                }
                CheckStateMode::DuplicateFirst if states.len() > 1 => {
                    states[1].y = states[0].y;
                }
                CheckStateMode::DuplicateFirst => {}
            }
            serde_json::to_string(&CheckStateResponse { states }).map_err(|e| e.to_string())
        }
    }

    struct CompleteBeforeFinalRestoreNetworking {
        inner: OpeningRecoveryHttpNetworking,
        swap_request_json: String,
        restore_calls: AtomicUsize,
    }

    impl SpilmanClientNetworking for CompleteBeforeFinalRestoreNetworking {
        fn call_mint_swap(&self, _: &str, _: &str) -> Result<String, String> {
            panic!("opening recovery must never submit through its networking interface")
        }

        fn call_mint_restore(&self, mint_url: &str, request_json: &str) -> Result<String, String> {
            let call = self.restore_calls.fetch_add(1, Ordering::SeqCst);
            if call < 2 {
                return Ok(r#"{"outputs":[],"signatures":[]}"#.to_string());
            }
            if call == 2 {
                self.inner
                    .call_mint_swap(mint_url, &self.swap_request_json)?;
            }
            self.inner.call_mint_restore(mint_url, request_json)
        }

        fn call_mint_keysets(&self, mint_url: &str) -> Result<String, String> {
            self.inner.call_mint_keysets(mint_url)
        }

        fn call_mint_keys(&self, mint_url: &str, keyset_id: &str) -> Result<String, String> {
            self.inner.call_mint_keys(mint_url, keyset_id)
        }
    }

    impl OpeningRecoveryNetworking for CompleteBeforeFinalRestoreNetworking {
        fn call_mint_check_state(&self, _: &str, request_json: &str) -> Result<String, String> {
            let request: CheckStateRequest =
                serde_json::from_str(request_json).map_err(|error| error.to_string())?;
            serde_json::to_string(&CheckStateResponse {
                states: request
                    .ys
                    .into_iter()
                    .map(|y| cashu::nuts::ProofState {
                        y,
                        state: State::Spent,
                        witness: None,
                    })
                    .collect(),
            })
            .map_err(|error| error.to_string())
        }
    }

    struct FinalRestoreFailureNetworking {
        restore_calls: AtomicUsize,
    }

    impl SpilmanClientNetworking for FinalRestoreFailureNetworking {
        fn call_mint_swap(&self, _: &str, _: &str) -> Result<String, String> {
            panic!("opening recovery must never submit a swap")
        }

        fn call_mint_restore(&self, _: &str, _: &str) -> Result<String, String> {
            if self.restore_calls.fetch_add(1, Ordering::SeqCst) < 2 {
                Ok(r#"{"outputs":[],"signatures":[]}"#.to_string())
            } else {
                Err("injected final restore failure".to_string())
            }
        }

        fn call_mint_keysets(&self, _: &str) -> Result<String, String> {
            Err("not used".to_string())
        }

        fn call_mint_keys(&self, _: &str, _: &str) -> Result<String, String> {
            Err("not used".to_string())
        }
    }

    impl OpeningRecoveryNetworking for FinalRestoreFailureNetworking {
        fn call_mint_check_state(&self, _: &str, request_json: &str) -> Result<String, String> {
            let request: CheckStateRequest =
                serde_json::from_str(request_json).map_err(|error| error.to_string())?;
            serde_json::to_string(&CheckStateResponse {
                states: request
                    .ys
                    .into_iter()
                    .map(|y| cashu::nuts::ProofState {
                        y,
                        state: State::Spent,
                        witness: None,
                    })
                    .collect(),
            })
            .map_err(|error| error.to_string())
        }
    }

    #[derive(Clone, Copy, Debug)]
    enum InvalidRestore {
        Json,
        Count,
        Identity,
        Duplicate,
        Partial,
        Absent,
        Signature,
        IncorrectSignaturePoint,
    }

    #[derive(Clone, Copy, Debug)]
    enum OpeningOrchestrationScenario {
        RestoreOnly,
        InvalidDirectAndRestore,
        LostResponseAndInvalidRestore,
        InvalidRestore {
            response_index: usize,
            mutation: InvalidRestore,
        },
        RejectedReplayThenDelayedOriginal,
    }

    struct ScriptedOpeningNetworking {
        inner: OpeningRecoveryHttpNetworking,
        scenario: OpeningOrchestrationScenario,
        swaps: Mutex<Vec<String>>,
        restores: Mutex<usize>,
    }

    impl ScriptedOpeningNetworking {
        fn call_opening_swap(&self, mint_url: &str, request: &str) -> anyhow::Result<String> {
            let mut swaps = self.swaps.lock().unwrap();
            swaps.push(request.to_string());
            match self.scenario {
                OpeningOrchestrationScenario::RejectedReplayThenDelayedOriginal => {
                    match swaps.len() {
                        // Neither call reaches the mint. The test submits the saved original
                        // later; this models uncertainty, not concurrent mint execution.
                        1 => {
                            // Replay authorization requires a strictly later wall-clock second.
                            std::thread::sleep(Duration::from_millis(1_100));
                            Err(anyhow::anyhow!("scripted original transport uncertainty"))
                        }
                        2 => Err(MintHttpRejection {
                            status: 400,
                            code: Some(12002),
                        }
                        .into()),
                        _ => panic!("unexpected successor or additional replay"),
                    }
                }
                OpeningOrchestrationScenario::InvalidDirectAndRestore
                | OpeningOrchestrationScenario::LostResponseAndInvalidRestore => {
                    assert_eq!(swaps.len(), 1);
                    self.inner.call_opening_swap(mint_url, request)?;
                    if matches!(
                        self.scenario,
                        OpeningOrchestrationScenario::LostResponseAndInvalidRestore
                    ) {
                        anyhow::bail!("lost successful opening response");
                    }
                    Ok("invalid direct swap JSON".to_string())
                }
                OpeningOrchestrationScenario::RestoreOnly
                | OpeningOrchestrationScenario::InvalidRestore { .. } => Err(anyhow::anyhow!(
                    "scripted guard: restore-only recovery must not submit"
                )),
            }
        }
    }

    impl SpilmanClientNetworking for ScriptedOpeningNetworking {
        fn call_mint_swap(&self, mint_url: &str, request: &str) -> Result<String, String> {
            self.call_opening_swap(mint_url, request)
                .map_err(|e| e.to_string())
        }

        fn call_mint_restore(&self, mint_url: &str, request: &str) -> Result<String, String> {
            let mut calls = self.restores.lock().unwrap();
            let index = *calls;
            *calls += 1;
            let response = self.inner.call_mint_restore(mint_url, request)?;
            if matches!(self.scenario, OpeningOrchestrationScenario::RestoreOnly) {
                let mut response: RestoreResponse = serde_json::from_str(&response).unwrap();
                response.outputs.reverse();
                response.signatures.reverse();
                return Ok(serde_json::to_string(&response).unwrap());
            }
            let mutation = match self.scenario {
                OpeningOrchestrationScenario::InvalidDirectAndRestore
                | OpeningOrchestrationScenario::LostResponseAndInvalidRestore => {
                    Some(InvalidRestore::Json)
                }
                OpeningOrchestrationScenario::InvalidRestore {
                    response_index,
                    mutation,
                } if response_index == index => Some(mutation),
                _ => None,
            };
            let Some(mutation) = mutation else {
                return Ok(response);
            };
            if matches!(mutation, InvalidRestore::Json) {
                return Ok("invalid restore JSON".to_string());
            }
            let mut response: serde_json::Value = serde_json::from_str(&response).unwrap();
            assert!(!response["signatures"].as_array().unwrap().is_empty());
            match mutation {
                InvalidRestore::Count => {
                    response["signatures"].as_array_mut().unwrap().pop();
                }
                InvalidRestore::Identity => {
                    response["outputs"][0]["B_"] = serde_json::json!(
                        "02a9acc1e48c25eeeb9289b5031cc57da9fe72f3fe2861d264bdc074209b107ba2"
                    )
                }
                InvalidRestore::Duplicate => {
                    for field in ["outputs", "signatures"] {
                        let values = response[field].as_array_mut().unwrap();
                        assert!(values.len() > 1);
                        values[1] = values[0].clone();
                    }
                }
                InvalidRestore::Partial => {
                    for field in ["outputs", "signatures"] {
                        let values = response[field].as_array_mut().unwrap();
                        assert!(values.len() > 1);
                        values.pop();
                    }
                }
                InvalidRestore::Absent => {
                    response["outputs"] = serde_json::json!([]);
                    response["signatures"] = serde_json::json!([]);
                }
                InvalidRestore::Signature => {
                    response["signatures"][0]["C_"] = serde_json::json!("invalid point")
                }
                InvalidRestore::IncorrectSignaturePoint => {
                    let original: cashu::nuts::BlindSignature =
                        serde_json::from_value(response["signatures"][0].clone()).unwrap();
                    assert!(original.dleq.is_some(), "mint must supply DLEQ evidence");
                    let point = response["signatures"][0]["C_"].as_str().unwrap();
                    // Negation is another valid curve point, but the original DLEQ
                    // evidence no longer proves this blinded signature.
                    let negated = format!(
                        "{}{}",
                        if point.starts_with("02") { "03" } else { "02" },
                        &point[2..]
                    );
                    response["signatures"][0]["C_"] = serde_json::json!(negated);
                    let mutated: cashu::nuts::BlindSignature =
                        serde_json::from_value(response["signatures"][0].clone()).unwrap();
                    assert_ne!(mutated.c, original.c);
                    assert_eq!(mutated.dleq, original.dleq);
                }
                InvalidRestore::Json => unreachable!(),
            }
            Ok(response.to_string())
        }

        fn call_mint_keysets(&self, mint_url: &str) -> Result<String, String> {
            self.inner.call_mint_keysets(mint_url)
        }

        fn call_mint_keys(&self, mint_url: &str, keyset_id: &str) -> Result<String, String> {
            self.inner.call_mint_keys(mint_url, keyset_id)
        }
    }

    impl OpeningRecoveryNetworking for ScriptedOpeningNetworking {
        fn call_opening_swap(&self, mint_url: &str, request: &str) -> anyhow::Result<String> {
            self.call_opening_swap(mint_url, request)
        }
        fn call_mint_check_state(&self, mint_url: &str, request: &str) -> Result<String, String> {
            self.inner.call_mint_check_state(mint_url, request)
        }
    }

    struct FourSubmissionNetworking {
        inner: OpeningRecoveryHttpNetworking,
        swap_requests: Mutex<Vec<String>>,
        check_state_requests: Mutex<Vec<CheckStateRequest>>,
    }

    impl FourSubmissionNetworking {
        fn new() -> Self {
            Self {
                inner: OpeningRecoveryHttpNetworking::new().unwrap(),
                swap_requests: Mutex::new(Vec::new()),
                check_state_requests: Mutex::new(Vec::new()),
            }
        }
    }

    impl FourSubmissionNetworking {
        fn call_opening_swap(&self, mint_url: &str, request_json: &str) -> anyhow::Result<String> {
            let call_index = {
                let mut requests = self.swap_requests.lock().unwrap();
                requests.push(request_json.to_string());
                requests.len() - 1
            };
            match call_index {
                0 | 2 => {
                    std::thread::sleep(Duration::from_millis(1_100));
                    Err(anyhow::anyhow!(
                        "injected transport loss before mint submission"
                    ))
                }
                1 | 3 => self.inner.call_opening_swap(mint_url, request_json),
                _ => Err(anyhow::anyhow!(
                    "unexpected swap submission {}",
                    call_index + 1
                )),
            }
        }
    }

    impl SpilmanClientNetworking for FourSubmissionNetworking {
        fn call_mint_swap(&self, mint_url: &str, request: &str) -> Result<String, String> {
            self.call_opening_swap(mint_url, request)
                .map_err(|e| e.to_string())
        }

        fn call_mint_restore(&self, mint_url: &str, request_json: &str) -> Result<String, String> {
            self.inner.call_mint_restore(mint_url, request_json)
        }

        fn call_mint_keysets(&self, mint_url: &str) -> Result<String, String> {
            self.inner.call_mint_keysets(mint_url)
        }

        fn call_mint_keys(&self, mint_url: &str, keyset_id: &str) -> Result<String, String> {
            self.inner.call_mint_keys(mint_url, keyset_id)
        }
    }

    impl OpeningRecoveryNetworking for FourSubmissionNetworking {
        fn call_opening_swap(&self, mint_url: &str, request: &str) -> anyhow::Result<String> {
            self.call_opening_swap(mint_url, request)
        }
        fn call_mint_check_state(
            &self,
            mint_url: &str,
            request_json: &str,
        ) -> Result<String, String> {
            let request: CheckStateRequest =
                serde_json::from_str(request_json).map_err(|e| e.to_string())?;
            self.check_state_requests.lock().unwrap().push(request);
            self.inner.call_mint_check_state(mint_url, request_json)
        }
    }

    fn prepared_opening_with_input_secrets(secrets: &[&str]) -> PreparedOpenChannel {
        let keyset_id =
            test_keyset_id("0101010101010101010101010101010101010101010101010101010101010101");
        let c = "02a9acc1e48c25eeeb9289b5031cc57da9fe72f3fe2861d264bdc074209b107ba2"
            .parse()
            .unwrap();
        let proofs = secrets
            .iter()
            .map(|secret| Proof {
                amount: cashu::Amount::from(1),
                keyset_id,
                secret: cashu::secret::Secret::new((*secret).to_string()),
                c,
                witness: None,
                dleq: None,
                p2pk_e: None,
            })
            .collect::<Vec<_>>();
        PreparedOpenChannel {
            channel_id: "channel".to_string(),
            mint_url: "http://mint".to_string(),
            swap_request_json: "{}".to_string(),
            opening: ClientChannelOpeningFromSwap {
                params_json: "{}".to_string(),
                channel_secret_hex: "secret".to_string(),
                keyset_info_json: "{}".to_string(),
                sender_pubkey_hex: "sender".to_string(),
                receiver_pubkey_hex: "receiver".to_string(),
                capacity: 1,
                funding_token_amount: 1,
                mint_url: "http://mint".to_string(),
                unit: "sat".to_string(),
                input_token: serde_json::to_string(&proofs).unwrap(),
                change_secrets_json: "[]".to_string(),
                change_amount_raw: 0,
                created_at: 1,
            },
            funding_secrets_json: "[]".to_string(),
            change_secrets_json: "[]".to_string(),
            keyset_id: keyset_id.to_string(),
        }
    }

    fn journal_prepared_opening_for_authority_test(
        wallet: &SqliteClientWallet,
        prepared: &PreparedOpenChannel,
    ) -> OpeningSubmissionPermit {
        let proofs: Vec<Proof> = serde_json::from_str(&prepared.opening.input_token).unwrap();
        let records = proofs
            .iter()
            .map(|proof| NewLooseProof {
                proof_id: proof.y().unwrap().to_hex(),
                mint_url: prepared.mint_url.clone(),
                unit: "sat".to_string(),
                keyset_id: proof.keyset_id.to_string(),
                amount_raw: u64::from(proof.amount),
                proof_json: serde_json::to_string(proof).unwrap(),
                source_quote_id: None,
                source_batch_id: None,
            })
            .collect::<Vec<_>>();
        wallet.loose_wallet().import_proofs(&records).unwrap();
        let proof_ids = records
            .iter()
            .map(|proof| proof.proof_id.clone())
            .collect::<Vec<_>>();
        wallet
            .loose_wallet()
            .reserve_selected_proofs_with_opening_attempt(
                &prepared.mint_url,
                "sat",
                &proof_ids,
                &NewOpeningAttempt {
                    attempt_id: prepared.channel_id.clone(),
                    opening_id: prepared.channel_id.clone(),
                    predecessor_attempt_id: None,
                    reservation_id: "reservation".to_string(),
                    receiver_pubkey: "receiver".to_string(),
                    mint_url: prepared.mint_url.clone(),
                    unit: "sat".to_string(),
                    funding_token_target_msats: 1_000,
                    expiry_timestamp: 123_456,
                    prepared_open_json: serde_json::to_string(prepared).unwrap(),
                    selected_proof_ids: proof_ids.clone(),
                },
            )
            .unwrap();
        let OpeningSubmissionClaim::Acquired(permit) = wallet
            .loose_wallet()
            .claim_opening_attempt_submission(&prepared.channel_id)
            .unwrap()
        else {
            panic!("submission claim not acquired");
        };
        permit
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

    #[tokio::test(flavor = "multi_thread")]
    async fn read_only_inspection_needs_no_sender_secret_and_cannot_write() {
        let temp = tempfile::tempdir().unwrap();
        let loose_db = temp.path().join("loose.sqlite");
        let channel_db = temp.path().join("channels.sqlite");
        let loose_wallet = LooseProofWallet::open(&loose_db, "alice").unwrap();
        loose_wallet
            .import_proofs(&[NewLooseProof {
                proof_id: "proof-1".to_string(),
                mint_url: "https://mint.example".to_string(),
                unit: "sat".to_string(),
                keyset_id: "00abcd".to_string(),
                amount_raw: 8,
                proof_json: "{}".to_string(),
                source_quote_id: None,
                source_batch_id: None,
            }])
            .unwrap();
        drop(SqliteClientWallet::open(loose_wallet, &channel_db, &sender_secret_hex()).unwrap());

        let inspection = ClientWalletInspection::open(&loose_db, &channel_db, "alice").unwrap();
        let summaries = inspection.list_available_proof_summaries().unwrap();
        assert_eq!(summaries.len(), 1);
        assert_eq!(summaries[0].amount_raw, 8);
        assert!(inspection.list_channels().unwrap().is_empty());
        let conn = inspection.channel_db.lock().unwrap();
        assert!(conn
            .execute("CREATE TABLE forbidden(value INTEGER)", [])
            .is_err());
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn read_only_channel_inspection_rejects_malformed_upstream_json() {
        let temp = tempfile::tempdir().unwrap();
        let loose_db = temp.path().join("loose.sqlite");
        let channel_db = temp.path().join("channels.sqlite");
        let loose_wallet = LooseProofWallet::open(&loose_db, "alice").unwrap();
        drop(SqliteClientWallet::open(loose_wallet, &channel_db, &sender_secret_hex()).unwrap());

        let conn = Connection::open(&channel_db).unwrap();
        conn.execute(
            "INSERT INTO monad_client_channels
             (channel_id, receiver_pubkey, mint_url, unit, keyset_id, capacity_msats,
              attached_session_id, state, reservation_id, expiry_timestamp, created_at, updated_at)
             VALUES ('corrupt', 'receiver', 'https://mint.example', 'sat', 'keyset', 1000,
                     NULL, 'open', NULL, 100, 1, 1)",
            [],
        )
        .unwrap();
        conn.execute(
            "INSERT INTO spilman_client_channels
             (channel_id, state, opening_json, funding_json, payment_json, failure_json)
             VALUES ('corrupt', 'Open', NULL, '{not-json', NULL, NULL)",
            [],
        )
        .unwrap();
        drop(conn);

        let inspection = ClientWalletInspection::open(&loose_db, &channel_db, "alice").unwrap();
        let error = inspection.list_channels().unwrap_err().to_string();
        assert!(error.contains("decode upstream channel corrupt funding"));
    }

    fn offer(mint_url: &str, receiver_pubkey: &str, keyset_id: &str) -> RelayPaymentOffer {
        RelayPaymentOffer {
            receiver_pubkey: receiver_pubkey.to_string(),
            mint_url: mint_url.to_string(),
            unit: "sat".to_string(),
            preferred_keyset_ids: vec![keyset_id.to_string()],
            negotiated_keyset_versions: BTreeSet::from(["v1".to_string(), "v2".to_string()]),
            in_bytes_per_millisat: 1,
            out_bytes_per_millisat: 1,
        }
    }

    fn selection_proof(id: &str, keyset_id: &str, amount_raw: u64) -> LooseProofRecord {
        LooseProofRecord {
            proof_id: id.to_string(),
            wallet_name: "alice".to_string(),
            mint_url: "https://mint.example".to_string(),
            unit: "sat".to_string(),
            keyset_id: keyset_id.to_string(),
            amount_raw,
            proof_json: "{}".to_string(),
            state: LooseProofState::Available,
            source_quote_id: None,
            source_batch_id: None,
            reserved_by: None,
            spent_channel_id: None,
            created_at: 0,
            updated_at: 0,
        }
    }

    #[test]
    fn plain_selection_refreshes_missing_metadata_once() {
        let proofs = vec![
            selection_proof("small", "missing", 1),
            selection_proof("large", "known", 10),
        ];
        let refreshes = std::cell::Cell::new(0);
        let selection = select_plain_inputs_refreshing_once(
            &proofs,
            HashMap::from([("known".to_string(), 0)]),
            10,
            || {
                refreshes.set(refreshes.get() + 1);
                Ok(HashMap::from([
                    ("known".to_string(), 0),
                    ("missing".to_string(), 0),
                ]))
            },
        )
        .unwrap();
        assert_eq!(refreshes.get(), 1);
        assert_eq!(selection.proof_ids, vec!["small", "large"]);
    }

    #[test]
    fn plain_selection_reports_metadata_unavailable_after_one_refresh() {
        let proofs = vec![selection_proof("small", "missing", 1)];
        let refreshes = std::cell::Cell::new(0);
        let error = select_plain_inputs_refreshing_once(&proofs, HashMap::new(), 1, || {
            refreshes.set(refreshes.get() + 1);
            Ok(HashMap::new())
        })
        .unwrap_err();
        assert_eq!(refreshes.get(), 1);
        assert_eq!(
            error,
            ProofSelectionError::InputKeysetMetadataUnavailable {
                keyset_ids: vec!["missing".to_string()]
            }
        );
    }

    #[test]
    fn plain_selection_stays_blocked_when_refresh_fails_before_target() {
        let proofs = vec![
            selection_proof("small", "missing", 1),
            selection_proof("large", "known", 10),
        ];
        let error = select_plain_inputs_refreshing_once(
            &proofs,
            HashMap::from([("known".to_string(), 0)]),
            10,
            || Err("refresh unavailable".to_string()),
        )
        .unwrap_err();
        assert_eq!(
            error,
            ProofSelectionError::InputKeysetMetadataUnavailable {
                keyset_ids: vec!["missing".to_string()]
            }
        );
    }

    #[test]
    fn exact_selection_uses_sufficient_known_subset_when_refresh_fails() {
        let proofs = vec![
            selection_proof("known", "known", 10),
            selection_proof("unknown", "missing", 100),
        ];
        let selection = select_exact_inputs_refreshing_once(
            &proofs,
            HashMap::from([("known".to_string(), 0)]),
            10,
            || Err("refresh unavailable".to_string()),
        )
        .unwrap();
        assert_eq!(selection.proof_ids, vec!["known"]);
    }

    #[test]
    fn exact_selection_reports_metadata_unavailable_when_known_subset_is_insufficient() {
        let proofs = vec![
            selection_proof("known", "known", 9),
            selection_proof("unknown", "missing", 100),
        ];
        let error = select_exact_inputs_refreshing_once(
            &proofs,
            HashMap::from([("known".to_string(), 0)]),
            10,
            || Err("refresh unavailable".to_string()),
        )
        .unwrap_err();
        assert_eq!(
            error,
            ProofSelectionError::InputKeysetMetadataUnavailable {
                keyset_ids: vec!["missing".to_string()]
            }
        );
    }

    #[test]
    fn selection_overflow_is_typed_as_safe_preflight() {
        let offer = offer(
            "https://mint.example",
            "02a9acc1e48c25eeeb9289b5031cc57da9fe72f3fe2861d264bdc074209b107ba2",
            "0000000000000001",
        );
        assert!(matches!(
            map_proof_selection_error(ProofSelectionError::Overflow, &offer),
            WalletError::ProvisioningPreflight { .. }
        ));
    }

    #[test]
    fn plain_selection_does_not_refresh_unknown_metadata_after_target() {
        let proofs = vec![
            selection_proof("enough", "known", 10),
            selection_proof("later", "missing", 20),
        ];
        let refreshes = std::cell::Cell::new(0);
        let selection = select_plain_inputs_refreshing_once(
            &proofs,
            HashMap::from([("known".to_string(), 0)]),
            10,
            || {
                refreshes.set(refreshes.get() + 1);
                Ok(HashMap::new())
            },
        )
        .unwrap();
        assert_eq!(refreshes.get(), 0);
        assert_eq!(selection.proof_ids, vec!["enough"]);
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn plain_gross_insufficiency_precedes_network_and_reservation() {
        let temp = tempfile::tempdir().unwrap();
        let loose_wallet =
            LooseProofWallet::open(temp.path().join("loose.sqlite"), "alice").unwrap();
        loose_wallet
            .import_proofs(&[NewLooseProof {
                proof_id: "proof-a".to_string(),
                mint_url: "http://127.0.0.1:1".to_string(),
                unit: "sat".to_string(),
                keyset_id: "0000000000000001".to_string(),
                amount_raw: 1,
                proof_json: "{}".to_string(),
                source_quote_id: None,
                source_batch_id: None,
            }])
            .unwrap();
        let wallet = SqliteClientWallet::open(
            loose_wallet,
            temp.path().join("channels.sqlite"),
            &sender_secret_hex(),
        )
        .unwrap();
        let error = wallet
            .provision_channel(
                &offer(
                    "http://127.0.0.1:1",
                    "02a9acc1e48c25eeeb9289b5031cc57da9fe72f3fe2861d264bdc074209b107ba2",
                    "0000000000000001",
                ),
                2_000,
            )
            .unwrap_err();
        assert!(matches!(
            error,
            WalletError::InsufficientLooseProofFunds {
                requested_raw: 2,
                available_raw: 1,
                ..
            }
        ));
        assert_eq!(
            wallet
                .loose_wallet()
                .list_available_proofs("http://127.0.0.1:1", "sat", &[])
                .unwrap()
                .len(),
            1
        );
        assert!(wallet
            .loose_wallet()
            .opening_attempts_for_recovery()
            .unwrap()
            .is_empty());
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
            ReqwestClientNetworking::new(MINT_HTTP_REQUEST_TIMEOUT)
                .expect("construct bridge HTTP networking"),
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

        let receiver_pubkey = SecretKey::from_hex(hex::encode([2; 32]))
            .unwrap()
            .public_key()
            .to_hex();
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
            mint_helper,
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

    fn refund_test_locks(ctx: &OpenedTestChannel) -> crate::wallet_lock::ClientWalletLocks {
        crate::wallet_lock::ClientWalletLocks::acquire(
            &ctx.loose_db,
            &ctx.channel_db,
            crate::wallet_lock::WalletLockMode::Maintenance,
        )
        .unwrap()
    }

    fn scripted_refund_mint(ctx: &OpenedTestChannel) -> ScriptedRefundMint {
        ScriptedRefundMint {
            inner: direct_mint_connection(ctx),
            requests: Mutex::new(vec![]),
            lose_response: false,
            reject_replay: false,
            invalid_restore: false,
            fail_state: false,
            fail_second_submit: false,
            complete_on_state: Mutex::new(None),
            close_on_submit: Mutex::new(None),
            empty_restore: false,
            restore_calls: AtomicUsize::new(0),
            hide_funding_witness: false,
        }
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn refund_rotations_before_and_after_preparation_use_independent_output_keys() {
        for prepare_before_rotation in [false, true] {
            let ctx = open_short_expiry_test_channel(32, 1).await;
            wait_until_expired(ctx.expiry_timestamp).await;
            let funding = ctx
                .wallet
                .bridge
                .lock()
                .unwrap()
                .get_channel_funding(&ctx.channel_id)
                .unwrap();
            let established = EstablishedChannel::from_client_channel_funding(&funding).unwrap();
            let old = if prepare_before_rotation {
                Some(
                    ctx.wallet
                        .prepare_and_persist_refund_recovery(
                            &ctx.channel_id,
                            &established,
                            SqliteClientWallet::now_seconds().unwrap(),
                        )
                        .unwrap(),
                )
            } else {
                None
            };
            let rotated = rotate_sat_keyset(&ctx.mint_helper.mint(), 400)
                .await
                .unwrap();
            if !prepare_before_rotation {
                ctx.wallet
                    .select_refund_output_keyset(&established, true)
                    .unwrap();
            }
            let mut mint = scripted_refund_mint(&ctx);
            mint.fail_second_submit = prepare_before_rotation;
            let locks = refund_test_locks(&ctx);
            let result = ctx
                .wallet
                .recover_channel_funds(&locks.exclusive_access().unwrap(), &ctx.channel_id, &mint)
                .await
                .unwrap();
            assert!(matches!(
                result,
                ChannelFundRecoveryResult::PostExpiryRefundRecovered { .. }
            ));
            let prepared = PreparedSenderRefund::from_json(
                &prepared_refund_json(&ctx.wallet, &ctx.channel_id).unwrap(),
            )
            .unwrap();
            assert_eq!(prepared.output_keyset.keyset_id, rotated);
            assert_eq!(
                prepared
                    .swap_request
                    .inputs()
                    .iter()
                    .map(|p| (p.keyset_id, p.amount, p.secret.clone()))
                    .collect::<Vec<_>>(),
                established
                    .funding_proofs
                    .iter()
                    .map(|p| (p.keyset_id, p.amount, p.secret.clone()))
                    .collect::<Vec<_>>()
            );
            let predecessors: i64 = ctx
                .wallet
                .conn()
                .unwrap()
                .query_row(
                    "SELECT COUNT(*) FROM monad_client_refund_predecessors",
                    [],
                    |r| r.get(0),
                )
                .unwrap();
            assert_eq!(predecessors, i64::from(prepare_before_rotation));
            assert_eq!(
                mint.requests.lock().unwrap().len(),
                if prepare_before_rotation { 3 } else { 1 }
            );
            if let Some(old) = old {
                let requests = mint.requests.lock().unwrap();
                assert_eq!(requests[1], requests[2]);
                assert_ne!(old.derivation_context, prepared.derivation_context);
                assert_eq!(old.output_amount_raw, prepared.output_amount_raw);
                let stored: String = ctx
                    .wallet
                    .conn()
                    .unwrap()
                    .query_row(
                        "SELECT prepared_json FROM monad_client_refund_predecessors",
                        [],
                        |r| r.get(0),
                    )
                    .unwrap();
                assert_eq!(stored, old.to_json().unwrap());
            }
            let _ = ctx.shutdown_tx.send(());
            ctx.mint_task.await.unwrap().unwrap();
        }
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn refund_lost_response_restores_without_second_submission() {
        let ctx = open_short_expiry_test_channel(16, 1).await;
        wait_until_expired(ctx.expiry_timestamp).await;
        let mut mint = scripted_refund_mint(&ctx);
        mint.lose_response = true;
        let locks = refund_test_locks(&ctx);
        let result = ctx
            .wallet
            .recover_channel_funds(&locks.exclusive_access().unwrap(), &ctx.channel_id, &mint)
            .await
            .unwrap();
        assert!(matches!(
            result,
            ChannelFundRecoveryResult::PostExpiryRefundRecovered { .. }
        ));
        assert_eq!(mint.requests.lock().unwrap().len(), 1);
        let _ = ctx.shutdown_tx.send(());
        ctx.mint_task.await.unwrap().unwrap();
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn refund_ambiguous_replay_rejection_never_creates_successor() {
        let ctx = open_short_expiry_test_channel(16, 1).await;
        wait_until_expired(ctx.expiry_timestamp).await;
        let mut mint = scripted_refund_mint(&ctx);
        mint.reject_replay = true;
        let locks = refund_test_locks(&ctx);
        for _ in 0..2 {
            let result = ctx
                .wallet
                .recover_channel_funds(&locks.exclusive_access().unwrap(), &ctx.channel_id, &mint)
                .await
                .unwrap();
            assert!(matches!(
                result,
                ChannelFundRecoveryResult::RecoveryRetryLater { .. }
            ));
        }
        {
            let requests = mint.requests.lock().unwrap();
            assert_eq!(requests.len(), 4);
            assert!(requests.iter().all(|r| r == &requests[0]));
        }
        {
            let conn = ctx.wallet.conn().unwrap();
            let successors: i64 = conn
                .query_row(
                    "SELECT COUNT(*) FROM monad_client_refund_predecessors",
                    [],
                    |r| r.get(0),
                )
                .unwrap();
            let uncertain: i64 = conn
                .query_row(
                    "SELECT COUNT(*) FROM monad_client_refund_executions WHERE outcome = 'uncertain'",
                    [],
                    |r| r.get(0),
                )
                .unwrap();
            assert_eq!(successors, 0);
            assert_eq!(uncertain, 4);
        }
        assert!(ctx
            .wallet
            .attach_channel_to_session(&ctx.channel_id, [1; 32])
            .is_err());
        let _ = ctx.shutdown_tx.send(());
        ctx.mint_task.await.unwrap().unwrap();
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn refund_invalid_restore_blocks_replay_and_restores_before_state_errors() {
        let ctx = open_short_expiry_test_channel(16, 1).await;
        wait_until_expired(ctx.expiry_timestamp).await;
        let funding = ctx
            .wallet
            .bridge
            .lock()
            .unwrap()
            .get_channel_funding(&ctx.channel_id)
            .unwrap();
        let established = EstablishedChannel::from_client_channel_funding(&funding).unwrap();
        let prepared = ctx
            .wallet
            .prepare_and_persist_refund_recovery(
                &ctx.channel_id,
                &established,
                SqliteClientWallet::now_seconds().unwrap(),
            )
            .unwrap();
        ctx.wallet
            .record_refund_execution(&ctx.channel_id, &prepared)
            .unwrap();
        let mut mint = scripted_refund_mint(&ctx);
        mint.invalid_restore = true;
        mint.fail_state = true;
        let locks = refund_test_locks(&ctx);
        let result = ctx
            .wallet
            .recover_channel_funds(&locks.exclusive_access().unwrap(), &ctx.channel_id, &mint)
            .await
            .unwrap();
        assert!(matches!(
            result,
            ChannelFundRecoveryResult::RecoveryRetryLater { .. }
        ));
        assert!(mint.requests.lock().unwrap().is_empty());
        established
            .submit_prepared_sender_refund(
                &prepared,
                &ctx.wallet.sender_secret,
                SqliteClientWallet::now_seconds().unwrap(),
                &mint.inner,
            )
            .await
            .unwrap();
        rotate_sat_keyset(&ctx.mint_helper.mint(), 400)
            .await
            .unwrap();
        mint.invalid_restore = false;
        let reopened = reopen_wallet(&ctx);
        let result = reopened
            .recover_channel_funds(&locks.exclusive_access().unwrap(), &ctx.channel_id, &mint)
            .await
            .unwrap();
        assert!(matches!(
            result,
            ChannelFundRecoveryResult::PostExpiryRefundRecovered { .. }
        ));
        assert!(mint.requests.lock().unwrap().is_empty());
        let _ = ctx.shutdown_tx.send(());
        ctx.mint_task.await.unwrap().unwrap();
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn refund_requires_matching_authority_and_singleflight() {
        let ctx = open_short_expiry_test_channel(16, 1).await;
        let other = tempfile::tempdir().unwrap();
        let wrong = crate::wallet_lock::ClientWalletLocks::acquire(
            other.path().join("loose"),
            other.path().join("channels"),
            crate::wallet_lock::WalletLockMode::Maintenance,
        )
        .unwrap();
        assert!(ctx
            .wallet
            .recover_channel_funds(
                &wrong.exclusive_access().unwrap(),
                &ctx.channel_id,
                &OfflineRefundMint
            )
            .await
            .unwrap_err()
            .to_string()
            .contains("different wallet"));
        let locks = refund_test_locks(&ctx);
        let guard = enter_active_opening(&format!(
            "refund:{}:{}",
            ctx.wallet.opening_scope, ctx.channel_id
        ))
        .unwrap();
        assert!(matches!(
            ctx.wallet
                .recover_channel_funds(
                    &locks.exclusive_access().unwrap(),
                    &ctx.channel_id,
                    &OfflineRefundMint
                )
                .await,
            Err(WalletError::OpeningInProgress { .. })
        ));
        drop(guard);
        wait_until_expired(ctx.expiry_timestamp).await;
        let access = locks.exclusive_access().unwrap();
        let mint = BlockingRefundMint {
            inner: direct_mint_connection(&ctx),
            entered: tokio::sync::Notify::new(),
        };
        let mut first = Box::pin(
            ctx.wallet
                .recover_channel_funds(&access, &ctx.channel_id, &mint),
        );
        tokio::select! {
            _ = mint.entered.notified() => {},
            result = &mut first => panic!("refund should block in submit: {result:?}"),
        }
        let reopened = reopen_wallet(&ctx);
        assert!(matches!(
            reopened
                .recover_channel_funds(&access, &ctx.channel_id, &OfflineRefundMint)
                .await,
            Err(WalletError::OpeningInProgress { .. })
        ));
        drop(first);
        let original = prepared_refund_json(&ctx.wallet, &ctx.channel_id).unwrap();
        rotate_sat_keyset(&ctx.mint_helper.mint(), 0).await.unwrap();
        let retry = scripted_refund_mint(&ctx);
        let result = reopened
            .recover_channel_funds(&access, &ctx.channel_id, &retry)
            .await
            .unwrap();
        assert!(matches!(
            result,
            ChannelFundRecoveryResult::RecoveryRetryLater { .. }
        ));
        assert_eq!(
            prepared_refund_json(&ctx.wallet, &ctx.channel_id).unwrap(),
            original
        );
        assert_eq!(retry.requests.lock().unwrap().len(), 2);
        assert!(!reopened
            .refund_has_initial_rejection(&ctx.channel_id)
            .unwrap());
        let _ = ctx.shutdown_tx.send(());
        ctx.mint_task.await.unwrap().unwrap();
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn refund_finalization_resumes_offline_at_local_database_boundaries() {
        for trigger in [
            "CREATE TRIGGER fail_finalize BEFORE UPDATE ON monad_client_channels WHEN NEW.state = 'closed' BEGIN SELECT RAISE(ABORT, 'injected metadata failure'); END",
            "CREATE TRIGGER fail_finalize BEFORE UPDATE ON monad_client_channel_recoveries WHEN NEW.status = 'completed' BEGIN SELECT RAISE(ABORT, 'injected completion failure'); END",
        ] {
            let ctx = open_short_expiry_test_channel(16, 1).await;
            wait_until_expired(ctx.expiry_timestamp).await;
            ctx.wallet.conn().unwrap().execute_batch(trigger).unwrap();
            let locks = refund_test_locks(&ctx);
            let mint = scripted_refund_mint(&ctx);
            assert!(ctx.wallet.recover_channel_funds(&locks.exclusive_access().unwrap(), &ctx.channel_id, &mint).await.is_err());
            assert_eq!(recovery_row_status(&ctx.wallet, &ctx.channel_id), "finalizing");
            assert_eq!(mint.requests.lock().unwrap().len(), 1);
            let json: String = ctx.wallet.conn().unwrap().query_row("SELECT completed_proofs_json FROM monad_client_channel_recoveries WHERE channel_id = ?1", [&ctx.channel_id], |r| r.get(0)).unwrap();
            ctx.wallet.conn().unwrap().execute_batch("DROP TRIGGER fail_finalize").unwrap();
            let reopened = reopen_wallet(&ctx);
            let result = reopened.recover_channel_funds(&locks.exclusive_access().unwrap(), &ctx.channel_id, &OfflineRefundMint).await.unwrap();
            assert!(matches!(result, ChannelFundRecoveryResult::PostExpiryRefundRecovered { .. }));
            let stored: String = reopened.conn().unwrap().query_row("SELECT completed_proofs_json FROM monad_client_channel_recoveries WHERE channel_id = ?1", [&ctx.channel_id], |r| r.get(0)).unwrap();
            assert_eq!(stored, json);
            assert!(matches!(reopened.recover_channel_funds(&locks.exclusive_access().unwrap(), &ctx.channel_id, &OfflineRefundMint).await.unwrap(), ChannelFundRecoveryResult::AlreadyRecovered { .. }));
            let _ = ctx.shutdown_tx.send(());
            ctx.mint_task.await.unwrap().unwrap();
        }
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn refund_successor_persistence_failure_retains_initial_rejection_authority() {
        let ctx = open_short_expiry_test_channel(16, 1).await;
        wait_until_expired(ctx.expiry_timestamp).await;
        let funding = ctx
            .wallet
            .bridge
            .lock()
            .unwrap()
            .get_channel_funding(&ctx.channel_id)
            .unwrap();
        let established = EstablishedChannel::from_client_channel_funding(&funding).unwrap();
        let prepared = ctx
            .wallet
            .prepare_and_persist_refund_recovery(
                &ctx.channel_id,
                &established,
                SqliteClientWallet::now_seconds().unwrap(),
            )
            .unwrap();
        rotate_sat_keyset(&ctx.mint_helper.mint(), 0).await.unwrap();
        ctx.wallet.conn().unwrap().execute_batch("CREATE TRIGGER fail_successor BEFORE UPDATE ON monad_client_channel_recoveries WHEN NEW.status = 'prepared' AND OLD.status = 'submitting' BEGIN SELECT RAISE(ABORT, 'injected successor failure after predecessor insert'); END").unwrap();
        let locks = refund_test_locks(&ctx);
        let mint = scripted_refund_mint(&ctx);
        assert!(ctx
            .wallet
            .recover_channel_funds(&locks.exclusive_access().unwrap(), &ctx.channel_id, &mint)
            .await
            .is_err());
        assert_eq!(
            prepared_refund_json(&ctx.wallet, &ctx.channel_id).unwrap(),
            prepared.to_json().unwrap()
        );
        assert!(ctx
            .wallet
            .refund_has_initial_rejection(&ctx.channel_id)
            .unwrap());
        let predecessors: i64 = ctx
            .wallet
            .conn()
            .unwrap()
            .query_row(
                "SELECT COUNT(*) FROM monad_client_refund_predecessors",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(predecessors, 0);
        ctx.wallet
            .conn()
            .unwrap()
            .execute_batch("DROP TRIGGER fail_successor")
            .unwrap();
        let reopened = reopen_wallet(&ctx);
        let result = reopened
            .recover_channel_funds(&locks.exclusive_access().unwrap(), &ctx.channel_id, &mint)
            .await
            .unwrap();
        assert!(matches!(
            result,
            ChannelFundRecoveryResult::PostExpiryRefundRecovered { .. }
        ));
        assert_eq!(mint.requests.lock().unwrap().len(), 2);
        let _ = ctx.shutdown_tx.send(());
        ctx.mint_task.await.unwrap().unwrap();
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn refund_completion_between_restore_and_state_gets_final_exact_restore() {
        for hide_outputs in [false, true] {
            let ctx = open_short_expiry_test_channel(16, 1).await;
            wait_until_expired(ctx.expiry_timestamp).await;
            let funding = ctx
                .wallet
                .bridge
                .lock()
                .unwrap()
                .get_channel_funding(&ctx.channel_id)
                .unwrap();
            let established = EstablishedChannel::from_client_channel_funding(&funding).unwrap();
            let prepared = ctx
                .wallet
                .prepare_and_persist_refund_recovery(
                    &ctx.channel_id,
                    &established,
                    SqliteClientWallet::now_seconds().unwrap(),
                )
                .unwrap();
            ctx.wallet
                .record_refund_execution(&ctx.channel_id, &prepared)
                .unwrap();
            let mut mint = scripted_refund_mint(&ctx);
            *mint.complete_on_state.lock().unwrap() = Some(prepared.swap_request);
            mint.empty_restore = hide_outputs;
            mint.hide_funding_witness = !hide_outputs;
            let result = ctx
                .wallet
                .recover_channel_funds(
                    &refund_test_locks(&ctx).exclusive_access().unwrap(),
                    &ctx.channel_id,
                    &mint,
                )
                .await
                .unwrap();
            if hide_outputs {
                assert!(matches!(
                    result,
                    ChannelFundRecoveryResult::RecoveryRetryLater { .. }
                ));
                assert_eq!(
                    recovery_row_status(&ctx.wallet, &ctx.channel_id),
                    "submitting"
                );
            } else {
                assert!(matches!(
                    result,
                    ChannelFundRecoveryResult::PostExpiryRefundRecovered { .. }
                ));
            }
            assert_eq!(mint.restore_calls.load(Ordering::SeqCst), 2);
            assert!(mint.requests.lock().unwrap().is_empty());
            let _ = ctx.shutdown_tx.send(());
            ctx.mint_task.await.unwrap().unwrap();
        }
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn checked_sender_discovery_handles_extra_close_signature_and_close_winning_submit_race()
    {
        for mode in ["closed", "race", "empty", "invalid", "network"] {
            let ctx = open_short_expiry_test_channel(16, 1).await;
            wait_until_expired(ctx.expiry_timestamp).await;
            let funding = ctx
                .wallet
                .bridge
                .lock()
                .unwrap()
                .get_channel_funding(&ctx.channel_id)
                .unwrap();
            let established = EstablishedChannel::from_client_channel_funding(&funding).unwrap();
            let commitment =
                cdk_spilman::CommitmentOutputs::for_balance(5, &established.params).unwrap();
            let mut close = commitment
                .create_swap_request(established.funding_proofs.clone(), None)
                .unwrap();
            close
                .sign_sig_all(
                    established
                        .params
                        .get_sender_blinded_secret_key_for_stage1(&ctx.wallet.sender_secret)
                        .unwrap(),
                )
                .unwrap();
            close
                .sign_sig_all(
                    established
                        .params
                        .get_receiver_blinded_secret_key_for_stage1(
                            &SecretKey::from_hex(hex::encode([2; 32])).unwrap(),
                        )
                        .unwrap(),
                )
                .unwrap();
            close.sign_sig_all(SecretKey::generate()).unwrap();
            let mut mint = scripted_refund_mint(&ctx);
            if mode == "race" {
                *mint.close_on_submit.lock().unwrap() = Some(close);
            } else {
                mint.inner.process_swap(close).await.unwrap();
            }
            mint.empty_restore = mode == "empty";
            mint.invalid_restore = mode == "invalid";
            let locks = refund_test_locks(&ctx);
            let access = locks.exclusive_access().unwrap();
            let result = if mode == "network" {
                ctx.wallet
                    .recover_channel_funds(
                        &access,
                        &ctx.channel_id,
                        &FailingRefundMintConnection {
                            inner: direct_mint_connection(&ctx),
                        },
                    )
                    .await
                    .unwrap()
            } else {
                ctx.wallet
                    .recover_channel_funds(&access, &ctx.channel_id, &mint)
                    .await
                    .unwrap()
            };
            let state = established
                .check_funding_token_state(&mint.inner)
                .await
                .unwrap();
            assert_eq!(state.state, State::Spent);
            assert_eq!(
                EstablishedChannel::classify_funding_spend_witness(&state),
                FundingSpendKind::Unknown
            );
            match mode {
                "empty" => assert_eq!(result, ChannelFundRecoveryResult::UnknownSpent),
                "invalid" | "network" => assert!(matches!(
                    result,
                    ChannelFundRecoveryResult::RecoveryRetryLater { .. }
                )),
                _ => {
                    let ChannelFundRecoveryResult::RelayCloseRecovered {
                        recovered_amount_raw,
                        ..
                    } = result
                    else {
                        panic!("expected checked sender discovery: {result:?}");
                    };
                    assert!(recovered_amount_raw > 0);
                    if mode == "race" {
                        assert_eq!(mint.requests.lock().unwrap().len(), 1);
                        assert!(prepared_refund_json(&ctx.wallet, &ctx.channel_id).is_some());
                        let count: i64 = ctx.wallet.conn().unwrap().query_row("SELECT COUNT(*) FROM monad_client_refund_executions WHERE outcome = 'uncertain'", [], |r| r.get(0)).unwrap();
                        assert_eq!(count, 1);
                    }
                }
            }
            let _ = ctx.shutdown_tx.send(());
            ctx.mint_task.await.unwrap().unwrap();
        }
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn refund_import_conflict_remains_finalizing_and_offline_retry_never_resurrects_spent() {
        let ctx = open_short_expiry_test_channel(16, 1).await;
        wait_until_expired(ctx.expiry_timestamp).await;
        ctx.wallet.fail_next_recovered_proof_import_for_test();
        let locks = refund_test_locks(&ctx);
        let access = locks.exclusive_access().unwrap();
        assert!(ctx
            .wallet
            .recover_channel_funds(&access, &ctx.channel_id, &direct_mint_connection(&ctx))
            .await
            .is_err());
        let json: String = ctx.wallet.conn().unwrap().query_row("SELECT completed_proofs_json FROM monad_client_channel_recoveries WHERE channel_id = ?1", [&ctx.channel_id], |r| r.get(0)).unwrap();
        let proofs: Vec<Proof> = serde_json::from_str(&json).unwrap();
        let funding = ctx
            .wallet
            .bridge
            .lock()
            .unwrap()
            .get_channel_funding(&ctx.channel_id)
            .unwrap();
        let original = proof_to_new_loose_proof(&proofs[0], &funding).unwrap();
        ctx.wallet
            .loose_wallet
            .import_proofs(std::slice::from_ref(&original))
            .unwrap();
        let reservation = ctx
            .wallet
            .loose_wallet
            .reserve_proofs(&ctx.mint_url, "sat", &[], original.amount_raw)
            .unwrap();
        ctx.wallet
            .loose_wallet
            .mark_reservation_spent(&reservation.reservation_id, "already-spent")
            .unwrap();
        // A conflicting existing bearer record must not be ignored, even spent.
        let db = Connection::open(&ctx.loose_db).unwrap();
        db.execute("UPDATE monad_client_loose_proofs SET amount_raw = amount_raw + 1 WHERE proof_id = ?1 AND wallet_name = 'alice'", [&original.proof_id]).unwrap();
        let reopened = reopen_wallet(&ctx);
        let error = reopened
            .recover_channel_funds(&access, &ctx.channel_id, &OfflineRefundMint)
            .await
            .unwrap_err();
        assert!(error
            .to_string()
            .contains("immutable imported proof conflict"));
        assert_eq!(
            recovery_row_status(&ctx.wallet, &ctx.channel_id),
            "finalizing"
        );
        db.execute("UPDATE monad_client_loose_proofs SET amount_raw = ?2 WHERE proof_id = ?1 AND wallet_name = 'alice'", params![original.proof_id, original.amount_raw]).unwrap();
        assert!(matches!(
            reopened
                .recover_channel_funds(&access, &ctx.channel_id, &OfflineRefundMint)
                .await
                .unwrap(),
            ChannelFundRecoveryResult::PostExpiryRefundRecovered { .. }
        ));
        let state: String = db.query_row("SELECT state FROM monad_client_loose_proofs WHERE proof_id = ?1 AND wallet_name = 'alice'", [&original.proof_id], |r| r.get(0)).unwrap();
        assert_eq!(state, "spent");
        assert!(!reopened
            .loose_wallet
            .list_available_proofs(&ctx.mint_url, "sat", &[])
            .unwrap()
            .iter()
            .any(|p| p.proof_id == original.proof_id));
        let _ = ctx.shutdown_tx.send(());
        ctx.mint_task.await.unwrap().unwrap();
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn refund_custody_binding_rejects_other_destinations_before_io_and_survives_aliases() {
        let ctx = open_short_expiry_test_channel(16, 1).await;
        wait_until_expired(ctx.expiry_timestamp).await;
        ctx.wallet.conn().unwrap().execute_batch("CREATE TRIGGER fail_completed BEFORE UPDATE ON monad_client_channel_recoveries WHEN NEW.status = 'completed' BEGIN SELECT RAISE(ABORT, 'failure after import'); END").unwrap();
        let mint = scripted_refund_mint(&ctx);
        assert!(ctx
            .wallet
            .recover_channel_funds(
                &refund_test_locks(&ctx).exclusive_access().unwrap(),
                &ctx.channel_id,
                &mint
            )
            .await
            .is_err());
        assert_eq!(
            recovery_row_status(&ctx.wallet, &ctx.channel_id),
            "finalizing"
        );
        let imported = ctx
            .wallet
            .loose_wallet
            .list_available_proofs(&ctx.mint_url, "sat", &[])
            .unwrap();
        assert!(!imported.is_empty());
        let other_db = ctx._temp.path().join("other-loose.sqlite");
        for phase in ["finalizing", "completed"] {
            for (db, name, secret) in [
                (&ctx.loose_db, "bob", ctx.sender_secret.clone()),
                (&other_db, "alice", ctx.sender_secret.clone()),
                (&ctx.loose_db, "alice", hex::encode([42; 32])),
            ] {
                let wallet = SqliteClientWallet::open(
                    LooseProofWallet::open(db, name).unwrap(),
                    &ctx.channel_db,
                    &secret,
                )
                .unwrap();
                wallet.fail_next_recovered_proof_import_for_test();
                let locks = crate::wallet_lock::ClientWalletLocks::acquire(
                    db,
                    &ctx.channel_db,
                    crate::wallet_lock::WalletLockMode::Maintenance,
                )
                .unwrap();
                let error = wallet
                    .recover_channel_funds(
                        &locks.exclusive_access().unwrap(),
                        &ctx.channel_id,
                        &OfflineRefundMint,
                    )
                    .await
                    .unwrap_err();
                assert!(error.to_string().contains("custody destination mismatch"));
                assert!(wallet
                    .fail_next_recovered_proof_import
                    .load(Ordering::SeqCst));
                if name == "bob" || db == &other_db {
                    assert!(wallet
                        .loose_wallet
                        .list_available_proofs(&ctx.mint_url, "sat", &[])
                        .unwrap()
                        .is_empty());
                }
            }
            assert_eq!(recovery_row_status(&ctx.wallet, &ctx.channel_id), phase);
            if phase == "finalizing" {
                ctx.wallet
                    .conn()
                    .unwrap()
                    .execute_batch("DROP TRIGGER fail_completed")
                    .unwrap();
                let alias = ctx._temp.path().join("loose-alias.sqlite");
                #[cfg(unix)]
                std::os::unix::fs::symlink(&ctx.loose_db, &alias).unwrap();
                #[cfg(not(unix))]
                let alias = ctx.loose_db.clone();
                let wallet = SqliteClientWallet::open(
                    LooseProofWallet::open(&alias, "alice").unwrap(),
                    &ctx.channel_db,
                    &ctx.sender_secret,
                )
                .unwrap();
                let locks = crate::wallet_lock::ClientWalletLocks::acquire(
                    &alias,
                    &ctx.channel_db,
                    crate::wallet_lock::WalletLockMode::Maintenance,
                )
                .unwrap();
                assert!(matches!(
                    wallet
                        .recover_channel_funds(
                            &locks.exclusive_access().unwrap(),
                            &ctx.channel_id,
                            &OfflineRefundMint
                        )
                        .await
                        .unwrap(),
                    ChannelFundRecoveryResult::PostExpiryRefundRecovered { .. }
                ));
                assert_eq!(
                    wallet
                        .loose_wallet
                        .list_available_proofs(&ctx.mint_url, "sat", &[])
                        .unwrap()
                        .len(),
                    imported.len()
                );
            }
        }
        let _ = ctx.shutdown_tx.send(());
        ctx.mint_task.await.unwrap().unwrap();
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn refund_execution_rejection_and_finalizing_journal_failures_preserve_evidence() {
        for boundary in ["execution", "rejection", "finalizing"] {
            let ctx = open_short_expiry_test_channel(16, 1).await;
            wait_until_expired(ctx.expiry_timestamp).await;
            let funding = ctx
                .wallet
                .bridge
                .lock()
                .unwrap()
                .get_channel_funding(&ctx.channel_id)
                .unwrap();
            let established = EstablishedChannel::from_client_channel_funding(&funding).unwrap();
            let prepared = ctx
                .wallet
                .prepare_and_persist_refund_recovery(
                    &ctx.channel_id,
                    &established,
                    SqliteClientWallet::now_seconds().unwrap(),
                )
                .unwrap();
            let trigger = match boundary {
                "execution" => "CREATE TRIGGER fail_boundary BEFORE INSERT ON monad_client_refund_executions BEGIN SELECT RAISE(ABORT, 'execution insert failure'); END",
                "rejection" => "CREATE TRIGGER fail_boundary BEFORE UPDATE ON monad_client_refund_executions BEGIN SELECT RAISE(ABORT, 'rejection record failure'); END",
                _ => "CREATE TRIGGER fail_boundary BEFORE UPDATE ON monad_client_channel_recoveries WHEN NEW.status = 'finalizing' BEGIN SELECT RAISE(ABORT, 'verified proofs persistence failure'); END",
            };
            if boundary == "rejection" {
                rotate_sat_keyset(&ctx.mint_helper.mint(), 0).await.unwrap();
            }
            ctx.wallet.conn().unwrap().execute_batch(trigger).unwrap();
            let locks = refund_test_locks(&ctx);
            let mint = scripted_refund_mint(&ctx);
            assert!(ctx
                .wallet
                .recover_channel_funds(&locks.exclusive_access().unwrap(), &ctx.channel_id, &mint)
                .await
                .is_err());
            let count: i64 = ctx.wallet.conn().unwrap().query_row("SELECT COUNT(*) FROM monad_client_refund_executions WHERE outcome = 'uncertain'", [], |r| r.get(0)).unwrap();
            assert_eq!(
                mint.requests.lock().unwrap().len(),
                if boundary == "execution" { 0 } else { 1 }
            );
            assert_eq!(count, if boundary == "execution" { 0 } else { 1 });
            assert_eq!(
                recovery_row_status(&ctx.wallet, &ctx.channel_id),
                if boundary == "execution" {
                    "prepared"
                } else {
                    "submitting"
                }
            );
            assert_eq!(
                prepared_refund_json(&ctx.wallet, &ctx.channel_id).unwrap(),
                prepared.to_json().unwrap()
            );
            assert!(ctx
                .wallet
                .loose_wallet
                .list_available_proofs(&ctx.mint_url, "sat", &[])
                .unwrap()
                .is_empty());
            ctx.wallet
                .conn()
                .unwrap()
                .execute_batch("DROP TRIGGER fail_boundary")
                .unwrap();
            let reopened = reopen_wallet(&ctx);
            let result = reopened
                .recover_channel_funds(&locks.exclusive_access().unwrap(), &ctx.channel_id, &mint)
                .await
                .unwrap();
            if boundary == "rejection" {
                assert!(matches!(
                    result,
                    ChannelFundRecoveryResult::RecoveryRetryLater { .. }
                ));
                assert_eq!(mint.requests.lock().unwrap().len(), 3);
                assert_eq!(
                    prepared_refund_json(&ctx.wallet, &ctx.channel_id).unwrap(),
                    prepared.to_json().unwrap()
                );
            } else {
                assert!(matches!(
                    result,
                    ChannelFundRecoveryResult::PostExpiryRefundRecovered { .. }
                ));
                assert_eq!(mint.requests.lock().unwrap().len(), 1);
            }
            let _ = ctx.shutdown_tx.send(());
            ctx.mint_task.await.unwrap().unwrap();
        }
    }

    #[test]
    fn mint_rejection_requires_structured_direct_inactive_keyset_code() {
        for (status, body, expected) in [
            (400, r#"{"code":12002}"#, true),
            (500, r#"{"code":12002}"#, false),
            (200, r#"{"code":12002}"#, false),
            (400, r#"{"code":12001}"#, false),
            (400, r#"{"code":"12002"}"#, false),
            (400, r#"{"detail":"12002"}"#, false),
            (400, "upstream: {\"code\":12002}", false),
            (400, r#"{"code":12002.0}"#, false),
            (400, r#"{"code":-12002}"#, false),
            (400, r#"{"code":11001,"detail":"12002"}"#, false),
            (400, r#"{"code":12002} trailing"#, false),
        ] {
            let rejection = MintHttpRejection::from_body(status, body);
            assert_eq!(rejection.inactive_output_keyset(), expected);
            assert!(!format!("{rejection:?}").contains(body));
        }
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn opening_http_rejection_preserves_only_status_and_numeric_code() {
        for (status, body, code, definitive) in [
            (
                400,
                r#"{"code":12002,"detail":"secret mint body"}"#,
                Some(12002),
                true,
            ),
            (
                503,
                r#"{"code":12002,"detail":"secret mint body"}"#,
                Some(12002),
                false,
            ),
            (
                400,
                r#"{"code":"12002","detail":"secret mint body"}"#,
                None,
                false,
            ),
            (400, "secret mint body with 12002", None, false),
            (
                400,
                r#"{"code":12001,"detail":"secret mint body"}"#,
                Some(12001),
                false,
            ),
        ] {
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let url = format!("http://{}", listener.local_addr().unwrap());
            let app = axum::Router::new().route(
                "/v1/swap",
                axum::routing::post(move || async move {
                    (http::StatusCode::from_u16(status).unwrap(), body)
                }),
            );
            let (shutdown, stopped) = oneshot::channel();
            let task = tokio::spawn(async move {
                axum::serve(listener, app)
                    .with_graceful_shutdown(async {
                        let _ = stopped.await;
                    })
                    .await
                    .unwrap();
            });
            let networking = OpeningRecoveryHttpNetworking::new().unwrap();
            let error = networking.call_opening_swap(&url, "{}").unwrap_err();
            let rejection = error.downcast_ref::<MintHttpRejection>().unwrap();
            assert_eq!(rejection.status, status);
            assert_eq!(rejection.code, code);
            assert_eq!(rejection.inactive_output_keyset(), definitive);
            assert!(!format!("{error:?}").contains("secret mint body"));
            assert!(!error.to_string().contains("secret mint body"));
            // The string-only upstream interface does not recreate typed authority.
            let string_error = networking.call_mint_swap(&url, "{}").unwrap_err();
            assert!(!string_error.contains("secret mint body"));
            shutdown.send(()).unwrap();
            task.await.unwrap();
        }
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn refund_nonempty_legacy_journal_is_rejected_without_deleting_rows() {
        let temp = tempfile::tempdir().unwrap();
        let channel_db = temp.path().join("channels.sqlite");
        let conn = Connection::open(&channel_db).unwrap();
        conn.execute_batch("CREATE TABLE monad_client_channel_recoveries(channel_id TEXT, prepared_refund_json TEXT); INSERT INTO monad_client_channel_recoveries VALUES ('original', 'immutable old data')").unwrap();
        let loose = LooseProofWallet::open(temp.path().join("loose.sqlite"), "alice").unwrap();
        let error = SqliteClientWallet::open(loose, &channel_db, &sender_secret_hex())
            .err()
            .unwrap();
        assert!(
            error
                .to_string()
                .contains("incompatible nonempty refund journal"),
            "{error}"
        );
        let original: String = conn
            .query_row(
                "SELECT prepared_refund_json FROM monad_client_channel_recoveries",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(original, "immutable old data");
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
            .recover_channel_funds(
                &refund_test_locks(&ctx).exclusive_access().unwrap(),
                &ctx.channel_id,
                &mint_connection,
            )
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
            .recover_channel_funds(
                &refund_test_locks(&ctx).exclusive_access().unwrap(),
                &ctx.channel_id,
                &mint_connection,
            )
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
                 (channel_id, kind, status, recovered_amount_raw, recovered_proof_count, prepared_refund_json, created_at, updated_at, custody_db, custody_wallet, custody_sender)
                 VALUES (?1, 'post_expiry_refund', 'bogus', NULL, NULL, NULL, ?2, ?2, ?3, ?4, ?5)",
                params![ctx.channel_id, to_i64(now).unwrap(), ctx.wallet.recovery_custody().unwrap().0, "alice", ctx.wallet.sender_pubkey_hex],
            )
            .unwrap();

        let mint_connection = direct_mint_connection(&ctx);
        let err = ctx
            .wallet
            .recover_channel_funds(
                &refund_test_locks(&ctx).exclusive_access().unwrap(),
                &ctx.channel_id,
                &mint_connection,
            )
            .await
            .unwrap_err();
        assert!(err
            .to_string()
            .contains("unknown channel recovery status: bogus"));
        assert_eq!(
            ctx.wallet.get_channel(&ctx.channel_id).unwrap().state,
            WalletChannelState::Closing
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
            .prepare_sender_refund_after_expiry(
                ctx.wallet.sender_secret.clone(),
                now,
                established.params.keyset_info.clone(),
                rand::random(),
            )
            .unwrap();
        let mint_connection = direct_mint_connection(&ctx);
        let proofs = established
            .submit_prepared_sender_refund(
                &prepared,
                &ctx.wallet.sender_secret,
                now,
                &mint_connection,
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
            .recover_channel_funds(
                &refund_test_locks(&ctx).exclusive_access().unwrap(),
                &ctx.channel_id,
                &mint_connection,
            )
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
            .recover_channel_funds(
                &refund_test_locks(&ctx).exclusive_access().unwrap(),
                &ctx.channel_id,
                &mint_connection,
            )
            .await
            .unwrap_err();
        assert!(err
            .to_string()
            .contains("injected recovered proof import failure"));
        assert_eq!(
            ctx.wallet.get_channel(&ctx.channel_id).unwrap().state,
            WalletChannelState::Closing
        );
        assert_eq!(
            completed_recovery_row_count(&ctx.wallet, &ctx.channel_id),
            0
        );
        assert!(prepared_refund_json(&ctx.wallet, &ctx.channel_id).is_some());
        // Verified proofs are durable before import, so retry needs no mint IO.
        assert_eq!(
            recovery_row_status(&ctx.wallet, &ctx.channel_id),
            "finalizing"
        );

        let mint_connection = OfflineRefundMint;
        let reopened_wallet = reopen_wallet(&ctx);
        let retry = reopened_wallet
            .recover_channel_funds(
                &refund_test_locks(&ctx).exclusive_access().unwrap(),
                &ctx.channel_id,
                &mint_connection,
            )
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
            .recover_channel_funds(
                &refund_test_locks(&ctx).exclusive_access().unwrap(),
                &ctx.channel_id,
                &mint_connection,
            )
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
            .recover_channel_funds(
                &refund_test_locks(&ctx).exclusive_access().unwrap(),
                &ctx.channel_id,
                &mint_connection,
            )
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
            .prepare_sender_refund_after_expiry(
                ctx.wallet.sender_secret.clone(),
                now,
                established.params.keyset_info.clone(),
                rand::random(),
            )
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
        let submitted = established
            .submit_prepared_sender_refund(
                &prepared,
                &ctx.wallet.sender_secret,
                now,
                &mint_connection,
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
            .recover_channel_funds(
                &refund_test_locks(&ctx).exclusive_access().unwrap(),
                &ctx.channel_id,
                &mint_connection,
            )
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
            .prepare_sender_refund_after_expiry(
                ctx.wallet.sender_secret.clone(),
                now,
                established.params.keyset_info.clone(),
                rand::random(),
            )
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
            .recover_channel_funds(
                &refund_test_locks(&ctx).exclusive_access().unwrap(),
                &ctx.channel_id,
                &mint_connection,
            )
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
            .prepare_sender_refund_after_expiry(
                ctx.wallet.sender_secret.clone(),
                now,
                established.params.keyset_info.clone(),
                rand::random(),
            )
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
            .recover_channel_funds(
                &refund_test_locks(&ctx).exclusive_access().unwrap(),
                &ctx.channel_id,
                &mint_connection,
            )
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
                 (channel_id, kind, status, recovered_amount_raw, recovered_proof_count, prepared_refund_json, created_at, updated_at, custody_db, custody_wallet, custody_sender)
                 VALUES (?1, 'post_expiry_refund', 'submitting', NULL, NULL, NULL, ?2, ?2, ?3, ?4, ?5)",
                params![ctx.channel_id, to_i64(now).unwrap(), ctx.wallet.recovery_custody().unwrap().0, "alice", ctx.wallet.sender_pubkey_hex],
            )
            .unwrap();

        let mint_connection = direct_mint_connection(&ctx);
        let err = ctx
            .wallet
            .recover_channel_funds(
                &refund_test_locks(&ctx).exclusive_access().unwrap(),
                &ctx.channel_id,
                &mint_connection,
            )
            .await
            .unwrap_err();
        assert!(err
            .to_string()
            .contains("submitting refund recovery is missing prepared refund json"));
        assert_eq!(
            ctx.wallet.get_channel(&ctx.channel_id).unwrap().state,
            WalletChannelState::Closing
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
            .recover_channel_funds(
                &refund_test_locks(&ctx).exclusive_access().unwrap(),
                &ctx.channel_id,
                &mint_connection,
            )
            .await
            .unwrap();
        let ChannelFundRecoveryResult::RecoveryRetryLater { channel_id, reason } = result else {
            panic!("expected retry-later recovery result, got {result:?}");
        };
        assert_eq!(channel_id, ctx.channel_id);
        assert!(reason.contains("refund restore failed"));
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
            WalletChannelState::Closing
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
            ReqwestClientNetworking::new(MINT_HTTP_REQUEST_TIMEOUT)
                .expect("construct bridge HTTP networking"),
        );
        let keyset_info_json = bridge.fetch_keyset_info(&mint_url, &keyset_id).unwrap();

        let minted_amount_raw = 1024u64;
        let funding_token_target_raw = 1000u64;
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
        let expected_change_raw = minted_amount_raw - input_fee_raw - funding_token_target_raw;

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

        let funding_token_target_msats = funding_token_target_raw * 1000;
        let offer = offer(&mint_url, &receiver_pubkey, &keyset_id);
        let before_open = SqliteClientWallet::now_seconds().unwrap();
        let channel_id = wallet
            .provision_channel(&offer, funding_token_target_msats)
            .expect("provision channel from loose proofs");
        let after_open = SqliteClientWallet::now_seconds().unwrap();

        let channel = wallet.get_channel(&channel_id).unwrap();
        let attempt = wallet
            .loose_wallet()
            .opening_attempt(&channel_id)
            .unwrap()
            .expect("completed opening journal");
        assert_eq!(attempt.state, OpeningAttemptState::Completed);
        let persisted_prepared: PreparedOpenChannel =
            serde_json::from_str(&attempt.prepared_open_json).unwrap();
        assert_eq!(persisted_prepared.channel_id, channel_id);
        assert!(!persisted_prepared.swap_request_json.is_empty());
        assert_eq!(channel.receiver_pubkey, receiver_pubkey);
        assert_eq!(channel.mint_url, mint_url);
        assert_eq!(channel.unit, "sat");
        assert_eq!(channel.keyset_id, keyset_id);
        assert_eq!(channel.state, WalletChannelState::Open);
        // Actual usable capacity is what upstream returned after fees; it must be
        // positive and not exceed the requested funding-token value.
        assert!(channel.capacity_msats > 0);
        assert!(channel.capacity_msats <= funding_token_target_msats);

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
        // original funding-token target.
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
        offer.preferred_keyset_ids.push(output_keyset_id.clone());
        assert_eq!(offer.preferred_keyset_ids[0], input_keyset_id);

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
        assert!(!offer.preferred_keyset_ids.contains(&input_keyset_id));

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
            ReqwestClientNetworking::new(MINT_HTTP_REQUEST_TIMEOUT)
                .expect("construct bridge HTTP networking"),
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
        assert!(matches!(
            err,
            WalletError::InsufficientLooseProofFunds { .. }
        ));

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

    #[tokio::test(flavor = "multi_thread")]
    async fn opening_recovery_rejects_exclusive_access_for_another_wallet() {
        let temp = tempfile::tempdir().unwrap();
        let loose_a = temp.path().join("loose-a.sqlite");
        let channels_a = temp.path().join("channels-a.sqlite");
        let loose_b = temp.path().join("loose-b.sqlite");
        let channels_b = temp.path().join("channels-b.sqlite");
        let locks_b = ClientWalletLocks::acquire(
            &loose_b,
            &channels_b,
            crate::wallet_lock::WalletLockMode::Maintenance,
        )
        .unwrap();
        let wallet_a = SqliteClientWallet::open(
            LooseProofWallet::open(&loose_a, "alice").unwrap(),
            &channels_a,
            &sender_secret_hex(),
        )
        .unwrap();

        let error = wallet_a
            .recover_pending_openings(&locks_b.exclusive_access().unwrap())
            .unwrap_err();
        assert!(error.to_string().contains("belongs to a different wallet"));
    }

    #[cfg(unix)]
    #[tokio::test(flavor = "multi_thread")]
    async fn opening_recovery_accepts_aliases_and_deduplicated_same_file_identity() {
        use std::os::unix::fs::symlink;

        let temp = tempfile::tempdir().unwrap();
        let loose = temp.path().join("loose.sqlite");
        let channels = temp.path().join("channels.sqlite");
        let loose_alias = temp.path().join("loose-alias.sqlite");
        let channels_alias = temp.path().join("channels-alias.sqlite");
        symlink(&loose, &loose_alias).unwrap();
        symlink(&channels, &channels_alias).unwrap();
        let locks = ClientWalletLocks::acquire(
            &loose_alias,
            &channels_alias,
            crate::wallet_lock::WalletLockMode::Maintenance,
        )
        .unwrap();
        let wallet = SqliteClientWallet::open(
            LooseProofWallet::open(&loose, "alice").unwrap(),
            &channels,
            &sender_secret_hex(),
        )
        .unwrap();
        assert!(wallet
            .recover_pending_openings(&locks.exclusive_access().unwrap())
            .unwrap()
            .is_empty());
        drop(wallet);
        drop(locks);

        let combined = temp.path().join("combined.sqlite");
        let locks = ClientWalletLocks::acquire(
            &combined,
            &combined,
            crate::wallet_lock::WalletLockMode::Maintenance,
        )
        .unwrap();
        let wallet = SqliteClientWallet::open(
            LooseProofWallet::open(&combined, "alice").unwrap(),
            &combined,
            &sender_secret_hex(),
        )
        .unwrap();
        assert!(wallet
            .recover_pending_openings(&locks.exclusive_access().unwrap())
            .unwrap()
            .is_empty());
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn opening_recovery_reports_cancellation_and_unresolved_without_mint_io() {
        let temp = tempfile::tempdir().unwrap();
        let loose = LooseProofWallet::open(temp.path().join("loose.sqlite"), "alice").unwrap();
        let wallet = SqliteClientWallet::open(
            loose,
            temp.path().join("channels.sqlite"),
            &sender_secret_hex(),
        )
        .unwrap();
        for id in ["prepared", "rejected", "submitted"] {
            wallet
                .loose_wallet()
                .import_proofs(&[NewLooseProof {
                    proof_id: id.to_string(),
                    mint_url: "http://unused.invalid".to_string(),
                    unit: "sat".to_string(),
                    keyset_id: "keyset".to_string(),
                    amount_raw: 8,
                    proof_json: "{}".to_string(),
                    source_quote_id: None,
                    source_batch_id: None,
                }])
                .unwrap();
            wallet
                .loose_wallet()
                .reserve_selected_proofs_with_opening_attempt(
                    "http://unused.invalid",
                    "sat",
                    &[id.to_string()],
                    &NewOpeningAttempt {
                        attempt_id: id.to_string(),
                        opening_id: id.to_string(),
                        predecessor_attempt_id: None,
                        reservation_id: id.to_string(),
                        receiver_pubkey: "receiver".to_string(),
                        mint_url: "http://unused.invalid".to_string(),
                        unit: "sat".to_string(),
                        funding_token_target_msats: 8000,
                        expiry_timestamp: 123456,
                        prepared_open_json: "invalid preparation".to_string(),
                        selected_proof_ids: vec![id.to_string()],
                    },
                )
                .unwrap();
            if id != "prepared" {
                let OpeningSubmissionClaim::Acquired(permit) = wallet
                    .loose_wallet()
                    .claim_opening_attempt_submission(id)
                    .unwrap()
                else {
                    panic!("submission claim not acquired");
                };
                let authorized = wallet
                    .loose_wallet()
                    .authorize_opening_submission(permit)
                    .unwrap();
                if id == "rejected" {
                    wallet
                        .loose_wallet()
                        .record_definitive_opening_rejection(authorized, 12_002, "inactive keyset")
                        .unwrap();
                }
            }
        }
        let mut report = wallet.recover_pending_openings_inner().unwrap();
        report.cancelled_attempt_ids.sort();
        assert_eq!(report.cancelled_attempt_ids, vec!["prepared", "rejected"]);
        assert!(report.recovered_channel_ids.is_empty());
        assert!(report.externally_spent_attempt_ids.is_empty());
        assert_eq!(report.unresolved.len(), 1);
        assert_eq!(report.unresolved[0].attempt_id, "submitted");
        assert!(report.unresolved[0]
            .reason
            .contains("decode opening attempt"));
        assert_eq!(
            wallet
                .loose_wallet()
                .proofs_for_reservation("submitted")
                .unwrap()[0]
                .state,
            LooseProofState::Reserved
        );
        let repeated = wallet.recover_pending_openings_inner().unwrap();
        assert!(repeated.cancelled_attempt_ids.is_empty());
        assert_eq!(repeated.unresolved, report.unresolved);
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn submission_preflight_failure_cancels_claim_without_http_or_ambiguity() {
        let temp = tempfile::tempdir().unwrap();
        let loose = LooseProofWallet::open(temp.path().join("loose.sqlite"), "alice").unwrap();
        let wallet = SqliteClientWallet::open(
            loose,
            temp.path().join("channels.sqlite"),
            &sender_secret_hex(),
        )
        .unwrap();
        let prepared = prepared_opening_with_input_secrets(&["proof-a"]);
        let permit = journal_prepared_opening_for_authority_test(&wallet, &prepared);
        let mut conflicting = prepared.clone();
        conflicting.swap_request_json = "different request".to_string();
        let networking = CountingSwapNetworking {
            calls: Mutex::new(0),
        };

        let error = wallet
            .submit_prepared_open(conflicting, permit, &networking)
            .unwrap_err();
        assert!(error.message.contains("authoritative journal"));
        assert_eq!(*networking.calls.lock().unwrap(), 0);
        let attempt = wallet
            .loose_wallet()
            .opening_attempt(&prepared.channel_id)
            .unwrap()
            .unwrap();
        assert_eq!(attempt.state, OpeningAttemptState::Prepared);
        assert_eq!(attempt.latest_submitted_at, None);
        assert_eq!(
            wallet
                .loose_wallet()
                .opening_executions(&prepared.channel_id)
                .unwrap()[0]
                .status,
            OpeningExecutionStatus::Cancelled
        );
        wallet
            .loose_wallet()
            .cancel_prepared_opening_attempt(&prepared.channel_id)
            .unwrap();
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn concurrent_same_opening_across_handles_submits_once() {
        let temp = tempfile::tempdir().unwrap();
        let loose_db = temp.path().join("loose.sqlite");
        let channel_db = temp.path().join("channels.sqlite");
        let sender_secret = sender_secret_hex();
        let first = SqliteClientWallet::open(
            LooseProofWallet::open(&loose_db, "alice").unwrap(),
            &channel_db,
            &sender_secret,
        )
        .unwrap();
        let prepared = prepared_opening_with_input_secrets(&["proof-a"]);
        let claim = journal_prepared_opening_for_authority_test(&first, &prepared);
        first
            .loose_wallet()
            .cancel_opening_submission_claim(claim)
            .unwrap();
        let second = SqliteClientWallet::open(
            LooseProofWallet::open(&loose_db, "alice").unwrap(),
            &channel_db,
            &sender_secret,
        )
        .unwrap();
        let record = first
            .loose_wallet()
            .opening_attempt(&prepared.channel_id)
            .unwrap()
            .unwrap();
        let reservation = ProofReservation {
            reservation_id: record.reservation_id,
            proofs: first
                .loose_wallet()
                .proofs_for_reservation("reservation")
                .unwrap(),
            total_amount_raw: 1,
        };
        let attempt = ClientOpenAttempt {
            opening_id: prepared.channel_id.clone(),
            output_keyset: SelectedOutputKeyset {
                id: prepared.keyset_id.clone(),
                info_json: prepared.opening.keyset_info_json.clone(),
            },
            reservation,
            prepared: prepared.clone(),
            requested_capacity_raw: None,
            desired_funding_token_amount_raw: Some(1),
            funding_token_target_msats: 1_000,
            selected_input_msats: 1_000,
            expiry_timestamp: 123_456,
        };
        let offer = RelayPaymentOffer {
            receiver_pubkey: "receiver".to_string(),
            mint_url: prepared.mint_url.clone(),
            unit: "sat".to_string(),
            preferred_keyset_ids: vec![prepared.keyset_id.clone()],
            negotiated_keyset_versions: BTreeSet::from(["v1".to_string()]),
            in_bytes_per_millisat: 1,
            out_bytes_per_millisat: 1,
        };
        let networking = BlockingSwapNetworking::new();

        std::thread::scope(|scope| {
            let leader_attempt = attempt.clone();
            let leader = scope.spawn(|| {
                first.execute_open_attempt_with_networking(
                    &offer,
                    leader_attempt,
                    false,
                    &networking,
                )
            });
            let mut entered = networking.entered.0.lock().unwrap();
            while !*entered {
                entered = networking.entered.1.wait(entered).unwrap();
            }
            drop(entered);

            let follower = scope.spawn(|| {
                second.execute_open_attempt_with_networking(&offer, attempt, false, &networking)
            });
            assert_eq!(
                follower.join().unwrap().unwrap_err(),
                WalletError::OpeningInProgress {
                    channel_id: prepared.channel_id.clone()
                }
            );
            *networking.release.0.lock().unwrap() = true;
            networking.release.1.notify_one();
            assert!(leader.join().unwrap().is_err());
        });
        assert_eq!(networking.calls.load(Ordering::SeqCst), 1);
        assert_eq!(
            first
                .loose_wallet()
                .opening_executions(&prepared.channel_id)
                .unwrap()
                .iter()
                .filter(|execution| execution.status != OpeningExecutionStatus::Cancelled)
                .count(),
            1
        );
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn http_success_then_execution_result_record_failure_remains_ambiguous() {
        let temp = tempfile::tempdir().unwrap();
        let loose_db = temp.path().join("loose.sqlite");
        let loose = LooseProofWallet::open(&loose_db, "alice").unwrap();
        let wallet = SqliteClientWallet::open(
            loose,
            temp.path().join("channels.sqlite"),
            &sender_secret_hex(),
        )
        .unwrap();
        let prepared = prepared_opening_with_input_secrets(&["proof-a"]);
        let permit = journal_prepared_opening_for_authority_test(&wallet, &prepared);
        Connection::open(&loose_db)
            .unwrap()
            .execute_batch(
                "CREATE TRIGGER fail_execution_result BEFORE UPDATE
                 ON monad_client_opening_executions
                 WHEN OLD.status = 'authorized' AND NEW.status = 'response_received'
                 BEGIN SELECT RAISE(ABORT, 'injected execution result fault'); END;",
            )
            .unwrap();
        let networking = CountingSwapNetworking {
            calls: Mutex::new(0),
        };

        let error = wallet
            .submit_prepared_open(prepared.clone(), permit, &networking)
            .unwrap_err();
        assert!(error.message.contains("persist opening execution response"));
        assert_eq!(*networking.calls.lock().unwrap(), 1);
        let attempt = wallet
            .loose_wallet()
            .opening_attempt(&prepared.channel_id)
            .unwrap()
            .unwrap();
        assert_eq!(attempt.state, OpeningAttemptState::Submitted);
        assert!(attempt.latest_submitted_at.is_some());
        assert_eq!(
            wallet
                .loose_wallet()
                .opening_executions(&prepared.channel_id)
                .unwrap()[0]
                .status,
            OpeningExecutionStatus::Authorized
        );
        assert!(wallet
            .loose_wallet()
            .proofs_for_reservation("reservation")
            .unwrap()
            .iter()
            .all(|proof| proof.state == LooseProofState::Reserved));
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn obsolete_opening_recovery_table_is_dropped_only_when_empty() {
        for nonempty in [false, true] {
            let temp = tempfile::tempdir().unwrap();
            let channel_db = temp.path().join("channels.sqlite");
            let conn = Connection::open(&channel_db).unwrap();
            conn.execute_batch(CREATE_OPENING_RECOVERIES_SQL_FOR_TEST)
                .unwrap();
            if nonempty {
                conn.execute(
                    "INSERT INTO monad_client_channel_opening_recoveries VALUES
                     ('channel', 'reservation', 'receiver', 'https://mint.invalid', 'sat',
                      1000, 'submitted', 'unknown', 1, 1)",
                    [],
                )
                .unwrap();
            }
            drop(conn);
            let loose = LooseProofWallet::open(temp.path().join("loose.sqlite"), "alice").unwrap();
            let result = SqliteClientWallet::open(loose, &channel_db, &sender_secret_hex());
            if nonempty {
                assert!(result
                    .err()
                    .unwrap()
                    .to_string()
                    .contains("obsolete nonempty"));
            } else {
                let wallet = result.unwrap();
                let exists: bool = wallet
                    .channel_db
                    .lock()
                    .unwrap()
                    .query_row(
                        "SELECT EXISTS(SELECT 1 FROM sqlite_master WHERE name =
                                'monad_client_channel_opening_recoveries')",
                        [],
                        |row| row.get(0),
                    )
                    .unwrap();
                assert!(!exists);
            }
        }
    }

    async fn assert_recovers_persisted_ambiguous_opening(
        swap_reached_mint: bool,
        finalizing_boundary: Option<usize>,
        export_before_recovery: bool,
        externally_spent_after_export: bool,
        complete_before_final_restore: bool,
        include_broken_export_attempt: bool,
    ) {
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
            ReqwestClientNetworking::new(MINT_HTTP_REQUEST_TIMEOUT)
                .expect("construct bridge HTTP networking"),
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
        let funding_token_target_msats = desired_funding_raw * 1000;
        let funding_token_target_raw =
            msats_to_raw_units(unit, funding_token_target_msats).unwrap();
        let reservation = wallet
            .loose_wallet()
            .reserve_proofs(
                &mint_url,
                unit,
                std::slice::from_ref(&keyset_id),
                funding_token_target_raw,
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
        let opening = ClientChannelOpeningFromSwap {
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
            change_secrets_json: change_secrets_json.clone(),
            change_amount_raw,
            created_at: SqliteClientWallet::now_seconds().unwrap(),
        };
        let prepared = PreparedOpenChannel {
            channel_id: channel_id.clone(),
            mint_url: mint_url.clone(),
            swap_request_json: swap_json["swap_request_json"].as_str().unwrap().to_string(),
            opening: opening.clone(),
            funding_secrets_json: swap_json["funding_secrets_json"]
                .as_str()
                .unwrap()
                .to_string(),
            change_secrets_json,
            keyset_id: keyset_id.clone(),
        };
        let proof_ids = reservation
            .proofs
            .iter()
            .map(|proof| proof.proof_id.clone())
            .collect::<Vec<_>>();
        wallet
            .loose_wallet()
            .release_reservation(&reservation.reservation_id)
            .unwrap();
        wallet
            .loose_wallet()
            .reserve_selected_proofs_with_opening_attempt(
                &mint_url,
                unit,
                &proof_ids,
                &NewOpeningAttempt {
                    attempt_id: channel_id.clone(),
                    opening_id: channel_id.clone(),
                    predecessor_attempt_id: None,
                    reservation_id: reservation.reservation_id.clone(),
                    receiver_pubkey: receiver_pubkey.clone(),
                    mint_url: mint_url.clone(),
                    unit: unit.to_string(),
                    funding_token_target_msats,
                    expiry_timestamp,
                    prepared_open_json: serde_json::to_string(&prepared).unwrap(),
                    selected_proof_ids: proof_ids.clone(),
                },
            )
            .unwrap();
        let OpeningSubmissionClaim::Acquired(permit) = wallet
            .loose_wallet()
            .claim_opening_attempt_submission(&channel_id)
            .unwrap()
        else {
            panic!("submission claim not acquired");
        };
        let _authorized = wallet
            .loose_wallet()
            .authorize_opening_submission_at(permit, 1)
            .unwrap();
        storage
            .save_opening_from_swap(&channel_id, opening)
            .unwrap();
        let record = wallet
            .loose_wallet()
            .opening_attempt(&channel_id)
            .unwrap()
            .unwrap();
        for mode in [
            CheckStateMode::States(vec![State::Pending; reservation.proofs.len()]),
            CheckStateMode::States(vec![State::Spent; reservation.proofs.len()]),
            CheckStateMode::MissingLast,
            CheckStateMode::NetworkError,
        ] {
            let networking = StateCheckNetworking::new(mode);
            let outcome = wallet.recover_journaled_opening(&record, &networking);
            assert!(matches!(
                outcome,
                Ok(OpeningRecoveryOutcome::Unresolved) | Err(_)
            ));
            assert_eq!(
                wallet
                    .loose_wallet()
                    .opening_attempt(&channel_id)
                    .unwrap()
                    .unwrap(),
                record
            );
            assert!(wallet
                .loose_wallet()
                .proofs_for_reservation(&reservation.reservation_id)
                .unwrap()
                .iter()
                .all(|proof| proof.state == LooseProofState::Reserved));
        }
        for response in [
            Err("restore network failure".to_string()),
            Ok("invalid JSON".to_string()),
            Ok(r#"{"outputs":[],"signatures":[{}]}"#.to_string()),
        ] {
            let mut networking = StateCheckNetworking::new(CheckStateMode::States(vec![
                    State::Unspent;
                    reservation.proofs.len()
                ]));
            networking.restore_response = response;
            assert!(wallet
                .recover_journaled_opening(&record, &networking)
                .is_err());
            assert!(networking.requested_y_count.lock().unwrap().is_none());
            assert_eq!(
                wallet
                    .loose_wallet()
                    .opening_attempt(&channel_id)
                    .unwrap()
                    .unwrap(),
                record
            );
        }
        if export_before_recovery {
            if include_broken_export_attempt {
                let broken_mint = "http://broken.invalid";
                let broken_proof_id = "broken-export-proof";
                wallet
                    .loose_wallet()
                    .import_proofs(&[NewLooseProof {
                        proof_id: broken_proof_id.to_string(),
                        mint_url: broken_mint.to_string(),
                        unit: unit.to_string(),
                        keyset_id: keyset_id.clone(),
                        amount_raw: 1,
                        proof_json: loose_proofs[0].proof_json.clone(),
                        source_quote_id: None,
                        source_batch_id: None,
                    }])
                    .unwrap();
                wallet
                    .loose_wallet()
                    .reserve_selected_proofs_with_opening_attempt(
                        broken_mint,
                        unit,
                        &[broken_proof_id.to_string()],
                        &NewOpeningAttempt {
                            attempt_id: "broken-export-attempt".to_string(),
                            opening_id: "broken-export-attempt".to_string(),
                            predecessor_attempt_id: None,
                            reservation_id: "broken-export-reservation".to_string(),
                            receiver_pubkey: receiver_pubkey.clone(),
                            mint_url: broken_mint.to_string(),
                            unit: unit.to_string(),
                            funding_token_target_msats: 1_000,
                            expiry_timestamp,
                            prepared_open_json: "not JSON".to_string(),
                            selected_proof_ids: vec![broken_proof_id.to_string()],
                        },
                    )
                    .unwrap();
                let OpeningSubmissionClaim::Acquired(permit) = wallet
                    .loose_wallet()
                    .claim_opening_attempt_submission("broken-export-attempt")
                    .unwrap()
                else {
                    panic!("broken attempt submission claim not acquired");
                };
                wallet
                    .loose_wallet()
                    .authorize_opening_submission_at(permit, 1)
                    .unwrap();
            }
            let locks =
                ClientWalletLocks::acquire(&loose_db, &channel_db, WalletLockMode::Maintenance)
                    .unwrap();
            let report = wallet
                .export_stale_opening_inputs(&locks.exclusive_access().unwrap())
                .unwrap();
            assert_eq!(
                report
                    .unresolved
                    .iter()
                    .map(|unresolved| unresolved.attempt_id.as_str())
                    .collect::<Vec<_>>(),
                if include_broken_export_attempt {
                    vec!["broken-export-attempt"]
                } else {
                    Vec::new()
                }
            );
            assert_eq!(report.exports.len(), 1);
            assert_eq!(report.exports[0].mint_url, mint_url);
            assert_eq!(report.exports[0].unit, unit);
            assert_eq!(report.exports[0].amount_raw, reservation.total_amount_raw);
            assert_eq!(report.exports[0].proof_count, reservation.proofs.len());
            assert_eq!(report.exports[0].attempt_ids, vec![channel_id.clone()]);
            assert!(report.exports[0].token.parse::<Token>().is_ok());
            let repeated = wallet
                .export_stale_opening_inputs(&locks.exclusive_access().unwrap())
                .unwrap();
            assert_eq!(repeated, report);
            assert_eq!(
                wallet
                    .loose_wallet()
                    .opening_attempt(&channel_id)
                    .unwrap()
                    .unwrap()
                    .state,
                OpeningAttemptState::Exported
            );
            assert!(wallet
                .loose_wallet()
                .proofs_for_reservation(&reservation.reservation_id)
                .unwrap()
                .iter()
                .all(|proof| proof.state == LooseProofState::Reserved));
            drop(locks);

            let exported = wallet
                .loose_wallet()
                .opening_attempt(&channel_id)
                .unwrap()
                .unwrap();
            let mut inconclusive_modes = vec![
                CheckStateMode::States(vec![State::Unspent; reservation.proofs.len()]),
                CheckStateMode::States(vec![State::Pending; reservation.proofs.len()]),
                CheckStateMode::MissingLast,
                CheckStateMode::DuplicateFirst,
                CheckStateMode::NetworkError,
            ];
            if reservation.proofs.len() > 1 {
                inconclusive_modes.push(CheckStateMode::States(
                    (0..reservation.proofs.len())
                        .map(|index| {
                            if index == 0 {
                                State::Spent
                            } else {
                                State::Unspent
                            }
                        })
                        .collect(),
                ));
            }
            for mode in inconclusive_modes {
                let networking = StateCheckNetworking::new(mode);
                assert!(matches!(
                    wallet.recover_journaled_opening(&exported, &networking),
                    Ok(OpeningRecoveryOutcome::Unresolved) | Err(_)
                ));
                assert_eq!(
                    wallet
                        .loose_wallet()
                        .opening_attempt(&channel_id)
                        .unwrap()
                        .unwrap(),
                    exported
                );
                assert!(wallet
                    .loose_wallet()
                    .proofs_for_reservation(&reservation.reservation_id)
                    .unwrap()
                    .iter()
                    .all(|proof| proof.state == LooseProofState::Reserved));
            }
            let final_restore_failure = FinalRestoreFailureNetworking {
                restore_calls: AtomicUsize::new(0),
            };
            assert!(wallet
                .recover_journaled_opening(&exported, &final_restore_failure)
                .is_err());
            assert_eq!(
                wallet
                    .loose_wallet()
                    .opening_attempt(&channel_id)
                    .unwrap()
                    .unwrap(),
                exported
            );

            if complete_before_final_restore {
                let networking = CompleteBeforeFinalRestoreNetworking {
                    inner: OpeningRecoveryHttpNetworking::new().unwrap(),
                    swap_request_json: prepared.swap_request_json.clone(),
                    restore_calls: AtomicUsize::new(0),
                };
                let outcome = wallet.recover_journaled_opening(&exported, &networking);
                assert!(
                    matches!(
                        outcome,
                        Ok(OpeningRecoveryOutcome::Recovered(ref recovered)) if recovered == &channel_id
                    ),
                    "unexpected recovery outcome: {outcome:?}"
                );
                assert!(networking.restore_calls.load(Ordering::SeqCst) >= 2);
                assert_eq!(
                    wallet
                        .loose_wallet()
                        .opening_attempt(&channel_id)
                        .unwrap()
                        .unwrap()
                        .state,
                    OpeningAttemptState::Completed
                );
                assert_eq!(
                    wallet.get_channel(&channel_id).unwrap().state,
                    WalletChannelState::Open
                );
                let _ = shutdown_tx.send(());
                mint_task.await.unwrap().unwrap();
                return;
            }

            if externally_spent_after_export {
                // The partial-export fixture is independent of real external-spend recovery.
                if include_broken_export_attempt {
                    let _ = shutdown_tx.send(());
                    mint_task.await.unwrap().unwrap();
                    return;
                }
                let executions = wallet
                    .loose_wallet()
                    .opening_executions(&channel_id)
                    .unwrap();
                let original_rows = || {
                    let conn = Connection::open(&loose_db).unwrap();
                    proof_ids.iter().map(|proof_id| {
                        conn.query_row(
                            "SELECT proof_id, wallet_name, mint_url, unit, keyset_id, amount_raw,
                                    proof_json, state, source_quote_id, source_batch_id,
                                    reserved_by, spent_channel_id, created_at
                             FROM monad_client_loose_proofs WHERE wallet_name = 'alice' AND proof_id = ?1",
                            [proof_id],
                            |row| (0..13).map(|index| row.get::<_, rusqlite::types::Value>(index)).collect::<Result<Vec<_>, _>>(),
                        ).unwrap()
                    }).collect::<Vec<_>>()
                };
                let mut expected_rows = original_rows();
                for row in &mut expected_rows {
                    assert_eq!(row[7], rusqlite::types::Value::Text("reserved".to_string()));
                    assert_eq!(
                        row[10],
                        rusqlite::types::Value::Text(reservation.reservation_id.clone())
                    );
                    assert_eq!(row[11], rusqlite::types::Value::Null);
                    row[7] = rusqlite::types::Value::Text("spent".to_string());
                    row[10] = rusqlite::types::Value::Null;
                }
                // Spend the exported originals into unrelated ordinary outputs, not the
                // prepared channel/change outputs that recovery would finalize.
                let fresh: serde_json::Value = serde_json::from_str(
                    &create_plain_blinded_messages(amount_raw - input_fee_raw, &keyset_info_json)
                        .unwrap(),
                )
                .unwrap();
                let prepared_request: serde_json::Value =
                    serde_json::from_str(&prepared.swap_request_json).unwrap();
                assert!(fresh["blinded_messages"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .all(|output| {
                        prepared_request["outputs"]
                            .as_array()
                            .unwrap()
                            .iter()
                            .all(|prepared| output["B_"] != prepared["B_"])
                    }));
                let response: serde_json::Value = client
                    .post(format!("{mint_url}/v1/swap"))
                    .json(&serde_json::json!({
                        "inputs": serde_json::from_str::<serde_json::Value>(&input_proofs_json).unwrap(),
                        "outputs": fresh["blinded_messages"],
                    }))
                    .send().await.unwrap().error_for_status().unwrap()
                    .json().await.unwrap();
                let fresh_proofs: Vec<Proof> = serde_json::from_str(
                    &construct_proofs(
                        &response["signatures"].to_string(),
                        &fresh["secrets_with_blinding"].to_string(),
                        &keyset_info_json,
                    )
                    .unwrap(),
                )
                .unwrap();
                assert_eq!(
                    fresh_proofs
                        .iter()
                        .map(|proof| proof.amount.to_u64())
                        .sum::<u64>(),
                    amount_raw - input_fee_raw
                );
                drop(storage);
                drop(wallet);
                let wallet = SqliteClientWallet::open(
                    LooseProofWallet::open(&loose_db, "alice").unwrap(),
                    &channel_db,
                    &sender_secret,
                )
                .unwrap();
                let networking = ScriptedOpeningNetworking {
                    inner: OpeningRecoveryHttpNetworking::new().unwrap(),
                    scenario: OpeningOrchestrationScenario::RestoreOnly,
                    swaps: Mutex::new(Vec::new()),
                    restores: Mutex::new(0),
                };
                assert_eq!(
                    wallet
                        .recover_pending_openings_with_networking(&networking)
                        .unwrap(),
                    OpeningRecoveryReport {
                        externally_spent_attempt_ids: vec![channel_id.clone()],
                        ..Default::default()
                    }
                );
                assert_eq!(
                    wallet
                        .loose_wallet()
                        .opening_attempt(&channel_id)
                        .unwrap()
                        .unwrap()
                        .state,
                    OpeningAttemptState::ExternallySpent
                );
                assert!(wallet
                    .loose_wallet()
                    .proofs_for_reservation(&reservation.reservation_id)
                    .unwrap()
                    .is_empty());
                assert_eq!(original_rows(), expected_rows);
                assert_eq!(
                    wallet
                        .loose_wallet()
                        .opening_executions(&channel_id)
                        .unwrap(),
                    executions
                );
                assert_eq!(
                    wallet
                        .loose_wallet()
                        .available_balance_raw(&mint_url, unit, std::slice::from_ref(&keyset_id))
                        .unwrap(),
                    0
                );
                assert!(wallet.get_channel(&channel_id).is_err());
                let conn = Connection::open(&loose_db).unwrap();
                let proof_count: usize = conn.query_row(
                    "SELECT COUNT(*) FROM monad_client_loose_proofs WHERE wallet_name = 'alice'",
                    [], |row| row.get(0),
                ).unwrap();
                assert_eq!(proof_count, proof_ids.len(), "no channel change imported");
                drop(conn);
                assert!(networking.swaps.lock().unwrap().is_empty());
                let restores = *networking.restores.lock().unwrap();
                assert!(restores > 0);
                drop(wallet);
                let wallet = SqliteClientWallet::open(
                    LooseProofWallet::open(&loose_db, "alice").unwrap(),
                    &channel_db,
                    &sender_secret,
                )
                .unwrap();
                // Shut down the mint as well: terminal scans must need no network.
                let _ = shutdown_tx.send(());
                mint_task.await.unwrap().unwrap();
                assert!(wallet
                    .recover_pending_openings_with_networking(&networking)
                    .unwrap()
                    .is_empty());
                let locks =
                    ClientWalletLocks::acquire(&loose_db, &channel_db, WalletLockMode::Maintenance)
                        .unwrap();
                let report = wallet
                    .export_stale_opening_inputs(&locks.exclusive_access().unwrap())
                    .unwrap();
                assert!(report.exports.is_empty());
                assert!(report.unresolved.is_empty());
                assert!(networking.swaps.lock().unwrap().is_empty());
                assert_eq!(*networking.restores.lock().unwrap(), restores);
                assert_eq!(original_rows(), expected_rows);
                assert_eq!(
                    wallet
                        .loose_wallet()
                        .opening_executions(&channel_id)
                        .unwrap(),
                    executions
                );
                return;
            }
        }
        if swap_reached_mint {
            let swap_response = client
                .post(format!("{mint_url}/v1/swap"))
                .header("Content-Type", "application/json")
                .body(prepared.swap_request_json.clone())
                .send()
                .await
                .unwrap();
            if !swap_response.status().is_success() {
                let status = swap_response.status();
                let body = swap_response.text().await.unwrap_or_default();
                panic!("swap failed with {status}: {body}");
            }
            if export_before_recovery {
                let locks =
                    ClientWalletLocks::acquire(&loose_db, &channel_db, WalletLockMode::Maintenance)
                        .unwrap();
                let report = wallet
                    .export_stale_opening_inputs(&locks.exclusive_access().unwrap())
                    .unwrap();
                assert!(report.exports.is_empty());
                assert_eq!(report.unresolved.len(), 1);
                assert_eq!(report.unresolved[0].attempt_id, channel_id);
                assert!(report.unresolved[0].reason.contains("run recover-openings"));
                assert_eq!(
                    wallet
                        .loose_wallet()
                        .opening_attempt(&channel_id)
                        .unwrap()
                        .unwrap()
                        .state,
                    OpeningAttemptState::Exported
                );
            }
        }

        if let Some(boundary) = finalizing_boundary {
            let OpeningRestoreOutcome::Completed(completed) = wallet
                .restore_journaled_opening(
                    &prepared,
                    &OpeningRecoveryHttpNetworking::new().unwrap(),
                )
                .unwrap()
            else {
                panic!("expected completed restore");
            };
            wallet
                .loose_wallet()
                .mark_opening_attempt_finalizing(
                    &channel_id,
                    &serde_json::to_string(&completed).unwrap(),
                )
                .unwrap();
            if boundary >= 1 {
                wallet
                    .bridge
                    .lock()
                    .unwrap()
                    .mark_completed_open(&completed)
                    .unwrap();
            }
            if boundary >= 2 {
                wallet
                    .loose_wallet()
                    .import_proofs(&change_proofs_to_loose_proofs(&completed.result).unwrap())
                    .unwrap();
            }
            if boundary >= 3 {
                wallet
                    .store_open_channel_metadata(
                        &completed.result,
                        &reservation.reservation_id,
                        expiry_timestamp,
                    )
                    .unwrap();
            }
            if boundary >= 4 {
                wallet
                    .loose_wallet()
                    .complete_opening_attempt_exact(&channel_id)
                    .unwrap();
            }
        }
        drop(storage);
        drop(wallet);

        let loose_wallet = LooseProofWallet::open(&loose_db, "alice").unwrap();
        let wallet = SqliteClientWallet::open(loose_wallet, &channel_db, &sender_secret).unwrap();
        let recovered = wallet.recover_pending_openings_inner().unwrap();
        if !swap_reached_mint {
            assert!(recovered.externally_spent_attempt_ids.is_empty());
            assert!(recovered.recovered_channel_ids.is_empty());
            assert_eq!(recovered.unresolved.len(), 1);
            assert_eq!(recovered.unresolved[0].attempt_id, channel_id);
            let record = wallet
                .loose_wallet()
                .opening_attempt(&channel_id)
                .unwrap()
                .unwrap();
            assert_eq!(record.state, OpeningAttemptState::Submitted);
            assert_eq!(
                wallet
                    .loose_wallet()
                    .available_balance_raw(&mint_url, unit, std::slice::from_ref(&keyset_id))
                    .unwrap(),
                0
            );
            assert!(wallet.get_channel(&channel_id).is_err());
            let repeated = wallet.recover_pending_openings_inner().unwrap();
            assert_eq!(repeated.unresolved.len(), 1);
            assert_eq!(
                wallet
                    .loose_wallet()
                    .opening_attempt(&channel_id)
                    .unwrap()
                    .unwrap(),
                record
            );
            let _ = shutdown_tx.send(());
            mint_task.await.unwrap().unwrap();
            return;
        }
        if finalizing_boundary == Some(4) {
            assert!(recovered.recovered_channel_ids.is_empty());
        } else {
            assert_eq!(recovered.recovered_channel_ids, vec![channel_id.clone()]);
        }
        assert_eq!(
            wallet
                .loose_wallet()
                .opening_attempt(&channel_id)
                .unwrap()
                .unwrap()
                .state,
            OpeningAttemptState::Completed
        );

        let channel = wallet.get_channel(&channel_id).unwrap();
        assert_eq!(channel.state, WalletChannelState::Open);
        assert!(channel.capacity_msats > 0);
        assert!(channel.capacity_msats <= funding_token_target_msats);

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
        assert!(wallet.recover_pending_openings_inner().unwrap().is_empty());

        let _ = shutdown_tx.send(());
        mint_task.await.unwrap().unwrap();
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn recovers_persisted_ambiguous_opening() {
        assert_recovers_persisted_ambiguous_opening(true, None, false, false, false, false).await;
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn startup_recovery_keeps_empty_submitted_opening_reserved() {
        assert_recovers_persisted_ambiguous_opening(false, None, false, false, false, false).await;
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn finalizing_opening_recovers_at_each_local_persistence_boundary() {
        for boundary in 0..=4 {
            assert_recovers_persisted_ambiguous_opening(
                true,
                Some(boundary),
                false,
                false,
                false,
                false,
            )
            .await;
        }
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn stale_opening_export_reemits_token_and_delayed_completion_wins() {
        assert_recovers_persisted_ambiguous_opening(true, None, true, false, false, false).await;
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn exported_opening_becomes_externally_spent_only_with_conclusive_evidence() {
        assert_recovers_persisted_ambiguous_opening(false, None, true, true, false, false).await;
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn final_restore_completion_wins_over_external_spend_evidence() {
        assert_recovers_persisted_ambiguous_opening(false, None, true, false, true, false).await;
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn one_unresolved_export_group_does_not_suppress_an_independent_token() {
        assert_recovers_persisted_ambiguous_opening(false, None, true, true, false, true).await;
    }

    async fn assert_grouped_stale_opening_export(fail_first_group: bool) {
        let temp = tempfile::tempdir().unwrap();
        let loose_db = temp.path().join("loose.sqlite");
        let channel_db = temp.path().join("channels.sqlite");
        let wallet = SqliteClientWallet::open(
            LooseProofWallet::open(&loose_db, "alice").unwrap(),
            &channel_db,
            &sender_secret_hex(),
        )
        .unwrap();
        let client = reqwest::Client::new();
        let mut mints = Vec::new();
        let mut servers = Vec::new();
        for _ in 0..if fail_first_group { 2 } else { 1 } {
            let helper = TestMintHelper::new().await.unwrap();
            let mint = helper.mint();
            let port = free_loopback_port();
            let mint_url = format!("http://127.0.0.1:{port}");
            let config = TestMintConfig::for_port(port);
            let (shutdown_tx, shutdown_rx) = oneshot::channel::<()>();
            let task = tokio::spawn(async move {
                serve_existing_mint_with_shutdown(mint, config, async {
                    let _ = shutdown_rx.await;
                })
                .await
            });
            wait_for_mint(&client, &mint_url).await;
            mints.push((mint_url, helper));
            servers.push((shutdown_tx, task));
        }
        // The failed group must precede the independent group in the export scan.
        mints.sort_by(|left, right| left.0.cmp(&right.0));
        let mut groups = Vec::new();
        for (group_index, (mint_url, helper)) in mints.iter().enumerate() {
            let mut attempts = Vec::new();
            for opening_index in 0..if group_index == 0 { 2 } else { 1 } {
                let keyset_id = if opening_index == 0 {
                    helper.keyset_id()
                } else {
                    rotate_sat_keyset(&helper.mint(), 0).await.unwrap()
                };
                let offer = offer(
                    mint_url,
                    "02a9acc1e48c25eeeb9289b5031cc57da9fe72f3fe2861d264bdc074209b107ba2",
                    &keyset_id.to_string(),
                );
                wallet.ensure_offer_keysets_cached(&offer).unwrap();
                let proofs = helper.mint_proofs(128).await.unwrap();
                assert!(proofs.iter().all(|proof| proof.keyset_id == keyset_id));
                let batch = format!("group-{group_index}-opening-{opening_index}");
                wallet
                    .loose_wallet()
                    .import_proofs(&loose_proofs_from_json(
                        mint_url,
                        "sat",
                        &batch,
                        &batch,
                        &serde_json::to_string(&proofs).unwrap(),
                    ))
                    .unwrap();
                let output_keyset = wallet
                    .select_output_keyset_refreshing_client_first(&offer)
                    .unwrap();
                let attempt = wallet
                    .prepare_target_capacity_attempt(
                        &offer,
                        32,
                        output_keyset,
                        SqliteClientWallet::now_seconds().unwrap() + CHANNEL_EXPIRY_SECONDS,
                    )
                    .unwrap();
                let OpeningSubmissionClaim::Acquired(permit) = wallet
                    .loose_wallet()
                    .claim_opening_attempt_submission(&attempt.prepared.channel_id)
                    .unwrap()
                else {
                    panic!("submission claim not acquired");
                };
                // Journal an old authorized submission without sending the swap.
                wallet
                    .loose_wallet()
                    .authorize_opening_submission_at(permit, 1)
                    .unwrap();
                attempts.push(
                    wallet
                        .loose_wallet()
                        .opening_attempt(&attempt.prepared.channel_id)
                        .unwrap()
                        .unwrap(),
                );
            }
            attempts.sort_by(|left, right| left.attempt_id.cmp(&right.attempt_id));
            groups.push(attempts);
        }
        if fail_first_group {
            let conn = Connection::open(&loose_db).unwrap();
            conn.execute_batch(&format!(
                "CREATE TRIGGER fail_second_grouped_export
                 BEFORE UPDATE ON monad_client_opening_attempts
                 WHEN OLD.attempt_id = '{}' AND NEW.state = 'exported'
                   AND EXISTS (SELECT 1 FROM monad_client_opening_attempts
                               WHERE attempt_id = '{}' AND state = 'exported')
                 BEGIN SELECT RAISE(ABORT, 'injected second export update failure'); END;",
                groups[0][1].attempt_id, groups[0][0].attempt_id,
            ))
            .unwrap();
        }
        let locks = ClientWalletLocks::acquire(&loose_db, &channel_db, WalletLockMode::Maintenance)
            .unwrap();
        let report = wallet
            .export_stale_opening_inputs(&locks.exclusive_access().unwrap())
            .unwrap();
        assert_eq!(report.exports.len(), 1);
        if fail_first_group {
            assert_eq!(report.unresolved.len(), 2);
            for (unresolved, original) in report.unresolved.iter().zip(&groups[0]) {
                assert_eq!(unresolved.attempt_id, original.attempt_id);
                assert_eq!(unresolved.state, OpeningAttemptState::Submitted);
                assert!(unresolved
                    .reason
                    .contains("injected second export update failure"));
            }
        } else {
            assert!(report.unresolved.is_empty());
        }
        let successful_group = usize::from(fail_first_group);
        let exported = &report.exports[0];
        assert_eq!(exported.mint_url, mints[successful_group].0);
        assert_eq!(exported.unit, "sat");
        assert_eq!(
            exported.attempt_ids,
            groups[successful_group]
                .iter()
                .map(|attempt| attempt.attempt_id.clone())
                .collect::<Vec<_>>()
        );
        let mut expected_proofs = Vec::new();
        for (group_index, attempts) in groups.iter().enumerate() {
            for original in attempts {
                let current = wallet
                    .loose_wallet()
                    .opening_attempt(&original.attempt_id)
                    .unwrap()
                    .unwrap();
                if group_index == successful_group {
                    assert_eq!(current.state, OpeningAttemptState::Exported);
                } else {
                    assert_eq!(
                        &current, original,
                        "failed group must roll back both updates"
                    );
                }
                let reserved = wallet
                    .loose_wallet()
                    .proofs_for_reservation(&original.reservation_id)
                    .unwrap();
                assert_eq!(reserved.len(), original.selected_proof_ids.len());
                assert!(!reserved.is_empty());
                assert!(reserved
                    .iter()
                    .all(|proof| proof.state == LooseProofState::Reserved));
                assert_eq!(
                    reserved
                        .iter()
                        .map(|proof| &proof.proof_id)
                        .collect::<HashSet<_>>(),
                    original.selected_proof_ids.iter().collect::<HashSet<_>>()
                );
                if group_index == successful_group {
                    expected_proofs.extend(
                        reserved
                            .iter()
                            .map(|proof| serde_json::from_str::<Proof>(&proof.proof_json).unwrap()),
                    );
                }
            }
        }
        let token: Token = exported.token.parse().unwrap();
        let Token::TokenV4(v4) = &token else {
            panic!("expected TokenV4 export");
        };
        let input_keysets = expected_proofs
            .iter()
            .map(|proof| proof.keyset_id)
            .collect::<HashSet<_>>();
        assert_eq!(input_keysets.len(), if fail_first_group { 1 } else { 2 });
        assert_eq!(v4.token.len(), input_keysets.len());
        assert!(v4
            .token
            .windows(2)
            .all(|groups| groups[0].keyset_id < groups[1].keyset_id));
        assert_eq!(token.mint_url().unwrap().to_string(), exported.mint_url);
        assert_eq!(token.unit(), Some(CurrencyUnit::Sat));
        let keysets: cashu::nuts::KeysetResponse = client
            .get(format!("{}/v1/keysets", exported.mint_url))
            .send()
            .await
            .unwrap()
            .error_for_status()
            .unwrap()
            .json()
            .await
            .unwrap();
        let mut decoded = token.proofs(&keysets.keysets).unwrap();
        decoded.sort_by_key(|proof| proof.secret.to_string());
        expected_proofs.sort_by_key(|proof| proof.secret.to_string());
        assert_eq!(decoded, expected_proofs);
        assert_eq!(exported.proof_count, decoded.len());
        assert_eq!(
            exported.amount_raw,
            decoded
                .iter()
                .map(|proof| proof.amount.to_u64())
                .sum::<u64>()
        );
        assert_eq!(
            wallet
                .export_stale_opening_inputs(&locks.exclusive_access().unwrap())
                .unwrap(),
            report,
            "reexport must preserve the exact token, attempt IDs and partial failure"
        );
        for (shutdown_tx, task) in servers {
            let _ = shutdown_tx.send(());
            task.await.unwrap().unwrap();
        }
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn stale_opening_export_combines_two_valid_openings_in_one_token() {
        assert_grouped_stale_opening_export(false).await;
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn stale_opening_export_rolls_back_second_update_and_exports_independent_group() {
        assert_grouped_stale_opening_export(true).await;
    }

    async fn assert_opening_orchestration_recovers(scenario: OpeningOrchestrationScenario) {
        let helper = TestMintHelper::new().await.unwrap();
        let mint = helper.mint();
        let keyset_id = helper.keyset_id().to_string();
        let proofs = helper.mint_proofs(128).await.unwrap();
        let port = free_loopback_port();
        let mint_url = format!("http://127.0.0.1:{port}");
        let config = TestMintConfig::for_port(port);
        let (shutdown_tx, shutdown_rx) = oneshot::channel::<()>();
        let task = tokio::spawn(async move {
            serve_existing_mint_with_shutdown(mint, config, async {
                let _ = shutdown_rx.await;
            })
            .await
        });
        wait_for_mint(&reqwest::Client::new(), &mint_url).await;
        let temp = tempfile::tempdir().unwrap();
        let loose_db = temp.path().join("loose.sqlite");
        let channel_db = temp.path().join("channels.sqlite");
        let wallet = SqliteClientWallet::open(
            LooseProofWallet::open(&loose_db, "alice").unwrap(),
            &channel_db,
            &sender_secret_hex(),
        )
        .unwrap();
        wallet
            .loose_wallet()
            .import_proofs(&loose_proofs_from_json(
                &mint_url,
                "sat",
                "orchestration",
                "orchestration",
                &serde_json::to_string(&proofs).unwrap(),
            ))
            .unwrap();
        let offer = offer(
            &mint_url,
            "02a9acc1e48c25eeeb9289b5031cc57da9fe72f3fe2861d264bdc074209b107ba2",
            &keyset_id,
        );
        wallet.ensure_offer_keysets_cached(&offer).unwrap();
        let output_keyset = wallet
            .select_output_keyset_refreshing_client_first(&offer)
            .unwrap();
        let attempt = wallet
            .prepare_target_capacity_attempt(
                &offer,
                31,
                output_keyset,
                SqliteClientWallet::now_seconds().unwrap() + CHANNEL_EXPIRY_SECONDS,
            )
            .unwrap();
        let prepared = attempt.prepared.clone();
        let id = &prepared.channel_id;
        let reservation_id = attempt.reservation.reservation_id.clone();
        let reserved = wallet
            .loose_wallet()
            .proofs_for_reservation(&reservation_id)
            .unwrap();
        assert!(!reserved.is_empty());
        assert!(reserved
            .iter()
            .all(|proof| proof.state == LooseProofState::Reserved));
        let expected_change = prepared.opening.change_amount_raw;
        assert!(expected_change > 0);
        let networking = ScriptedOpeningNetworking {
            inner: OpeningRecoveryHttpNetworking::new().unwrap(),
            scenario,
            swaps: Mutex::new(Vec::new()),
            restores: Mutex::new(0),
        };
        match scenario {
            OpeningOrchestrationScenario::InvalidRestore { response_index, .. } => {
                let OpeningSubmissionClaim::Acquired(permit) = wallet
                    .loose_wallet()
                    .claim_opening_attempt_submission(id)
                    .unwrap()
                else {
                    panic!("submission claim not acquired");
                };
                wallet
                    .loose_wallet()
                    .authorize_opening_submission_at(permit, 1)
                    .unwrap();
                networking
                    .inner
                    .call_mint_swap(&mint_url, &prepared.swap_request_json)
                    .unwrap();
                let before = wallet.loose_wallet().opening_attempt(id).unwrap().unwrap();
                let executions = wallet.loose_wallet().opening_executions(id).unwrap();
                let error = wallet
                    .recover_journaled_opening(&before, &networking)
                    .expect_err(&format!("{scenario:?}"));
                if matches!(
                    scenario,
                    OpeningOrchestrationScenario::InvalidRestore {
                        mutation: InvalidRestore::IncorrectSignaturePoint,
                        ..
                    }
                ) {
                    assert!(error.to_string().to_lowercase().contains("dleq"), "{error}");
                }
                // Well-formed pairs are matched by upstream checked completion,
                // after both reads; malformed JSON/counts still fail immediately.
                let expected_reads = if matches!(
                    scenario,
                    OpeningOrchestrationScenario::InvalidRestore {
                        mutation: InvalidRestore::Json
                            | InvalidRestore::Count
                            | InvalidRestore::Signature,
                        ..
                    }
                ) {
                    response_index + 1
                } else {
                    2
                };
                assert_eq!(*networking.restores.lock().unwrap(), expected_reads);
                assert_eq!(
                    wallet.loose_wallet().opening_attempt(id).unwrap().unwrap(),
                    before
                );
                assert_eq!(
                    wallet.loose_wallet().opening_executions(id).unwrap(),
                    executions
                );
                assert!(networking.swaps.lock().unwrap().is_empty());
            }
            _ => {
                assert!(wallet
                    .execute_open_attempt_with_networking(&offer, attempt, true, &networking)
                    .is_err());
                let swaps = networking.swaps.lock().unwrap();
                let executions = wallet.loose_wallet().opening_executions(id).unwrap();
                match scenario {
                    OpeningOrchestrationScenario::InvalidDirectAndRestore
                    | OpeningOrchestrationScenario::LostResponseAndInvalidRestore => {
                        assert_eq!(swaps.len(), 1);
                        assert_eq!(*networking.restores.lock().unwrap(), 1);
                        assert_eq!(executions.len(), 1);
                    }
                    OpeningOrchestrationScenario::RejectedReplayThenDelayedOriginal => {
                        assert_eq!(swaps.len(), 2);
                        assert_eq!(swaps[0], swaps[1]);
                        assert_eq!(swaps[0], prepared.swap_request_json);
                        assert_eq!(executions.len(), 2);
                        assert_eq!(executions[0].kind, OpeningExecutionKind::Initial);
                        assert_eq!(executions[0].status, OpeningExecutionStatus::Uncertain);
                        assert_eq!(executions[1].kind, OpeningExecutionKind::Replay);
                        assert_eq!(executions[1].status, OpeningExecutionStatus::Rejected);
                    }
                    _ => unreachable!(),
                }
            }
        }
        let journal = wallet.loose_wallet().opening_attempt(id).unwrap().unwrap();
        if matches!(
            scenario,
            OpeningOrchestrationScenario::InvalidDirectAndRestore
        ) {
            let executions = wallet.loose_wallet().opening_executions(id).unwrap();
            assert!(wallet
                .recover_journaled_opening(&journal, &networking)
                .is_err());
            assert_eq!(
                wallet.loose_wallet().opening_attempt(id).unwrap().unwrap(),
                journal
            );
            assert_eq!(
                wallet.loose_wallet().opening_executions(id).unwrap(),
                executions
            );
        }
        assert_eq!(journal.state, OpeningAttemptState::Submitted);
        assert_eq!(journal.rejection_code, None);
        assert_eq!(
            journal.prepared_open_json,
            serde_json::to_string(&prepared).unwrap()
        );
        assert_eq!(
            journal.selected_proof_ids.iter().collect::<HashSet<_>>(),
            reserved
                .iter()
                .map(|proof| &proof.proof_id)
                .collect::<HashSet<_>>()
        );
        assert_eq!(
            wallet
                .loose_wallet()
                .proofs_for_reservation(&reservation_id)
                .unwrap(),
            reserved
        );
        assert_eq!(
            wallet
                .loose_wallet()
                .available_balance_raw(&mint_url, "sat", std::slice::from_ref(&keyset_id))
                .unwrap(),
            0
        );
        assert!(wallet.get_channel(id).is_err());
        assert_eq!(
            wallet
                .channel_db
                .lock()
                .unwrap()
                .query_row("SELECT COUNT(*) FROM monad_client_channels", [], |row| row
                    .get::<_, u64>(
                    0
                ))
                .unwrap(),
            0
        );

        if matches!(
            scenario,
            OpeningOrchestrationScenario::RejectedReplayThenDelayedOriginal
        ) {
            // The keyset remains active. Only this delayed original is actually executed.
            networking
                .inner
                .call_mint_swap(&mint_url, &prepared.swap_request_json)
                .unwrap();
        }
        assert_eq!(
            prepared_input_state(&prepared, &networking.inner).unwrap(),
            ExactInputState::AllSpent
        );
        let executions = wallet.loose_wallet().opening_executions(id).unwrap();
        drop(wallet);
        let wallet = SqliteClientWallet::open(
            LooseProofWallet::open(&loose_db, "alice").unwrap(),
            &channel_db,
            &sender_secret_hex(),
        )
        .unwrap();
        assert_eq!(
            wallet.loose_wallet().opening_attempt(id).unwrap().unwrap(),
            journal
        );
        let restore_only = ScriptedOpeningNetworking {
            inner: OpeningRecoveryHttpNetworking::new().unwrap(),
            scenario: OpeningOrchestrationScenario::RestoreOnly,
            swaps: Mutex::new(Vec::new()),
            restores: Mutex::new(0),
        };
        let report = wallet
            .recover_pending_openings_with_networking(&restore_only)
            .unwrap();
        assert!(restore_only.swaps.lock().unwrap().is_empty());
        assert_eq!(*restore_only.restores.lock().unwrap(), 2);
        assert_eq!(report.recovered_channel_ids, vec![id.clone()]);
        assert!(report.unresolved.is_empty());
        assert!(report.externally_spent_attempt_ids.is_empty());
        assert_eq!(
            wallet.get_channel(id).unwrap().state,
            WalletChannelState::Open
        );
        let completed = wallet.loose_wallet().opening_attempt(id).unwrap().unwrap();
        assert_eq!(completed.state, OpeningAttemptState::Completed);
        let spent = wallet
            .loose_wallet()
            .proofs_for_reservation(&reservation_id)
            .unwrap();
        assert_eq!(spent.len(), reserved.len());
        for (actual, original) in spent.iter().zip(&reserved) {
            assert_eq!(actual.proof_id, original.proof_id);
            assert_eq!(actual.proof_json, original.proof_json);
            assert_eq!(actual.state, LooseProofState::Spent);
        }
        assert_eq!(
            wallet
                .loose_wallet()
                .available_balance_raw(&mint_url, "sat", std::slice::from_ref(&keyset_id))
                .unwrap(),
            expected_change
        );
        assert!(wallet
            .recover_pending_openings_with_networking(&restore_only)
            .unwrap()
            .is_empty());
        assert!(restore_only.swaps.lock().unwrap().is_empty());
        assert_eq!(*restore_only.restores.lock().unwrap(), 2);
        assert_eq!(
            wallet.loose_wallet().opening_attempt(id).unwrap().unwrap(),
            completed
        );
        assert_eq!(
            wallet.loose_wallet().opening_executions(id).unwrap(),
            executions,
            "startup/manual recovery must be restore-only"
        );
        assert_eq!(
            wallet
                .loose_wallet()
                .proofs_for_reservation(&reservation_id)
                .unwrap(),
            spent
        );
        assert_eq!(
            wallet
                .loose_wallet()
                .available_balance_raw(&mint_url, "sat", std::slice::from_ref(&keyset_id))
                .unwrap(),
            expected_change
        );
        assert_eq!(
            wallet
                .channel_db
                .lock()
                .unwrap()
                .query_row("SELECT COUNT(*) FROM monad_client_channels", [], |row| row
                    .get::<_, u64>(
                    0
                ))
                .unwrap(),
            1
        );
        assert_eq!(Connection::open(&loose_db).unwrap().query_row(
            "SELECT COUNT(*) FROM monad_client_opening_attempts WHERE wallet_name = 'alice'",
            [], |row| row.get::<_, u64>(0),
        ).unwrap(), 1, "no successor attempt");
        let _ = shutdown_tx.send(());
        task.await.unwrap().unwrap();
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn orchestration_invalid_direct_and_restore_preserve_custody_until_valid_recovery() {
        assert_opening_orchestration_recovers(
            OpeningOrchestrationScenario::InvalidDirectAndRestore,
        )
        .await;
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn orchestration_lost_opening_response_and_invalid_restore_preserve_custody() {
        assert_opening_orchestration_recovers(
            OpeningOrchestrationScenario::LostResponseAndInvalidRestore,
        )
        .await;
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn orchestration_invalid_funding_and_change_restores_preserve_journal() {
        for response_index in 0..=1 {
            for mutation in [
                InvalidRestore::Json,
                InvalidRestore::Count,
                InvalidRestore::Identity,
                InvalidRestore::Duplicate,
                InvalidRestore::Partial,
                InvalidRestore::Absent,
                InvalidRestore::Signature,
                InvalidRestore::IncorrectSignaturePoint,
            ] {
                assert_opening_orchestration_recovers(
                    OpeningOrchestrationScenario::InvalidRestore {
                        response_index,
                        mutation,
                    },
                )
                .await;
            }
        }
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn orchestration_scripted_replay_rejection_then_delayed_original_recovers_once() {
        assert_opening_orchestration_recovers(
            OpeningOrchestrationScenario::RejectedReplayThenDelayedOriginal,
        )
        .await;
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn replay_rejection_does_not_resolve_prior_execution_uncertainty() {
        let mint_helper = TestMintHelper::new().await.unwrap();
        let mint = mint_helper.mint();
        let initial_keyset_id = mint_helper.keyset_id().to_string();
        let input_proofs = mint_helper.mint_proofs(128).await.unwrap();

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
        let loose_db = temp.path().join("loose.sqlite");
        let channel_db = temp.path().join("channels.sqlite");
        let loose_wallet = LooseProofWallet::open(&loose_db, "alice").unwrap();
        loose_wallet
            .import_proofs(&loose_proofs_from_json(
                &mint_url,
                "sat",
                "four-submission-quote",
                "four-submission-batch",
                &serde_json::to_string(&input_proofs).unwrap(),
            ))
            .unwrap();
        let wallet =
            SqliteClientWallet::open(loose_wallet, &channel_db, &sender_secret_hex()).unwrap();
        let receiver_pubkey = "02a9acc1e48c25eeeb9289b5031cc57da9fe72f3fe2861d264bdc074209b107ba2";
        let mut offer = offer(&mint_url, receiver_pubkey, &initial_keyset_id);

        wallet.ensure_offer_keysets_cached(&offer).unwrap();
        let output_keyset = wallet
            .select_output_keyset_refreshing_client_first(&offer)
            .unwrap();
        let attempt = wallet
            .prepare_target_capacity_attempt(
                &offer,
                32,
                output_keyset,
                SqliteClientWallet::now_seconds().unwrap() + CHANNEL_EXPIRY_SECONDS,
            )
            .unwrap();
        let losing_attempt = attempt.clone();
        let opening_id = attempt.opening_id.clone();
        let reservation_id = attempt.reservation.reservation_id.clone();
        let expected_input_ys =
            serde_json::from_str::<Vec<Proof>>(&attempt.prepared.opening.input_token)
                .unwrap()
                .into_iter()
                .map(|proof| proof.y().unwrap().to_string())
                .collect::<HashSet<_>>();

        let successor_keyset_id = rotate_sat_keyset(&mint, 0).await.unwrap().to_string();
        assert_ne!(initial_keyset_id, successor_keyset_id);
        offer.preferred_keyset_ids.push(successor_keyset_id.clone());

        let networking = FourSubmissionNetworking::new();
        let error = wallet
            .execute_open_attempt_with_networking(&offer, attempt, true, &networking)
            .unwrap_err();
        assert!(error.to_string().contains("input may be spent"));
        let losing_error = wallet
            .execute_open_attempt_with_networking(&offer, losing_attempt, true, &networking)
            .unwrap_err();
        assert_eq!(
            losing_error,
            WalletError::OpeningInProgress {
                channel_id: opening_id.clone()
            }
        );

        {
            let swap_requests = networking.swap_requests.lock().unwrap();
            assert_eq!(swap_requests.len(), 2);
            assert_eq!(swap_requests[0], swap_requests[1]);
        }

        let root = wallet
            .loose_wallet()
            .opening_attempt(&opening_id)
            .unwrap()
            .unwrap();
        assert_eq!(root.state, OpeningAttemptState::Submitted);
        assert_eq!(root.rejection_code, None);
        assert!(root.latest_submitted_at.is_some());
        assert_eq!(root.predecessor_attempt_id, None);
        let root_prepared: PreparedOpenChannel =
            serde_json::from_str(&root.prepared_open_json).unwrap();
        assert_eq!(root_prepared.keyset_id, initial_keyset_id);

        let executions = wallet
            .loose_wallet()
            .opening_executions(&opening_id)
            .unwrap();
        assert_eq!(executions.len(), 2);
        assert_eq!(executions[0].execution_sequence, 1);
        assert_eq!(executions[0].kind, OpeningExecutionKind::Initial);
        assert_eq!(executions[0].status, OpeningExecutionStatus::Uncertain);
        assert_eq!(executions[1].execution_sequence, 2);
        assert_eq!(executions[1].kind, OpeningExecutionKind::Replay);
        assert_eq!(executions[1].status, OpeningExecutionStatus::Rejected);

        {
            let state_requests = networking.check_state_requests.lock().unwrap();
            assert_eq!(state_requests.len(), 1);
            for request in state_requests.iter() {
                assert_eq!(request.ys.len(), expected_input_ys.len());
                assert_eq!(
                    request
                        .ys
                        .iter()
                        .map(ToString::to_string)
                        .collect::<HashSet<_>>(),
                    expected_input_ys
                );
            }
        }

        let reserved = wallet
            .loose_wallet()
            .proofs_for_reservation(&reservation_id)
            .unwrap();
        assert!(!reserved.is_empty());
        assert!(reserved
            .iter()
            .all(|proof| proof.state == LooseProofState::Reserved));

        let journal_db = Connection::open(&loose_db).unwrap();
        let successor_count: u64 = journal_db
            .query_row(
                "SELECT COUNT(*) FROM monad_client_opening_attempts
                 WHERE wallet_name = 'alice' AND opening_id = ?1
                   AND predecessor_attempt_id IS NOT NULL",
                params![opening_id],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(successor_count, 0);
        let channel_count: u64 = wallet
            .channel_db
            .lock()
            .unwrap()
            .query_row("SELECT COUNT(*) FROM monad_client_channels", [], |row| {
                row.get(0)
            })
            .unwrap();
        assert_eq!(channel_count, 0);

        assert_eq!(networking.swap_requests.lock().unwrap().len(), 2);

        let _ = shutdown_tx.send(());
        mint_task.await.unwrap().unwrap();
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn output_keyset_selection_refreshes_for_new_relay_preference() {
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
        // The relay preference is newer, so refresh before falling back to the
        // cached active keyset. The refresh reveals the preferred active ID.
        let second_offer = offer(&mint_url, receiver_pubkey, &second_keyset_id);
        let selected = wallet
            .select_output_keyset_refreshing_client_first(&second_offer)
            .unwrap();
        assert_eq!(selected.id, second_keyset_id);

        let _ = shutdown_tx.send(());
        mint_task.await.unwrap().unwrap();
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn output_keyset_selection_falls_back_after_client_refresh() {
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
        let selected = wallet
            .select_output_keyset_refreshing_client_first(&first_offer)
            .unwrap();
        let cached_keysets = wallet
            .bridge
            .lock()
            .unwrap()
            .cached_keysets_for_unit(&mint_url, &CurrencyUnit::Sat);
        assert!(cached_keysets
            .iter()
            .any(|(keyset_id, _entry)| keyset_id.to_string() == first_keyset_id));
        assert_eq!(selected.id, first_keyset_id);

        let _ = shutdown_tx.send(());
        mint_task.await.unwrap().unwrap();
    }

    #[test]
    fn active_output_keyset_selection_falls_back_from_inactive_preference() {
        let old =
            test_keyset_id("0101010101010101010101010101010101010101010101010101010101010101");
        let new =
            test_keyset_id("0202020202020202020202020202020202020202020202020202020202020202");
        let offer = RelayPaymentOffer {
            receiver_pubkey: "receiver".to_string(),
            mint_url: "http://mint".to_string(),
            unit: "sat".to_string(),
            preferred_keyset_ids: vec![old.to_string()],
            negotiated_keyset_versions: BTreeSet::from(["v1".to_string(), "v2".to_string()]),
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
    fn active_output_keyset_selection_rejects_without_compatible_active_keyset() {
        let old =
            test_keyset_id("0101010101010101010101010101010101010101010101010101010101010101");
        let other_unit =
            test_keyset_id("0202020202020202020202020202020202020202020202020202020202020202");
        let offer = RelayPaymentOffer {
            receiver_pubkey: "receiver".to_string(),
            mint_url: "http://mint".to_string(),
            unit: "sat".to_string(),
            preferred_keyset_ids: vec![old.to_string(), other_unit.to_string()],
            negotiated_keyset_versions: BTreeSet::from(["v2".to_string()]),
            in_bytes_per_millisat: 1,
            out_bytes_per_millisat: 1,
        };
        let bridge = bridge_with_cached_keysets(vec![
            (old, CurrencyUnit::Sat, true),
            (other_unit, CurrencyUnit::Msat, true),
        ]);

        let selected = active_output_keyset_id_from_cache(&bridge, &offer).unwrap();
        assert_eq!(selected, OutputKeysetSelection::NoCompatibleActiveKeyset);
    }

    #[tokio::test]
    async fn plain_provisioning_reports_insufficient_funds_before_keyset_io() {
        let temp = tempfile::tempdir().unwrap();
        let loose = LooseProofWallet::open(temp.path().join("loose.sqlite"), "alice").unwrap();
        let wallet = SqliteClientWallet::open(
            loose,
            temp.path().join("channels.sqlite"),
            &sender_secret_hex(),
        )
        .unwrap();
        let mint_url = "http://127.0.0.1:1";
        let keyset_id =
            test_keyset_id("0101010101010101010101010101010101010101010101010101010101010101")
                .to_string();
        let receiver_pubkey = SecretKey::generate().public_key().to_hex();

        let error = wallet
            .provision_channel(&offer(mint_url, &receiver_pubkey, &keyset_id), 1_000)
            .unwrap_err();

        assert_eq!(
            error,
            WalletError::InsufficientLooseProofFunds {
                mint_url: mint_url.to_string(),
                unit: "sat".to_string(),
                requested_raw: 1,
                available_raw: 0,
            }
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn plain_provisioning_types_unavailable_input_keyset_metadata() {
        let temp = tempfile::tempdir().unwrap();
        let loose = LooseProofWallet::open(temp.path().join("loose.sqlite"), "alice").unwrap();
        let wallet = SqliteClientWallet::open(
            loose,
            temp.path().join("channels.sqlite"),
            &sender_secret_hex(),
        )
        .unwrap();
        let mint_url = "http://127.0.0.1:1";
        let keyset_id =
            test_keyset_id("0101010101010101010101010101010101010101010101010101010101010101")
                .to_string();
        wallet
            .loose_wallet()
            .import_proofs(&[NewLooseProof {
                proof_id: "proof".to_string(),
                mint_url: mint_url.to_string(),
                unit: "sat".to_string(),
                keyset_id: keyset_id.clone(),
                amount_raw: 1,
                proof_json: "{}".to_string(),
                source_quote_id: None,
                source_batch_id: None,
            }])
            .unwrap();
        let receiver_pubkey = SecretKey::generate().public_key().to_hex();

        let error = wallet
            .provision_channel(&offer(mint_url, &receiver_pubkey, &keyset_id), 1_000)
            .unwrap_err();

        assert!(matches!(
            error,
            WalletError::InputKeysetMetadataUnavailable {
                mint_url: failed_mint_url,
                unit,
                keyset_ids,
                ..
            } if failed_mint_url == mint_url && unit == "sat" && keyset_ids == vec![keyset_id.clone()]
        ));
        assert_eq!(
            wallet
                .loose_wallet()
                .available_balance_raw(mint_url, "sat", &[keyset_id])
                .unwrap(),
            1
        );
    }

    #[test]
    fn string_only_errors_are_not_typed_rejection_evidence() {
        for message in [
            r#"{"code":12002}"#,
            r#"MONAD_HTTP_CLIENT_ERROR 400 Bad Request - {"code":12002}"#,
            "mint HTTP rejection (400, NUT-00 code Some(12002))",
        ] {
            let error = anyhow::Error::msg(message);
            assert!(error.downcast_ref::<MintHttpRejection>().is_none());
        }
    }

    #[test]
    fn nut07_replay_gate_requires_every_input_unspent_in_one_response() {
        let prepared = prepared_opening_with_input_secrets(&["input-a", "input-b"]);
        let all_unspent =
            StateCheckNetworking::new(CheckStateMode::States(vec![State::Unspent, State::Unspent]));
        assert!(prepared_inputs_are_all_unspent(&prepared, &all_unspent).unwrap());
        assert_eq!(*all_unspent.requested_y_count.lock().unwrap(), Some(2));

        for other_state in [
            State::Pending,
            State::Spent,
            State::Reserved,
            State::PendingSpent,
        ] {
            let mixed = StateCheckNetworking::new(CheckStateMode::States(vec![
                State::Unspent,
                other_state,
            ]));
            assert!(!prepared_inputs_are_all_unspent(&prepared, &mixed).unwrap());
        }
    }

    #[test]
    fn nut07_replay_gate_rejects_incomplete_or_duplicate_responses() {
        let prepared = prepared_opening_with_input_secrets(&["input-a", "input-b"]);
        let missing = StateCheckNetworking::new(CheckStateMode::MissingLast);
        assert!(prepared_inputs_are_all_unspent(&prepared, &missing).is_err());

        let duplicate = StateCheckNetworking::new(CheckStateMode::DuplicateFirst);
        assert!(prepared_inputs_are_all_unspent(&prepared, &duplicate).is_err());
    }

    #[test]
    fn nut09_restore_absence_requires_empty_paired_arrays() {
        let keyset_id =
            test_keyset_id("0101010101010101010101010101010101010101010101010101010101010101");
        let output_a = cashu::nuts::BlindedMessage::new(
            cashu::Amount::from(1),
            keyset_id,
            "02a9acc1e48c25eeeb9289b5031cc57da9fe72f3fe2861d264bdc074209b107ba2"
                .parse()
                .unwrap(),
        );
        let output_b = cashu::nuts::BlindedMessage::new(
            cashu::Amount::from(2),
            keyset_id,
            "03b287e320b3e35e9c0190626d6f0ad375b5f1f34c0f7c8f0b6be9f14c53c9d9d9"
                .parse()
                .unwrap(),
        );
        let signature_a = cashu::nuts::BlindSignature {
            amount: cashu::Amount::from(1),
            keyset_id,
            c: output_a.blinded_secret,
            dleq: None,
        };
        let signature_b = cashu::nuts::BlindSignature {
            amount: cashu::Amount::from(2),
            keyset_id,
            c: output_b.blinded_secret,
            dleq: None,
        };
        let empty = serde_json::to_string(&RestoreResponse {
            outputs: vec![],
            signatures: vec![],
        })
        .unwrap();
        assert!(restore_response_is_absent(&empty).unwrap());

        let reversed = serde_json::to_string(&RestoreResponse {
            outputs: vec![output_b.clone(), output_a.clone()],
            signatures: vec![signature_b.clone(), signature_a.clone()],
        })
        .unwrap();
        assert!(!restore_response_is_absent(&reversed).unwrap());
        for invalid in ["not JSON", "{}", r#"{"outputs":[]}"#] {
            assert!(restore_response_is_absent(invalid).is_err());
        }
    }

    #[test]
    fn nut09_mismatched_pairs_are_not_absence() {
        let keyset_id =
            test_keyset_id("0101010101010101010101010101010101010101010101010101010101010101");
        let output = cashu::nuts::BlindedMessage::new(
            cashu::Amount::from(1),
            keyset_id,
            "02a9acc1e48c25eeeb9289b5031cc57da9fe72f3fe2861d264bdc074209b107ba2"
                .parse()
                .unwrap(),
        );
        let missing_signature = serde_json::to_string(&RestoreResponse {
            outputs: vec![output.clone()],
            signatures: vec![],
        })
        .unwrap();
        assert!(restore_response_is_absent(&missing_signature).is_err());
        let missing_output = serde_json::to_string(&RestoreResponse {
            outputs: vec![],
            signatures: vec![cashu::nuts::BlindSignature {
                amount: cashu::Amount::from(1),
                keyset_id,
                c: output.blinded_secret,
                dleq: None,
            }],
        })
        .unwrap();
        assert!(restore_response_is_absent(&missing_output).is_err());
    }
}
