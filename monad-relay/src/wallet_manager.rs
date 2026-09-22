use crate::channel_store::ChannelStore;
use crate::listener::{
    shared_spilman_mint_cache, SharedSpilmanMintCache, SpilmanMintCache, TrustedMintUnits,
};
use crate::payments::{CloseOutcome, RelayPayments, SpilmanRelayPayments};
use cashu::nuts::{BlindedMessage, Proof, SecretKey, SwapRequest};
use cdk_spilman::configurable_host::{KeysetCacheEntry, SpilmanStorage, SqliteStorage};
use cdk_spilman::configurable_networking::{
    build_keyset_info_json, fetch_all_keysets_from_mint, MintKeysetWithKeys,
};
use cdk_spilman::{
    complete_funding_swap, complete_plain_change_restore, create_plain_blinded_messages,
    ChannelFunding, ChannelState, CloseError, SpilmanAsyncKeysetRefresher, SpilmanAsyncMintClient,
};
use monad_common::config::RelayChannelPolicyConfig;
use monad_common::wallet_lock::{WalletLockIdentity, WalletLockMode, WalletLocks};
use rusqlite::{params, Connection, OpenFlags, OptionalExtension};
use serde::Serialize;
use std::collections::{BTreeMap, HashMap};
use std::future::Future;
use std::io;
use std::pin::Pin;
use std::sync::{Arc, Mutex, RwLock};

mod drain_recovery;

const CREATE_IDENTITIES_TABLE_SQL: &str = r#"
    CREATE TABLE IF NOT EXISTS monad_relay_wallet_identities (
        relay_name TEXT PRIMARY KEY,
        receiver_secret_hex TEXT NOT NULL,
        receiver_pubkey_hex TEXT NOT NULL UNIQUE
    )
"#;

const CREATE_CHANNEL_META_TABLE_SQL: &str = r#"
    CREATE TABLE IF NOT EXISTS monad_relay_channel_meta (
        channel_id TEXT PRIMARY KEY,
        relay_name TEXT NOT NULL,
        receiver_pubkey_hex TEXT NOT NULL
    )
"#;

const CREATE_DRAIN_TABLES_SQL: &str = r#"
    CREATE TABLE IF NOT EXISTS monad_relay_drain_journals (
        drain_id TEXT PRIMARY KEY,
        journal_json TEXT NOT NULL
    );
    CREATE TABLE IF NOT EXISTS monad_relay_drains (
        drain_id TEXT PRIMARY KEY,
        relay_name TEXT NOT NULL,
        mint_url TEXT NOT NULL,
        unit TEXT NOT NULL,
        state TEXT NOT NULL,
        input_amount_raw INTEGER NOT NULL,
        output_amount_raw INTEGER NOT NULL,
        swap_request_json TEXT NOT NULL,
        restore_request_json TEXT NOT NULL,
        output_secrets_json TEXT NOT NULL,
        output_keyset_id TEXT NOT NULL,
        output_keyset_info_json TEXT NOT NULL,
        output_proofs_json TEXT,
        error TEXT,
        created_at INTEGER NOT NULL,
        submitted_at INTEGER,
        completed_at INTEGER,
        failed_at INTEGER
    );

    CREATE TABLE IF NOT EXISTS monad_relay_drain_inputs (
        drain_id TEXT NOT NULL,
        channel_id TEXT NOT NULL,
        receiver_sum_raw INTEGER NOT NULL,
        receiver_proofs_json TEXT NOT NULL,
        PRIMARY KEY (drain_id, channel_id),
        FOREIGN KEY (drain_id) REFERENCES monad_relay_drains(drain_id)
    );

    CREATE TABLE IF NOT EXISTS monad_relay_drained_channels (
        channel_id TEXT PRIMARY KEY,
        drain_id TEXT NOT NULL,
        FOREIGN KEY (drain_id) REFERENCES monad_relay_drains(drain_id)
    );
"#;

#[derive(Clone, PartialEq, Eq, Serialize)]
pub struct DrainSwapResult {
    pub drain_id: String,
    pub relay_name: String,
    pub mint_url: String,
    pub unit: String,
    pub input_amount_raw: u64,
    pub output_amount_raw: u64,
    pub output_proofs_json: String,
    pub channel_ids: Vec<String>,
    pub recovered: bool,
}

impl std::fmt::Debug for DrainSwapResult {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DrainSwapResult").finish_non_exhaustive()
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct DrainSummary {
    pub drain_id: String,
    pub relay_name: String,
    pub mint_url: String,
    pub unit: String,
    pub state: String,
    pub input_amount_raw: u64,
    pub output_amount_raw: u64,
}

pub trait DrainSwapNetworking: Sync {
    fn checked_swap<'a>(
        &'a self,
        mint: &'a str,
        request: &'a str,
    ) -> Pin<Box<dyn Future<Output = anyhow::Result<String>> + Send + 'a>> {
        Box::pin(async move {
            self.call_mint_swap(mint, request)
                .await
                .map_err(|_| anyhow::anyhow!("untyped drain submission failure"))
        })
    }

    fn checked_state<'a>(
        &'a self,
        _: &'a str,
        _: &'a str,
    ) -> Pin<Box<dyn Future<Output = anyhow::Result<String>> + Send + 'a>> {
        Box::pin(async { Err(anyhow::anyhow!("drain input-state transport unavailable")) })
    }
    fn call_mint_swap<'a>(
        &'a self,
        mint_url: &'a str,
        swap_request_json: &'a str,
    ) -> Pin<Box<dyn Future<Output = Result<String, String>> + Send + 'a>>;

    fn call_mint_restore<'a>(
        &'a self,
        mint_url: &'a str,
        restore_request_json: &'a str,
    ) -> Pin<Box<dyn Future<Output = Result<String, String>> + Send + 'a>>;
}

#[derive(Debug, Clone)]
pub struct RelayWalletMintClient {
    client: reqwest::Client,
}

impl RelayWalletMintClient {
    pub fn new() -> Self {
        Self {
            client: reqwest::Client::new(),
        }
    }

    async fn post_json(&self, url: String, body: String, action: &str) -> Result<String, String> {
        let resp = self
            .client
            .post(url)
            .timeout(std::time::Duration::from_secs(15))
            .header("Content-Type", "application/json")
            .body(body)
            .send()
            .await
            .map_err(|e| format!("{action} request failed: {e}"))?;
        if !resp.status().is_success() {
            let status = resp.status();
            let body = resp.text().await.unwrap_or_default();
            return Err(monad_common::mint_error::MintHttpRejection::from_body(
                status.as_u16(),
                &body,
            )
            .to_string());
        }
        resp.text()
            .await
            .map_err(|e| format!("Failed to read {action} response: {e}"))
    }
}

impl Default for RelayWalletMintClient {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait::async_trait]
impl crate::mint_recovery::RecoveryMintClient for RelayWalletMintClient {
    async fn swap_checked(&self, mint: &str, request: &str) -> anyhow::Result<String> {
        crate::mint_recovery::post(&self.client, mint, "v1/swap", request).await
    }
    async fn restore(&self, mint: &str, request: &str) -> anyhow::Result<String> {
        crate::mint_recovery::post(&self.client, mint, "v1/restore", request).await
    }
    async fn check_state(&self, mint: &str, request: &str) -> anyhow::Result<String> {
        crate::mint_recovery::post(&self.client, mint, "v1/checkstate", request).await
    }
}

#[async_trait::async_trait]
impl SpilmanAsyncMintClient for RelayWalletMintClient {
    async fn call_mint_swap(
        &self,
        mint_url: &str,
        swap_request_json: &str,
    ) -> Result<String, String> {
        self.post_json(
            format!("{mint_url}/v1/swap"),
            swap_request_json.to_string(),
            "Swap",
        )
        .await
    }
}

impl DrainSwapNetworking for RelayWalletMintClient {
    fn checked_swap<'a>(
        &'a self,
        mint: &'a str,
        request: &'a str,
    ) -> Pin<Box<dyn Future<Output = anyhow::Result<String>> + Send + 'a>> {
        Box::pin(crate::mint_recovery::post(
            &self.client,
            mint,
            "v1/swap",
            request,
        ))
    }
    fn checked_state<'a>(
        &'a self,
        mint: &'a str,
        request: &'a str,
    ) -> Pin<Box<dyn Future<Output = anyhow::Result<String>> + Send + 'a>> {
        Box::pin(crate::mint_recovery::post(
            &self.client,
            mint,
            "v1/checkstate",
            request,
        ))
    }
    fn call_mint_swap<'a>(
        &'a self,
        mint_url: &'a str,
        swap_request_json: &'a str,
    ) -> Pin<Box<dyn Future<Output = Result<String, String>> + Send + 'a>> {
        Box::pin(async move {
            SpilmanAsyncMintClient::call_mint_swap(self, mint_url, swap_request_json).await
        })
    }

    fn call_mint_restore<'a>(
        &'a self,
        mint_url: &'a str,
        restore_request_json: &'a str,
    ) -> Pin<Box<dyn Future<Output = Result<String, String>> + Send + 'a>> {
        Box::pin(async move {
            self.post_json(
                format!("{mint_url}/v1/restore"),
                restore_request_json.to_string(),
                "Restore",
            )
            .await
        })
    }
}

#[derive(Debug, Clone)]
pub struct RelayWalletIdentity {
    pub name: String,
    pub receiver_secret: SecretKey,
}

#[derive(Clone)]
pub(crate) struct ChannelMetadataStore {
    pub(crate) db_path: String,
    authority: Arc<Mutex<WalletLocks>>,
}

impl ChannelMetadataStore {
    pub(crate) fn new(
        db_path: impl Into<String>,
        authority: Arc<Mutex<WalletLocks>>,
    ) -> io::Result<Self> {
        let store = Self {
            db_path: db_path.into(),
            authority,
        };
        store.init()?;
        Ok(store)
    }

    fn init(&self) -> io::Result<()> {
        let conn = cdk_spilman::sqlite_durability::open_wallet_database(&self.db_path)
            .map_err(|e| io::Error::other(format!("open relay wallet metadata db: {e}")))?;
        conn.execute_batch(CREATE_CHANNEL_META_TABLE_SQL)
            .map_err(|e| io::Error::other(format!("create relay wallet metadata table: {e}")))?;
        Ok(())
    }

    pub(crate) fn record_channel(
        &self,
        channel_id: &str,
        relay_name: &str,
        receiver_pubkey_hex: &str,
    ) -> Result<(), String> {
        let conn = cdk_spilman::sqlite_durability::open_wallet_database(&self.db_path)
            .map_err(|e| format!("open relay wallet metadata db: {e}"))?;
        conn.execute(
            "INSERT INTO monad_relay_channel_meta(channel_id, relay_name, receiver_pubkey_hex)
             VALUES (?1, ?2, ?3)
             ON CONFLICT(channel_id) DO UPDATE SET
               relay_name = excluded.relay_name,
               receiver_pubkey_hex = excluded.receiver_pubkey_hex",
            params![channel_id, relay_name, receiver_pubkey_hex],
        )
        .map_err(|e| format!("record relay channel metadata: {e}"))?;
        Ok(())
    }

    pub fn relay_name_for_channel(&self, channel_id: &str) -> io::Result<Option<String>> {
        let conn = cdk_spilman::sqlite_durability::open_wallet_database(&self.db_path)
            .map_err(|e| io::Error::other(format!("open relay wallet metadata db: {e}")))?;
        conn.query_row(
            "SELECT relay_name FROM monad_relay_channel_meta WHERE channel_id = ?1",
            params![channel_id],
            |row| row.get(0),
        )
        .optional()
        .map_err(|e| io::Error::other(format!("query relay channel metadata: {e}")))
    }

    pub fn list_channels(
        &self,
        relay_name: Option<&str>,
    ) -> io::Result<Vec<(String, String, String)>> {
        let conn = cdk_spilman::sqlite_durability::open_wallet_database(&self.db_path)
            .map_err(|e| io::Error::other(format!("open relay wallet metadata db: {e}")))?;
        let mut out = Vec::new();
        if let Some(name) = relay_name {
            let mut stmt = conn
                .prepare(
                    "SELECT channel_id, relay_name, receiver_pubkey_hex
                 FROM monad_relay_channel_meta
                 WHERE relay_name = ?1
                 ORDER BY channel_id",
                )
                .map_err(|e| {
                    io::Error::other(format!("prepare relay channel metadata query: {e}"))
                })?;
            let mut rows = stmt
                .query(params![name])
                .map_err(|e| io::Error::other(format!("query relay channel metadata: {e}")))?;
            while let Some(row) = rows
                .next()
                .map_err(|e| io::Error::other(format!("read relay channel metadata row: {e}")))?
            {
                out.push((
                    row.get(0)
                        .map_err(|e| io::Error::other(format!("read channel_id: {e}")))?,
                    row.get(1)
                        .map_err(|e| io::Error::other(format!("read relay_name: {e}")))?,
                    row.get(2)
                        .map_err(|e| io::Error::other(format!("read receiver_pubkey_hex: {e}")))?,
                ));
            }
        } else {
            let mut stmt = conn
                .prepare(
                    "SELECT channel_id, relay_name, receiver_pubkey_hex
                 FROM monad_relay_channel_meta
                 ORDER BY channel_id",
                )
                .map_err(|e| {
                    io::Error::other(format!("prepare relay channel metadata query: {e}"))
                })?;
            let mut rows = stmt
                .query([])
                .map_err(|e| io::Error::other(format!("query relay channel metadata: {e}")))?;
            while let Some(row) = rows
                .next()
                .map_err(|e| io::Error::other(format!("read relay channel metadata row: {e}")))?
            {
                out.push((
                    row.get(0)
                        .map_err(|e| io::Error::other(format!("read channel_id: {e}")))?,
                    row.get(1)
                        .map_err(|e| io::Error::other(format!("read relay_name: {e}")))?,
                    row.get(2)
                        .map_err(|e| io::Error::other(format!("read receiver_pubkey_hex: {e}")))?,
                ));
            }
        }
        Ok(out)
    }
}

#[derive(Clone)]
pub struct RelayWalletManager {
    storage: Arc<dyn SpilmanStorage>,
    metadata: Arc<ChannelMetadataStore>,
    identities: Arc<Mutex<HashMap<String, SecretKey>>>,
    keyset_cache: SharedSpilmanMintCache,
    trusted_mint_units: Arc<RwLock<TrustedMintUnits>>,
}

#[derive(Debug, Clone)]
pub struct RelayWalletInspection {
    db_path: String,
}

impl RelayWalletInspection {
    pub fn open(db_path: impl Into<String>) -> io::Result<Self> {
        let inspection = Self {
            db_path: db_path.into(),
        };
        inspection.connection()?;
        Ok(inspection)
    }

    fn connection(&self) -> io::Result<Connection> {
        Connection::open_with_flags(&self.db_path, OpenFlags::SQLITE_OPEN_READ_ONLY)
            .map_err(|e| io::Error::other(format!("open relay wallet db read-only: {e}")))
    }

    pub fn list_identities(&self) -> io::Result<Vec<RelayWalletIdentitySummary>> {
        let conn = self.connection()?;
        let mut stmt = conn
            .prepare(
                "SELECT relay_name, receiver_pubkey_hex
                 FROM monad_relay_wallet_identities ORDER BY relay_name",
            )
            .map_err(|e| io::Error::other(format!("prepare relay identity list: {e}")))?;
        let rows = stmt
            .query_map([], |row| {
                Ok(RelayWalletIdentitySummary {
                    name: row.get(0)?,
                    receiver_pubkey_hex: row.get(1)?,
                })
            })
            .map_err(|e| io::Error::other(format!("query relay identities: {e}")))?;
        rows.collect::<Result<Vec<_>, _>>()
            .map_err(|e| io::Error::other(format!("decode relay identities: {e}")))
    }

    pub fn list_channels(&self, relay_name: Option<&str>) -> io::Result<Vec<ChannelSummary>> {
        let records = self.channel_records(relay_name)?;
        records.into_iter().map(|record| record.summary()).collect()
    }

    pub fn find_expiring_channels(
        &self,
        relay_name: Option<&str>,
        now: u64,
        close_before_expiry_secs: u64,
    ) -> io::Result<Vec<ExpiringChannelSummary>> {
        let cutoff = now.saturating_add(close_before_expiry_secs);
        let mut summaries = self
            .channel_records(relay_name)?
            .into_iter()
            .filter_map(|record| match record.expiring_summary(now, cutoff) {
                Ok(summary) => summary.map(Ok),
                Err(error) => Some(Err(error)),
            })
            .collect::<io::Result<Vec<_>>>()?;
        summaries.sort_by_key(|summary| summary.seconds_until_expiry);
        Ok(summaries)
    }

    pub fn list_drains(&self) -> io::Result<Vec<DrainSummary>> {
        let conn = self.connection()?;
        let mut stmt = conn
            .prepare(
                "SELECT drain_id, relay_name, mint_url, unit, state,
                        input_amount_raw, output_amount_raw
                 FROM monad_relay_drains ORDER BY created_at, drain_id",
            )
            .map_err(|e| io::Error::other(format!("prepare drain list: {e}")))?;
        let rows = stmt
            .query_map([], |row| {
                Ok(DrainSummary {
                    drain_id: row.get(0)?,
                    relay_name: row.get(1)?,
                    mint_url: row.get(2)?,
                    unit: row.get(3)?,
                    state: row.get(4)?,
                    input_amount_raw: u64_from_i64(row.get(5)?)?,
                    output_amount_raw: u64_from_i64(row.get(6)?)?,
                })
            })
            .map_err(|e| io::Error::other(format!("query drains: {e}")))?;
        rows.collect::<Result<Vec<_>, _>>()
            .map_err(|e| io::Error::other(format!("decode drains: {e}")))
    }

    fn channel_records(&self, relay_name: Option<&str>) -> io::Result<Vec<InspectionChannel>> {
        let conn = self.connection()?;
        let sql = "SELECT m.channel_id, m.relay_name, m.receiver_pubkey_hex,
                          c.funding_json, c.balance, c.state, c.closing_json
                   FROM monad_relay_channel_meta m
                   JOIN spilman_channels c ON c.channel_id = m.channel_id
                   WHERE (?1 IS NULL OR m.relay_name = ?1)
                   ORDER BY m.channel_id";
        let mut stmt = conn
            .prepare(sql)
            .map_err(|e| io::Error::other(format!("prepare relay channel list: {e}")))?;
        let rows = stmt
            .query_map(params![relay_name], |row| {
                let state: String = row.get(5)?;
                Ok(InspectionChannel {
                    channel_id: row.get(0)?,
                    relay_name: row.get(1)?,
                    receiver_pubkey_hex: row.get(2)?,
                    funding_json: row.get(3)?,
                    balance_raw: u64_from_i64(row.get(4)?)?,
                    state: match state.as_str() {
                        "Closing" => ChannelState::Closing,
                        "Closed" => ChannelState::Closed,
                        "SenderRefundedAfterExpiry" => ChannelState::SenderRefundedAfterExpiry,
                        _ => ChannelState::Open,
                    },
                    closing_json: row.get(6)?,
                })
            })
            .map_err(|e| io::Error::other(format!("query relay channels: {e}")))?;
        rows.collect::<Result<Vec<_>, _>>()
            .map_err(|e| io::Error::other(format!("decode relay channels: {e}")))
    }
}

struct InspectionChannel {
    channel_id: String,
    relay_name: String,
    receiver_pubkey_hex: String,
    funding_json: String,
    balance_raw: u64,
    state: ChannelState,
    closing_json: Option<String>,
}

impl InspectionChannel {
    fn funding(&self) -> io::Result<ChannelSummaryMetadata> {
        let funding: ChannelFunding =
            serde_json::from_str(&self.funding_json).map_err(|error| {
                io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!("decode funding for channel '{}': {error}", self.channel_id),
                )
            })?;
        parse_channel_summary_metadata(&self.channel_id, &funding.params_json)
    }

    fn summary(self) -> io::Result<ChannelSummary> {
        let funding = self.funding()?;
        Ok(ChannelSummary {
            channel_id: self.channel_id,
            relay_name: self.relay_name,
            receiver_pubkey_hex: self.receiver_pubkey_hex,
            state: self.state,
            mint_url: funding.mint_url,
            unit: funding.unit,
            capacity_raw: funding.capacity_raw,
            balance_raw: self.balance_raw,
        })
    }

    fn expiring_summary(self, now: u64, cutoff: u64) -> io::Result<Option<ExpiringChannelSummary>> {
        if matches!(
            self.state,
            ChannelState::Closed | ChannelState::SenderRefundedAfterExpiry
        ) {
            return Ok(None);
        }
        let funding = self.funding()?;
        let expiry_timestamp = if self.state == ChannelState::Closing {
            self.closing_json
                .as_deref()
                .and_then(|json| serde_json::from_str::<serde_json::Value>(json).ok())
                .and_then(|closing| closing["expiry_timestamp"].as_u64())
                .unwrap_or(funding.expiry_timestamp)
        } else {
            funding.expiry_timestamp
        };
        if expiry_timestamp > cutoff {
            return Ok(None);
        }
        Ok(Some(ExpiringChannelSummary {
            channel_id: self.channel_id,
            relay_name: self.relay_name,
            receiver_pubkey_hex: self.receiver_pubkey_hex,
            state: self.state,
            mint_url: funding.mint_url,
            unit: funding.unit,
            expiry_timestamp,
            seconds_until_expiry: seconds_until_expiry(now, expiry_timestamp),
            capacity_raw: funding.capacity_raw,
            balance_raw: self.balance_raw,
        }))
    }
}

impl std::fmt::Debug for RelayWalletManager {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RelayWalletManager").finish_non_exhaustive()
    }
}

impl RelayWalletManager {
    pub fn open(db_path: impl Into<String>) -> io::Result<Self> {
        let db_path = db_path.into();
        let locks = WalletLocks::acquire(
            [std::path::Path::new(&db_path)],
            WalletLockMode::Maintenance,
            "relay",
        )?;
        Self::open_with_locks(db_path, locks)
    }

    pub fn open_with_locks(db_path: impl Into<String>, locks: WalletLocks) -> io::Result<Self> {
        let db_path = db_path.into();
        let identity = WalletLockIdentity::new([std::path::Path::new(&db_path)])?;
        if !locks.exclusive_access()?.authorizes(&identity) {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "relay wallet authority does not match database",
            ));
        }
        Self::open_with_authority(db_path, Arc::new(Mutex::new(locks)))
    }

    /// Reopen storage/cache under this manager's existing exclusive owner.
    /// Does not grant an independent process maintenance authority.
    pub fn reopen(&self) -> io::Result<Self> {
        self.require_maintenance().map_err(io::Error::other)?;
        Self::open_with_authority(
            self.metadata.db_path.clone(),
            self.metadata.authority.clone(),
        )
    }

    fn open_with_authority(
        db_path: String,
        authority: Arc<Mutex<WalletLocks>>,
    ) -> io::Result<Self> {
        let conn = cdk_spilman::sqlite_durability::open_wallet_database(&db_path)
            .map_err(|e| io::Error::other(format!("open relay wallet db: {e}")))?;
        let exists = |name: &str| -> io::Result<bool> {
            conn.query_row(
                "SELECT EXISTS(SELECT 1 FROM sqlite_master WHERE type='table' AND name=?1)",
                [name],
                |row| row.get(0),
            )
            .map_err(|e| io::Error::other(e.to_string()))
        };
        // Inspect before any schema initialization. Rejection must not even add
        // empty recovery tables to an incompatible nonempty wallet.
        if exists("monad_relay_drains")? {
            let query = if exists("monad_relay_drain_journals")? {
                "SELECT COUNT(*) FROM monad_relay_drains d WHERE NOT EXISTS (SELECT 1 FROM monad_relay_drain_journals j WHERE j.drain_id=d.drain_id)"
            } else {
                "SELECT COUNT(*) FROM monad_relay_drains"
            };
            let incompatible: u64 = conn
                .query_row(query, [], |row| row.get(0))
                .map_err(|e| io::Error::other(e.to_string()))?;
            if incompatible != 0 {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "incompatible nonempty drain journal; database retained without migration",
                ));
            }
        }
        if exists("monad_relay_drain_journals")? {
            let mut statement = conn
                .prepare("SELECT journal_json FROM monad_relay_drain_journals")
                .map_err(|e| io::Error::other(e.to_string()))?;
            let rows = statement
                .query_map([], |row| row.get::<_, String>(0))
                .map_err(|e| io::Error::other(e.to_string()))?;
            for row in rows {
                drain_recovery::validate_schema(&row.map_err(|e| io::Error::other(e.to_string()))?)
                    .map_err(io::Error::other)?;
            }
        }
        if exists("spilman_channels")? {
            let query = if exists("spilman_close_journals")? {
                "SELECT COUNT(*) FROM spilman_channels c WHERE state='Closing' AND NOT EXISTS (SELECT 1 FROM spilman_close_journals j WHERE j.channel_id=c.channel_id)"
            } else {
                "SELECT COUNT(*) FROM spilman_channels WHERE state='Closing'"
            };
            let legacy: u64 = conn
                .query_row(query, [], |row| row.get(0))
                .map_err(|e| io::Error::other(e.to_string()))?;
            if legacy != 0 {
                return Err(io::Error::new(io::ErrorKind::InvalidData, "legacy Closing channel lacks exact journal; database retained without migration"));
            }
        }
        if exists("spilman_close_journals")? {
            let mut statement = conn
                .prepare("SELECT journal FROM spilman_close_journals")
                .map_err(|e| io::Error::other(e.to_string()))?;
            let rows = statement
                .query_map([], |row| row.get::<_, String>(0))
                .map_err(|e| io::Error::other(e.to_string()))?;
            for row in rows {
                SpilmanRelayPayments::validate_close_schema(
                    &row.map_err(|e| io::Error::other(e.to_string()))?,
                )
                .map_err(io::Error::other)?;
            }
        }
        conn.execute_batch(CREATE_IDENTITIES_TABLE_SQL)
            .map_err(|e| io::Error::other(format!("create relay wallet identities table: {e}")))?;
        conn.execute_batch(CREATE_DRAIN_TABLES_SQL)
            .map_err(|e| io::Error::other(format!("create relay wallet drain tables: {e}")))?;
        drop(conn);
        let storage = Arc::new(
            SqliteStorage::open(&db_path)
                .map_err(|e| io::Error::other(format!("open relay wallet storage: {e}")))?,
        );
        let metadata = Arc::new(ChannelMetadataStore::new(db_path.clone(), authority)?);
        let identities = Arc::new(Mutex::new(load_identities(&db_path)?));
        let keyset_cache = shared_spilman_mint_cache(SpilmanMintCache::default());
        let trusted_mint_units = Arc::new(RwLock::new(TrustedMintUnits::default()));

        Ok(Self {
            storage,
            metadata,
            identities,
            keyset_cache,
            trusted_mint_units,
        })
    }

    pub fn enter_steady_state(&self) -> io::Result<()> {
        let mut locks = self
            .metadata
            .authority
            .lock()
            .map_err(|_| io::Error::other("relay authority lock poisoned"))?;
        if !locks.holds_runtime_owner() {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "runtime wallet ownership required",
            ));
        }
        locks.enter_steady_state()
    }

    fn require_maintenance(&self) -> Result<(), String> {
        self.metadata
            .authority
            .lock()
            .map_err(|_| "relay authority lock poisoned".to_string())?
            .exclusive_access()
            .map(|_| ())
            .map_err(|e| e.to_string())
    }

    pub fn register_identity(
        &self,
        relay_name: &str,
        receiver_secret: SecretKey,
    ) -> io::Result<()> {
        let receiver_secret_hex = receiver_secret.to_secret_hex();
        let receiver_pubkey_hex = receiver_secret.public_key().to_hex();
        {
            let mut identities = self
                .identities
                .lock()
                .map_err(|_| io::Error::other("relay wallet identity mutex poisoned"))?;
            if let Some(existing) = identities.get(relay_name) {
                if existing.to_secret_hex() == receiver_secret_hex {
                    return Ok(());
                }
                return Err(io::Error::new(
                    io::ErrorKind::AlreadyExists,
                    format!("relay wallet identity '{relay_name}' already exists with a different receiver secret"),
                ));
            }
            store_identity(
                relay_name,
                &receiver_secret_hex,
                &receiver_pubkey_hex,
                &self.metadata.db_path,
            )?;
            identities.insert(relay_name.to_string(), receiver_secret);
        }
        Ok(())
    }

    pub fn receiver_secret(&self, relay_name: &str) -> io::Result<SecretKey> {
        let identities = self
            .identities
            .lock()
            .map_err(|_| io::Error::other("relay wallet identity mutex poisoned"))?;
        identities.get(relay_name).cloned().ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::NotFound,
                format!("unknown relay wallet identity '{relay_name}'"),
            )
        })
    }

    pub fn receiver_pubkey_hex(&self, relay_name: &str) -> io::Result<String> {
        Ok(self.receiver_secret(relay_name)?.public_key().to_hex())
    }

    pub fn db_path(&self) -> &str {
        &self.metadata.db_path
    }

    pub fn spilman_storage(&self) -> &dyn SpilmanStorage {
        self.storage.as_ref()
    }

    pub fn keyset_cache(&self) -> SharedSpilmanMintCache {
        self.keyset_cache.clone()
    }

    pub fn keyset_cache_snapshot(&self) -> SpilmanMintCache {
        self.keyset_cache
            .read()
            .expect("relay wallet keyset cache lock poisoned")
            .clone()
    }

    pub fn set_trusted_mint_units(&self, trusted_mint_units: TrustedMintUnits) {
        *self
            .trusted_mint_units
            .write()
            .expect("relay wallet trusted mint units lock poisoned") = trusted_mint_units;
    }

    pub fn trusted_mint_units(&self) -> TrustedMintUnits {
        self.trusted_mint_units
            .read()
            .expect("relay wallet trusted mint units lock poisoned")
            .clone()
    }

    /// Replace the manager's in-memory keyset cache with the supplied snapshot.
    ///
    /// Intended for test helpers and explicit admin bootstrap that already have
    /// a trusted mint cache snapshot and need the wallet manager's own cache
    /// (used by close/drain paths) to stay consistent with the relay session
    /// cache.
    pub fn install_keyset_cache(&self, cache: SpilmanMintCache) {
        *self
            .keyset_cache
            .write()
            .expect("relay wallet keyset cache lock poisoned") = cache;
    }

    pub fn payments_for(&self, relay_name: &str) -> io::Result<Arc<dyn RelayPayments>> {
        Ok(self.spilman_payments_for_live(relay_name)? as Arc<dyn RelayPayments>)
    }

    pub fn payments_for_with_policy(
        &self,
        relay_name: &str,
        channel_policy: RelayChannelPolicyConfig,
    ) -> io::Result<Arc<dyn RelayPayments>> {
        Ok(
            self.spilman_payments_for_live_with_policy(relay_name, channel_policy)?
                as Arc<dyn RelayPayments>,
        )
    }

    pub fn payments_for_with_trusted_mints_and_policy(
        &self,
        relay_name: &str,
        trusted_mint_units: TrustedMintUnits,
        channel_policy: RelayChannelPolicyConfig,
    ) -> io::Result<Arc<dyn RelayPayments>> {
        let receiver_secret = self.receiver_secret(relay_name)?;
        let receiver_pubkey_hex = receiver_secret.public_key().to_hex();
        let store = ChannelStore::with_relay_metadata(
            self.storage.clone(),
            self.metadata.clone(),
            relay_name.to_string(),
            receiver_pubkey_hex,
        );
        Ok(Arc::new(SpilmanRelayPayments::from_store(
            receiver_secret,
            self.keyset_cache.clone(),
            trusted_mint_units,
            channel_policy,
            store,
        )))
    }

    pub fn spilman_payments_for_live(
        &self,
        relay_name: &str,
    ) -> io::Result<Arc<SpilmanRelayPayments>> {
        self.spilman_payments_for_live_with_policy(relay_name, RelayChannelPolicyConfig::default())
    }

    pub fn spilman_payments_for_live_with_policy(
        &self,
        relay_name: &str,
        channel_policy: RelayChannelPolicyConfig,
    ) -> io::Result<Arc<SpilmanRelayPayments>> {
        let receiver_secret = self.receiver_secret(relay_name)?;
        let receiver_pubkey_hex = receiver_secret.public_key().to_hex();
        let store = ChannelStore::with_relay_metadata(
            self.storage.clone(),
            self.metadata.clone(),
            relay_name.to_string(),
            receiver_pubkey_hex,
        );
        Ok(Arc::new(SpilmanRelayPayments::from_store(
            receiver_secret,
            self.keyset_cache.clone(),
            self.trusted_mint_units(),
            channel_policy,
            store,
        )))
    }

    pub fn spilman_payments_for(
        &self,
        relay_name: &str,
        mint_cache: SpilmanMintCache,
        trusted_mint_units: TrustedMintUnits,
    ) -> io::Result<Arc<SpilmanRelayPayments>> {
        self.spilman_payments_for_with_policy(
            relay_name,
            mint_cache,
            trusted_mint_units,
            RelayChannelPolicyConfig::default(),
        )
    }

    pub fn spilman_payments_for_with_policy(
        &self,
        relay_name: &str,
        mint_cache: SpilmanMintCache,
        trusted_mint_units: TrustedMintUnits,
        channel_policy: RelayChannelPolicyConfig,
    ) -> io::Result<Arc<SpilmanRelayPayments>> {
        let receiver_secret = self.receiver_secret(relay_name)?;
        let receiver_pubkey_hex = receiver_secret.public_key().to_hex();
        let store = ChannelStore::with_relay_metadata(
            self.storage.clone(),
            self.metadata.clone(),
            relay_name.to_string(),
            receiver_pubkey_hex,
        );
        Ok(Arc::new(SpilmanRelayPayments::from_store_with_snapshot(
            receiver_secret,
            mint_cache,
            trusted_mint_units,
            channel_policy,
            store,
        )))
    }

    pub fn relay_name_for_channel(&self, channel_id: &str) -> io::Result<Option<String>> {
        self.metadata.relay_name_for_channel(channel_id)
    }

    pub fn list_identities(&self) -> Vec<RelayWalletIdentitySummary> {
        let identities = self
            .identities
            .lock()
            .expect("relay wallet identity mutex poisoned");
        identities
            .iter()
            .map(|(name, secret)| RelayWalletIdentitySummary {
                name: name.clone(),
                receiver_pubkey_hex: secret.public_key().to_hex(),
            })
            .collect()
    }

    pub fn list_channels(&self, relay_name: Option<&str>) -> io::Result<Vec<ChannelSummary>> {
        let meta = self.metadata.list_channels(relay_name)?;
        let store = ChannelStore::new(self.storage.clone());
        let mut summaries = Vec::with_capacity(meta.len());
        for (channel_id, chan_relay_name, receiver_pubkey_hex) in meta {
            let channel = match store
                .get_channel(&channel_id)
                .map_err(|e| io::Error::other(format!("load channel {channel_id}: {e}")))?
            {
                Some(c) => c,
                None => continue,
            };
            let funding_json: serde_json::Value =
                serde_json::from_str(&channel.funding.params_json).map_err(|e| {
                    io::Error::other(format!("corrupt funding JSON for {channel_id}: {e}"))
                })?;
            let mint_url = funding_json["mint"]
                .as_str()
                .unwrap_or("unknown")
                .to_string();
            summaries.push(ChannelSummary {
                channel_id,
                relay_name: chan_relay_name,
                receiver_pubkey_hex,
                state: channel.state,
                mint_url,
                unit: channel.unit.as_str().to_string(),
                capacity_raw: channel.capacity_raw,
                balance_raw: channel.latest_payment.balance,
            });
        }
        Ok(summaries)
    }

    pub fn find_expiring_channels(
        &self,
        relay_name: Option<&str>,
        now: u64,
        close_before_expiry_secs: u64,
    ) -> io::Result<Vec<ExpiringChannelSummary>> {
        let meta = self.metadata.list_channels(relay_name)?;
        let store = ChannelStore::new(self.storage.clone());
        let cutoff = now.saturating_add(close_before_expiry_secs);
        let mut summaries = Vec::new();
        for (channel_id, chan_relay_name, receiver_pubkey_hex) in meta {
            let channel = match store
                .get_channel(&channel_id)
                .map_err(|e| io::Error::other(format!("load channel {channel_id}: {e}")))?
            {
                Some(c) => c,
                None => continue,
            };
            if matches!(
                channel.state,
                ChannelState::Closed | ChannelState::SenderRefundedAfterExpiry
            ) {
                continue;
            }
            let funding =
                parse_channel_summary_metadata(&channel_id, &channel.funding.params_json)?;
            let expiry_timestamp = match channel.state {
                ChannelState::Open => funding.expiry_timestamp,
                ChannelState::Closing => channel
                    .closing_data
                    .as_ref()
                    .map(|closing| closing.expiry_timestamp)
                    .unwrap_or(funding.expiry_timestamp),
                ChannelState::Closed | ChannelState::SenderRefundedAfterExpiry => continue,
            };
            if expiry_timestamp > cutoff {
                continue;
            }
            summaries.push(ExpiringChannelSummary {
                channel_id,
                relay_name: chan_relay_name,
                receiver_pubkey_hex,
                state: channel.state,
                mint_url: funding.mint_url,
                unit: channel.unit.as_str().to_string(),
                expiry_timestamp,
                seconds_until_expiry: seconds_until_expiry(now, expiry_timestamp),
                capacity_raw: channel.capacity_raw,
                balance_raw: channel.latest_payment.balance,
            });
        }
        summaries.sort_by_key(|summary| summary.seconds_until_expiry);
        Ok(summaries)
    }

    /// Build mint networking for the mint and receiver identity associated
    /// with a stored channel. Used by the CLI close command.
    pub fn mint_client_for_channel(
        &self,
        channel_id: &str,
    ) -> Result<RelayWalletMintClient, String> {
        let (receiver_secret, mint_url, unit) = self.channel_owner_and_mint(channel_id)?;
        let _ = (receiver_secret, mint_url, unit);
        Ok(RelayWalletMintClient::new())
    }

    /// Build mint networking for a relay identity and mint/unit. Used by wallet
    /// drain CLI commands.
    pub fn mint_client_for_relay(
        &self,
        relay_name: &str,
        mint_url: &str,
        unit: &str,
    ) -> Result<RelayWalletMintClient, String> {
        let identities = self
            .identities
            .lock()
            .map_err(|_| "relay wallet identity mutex poisoned".to_string())?;
        let receiver_secret = identities
            .get(relay_name)
            .ok_or_else(|| format!("unknown relay identity '{relay_name}'"))?;
        let _ = (receiver_secret, mint_url, unit);
        Ok(RelayWalletMintClient::new())
    }

    /// Close any channel stored in this wallet DB, regardless of which relay
    /// identity owns it.  If the channel is already `Closed`, returns a
    /// synthetic success.  If it is `Closing`, completes the close.  Otherwise
    /// initiates and executes a unilateral close against the channel's mint.
    pub async fn close_channel<N: crate::mint_recovery::RecoveryMintClient>(
        &self,
        channel_id: &str,
        net: &N,
    ) -> Result<CloseOutcome, CloseError> {
        let payments = self.payments_for_channel(channel_id).await?;
        // The close driver reads its journal before any cache warmup or mint IO.
        payments
            .close_channel_any_state_async(channel_id, net, self)
            .await
    }

    pub async fn close_expiring_channels(
        &self,
        relay_name: Option<&str>,
        now: u64,
        close_before_expiry_secs: u64,
    ) -> io::Result<CloseExpiringChannelsResult> {
        let channels = self.find_expiring_channels(relay_name, now, close_before_expiry_secs)?;
        Ok(self
            .close_expiring_channel_candidates(channels, close_before_expiry_secs)
            .await)
    }

    pub async fn close_expiring_channel_candidates(
        &self,
        channels: Vec<ExpiringChannelSummary>,
        close_before_expiry_secs: u64,
    ) -> CloseExpiringChannelsResult {
        let mut result = CloseExpiringChannelsResult::new(close_before_expiry_secs, channels.len());
        for channel in channels {
            match self.mint_client_for_channel(&channel.channel_id) {
                Ok(net) => match self.close_channel(&channel.channel_id, &net).await {
                    Ok(CloseOutcome::UnknownSpent { .. }) => result.unresolved.push(channel),
                    Ok(close) => result
                        .resolved
                        .push(CloseExpiringChannelSuccess { channel, close }),
                    Err(error) => result.failures.push(CloseExpiringChannelFailure {
                        error: close_error_summary(&error),
                        channel,
                    }),
                },
                Err(error) => result
                    .failures
                    .push(CloseExpiringChannelFailure { channel, error }),
            }
        }
        result
    }

    pub async fn drain_closed_channels_to_swap<N: DrainSwapNetworking>(
        &self,
        relay_name: &str,
        mint_url: &str,
        unit: &str,
        net: &N,
        limit: Option<usize>,
    ) -> Result<DrainSwapResult, String> {
        self.start_exact_drain(relay_name, mint_url, unit, net, limit)
            .await
    }

    pub async fn recover_submitted_drain<N: DrainSwapNetworking>(
        &self,
        drain_id: &str,
        net: &N,
    ) -> Result<DrainSwapResult, String> {
        self.run_exact_drain(drain_id, net, true, None).await
    }

    pub fn list_drains(&self) -> Result<Vec<DrainSummary>, String> {
        let conn = cdk_spilman::sqlite_durability::open_wallet_database(&self.metadata.db_path)
            .map_err(|e| format!("open relay wallet db: {e}"))?;
        let mut stmt = conn
            .prepare(
                "SELECT drain_id, relay_name, mint_url, unit, state, input_amount_raw, output_amount_raw
                 FROM monad_relay_drains
                 ORDER BY created_at, drain_id",
            )
            .map_err(|e| format!("prepare drain list: {e}"))?;
        let rows = stmt
            .query_map([], |row| {
                Ok(DrainSummary {
                    drain_id: row.get(0)?,
                    relay_name: row.get(1)?,
                    mint_url: row.get(2)?,
                    unit: row.get(3)?,
                    state: row.get(4)?,
                    input_amount_raw: u64_from_i64(row.get(5)?)?,
                    output_amount_raw: u64_from_i64(row.get(6)?)?,
                })
            })
            .map_err(|e| format!("query drains: {e}"))?;
        rows.collect::<Result<Vec<_>, _>>()
            .map_err(|e| format!("decode drains: {e}"))
    }

    /// Fetch all keysets reported by one mint and persist them in SQLite.
    ///
    /// Use [`Self::refresh_all_keysets_for_mint_into_shared_cache`] when the
    /// caller also needs existing live payment/session objects to observe the
    /// new keysets.
    pub async fn refresh_all_keysets_for_mint_into_sqlite(
        &self,
        mint_url: &str,
    ) -> Result<Vec<MintKeysetWithKeys>, String> {
        let keysets = fetch_all_keysets_from_mint(mint_url).await?;
        cache_relay_keysets(self.storage.as_ref(), mint_url, &keysets)?;
        Ok(keysets)
    }

    /// Refresh all keysets reported by one mint into SQLite and merge them into
    /// the shared memory cache used by live relay payment objects.
    ///
    /// Channel close uses this from the upstream keyset-error retry hook: the
    /// first close attempt is cache-first, then a retry refreshes this mint and
    /// re-prepares the swap against the updated shared cache.
    pub async fn refresh_all_keysets_for_mint_into_shared_cache(
        &self,
        mint_url: &str,
    ) -> Result<(), String> {
        let keysets = self
            .refresh_all_keysets_for_mint_into_sqlite(mint_url)
            .await?;
        let mut cache = self
            .keyset_cache
            .write()
            .expect("relay wallet keyset cache lock poisoned");
        merge_keysets_into_cache(&mut cache, mint_url, &keysets);
        Ok(())
    }

    /// Rebuild the shared keyset cache from the currently configured trusted
    /// mint URLs, storing every keyset those mints report.
    ///
    /// The trusted unit map is saved separately and filters advertisements and
    /// incoming channel acceptance at read time.
    pub async fn refresh_trusted_mint_cache(
        &self,
        trusted_mint_units: &TrustedMintUnits,
    ) -> Result<SharedSpilmanMintCache, String> {
        let mut refreshed = SpilmanMintCache::default();
        for mint_url in trusted_mint_units.keys() {
            let keysets = fetch_all_keysets_from_mint(mint_url).await?;
            cache_relay_keysets(self.storage.as_ref(), mint_url, &keysets)?;
            merge_keysets_into_cache(&mut refreshed, mint_url, &keysets);
        }
        *self
            .keyset_cache
            .write()
            .expect("relay wallet keyset cache lock poisoned") = refreshed;
        self.set_trusted_mint_units(trusted_mint_units.clone());
        Ok(self.keyset_cache.clone())
    }

    fn closed_drain_candidates(
        &self,
        relay_name: &str,
        mint_url: &str,
        unit: &str,
        limit: Option<usize>,
    ) -> Result<Vec<DrainCandidate>, String> {
        let meta = self
            .metadata
            .list_channels(Some(relay_name))
            .map_err(|e| format!("list relay channels: {e}"))?;
        let conn = cdk_spilman::sqlite_durability::open_wallet_database(&self.metadata.db_path)
            .map_err(|e| format!("open relay wallet db: {e}"))?;
        let mut out = Vec::new();
        for (channel_id, _, _) in meta {
            if limit.is_some_and(|limit| out.len() >= limit) {
                break;
            }
            let already_drained: Option<String> = conn
                .query_row(
                    "SELECT drain_id FROM monad_relay_drained_channels WHERE channel_id = ?1",
                    params![channel_id],
                    |row| row.get(0),
                )
                .optional()
                .map_err(|e| format!("query drained channel marker: {e}"))?;
            if already_drained.is_some()
                || self.storage.get_state(&channel_id) != ChannelState::Closed
            {
                continue;
            }
            let funding = match self.storage.get_funding(&channel_id) {
                Some(funding) => funding,
                None => continue,
            };
            let funding_json: serde_json::Value = serde_json::from_str(&funding.params_json)
                .map_err(|e| format!("corrupt funding JSON for {channel_id}: {e}"))?;
            if funding_json["mint"].as_str() != Some(mint_url)
                || funding_json["unit"].as_str() != Some(unit)
            {
                continue;
            }
            let closed = self
                .storage
                .get_closed_data(&channel_id)
                .ok_or_else(|| format!("channel {channel_id} is Closed but has no closed data"))?;
            out.push(DrainCandidate {
                channel_id,
                receiver_sum_raw: closed.receiver_sum,
                receiver_proofs_json: closed.receiver_proofs_json,
            });
        }
        Ok(out)
    }

    fn load_drain(&self, drain_id: &str) -> Result<StoredDrain, String> {
        let conn = cdk_spilman::sqlite_durability::open_wallet_database(&self.metadata.db_path)
            .map_err(|e| format!("open relay wallet db: {e}"))?;
        conn.query_row(
            "SELECT drain_id, relay_name, mint_url, unit, state, input_amount_raw,
                    output_amount_raw, restore_request_json, output_secrets_json,
                    output_keyset_info_json, output_proofs_json
             FROM monad_relay_drains WHERE drain_id = ?1",
            params![drain_id],
            |row| {
                Ok(StoredDrain {
                    drain_id: row.get(0)?,
                    relay_name: row.get(1)?,
                    mint_url: row.get(2)?,
                    unit: row.get(3)?,
                    state: row.get(4)?,
                    input_amount_raw: u64_from_i64(row.get(5)?)?,
                    output_amount_raw: u64_from_i64(row.get(6)?)?,
                    restore_request_json: row.get(7)?,
                    output_secrets_json: row.get(8)?,
                    output_keyset_info_json: row.get(9)?,
                    output_proofs_json: row.get(10)?,
                })
            },
        )
        .optional()
        .map_err(|e| format!("load drain: {e}"))?
        .ok_or_else(|| format!("drain {drain_id} not found"))
    }

    fn drain_channel_ids(&self, drain_id: &str) -> Result<Vec<String>, String> {
        let conn = cdk_spilman::sqlite_durability::open_wallet_database(&self.metadata.db_path)
            .map_err(|e| format!("open relay wallet db: {e}"))?;
        let mut stmt = conn
            .prepare(
                "SELECT channel_id FROM monad_relay_drain_inputs
                 WHERE drain_id = ?1 ORDER BY channel_id",
            )
            .map_err(|e| format!("prepare drain channel list: {e}"))?;
        let rows = stmt
            .query_map(params![drain_id], |row| row.get(0))
            .map_err(|e| format!("query drain channel list: {e}"))?;
        rows.collect::<Result<Vec<_>, _>>()
            .map_err(|e| format!("decode drain channel list: {e}"))
    }

    fn completed_drain_result(
        &self,
        drain: StoredDrain,
        recovered: bool,
    ) -> Result<DrainSwapResult, String> {
        Ok(DrainSwapResult {
            channel_ids: self.drain_channel_ids(&drain.drain_id)?,
            output_proofs_json: drain.output_proofs_json.ok_or_else(|| {
                format!(
                    "drain {} is Completed but has no output proofs",
                    drain.drain_id
                )
            })?,
            drain_id: drain.drain_id,
            relay_name: drain.relay_name,
            mint_url: drain.mint_url,
            unit: drain.unit,
            input_amount_raw: drain.input_amount_raw,
            output_amount_raw: drain.output_amount_raw,
            recovered,
        })
    }

    fn prepare_drain_attempt_with_keysets(
        &self,
        drain_keysets: DrainKeysets,
        all_input_proofs: &[Proof],
        input_amount_raw: u64,
    ) -> Result<PreparedDrainAttempt, String> {
        let mut input_fee_ppk_sum = 0u64;
        for proof in all_input_proofs {
            let proof_keyset_id = proof.keyset_id.to_string();
            let input_fee_ppk = drain_keysets
                .input_fee_ppk_by_keyset
                .get(&proof_keyset_id)
                .ok_or_else(|| {
                    format!(
                        "missing input fee metadata for receiver proof keyset {}",
                        proof.keyset_id
                    )
                })?;
            input_fee_ppk_sum = input_fee_ppk_sum
                .checked_add(*input_fee_ppk)
                .ok_or_else(|| "drain input fee overflow".to_string())?;
        }
        let input_fee_raw = input_fee_ppk_sum.div_ceil(1000);
        let output_amount_raw = input_amount_raw
            .checked_sub(input_fee_raw)
            .ok_or_else(|| "drain input fees exceed input amount".to_string())?;
        if output_amount_raw == 0 {
            return Err("drain output amount is zero after fees".to_string());
        }
        let prepared = prepare_plain_drain_swap(
            all_input_proofs.to_vec(),
            output_amount_raw,
            &drain_keysets.output_keyset_info_json,
        )?;
        Ok(PreparedDrainAttempt {
            drain_keysets,
            prepared,
            output_amount_raw,
        })
    }

    fn drain_keysets_from_shared_cache(
        &self,
        mint_url: &str,
        unit: &str,
    ) -> Result<DrainKeysets, String> {
        let cache = self
            .keyset_cache
            .read()
            .expect("relay wallet keyset cache lock poisoned");
        let by_id = cache
            .keysets
            .get(mint_url)
            .ok_or_else(|| format!("mint {mint_url} has no cached keysets"))?;
        let mut input_fee_ppk_by_keyset = BTreeMap::new();
        let mut active_output_keysets = Vec::new();
        for (keyset_id, keyset) in by_id {
            if keyset.unit != unit {
                continue;
            }
            input_fee_ppk_by_keyset.insert(keyset_id.clone(), keyset.input_fee_ppk);
            if keyset.active
                && cdk_spilman::parse_keyset_info_from_json(&keyset.info_json)
                    .is_ok_and(|info| info.is_unexpired_at(cashu::util::unix_time()))
            {
                active_output_keysets.push((keyset_id.clone(), keyset.info_json.clone()));
            }
        }
        active_output_keysets.sort_by(|a, b| a.0.cmp(&b.0));
        let (output_keyset_id, output_keyset_info_json) = active_output_keysets
            .into_iter()
            .next()
            .ok_or_else(|| format!("mint {mint_url} has no active keyset for unit {unit}"))?;
        Ok(DrainKeysets {
            output_keyset_id,
            output_keyset_info_json,
            input_fee_ppk_by_keyset,
        })
    }

    async fn ensure_drain_keysets_cached(&self, mint_url: &str, unit: &str) -> Result<(), String> {
        let has_cached_keysets = self.drain_keysets_from_shared_cache(mint_url, unit).is_ok();
        if !has_cached_keysets {
            self.refresh_all_keysets_for_mint_into_shared_cache(mint_url)
                .await?;
        }
        Ok(())
    }

    fn channel_owner_and_mint(
        &self,
        channel_id: &str,
    ) -> Result<(SecretKey, String, String), String> {
        let relay_name = self
            .metadata
            .relay_name_for_channel(channel_id)
            .map_err(|e| format!("lookup channel metadata: {e}"))?
            .ok_or_else(|| format!("channel {channel_id} not found in wallet metadata"))?;
        let receiver_secret = self
            .receiver_secret(&relay_name)
            .map_err(|e| format!("load receiver secret for relay '{relay_name}': {e}"))?;

        let store = ChannelStore::new(self.storage.clone());
        let funding = store
            .get_channel(channel_id)?
            .map(|c| c.funding)
            .ok_or_else(|| format!("channel {channel_id} has no funding"))?;
        let funding_json: serde_json::Value = serde_json::from_str(&funding.params_json)
            .map_err(|e| format!("corrupt funding JSON for {channel_id}: {e}"))?;
        let mint_url = funding_json["mint"]
            .as_str()
            .ok_or_else(|| format!("channel {channel_id} funding has no mint URL"))?
            .to_string();
        let unit = funding_json["unit"]
            .as_str()
            .ok_or_else(|| format!("channel {channel_id} funding has no unit"))?
            .to_string();
        Ok((receiver_secret, mint_url, unit))
    }

    async fn payments_for_channel(
        &self,
        channel_id: &str,
    ) -> Result<Arc<SpilmanRelayPayments>, CloseError> {
        let relay_name = self
            .metadata
            .relay_name_for_channel(channel_id)
            .map_err(|e| CloseError::StorageFailed {
                reason: format!("lookup channel metadata: {e}"),
                status: 500,
            })?
            .ok_or_else(|| CloseError::ValidationFailed {
                reason: format!("channel {channel_id} not found in wallet metadata"),
                status: 404,
                expected_balance: None,
                actual_balance: None,
            })?;

        self.spilman_payments_for_live(&relay_name)
            .map_err(|e| CloseError::StorageFailed {
                reason: format!("build payments for relay '{relay_name}': {e}"),
                status: 500,
            })
    }
}

#[derive(Clone, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct DrainCandidate {
    channel_id: String,
    receiver_sum_raw: u64,
    receiver_proofs_json: String,
}

#[derive(Debug, Clone)]
struct DrainKeysets {
    output_keyset_id: String,
    output_keyset_info_json: String,
    input_fee_ppk_by_keyset: BTreeMap<String, u64>,
}

#[derive(Clone, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct PreparedDrainSwap {
    swap_request_json: String,
    restore_request_json: String,
    output_secrets_json: String,
}

#[derive(Clone)]
struct PreparedDrainAttempt {
    drain_keysets: DrainKeysets,
    prepared: PreparedDrainSwap,
    output_amount_raw: u64,
}

#[derive(Clone)]
struct StoredDrain {
    drain_id: String,
    relay_name: String,
    mint_url: String,
    unit: String,
    state: String,
    input_amount_raw: u64,
    output_amount_raw: u64,
    restore_request_json: String,
    output_secrets_json: String,
    output_keyset_info_json: String,
    output_proofs_json: Option<String>,
}

pub(crate) fn merge_keysets_into_cache(
    cache: &mut SpilmanMintCache,
    mint_url: &str,
    keysets: &[MintKeysetWithKeys],
) {
    use crate::listener::CachedKeyset;

    let mut by_unit = BTreeMap::<String, Vec<String>>::new();
    let mut by_id = BTreeMap::<String, CachedKeyset>::new();
    for keyset in keysets {
        let unit = keyset.unit.to_string();
        let id = keyset.id.to_string();
        by_unit.entry(unit.clone()).or_default().push(id.clone());
        by_id.insert(
            id,
            CachedKeyset {
                unit,
                active: keyset.active,
                input_fee_ppk: keyset.input_fee_ppk,
                info_json: build_keyset_info_json(
                    &keyset.id,
                    &keyset.unit,
                    &keyset.keys,
                    keyset.input_fee_ppk,
                    keyset.final_expiry,
                ),
            },
        );
    }
    for ids in by_unit.values_mut() {
        ids.sort();
        ids.dedup();
    }

    // Merge into existing per-mint entries rather than replacing them, so
    // fetching one mint does not drop previously cached units for the same mint.
    let unit_entry = cache.advertised.entry(mint_url.to_string()).or_default();
    for (unit, ids) in by_unit {
        let existing = unit_entry.entry(unit).or_default();
        existing.extend(ids);
        existing.sort();
        existing.dedup();
    }

    cache
        .keysets
        .entry(mint_url.to_string())
        .or_default()
        .extend(by_id);
}

pub(crate) fn cache_relay_keysets(
    storage: &dyn SpilmanStorage,
    mint_url: &str,
    keysets: &[MintKeysetWithKeys],
) -> Result<(), String> {
    for keyset in keysets {
        storage.set_keyset(
            mint_url,
            keyset.id,
            KeysetCacheEntry {
                info_json: build_keyset_info_json(
                    &keyset.id,
                    &keyset.unit,
                    &keyset.keys,
                    keyset.input_fee_ppk,
                    keyset.final_expiry,
                ),
                active: keyset.active,
                unit: keyset.unit.clone(),
            },
        )?;
    }
    Ok(())
}

fn prepare_plain_drain_swap(
    input_proofs: Vec<Proof>,
    output_amount_raw: u64,
    output_keyset_info_json: &str,
) -> Result<PreparedDrainSwap, String> {
    let plain = create_plain_blinded_messages(output_amount_raw, output_keyset_info_json)?;
    let plain_json: serde_json::Value =
        serde_json::from_str(&plain).map_err(|e| format!("parse plain outputs: {e}"))?;
    let blinded_messages_value = plain_json
        .get("blinded_messages")
        .cloned()
        .ok_or_else(|| "plain output helper returned no blinded_messages".to_string())?;
    let output_secrets_value = plain_json
        .get("secrets_with_blinding")
        .cloned()
        .ok_or_else(|| "plain output helper returned no secrets_with_blinding".to_string())?;
    let blinded_messages: Vec<BlindedMessage> =
        serde_json::from_value(blinded_messages_value.clone())
            .map_err(|e| format!("parse blinded messages: {e}"))?;
    let swap_request = SwapRequest::new(input_proofs, blinded_messages);
    let swap_request_json = serde_json::to_string(&swap_request)
        .map_err(|e| format!("serialize drain swap request: {e}"))?;
    let restore_request_json = serde_json::to_string(&serde_json::json!({
        "outputs": blinded_messages_value,
    }))
    .map_err(|e| format!("serialize drain restore request: {e}"))?;
    let output_secrets_json = serde_json::to_string(&output_secrets_value)
        .map_err(|e| format!("serialize drain output secrets: {e}"))?;

    Ok(PreparedDrainSwap {
        swap_request_json,
        restore_request_json,
        output_secrets_json,
    })
}

fn complete_plain_drain_swap(
    swap_response_json: &str,
    output_secrets_json: &str,
    output_keyset_info_json: &str,
) -> Result<String, String> {
    let complete = complete_funding_swap(
        swap_response_json,
        output_secrets_json,
        output_keyset_info_json,
    )?;
    let complete_json: serde_json::Value =
        serde_json::from_str(&complete).map_err(|e| format!("parse completed drain swap: {e}"))?;
    complete_json["funding_proofs_json"]
        .as_str()
        .map(ToString::to_string)
        .ok_or_else(|| "completed drain swap returned no funding_proofs_json".to_string())
}

fn new_drain_id() -> String {
    format!("drain-{}", SecretKey::generate().to_secret_hex())
}

fn now_seconds() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

fn i64_from_u64(value: u64) -> Result<i64, String> {
    i64::try_from(value).map_err(|_| format!("integer too large for SQLite: {value}"))
}

fn u64_from_i64(value: i64) -> rusqlite::Result<u64> {
    u64::try_from(value).map_err(|_| {
        rusqlite::Error::FromSqlConversionFailure(
            0,
            rusqlite::types::Type::Integer,
            Box::new(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("negative integer in database: {value}"),
            )),
        )
    })
}

#[async_trait::async_trait]
impl SpilmanAsyncKeysetRefresher for RelayWalletManager {
    async fn refresh(&self, mint: &str) -> Result<(), String> {
        self.refresh_all_keysets_for_mint_into_shared_cache(mint)
            .await
    }
}

#[cfg(test)]
mod keyset_refresher_tests {
    use super::*;
    use cdk_spilman_test_mint::{build_router, rotate_sat_keyset, TestMintHelper};
    use tokio::net::TcpListener;

    #[tokio::test]
    async fn keyset_refresher_updates_sqlite_and_shared_cache() {
        let mint_helper = TestMintHelper::new().await.unwrap();
        let mint = mint_helper.mint();
        let old_keyset_id = mint_helper.keyset_id().to_string();
        let new_keyset_id = rotate_sat_keyset(&mint, 123).await.unwrap().to_string();
        assert_ne!(old_keyset_id, new_keyset_id);

        let mint_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let mint_addr = mint_listener.local_addr().unwrap();
        let mint_url = format!("http://127.0.0.1:{}", mint_addr.port());
        let mint_router = build_router(mint).await.unwrap();
        let (mint_shutdown_tx, mint_shutdown_rx) = tokio::sync::oneshot::channel();
        tokio::spawn(async move {
            axum::serve(mint_listener, mint_router)
                .with_graceful_shutdown(async {
                    let _ = mint_shutdown_rx.await;
                })
                .await
                .unwrap();
        });

        let temp_db = tempfile::NamedTempFile::new().unwrap();
        let manager = RelayWalletManager::open(temp_db.path().to_str().unwrap()).unwrap();

        SpilmanAsyncKeysetRefresher::refresh(&manager, &mint_url)
            .await
            .unwrap();

        let old_id = old_keyset_id.parse().unwrap();
        let new_id = new_keyset_id.parse().unwrap();
        let old_cached = manager
            .spilman_storage()
            .get_keyset(&mint_url, &old_id)
            .expect("old keyset cached");
        let new_cached = manager
            .spilman_storage()
            .get_keyset(&mint_url, &new_id)
            .expect("new keyset cached");
        assert!(!old_cached.active);
        assert!(new_cached.active);

        // Upstream close retry re-prepares the close with the same payments
        // object, so the refresher must update the shared cache it reads from.
        let snapshot = manager.keyset_cache_snapshot();
        let cached_keysets = snapshot
            .keysets
            .get(&mint_url)
            .expect("mint keysets cached in shared cache");
        assert!(
            !cached_keysets
                .get(&old_keyset_id)
                .expect("old keyset in shared cache")
                .active
        );
        assert!(
            cached_keysets
                .get(&new_keyset_id)
                .expect("new keyset in shared cache")
                .active
        );

        let _ = mint_shutdown_tx.send(());
    }
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct RelayWalletIdentitySummary {
    pub name: String,
    pub receiver_pubkey_hex: String,
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct ChannelSummary {
    pub channel_id: String,
    pub relay_name: String,
    pub receiver_pubkey_hex: String,
    pub state: ChannelState,
    pub mint_url: String,
    pub unit: String,
    pub capacity_raw: u64,
    pub balance_raw: u64,
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct ExpiringChannelSummary {
    pub channel_id: String,
    pub relay_name: String,
    pub receiver_pubkey_hex: String,
    pub state: ChannelState,
    pub mint_url: String,
    pub unit: String,
    pub expiry_timestamp: u64,
    pub seconds_until_expiry: i64,
    pub capacity_raw: u64,
    pub balance_raw: u64,
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct CloseExpiringChannelsResult {
    pub dry_run: bool,
    pub close_before_expiry_secs: u64,
    pub candidate_count: usize,
    pub candidates: Vec<ExpiringChannelSummary>,
    pub resolved: Vec<CloseExpiringChannelSuccess>,
    pub failures: Vec<CloseExpiringChannelFailure>,
    pub unresolved: Vec<ExpiringChannelSummary>,
}

impl CloseExpiringChannelsResult {
    pub fn new(close_before_expiry_secs: u64, candidate_count: usize) -> Self {
        Self {
            dry_run: false,
            close_before_expiry_secs,
            candidate_count,
            candidates: Vec::new(),
            resolved: Vec::new(),
            failures: Vec::new(),
            unresolved: Vec::new(),
        }
    }

    pub fn dry_run(close_before_expiry_secs: u64, candidates: Vec<ExpiringChannelSummary>) -> Self {
        Self {
            dry_run: true,
            close_before_expiry_secs,
            candidate_count: candidates.len(),
            candidates,
            resolved: Vec::new(),
            failures: Vec::new(),
            unresolved: Vec::new(),
        }
    }
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct CloseExpiringChannelSuccess {
    pub channel: ExpiringChannelSummary,
    pub close: CloseOutcome,
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct CloseExpiringChannelFailure {
    pub channel: ExpiringChannelSummary,
    pub error: String,
}

struct ChannelSummaryMetadata {
    mint_url: String,
    unit: String,
    capacity_raw: u64,
    expiry_timestamp: u64,
}

fn parse_channel_summary_metadata(
    channel_id: &str,
    params_json: &str,
) -> io::Result<ChannelSummaryMetadata> {
    let value: serde_json::Value = serde_json::from_str(params_json)
        .map_err(|e| io::Error::other(format!("corrupt funding JSON for {channel_id}: {e}")))?;
    let mint_url = value["mint"].as_str().unwrap_or("unknown").to_string();
    let unit = value["unit"].as_str().unwrap_or("unknown").to_string();
    let capacity_raw = value["capacity"].as_u64().ok_or_else(|| {
        io::Error::other(format!(
            "corrupt funding JSON for {channel_id}: missing capacity"
        ))
    })?;
    let expiry_timestamp = value["expiry_timestamp"].as_u64().ok_or_else(|| {
        io::Error::other(format!(
            "corrupt funding JSON for {channel_id}: missing expiry_timestamp"
        ))
    })?;
    Ok(ChannelSummaryMetadata {
        mint_url,
        unit,
        capacity_raw,
        expiry_timestamp,
    })
}

fn seconds_until_expiry(now: u64, expiry_timestamp: u64) -> i64 {
    if expiry_timestamp >= now {
        let remaining = expiry_timestamp - now;
        remaining.min(i64::MAX as u64) as i64
    } else {
        let overdue = now - expiry_timestamp;
        -(overdue.min(i64::MAX as u64) as i64)
    }
}

fn close_error_summary(error: &CloseError) -> String {
    match error {
        CloseError::ValidationFailed { reason, .. } => format!("validation failed: {reason}"),
        CloseError::UnknownChannel { .. } => "unknown channel".to_string(),
        CloseError::AlreadyClosed {
            closed_balance,
            requested_balance,
            ..
        } => format!(
            "already closed: closed_balance={closed_balance} requested_balance={requested_balance}"
        ),
        CloseError::MintRejected { mint_error, .. } => format!("mint rejected: {mint_error}"),
        CloseError::MintRejectedAfterRetry {
            original_error,
            retry_error,
            ..
        } => format!("mint rejected after retry: original={original_error} retry={retry_error}"),
        CloseError::UnblindFailed { reason, .. } => format!("unblind failed: {reason}"),
        CloseError::StorageFailed { reason, .. } => format!("storage failed: {reason}"),
    }
}

fn load_identities(db_path: &str) -> io::Result<HashMap<String, SecretKey>> {
    let conn = cdk_spilman::sqlite_durability::open_wallet_database(db_path)
        .map_err(|e| io::Error::other(format!("open relay wallet db: {e}")))?;
    let mut stmt = conn
        .prepare("SELECT relay_name, receiver_secret_hex FROM monad_relay_wallet_identities")
        .map_err(|e| io::Error::other(format!("prepare relay wallet identity query: {e}")))?;
    let rows = stmt
        .query_map([], |row| {
            let relay_name: String = row.get(0)?;
            let receiver_secret_hex: String = row.get(1)?;
            Ok((relay_name, receiver_secret_hex))
        })
        .map_err(|e| io::Error::other(format!("query relay wallet identities: {e}")))?;

    let mut identities = HashMap::new();
    for row in rows {
        let (relay_name, receiver_secret_hex) =
            row.map_err(|e| io::Error::other(format!("read relay wallet identity row: {e}")))?;
        let receiver_secret = SecretKey::from_hex(&receiver_secret_hex).map_err(|e| {
            io::Error::other(format!(
                "decode receiver secret for relay wallet identity '{relay_name}': {e}"
            ))
        })?;
        identities.insert(relay_name, receiver_secret);
    }
    Ok(identities)
}

fn store_identity(
    relay_name: &str,
    receiver_secret_hex: &str,
    receiver_pubkey_hex: &str,
    db_path: &str,
) -> io::Result<()> {
    let conn = cdk_spilman::sqlite_durability::open_wallet_database(db_path)
        .map_err(|e| io::Error::other(format!("open relay wallet db: {e}")))?;
    conn.execute(
        "INSERT INTO monad_relay_wallet_identities(relay_name, receiver_secret_hex, receiver_pubkey_hex)
         VALUES (?1, ?2, ?3)",
        params![relay_name, receiver_secret_hex, receiver_pubkey_hex],
    )
    .map_err(|e| {
        io::Error::new(
            io::ErrorKind::AlreadyExists,
            format!("store relay wallet identity '{relay_name}': {e}"),
        )
    })?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use cdk_spilman::configurable_host::ClosedDataView;
    use cdk_spilman::{ChannelFunding, PaymentProof};

    fn temp_db_path() -> String {
        tempfile::NamedTempFile::new()
            .unwrap()
            .path()
            .to_str()
            .unwrap()
            .to_string()
    }

    fn save_test_channel(
        store: &ChannelStore,
        channel_id: &str,
        receiver_pubkey_hex: &str,
        expiry_timestamp: u64,
        balance: u64,
    ) {
        let funding = ChannelFunding {
            params_json: serde_json::json!({
                "channel_id": channel_id,
                "mint": "https://test.mint",
                "unit": "sat",
                "capacity": 1000u64,
                "expiry_timestamp": 4_000_000_000u64,
                "keyset_id": "00testkeyset0000",
                "receiver_pubkey": receiver_pubkey_hex,
                "sender_pubkey": "0000000000000000000000000000000000000000000000000000000000000002",
                "expiry_timestamp": expiry_timestamp,
            })
            .to_string(),
            funding_proofs_json: "[]".to_string(),
            channel_secret_hex: "0000000000000000000000000000000000000000000000000000000000000001"
                .to_string(),
            keyset_info_json: "{}".to_string(),
        };
        store
            .save_funding(
                channel_id,
                funding,
                PaymentProof {
                    balance,
                    signature: "sig".to_string(),
                },
            )
            .unwrap();
    }

    #[test]
    fn list_identities_after_register() {
        let manager = RelayWalletManager::open(temp_db_path()).unwrap();
        let s1 = SecretKey::generate();
        let s2 = SecretKey::generate();
        manager.register_identity("r1", s1).unwrap();
        manager.register_identity("r2", s2).unwrap();

        let mut ids = manager.list_identities();
        ids.sort_by(|a, b| a.name.cmp(&b.name));
        assert_eq!(ids.len(), 2);
        assert_eq!(ids[0].name, "r1");
        assert_eq!(ids[1].name, "r2");
    }

    #[test]
    fn wallet_authority_matches_database_and_outlives_manager_handles() {
        let dir = tempfile::tempdir().unwrap();
        let db = dir.path().join("relay.db");
        let other = dir.path().join("other.db");
        let locks =
            WalletLocks::acquire([db.as_path()], WalletLockMode::Maintenance, "test").unwrap();
        assert!(RelayWalletManager::open_with_locks(other.to_str().unwrap(), locks).is_err());
        assert!(!other.exists());
        let locks = WalletLocks::acquire([db.as_path()], WalletLockMode::Runtime, "test").unwrap();
        let manager = RelayWalletManager::open_with_locks(db.to_str().unwrap(), locks).unwrap();
        manager.enter_steady_state().unwrap();
        assert!(manager.require_maintenance().is_err());
        assert!(manager.reopen().is_err());
        let channel_owner = manager.metadata.clone();
        drop(manager);
        assert!(RelayWalletManager::open(db.to_str().unwrap()).is_err());
        drop(channel_owner);
        assert!(RelayWalletManager::open(db.to_str().unwrap()).is_ok());
    }

    #[test]
    fn incompatible_journals_are_rejected_before_schema_initialization() {
        for fixture in [
            "CREATE TABLE monad_relay_drains(drain_id TEXT); INSERT INTO monad_relay_drains VALUES ('legacy')",
            "CREATE TABLE spilman_channels(channel_id TEXT,state TEXT); INSERT INTO spilman_channels VALUES ('legacy','Closing')",
        ] {
            let db = tempfile::NamedTempFile::new().unwrap();
            let conn = Connection::open(db.path()).unwrap();
            conn.execute_batch(fixture).unwrap();
            let before: u64 = conn.query_row("PRAGMA schema_version", [], |r| r.get(0)).unwrap();
            assert!(RelayWalletManager::open(db.path().to_str().unwrap()).is_err());
            let after: u64 = conn.query_row("PRAGMA schema_version", [], |r| r.get(0)).unwrap();
            assert_eq!(before, after);
            assert_eq!(conn.query_row("SELECT COUNT(*) FROM sqlite_master WHERE type='table'", [], |r| r.get::<_,u64>(0)).unwrap(), 1);
        }
    }

    #[tokio::test]
    async fn legacy_closing_authorization_is_not_reinterpreted_as_a_request() {
        let db = tempfile::NamedTempFile::new().unwrap();
        let manager = RelayWalletManager::open(db.path().to_str().unwrap()).unwrap();
        let key = SecretKey::generate();
        manager.register_identity("relay", key.clone()).unwrap();
        let store = ChannelStore::with_relay_metadata(
            manager.storage.clone(),
            manager.metadata.clone(),
            "relay".to_string(),
            key.public_key().to_hex(),
        );
        save_test_channel(&store, "channel", &key.public_key().to_hex(), 10, 5);
        store
            .mark_channel_closing(
                "channel",
                10,
                PaymentProof {
                    balance: 5,
                    signature: "sig".to_string(),
                },
            )
            .unwrap();
        let error = manager
            .close_channel("channel", &RelayWalletMintClient::new())
            .await
            .unwrap_err();
        assert!(error.to_string().contains("lacks exact close journal"));
        assert_eq!(store.channel_state("channel"), Some(ChannelState::Closing));
        assert!(manager
            .storage
            .get_close_journal("channel")
            .unwrap()
            .is_none());
        assert!(manager.reopen().is_err());
    }

    #[test]
    fn read_only_inspection_reads_existing_wallet_and_never_creates_one() {
        let dir = tempfile::tempdir().unwrap();
        let db_path = dir.path().join("relay.db");
        let manager = RelayWalletManager::open(db_path.to_str().unwrap()).unwrap();
        manager
            .register_identity("relay-a", SecretKey::generate())
            .unwrap();
        drop(manager);

        let inspection = RelayWalletInspection::open(db_path.to_str().unwrap()).unwrap();
        assert_eq!(inspection.list_identities().unwrap().len(), 1);

        let missing = dir.path().join("missing.db");
        assert!(RelayWalletInspection::open(missing.to_str().unwrap()).is_err());
        assert!(!missing.exists());
    }

    #[test]
    fn list_channels_returns_saved_channel() {
        let db_path = temp_db_path();
        let manager = RelayWalletManager::open(&db_path).unwrap();
        let secret = SecretKey::generate();
        let pubkey_hex = secret.public_key().to_hex();
        manager.register_identity("r1", secret).unwrap();

        let store = ChannelStore::with_relay_metadata(
            manager.storage.clone(),
            manager.metadata.clone(),
            "r1".to_string(),
            pubkey_hex.clone(),
        );
        let channel_id = "chan-abc".to_string();
        let funding = ChannelFunding {
            params_json: serde_json::json!({
                "channel_id": &channel_id,
                "mint": "https://test.mint",
                "unit": "sat",
                "capacity": 1000u64,
                "expiry_timestamp": 4_000_000_000u64,
                "keyset_id": "00testkeyset0000",
                "receiver_pubkey": &pubkey_hex,
                "sender_pubkey": "0000000000000000000000000000000000000000000000000000000000000002",
            })
            .to_string(),
            funding_proofs_json: "[]".to_string(),
            channel_secret_hex: "0000000000000000000000000000000000000000000000000000000000000001"
                .to_string(),
            keyset_info_json: "{}".to_string(),
        };
        let initial_payment = PaymentProof {
            balance: 250,
            signature: "sig".to_string(),
        };
        store
            .save_funding(&channel_id, funding, initial_payment)
            .unwrap();

        let channels = manager.list_channels(Some("r1")).unwrap();
        assert_eq!(channels.len(), 1);
        assert_eq!(channels[0].channel_id, channel_id);
        assert_eq!(channels[0].relay_name, "r1");
        assert_eq!(channels[0].mint_url, "https://test.mint");
        assert_eq!(channels[0].unit, "sat");
        assert_eq!(channels[0].capacity_raw, 1000);

        let inspection = RelayWalletInspection::open(&db_path).unwrap();
        let inspected = inspection.list_channels(Some("r1")).unwrap();
        assert_eq!(inspected.len(), 1);
        assert_eq!(inspected[0].channel_id, channel_id);
        assert_eq!(inspected[0].mint_url, "https://test.mint");
        assert_eq!(inspected[0].capacity_raw, 1000);
        assert_eq!(channels[0].balance_raw, 250);

        let all_channels = manager.list_channels(None).unwrap();
        assert_eq!(all_channels.len(), 1);
    }

    #[test]
    fn find_expiring_channels_filters_open_closing_closed_and_orders_by_expiry() {
        let manager = RelayWalletManager::open(temp_db_path()).unwrap();
        let secret = SecretKey::generate();
        let pubkey_hex = secret.public_key().to_hex();
        manager.register_identity("r1", secret).unwrap();
        let store = ChannelStore::with_relay_metadata(
            manager.storage.clone(),
            manager.metadata.clone(),
            "r1".to_string(),
            pubkey_hex.clone(),
        );
        let now = 1_000u64;
        save_test_channel(&store, "open-far", &pubkey_hex, now + 10_000, 10);
        save_test_channel(&store, "open-near", &pubkey_hex, now + 100, 20);
        save_test_channel(&store, "closing-far", &pubkey_hex, now + 10_000, 30);
        save_test_channel(&store, "closing-near", &pubkey_hex, now + 200, 40);
        save_test_channel(&store, "closed-near", &pubkey_hex, now + 100, 50);

        store
            .mark_channel_closing(
                "closing-far",
                now + 10_000,
                PaymentProof {
                    balance: 30,
                    signature: "sig".to_string(),
                },
            )
            .unwrap();
        store
            .mark_channel_closing(
                "closing-near",
                now + 200,
                PaymentProof {
                    balance: 40,
                    signature: "sig".to_string(),
                },
            )
            .unwrap();
        store
            .mark_channel_closed(
                "closed-near",
                ClosedDataView {
                    expiry_timestamp: now + 100,
                    closed_amount: 50,
                    value_after_stage1: 1000,
                    receiver_sum: 50,
                    sender_sum: 950,
                    receiver_proofs_json: "[]".to_string(),
                    sender_proofs_json: "[]".to_string(),
                },
            )
            .unwrap();

        let expiring = manager
            .find_expiring_channels(Some("r1"), now, 300)
            .unwrap();
        let ids = expiring
            .iter()
            .map(|channel| channel.channel_id.as_str())
            .collect::<Vec<_>>();
        assert_eq!(ids, vec!["open-near", "closing-near"]);
        let closing = expiring
            .iter()
            .find(|channel| channel.channel_id == "closing-near")
            .unwrap();
        assert_eq!(closing.state, ChannelState::Closing);
        assert_eq!(closing.seconds_until_expiry, 200);
        assert_eq!(closing.balance_raw, 40);
    }

    #[test]
    fn find_expiring_channels_without_relay_scans_all_identities() {
        let manager = RelayWalletManager::open(temp_db_path()).unwrap();
        let secret1 = SecretKey::generate();
        let pubkey1_hex = secret1.public_key().to_hex();
        let secret2 = SecretKey::generate();
        let pubkey2_hex = secret2.public_key().to_hex();
        manager.register_identity("r1", secret1).unwrap();
        manager.register_identity("r2", secret2).unwrap();
        let store1 = ChannelStore::with_relay_metadata(
            manager.storage.clone(),
            manager.metadata.clone(),
            "r1".to_string(),
            pubkey1_hex.clone(),
        );
        let store2 = ChannelStore::with_relay_metadata(
            manager.storage.clone(),
            manager.metadata.clone(),
            "r2".to_string(),
            pubkey2_hex.clone(),
        );
        let now = 1_000u64;
        save_test_channel(&store1, "r1-near", &pubkey1_hex, now + 200, 20);
        save_test_channel(&store2, "r2-nearer", &pubkey2_hex, now + 100, 30);

        let expiring = manager.find_expiring_channels(None, now, 300).unwrap();
        let ids = expiring
            .iter()
            .map(|channel| (channel.channel_id.as_str(), channel.relay_name.as_str()))
            .collect::<Vec<_>>();

        assert_eq!(ids, vec![("r2-nearer", "r2"), ("r1-near", "r1")]);
    }

    #[tokio::test]
    async fn close_expiring_channel_candidates_records_failures_and_continues() {
        let manager = RelayWalletManager::open(temp_db_path()).unwrap();
        let channels = vec![ExpiringChannelSummary {
            channel_id: "missing-channel".to_string(),
            relay_name: "r1".to_string(),
            receiver_pubkey_hex: "receiver".to_string(),
            state: ChannelState::Open,
            mint_url: "https://test.mint".to_string(),
            unit: "sat".to_string(),
            expiry_timestamp: 1_000,
            seconds_until_expiry: 100,
            capacity_raw: 1_000,
            balance_raw: 0,
        }];

        let result = manager
            .close_expiring_channel_candidates(channels, 300)
            .await;

        assert_eq!(result.candidate_count, 1);
        assert!(result.resolved.is_empty());
        assert_eq!(result.failures.len(), 1);
        assert_eq!(result.failures[0].channel.channel_id, "missing-channel");
        assert!(result.failures[0].error.contains("not found"));
    }

    #[test]
    fn relay_name_for_channel_returns_owner() {
        let db_path = temp_db_path();
        let manager = RelayWalletManager::open(&db_path).unwrap();
        let secret = SecretKey::generate();
        let pubkey_hex = secret.public_key().to_hex();
        manager.register_identity("r1", secret).unwrap();

        let store = ChannelStore::with_relay_metadata(
            manager.storage.clone(),
            manager.metadata.clone(),
            "r1".to_string(),
            pubkey_hex,
        );
        let channel_id = "chan-xyz".to_string();
        let funding = ChannelFunding {
            params_json: serde_json::json!({
                "channel_id": &channel_id,
                "mint": "https://test.mint",
                "unit": "sat",
                "capacity": 100u64,
            })
            .to_string(),
            funding_proofs_json: "[]".to_string(),
            channel_secret_hex: "0000000000000000000000000000000000000000000000000000000000000001"
                .to_string(),
            keyset_info_json: "{}".to_string(),
        };
        store
            .save_funding(
                &channel_id,
                funding,
                PaymentProof {
                    balance: 0,
                    signature: String::new(),
                },
            )
            .unwrap();

        assert_eq!(
            manager.relay_name_for_channel(&channel_id).unwrap(),
            Some("r1".to_string())
        );
    }
}
