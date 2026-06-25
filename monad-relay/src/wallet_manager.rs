use crate::channel_store::ChannelStore;
use crate::listener::{
    shared_spilman_mint_cache, SharedSpilmanMintCache, SpilmanMintCache, TrustedMintUnits,
};
use crate::payments::{RelayPayments, SpilmanRelayPayments};
use cashu::nuts::{BlindedMessage, Proof, SecretKey, SwapRequest};
use cdk_spilman::configurable_host::{
    ConfigurableHost, ConfigurableHostConfig, KeysetCacheEntry, SpilmanStorage, SqliteStorage,
    StorageConfig, UnitPricingConfig,
};
use cdk_spilman::configurable_networking::{
    build_keyset_info_json, fetch_all_keysets_from_mint, MintKeysetWithKeys, ReqwestNetworking,
};
use cdk_spilman::{
    complete_funding_swap, create_plain_blinded_messages, is_retryable_keyset_mint_error,
    with_active_keyset_retry_async, ActiveKeysetSelection, ChannelState, CloseError, CloseSuccess,
    KeysetRetryError, SelectedOutputKeyset, SpilmanAsyncNetworking,
};
use rusqlite::{params, Connection, OptionalExtension};
use serde::Serialize;
use std::collections::{BTreeMap, HashMap};
use std::future::Future;
use std::io;
use std::pin::Pin;
use std::sync::{Arc, Mutex, RwLock};

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

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
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

pub trait DrainSwapNetworking {
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

impl DrainSwapNetworking for ReqwestNetworking {
    fn call_mint_swap<'a>(
        &'a self,
        mint_url: &'a str,
        swap_request_json: &'a str,
    ) -> Pin<Box<dyn Future<Output = Result<String, String>> + Send + 'a>> {
        Box::pin(async move {
            SpilmanAsyncNetworking::call_mint_swap(self, mint_url, swap_request_json).await
        })
    }

    fn call_mint_restore<'a>(
        &'a self,
        mint_url: &'a str,
        restore_request_json: &'a str,
    ) -> Pin<Box<dyn Future<Output = Result<String, String>> + Send + 'a>> {
        Box::pin(async move {
            let resp = reqwest::Client::new()
                .post(format!("{mint_url}/v1/restore"))
                .header("Content-Type", "application/json")
                .body(restore_request_json.to_string())
                .send()
                .await
                .map_err(|e| format!("Restore request failed: {e}"))?;
            if !resp.status().is_success() {
                let status = resp.status();
                let body = resp.text().await.unwrap_or_default();
                return Err(format!("Restore failed: {status} - {body}"));
            }
            resp.text()
                .await
                .map_err(|e| format!("Failed to read restore response: {e}"))
        })
    }
}

struct RelayWalletCloseNetworking<'a, N> {
    inner: &'a N,
    wallet_manager: &'a RelayWalletManager,
}

#[async_trait::async_trait]
impl<N: SpilmanAsyncNetworking + Sync> SpilmanAsyncNetworking
    for RelayWalletCloseNetworking<'_, N>
{
    async fn call_mint_swap(
        &self,
        mint_url: &str,
        swap_request_json: &str,
    ) -> Result<String, String> {
        self.inner.call_mint_swap(mint_url, swap_request_json).await
    }

    async fn refresh_all_keysets(&self, mint: &str) -> Result<(), String> {
        self.wallet_manager
            .refresh_keysets_into_shared_cache(mint)
            .await?;
        self.inner.refresh_all_keysets(mint).await
    }
}

#[derive(Debug, Clone)]
pub struct RelayWalletIdentity {
    pub name: String,
    pub receiver_secret: SecretKey,
}

#[derive(Debug, Clone)]
pub(crate) struct ChannelMetadataStore {
    db_path: String,
}

impl ChannelMetadataStore {
    pub(crate) fn new(db_path: impl Into<String>) -> io::Result<Self> {
        let store = Self {
            db_path: db_path.into(),
        };
        store.init()?;
        Ok(store)
    }

    fn init(&self) -> io::Result<()> {
        let conn = Connection::open(&self.db_path)
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
        let conn = Connection::open(&self.db_path)
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
        let conn = Connection::open(&self.db_path)
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
        let conn = Connection::open(&self.db_path)
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

impl std::fmt::Debug for RelayWalletManager {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RelayWalletManager").finish_non_exhaustive()
    }
}

impl RelayWalletManager {
    pub fn open(db_path: impl Into<String>) -> io::Result<Self> {
        let db_path = db_path.into();
        let conn = Connection::open(&db_path)
            .map_err(|e| io::Error::other(format!("open relay wallet db: {e}")))?;
        conn.execute_batch(CREATE_IDENTITIES_TABLE_SQL)
            .map_err(|e| io::Error::other(format!("create relay wallet identities table: {e}")))?;
        conn.execute_batch(CREATE_DRAIN_TABLES_SQL)
            .map_err(|e| io::Error::other(format!("create relay wallet drain tables: {e}")))?;
        drop(conn);

        let storage = Arc::new(
            SqliteStorage::open(&db_path)
                .map_err(|e| io::Error::other(format!("open relay wallet storage: {e}")))?,
        );
        let metadata = Arc::new(ChannelMetadataStore::new(db_path.clone())?);
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

    pub fn spilman_payments_for_live(
        &self,
        relay_name: &str,
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
            store,
        )))
    }

    pub fn spilman_payments_for(
        &self,
        relay_name: &str,
        mint_cache: SpilmanMintCache,
        trusted_mint_units: TrustedMintUnits,
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

    /// Build a [`ReqwestNetworking`] instance configured for the mint and
    /// receiver identity associated with a stored channel.  Used by the CLI
    /// close command.
    pub fn reqwest_networking_for_channel(
        &self,
        channel_id: &str,
    ) -> Result<ReqwestNetworking, String> {
        let (receiver_secret, mint_url, unit) = self.channel_owner_and_mint(channel_id)?;
        build_reqwest_networking(&receiver_secret, &mint_url, &unit)
    }

    /// Build a [`ReqwestNetworking`] instance for a relay identity and mint/unit.
    /// Used by wallet drain CLI commands.
    pub fn reqwest_networking_for_relay(
        &self,
        relay_name: &str,
        mint_url: &str,
        unit: &str,
    ) -> Result<ReqwestNetworking, String> {
        let identities = self
            .identities
            .lock()
            .map_err(|_| "relay wallet identity mutex poisoned".to_string())?;
        let receiver_secret = identities
            .get(relay_name)
            .ok_or_else(|| format!("unknown relay identity '{relay_name}'"))?;
        build_reqwest_networking(receiver_secret, mint_url, unit)
    }

    /// Close any channel stored in this wallet DB, regardless of which relay
    /// identity owns it.  If the channel is already `Closed`, returns a
    /// synthetic success.  If it is `Closing`, completes the close.  Otherwise
    /// initiates and executes a unilateral close against the channel's mint.
    pub async fn close_channel<N: SpilmanAsyncNetworking + Sync>(
        &self,
        channel_id: &str,
        net: &N,
    ) -> Result<CloseSuccess, CloseError> {
        let payments = self.payments_for_channel(channel_id).await?;
        let net = RelayWalletCloseNetworking {
            inner: net,
            wallet_manager: self,
        };
        payments
            .close_channel_any_state_async(channel_id, &net)
            .await
    }

    pub async fn drain_closed_channels_to_swap<N: DrainSwapNetworking>(
        &self,
        relay_name: &str,
        mint_url: &str,
        unit: &str,
        net: &N,
        limit: Option<usize>,
    ) -> Result<DrainSwapResult, String> {
        let candidates = self.closed_drain_candidates(relay_name, mint_url, unit, limit)?;
        if candidates.is_empty() {
            return Err("no closed channels available to drain".to_string());
        }

        let mut all_input_proofs = Vec::new();
        let mut input_amount_raw = 0u64;
        for candidate in &candidates {
            let proofs: Vec<Proof> = serde_json::from_str(&candidate.receiver_proofs_json)
                .map_err(|e| format!("parse receiver proofs for {}: {e}", candidate.channel_id))?;
            for proof in proofs {
                input_amount_raw = input_amount_raw
                    .checked_add(u64::from(proof.amount))
                    .ok_or_else(|| "drain input amount overflow".to_string())?;
                all_input_proofs.push(proof);
            }
        }
        if all_input_proofs.is_empty() {
            return Err("closed channels have no receiver proofs to drain".to_string());
        }

        let drain_id = new_drain_id();
        let outcome = self
            .submit_drain_with_keyset_retry(
                net,
                DrainSubmitRequest {
                    relay_name,
                    mint_url,
                    unit,
                    drain_id: &drain_id,
                    candidates: &candidates,
                    all_input_proofs: &all_input_proofs,
                    input_amount_raw,
                },
            )
            .await?;
        // The helper reports whether the retry branch was used; integration
        // tests assert that path via submitted swap contents and call counts.
        let _did_retry = outcome.did_retry;
        let attempt = outcome.attempt;

        let output_proofs_json = complete_plain_drain_swap(
            &outcome.swap_response,
            &attempt.prepared.output_secrets_json,
            &attempt.drain_keysets.output_keyset_info_json,
        )?;
        self.mark_drain_completed(&drain_id, &output_proofs_json, now_seconds())?;

        Ok(DrainSwapResult {
            drain_id,
            relay_name: relay_name.to_string(),
            mint_url: mint_url.to_string(),
            unit: unit.to_string(),
            input_amount_raw,
            output_amount_raw: attempt.output_amount_raw,
            output_proofs_json,
            channel_ids: candidates.into_iter().map(|c| c.channel_id).collect(),
            recovered: false,
        })
    }

    pub async fn recover_submitted_drain<N: DrainSwapNetworking>(
        &self,
        drain_id: &str,
        net: &N,
    ) -> Result<DrainSwapResult, String> {
        let drain = self.load_drain(drain_id)?;
        if drain.state == "Completed" {
            return self.completed_drain_result(drain, false);
        }
        if drain.state != "Submitted" {
            return Err(format!(
                "drain {drain_id} is in state {}, not Submitted",
                drain.state
            ));
        }

        let restore_response = net
            .call_mint_restore(&drain.mint_url, &drain.restore_request_json)
            .await?;
        let swap_response = wrap_restore_response_as_swap_response(&restore_response)?;
        let output_proofs_json = complete_plain_drain_swap(
            &swap_response,
            &drain.output_secrets_json,
            &drain.output_keyset_info_json,
        )?;
        self.mark_drain_completed(drain_id, &output_proofs_json, now_seconds())?;

        let mut completed = drain;
        completed.state = "Completed".to_string();
        completed.output_proofs_json = Some(output_proofs_json);
        self.completed_drain_result(completed, true)
    }

    pub fn list_drains(&self) -> Result<Vec<DrainSummary>, String> {
        let conn = Connection::open(&self.metadata.db_path)
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

    /// Fetch all keysets from a mint and persist them in SQLite.
    ///
    /// Use [`Self::refresh_keysets_into_shared_cache`] when the caller also
    /// needs existing live payment/session objects to observe the new keysets.
    pub async fn refresh_keysets_from_mint(
        &self,
        mint_url: &str,
    ) -> Result<Vec<MintKeysetWithKeys>, String> {
        let keysets = fetch_all_keysets_from_mint(mint_url).await?;
        cache_relay_keysets(self.storage.as_ref(), mint_url, &keysets)?;
        Ok(keysets)
    }

    /// Refresh one mint into SQLite and merge the result into the shared memory
    /// cache used by live relay payment objects.
    ///
    /// Channel close uses this from the upstream keyset-error retry hook: the
    /// first close attempt is cache-first, then a retry refreshes this mint and
    /// re-prepares the swap against the updated shared cache.
    pub async fn refresh_keysets_into_shared_cache(&self, mint_url: &str) -> Result<(), String> {
        let keysets = self.refresh_keysets_from_mint(mint_url).await?;
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
        let conn = Connection::open(&self.metadata.db_path)
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

    #[allow(clippy::too_many_arguments)]
    fn insert_prepared_drain(
        &self,
        drain_id: &str,
        relay_name: &str,
        mint_url: &str,
        unit: &str,
        input_amount_raw: u64,
        output_amount_raw: u64,
        prepared: &PreparedDrainSwap,
        output_keyset_id: &str,
        output_keyset_info_json: &str,
        candidates: &[DrainCandidate],
        created_at: u64,
    ) -> Result<(), String> {
        let mut conn = Connection::open(&self.metadata.db_path)
            .map_err(|e| format!("open relay wallet db: {e}"))?;
        let tx = conn
            .transaction()
            .map_err(|e| format!("begin drain transaction: {e}"))?;
        tx.execute(
            "INSERT INTO monad_relay_drains(
                drain_id, relay_name, mint_url, unit, state, input_amount_raw, output_amount_raw,
                swap_request_json, restore_request_json, output_secrets_json, output_keyset_id,
                output_keyset_info_json, created_at
             ) VALUES (?1, ?2, ?3, ?4, 'Prepared', ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12)",
            params![
                drain_id,
                relay_name,
                mint_url,
                unit,
                i64_from_u64(input_amount_raw)?,
                i64_from_u64(output_amount_raw)?,
                prepared.swap_request_json,
                prepared.restore_request_json,
                prepared.output_secrets_json,
                output_keyset_id,
                output_keyset_info_json,
                i64_from_u64(created_at)?,
            ],
        )
        .map_err(|e| format!("insert drain: {e}"))?;

        for candidate in candidates {
            tx.execute(
                "INSERT INTO monad_relay_drain_inputs(
                    drain_id, channel_id, receiver_sum_raw, receiver_proofs_json
                 ) VALUES (?1, ?2, ?3, ?4)",
                params![
                    drain_id,
                    candidate.channel_id,
                    i64_from_u64(candidate.receiver_sum_raw)?,
                    candidate.receiver_proofs_json,
                ],
            )
            .map_err(|e| format!("insert drain input: {e}"))?;
            tx.execute(
                "INSERT INTO monad_relay_drained_channels(channel_id, drain_id) VALUES (?1, ?2)",
                params![candidate.channel_id, drain_id],
            )
            .map_err(|e| format!("reserve drained channel {}: {e}", candidate.channel_id))?;
        }

        tx.commit()
            .map_err(|e| format!("commit drain transaction: {e}"))
    }

    fn mark_drain_submitted(&self, drain_id: &str, submitted_at: u64) -> Result<(), String> {
        let conn = Connection::open(&self.metadata.db_path)
            .map_err(|e| format!("open relay wallet db: {e}"))?;
        conn.execute(
            "UPDATE monad_relay_drains
             SET state = 'Submitted', submitted_at = ?2
             WHERE drain_id = ?1 AND state = 'Prepared'",
            params![drain_id, i64_from_u64(submitted_at)?],
        )
        .map_err(|e| format!("mark drain submitted: {e}"))?;
        Ok(())
    }

    fn update_prepared_drain_attempt(
        &self,
        drain_id: &str,
        output_amount_raw: u64,
        prepared: &PreparedDrainSwap,
        output_keyset_id: &str,
        output_keyset_info_json: &str,
        submitted_at: u64,
    ) -> Result<(), String> {
        let conn = Connection::open(&self.metadata.db_path)
            .map_err(|e| format!("open relay wallet db: {e}"))?;
        conn.execute(
            "UPDATE monad_relay_drains
             SET output_amount_raw = ?2,
                 swap_request_json = ?3,
                 restore_request_json = ?4,
                 output_secrets_json = ?5,
                 output_keyset_id = ?6,
                 output_keyset_info_json = ?7,
                 submitted_at = ?8,
                 error = NULL
             WHERE drain_id = ?1 AND state = 'Submitted'",
            params![
                drain_id,
                i64_from_u64(output_amount_raw)?,
                prepared.swap_request_json,
                prepared.restore_request_json,
                prepared.output_secrets_json,
                output_keyset_id,
                output_keyset_info_json,
                i64_from_u64(submitted_at)?,
            ],
        )
        .map_err(|e| format!("update drain retry attempt: {e}"))?;
        Ok(())
    }

    fn record_drain_error(&self, drain_id: &str, error: &str) -> Result<(), String> {
        let conn = Connection::open(&self.metadata.db_path)
            .map_err(|e| format!("open relay wallet db: {e}"))?;
        conn.execute(
            "UPDATE monad_relay_drains SET error = ?2 WHERE drain_id = ?1",
            params![drain_id, error],
        )
        .map_err(|e| format!("record drain error: {e}"))?;
        Ok(())
    }

    fn mark_drain_failed_and_release(
        &self,
        drain_id: &str,
        error: &str,
        failed_at: u64,
    ) -> Result<(), String> {
        let mut conn = Connection::open(&self.metadata.db_path)
            .map_err(|e| format!("open relay wallet db: {e}"))?;
        let tx = conn
            .transaction()
            .map_err(|e| format!("begin failed drain transaction: {e}"))?;
        tx.execute(
            "UPDATE monad_relay_drains
             SET state = 'Failed', error = ?2, failed_at = ?3
             WHERE drain_id = ?1 AND state IN ('Prepared', 'Submitted')",
            params![drain_id, error, i64_from_u64(failed_at)?],
        )
        .map_err(|e| format!("mark drain failed: {e}"))?;
        tx.execute(
            "DELETE FROM monad_relay_drained_channels WHERE drain_id = ?1",
            params![drain_id],
        )
        .map_err(|e| format!("release failed drain channels: {e}"))?;
        tx.commit()
            .map_err(|e| format!("commit failed drain transaction: {e}"))
    }

    fn mark_drain_completed(
        &self,
        drain_id: &str,
        output_proofs_json: &str,
        completed_at: u64,
    ) -> Result<(), String> {
        let conn = Connection::open(&self.metadata.db_path)
            .map_err(|e| format!("open relay wallet db: {e}"))?;
        conn.execute(
            "UPDATE monad_relay_drains
             SET state = 'Completed', output_proofs_json = ?2, completed_at = ?3, error = NULL
             WHERE drain_id = ?1 AND state IN ('Prepared', 'Submitted', 'Completed')",
            params![drain_id, output_proofs_json, i64_from_u64(completed_at)?],
        )
        .map_err(|e| format!("mark drain completed: {e}"))?;
        Ok(())
    }

    fn load_drain(&self, drain_id: &str) -> Result<StoredDrain, String> {
        let conn = Connection::open(&self.metadata.db_path)
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
        let conn = Connection::open(&self.metadata.db_path)
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
            if keyset.active {
                active_output_keysets.push((keyset_id.clone(), keyset.info_json.clone()));
            }
        }
        active_output_keysets.sort_by(|a, b| a.0.cmp(&b.0));
        let (output_keyset_id, output_keyset_info_json) = active_output_keysets
            .into_iter()
            .next()
            .ok_or_else(|| format!("mint {mint_url} has no active keyset for unit {unit}"))?;
        Ok(DrainKeysets {
            output_keyset: SelectedOutputKeyset {
                id: output_keyset_id.clone(),
                info_json: output_keyset_info_json.clone(),
            },
            output_keyset_id,
            output_keyset_info_json,
            input_fee_ppk_by_keyset,
        })
    }

    async fn ensure_drain_keysets_cached(&self, mint_url: &str, unit: &str) -> Result<(), String> {
        let has_cached_keysets = {
            let cache = self
                .keyset_cache
                .read()
                .expect("relay wallet keyset cache lock poisoned");
            cache
                .keysets
                .get(mint_url)
                .is_some_and(|by_id| by_id.values().any(|keyset| keyset.unit == unit))
        };
        if !has_cached_keysets {
            self.refresh_keysets_into_shared_cache(mint_url).await?;
        }
        Ok(())
    }

    async fn submit_drain_attempt<N: DrainSwapNetworking>(
        &self,
        net: &N,
        mint_url: &str,
        drain_id: &str,
        attempt: &PreparedDrainAttempt,
    ) -> Result<String, String> {
        match net
            .call_mint_swap(mint_url, &attempt.prepared.swap_request_json)
            .await
        {
            Ok(response) => Ok(response),
            Err(e) => {
                if is_explicit_drain_mint_rejection(&e) {
                    return Err(e);
                }
                let _ = self.record_drain_error(drain_id, &e);
                Err(format!(
                    "drain swap submitted for {drain_id}, but response was not completed: {e}"
                ))
            }
        }
    }

    async fn submit_drain_with_keyset_retry<N: DrainSwapNetworking>(
        &self,
        net: &N,
        request: DrainSubmitRequest<'_>,
    ) -> Result<DrainSubmitOutcome, String> {
        let prepared_once = std::cell::Cell::new(false);
        self.ensure_drain_keysets_cached(request.mint_url, request.unit)
            .await?;
        // Draining closed channels is another mint swap: receiver proofs from
        // already-closed channels are spent into fresh relay-owned output proofs.
        // The relay wallet manager keeps a shared in-memory cache containing all
        // keysets returned by each trusted mint (all units, active and inactive),
        // because drain preparation needs two kinds of keyset metadata:
        //
        // 1. the active output keyset info used to build the new drain outputs;
        // 2. input-fee metadata for every keyset represented by the closed
        //    receiver proofs being drained.
        //
        // Before entering the retry helper, ensure the shared cache has at least
        // one keyset for this mint/unit; helper selection is cache-only.  If the
        // cached active output keyset is stale, the mint may reject the drain
        // swap before consuming inputs.  The retry helper owns the common
        // recovery policy: submit once from cache, refresh the shared cache on a
        // retryable keyset rejection, reselect keysets, skip the retry if the
        // active output keyset id is unchanged, otherwise reprepare the same
        // drain row and submit one changed-keyset retry.
        let result = with_active_keyset_retry_async(
            // Select from the shared runtime cache.  The selection carries both
            // the active output keyset and the input-fee map needed by prepare.
            || self.drain_keysets_from_shared_cache(request.mint_url, request.unit),
            // First preparation inserts the durable drain row and reserves the
            // source closed channels in SQLite.  Retry preparation updates that
            // same row with a rebuilt swap for the newly selected output keyset;
            // channel reservations are not duplicated.
            |drain_keysets| {
                let attempt = self.prepare_drain_attempt_with_keysets(
                    drain_keysets,
                    request.all_input_proofs,
                    request.input_amount_raw,
                )?;
                if prepared_once.get() {
                    self.update_prepared_drain_attempt(
                        request.drain_id,
                        attempt.output_amount_raw,
                        &attempt.prepared,
                        &attempt.drain_keysets.output_keyset_id,
                        &attempt.drain_keysets.output_keyset_info_json,
                        now_seconds(),
                    )?;
                } else {
                    self.insert_prepared_drain(
                        request.drain_id,
                        request.relay_name,
                        request.mint_url,
                        request.unit,
                        request.input_amount_raw,
                        attempt.output_amount_raw,
                        &attempt.prepared,
                        &attempt.drain_keysets.output_keyset_id,
                        &attempt.drain_keysets.output_keyset_info_json,
                        request.candidates,
                        now_seconds(),
                    )?;
                    self.mark_drain_submitted(request.drain_id, now_seconds())?;
                    prepared_once.set(true);
                }
                Ok(attempt)
            },
            // Submit the currently prepared drain swap to the mint.
            |attempt| async move {
                self.submit_drain_attempt(net, request.mint_url, request.drain_id, &attempt)
                    .await
            },
            // Only retry explicit keyset-class mint rejections.  Ambiguous
            // submission failures stay in Submitted for restore/recovery.
            |error| is_retryable_keyset_mint_error(error),
            // Refresh this mint into SQLite plus the manager's shared runtime
            // cache before the helper reselects output/input keyset metadata.
            || async {
                self.refresh_keysets_into_shared_cache(request.mint_url)
                    .await
            },
            // Cleanup is a no-op here.  Drain reservations are durable DB state:
            // they are either completed, restored later, or released by the
            // final failure handler after the helper returns.
            |_attempt, _error| Ok(()),
        )
        .await;

        match result {
            Ok(success) => Ok(DrainSubmitOutcome {
                attempt: success.attempt,
                swap_response: success.value,
                did_retry: success.retried,
            }),
            Err(KeysetRetryError::Submit { error, .. }) => {
                self.fail_or_return_submitted_drain_error(request.drain_id, error)
            }
            Err(KeysetRetryError::RetryKeysetUnchanged {
                error, keyset_id, ..
            }) => self.fail_drain_after_retry_setup_error(
                request.drain_id,
                format!("retry keyset unchanged after refresh ({keyset_id}): {error}"),
            ),
            Err(error) => self.handle_drain_retry_setup_error(request.drain_id, error),
        }
    }

    fn handle_drain_retry_setup_error<T>(
        &self,
        drain_id: &str,
        error: KeysetRetryError<PreparedDrainAttempt, String, String>,
    ) -> Result<T, String> {
        match error {
            KeysetRetryError::Select { error } | KeysetRetryError::Prepare { error } => {
                if self.load_drain(drain_id).is_ok() {
                    self.fail_drain_after_retry_setup_error(
                        drain_id,
                        format!("prepare retry drain after keyset refresh: {error}"),
                    )
                } else {
                    Err(format!("prepare drain swap: {error}"))
                }
            }
            KeysetRetryError::Refresh { error } => self.fail_drain_after_retry_setup_error(
                drain_id,
                format!("refresh keysets after keyset rejection: {error}"),
            ),
            KeysetRetryError::Cleanup { error } => self.fail_drain_after_retry_setup_error(
                drain_id,
                format!("cleanup before retry drain after keyset rejection: {error}"),
            ),
            KeysetRetryError::Submit { .. } | KeysetRetryError::RetryKeysetUnchanged { .. } => {
                Err("unexpected drain submit error".to_string())
            }
        }
    }

    fn fail_drain_after_retry_setup_error<T>(
        &self,
        drain_id: &str,
        error: String,
    ) -> Result<T, String> {
        self.mark_drain_failed_and_release(drain_id, &error, now_seconds())?;
        Err(format!("drain swap failed for {drain_id}: {error}"))
    }

    fn fail_or_return_submitted_drain_error<T>(
        &self,
        drain_id: &str,
        error: String,
    ) -> Result<T, String> {
        if is_explicit_drain_mint_rejection(&error) {
            self.mark_drain_failed_and_release(drain_id, &error, now_seconds())?;
            return Err(format!("drain swap failed for {drain_id}: {error}"));
        }
        Err(error)
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

#[derive(Debug, Clone)]
struct DrainCandidate {
    channel_id: String,
    receiver_sum_raw: u64,
    receiver_proofs_json: String,
}

#[derive(Debug, Clone)]
struct DrainKeysets {
    output_keyset: SelectedOutputKeyset,
    output_keyset_id: String,
    output_keyset_info_json: String,
    input_fee_ppk_by_keyset: BTreeMap<String, u64>,
}

impl ActiveKeysetSelection for DrainKeysets {
    fn selected_output_keyset(&self) -> &SelectedOutputKeyset {
        &self.output_keyset
    }
}

#[derive(Debug, Clone)]
struct PreparedDrainSwap {
    swap_request_json: String,
    restore_request_json: String,
    output_secrets_json: String,
}

#[derive(Debug, Clone)]
struct PreparedDrainAttempt {
    drain_keysets: DrainKeysets,
    prepared: PreparedDrainSwap,
    output_amount_raw: u64,
}

#[derive(Debug, Clone)]
struct DrainSubmitOutcome {
    attempt: PreparedDrainAttempt,
    swap_response: String,
    did_retry: bool,
}

struct DrainSubmitRequest<'a> {
    relay_name: &'a str,
    mint_url: &'a str,
    unit: &'a str,
    drain_id: &'a str,
    candidates: &'a [DrainCandidate],
    all_input_proofs: &'a [Proof],
    input_amount_raw: u64,
}

#[derive(Debug, Clone)]
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

fn wrap_restore_response_as_swap_response(restore_response_json: &str) -> Result<String, String> {
    let restore: serde_json::Value = serde_json::from_str(restore_response_json)
        .map_err(|e| format!("parse restore response: {e}"))?;
    let signatures = restore
        .get("signatures")
        .cloned()
        .ok_or_else(|| "restore response missing signatures".to_string())?;
    serde_json::to_string(&serde_json::json!({ "signatures": signatures }))
        .map_err(|e| format!("serialize restored swap response: {e}"))
}

fn is_explicit_drain_mint_rejection(error: &str) -> bool {
    let Ok(value) = serde_json::from_str::<serde_json::Value>(error) else {
        return false;
    };
    value.is_object()
        && (value.get("code").is_some()
            || value.get("detail").is_some()
            || value.get("error").is_some())
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

#[cfg(test)]
mod close_networking_tests {
    use super::*;
    use cdk_spilman_test_mint::{build_router, rotate_sat_keyset, TestMintHelper};
    use std::sync::atomic::{AtomicUsize, Ordering};
    use tokio::net::TcpListener;

    struct RefreshSpy {
        refreshes: AtomicUsize,
    }

    #[async_trait::async_trait]
    impl SpilmanAsyncNetworking for RefreshSpy {
        async fn call_mint_swap(
            &self,
            _mint_url: &str,
            _swap_request_json: &str,
        ) -> Result<String, String> {
            Err("unused".to_string())
        }

        async fn refresh_all_keysets(&self, _mint: &str) -> Result<(), String> {
            self.refreshes.fetch_add(1, Ordering::SeqCst);
            Ok(())
        }
    }

    #[tokio::test]
    async fn close_networking_refresh_updates_manager_cache_and_delegates() {
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
        let inner = RefreshSpy {
            refreshes: AtomicUsize::new(0),
        };
        let wrapper = RelayWalletCloseNetworking {
            inner: &inner,
            wallet_manager: &manager,
        };

        wrapper.refresh_all_keysets(&mint_url).await.unwrap();
        assert_eq!(inner.refreshes.load(Ordering::SeqCst), 1);

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
        // object, so the wrapper must update the shared cache it reads from.
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

pub(crate) fn build_reqwest_networking(
    receiver_secret: &SecretKey,
    mint_url: &str,
    unit: &str,
) -> Result<ReqwestNetworking, String> {
    let mut mints = HashMap::new();
    mints.insert(mint_url.to_string(), vec![unit.to_string()]);
    let mut pricing = HashMap::new();
    pricing.insert(
        unit.to_string(),
        UnitPricingConfig {
            min_capacity: 0,
            max_amount_per_output: None,
            variables: HashMap::new(),
        },
    );
    let config = ConfigurableHostConfig {
        mints,
        min_expiry_seconds: 3600,
        pricing_scale: 1,
        storage: StorageConfig::Memory,
        pricing,
    };
    let host = ConfigurableHost::new(config, &receiver_secret.to_secret_hex())
        .map_err(|e| format!("create configurable host: {e}"))?;
    Ok(ReqwestNetworking::new(Arc::new(host)))
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

fn load_identities(db_path: &str) -> io::Result<HashMap<String, SecretKey>> {
    let conn = Connection::open(db_path)
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
    let conn = Connection::open(db_path)
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
    use cdk_spilman::{ChannelFunding, PaymentProof};

    fn temp_db_path() -> String {
        tempfile::NamedTempFile::new()
            .unwrap()
            .path()
            .to_str()
            .unwrap()
            .to_string()
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
        assert_eq!(channels[0].balance_raw, 250);

        let all_channels = manager.list_channels(None).unwrap();
        assert_eq!(all_channels.len(), 1);
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
