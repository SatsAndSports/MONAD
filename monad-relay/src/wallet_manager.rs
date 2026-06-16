use crate::channel_store::ChannelStore;
use crate::listener::{discover_spilman_mint_cache, SpilmanMintCache};
use crate::payments::{RelayPayments, SpilmanRelayPayments};
use cashu::nuts::SecretKey;
use cdk_spilman::configurable_host::{
    ConfigurableHost, ConfigurableHostConfig, SpilmanStorage, SqliteStorage, StorageConfig,
    UnitPricingConfig,
};
use cdk_spilman::configurable_networking::ReqwestNetworking;
use cdk_spilman::{ChannelState, CloseError, CloseSuccess, SpilmanAsyncNetworking};
use rusqlite::{params, Connection, OptionalExtension};
use std::collections::{BTreeSet, HashMap};
use std::io;
use std::sync::{Arc, Mutex};

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
        drop(conn);

        let storage = Arc::new(
            SqliteStorage::open(&db_path)
                .map_err(|e| io::Error::other(format!("open relay wallet storage: {e}")))?,
        );
        let metadata = Arc::new(ChannelMetadataStore::new(db_path.clone())?);
        let identities = Arc::new(Mutex::new(load_identities(&db_path)?));

        Ok(Self {
            storage,
            metadata,
            identities,
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

    pub fn payments_for(
        &self,
        relay_name: &str,
        mint_cache: SpilmanMintCache,
    ) -> io::Result<Arc<dyn RelayPayments>> {
        Ok(self.spilman_payments_for(relay_name, mint_cache)? as Arc<dyn RelayPayments>)
    }

    pub fn spilman_payments_for(
        &self,
        relay_name: &str,
        mint_cache: SpilmanMintCache,
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
            mint_cache,
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

    /// Close any channel stored in this wallet DB, regardless of which relay
    /// identity owns it.  If the channel is already `Closed`, returns a
    /// synthetic success.  If it is `Closing`, completes the close.  Otherwise
    /// initiates and executes a unilateral close against the channel's mint.
    pub async fn close_channel<N: SpilmanAsyncNetworking>(
        &self,
        channel_id: &str,
        net: &N,
    ) -> Result<CloseSuccess, CloseError> {
        let payments = self.payments_for_channel(channel_id).await?;
        payments
            .close_channel_any_state_async(channel_id, net)
            .await
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
        let (_receiver_secret, mint_url, unit) =
            self.channel_owner_and_mint(channel_id)
                .map_err(|e| CloseError::StorageFailed {
                    reason: e,
                    status: 500,
                })?;

        let mut trusted_mint_units = std::collections::BTreeMap::new();
        let mut units = BTreeSet::new();
        units.insert(unit);
        trusted_mint_units.insert(mint_url, units);
        let mint_cache = discover_spilman_mint_cache(&trusted_mint_units)
            .await
            .map_err(|e| CloseError::StorageFailed {
                reason: format!("discover keysets: {e}"),
                status: 500,
            })?;

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

        self.spilman_payments_for(&relay_name, mint_cache)
            .map_err(|e| CloseError::StorageFailed {
                reason: format!("build payments for relay '{relay_name}': {e}"),
                status: 500,
            })
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
