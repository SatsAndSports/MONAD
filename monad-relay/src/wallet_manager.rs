use crate::channel_store::ChannelStore;
use crate::listener::SpilmanMintCache;
use crate::payments::{RelayPayments, SpilmanRelayPayments};
use cashu::nuts::SecretKey;
use cdk_spilman::configurable_host::SpilmanStorage;
use cdk_spilman::configurable_host::SqliteStorage;
use rusqlite::{params, Connection, OptionalExtension};
use std::collections::HashMap;
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
}

#[derive(Clone)]
pub struct RelayWalletManager {
    storage: Arc<dyn SpilmanStorage>,
    metadata: Arc<ChannelMetadataStore>,
    identities: Arc<Mutex<HashMap<String, SecretKey>>>,
    payments: Arc<Mutex<HashMap<String, Arc<SpilmanRelayPayments>>>>,
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
            payments: Arc::new(Mutex::new(HashMap::new())),
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
        if let Some(existing) = self
            .payments
            .lock()
            .map_err(|_| io::Error::other("relay wallet payments mutex poisoned"))?
            .get(relay_name)
            .cloned()
        {
            return Ok(existing);
        }

        let receiver_secret = self.receiver_secret(relay_name)?;
        let receiver_pubkey_hex = receiver_secret.public_key().to_hex();
        let store = ChannelStore::with_relay_metadata(
            self.storage.clone(),
            self.metadata.clone(),
            relay_name.to_string(),
            receiver_pubkey_hex,
        );
        let payments = Arc::new(SpilmanRelayPayments::from_store(
            receiver_secret,
            mint_cache,
            store,
        ));
        self.payments
            .lock()
            .map_err(|_| io::Error::other("relay wallet payments mutex poisoned"))?
            .insert(relay_name.to_string(), payments.clone());
        Ok(payments)
    }

    pub fn relay_name_for_channel(&self, channel_id: &str) -> io::Result<Option<String>> {
        self.metadata.relay_name_for_channel(channel_id)
    }
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
