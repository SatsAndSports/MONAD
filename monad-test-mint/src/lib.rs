//! Persistent, fake-Lightning CDK mints for MONAD demos. Not a real-funds mint.
use anyhow::{bail, Context, Result};
use cdk::{
    mint::{Mint, MintBuilder, MintMeltLimits, UnitConfig},
    nuts::{CurrencyUnit, Id, PaymentMethod},
    types::FeeReserve,
};
use cdk_common::{database::MintKeysDatabase, nut00::KnownMethod};
use monad_common::{
    config::{MonadConfig, TestMintConfig, TestMintUnit, TestMintUnitConfig},
    wallet_lock::{WalletLockMode, WalletLocks},
};
use monad_management::{events::EventLog, Backend, Command};
use serde::Deserialize;
use serde_json::{json, Value};
use std::{collections::BTreeMap, path::Path, sync::Arc};
use tokio::{
    net::TcpListener,
    sync::{oneshot, watch, Mutex},
    task::JoinSet,
};

mod storage;

pub fn currency(unit: TestMintUnit) -> CurrencyUnit {
    match unit {
        TestMintUnit::Sat => CurrencyUnit::Sat,
        TestMintUnit::Msat => CurrencyUnit::Msat,
    }
}

pub struct ManagedMint {
    config: TestMintConfig,
    base_url: String,
    mint: Arc<Mint>,
    rotation: Mutex<()>,
    events: EventLog,
    _locks: WalletLocks,
}

impl ManagedMint {
    /// Build without starting background workers. The process owner starts and
    /// stops them explicitly; callers must hold this owner while the mint is used.
    pub async fn open(config: TestMintConfig, base_url: &str) -> Result<Arc<Self>> {
        config.validate()?;
        let locks = WalletLocks::acquire(
            [Path::new(&config.db_path)],
            WalletLockMode::Runtime,
            "test-mint",
        )?;
        let manifest = storage::open_manifest(&config)?;
        let db = Arc::new(
            cdk_sqlite::mint::MintSqliteDatabase::new(std::path::PathBuf::from(&config.db_path))
                .await?,
        );
        let mut tx = MintKeysDatabase::begin_transaction(db.as_ref()).await?;
        let active = tx.get_active_keysets().await?;
        let keysets = tx.get_keyset_infos().await?;
        tx.commit().await?;
        if keysets
            .iter()
            .any(|k| !config.units.keys().any(|u| currency(*u) == k.unit))
        {
            bail!("persisted mint has an unexpected unit; database preserved");
        }
        let mut builder = MintBuilder::new(db.clone())
            .with_name(config.name.clone())
            .with_description("MONAD demo test mint: fake Lightning payments, no real value".into())
            .with_urls(vec![base_url.to_owned()])
            .with_keyset_v2(Some(true));
        for (unit, initial) in &manifest.initial_units {
            let unit = currency(*unit);
            let stored = match active.get(&unit) {
                Some(id) => Some(
                    keysets
                        .iter()
                        .find(|k| &k.id == id && k.unit == unit)
                        .context("active keyset metadata is missing")?,
                ),
                None if keysets.iter().any(|k| k.unit == unit) => {
                    bail!("persisted unit has no active keyset; refusing implicit repair")
                }
                None => None,
            };
            if let Some(stored) = stored {
                if stored.id.get_version() != cdk::nuts::nut02::KeySetVersion::Version01 {
                    bail!("persisted active keyset is not v2; refusing automatic format rotation");
                }
                TestMintUnitConfig {
                    input_fee_ppk: stored.input_fee_ppk,
                }
                .validate()?;
                if keysets
                    .iter()
                    .filter(|k| k.unit == unit)
                    .max_by_key(|k| k.derivation_path_index)
                    .is_some_and(|k| k.id != stored.id)
                {
                    bail!(
                        "persisted active keyset is not the latest; refusing CDK boot reactivation"
                    );
                }
            }
            // CDK auto-rotates when builder fees/amounts differ. Existing active
            // metadata, not current YAML, must therefore drive restart settings.
            let fee = stored
                .map(|k| k.input_fee_ppk)
                .unwrap_or(initial.input_fee_ppk);
            let amounts = stored
                .map(|k| k.amounts.clone())
                .unwrap_or_else(|| (0..32).map(|i| 1u64 << i).collect());
            builder.configure_unit(
                unit.clone(),
                UnitConfig {
                    amounts,
                    input_fee_ppk: fee,
                },
            )?;
            let fake = cdk_fake_wallet::FakeWallet::new(
                FeeReserve {
                    min_fee_reserve: 0.into(),
                    percent_fee_reserve: 0.0,
                },
                Default::default(),
                Default::default(),
                1,
                unit.clone(),
            );
            builder
                .add_payment_processor(
                    unit,
                    PaymentMethod::Known(KnownMethod::Bolt11),
                    MintMeltLimits {
                        mint_min: 1.into(),
                        mint_max: 1_000_000_000u64.into(),
                        melt_min: 1.into(),
                        melt_max: 1_000_000_000u64.into(),
                    },
                    Arc::new(fake),
                )
                .await?;
        }
        let mint = Arc::new(builder.build_with_seed(db, &manifest.seed).await?);
        let current = mint.get_active_keysets();
        for unit in config.units.keys() {
            let unit = currency(*unit);
            if !current.contains_key(&unit) {
                bail!("mint initialization left a unit without an active keyset");
            }
            if let Some(old) = active.get(&unit) {
                if current.get(&unit) != Some(old) {
                    bail!("CDK unexpectedly changed an active keyset on restart");
                }
            }
        }
        Ok(Arc::new(Self {
            config,
            base_url: base_url.to_owned(),
            mint,
            rotation: Mutex::new(()),
            events: Default::default(),
            _locks: locks,
        }))
    }

    pub fn mint(&self) -> Arc<Mint> {
        self.mint.clone()
    }

    pub fn snapshot(&self) -> Value {
        json!({"name": self.config.name, "base_url": self.base_url, "test_only": true, "keysets": self.mint.keysets().keysets, "events": self.events.snapshot()})
    }

    pub async fn rotate(&self, unit: TestMintUnit, input_fee_ppk: u64) -> Result<Value> {
        TestMintUnitConfig { input_fee_ppk }.validate()?;
        if !self.config.units.contains_key(&unit) {
            bail!("unit is not configured on this mint");
        }
        let _guard = self.rotation.lock().await;
        let currency = currency(unit);
        let previous: Id = *self
            .mint
            .get_active_keysets()
            .get(&currency)
            .context("unit has no active keyset")?;
        let keys = self.mint.keyset_pubkeys(&previous)?;
        let amounts = keys
            .keysets
            .first()
            .context("missing public keyset")?
            .keys
            .iter()
            .map(|(amount, _)| amount.to_u64())
            .collect();
        let new = self
            .mint
            .rotate_keyset(currency, amounts, input_fee_ppk, true, None)
            .await?;
        let result = json!({"unit": unit, "previous_keyset_id": previous.to_string(), "active_keyset_id": new.id.to_string(), "input_fee_ppk": input_fee_ppk});
        self.events.record("keyset_rotated", result.clone());
        Ok(result)
    }
}

pub struct MintBackend {
    mints: BTreeMap<String, Arc<ManagedMint>>,
}
impl MintBackend {
    pub fn new(mints: impl IntoIterator<Item = Arc<ManagedMint>>) -> Self {
        Self {
            mints: mints
                .into_iter()
                .map(|mint| (mint.config.name.clone(), mint))
                .collect(),
        }
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Rotation {
    unit: TestMintUnit,
    input_fee_ppk: u64,
}

#[async_trait::async_trait]
impl Backend for MintBackend {
    async fn snapshot(&self) -> Result<Value, String> {
        let instances: BTreeMap<_, _> = self
            .mints
            .iter()
            .map(|(name, mint)| (name, mint.snapshot()))
            .collect();
        Ok(json!({"kind": "test_mints", "instances": instances}))
    }
    async fn execute(&self, command: &Command) -> Result<Value, String> {
        let mint = self
            .mints
            .get(&command.instance)
            .ok_or("unknown test mint")?;
        if command.action != "rotate_keyset" {
            return Err("unknown test mint action".into());
        }
        let rotation: Rotation = serde_json::from_value(command.arguments.clone())
            .map_err(|_| "rotation requires unit (sat/msat) and unsigned input_fee_ppk")?;
        TestMintUnitConfig {
            input_fee_ppk: rotation.input_fee_ppk,
        }
        .validate()
        .map_err(|e| e.to_string())?;
        if !mint.config.units.contains_key(&rotation.unit) {
            return Err("unit is not configured on this mint".into());
        }
        mint.rotate(rotation.unit, rotation.input_fee_ppk)
            .await
            .map_err(|_| {
                "keyset rotation failed; inspect the mint snapshot before issuing a new command"
                    .into()
            })
    }
}

/// Cancellation of the caller signals an owning supervisor. That supervisor is
/// not aborted: it awaits HTTP children and CDK shutdown while retaining DB locks.
pub async fn run(
    config: MonadConfig,
    selected: Option<&str>,
    shutdown: impl std::future::Future<Output = ()> + Send,
) -> Result<()> {
    config.validate()?;
    let mints: Vec<_> = config
        .test_mints
        .into_iter()
        .filter(|m| selected.is_none_or(|name| name == m.name))
        .collect();
    if mints.is_empty() {
        bail!("no matching test mints configured");
    }
    let socket = config.management.and_then(|m| m.test_mint_socket);
    let (cancel, cancelled) = oneshot::channel::<()>();
    let mut task = tokio::spawn(run_owned(mints, socket, cancelled));
    tokio::select! {
        result = &mut task => result.context("test mint owner task failed")?,
        () = shutdown => { drop(cancel); task.await.context("test mint owner task failed")? }
    }
}

async fn run_owned(
    configs: Vec<TestMintConfig>,
    socket: Option<String>,
    mut cancelled: oneshot::Receiver<()>,
) -> Result<()> {
    let mut prepared = Vec::new();
    for config in configs {
        if !matches!(
            cancelled.try_recv(),
            Err(oneshot::error::TryRecvError::Empty)
        ) {
            return Ok(());
        }
        let listener = TcpListener::bind(&config.listen)
            .await
            .context("bind test mint HTTP listener")?;
        let address = listener.local_addr()?;
        let mint = ManagedMint::open(config, &format!("http://{address}")).await?;
        let router =
            cdk_axum::create_mint_router(mint.mint(), vec![KnownMethod::Bolt11.to_string()])
                .await?;
        prepared.push((mint, listener, router));
    }
    let mints: Vec<_> = prepared.iter().map(|(mint, ..)| mint.clone()).collect();
    let (stop, stopped) = watch::channel(false);
    let mut servers = JoinSet::new();
    let mut result = async {
        for (mint, listener, router) in prepared {
            if !matches!(cancelled.try_recv(), Err(oneshot::error::TryRecvError::Empty)) { return Ok(()); }
            mint.mint.start().await?;
            tracing::info!(mint = %mint.config.name, address = %listener.local_addr()?, "test mint started (fake Lightning)");
            let stopped = stopped.clone();
            servers.spawn(async move { monad_management::serve_owned(listener, router, stopped_signal(stopped)).await });
        }
        if let Some(socket) = socket {
            let backend = Arc::new(MintBackend::new(mints.clone()));
            let stopped = stopped.clone();
            servers.spawn(monad_management::serve_unix(socket.into(), backend, stopped_signal(stopped)));
        }
        tokio::select! {
            _ = &mut cancelled => Ok(()),
            result = servers.join_next() => match result {
                Some(Ok(Err(error))) => Err(error.into()),
                Some(Err(error)) => Err(error.into()),
                _ => Err(anyhow::anyhow!("test mint HTTP service stopped unexpectedly")),
            }
        }
    }.await;
    stop.send_replace(true);
    while let Some(joined) = servers.join_next().await {
        let error = match joined {
            Ok(Ok(())) => None,
            Ok(Err(error)) => Some(anyhow::Error::from(error)),
            Err(error) => Some(anyhow::Error::from(error)),
        };
        if let Some(error) = error {
            tracing::error!(%error, "test mint HTTP task failed during shutdown");
            if result.is_ok() {
                result = Err(error);
            }
        }
    }
    let mut stop_error = None;
    for mint in &mints {
        if let Err(error) = mint.mint.stop().await {
            stop_error = Some(anyhow::anyhow!("CDK test mint shutdown failed: {error}"));
        }
    }
    result.and(stop_error.map_or(Ok(()), Err))
}

async fn stopped_signal(mut stopped: watch::Receiver<bool>) {
    while !*stopped.borrow() {
        if stopped.changed().await.is_err() {
            break;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn config(path: &Path) -> TestMintConfig {
        TestMintConfig {
            name: "partial".into(),
            db_path: path.display().to_string(),
            listen: "127.0.0.1:0".into(),
            units: BTreeMap::from([
                (TestMintUnit::Sat, TestMintUnitConfig { input_fee_ppk: 400 }),
                (
                    TestMintUnit::Msat,
                    TestMintUnitConfig { input_fee_ppk: 700 },
                ),
            ]),
        }
    }
    #[tokio::test]
    async fn partial_initialization_retains_original_manifest_fees() {
        let dir = tempfile::tempdir().unwrap();
        let mut config = config(&dir.path().join("mint.db"));
        storage::open_manifest(&config).unwrap();
        for unit in config.units.values_mut() {
            unit.input_fee_ppk = 999;
        }
        let mint = ManagedMint::open(config, "http://127.0.0.1:3338")
            .await
            .unwrap();
        for keyset in mint.mint.keysets().keysets {
            assert_eq!(
                keyset.input_fee_ppk,
                if keyset.unit == CurrencyUnit::Sat {
                    400
                } else {
                    700
                }
            );
        }
    }
    #[tokio::test]
    async fn cancellation_before_start_does_not_initialize_databases() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("mint.db");
        let (cancel, cancelled) = oneshot::channel();
        drop(cancel);
        run_owned(vec![config(&path)], None, cancelled)
            .await
            .unwrap();
        assert!(!path.exists());
    }
}
