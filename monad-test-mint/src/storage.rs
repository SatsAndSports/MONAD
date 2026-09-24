use anyhow::{bail, Context, Result};
use monad_common::config::{TestMintConfig, TestMintUnit, TestMintUnitConfig};
use rusqlite::{params, Connection, OptionalExtension, TransactionBehavior};
use std::collections::BTreeMap;

// Deliberately not Debug/Serialize: the seed must never reach monitoring/logs.
pub(crate) struct Manifest {
    pub seed: Vec<u8>,
    pub initial_units: BTreeMap<TestMintUnit, TestMintUnitConfig>,
}

pub(crate) fn open_manifest(config: &TestMintConfig) -> Result<Manifest> {
    let mut conn = Connection::open(&config.db_path).context("open test mint database")?;
    conn.busy_timeout(std::time::Duration::from_secs(5))?;
    let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
    let exists: bool = tx.query_row(
        "SELECT EXISTS(SELECT 1 FROM sqlite_schema WHERE type='table' AND name='monad_test_mint')",
        [],
        |r| r.get(0),
    )?;
    let manifest = if exists {
        let row: Option<(i64, String, Vec<u8>, String)> = tx
            .query_row(
                "SELECT version, name, seed, initial_units FROM monad_test_mint WHERE id=1",
                [],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)),
            )
            .optional()?;
        let (version, name, seed, initial_units) = row.context("test mint manifest is missing")?;
        if version != 1 || seed.len() != 64 {
            bail!("unsupported or invalid test mint manifest; database preserved");
        }
        if name != config.name {
            bail!("database belongs to a different test mint name");
        }
        let initial_units: BTreeMap<TestMintUnit, TestMintUnitConfig> =
            serde_json::from_str(&initial_units)?;
        if !initial_units.keys().eq(config.units.keys()) {
            bail!("configured units differ from persisted test mint units; use a separate database for a different unit set");
        }
        for unit in initial_units.values() {
            unit.validate()?;
        }
        Manifest {
            seed,
            initial_units,
        }
    } else {
        let tables: i64 = tx.query_row(
            "SELECT COUNT(*) FROM sqlite_schema WHERE name NOT LIKE 'sqlite_%'",
            [],
            |r| r.get(0),
        )?;
        if tables != 0 {
            bail!("refusing to initialize an unrecognized nonempty database; database preserved");
        }
        let seed = rand::random::<[u8; 64]>().to_vec();
        tx.execute_batch("CREATE TABLE monad_test_mint (id INTEGER PRIMARY KEY CHECK(id=1), version INTEGER NOT NULL, name TEXT NOT NULL, seed BLOB NOT NULL, initial_units TEXT NOT NULL)")?;
        tx.execute(
            "INSERT INTO monad_test_mint VALUES (1, 1, ?1, ?2, ?3)",
            params![config.name, seed, serde_json::to_string(&config.units)?],
        )?;
        Manifest {
            seed,
            initial_units: config.units.clone(),
        }
    };
    tx.commit()?;
    Ok(manifest)
}
