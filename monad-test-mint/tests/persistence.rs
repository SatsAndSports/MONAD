use cdk::nuts::CurrencyUnit;
use monad_common::config::{TestMintConfig, TestMintUnit, TestMintUnitConfig};
use monad_test_mint::{currency, ManagedMint};
use std::collections::BTreeMap;

fn config(path: &std::path::Path, name: &str) -> TestMintConfig {
    TestMintConfig {
        name: name.into(),
        listen: "127.0.0.1:0".into(),
        db_path: path.display().to_string(),
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
async fn unit_rotation_is_persistent_and_yaml_fees_are_initial_only() {
    let dir = tempfile::tempdir().unwrap();
    let mut config = config(&dir.path().join("mint.db"), "mint");
    let mint = ManagedMint::open(config.clone(), "http://127.0.0.1:3338")
        .await
        .unwrap();
    let before = mint.mint().get_active_keysets();
    assert_eq!(mint.mint().keysets().keysets.len(), 2);
    for (unit, fee) in [(TestMintUnit::Sat, 750), (TestMintUnit::Msat, 900)] {
        let other = if unit == TestMintUnit::Sat {
            TestMintUnit::Msat
        } else {
            TestMintUnit::Sat
        };
        let unchanged = mint.mint().get_active_keysets()[&currency(other)];
        let result = mint.rotate(unit, fee).await.unwrap();
        assert_ne!(result["active_keyset_id"], result["previous_keyset_id"]);
        assert_eq!(
            mint.mint().get_active_keysets()[&currency(other)],
            unchanged
        );
        let all = mint.mint().keysets().keysets;
        assert_eq!(
            all.iter()
                .filter(|k| k.unit == currency(unit) && k.active)
                .count(),
            1
        );
        let old = all
            .iter()
            .find(|k| k.id == before[&currency(unit)])
            .unwrap();
        assert!(!old.active);
        assert_eq!(old.input_fee_ppk, config.units[&unit].input_fee_ppk);
    }
    assert!(
        ManagedMint::open(config.clone(), "http://127.0.0.1:3338")
            .await
            .is_err(),
        "database must have exclusive ownership"
    );
    let after = serde_json::to_value(mint.mint().keysets()).unwrap();
    drop(mint);
    for fee in config.units.values_mut() {
        fee.input_fee_ppk = 999;
    }
    let restarted = ManagedMint::open(config, "http://127.0.0.1:3338")
        .await
        .unwrap();
    let actual = serde_json::to_value(restarted.mint().keysets()).unwrap();
    // Compare by ID: upstream snapshot ordering is not an API guarantee.
    let sorted = |value: serde_json::Value| -> BTreeMap<String, serde_json::Value> {
        value["keysets"]
            .as_array()
            .unwrap()
            .iter()
            .cloned()
            .map(|k| (k["id"].as_str().unwrap().to_owned(), k))
            .collect()
    };
    assert_eq!(sorted(actual), sorted(after));
}

#[tokio::test]
async fn mints_have_independent_keys_and_unrecognized_data_is_preserved() {
    let dir = tempfile::tempdir().unwrap();
    let first = ManagedMint::open(
        config(&dir.path().join("one.db"), "one"),
        "http://127.0.0.1:1",
    )
    .await
    .unwrap();
    let second = ManagedMint::open(
        config(&dir.path().join("two.db"), "two"),
        "http://127.0.0.1:2",
    )
    .await
    .unwrap();
    for unit in [TestMintUnit::Sat, TestMintUnit::Msat] {
        assert_ne!(
            first.mint().get_active_keysets()[&currency(unit)],
            second.mint().get_active_keysets()[&currency(unit)]
        );
    }
    let path = dir.path().join("existing.db");
    let db = rusqlite::Connection::open(&path).unwrap();
    db.execute_batch(
        "CREATE TABLE important(value TEXT); INSERT INTO important VALUES ('keep me')",
    )
    .unwrap();
    assert!(
        ManagedMint::open(config(&path, "unexpected"), "http://127.0.0.1:3")
            .await
            .is_err()
    );
    assert_eq!(
        db.query_row("SELECT value FROM important", [], |r| r.get::<_, String>(0))
            .unwrap(),
        "keep me"
    );
}

#[tokio::test]
async fn unit_set_changes_are_explicit_and_rotation_rejects_unsupported_units() {
    let dir = tempfile::tempdir().unwrap();
    let mut config = config(&dir.path().join("mint.db"), "mint");
    config.units.remove(&TestMintUnit::Msat);
    let mint = ManagedMint::open(config.clone(), "http://127.0.0.1:3338")
        .await
        .unwrap();
    assert!(mint.rotate(TestMintUnit::Msat, 0).await.is_err());
    assert!(mint.rotate(TestMintUnit::Sat, u64::MAX).await.is_err());
    assert!(mint.rotate(TestMintUnit::Sat, 1000).await.is_err());
    assert_eq!(mint.mint().keysets().keysets.len(), 1);
    drop(mint);
    config
        .units
        .insert(TestMintUnit::Msat, TestMintUnitConfig { input_fee_ppk: 0 });
    assert!(ManagedMint::open(config, "http://127.0.0.1:3338")
        .await
        .is_err());
}

#[tokio::test]
async fn concurrent_rotations_report_a_single_ordered_keyset_chain() {
    let dir = tempfile::tempdir().unwrap();
    let mint = ManagedMint::open(
        config(&dir.path().join("mint.db"), "mint"),
        "http://127.0.0.1:3338",
    )
    .await
    .unwrap();
    let before = mint.mint().get_active_keysets()[&CurrencyUnit::Sat].to_string();
    let (a, b) = tokio::join!(
        mint.rotate(TestMintUnit::Sat, 0),
        mint.rotate(TestMintUnit::Sat, 999)
    );
    let a = a.unwrap();
    let b = b.unwrap();
    let (first, last) = if a["previous_keyset_id"] == before {
        (a, b)
    } else {
        (b, a)
    };
    assert_eq!(first["previous_keyset_id"], before);
    assert_eq!(last["previous_keyset_id"], first["active_keyset_id"]);
    assert_eq!(
        mint.mint().get_active_keysets()[&CurrencyUnit::Sat].to_string(),
        last["active_keyset_id"]
    );
    assert_eq!(mint.mint().keysets().keysets.len(), 4);
}
