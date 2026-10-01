use monad_relay::wallet_manager::RelayWalletManager;
use std::process::Command;

#[test]
fn wallet_json_stdout_remains_parseable_with_info_logging() {
    let dir = tempfile::tempdir().unwrap();
    let db_path = dir.path().join("relay.db");
    drop(RelayWalletManager::open(db_path.to_str().unwrap()).unwrap());

    let output = Command::new(env!("CARGO_BIN_EXE_monad-relay"))
        .arg("wallet")
        .arg("--wallet-db-path")
        .arg(&db_path)
        .args(["--json", "list"])
        .env("RUST_LOG", "info")
        .output()
        .unwrap();

    assert!(output.status.success(), "{output:?}");
    assert_eq!(
        serde_json::from_slice::<serde_json::Value>(&output.stdout).unwrap(),
        serde_json::json!([])
    );
    let stderr = String::from_utf8(output.stderr).unwrap();
    assert!(stderr.contains("running relay wallet command"), "{stderr}");
    assert!(!String::from_utf8(output.stdout)
        .unwrap()
        .contains("running relay wallet command"));
}
