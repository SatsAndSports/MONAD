use monad_client::wallet_lock::{ClientWalletLocks, WalletLockMode};
use std::path::Path;
use std::process::{Command, Output};

fn maintenance(loose: &Path, channel: &Path, command: &str) -> Output {
    Command::new(env!("CARGO_BIN_EXE_monad-client"))
        .arg("wallet")
        .arg("--loose-db")
        .arg(loose)
        .arg("--channel-db")
        .arg(channel)
        .args(["--sender-secret-hex", &"01".repeat(32), "--json", command])
        .env("RUST_LOG", "off")
        .output()
        .unwrap()
}

#[test]
fn opening_maintenance_cli_excludes_runtime_before_database_work() {
    for initialized in [false, true] {
        let dir = tempfile::tempdir().unwrap();
        let loose = dir.path().join("loose.db");
        let channel = dir.path().join("channel.db");
        if initialized {
            let output = maintenance(&loose, &channel, "recover-openings");
            assert!(output.status.success(), "{output:?}");
        }
        let before_loose = std::fs::read(&loose).ok();
        let before_channel = std::fs::read(&channel).ok();
        let mut runtime =
            ClientWalletLocks::acquire(&loose, &channel, WalletLockMode::Runtime).unwrap();
        assert!(runtime.holds_runtime_owner());

        // Startup holds exclusive maintenance access; steady state holds shared access.
        for steady_state in [false, true] {
            if steady_state {
                runtime.enter_steady_state().unwrap();
            }
            for command in ["recover-openings", "export-stale-opening-inputs"] {
                let output = maintenance(&loose, &channel, command);
                assert!(!output.status.success(), "{command}: {output:?}");
                assert!(output.stdout.is_empty(), "{command}: {output:?}");
                let error = String::from_utf8(output.stderr).unwrap();
                assert!(
                    error.contains("client wallet Maintenance lock unavailable"),
                    "{command}: {error}"
                );
                assert_eq!(std::fs::read(&loose).ok(), before_loose);
                assert_eq!(std::fs::read(&channel).ok(), before_channel);
            }
        }
        drop(runtime);

        // Positive controls ensure the same CLI invocations are otherwise valid.
        for (command, expected) in [
            (
                "recover-openings",
                serde_json::json!({
                    "recovered_channel_ids": [], "cancelled_attempt_ids": [],
                    "externally_spent_attempt_ids": [], "unresolved": []
                }),
            ),
            (
                "export-stale-opening-inputs",
                serde_json::json!({"exports": [], "unresolved": []}),
            ),
        ] {
            let output = maintenance(&loose, &channel, command);
            assert!(output.status.success(), "{command}: {output:?}");
            assert_eq!(
                serde_json::from_slice::<serde_json::Value>(&output.stdout).unwrap(),
                expected
            );
        }
    }
}
