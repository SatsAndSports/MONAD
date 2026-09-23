use monad_client::config_runtime::route_from_client_config;
use monad_common::blinded_hop::{resolve_blinded_hop_for_intro, PathNode};
use monad_common::config::ClientConfig;
use monad_common::secp_identity::SecpTransportKeypair;
use std::process::Command;

#[test]
fn offline_cli_emits_usable_yaml_and_preserves_real_predecessors() {
    let keys: Vec<_> = (7..=9)
        .map(|seed| SecpTransportKeypair::from_secret_bytes(&[seed; 32]).unwrap())
        .collect();
    let inputs = [
        format!("{}::localhost", keys[0].pubkey()),
        format!("{}::[::1]:9051", keys[1].pubkey()),
        format!("{}::127.0.0.1:9052", keys[2].pubkey()),
    ];
    let output = Command::new(env!("CARGO_BIN_EXE_monad-client"))
        .arg("blind-route")
        .args(&inputs)
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(output.stderr.is_empty());
    let yaml = String::from_utf8(output.stdout).unwrap();
    assert!(!yaml.contains("127.0.0.1"));
    assert!(!yaml.contains("[::1]"));
    let client: ClientConfig =
        serde_yaml::from_str(&format!("name: test\nsocks: 127.0.0.1:1080\n{yaml}")).unwrap();
    let route = route_from_client_config(&client).unwrap();
    assert_eq!(route.hops().len(), 3);
    assert!(route.hops().iter().all(|hop| hop.requires_quic()));
    assert_eq!(route.hops()[0].cleartext_addr(), Some("localhost:9050"));
    for i in 1..3 {
        let PathNode::Blinded(descriptor) = &client.route[i] else {
            panic!("expected blinded suffix")
        };
        let resolved = resolve_blinded_hop_for_intro(&keys[i - 1], descriptor).unwrap();
        assert_eq!(resolved.next_hop_real_pubkey, keys[i].pubkey());
        assert_eq!(
            resolved.next_hop_addr,
            inputs[i].split_once("::").unwrap().1
        );
    }
    let bad = Command::new(env!("CARGO_BIN_EXE_monad-client"))
        .args([
            "blind-route",
            &inputs[0],
            &client.route[1].to_compact_string().unwrap(),
        ])
        .output()
        .unwrap();
    assert!(!bad.status.success());
    assert!(bad.stdout.is_empty());
    assert!(String::from_utf8_lossy(&bad.stderr).contains("route hop 2"));
    let bad = Command::new(env!("CARGO_BIN_EXE_monad-client"))
        .args(["blind-route", &inputs[0]])
        .output()
        .unwrap();
    assert!(!bad.status.success());
}
