use monad_common::protocol::ServerMessage;
use monad_test_client::{Circuit, CircuitConfig, RebuildAfterFailureOutcome, TestRelayHandle};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio::sync::mpsc;
use tokio::time::sleep;
use tokio::time::timeout;
use tokio::time::Duration;

async fn run_echo_server(listener: TcpListener) {
    loop {
        let Ok((mut stream, _)) = listener.accept().await else {
            return;
        };
        tokio::spawn(async move {
            let mut buf = [0u8; 4096];
            loop {
                match stream.read(&mut buf).await {
                    Ok(0) => return,
                    Ok(n) => {
                        if stream.write_all(&buf[..n]).await.is_err() {
                            return;
                        }
                    }
                    Err(_) => return,
                }
            }
        });
    }
}

async fn assert_tunnel_works(circuit: &Circuit, target: &str, payload: &[u8]) {
    let final_conn = circuit.final_conn().expect("final connection available");
    let mut tunnel = final_conn.open_tunnel(target).await.expect("open tunnel");
    tunnel.write_all(payload).await.expect("write payload");
    tunnel.shutdown().await.expect("shutdown write side");
    let mut out = vec![0u8; payload.len()];
    tunnel
        .read_exact(&mut out)
        .await
        .expect("read echoed payload");
    assert_eq!(out, payload);
}

async fn build_three_hop_circuit() -> (
    Circuit,
    mpsc::UnboundedReceiver<monad_test_client::HopFailure>,
    Vec<TestRelayHandle>,
    String,
    Vec<Option<[u8; 32]>>,
) {
    let relays = vec![
        TestRelayHandle::start_ephemeral().await.unwrap(),
        TestRelayHandle::start_ephemeral().await.unwrap(),
        TestRelayHandle::start_ephemeral().await.unwrap(),
    ];
    let specs = relays
        .iter()
        .map(|relay| relay.spec.clone())
        .collect::<Vec<_>>();
    let (mut circuit, failure_rx) = Circuit::new(
        specs,
        CircuitConfig {
            status_interval: Some(Duration::from_millis(100)),
            status_timeout: Duration::from_millis(400),
            ..CircuitConfig::default()
        },
    )
    .unwrap();
    circuit.build_full().await.unwrap();

    let initial_ids = circuit.session_ids();
    assert!(initial_ids.iter().all(Option::is_some));

    let target_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let target_addr = target_listener.local_addr().unwrap().to_string();
    tokio::spawn(run_echo_server(target_listener));
    assert_tunnel_works(&circuit, &target_addr, b"before-rebuild").await;

    (circuit, failure_rx, relays, target_addr, initial_ids)
}

async fn expect_failure(
    failure_rx: &mut mpsc::UnboundedReceiver<monad_test_client::HopFailure>,
) -> monad_test_client::HopFailure {
    timeout(Duration::from_secs(5), failure_rx.recv())
        .await
        .expect("failure should arrive before timeout")
        .expect("failure channel should stay open")
}

async fn assert_suffix_rebuild(
    failed_hop_idx: usize,
    rebuild_from: usize,
    unchanged_prefix_len: usize,
) {
    let (mut circuit, _failure_rx, relays, target_addr, initial_ids) =
        build_three_hop_circuit().await;

    let killed_session_id = initial_ids[failed_hop_idx].expect("session id for failed hop");
    assert!(relays[failed_hop_idx].terminate_session(&killed_session_id));

    circuit.rebuild_from(rebuild_from).await.unwrap();

    let rebuilt_ids = circuit.session_ids();
    for idx in 0..unchanged_prefix_len {
        assert_eq!(
            rebuilt_ids[idx], initial_ids[idx],
            "hop {idx} should be preserved"
        );
    }
    for idx in rebuild_from..rebuilt_ids.len() {
        assert_ne!(
            rebuilt_ids[idx], initial_ids[idx],
            "hop {idx} should be rebuilt"
        );
    }

    assert_tunnel_works(&circuit, &target_addr, b"after-rebuild").await;
}

#[tokio::test]
async fn rebuild_after_failure_rebuilds_middle_suffix_and_preserves_entry_session() {
    let (mut circuit, mut failure_rx, relays, target_addr, initial_ids) =
        build_three_hop_circuit().await;

    let killed_session_id = initial_ids[1].expect("session id for failed hop");
    assert!(relays[1].terminate_session(&killed_session_id));

    let failure = expect_failure(&mut failure_rx).await;
    assert_eq!(failure.hop_idx, 1);
    assert_eq!(failure.epoch, circuit.hop_epoch(1).unwrap());

    assert_eq!(
        circuit.rebuild_after_failure(failure).await.unwrap(),
        RebuildAfterFailureOutcome::Rebuilt
    );

    let rebuilt_ids = circuit.session_ids();
    assert_eq!(rebuilt_ids[0], initial_ids[0]);
    assert_ne!(rebuilt_ids[1], initial_ids[1]);
    assert_ne!(rebuilt_ids[2], initial_ids[2]);
    assert_tunnel_works(&circuit, &target_addr, b"after-middle-failure").await;
}

#[tokio::test]
async fn rebuild_after_failure_rebuilds_only_final_hop_when_final_session_dies() {
    let (mut circuit, mut failure_rx, relays, target_addr, initial_ids) =
        build_three_hop_circuit().await;

    let killed_session_id = initial_ids[2].expect("session id for failed hop");
    assert!(relays[2].terminate_session(&killed_session_id));

    let failure = expect_failure(&mut failure_rx).await;
    assert_eq!(failure.hop_idx, 2);
    assert_eq!(failure.epoch, circuit.hop_epoch(2).unwrap());

    assert_eq!(
        circuit.rebuild_after_failure(failure).await.unwrap(),
        RebuildAfterFailureOutcome::Rebuilt
    );

    let rebuilt_ids = circuit.session_ids();
    assert_eq!(rebuilt_ids[0], initial_ids[0]);
    assert_eq!(rebuilt_ids[1], initial_ids[1]);
    assert_ne!(rebuilt_ids[2], initial_ids[2]);
    assert_tunnel_works(&circuit, &target_addr, b"after-final-failure").await;
}

#[tokio::test]
async fn stale_failure_after_successful_rebuild_does_not_trigger_second_rebuild() {
    let (mut circuit, mut failure_rx, relays, target_addr, initial_ids) =
        build_three_hop_circuit().await;

    let killed_session_id = initial_ids[1].expect("session id for failed hop");
    assert!(relays[1].terminate_session(&killed_session_id));

    let stale_failure = expect_failure(&mut failure_rx).await;
    assert_eq!(stale_failure.hop_idx, 1);
    assert_eq!(
        circuit
            .rebuild_after_failure(stale_failure.clone())
            .await
            .unwrap(),
        RebuildAfterFailureOutcome::Rebuilt
    );

    let rebuilt_ids = circuit.session_ids();
    assert_eq!(
        circuit.rebuild_after_failure(stale_failure).await.unwrap(),
        RebuildAfterFailureOutcome::Stale
    );
    assert_eq!(circuit.session_ids(), rebuilt_ids);
    assert_tunnel_works(&circuit, &target_addr, b"stale-failure-ignored").await;
}

#[tokio::test]
async fn failed_suffix_rebuild_preserves_prefix_and_clears_final_connection() {
    let (mut circuit, _failure_rx, mut relays, _target_addr, initial_ids) =
        build_three_hop_circuit().await;

    let replacement = TestRelayHandle::start_ephemeral().await.unwrap();
    let mut bad_spec = replacement.spec.clone();
    bad_spec.pubkey = TestRelayHandle::start_ephemeral()
        .await
        .unwrap()
        .spec
        .pubkey;
    relays.push(replacement);

    circuit.set_hop_spec(2, bad_spec).unwrap();

    let _err = circuit.rebuild_from(2).await.unwrap_err();
    assert_eq!(circuit.session_ids()[0], initial_ids[0]);
    assert_eq!(circuit.session_ids()[1], initial_ids[1]);
    assert_eq!(circuit.hop_session_id(2), None);
    assert_eq!(circuit.connected_hop_prefix_len(), 2);
    assert!(!circuit.is_complete());
    assert_eq!(circuit.first_incomplete_hop(), Some(2));
    assert!(circuit.final_conn().is_none());
}

#[tokio::test]
async fn set_hop_spec_and_rebuild_from_middle_switches_only_suffix() {
    let (mut circuit, _failure_rx, mut relays, target_addr, initial_ids) =
        build_three_hop_circuit().await;

    let replacement = TestRelayHandle::start_ephemeral().await.unwrap();
    let replacement_spec = replacement.spec.clone();
    relays.push(replacement);

    circuit.set_hop_spec(1, replacement_spec).unwrap();
    circuit.rebuild_from(1).await.unwrap();

    let rebuilt_ids = circuit.session_ids();
    assert_eq!(rebuilt_ids[0], initial_ids[0]);
    assert_ne!(rebuilt_ids[1], initial_ids[1]);
    assert_ne!(rebuilt_ids[2], initial_ids[2]);
    assert_tunnel_works(&circuit, &target_addr, b"spec-swap-rebuild").await;
}

#[tokio::test]
async fn channel_evicted_does_not_force_rebuild_when_control_stays_healthy() {
    let (circuit, mut failure_rx, relays, target_addr, initial_ids) =
        build_three_hop_circuit().await;

    let session_id = initial_ids[1].expect("middle hop session id");
    assert!(relays[1].notify_session(
        &session_id,
        ServerMessage::ChannelEvicted {
            channel_id: "synthetic-evict".to_string(),
        }
    ));

    sleep(Duration::from_millis(300)).await;
    assert!(timeout(Duration::from_millis(200), failure_rx.recv())
        .await
        .is_err());
    assert_eq!(circuit.hop_session_id(1), Some(session_id));
    assert_tunnel_works(&circuit, &target_addr, b"after-eviction-not-rebuild").await;
}

#[tokio::test]
async fn recoverable_control_error_does_not_force_rebuild() {
    let (circuit, mut failure_rx, relays, target_addr, initial_ids) =
        build_three_hop_circuit().await;

    let session_id = initial_ids[1].expect("middle hop session id");
    assert!(relays[1].notify_session(
        &session_id,
        ServerMessage::Error {
            message: "no new funds".to_string(),
        }
    ));

    sleep(Duration::from_millis(300)).await;
    assert!(timeout(Duration::from_millis(200), failure_rx.recv())
        .await
        .is_err());
    assert_eq!(circuit.hop_session_id(1), Some(session_id));
    assert_tunnel_works(&circuit, &target_addr, b"after-recoverable-error").await;
}

#[tokio::test]
async fn circuit_rebuilds_middle_and_later_hops_without_restarting_entry_session() {
    assert_suffix_rebuild(1, 1, 1).await;
}

#[tokio::test]
async fn circuit_rebuilds_only_final_hop_when_final_session_dies() {
    assert_suffix_rebuild(2, 2, 2).await;
}

#[tokio::test]
async fn circuit_rebuilds_entire_chain_when_entry_session_dies() {
    assert_suffix_rebuild(0, 0, 0).await;
}
