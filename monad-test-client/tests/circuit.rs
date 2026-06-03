use monad_test_client::{Circuit, CircuitConfig, TestRelayHandle};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
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

async fn build_three_hop_circuit() -> (Circuit, Vec<TestRelayHandle>, String, Vec<Option<[u8; 32]>>)
{
    let relays = vec![
        TestRelayHandle::start_ephemeral().await.unwrap(),
        TestRelayHandle::start_ephemeral().await.unwrap(),
        TestRelayHandle::start_ephemeral().await.unwrap(),
    ];
    let specs = relays
        .iter()
        .map(|relay| relay.spec.clone())
        .collect::<Vec<_>>();
    let (mut circuit, _failure_rx) = Circuit::new(
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

    (circuit, relays, target_addr, initial_ids)
}

async fn assert_suffix_rebuild(
    failed_hop_idx: usize,
    rebuild_from: usize,
    unchanged_prefix_len: usize,
) {
    let (mut circuit, relays, target_addr, initial_ids) = build_three_hop_circuit().await;

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
