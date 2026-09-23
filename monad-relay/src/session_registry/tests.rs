use super::*;
use std::sync::Arc;
use tokio::sync::oneshot;
use tokio::time::{timeout, Duration};

#[tokio::test]
async fn disable_waits_for_owned_handshake_drop_and_preserves_policy() {
    let registry = Arc::new(SessionRegistry::new());
    let (started_tx, started_rx) = oneshot::channel();
    let (dropped_tx, dropped_rx) = oneshot::channel();
    struct Dropped(Option<oneshot::Sender<()>>);
    impl Drop for Dropped {
        fn drop(&mut self) {
            self.0.take().unwrap().send(()).unwrap();
        }
    }
    let owner = registry.clone();
    let task = tokio::spawn(async move {
        owner
            .run_admitted(async move {
                let _drop = Dropped(Some(dropped_tx));
                started_tx.send(()).unwrap();
                std::future::pending::<()>().await;
            })
            .await;
    });
    started_rx.await.unwrap();
    let policy = RelayControls {
        enabled: false,
        accept_new_channels: false,
        accept_new_tunnels: false,
        ..RelayControls::default()
    };
    registry.set_controls(policy).unwrap();
    let enabled = RelayControls {
        enabled: true,
        ..policy
    };
    assert!(registry.set_controls(enabled).is_err());
    timeout(Duration::from_secs(2), registry.wait_disabled())
        .await
        .unwrap()
        .unwrap();
    dropped_rx.await.unwrap();
    task.await.unwrap();
    registry.set_controls(enabled).unwrap();
    assert_eq!(registry.controls(), enabled);
    let (tx, rx) = oneshot::channel();
    registry
        .run_admitted(async {
            tx.send(()).unwrap();
        })
        .await;
    rx.await.unwrap();
}

#[tokio::test]
async fn session_gate_preserves_existing_sessions_and_rejects_new_work() {
    let registry = SessionRegistry::new();
    let existing = CancellationToken::new();
    registry.register_session([1; 32], existing.clone());
    registry
        .set_controls(RelayControls {
            accept_new_sessions: false,
            ..RelayControls::default()
        })
        .unwrap();
    assert!(!existing.is_cancelled());
    registry
        .run_admitted(async { panic!("new work was polled") })
        .await;
    let rejected = CancellationToken::new();
    registry.register_session([2; 32], rejected.clone());
    assert!(rejected.is_cancelled());
    registry
        .set_controls(RelayControls {
            enabled: false,
            ..registry.controls()
        })
        .unwrap();
    assert!(existing.is_cancelled());
    registry.deregister_session(&[1; 32]);
    registry.wait_disabled().await.unwrap();
}
