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
    assert!(registry.set_control("enabled", true).is_err());
    registry.set_control("accept_new_channels", false).unwrap();
    assert!(!registry.controls().enabled);
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
#[test]
fn link_timestamps_are_per_channel_and_refresh_on_relink() {
    let registry = SessionRegistry::new();
    assert_eq!(registry.last_linked_at("channel-a"), None);
    assert_eq!(registry.last_linked_at("channel-b"), None);

    registry.record_channel_link("channel-a");
    let first_a = registry.last_linked_at("channel-a").unwrap();
    std::thread::sleep(Duration::from_millis(2));
    registry.record_channel_link("channel-b");
    let first_b = registry.last_linked_at("channel-b").unwrap();
    std::thread::sleep(Duration::from_millis(2));
    registry.record_channel_link("channel-a");
    let second_a = registry.last_linked_at("channel-a").unwrap();

    assert!(first_a > 0);
    assert!(first_b > first_a);
    assert!(second_a > first_b);
}

#[test]
fn link_timestamp_is_retained_after_session_departure() {
    let registry = SessionRegistry::new();
    registry.register_session([1; 32], CancellationToken::new());
    registry.record_channel_link("channel");
    let timestamp = registry.last_linked_at("channel").unwrap();

    registry.deregister_session(&[1; 32]);

    assert_eq!(registry.last_linked_at("channel"), Some(timestamp));
}
#[test]
fn concurrent_field_updates_preserve_independent_policy() {
    let registry = std::sync::Arc::new(SessionRegistry::default());
    let barrier = std::sync::Arc::new(std::sync::Barrier::new(3));
    std::thread::scope(|scope| {
        for field in ["accept_new_channels", "accept_new_tunnels", "enabled"] {
            let registry = registry.clone();
            let barrier = barrier.clone();
            scope.spawn(move || {
                barrier.wait();
                registry.set_control(field, false).unwrap();
            });
        }
    });
    let controls = registry.controls();
    assert!(!controls.enabled);
    assert!(!controls.accept_new_channels);
    assert!(!controls.accept_new_tunnels);
    assert!(controls.accept_new_sessions);
    assert!(registry.set_control("typo", true).is_err());
    registry.set_control("enabled", true).unwrap();
    assert!(!registry.controls().accept_new_channels);
}
