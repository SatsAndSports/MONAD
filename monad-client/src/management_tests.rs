use super::*;

fn refusal() -> crate::admission::RouteRefusal {
    crate::admission::RouteRefusal {
        refusing_hop: 1,
        target_hop: 2,
        operation: "connect",
        destination: "relay.example:443".into(),
        rejection: monad_common::rejection::RejectionCode::RelayDisabled.rejection(),
    }
}

#[test]
fn manual_authority_is_single_use_and_session_scoped() {
    let owner = Arc::new(ClientManagement::default());
    owner.set_automatic_provisioning(false);
    let lease = owner.register([1; 32], "hop 1");
    assert!(!lease.hop.begin_provisioning(&owner));
    let id = hex::encode([1; 32]);
    owner.provision_once(&id).unwrap();
    assert!(owner.provision_once(&id).is_err());
    assert!(lease.hop.begin_provisioning(&owner));
    assert!(owner.provision_once(&id).is_err());
    lease.hop.provisioning_finished(&owner);
    assert!(!lease.hop.begin_provisioning(&owner));
    drop(lease);
    assert!(owner.provision_once(&id).is_err());
    assert!(owner.hops().is_empty());
}

#[test]
fn enabling_automatic_consumes_pending_manual_request() {
    let owner = Arc::new(ClientManagement::default());
    owner.set_automatic_provisioning(false);
    let lease = owner.register([1; 32], "hop 1");
    assert!(!lease.hop.begin_provisioning(&owner));
    owner.provision_once(&hex::encode([1; 32])).unwrap();
    owner.set_automatic_provisioning(true);
    assert!(lease.hop.begin_provisioning(&owner));
    lease.hop.provisioning_finished(&owner);
    owner.set_automatic_provisioning(false);
    assert!(!lease.hop.begin_provisioning(&owner));
}

#[test]
fn disable_cannot_be_overwritten_before_runtime_cleanup() {
    let owner = ClientManagement::default();
    let first = owner.begin_run().unwrap();
    owner.set_enabled(false).unwrap();
    assert_eq!(
        owner.runtime_snapshot().lifecycle,
        ClientLifecycle::Disabling
    );
    assert!(owner.set_enabled(true).is_err());
    owner.connecting(first, 2, true);
    owner.rebuilding_suffix(first, 2, 1);
    owner.retry_backoff(first, 3, 123);
    let published = std::sync::atomic::AtomicBool::new(false);
    assert!(!owner.publish_active_route(first, "late".into(), || {
        published.store(true, std::sync::atomic::Ordering::SeqCst);
    }));
    assert!(!published.load(std::sync::atomic::Ordering::SeqCst));
    assert_eq!(
        owner.runtime_snapshot().lifecycle,
        ClientLifecycle::Disabling
    );
    owner.finish_run(first);
    assert_eq!(
        owner.runtime_snapshot().lifecycle,
        ClientLifecycle::Disabled
    );
    owner.set_enabled(true).unwrap();
    let second = owner.begin_run().unwrap();
    assert!(second > first);
    owner.finish_run(second);
}

#[test]
fn lifecycle_events_follow_revision_order_under_concurrent_updates() {
    let owner = Arc::new(ClientManagement::default());
    let generation = owner.begin_run().unwrap();
    let barrier = Arc::new(std::sync::Barrier::new(9));
    let mut tasks = Vec::new();
    for attempt in 0..8 {
        let owner = owner.clone();
        let barrier = barrier.clone();
        tasks.push(std::thread::spawn(move || {
            barrier.wait();
            owner.connecting(generation, attempt, true);
        }));
    }
    barrier.wait();
    for task in tasks {
        task.join().unwrap();
    }
    let revisions = owner
        .events
        .snapshot()
        .into_iter()
        .filter(|event| event.kind == "client_lifecycle_changed")
        .map(|event| event.data["revision"].as_u64().unwrap())
        .collect::<Vec<_>>();
    assert!(revisions.windows(2).all(|pair| pair[0] < pair[1]));
}

#[test]
fn lifecycle_generations_reject_stale_updates_and_track_route_publication() {
    let owner = ClientManagement::default();
    let first = owner.begin_run().unwrap();
    owner.connecting(first, 0, false);
    owner.publish_active_route(first, "first".into(), || {});
    assert_eq!(owner.runtime_snapshot().route_generation, 1);
    owner.finish_run(first);

    let second = owner.begin_run().unwrap();
    owner.connecting(second, 0, false);
    let before_stale = owner.runtime_snapshot();
    owner.publish_active_route(first, "stale".into(), || {});
    assert_eq!(owner.runtime_snapshot(), before_stale);
    owner.publish_active_route(second, "second".into(), || {});
    let current = owner.runtime_snapshot();
    assert_eq!(current.run_generation, second);
    assert_eq!(current.route_generation, 1);
    assert_eq!(current.lifecycle, ClientLifecycle::Active);
}

#[test]
fn repeated_admission_wait_updates_retry_time_without_duplicate_refusal_event() {
    let owner = ClientManagement::default();
    let generation = owner.begin_run().unwrap();
    owner.connecting(generation, 2, true);
    for retry_at_unix_ms in [100, 200] {
        owner.waiting_for_admission(
            generation,
            crate::admission::AdmissionWait {
                refusal: refusal(),
                retry_at_unix_ms,
                retry_interval_ms: 5_000,
            },
        );
    }
    assert!(matches!(
        owner.runtime_snapshot().lifecycle,
        ClientLifecycle::WaitingForAdmission { wait, .. }
            if wait.retry_at_unix_ms == 200
    ));
    assert_eq!(
        owner
            .events
            .snapshot()
            .iter()
            .filter(|event| event.kind == "route_refused")
            .count(),
        1
    );
}

#[test]
fn suffix_admission_wait_restores_rebuild_context() {
    let owner = ClientManagement::default();
    let generation = owner.begin_run().unwrap();
    owner.rebuilding_suffix(generation, 3, 2);
    owner.waiting_for_admission(
        generation,
        crate::admission::AdmissionWait {
            refusal: refusal(),
            retry_at_unix_ms: 100,
            retry_interval_ms: 5_000,
        },
    );
    assert!(matches!(
        owner.runtime_snapshot().lifecycle,
        ClientLifecycle::WaitingForAdmission {
            context: AdmissionWaitContext::RebuildingSuffix {
                failed_hop: 3,
                preserved_hops: 2,
            },
            ..
        }
    ));
    owner.clear_admission_wait(generation);
    assert_eq!(
        owner.runtime_snapshot().lifecycle,
        ClientLifecycle::RebuildingSuffix {
            failed_hop: 3,
            preserved_hops: 2,
        }
    );
}

#[test]
fn successful_exit_does_not_erase_another_tunnels_last_failure() {
    let owner = Arc::new(ClientManagement::default());
    let generation = owner.begin_run().unwrap();
    owner.connecting(generation, 0, false);
    let _lease = owner.register([3; 32], "hop 1");
    owner.publish_active_route(generation, hex::encode([3; 32]), || {});
    let error = monad_common::rejection::RejectionCode::DestinationPolicyDenied
        .rejection()
        .into_io();
    owner.note_exit_result(&[3; 32], "denied.example:443", Some(&error));
    let failure = owner
        .runtime_snapshot()
        .last_exit_failure
        .expect("recorded exit failure");
    owner.note_exit_result(&[4; 32], "allowed.example:443", None);
    assert_eq!(
        owner.runtime_snapshot().last_exit_failure.as_ref(),
        Some(&failure)
    );
}

#[test]
fn stale_exit_failure_cannot_overwrite_replacement_route() {
    let owner = Arc::new(ClientManagement::default());
    let generation = owner.begin_run().unwrap();
    owner.connecting(generation, 0, false);
    let _old = owner.register([1; 32], "old hop");
    owner.publish_active_route(generation, hex::encode([1; 32]), || {});
    owner.connecting(generation, 1, true);
    let _new = owner.register([2; 32], "new hop");
    owner.publish_active_route(generation, hex::encode([2; 32]), || {});
    let error = monad_common::rejection::RejectionCode::DestinationPolicyDenied
        .rejection()
        .into_io();

    owner.note_exit_result(&[1; 32], "stale.example:443", Some(&error));
    assert!(owner.runtime_snapshot().last_exit_failure.is_none());
    owner.note_exit_result(&[2; 32], "current.example:443", Some(&error));
    let failure = owner.runtime_snapshot().last_exit_failure.unwrap();
    assert_eq!(failure.route_generation, 2);
    assert_eq!(failure.destination, "current.example:443");
}

#[test]
fn withdrawn_route_rejects_late_exit_failure() {
    let owner = Arc::new(ClientManagement::default());
    let generation = owner.begin_run().unwrap();
    owner.connecting(generation, 0, false);
    let _lease = owner.register([1; 32], "old hop");
    owner.publish_active_route(generation, hex::encode([1; 32]), || {});
    let error = monad_common::rejection::RejectionCode::DestinationPolicyDenied
        .rejection()
        .into_io();
    owner.note_exit_result(&[1; 32], "old.example:443", Some(&error));
    assert!(owner.runtime_snapshot().last_exit_failure.is_some());
    owner.withdraw_active_route(generation, || {});
    assert!(owner.runtime_snapshot().last_exit_failure.is_none());
    owner.note_exit_result(&[1; 32], "stale.example:443", Some(&error));
    assert!(owner.runtime_snapshot().last_exit_failure.is_none());
}

#[test]
fn blocked_funding_state_survives_unpaused_status() {
    let owner = Arc::new(ClientManagement::default());
    let lease = owner.register([1; 32], "hop 1");
    lease.hop.blocked(&owner, "wallet unavailable".into());
    lease.hop.status(&owner, None, false, 1_000, 500);
    assert_eq!(
        owner.hops()[0].funding,
        HopFundingState::Blocked {
            message: "wallet unavailable".into(),
        }
    );
}

#[test]
fn recovery_retains_last_failure_while_lifecycle_returns_active() {
    let owner = ClientManagement::default();
    let generation = owner.begin_run().unwrap();
    owner.connecting(generation, 0, false);
    owner.publish_active_route(generation, "first".into(), || {});
    let failure = ClientFailure {
        stage: ClientFailureStage::Route,
        message: "funded hop failed".into(),
        hop: Some(2),
        retryable: true,
    };
    owner.record_failure(generation, failure.clone());
    owner.rebuilding_suffix(generation, 2, 1);
    owner.publish_active_route(generation, "second".into(), || {});

    let snapshot = owner.runtime_snapshot();
    assert_eq!(snapshot.lifecycle, ClientLifecycle::Active);
    assert_eq!(snapshot.route_generation, 2);
    assert_eq!(snapshot.last_failure, Some(failure));
    let events = owner.events.snapshot();
    assert!(events.iter().any(|event| event.kind == "client_failure"));
    assert!(events
        .iter()
        .filter(|event| event.kind == "client_lifecycle_changed")
        .any(|event| event.data["lifecycle"]["state"] == "rebuilding_suffix"));
}
