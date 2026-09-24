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
fn lifecycle_generations_reject_stale_updates_and_track_route_publication() {
    let owner = ClientManagement::default();
    let first = owner.begin_run().unwrap();
    owner.connecting(first, 0, false);
    owner.active(first);
    assert_eq!(owner.runtime_snapshot().route_generation, 1);
    owner.finish_run(first);

    let second = owner.begin_run().unwrap();
    owner.connecting(second, 0, false);
    let before_stale = owner.runtime_snapshot();
    owner.active(first);
    assert_eq!(owner.runtime_snapshot(), before_stale);
    owner.active(second);
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
fn successful_exit_does_not_erase_another_tunnels_last_failure() {
    let owner = Arc::new(ClientManagement::default());
    let generation = owner.begin_run().unwrap();
    owner.connecting(generation, 0, false);
    let _lease = owner.register([3; 32], "hop 1");
    owner.active(generation);
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
    owner.active(generation);
    owner.connecting(generation, 1, true);
    let _new = owner.register([2; 32], "new hop");
    owner.active(generation);
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
fn recovery_retains_last_failure_while_lifecycle_returns_active() {
    let owner = ClientManagement::default();
    let generation = owner.begin_run().unwrap();
    owner.connecting(generation, 0, false);
    owner.active(generation);
    let failure = ClientFailure {
        stage: ClientFailureStage::Route,
        message: "funded hop failed".into(),
        hop: Some(2),
        retryable: true,
    };
    owner.record_failure(generation, failure.clone());
    owner.rebuilding_suffix(generation, 2, 1);
    owner.active(generation);

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
