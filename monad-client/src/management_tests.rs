use super::*;

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
    lease.hop.provisioning_finished();
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
    lease.hop.provisioning_finished();
    owner.set_automatic_provisioning(false);
    assert!(!lease.hop.begin_provisioning(&owner));
}

#[test]
fn disable_cannot_be_overwritten_before_runtime_cleanup() {
    let owner = ClientManagement::default();
    assert!(owner.begin_run());
    owner.set_enabled(false).unwrap();
    assert!(owner.set_enabled(true).is_err());
    owner.finish_run();
    owner.set_enabled(true).unwrap();
    assert!(owner.begin_run());
    owner.finish_run();
}
