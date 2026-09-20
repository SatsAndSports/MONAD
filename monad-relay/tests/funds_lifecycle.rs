//! Opt-in process-death tests. Build both production binaries with the Make target.
#[path = "support/funds_lifecycle.rs"]
mod support;

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "requires explicitly built client and relay binaries; make test-funds-lifecycle"]
async fn process_funds_lifecycle() {
    let mut fixture = support::Fixture::start().await;
    fixture.cycle(false).await;
    fixture.cycle(true).await;
    fixture.finish().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "requires fault-injection client; make test-funds-crashes"]
async fn process_local_finalization_crashes() {
    let mut fixture = support::Fixture::start().await;
    for boundary in [
        "opening-finalizing",
        "opening-upstream",
        "opening-change",
        "opening-metadata",
    ] {
        fixture.opening_boundary(boundary).await;
    }
    for boundary in [
        "refund-finalizing",
        "refund-import",
        "refund-upstream",
        "refund-metadata",
    ] {
        fixture.refund_case(Some(boundary), false, false).await;
    }
    fixture.finish().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "requires fault-injection client; make test-funds-crashes"]
async fn process_refund_response_loss_and_rotation() {
    let mut fixture = support::Fixture::start().await;
    fixture.refund_case(None, false, true).await;
    fixture.refund_case(None, true, false).await;
    fixture.refund_case(None, true, true).await;
    fixture.finish().await;
}
