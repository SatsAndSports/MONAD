//! Opt-in process-death tests. Build both production binaries with the Make target.
#[path = "support/funds_lifecycle.rs"]
mod support;

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "requires isolated fault-injection relay; make test-funds-crashes"]
async fn process_relay_close_journal_boundaries() {
    let mut fixture = support::Fixture::start().await;
    for boundary in [
        "close-prepared",
        "close-submitting",
        "close-finalizing",
        "close-completed",
    ] {
        fixture.relay_close_case(Some(boundary), false, false).await;
    }
    for boundary in ["close-rejected", "close-successor"] {
        fixture.relay_close_case(Some(boundary), true, false).await;
    }
    fixture.finish().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "requires isolated fault-injection relay; make test-funds-crashes"]
async fn process_relay_close_response_loss_and_rotation() {
    let mut fixture = support::Fixture::start().await;
    fixture.relay_close_case(None, false, true).await;
    fixture.relay_close_case(None, true, false).await;
    fixture.relay_close_case(None, true, true).await;
    fixture.finish().await;
}

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
    fixture.refund_rotation_before_prepare().await;
    fixture.finish().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "requires fault-injection client; make test-funds-crashes"]
async fn process_opening_request_gates_and_rotation() {
    let mut fixture = support::Fixture::start().await;
    fixture.opening_request(false, true).await;
    fixture.finish().await;
    let mut fixture = support::Fixture::start().await;
    fixture.opening_request(true, false).await;
    fixture.rotate(200).await;
    fixture.cycle(false).await;
    fixture.finish().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "requires fault-injection client; make test-funds-crashes"]
async fn process_close_refund_races() {
    let mut fixture = support::Fixture::start().await;
    for winner in [Some(false), Some(true), None] {
        fixture.race(winner).await;
    }
    fixture.finish().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "requires fault-injection client; make test-funds-crashes"]
async fn process_refund_request_before_execution_crash() {
    let mut fixture = support::Fixture::start().await;
    fixture.refund_request_crash().await;
    fixture.finish().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "bounded purse stress; make stress-funds-lifecycle"]
async fn process_seeded_funds_stress() {
    let seed = std::env::var("MONAD_FUNDS_SEED")
        .map(|s| s.parse().unwrap())
        .unwrap_or(1);
    let cycles = std::env::var("MONAD_FUNDS_CYCLES")
        .map(|s| s.parse().unwrap())
        .unwrap_or(12);
    let mut fixture = support::Fixture::start().await;
    fixture.stress(seed, cycles).await;
    fixture.finish().await;
}
