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
