//! Actual MONAD channel compatibility, not ordinary swap compatibility.
#[allow(dead_code)]
#[path = "support/funds_lifecycle.rs"]
mod support;

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "requires disposable external mint and private bootstrap proofs; characterization/run.py"]
async fn external_mint_signed_lifecycle() {
    let url = std::env::var("MONAD_CHARACTERIZATION_URL").unwrap();
    let proofs = std::env::var("MONAD_CHARACTERIZATION_PROOFS").unwrap();
    let mut fixture = support::Fixture::start_external(url, proofs.into()).await;
    match std::env::var("MONAD_CHARACTERIZATION_CASE")
        .as_deref()
        .unwrap_or("baseline")
    {
        "baseline" => fixture.cycle(false).await,
        "opening-loss" => fixture.opening_request(false, false).await,
        "opening-rotation-loss" => fixture.opening_request(true, false).await,
        "close-loss" => fixture.relay_close_case(None, false, true).await,
        "close-rotation" => fixture.relay_close_case(None, true, false).await,
        "close-rotation-loss" => fixture.relay_close_case(None, true, true).await,
        "refund-loss" => fixture.refund_case(None, false, true).await,
        "refund-rotation" => fixture.refund_case(None, true, false).await,
        "refund-rotation-loss" => fixture.refund_case(None, true, true).await,
        "drain-loss" => fixture.relay_drain_case(None, false, true).await,
        "drain-rotation" => fixture.relay_drain_case(None, true, false).await,
        "drain-rotation-loss" => fixture.relay_drain_case(None, true, true).await,
        _ => panic!("unknown characterization case"),
    }
    fixture.finish().await;
}
