//! Disposable HTTP mint adapter. Never run against real funds.
use cdk_spilman_test_mint::{build_router, rotate_sat_keyset, TestMintHelper};

#[tokio::test]
#[ignore = "spawned and reaped by characterization/run.py"]
async fn characterization_cdk_server() {
    let port: u16 = std::env::var("MONAD_CHARACTERIZATION_PORT")
        .expect("explicit test port")
        .parse()
        .unwrap();
    let mint = TestMintHelper::new().await.unwrap();
    let shared = mint.mint();
    let router = build_router(shared.clone()).await.unwrap().route(
        "/_test/rotate",
        axum::routing::post(move || {
            let mint = shared.clone();
            async move {
                rotate_sat_keyset(&mint, 0).await.unwrap();
                axum::Json(serde_json::json!({"rotated": true}))
            }
        }),
    );
    let listener = tokio::net::TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, port))
        .await
        .unwrap();
    axum::serve(listener, router).await.unwrap();
}
