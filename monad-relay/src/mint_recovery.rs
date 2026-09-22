use cdk_spilman::SpilmanAsyncMintClient;
use monad_common::mint_error::MintHttpRejection;

/// Recovery transport keeps HTTP-origin rejection evidence typed. String-only
/// errors never authorize replacement of an immutable request.
#[async_trait::async_trait]
pub trait RecoveryMintClient: SpilmanAsyncMintClient + Send + Sync {
    async fn swap_checked(&self, mint: &str, request: &str) -> anyhow::Result<String>;
    async fn restore(&self, mint: &str, request: &str) -> anyhow::Result<String>;
    async fn check_state(&self, mint: &str, request: &str) -> anyhow::Result<String>;
}

pub(crate) async fn post(
    client: &reqwest::Client,
    mint: &str,
    endpoint: &str,
    request: &str,
) -> anyhow::Result<String> {
    let response = client
        .post(format!("{}/{endpoint}", mint.trim_end_matches('/')))
        .timeout(std::time::Duration::from_secs(15))
        .header("Content-Type", "application/json")
        .body(request.to_string())
        .send()
        .await
        .map_err(|_| anyhow::anyhow!("mint transport failure; outcome uncertain"))?;
    let status = response.status();
    let body = response
        .text()
        .await
        .map_err(|_| anyhow::anyhow!("mint response body failure; outcome uncertain"))?;
    if !status.is_success() {
        return Err(MintHttpRejection::from_body(status.as_u16(), &body).into());
    }
    Ok(body)
}
