use cdk_spilman::SpilmanAsyncMintClient;

/// Recovery transport keeps HTTP-origin rejection evidence typed. String-only
/// errors never authorize replacement of an immutable request.
#[async_trait::async_trait]
pub trait RecoveryMintClient: SpilmanAsyncMintClient + Send + Sync {
    async fn swap_checked(&self, mint: &str, request: &str) -> anyhow::Result<String>;
    async fn restore(&self, mint: &str, request: &str) -> anyhow::Result<String>;
    async fn check_state(&self, mint: &str, request: &str) -> anyhow::Result<String>;
}

/// Bind upstream reconciliation to the journal's mint, preserving typed failures.
pub(crate) struct ChannelMint<'a, M> {
    pub client: &'a M,
    pub mint: &'a str,
}

#[async_trait::async_trait]
impl<M: RecoveryMintClient> cdk_spilman::MintConnection for ChannelMint<'_, M> {
    async fn process_swap(
        &self,
        _: cashu::nuts::SwapRequest,
    ) -> anyhow::Result<cashu::nuts::SwapResponse> {
        anyhow::bail!("reconciliation must not submit swaps")
    }
    async fn post_restore(
        &self,
        request: cashu::nuts::RestoreRequest,
    ) -> anyhow::Result<cashu::nuts::RestoreResponse> {
        let response = self
            .client
            .restore(self.mint, &serde_json::to_string(&request)?)
            .await?;
        Ok(serde_json::from_str(&response)?)
    }
    async fn check_state(
        &self,
        ys: Vec<cashu::nuts::PublicKey>,
    ) -> anyhow::Result<cashu::nuts::CheckStateResponse> {
        let response = self
            .client
            .check_state(self.mint, &serde_json::json!({"Ys": ys}).to_string())
            .await?;
        Ok(serde_json::from_str(&response)?)
    }
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
    monad_common::mint_error::read_mint_response(response)
        .await
        .map_err(monad_common::mint_error::recovery_error)
}
