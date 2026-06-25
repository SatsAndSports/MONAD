use crate::config_runtime::route_from_client_config;
use crate::connector::{connect_route_with_runtime, ConnectorRuntime};
use crate::loose_proof_wallet::LooseProofWallet;
use crate::session_driver::PaymentPolicy;
use crate::sqlite_client_wallet::SqliteClientWallet;
use crate::wallet::MonadWallet;
use crate::{socks, tunnel};
use monad_common::config::MonadConfig;
use monad_common::session::RelayConnection;
use std::future::Future;
use std::sync::Arc;
use tokio::net::TcpListener;
use tracing::{info, warn};

pub async fn run_configured_client_until_shutdown<S>(
    config: MonadConfig,
    client_name: Option<&str>,
    shutdown: S,
) -> anyhow::Result<()>
where
    S: Future<Output = ()> + Send,
{
    tokio::pin!(shutdown);

    let client = config.select_client(client_name)?;
    let client_wallet = config
        .wallets
        .client
        .as_ref()
        .ok_or_else(|| anyhow::anyhow!("wallets.client is required to run a client"))?;

    let loose_wallet =
        LooseProofWallet::open(&client_wallet.loose_db_path, &client_wallet.wallet_name)?;
    let wallet = SqliteClientWallet::open(
        loose_wallet,
        &client_wallet.channel_db_path,
        &client_wallet.sender_secret_hex,
    )?;
    let wallet: Arc<dyn MonadWallet> = Arc::new(wallet);
    let runtime = ConnectorRuntime::with_payment_policy(
        Some(wallet),
        PaymentPolicy {
            channel_input_budget_msats: client_wallet.channel_input_budget_msats,
            ..PaymentPolicy::default()
        },
    )?;
    let route = route_from_client_config(client)?;

    info!(
        client = %client.name,
        socks = %client.socks,
        hops = route.hops().len(),
        "connecting configured QUIC route"
    );
    let conn = connect_route_with_runtime(&route, &runtime).await?;
    let conn = Arc::new(conn);
    let listener = TcpListener::bind(&client.socks).await?;
    info!(client = %client.name, socks = %client.socks, "SOCKS5 listener ready");

    let socks_task = tokio::spawn(run_socks_listener(listener, conn));
    tokio::select! {
        result = socks_task => {
            match result {
                Ok(Ok(())) => Ok(()),
                Ok(Err(err)) => Err(err.into()),
                Err(err) => Err(anyhow::anyhow!("SOCKS listener task failed: {err}")),
            }
        }
        _ = &mut shutdown => {
            info!("shutting down configured client");
            Ok(())
        }
    }
}

pub async fn run_socks_listener(
    listener: TcpListener,
    conn: Arc<RelayConnection>,
) -> std::io::Result<()> {
    loop {
        let (mut stream, peer_addr) = listener.accept().await?;
        let conn = conn.clone();
        tokio::spawn(async move {
            let result = async {
                let target = socks::socks5_handshake(&mut stream).await?;
                tunnel::open_tunnel(&conn, &target.authority, &mut stream).await
            }
            .await;
            if let Err(err) = result {
                warn!("SOCKS client {peer_addr} failed: {err}");
            }
        });
    }
}
