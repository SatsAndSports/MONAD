use crate::loose_proof_wallet::LooseProofWallet;
use crate::runtime::CONFIGURED_CLIENT_WALLET_NAME;
use crate::sqlite_client_wallet::{OpeningRecoveryReport, SqliteClientWallet};
use crate::wallet::MonadWallet;
use crate::wallet_lock::{ClientWalletLocks, WalletLockMode};
use monad_common::config::ClientWalletConfig;
use std::sync::Arc;

pub struct ClientWalletManager {
    wallet: Arc<SqliteClientWallet>,
    _locks: ClientWalletLocks,
}

impl ClientWalletManager {
    pub fn open(config: &ClientWalletConfig) -> anyhow::Result<(Self, OpeningRecoveryReport)> {
        let mut locks = ClientWalletLocks::acquire(
            &config.loose_db_path,
            &config.channel_db_path,
            WalletLockMode::Runtime,
        )?;
        let loose_wallet =
            LooseProofWallet::open(&config.loose_db_path, CONFIGURED_CLIENT_WALLET_NAME)?;
        let wallet = Arc::new(SqliteClientWallet::open(
            loose_wallet,
            &config.channel_db_path,
            &config.sender_secret_hex,
        )?);
        let recovery = wallet.recover_pending_openings()?;
        locks.enter_steady_state()?;
        Ok((
            Self {
                wallet,
                _locks: locks,
            },
            recovery,
        ))
    }

    pub fn wallet(&self) -> Arc<dyn MonadWallet> {
        self.wallet.clone()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test(flavor = "multi_thread")]
    async fn manager_owns_one_wallet_and_recovery_pass() {
        let dir = tempfile::tempdir().unwrap();
        let config = ClientWalletConfig {
            loose_db_path: dir.path().join("loose.db").display().to_string(),
            channel_db_path: dir.path().join("channels.db").display().to_string(),
            sender_secret_hex: hex::encode([7u8; 32]),
            channel_input_budget_msats: 1_000,
            target_topup_buffer_msats: 1_000,
            minimum_topup_msats: 1,
        };

        let (manager, recovery) = ClientWalletManager::open(&config).unwrap();
        assert!(recovery.is_empty());
        let first = manager.wallet();
        let second = manager.wallet();
        assert!(Arc::ptr_eq(&first, &second));
        assert!(ClientWalletManager::open(&config).is_err());
    }
}
