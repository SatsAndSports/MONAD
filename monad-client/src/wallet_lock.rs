use std::io;
use std::path::Path;

pub(crate) use monad_common::wallet_lock::normalize_path;
pub use monad_common::wallet_lock::{ExclusiveWalletAccess, WalletLockIdentity, WalletLockMode};

pub struct ClientWalletLocks(monad_common::wallet_lock::WalletLocks);

impl ClientWalletLocks {
    pub fn acquire(
        loose_db_path: impl AsRef<Path>,
        channel_db_path: impl AsRef<Path>,
        mode: WalletLockMode,
    ) -> io::Result<Self> {
        Ok(Self(monad_common::wallet_lock::WalletLocks::acquire(
            [loose_db_path.as_ref(), channel_db_path.as_ref()],
            mode,
            "client",
        )?))
    }

    pub fn enter_steady_state(&mut self) -> io::Result<()> {
        self.0.enter_steady_state()
    }

    pub fn exclusive_access(&self) -> io::Result<ExclusiveWalletAccess<'_>> {
        self.0.exclusive_access()
    }

    pub fn holds_runtime_owner(&self) -> bool {
        self.0.holds_runtime_owner()
    }
}
