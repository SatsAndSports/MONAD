use std::collections::BTreeSet;
use std::fs::{File, OpenOptions};
use std::io;
use std::path::{Component, Path, PathBuf};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WalletLockMode {
    Runtime,
    ReadOnly,
    Maintenance,
}

pub struct WalletLocks {
    runtime_owner: Vec<File>,
    maintenance: Vec<File>,
    maintenance_exclusive: bool,
    identity: WalletLockIdentity,
}

pub struct ExclusiveWalletAccess<'a> {
    _locks: &'a WalletLocks,
    identity: &'a WalletLockIdentity,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WalletLockIdentity(Vec<PathBuf>);

impl WalletLockIdentity {
    pub fn new<'a>(paths: impl IntoIterator<Item = &'a Path>) -> io::Result<Self> {
        Ok(Self(normalized_db_paths(paths)?))
    }
}

impl ExclusiveWalletAccess<'_> {
    pub fn authorizes(&self, identity: &WalletLockIdentity) -> bool {
        self.identity == identity
    }
}

impl WalletLocks {
    pub fn acquire<'a>(
        db_paths: impl IntoIterator<Item = &'a Path>,
        mode: WalletLockMode,
        owner_name: &str,
    ) -> io::Result<Self> {
        let identity = WalletLockIdentity::new(db_paths)?;
        let mut runtime_owner = Vec::new();
        let mut maintenance = Vec::new();

        if mode == WalletLockMode::Runtime {
            for path in sidecar_paths(&identity.0, "runtime-owner.lock") {
                let file = open_sidecar(&path, false)?;
                file.try_lock()
                    .map_err(io::Error::from)
                    .map_err(|error| lock_error(owner_name, &path, mode, error))?;
                runtime_owner.push(file);
            }
        }

        for path in sidecar_paths(&identity.0, "maintenance.lock") {
            let file = open_sidecar(&path, mode == WalletLockMode::ReadOnly)?;
            if mode == WalletLockMode::ReadOnly {
                File::lock_shared(&file)
                    .map_err(|error| lock_error(owner_name, &path, mode, error))?;
            } else {
                File::try_lock(&file)
                    .map_err(io::Error::from)
                    .map_err(|error| lock_error(owner_name, &path, mode, error))?;
            }
            maintenance.push(file);
        }

        Ok(Self {
            runtime_owner,
            maintenance,
            maintenance_exclusive: mode != WalletLockMode::ReadOnly,
            identity,
        })
    }

    pub fn enter_steady_state(&mut self) -> io::Result<()> {
        if !self.maintenance_exclusive {
            return Ok(());
        }
        for file in &self.maintenance {
            File::lock_shared(file)?;
        }
        self.maintenance_exclusive = false;
        Ok(())
    }

    pub fn exclusive_access(&self) -> io::Result<ExclusiveWalletAccess<'_>> {
        if !self.maintenance_exclusive {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "exclusive wallet maintenance access is not held",
            ));
        }
        Ok(ExclusiveWalletAccess {
            _locks: self,
            identity: &self.identity,
        })
    }

    pub fn holds_runtime_owner(&self) -> bool {
        !self.runtime_owner.is_empty()
    }
}

fn normalized_db_paths<'a>(paths: impl IntoIterator<Item = &'a Path>) -> io::Result<Vec<PathBuf>> {
    paths
        .into_iter()
        .map(normalize_path)
        .collect::<io::Result<BTreeSet<_>>>()
        .map(BTreeSet::into_iter)
        .map(Iterator::collect)
}

pub fn normalize_path(path: &Path) -> io::Result<PathBuf> {
    let absolute = if path.is_absolute() {
        path.to_path_buf()
    } else {
        std::env::current_dir()?.join(path)
    };
    let mut normalized = PathBuf::new();
    for component in absolute.components() {
        match component {
            Component::CurDir => {}
            Component::ParentDir => {
                normalized.pop();
            }
            other => normalized.push(other.as_os_str()),
        }
    }
    let Some(file_name) = normalized.file_name() else {
        return normalized.canonicalize().or(Ok(normalized));
    };
    let parent = normalized.parent().unwrap_or(Path::new("/"));
    let normalized = parent
        .canonicalize()
        .unwrap_or_else(|_| parent.to_path_buf())
        .join(file_name);

    match normalized.symlink_metadata() {
        Ok(metadata) if metadata.file_type().is_symlink() => {
            let target = std::fs::read_link(&normalized)?;
            let target = if target.is_absolute() {
                target
            } else {
                normalized.parent().unwrap_or(Path::new("/")).join(target)
            };
            normalize_path(&target)
        }
        Ok(metadata) => {
            #[cfg(unix)]
            {
                use std::os::unix::fs::MetadataExt;

                if metadata.is_file() && metadata.nlink() > 1 {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidInput,
                        format!(
                            "wallet database path {} has multiple hard links; hard-linked wallet databases are unsupported",
                            normalized.display()
                        ),
                    ));
                }
            }
            Ok(normalized)
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(normalized),
        Err(error) => Err(error),
    }
}

fn sidecar_paths(db_paths: &[PathBuf], suffix: &str) -> Vec<PathBuf> {
    db_paths
        .iter()
        .map(|path| {
            let mut sidecar = path.as_os_str().to_os_string();
            sidecar.push(format!(".monad-{suffix}"));
            PathBuf::from(sidecar)
        })
        .collect()
}

fn open_sidecar(path: &Path, read_only: bool) -> io::Result<File> {
    if read_only {
        match OpenOptions::new().read(true).open(path) {
            Ok(file) => return Ok(file),
            Err(error) if error.kind() == io::ErrorKind::NotFound => {}
            Err(error) => return Err(error),
        }
    }
    OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .open(path)
}

fn lock_error(owner_name: &str, path: &Path, mode: WalletLockMode, error: io::Error) -> io::Error {
    io::Error::new(
        error.kind(),
        format!(
            "{owner_name} wallet {mode:?} lock unavailable at {}: {error}",
            path.display()
        ),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{Mutex, MutexGuard, OnceLock};

    fn process_lock_test_guard() -> MutexGuard<'static, ()> {
        static GUARD: OnceLock<Mutex<()>> = OnceLock::new();
        GUARD.get_or_init(|| Mutex::new(())).lock().unwrap()
    }

    #[test]
    fn lock_matrix_enforces_runtime_and_maintenance_ownership() {
        // The process-death test forks this test binary; serialize it so the child
        // cannot transiently inherit this test's open lock descriptors.
        let _guard = process_lock_test_guard();
        let dir = tempfile::tempdir().unwrap();
        let db = dir.path().join("wallet.db");
        let paths = [&db as &Path];

        let mut runtime = WalletLocks::acquire(paths, WalletLockMode::Runtime, "test").unwrap();
        assert!(runtime.holds_runtime_owner());
        assert!(runtime.exclusive_access().is_ok());
        assert!(WalletLocks::acquire(paths, WalletLockMode::Runtime, "test").is_err());
        assert!(WalletLocks::acquire(paths, WalletLockMode::Maintenance, "test").is_err());

        runtime.enter_steady_state().unwrap();
        assert!(runtime.exclusive_access().is_err());
        let inspection = WalletLocks::acquire(paths, WalletLockMode::ReadOnly, "test").unwrap();
        assert!(WalletLocks::acquire(paths, WalletLockMode::Maintenance, "test").is_err());
        drop(inspection);
        drop(runtime);

        WalletLocks::acquire(paths, WalletLockMode::Maintenance, "test").unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn dangling_symlink_identity_is_stable_after_database_creation() {
        use std::os::unix::fs::symlink;

        let dir = tempfile::tempdir().unwrap();
        let target = dir.path().join("wallet.db");
        let alias = dir.path().join("wallet-alias.db");
        symlink(&target, &alias).unwrap();

        let locks =
            WalletLocks::acquire([alias.as_path()], WalletLockMode::Runtime, "test").unwrap();
        File::create(&target).unwrap();
        assert!(WalletLocks::acquire([target.as_path()], WalletLockMode::Runtime, "test").is_err());
        drop(locks);
        WalletLocks::acquire(
            [target.as_path(), alias.as_path()],
            WalletLockMode::Runtime,
            "test",
        )
        .unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn hard_linked_database_paths_are_rejected() {
        let dir = tempfile::tempdir().unwrap();
        let db = dir.path().join("wallet.db");
        let alias = dir.path().join("wallet-hardlink.db");
        File::create(&db).unwrap();
        std::fs::hard_link(&db, &alias).unwrap();

        let db_error = WalletLocks::acquire([db.as_path()], WalletLockMode::Runtime, "test")
            .err()
            .expect("original hard-linked path must be rejected");
        let alias_error = WalletLocks::acquire([alias.as_path()], WalletLockMode::Runtime, "test")
            .err()
            .expect("hard-link alias must be rejected");
        assert_eq!(db_error.kind(), io::ErrorKind::InvalidInput);
        assert_eq!(alias_error.kind(), io::ErrorKind::InvalidInput);
        assert!(db_error.to_string().contains("multiple hard links"));
    }

    #[cfg(unix)]
    #[test]
    fn inspection_uses_existing_sidecar_in_read_only_directory() {
        use std::os::unix::fs::PermissionsExt;

        let dir = tempfile::tempdir().unwrap();
        let db = dir.path().join("wallet.db");
        File::create(&db).unwrap();
        let locks = WalletLocks::acquire([db.as_path()], WalletLockMode::Runtime, "test").unwrap();
        drop(locks);

        let maintenance = sidecar_paths(std::slice::from_ref(&db), "maintenance.lock").remove(0);
        std::fs::set_permissions(&db, std::fs::Permissions::from_mode(0o444)).unwrap();
        std::fs::set_permissions(&maintenance, std::fs::Permissions::from_mode(0o444)).unwrap();
        std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o555)).unwrap();

        let inspection =
            WalletLocks::acquire([db.as_path()], WalletLockMode::ReadOnly, "test inspection");

        std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o755)).unwrap();
        assert!(inspection.is_ok());
    }

    #[test]
    fn process_lock_child() {
        let Ok(db) = std::env::var("MONAD_WALLET_LOCK_CHILD_DB") else {
            return;
        };
        let marker = std::env::var("MONAD_WALLET_LOCK_CHILD_MARKER").unwrap();
        let _locks =
            WalletLocks::acquire([Path::new(&db)], WalletLockMode::Runtime, "test child").unwrap();
        File::create(marker).unwrap();
        std::thread::sleep(std::time::Duration::from_secs(30));
    }

    #[test]
    fn runtime_ownership_is_released_when_process_dies() {
        let _guard = process_lock_test_guard();
        let dir = tempfile::tempdir().unwrap();
        let db = dir.path().join("wallet.db");
        let marker = dir.path().join("locked");
        let mut child = std::process::Command::new(std::env::current_exe().unwrap())
            .args(["--exact", "wallet_lock::tests::process_lock_child"])
            .env("MONAD_WALLET_LOCK_CHILD_DB", &db)
            .env("MONAD_WALLET_LOCK_CHILD_MARKER", &marker)
            .spawn()
            .unwrap();
        for _ in 0..100 {
            if marker.exists() {
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(10));
        }
        assert!(marker.exists(), "child did not acquire the runtime lock");
        assert!(WalletLocks::acquire([db.as_path()], WalletLockMode::Runtime, "test").is_err());
        child.kill().unwrap();
        child.wait().unwrap();
        WalletLocks::acquire([db.as_path()], WalletLockMode::Runtime, "test").unwrap();
    }
}
