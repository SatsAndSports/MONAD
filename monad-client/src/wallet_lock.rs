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

pub struct ClientWalletLocks {
    runtime_owner: Vec<File>,
    maintenance: Vec<File>,
    maintenance_exclusive: bool,
}

impl ClientWalletLocks {
    pub fn acquire(
        loose_db_path: impl AsRef<Path>,
        channel_db_path: impl AsRef<Path>,
        mode: WalletLockMode,
    ) -> io::Result<Self> {
        let db_paths = normalized_db_paths([loose_db_path.as_ref(), channel_db_path.as_ref()])?;
        let mut runtime_owner = Vec::new();
        let mut maintenance = Vec::new();

        if mode == WalletLockMode::Runtime {
            for path in sidecar_paths(&db_paths, "runtime-owner.lock") {
                let file = open_sidecar(&path)?;
                file.try_lock()
                    .map_err(io::Error::from)
                    .map_err(|error| lock_error(&path, mode, error))?;
                runtime_owner.push(file);
            }
        }

        for path in sidecar_paths(&db_paths, "maintenance.lock") {
            let file = open_sidecar(&path)?;
            if mode == WalletLockMode::ReadOnly {
                File::lock_shared(&file).map_err(|error| lock_error(&path, mode, error))?;
            } else {
                File::try_lock(&file)
                    .map_err(io::Error::from)
                    .map_err(|error| lock_error(&path, mode, error))?;
            }
            maintenance.push(file);
        }

        Ok(Self {
            runtime_owner,
            maintenance,
            maintenance_exclusive: mode != WalletLockMode::ReadOnly,
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

fn normalize_path(path: &Path) -> io::Result<PathBuf> {
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

    // Resolve the configured final symlink itself even while its target is
    // absent. This keeps lock identity stable when SQLite creates the target.
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
        Ok(_) => Ok(normalized),
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

fn open_sidecar(path: &Path) -> io::Result<File> {
    OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .open(path)
}

fn lock_error(path: &Path, mode: WalletLockMode, error: io::Error) -> io::Error {
    io::Error::new(
        error.kind(),
        format!(
            "client wallet {mode:?} lock unavailable at {}: {error}",
            path.display()
        ),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lock_matrix_enforces_runtime_and_maintenance_ownership() {
        let dir = tempfile::tempdir().unwrap();
        let loose = dir.path().join("loose.db");
        let channels = dir.path().join("channels.db");

        let mut runtime = ClientWalletLocks::acquire(&loose, &channels, WalletLockMode::Runtime)
            .expect("first runtime lock");
        assert!(runtime.holds_runtime_owner());
        assert!(ClientWalletLocks::acquire(&loose, &channels, WalletLockMode::Runtime).is_err());
        assert!(
            ClientWalletLocks::acquire(&loose, &channels, WalletLockMode::Maintenance).is_err()
        );

        runtime.enter_steady_state().unwrap();
        let inspection =
            ClientWalletLocks::acquire(&loose, &channels, WalletLockMode::ReadOnly).unwrap();
        assert!(
            ClientWalletLocks::acquire(&loose, &channels, WalletLockMode::Maintenance).is_err()
        );
        drop(inspection);
        drop(runtime);

        ClientWalletLocks::acquire(&loose, &channels, WalletLockMode::Maintenance)
            .expect("maintenance after runtime exit");
    }

    #[test]
    fn same_database_path_is_deduplicated() {
        let dir = tempfile::tempdir().unwrap();
        let db = dir.path().join("wallet.db");
        let locks = ClientWalletLocks::acquire(&db, &db, WalletLockMode::Runtime).unwrap();
        assert_eq!(locks.runtime_owner.len(), 1);
        assert_eq!(locks.maintenance.len(), 1);
    }

    #[cfg(unix)]
    #[test]
    fn dangling_symlink_identity_is_stable_after_database_creation() {
        use std::os::unix::fs::symlink;

        let dir = tempfile::tempdir().unwrap();
        let target = dir.path().join("wallet.db");
        let alias = dir.path().join("wallet-alias.db");
        symlink(&target, &alias).unwrap();

        let locks = ClientWalletLocks::acquire(&alias, &alias, WalletLockMode::Runtime).unwrap();
        File::create(&target).unwrap();

        assert!(ClientWalletLocks::acquire(&alias, &alias, WalletLockMode::Runtime).is_err());
        assert!(ClientWalletLocks::acquire(&target, &target, WalletLockMode::Runtime).is_err());
        drop(locks);
        ClientWalletLocks::acquire(&target, &alias, WalletLockMode::Runtime).unwrap();
    }
}
