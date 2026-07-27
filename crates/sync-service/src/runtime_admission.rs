use std::collections::HashMap;
use std::fmt;
use std::path::{Path, PathBuf};
use std::sync::{Arc, LazyLock, Mutex, Weak};

use local_db::DbStore;

static DB_RUNTIME_OWNERS: LazyLock<Mutex<HashMap<PathBuf, Weak<DbRuntimeOwner>>>> =
    LazyLock::new(|| Mutex::new(HashMap::new()));

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum DbRuntimeOwnerKind {
    SyncManager,
    OfflinePoiReset,
}

impl fmt::Display for DbRuntimeOwnerKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::SyncManager => "an active sync manager",
            Self::OfflinePoiReset => "an offline POI reset",
        })
    }
}

#[derive(Debug, thiserror::Error)]
#[error("database runtime at {path} is already owned by {active}")]
pub(crate) struct DbRuntimeAdmissionError {
    pub(crate) path: PathBuf,
    pub(crate) active: DbRuntimeOwnerKind,
}

struct DbRuntimeOwner {
    kind: DbRuntimeOwnerKind,
}

#[derive(Clone)]
pub(crate) struct DbRuntimeLease {
    _owner: Arc<DbRuntimeOwner>,
}

impl DbRuntimeLease {
    pub(crate) fn acquire(
        db: &DbStore,
        kind: DbRuntimeOwnerKind,
    ) -> Result<Self, DbRuntimeAdmissionError> {
        Self::acquire_path(db.root_dir(), kind)
    }

    fn acquire_path(
        path: &Path,
        kind: DbRuntimeOwnerKind,
    ) -> Result<Self, DbRuntimeAdmissionError> {
        let path = path.to_path_buf();
        let mut owners = DB_RUNTIME_OWNERS
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        owners.retain(|_, owner| owner.strong_count() > 0);
        if let Some(active) = owners
            .get(&path)
            .and_then(Weak::upgrade)
            .map(|owner| owner.kind)
        {
            return Err(DbRuntimeAdmissionError { path, active });
        }
        let owner = Arc::new(DbRuntimeOwner { kind });
        owners.insert(path, Arc::downgrade(&owner));
        Ok(Self { _owner: owner })
    }
}

#[cfg(test)]
mod tests {
    use std::sync::{Arc, Barrier};
    use std::thread;

    use super::*;

    #[test]
    fn competing_runtime_kinds_have_one_winner() {
        let path = PathBuf::from("runtime-admission-race");
        let start = Arc::new(Barrier::new(2));
        let finish = Arc::new(Barrier::new(2));
        let acquire = |kind, start: Arc<Barrier>, finish: Arc<Barrier>| {
            let path = path.clone();
            thread::spawn(move || {
                start.wait();
                let result = DbRuntimeLease::acquire_path(&path, kind);
                finish.wait();
                result
            })
        };
        let manager = acquire(
            DbRuntimeOwnerKind::SyncManager,
            Arc::clone(&start),
            Arc::clone(&finish),
        );
        let reset = acquire(DbRuntimeOwnerKind::OfflinePoiReset, start, finish);

        let manager = manager.join().expect("manager admission thread");
        let reset = reset.join().expect("reset admission thread");
        assert_eq!(usize::from(manager.is_ok()) + usize::from(reset.is_ok()), 1);
    }

    #[test]
    fn acquisition_prunes_dead_paths_and_allows_replacement() {
        let dead_path = PathBuf::from("runtime-admission-dead");
        let next_path = PathBuf::from("runtime-admission-next");
        let lease = DbRuntimeLease::acquire_path(&dead_path, DbRuntimeOwnerKind::OfflinePoiReset)
            .expect("acquire dead-path lease");
        drop(lease);

        let replacement = DbRuntimeLease::acquire_path(&next_path, DbRuntimeOwnerKind::SyncManager)
            .expect("acquire next-path lease");
        let owners = DB_RUNTIME_OWNERS
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        assert!(!owners.contains_key(&dead_path));
        assert!(owners.contains_key(&next_path));
        drop(owners);
        drop(replacement);

        DbRuntimeLease::acquire_path(&next_path, DbRuntimeOwnerKind::OfflinePoiReset)
            .expect("replace released manager lease");
    }
}
