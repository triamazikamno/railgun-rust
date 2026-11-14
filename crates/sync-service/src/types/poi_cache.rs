use std::collections::BTreeMap;
use std::fmt;
use std::ops::{Deref, DerefMut};
use std::sync::Arc;

use alloy::primitives::FixedBytes;
use poi::cache::PoiCache;
use tokio::sync::{
    OwnedRwLockReadGuard, OwnedRwLockWriteGuard, RwLock, RwLockReadGuard, RwLockWriteGuard, watch,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PoiArtifactCachePhase {
    Idle,
    LoadingPersisted,
    Resetting,
    ResolvingManifest,
    VerifyingCatalog,
    Planning,
    DownloadingChunks,
    ReplayingRanges,
    Validating,
    Persisting,
    LiveTailing,
    Ready,
    Failed,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct PoiArtifactCacheAttemptId(u64);

impl PoiArtifactCacheAttemptId {
    #[must_use]
    pub(crate) const fn new(value: u64) -> Self {
        assert!(value != 0, "POI artifact cache attempt IDs are nonzero");
        Self(value)
    }

    #[must_use]
    pub const fn from_u64(value: u64) -> Option<Self> {
        if value == 0 { None } else { Some(Self(value)) }
    }

    #[must_use]
    pub const fn get(self) -> u64 {
        self.0
    }
}

impl fmt::Display for PoiArtifactCacheAttemptId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(formatter)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PoiArtifactCacheListProgress {
    pub list_key: FixedBytes<32>,
    pub current_event_index: Option<u64>,
    pub target_event_index: Option<u64>,
    pub ready_for_wallet_checks: bool,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct PoiArtifactCacheGraphProgress {
    pub verified_chunks: usize,
    pub total_chunks: usize,
    pub verified_encoded_bytes: u64,
    pub total_authenticated_encoded_bytes: Option<u64>,
    pub replay_start_event_index: Option<u64>,
    pub replay_end_event_index: Option<u64>,
    pub replayed_event_count: u64,
    pub total_replay_event_count: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PoiArtifactCacheFailureKind {
    RefreshDegraded,
    ServingCorpusUnavailable,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PoiArtifactCacheProgress {
    pub attempt_id: PoiArtifactCacheAttemptId,
    pub generation: u64,
    pub chain_id: u64,
    pub phase: PoiArtifactCachePhase,
    pub completed_lists: usize,
    pub total_lists: usize,
    pub current_list_key: Option<FixedBytes<32>>,
    pub current_event_index: Option<u64>,
    pub target_event_index: Option<u64>,
    pub list_progress: Vec<PoiArtifactCacheListProgress>,
    pub graph: PoiArtifactCacheGraphProgress,
    pub ready_for_wallet_checks: bool,
    pub last_error: Option<String>,
}

impl PoiArtifactCacheProgress {
    #[must_use]
    pub fn percent(&self) -> u8 {
        if self.is_ready() {
            return 100;
        }
        if self.total_lists == 0 {
            return 0;
        }

        let completed_lists = self.completed_lists.min(self.total_lists);
        let mut basis_points = completed_lists.saturating_mul(10_000) / self.total_lists;
        if completed_lists < self.total_lists
            && let (Some(current), Some(target)) =
                (self.current_event_index, self.target_event_index)
            && target > 0
        {
            let current = current.min(target);
            basis_points = basis_points.saturating_add(
                current.saturating_mul(10_000) as usize
                    / (target as usize).saturating_mul(self.total_lists),
            );
        }
        (basis_points.min(10_000) / 100) as u8
    }

    #[must_use]
    pub const fn is_active(&self) -> bool {
        matches!(
            self.phase,
            PoiArtifactCachePhase::LoadingPersisted
                | PoiArtifactCachePhase::Resetting
                | PoiArtifactCachePhase::ResolvingManifest
                | PoiArtifactCachePhase::VerifyingCatalog
                | PoiArtifactCachePhase::Planning
                | PoiArtifactCachePhase::DownloadingChunks
                | PoiArtifactCachePhase::ReplayingRanges
                | PoiArtifactCachePhase::Validating
                | PoiArtifactCachePhase::Persisting
                | PoiArtifactCachePhase::LiveTailing
        )
    }

    #[must_use]
    pub const fn is_ready(&self) -> bool {
        matches!(self.phase, PoiArtifactCachePhase::Ready) && self.ready_for_wallet_checks
    }

    #[must_use]
    pub const fn is_error(&self) -> bool {
        matches!(self.phase, PoiArtifactCachePhase::Failed)
    }

    #[must_use]
    pub const fn failure_kind(&self) -> Option<PoiArtifactCacheFailureKind> {
        if self.last_error.is_none() {
            return None;
        }
        Some(if self.ready_for_wallet_checks {
            PoiArtifactCacheFailureKind::RefreshDegraded
        } else {
            PoiArtifactCacheFailureKind::ServingCorpusUnavailable
        })
    }
}

type LocalPoiCacheMap = BTreeMap<FixedBytes<32>, PoiCache>;

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub(crate) struct PoiCorpusRevision {
    pub(crate) revision: u64,
    pub(crate) blocked_shields_revision: u64,
}

#[derive(Debug)]
struct LocalPoiCachesInner {
    caches: RwLock<LocalPoiCacheMap>,
    revision_access: Arc<RwLock<()>>,
    committed_revision_tx: watch::Sender<PoiCorpusRevision>,
}

pub(crate) struct LocalPoiCachesReadGuard<'a> {
    caches: RwLockReadGuard<'a, LocalPoiCacheMap>,
}

impl Deref for LocalPoiCachesReadGuard<'_> {
    type Target = LocalPoiCacheMap;

    fn deref(&self) -> &Self::Target {
        &self.caches
    }
}

pub(crate) struct LocalPoiCachesWriteGuard<'a> {
    caches: RwLockWriteGuard<'a, LocalPoiCacheMap>,
}

impl Deref for LocalPoiCachesWriteGuard<'_> {
    type Target = LocalPoiCacheMap;

    fn deref(&self) -> &Self::Target {
        &self.caches
    }
}

impl DerefMut for LocalPoiCachesWriteGuard<'_> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.caches
    }
}

/// A shared handle to chain-local POI caches and committed corpus revisions.
#[derive(Debug, Clone)]
pub(crate) struct LocalPoiCaches {
    inner: Arc<LocalPoiCachesInner>,
}

impl LocalPoiCaches {
    #[must_use]
    pub(crate) fn new() -> Self {
        let (committed_revision_tx, _) = watch::channel(PoiCorpusRevision::default());
        Self {
            inner: Arc::new(LocalPoiCachesInner {
                caches: RwLock::new(BTreeMap::new()),
                revision_access: Arc::new(RwLock::new(())),
                committed_revision_tx,
            }),
        }
    }

    pub(crate) async fn read(&self) -> LocalPoiCachesReadGuard<'_> {
        LocalPoiCachesReadGuard {
            caches: self.inner.caches.read().await,
        }
    }

    pub(crate) async fn write(&self) -> LocalPoiCachesWriteGuard<'_> {
        LocalPoiCachesWriteGuard {
            caches: self.inner.caches.write().await,
        }
    }

    #[must_use]
    pub(crate) fn committed_revision_rx(&self) -> watch::Receiver<PoiCorpusRevision> {
        self.inner.committed_revision_tx.subscribe()
    }

    pub(crate) fn publish_committed_revision(&self, blocked_shields_changed: bool) {
        self.inner.committed_revision_tx.send_modify(|revision| {
            revision.revision = revision.revision.wrapping_add(1).max(1);
            if blocked_shields_changed {
                revision.blocked_shields_revision =
                    revision.blocked_shields_revision.wrapping_add(1).max(1);
            }
        });
    }

    /// Excludes corpus revision publication and cache installation while the guard is held.
    ///
    /// The fence is fair, so a queued writer blocks later readers, including the wallet actor.
    /// The guard must not be held across any await served by the wallet actor (a private apply
    /// round trip or its reply); record the committed revision instead and recheck it on the
    /// actor.
    pub(crate) async fn revision_read_fence(&self) -> OwnedRwLockReadGuard<()> {
        Arc::clone(&self.inner.revision_access).read_owned().await
    }

    pub(crate) async fn revision_write_fence(&self) -> OwnedRwLockWriteGuard<()> {
        Arc::clone(&self.inner.revision_access).write_owned().await
    }
}

pub(crate) type WalletLocalPoiCaches = LocalPoiCaches;

#[cfg(test)]
impl LocalPoiCaches {
    #[must_use]
    pub(crate) fn new_for_test(caches: BTreeMap<FixedBytes<32>, PoiCache>) -> Self {
        let initial_revision = u64::from(!caches.is_empty());
        let initial_revision = PoiCorpusRevision {
            revision: initial_revision,
            blocked_shields_revision: initial_revision,
        };
        let (committed_revision_tx, _) = watch::channel(initial_revision);
        Self {
            inner: Arc::new(LocalPoiCachesInner {
                caches: RwLock::new(caches),
                revision_access: Arc::new(RwLock::new(())),
                committed_revision_tx,
            }),
        }
    }

    pub(crate) fn ptr_eq(&self, other: &Self) -> bool {
        Arc::ptr_eq(&self.inner, &other.inner)
    }
}
