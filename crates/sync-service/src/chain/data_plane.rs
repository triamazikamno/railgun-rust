use super::{
    ChainError, ChainService, DEFAULT_TXID_VERSION, EVM_CHAIN_TYPE, Future, Mutex,
    PublicDataPlaneEpoch, PublicScanReadScope, PublicScanSource, WalletScanApply,
    WalletScanInputRows, WalletScanRows, WalletScanRowsPayload, debug,
};

use std::collections::BTreeMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex as StdMutex, PoisonError, Weak};

use alloy::primitives::FixedBytes;
use local_db::DbStore;
use poi::poi::PoiStatus;
use tokio::sync::{OwnedMutexGuard, watch};
use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;

use crate::indexed_artifacts::{
    IndexedArtifactMaintenanceAdmission, IndexedArtifactMaintenanceKey,
    IndexedArtifactMaintenanceScheduler,
};
use crate::poi_cache::{PoiCacheService, PoiPublicCacheResetLease};
use crate::public_cache::{
    reset_persisted_public_sync_caches, wallet_scan_artifact_cache_generation,
};
use crate::runtime_admission::DbRuntimeLease;
use crate::types::{
    LocalPoiCaches, PoiArtifactCacheProgress, PoiCorpusRevision, WalletObservation,
};
use crate::wallet::{LocalPoiMerkleProofSource, LocalPoiStatusReader};

mod handle;
mod poi_persistence;
mod public_scan;
mod scan_state;
mod txid;
mod wallet_scan_artifacts;

pub use handle::PublicDataPlaneHandle;
#[cfg(test)]
pub(crate) use poi_persistence::commit_artifact_after_admission;
pub use poi_persistence::{PoiArtifactCacheRetry, PoiArtifactPersistenceHandle};
use scan_state::ChainPublicDataPlaneState;
pub(crate) use txid::{
    PublicTxidCacheKey, PublicTxidDataAuthority, PublicTxidLatestValidated, PublicTxidProofRequest,
    PublicTxidProofTarget, PublicTxidSyncRequest, PublicTxidTransaction,
};

const RECENT_PUBLIC_SCAN_ROW_PAGE_LIMIT: usize = 4;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PublicScanRange {
    pub from_block: u64,
    pub to_block: u64,
}

impl PublicScanRange {
    #[must_use]
    pub const fn new(from_block: u64, to_block: u64) -> Self {
        Self {
            from_block,
            to_block,
        }
    }

    #[must_use]
    pub const fn is_valid(self) -> bool {
        self.from_block <= self.to_block
    }

    #[must_use]
    pub const fn intersects_from(self, from_block: u64) -> bool {
        self.to_block >= from_block
    }

    #[must_use]
    pub const fn intersects(self, other: Self) -> bool {
        self.from_block <= other.to_block && other.from_block <= self.to_block
    }
}

#[cfg(test)]
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct PublicScanCoverageWrite {
    pub range: PublicScanRange,
    pub source: PublicScanSource,
    pub row_count: usize,
    pub read_scope: PublicScanReadScope,
}

pub(crate) struct PublicScanCommitPermit {
    _guard: tokio::sync::OwnedMutexGuard<()>,
}

pub(crate) struct PublicCacheCommitPermit {
    _guard: tokio::sync::OwnedMutexGuard<()>,
}

/// Short-lived authority preventing a public cache reset while a derived private commit applies.
pub(crate) struct ChainPublicDataPlaneCommitGuard {
    _guard: OwnedMutexGuard<()>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PublicCoverageAnswer {
    ReplayableEmpty {
        range: PublicScanRange,
        source: PublicScanSource,
        epoch: PublicDataPlaneEpoch,
    },
    CoveredWithRows {
        range: PublicScanRange,
        source: PublicScanSource,
        epoch: PublicDataPlaneEpoch,
    },
    Missing {
        range: PublicScanRange,
        epoch: PublicDataPlaneEpoch,
    },
}

#[derive(Debug, Clone)]
pub struct PublicScanRows {
    pub range: PublicScanRange,
    pub source: PublicScanSource,
    pub to_block_hash: Option<[u8; 32]>,
    pub rows: WalletScanInputRows,
    pub epoch: PublicDataPlaneEpoch,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LocalPoiQueryUnavailable {
    RequiredListsEmpty,
    SubmittedRootsEmpty,
    ListUnavailable { list_key: FixedBytes<32> },
    CacheIdentityMismatch { list_key: FixedBytes<32> },
    AcceptedRootsUnavailable { list_key: FixedBytes<32> },
    SubmittedRootAbsent { list_key: FixedBytes<32> },
    StatusUnresolved { list_key: FixedBytes<32> },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LocalPoiRootValidation {
    Accepted,
    Unavailable(LocalPoiQueryUnavailable),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LocalPoiStatusLookup {
    Valid(BTreeMap<FixedBytes<32>, PoiStatus>),
    Unavailable(LocalPoiQueryUnavailable),
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub(crate) struct PublicPoiCorpusKey {
    pub chain_type: u8,
    pub chain_id: u64,
    pub txid_version: String,
}

impl PublicPoiCorpusKey {
    pub(crate) fn new(chain_type: u8, chain_id: u64, txid_version: impl Into<String>) -> Self {
        Self {
            chain_type,
            chain_id,
            txid_version: txid_version.into(),
        }
    }

    pub(crate) fn wallet_default(chain_id: u64) -> Self {
        Self::new(EVM_CHAIN_TYPE, chain_id, DEFAULT_TXID_VERSION)
    }
}

#[derive(Debug, Clone)]
pub(crate) struct PublicPoiCorpusHandle {
    local_caches: LocalPoiCaches,
}

impl PublicPoiCorpusHandle {
    #[must_use]
    pub(crate) fn status_reader(&self) -> LocalPoiStatusReader {
        LocalPoiStatusReader::new(self.local_caches.clone())
    }

    #[must_use]
    pub(crate) fn merkle_proof_source(&self) -> LocalPoiMerkleProofSource {
        LocalPoiMerkleProofSource::new(self.local_caches.clone())
    }

    #[must_use]
    pub(crate) fn committed_revision_rx(&self) -> watch::Receiver<PoiCorpusRevision> {
        self.local_caches.committed_revision_rx()
    }

    /// See [`LocalPoiCaches::revision_read_fence`]: never hold the guard across an await served
    /// by the wallet actor.
    pub(crate) async fn revision_read_fence(&self) -> tokio::sync::OwnedRwLockReadGuard<()> {
        self.local_caches.revision_read_fence().await
    }
}

impl PublicScanRows {
    #[must_use]
    pub const fn row_count(&self) -> usize {
        self.rows.row_count()
    }
}

#[derive(Debug, Clone)]
pub enum PublicScanRowsAnswer {
    Rows(PublicScanRows),
    CompleteCoverage {
        range: PublicScanRange,
        source: PublicScanSource,
        row_count: usize,
        epoch: PublicDataPlaneEpoch,
    },
    Missing {
        range: PublicScanRange,
        epoch: PublicDataPlaneEpoch,
    },
}

impl From<WalletScanApply> for PublicScanRowsAnswer {
    fn from(apply: WalletScanApply) -> Self {
        let WalletScanApply {
            from_block,
            to_block,
            rows,
            read_scope,
        } = apply;
        let WalletScanRows {
            source,
            to_block_hash,
            payload,
            ..
        } = rows;
        let range = PublicScanRange::new(from_block, to_block);
        let epoch = read_scope.epoch();
        match payload {
            WalletScanRowsPayload::Rows(rows) => Self::Rows(PublicScanRows {
                range,
                source,
                to_block_hash,
                rows: *rows,
                epoch,
            }),
            WalletScanRowsPayload::EmptyCoverage => Self::CompleteCoverage {
                range,
                source,
                row_count: 0,
                epoch,
            },
            #[cfg(test)]
            WalletScanRowsPayload::IndexedDeltaForTest { .. } => Self::CompleteCoverage {
                range,
                source,
                row_count: 0,
                epoch,
            },
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PublicDataPlaneDiagnosticKind {
    SourceSelected,
    SourceFallback,
    ArtifactProgress,
    CoverageRecorded,
    CoverageRejected,
    CoverageInvalidated,
    PublicCacheReset,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PublicDataPlaneDiagnostic {
    pub kind: PublicDataPlaneDiagnosticKind,
    pub source: Option<PublicScanSource>,
    pub range: Option<PublicScanRange>,
    pub reason: String,
    pub epoch: PublicDataPlaneEpoch,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PublicDataPlaneDiagnostics {
    pub epoch: PublicDataPlaneEpoch,
    pub events: Vec<PublicDataPlaneDiagnostic>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ChainPublicSyncCacheReset {
    pub previous_epoch: PublicDataPlaneEpoch,
    pub new_epoch: PublicDataPlaneEpoch,
    pub coverage_entries_removed: usize,
    pub diagnostics_removed: usize,
}

impl ChainPublicSyncCacheReset {
    #[must_use]
    pub fn total_removed_entries(self) -> u64 {
        u64::try_from(self.coverage_entries_removed)
            .unwrap_or(u64::MAX)
            .saturating_add(u64::try_from(self.diagnostics_removed).unwrap_or(u64::MAX))
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PublicSyncCacheReset {
    pub previous_epoch: PublicDataPlaneEpoch,
    pub new_epoch: PublicDataPlaneEpoch,
    pub coverage_entries_removed: usize,
    pub diagnostics_removed: usize,
    pub wallet_scan_artifact_chunk_entries_removed: u64,
    pub txid_blob_entries_removed: u64,
    pub poi_artifact_checkpoint_chunk_entries_removed: u64,
    pub amount_statistics_entries_removed: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum PublicDataPlaneError {
    #[error("invalid public scan range {from_block}..={to_block}")]
    InvalidRange { from_block: u64, to_block: u64 },
    #[error("invalid completed public scan acquisition: {reason}")]
    InvalidCompletedAcquisition { reason: String },
    #[error(
        "completed public scan acquisition requires {row_pages} retained row pages, limit is {limit}"
    )]
    CompletedAcquisitionRowPageLimit { row_pages: usize, limit: usize },
    #[error(
        "RPC public scan coverage {from_block}..={to_block} from {scan_source:?} has no endpoint hash"
    )]
    UnprovenRpcCoverage {
        from_block: u64,
        to_block: u64,
        scan_source: PublicScanSource,
    },
    #[error("stale public data-plane epoch: expected {expected}, actual {actual}")]
    StaleEpoch { expected: u64, actual: u64 },
    #[error("public cache reset failed: {reason}")]
    PublicCacheReset { reason: String },
    #[error("POI corpus is unavailable for chain {chain_id} and txid version {txid_version}")]
    PoiCorpusUnavailable { chain_id: u64, txid_version: String },
    #[error("POI corpus refresh failed for chain {chain_id}: {reason}")]
    PoiCorpusRefresh { chain_id: u64, reason: String },
    #[error("POI persistence operation failed: {reason}")]
    PoiArtifactPersistence { reason: String },
}

#[derive(Debug)]
pub(crate) struct WalletScanAcquisitionCandidate {
    pub(crate) range: PublicScanRange,
    pub(crate) applies: Vec<WalletScanApply>,
}

#[derive(Debug)]
pub(crate) enum WalletScanAcquisitionOutcome {
    Retained,
    NonRetainable(PublicDataPlaneError),
    Rejected(PublicDataPlaneError),
}

#[derive(Clone)]
pub(crate) struct ChainPublicDataPlane {
    scan_service: Arc<StdMutex<Weak<ChainService>>>,
    db: Arc<DbStore>,
    epoch: Arc<AtomicU64>,
    state: Arc<Mutex<ChainPublicDataPlaneState>>,
    commit_fence: Arc<Mutex<()>>,
    indexed_artifact_maintenance: IndexedArtifactMaintenanceScheduler,
    poi_cache_service: Option<Arc<PoiCacheService>>,
    runtime_lease: Option<DbRuntimeLease>,
    window_warm: Arc<StdMutex<PublicWindowWarmSlot>>,
}

/// The chain's single background task that warms the leading part of a
/// short-startup window after the wallet's own range was delivered.
#[derive(Default)]
struct PublicWindowWarmSlot {
    /// Set while a public-cache reset permit is held.
    reset_blocked: bool,
    /// Set once the data plane shuts down.
    closed: bool,
    next_id: u64,
    active: Option<PublicWindowWarmTask>,
}

struct PublicWindowWarmTask {
    id: u64,
    cancel: CancellationToken,
    handle: JoinHandle<()>,
}

fn clear_finished_public_window_warm(slot: &StdMutex<PublicWindowWarmSlot>, id: u64) {
    let mut slot = slot.lock().unwrap_or_else(PoisonError::into_inner);
    if slot.active.as_ref().is_some_and(|active| active.id == id) {
        slot.active = None;
    }
}

pub(crate) struct PublicCacheResetPermit {
    data_plane: ChainPublicDataPlane,
    commit_guard: Option<OwnedMutexGuard<()>>,
    poi_reset_lease: Option<PoiPublicCacheResetLease>,
    window_warm_blocked: bool,
}

impl PublicCacheResetPermit {
    pub(crate) async fn apply(mut self) -> Result<ChainPublicSyncCacheReset, PublicDataPlaneError> {
        let reset = self.data_plane.invalidate_public_cache_state().await;
        self.release();
        Ok(reset)
    }

    fn release(&mut self) {
        if std::mem::take(&mut self.window_warm_blocked) {
            self.data_plane.unblock_public_window_warm();
        }
        drop(self.commit_guard.take());
        drop(self.poi_reset_lease.take());
    }
}

impl Drop for PublicCacheResetPermit {
    fn drop(&mut self) {
        self.release();
    }
}

impl ChainPublicDataPlane {
    #[must_use]
    pub(crate) fn new(db: Arc<DbStore>, epoch: Arc<AtomicU64>) -> Self {
        Self {
            scan_service: Arc::new(StdMutex::new(Weak::new())),
            db,
            epoch,
            state: Arc::new(Mutex::new(ChainPublicDataPlaneState::default())),
            commit_fence: Arc::new(Mutex::new(())),
            indexed_artifact_maintenance: IndexedArtifactMaintenanceScheduler::new(),
            poi_cache_service: None,
            runtime_lease: None,
            window_warm: Arc::new(StdMutex::new(PublicWindowWarmSlot::default())),
        }
    }

    pub(crate) fn bind_scan_service(&self, service: &Arc<ChainService>) {
        *self
            .scan_service
            .lock()
            .unwrap_or_else(PoisonError::into_inner) = Arc::downgrade(service);
    }

    /// Reads recovery rows without exposing a wallet-selected block to query-based sources.
    pub(crate) async fn output_poi_source_block_rows(
        &self,
        block_number: u64,
    ) -> Result<PublicScanRowsAnswer, ChainError> {
        let service = self
            .scan_service
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .upgrade();
        if let Some(service) = service {
            return service.output_poi_source_block_rows(block_number).await;
        }
        Ok(
            match self
                .cached_wallet_scan_apply(block_number, block_number)
                .await
            {
                Some(apply) => apply.into(),
                None => PublicScanRowsAnswer::Missing {
                    range: PublicScanRange::new(block_number, block_number),
                    epoch: self.current_epoch(),
                },
            },
        )
    }

    pub(crate) async fn saved_poi_source_block_rows(
        &self,
        block_number: u64,
    ) -> Result<PublicScanRowsAnswer, ChainError> {
        let service = self
            .scan_service
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .upgrade();
        if let Some(service) = service {
            return service
                .public_scan_rows(PublicScanRange::new(block_number, block_number))
                .await;
        }
        // Also supports standalone data planes with retained public rows.
        Ok(
            match self
                .cached_wallet_scan_apply(block_number, block_number)
                .await
            {
                Some(apply) => apply.into(),
                None => PublicScanRowsAnswer::Missing {
                    range: PublicScanRange::new(block_number, block_number),
                    epoch: self.current_epoch(),
                },
            },
        )
    }

    #[must_use]
    pub(crate) fn with_runtime_lease(mut self, runtime_lease: DbRuntimeLease) -> Self {
        self.runtime_lease = Some(runtime_lease);
        self
    }

    pub(crate) fn runtime_lease(&self) -> Option<DbRuntimeLease> {
        self.runtime_lease.clone()
    }

    pub(crate) fn poi_artifact_persistence(&self) -> PoiArtifactPersistenceHandle {
        let persistence =
            PoiArtifactPersistenceHandle::new(Arc::clone(&self.db), Arc::clone(&self.commit_fence));
        match self.runtime_lease.as_ref() {
            Some(runtime_lease) => persistence.with_runtime_lease(runtime_lease.clone()),
            None => persistence,
        }
    }

    #[must_use]
    pub(crate) fn with_poi_cache_service(mut self, service: Arc<PoiCacheService>) -> Self {
        self.poi_cache_service = Some(service);
        self
    }

    pub(crate) async fn update_poi_cache_demand(
        &self,
        actor_id: u64,
        observation: &WalletObservation,
    ) {
        if let Some(service) = self.poi_cache_service.as_ref() {
            service.update_wallet_demand(actor_id, observation).await;
        }
    }

    pub(crate) async fn clear_poi_cache_demand(&self, actor_id: u64) {
        if let Some(service) = self.poi_cache_service.as_ref() {
            service.clear_wallet_demand(actor_id).await;
        }
    }

    pub(crate) async fn shutdown(&self) {
        self.begin_shutdown();
        self.quiesce_public_window_warm().await;
        self.indexed_artifact_maintenance.shutdown().await;
        if let Some(service) = self.poi_cache_service.as_ref() {
            service.shutdown().await;
        }
        let _commit_drain = self.commit_fence.lock().await;
    }

    pub(crate) fn begin_shutdown(&self) {
        {
            let mut slot = self
                .window_warm
                .lock()
                .unwrap_or_else(PoisonError::into_inner);
            slot.closed = true;
            if let Some(active) = slot.active.as_ref() {
                active.cancel.cancel();
            }
        }
        self.indexed_artifact_maintenance.begin_shutdown();
        if let Some(service) = self.poi_cache_service.as_ref() {
            service.begin_shutdown();
        }
    }

    /// Starts the chain's background window-warm task unless one is already
    /// running or starts are blocked by a public-cache reset or shutdown.
    ///
    /// The task receives a child of `parent`, so cancelling the chain service
    /// also stops it. Returns whether a task was started.
    pub(crate) fn try_start_public_window_warm<F, Fut>(
        &self,
        parent: &CancellationToken,
        warm: F,
    ) -> bool
    where
        F: FnOnce(CancellationToken) -> Fut,
        Fut: Future<Output = ()> + Send + 'static,
    {
        let mut slot = self
            .window_warm
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        if slot.reset_blocked || slot.closed || slot.active.is_some() || parent.is_cancelled() {
            return false;
        }
        let id = slot.next_id;
        slot.next_id = slot.next_id.wrapping_add(1);
        let cancel = parent.child_token();
        let task = warm(cancel.clone());
        let window_warm = Arc::clone(&self.window_warm);
        // The slot lock is held until the task is recorded, so its exit
        // cleanup cannot run before the task is visible to resets.
        let handle = tokio::spawn(async move {
            task.await;
            clear_finished_public_window_warm(&window_warm, id);
        });
        slot.active = Some(PublicWindowWarmTask { id, cancel, handle });
        true
    }

    /// Blocks new window-warm starts, cancels the running task, and waits for
    /// it to exit.
    async fn quiesce_public_window_warm(&self) {
        let active = {
            let mut slot = self
                .window_warm
                .lock()
                .unwrap_or_else(PoisonError::into_inner);
            slot.reset_blocked = true;
            slot.active.take()
        };
        if let Some(active) = active {
            active.cancel.cancel();
            if let Err(err) = active.handle.await {
                debug!(?err, "public window warm task ended abnormally");
            }
        }
    }

    fn unblock_public_window_warm(&self) {
        self.window_warm
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .reset_blocked = false;
    }

    #[cfg(test)]
    pub(crate) fn public_window_warm_running(&self) -> bool {
        self.window_warm
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .active
            .is_some()
    }

    pub(crate) fn schedule_indexed_artifact_maintenance<F>(
        &self,
        key: IndexedArtifactMaintenanceKey,
        retained_payload_bytes: u64,
        job: F,
    ) -> IndexedArtifactMaintenanceAdmission
    where
        F: Future<Output = ()> + Send + 'static,
    {
        let runtime_lease = self.runtime_lease.clone();
        self.indexed_artifact_maintenance
            .try_schedule(key, retained_payload_bytes, async move {
                job.await;
                drop(runtime_lease);
            })
    }

    pub(crate) fn indexed_artifact_maintenance(&self) -> IndexedArtifactMaintenanceScheduler {
        self.indexed_artifact_maintenance.clone()
    }

    #[must_use]
    pub(crate) fn current_epoch(&self) -> PublicDataPlaneEpoch {
        PublicDataPlaneEpoch::new(self.epoch.load(Ordering::Acquire))
    }

    pub(crate) async fn acquire_commit_guard(&self) -> ChainPublicDataPlaneCommitGuard {
        ChainPublicDataPlaneCommitGuard {
            _guard: Arc::clone(&self.commit_fence).lock_owned().await,
        }
    }

    #[must_use]
    pub(crate) fn begin_public_scan_read(&self) -> PublicScanReadScope {
        PublicScanReadScope::new(self.current_epoch())
    }

    pub(crate) fn wallet_scan_artifact_cache_generation(&self) -> u64 {
        wallet_scan_artifact_cache_generation(self.db.as_ref())
    }

    pub(crate) async fn cached_public_scan_coverage(
        &self,
        range: PublicScanRange,
    ) -> PublicCoverageAnswer {
        let state = self.state.lock().await;
        let epoch = self.current_epoch();
        state.coverage_for_range(range, epoch).map_or(
            PublicCoverageAnswer::Missing { range, epoch },
            |coverage| {
                let range = PublicScanRange::new(range.from_block, coverage.covered_to);
                if coverage.has_rows {
                    PublicCoverageAnswer::CoveredWithRows {
                        range,
                        source: coverage.source,
                        epoch,
                    }
                } else {
                    PublicCoverageAnswer::ReplayableEmpty {
                        range,
                        source: coverage.source,
                        epoch,
                    }
                }
            },
        )
    }

    pub(crate) async fn diagnostics(&self) -> PublicDataPlaneDiagnostics {
        let state = self.state.lock().await;
        PublicDataPlaneDiagnostics {
            epoch: self.current_epoch(),
            events: state.diagnostics.clone(),
        }
    }

    pub(crate) async fn reset_public_cache(
        &self,
    ) -> Result<PublicSyncCacheReset, PublicDataPlaneError> {
        let permit = self.acquire_public_cache_reset_permit().await;
        let persisted = reset_persisted_public_sync_caches(self.db.as_ref())
            .await
            .map_err(|err| PublicDataPlaneError::PublicCacheReset {
                reason: err.to_string(),
            })?;
        let chain_reset = permit.apply().await?;
        Ok(PublicSyncCacheReset {
            previous_epoch: chain_reset.previous_epoch,
            new_epoch: chain_reset.new_epoch,
            coverage_entries_removed: chain_reset.coverage_entries_removed,
            diagnostics_removed: chain_reset.diagnostics_removed,
            wallet_scan_artifact_chunk_entries_removed: persisted
                .wallet_scan_artifact_chunk_entries_removed,
            txid_blob_entries_removed: persisted.txid_blob_entries_removed,
            poi_artifact_checkpoint_chunk_entries_removed: persisted
                .poi_artifact_checkpoint_chunk_entries_removed,
            amount_statistics_entries_removed: persisted.amount_statistics_entries_removed,
        })
    }

    async fn acquire_public_cache_reset_permit(&self) -> PublicCacheResetPermit {
        let poi_reset_lease = if let Some(service) = self.poi_cache_service.as_ref() {
            Some(service.quiesce_for_public_cache_reset().await)
        } else {
            None
        };
        let commit_guard = Arc::clone(&self.commit_fence).lock_owned().await;
        // Window warming is quiesced under the commit fence, so concurrent
        // resets take turns and each one waits for the task it cancelled. The
        // warm task never takes the fence, so waiting here cannot deadlock.
        // The permit exists first so that dropping this future mid-wait
        // unblocks warm starts again.
        let permit = PublicCacheResetPermit {
            data_plane: self.clone(),
            commit_guard: Some(commit_guard),
            poi_reset_lease,
            window_warm_blocked: true,
        };
        permit.data_plane.quiesce_public_window_warm().await;
        permit
    }

    async fn invalidate_public_cache_state(&self) -> ChainPublicSyncCacheReset {
        let (previous_epoch, new_epoch, coverage_entries_removed, diagnostics_removed) = {
            let mut state = self.state.lock().await;
            let previous_epoch = self.current_epoch();
            let coverage_entries_removed = state.coverage.len();
            let diagnostics_removed = state.diagnostics.len();
            state.coverage.clear();
            state.recent_scan_rows.clear();
            state.diagnostics.clear();
            let new_epoch = self.bump_epoch_locked(previous_epoch);
            state.push_diagnostic(PublicDataPlaneDiagnostic {
                kind: PublicDataPlaneDiagnosticKind::PublicCacheReset,
                source: None,
                range: None,
                reason: "public sync cache reset".to_string(),
                epoch: new_epoch,
            });
            (
                previous_epoch,
                new_epoch,
                coverage_entries_removed,
                diagnostics_removed,
            )
        };
        ChainPublicSyncCacheReset {
            previous_epoch,
            new_epoch,
            coverage_entries_removed,
            diagnostics_removed,
        }
    }

    pub(crate) async fn ensure_poi_corpus(
        &self,
        key: PublicPoiCorpusKey,
    ) -> Result<PublicPoiCorpusHandle, PublicDataPlaneError> {
        let Some(service) = self.poi_cache_service.as_ref() else {
            return Err(PublicDataPlaneError::PoiCorpusUnavailable {
                chain_id: key.chain_id,
                txid_version: key.txid_version,
            });
        };
        let local_caches = service.start_chain(key.chain_id).await.map_err(|err| {
            PublicDataPlaneError::PoiCorpusRefresh {
                chain_id: key.chain_id,
                reason: err.to_string(),
            }
        })?;
        let mut state = self.state.lock().await;
        let local_caches = state
            .poi_corpora
            .entry(key)
            .or_insert_with(|| local_caches.clone())
            .clone();
        Ok(PublicPoiCorpusHandle { local_caches })
    }

    fn poi_artifact_cache_progress_rx(
        &self,
    ) -> Option<watch::Receiver<BTreeMap<u64, PoiArtifactCacheProgress>>> {
        self.poi_cache_service
            .as_ref()
            .map(|service| service.progress_rx())
    }

    pub(crate) async fn retry_poi_artifact_cache(
        &self,
        chain_id: u64,
    ) -> Result<PoiArtifactCacheRetry, PublicDataPlaneError> {
        let Some(service) = self.poi_cache_service.as_ref() else {
            return Err(PublicDataPlaneError::PoiCorpusUnavailable {
                chain_id,
                txid_version: DEFAULT_TXID_VERSION.to_string(),
            });
        };
        service
            .retry_chain(chain_id)
            .await
            .map(|retry| PoiArtifactCacheRetry { chain_id, retry })
            .map_err(|reason| PublicDataPlaneError::PoiCorpusRefresh {
                chain_id,
                reason: reason.to_string(),
            })
    }

    pub(crate) async fn retry_poi_artifact_cache_events(
        &self,
        chain_id: u64,
    ) -> Result<PoiArtifactCacheRetry, PublicDataPlaneError> {
        let Some(service) = self.poi_cache_service.as_ref() else {
            return Err(PublicDataPlaneError::PoiCorpusUnavailable {
                chain_id,
                txid_version: DEFAULT_TXID_VERSION.to_string(),
            });
        };
        service
            .retry_chain_events(chain_id)
            .await
            .map(|retry| PoiArtifactCacheRetry { chain_id, retry })
            .map_err(|reason| PublicDataPlaneError::PoiCorpusRefresh {
                chain_id,
                reason: reason.to_string(),
            })
    }

    pub(crate) async fn poi_corpus_ready_for_lists(
        &self,
        key: PublicPoiCorpusKey,
        active_list_keys: &[FixedBytes<32>],
    ) -> bool {
        if active_list_keys.is_empty() {
            return true;
        }
        let Ok(corpus) = self.ensure_poi_corpus(key.clone()).await else {
            return false;
        };
        let caches = corpus.local_caches.read().await;
        active_list_keys.iter().all(|list_key| {
            caches.get(list_key).is_some_and(|cache| {
                cache.identity().chain_type == key.chain_type
                    && cache.identity().chain_id == key.chain_id
                    && cache.identity().txid_version == key.txid_version
                    && (cache.progress().next_event_index > 0
                        || cache.progress().next_leaf_index > 0)
            })
        })
    }
}

#[cfg(test)]
impl PublicPoiCorpusHandle {
    #[must_use]
    pub(crate) const fn new_for_test(local_caches: LocalPoiCaches) -> Self {
        Self { local_caches }
    }

    #[must_use]
    pub(crate) fn local_caches(&self) -> LocalPoiCaches {
        self.local_caches.clone()
    }
}

#[cfg(test)]
mod tests;
