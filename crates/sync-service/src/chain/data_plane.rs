use super::*;

use std::collections::BTreeMap;
use std::fs;
use std::io::ErrorKind;
use std::path::Path;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

use alloy::primitives::{FixedBytes, U256};
use local_db::{BlobMeta, DbStore};
use merkletree::tree::MerkleProof;
use sha2::{Digest, Sha256};
use url::Url;

use crate::indexed_artifacts::{
    ChainScope, ChainType, IndexedArtifactDescriptor, IndexedArtifactRangeKind, IndexedDatasetKind,
    VerifiedIndexedArtifactChunk, format_scope, verify_chunk_bytes,
};
use crate::poi_artifacts::clear_poi_artifact_cache_for_reset;
use crate::poi_cache::PoiCacheService;
use crate::txid_cache::{
    TxidPublicCache, TxidPublicCacheError, TxidPublicCacheKey, TxidPublicLatestValidated,
    reset_txid_public_cache, txid_public_proof_for_recovered_output,
    txid_public_proof_for_recovered_output_at_index,
};
use crate::types::{IndexedArtifactSourceConfig, LocalPoiCaches};

const PUBLIC_DATA_PLANE_DIAGNOSTIC_LIMIT: usize = 128;
const WALLET_SCAN_ARTIFACT_CHUNK_BLOB_KIND: &str = "wallet_scan_artifact_chunks";
const WALLET_SCAN_ARTIFACT_CHUNK_CACHE_FORMAT_VERSION: u32 = 1;
static WALLET_SCAN_ARTIFACT_CHUNK_TEMP_COUNTER: AtomicU64 = AtomicU64::new(0);

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

#[derive(Clone)]
pub(crate) struct PublicPoiCorpusHandle {
    local_caches: LocalPoiCaches,
}

impl PublicPoiCorpusHandle {
    #[must_use]
    pub(crate) fn local_caches(&self) -> LocalPoiCaches {
        self.local_caches.clone()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct PublicTxidCacheKey {
    pub scope: ChainScope,
    pub txid_version: String,
}

impl PublicTxidCacheKey {
    pub(crate) fn new(scope: ChainScope, txid_version: impl Into<String>) -> Self {
        Self {
            scope,
            txid_version: txid_version.into(),
        }
    }

    fn as_cache_key(&self) -> TxidPublicCacheKey<'_> {
        TxidPublicCacheKey {
            chain_type: match self.scope.chain_type {
                ChainType::Evm => EVM_CHAIN_TYPE,
            },
            chain_id: self.scope.chain_id,
            railgun_contract: self.scope.railgun_contract,
            txid_version: &self.txid_version,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct PublicTxidLatestValidated {
    pub txid_index: u64,
    pub merkleroot: Option<FixedBytes<32>>,
}

impl From<TxidPublicLatestValidated> for PublicTxidLatestValidated {
    fn from(latest: TxidPublicLatestValidated) -> Self {
        Self {
            txid_index: latest.txid_index,
            merkleroot: latest.merkleroot,
        }
    }
}

impl From<PublicTxidLatestValidated> for TxidPublicLatestValidated {
    fn from(latest: PublicTxidLatestValidated) -> Self {
        Self {
            txid_index: latest.txid_index,
            merkleroot: latest.merkleroot,
        }
    }
}

pub(crate) struct PublicTxidSyncRequest<'a> {
    pub key: PublicTxidCacheKey,
    pub endpoint: Option<&'a Url>,
    pub http_client: Option<&'a reqwest::Client>,
    pub latest: PublicTxidLatestValidated,
    pub indexed_artifact_source: Option<&'a IndexedArtifactSourceConfig>,
}

#[derive(Debug, Clone, Copy)]
pub(crate) enum PublicTxidProofTarget {
    KnownIndex {
        txid_index: u64,
        expected_leaf_hash: U256,
        output_start_global: u128,
    },
    UnknownIndex {
        expected_leaf_hash: U256,
        output_start_global: u128,
    },
}

impl PublicTxidProofTarget {
    pub(crate) const fn txid_index(self) -> Option<u64> {
        match self {
            Self::KnownIndex { txid_index, .. } => Some(txid_index),
            Self::UnknownIndex { .. } => None,
        }
    }

    const fn proof_inputs(self) -> (U256, u128) {
        match self {
            Self::KnownIndex {
                expected_leaf_hash,
                output_start_global,
                ..
            }
            | Self::UnknownIndex {
                expected_leaf_hash,
                output_start_global,
            } => (expected_leaf_hash, output_start_global),
        }
    }
}

pub(crate) struct PublicTxidProofRequest {
    pub key: PublicTxidCacheKey,
    pub target: PublicTxidProofTarget,
}

#[derive(Debug, Clone)]
pub(crate) struct PublicTxidProof {
    pub latest_validated: PublicTxidLatestValidated,
    pub target_txid_index: u64,
    pub root_txid_index: u64,
    pub proof: MerkleProof,
}

#[derive(Clone)]
pub struct PublicDataPlaneHandle {
    service: Arc<ChainService>,
}

impl PublicDataPlaneHandle {
    #[must_use]
    pub(crate) fn new(service: Arc<ChainService>) -> Self {
        Self { service }
    }

    pub async fn public_scan_rows(
        &self,
        range: PublicScanRange,
    ) -> Result<PublicScanRowsAnswer, ChainError> {
        self.service.public_scan_rows(range).await
    }

    pub async fn public_scan_coverage(
        &self,
        range: PublicScanRange,
    ) -> Result<PublicCoverageAnswer, ChainError> {
        self.service.public_scan_coverage(range).await
    }

    pub async fn diagnostics(&self) -> PublicDataPlaneDiagnostics {
        self.service.public_data_plane.diagnostics().await
    }

    pub async fn reset_public_cache(&self) -> Result<PublicSyncCacheReset, PublicDataPlaneError> {
        self.service.public_data_plane.reset_public_cache().await
    }
}

impl PublicScanRows {
    #[must_use]
    pub fn row_count(&self) -> usize {
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

impl PublicScanRowsAnswer {
    pub(crate) fn from_wallet_scan_apply(apply: WalletScanApply) -> Self {
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
pub struct PublicSyncCacheReset {
    pub previous_epoch: PublicDataPlaneEpoch,
    pub new_epoch: PublicDataPlaneEpoch,
    pub coverage_entries_removed: usize,
    pub diagnostics_removed: usize,
    pub wallet_scan_artifact_chunk_entries_removed: u64,
    pub wallet_scan_artifact_chunk_files_removed: u64,
    pub txid_blob_entries_removed: u64,
    pub txid_files_removed: u64,
    pub poi_cache_entries_removed: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum PublicDataPlaneError {
    #[error("invalid public scan range {from_block}..={to_block}")]
    InvalidRange { from_block: u64, to_block: u64 },
    #[error("stale public data-plane epoch: expected {expected}, actual {actual}")]
    StaleEpoch { expected: u64, actual: u64 },
    #[error("public cache reset failed: {reason}")]
    PublicCacheReset { reason: String },
    #[error("POI corpus is unavailable for chain {chain_id} and txid version {txid_version}")]
    PoiCorpusUnavailable { chain_id: u64, txid_version: String },
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct PublicScanCoverageRecord {
    range: PublicScanRange,
    source: PublicScanSource,
    row_count: usize,
    epoch: PublicDataPlaneEpoch,
}

#[derive(Debug, Default)]
struct PublicCoverageStore {
    records: Vec<PublicScanCoverageRecord>,
}

impl PublicCoverageStore {
    fn len(&self) -> usize {
        self.records.len()
    }

    fn clear(&mut self) {
        self.records.clear();
    }

    fn retain_epoch(&mut self, epoch: PublicDataPlaneEpoch) {
        self.records.retain(|record| record.epoch == epoch);
    }

    fn insert_canonical(&mut self, record: PublicScanCoverageRecord) {
        self.retain_epoch(record.epoch);
        let mut records = Vec::with_capacity(self.records.len() + 2);
        for existing in self.records.drain(..) {
            if !existing.range.intersects(record.range) {
                records.push(existing);
                continue;
            }

            if existing.range.from_block < record.range.from_block {
                let mut left = existing.clone();
                left.range.to_block = record.range.from_block.saturating_sub(1);
                if left.range.is_valid() {
                    records.push(left);
                }
            }
            if existing.range.to_block > record.range.to_block {
                let mut right = existing;
                right.range.from_block = record.range.to_block.saturating_add(1);
                if right.range.is_valid() {
                    records.push(right);
                }
            }
        }
        records.push(record);
        records.sort_by_key(|coverage| (coverage.range.from_block, coverage.range.to_block));
        self.records = records;
    }

    fn invalidate_from(&mut self, from_block: u64) -> usize {
        let mut records = Vec::with_capacity(self.records.len());
        let mut affected = 0;
        for mut record in self.records.drain(..) {
            if !record.range.intersects_from(from_block) {
                records.push(record);
                continue;
            }

            affected += 1;
            if record.range.from_block < from_block {
                record.range.to_block = from_block.saturating_sub(1);
                if record.range.is_valid() {
                    records.push(record);
                }
            }
        }
        self.records = records;
        affected
    }

    fn restamp_epoch(&mut self, epoch: PublicDataPlaneEpoch) {
        for record in &mut self.records {
            record.epoch = epoch;
        }
    }

    fn coverage_for_range(
        &self,
        range: PublicScanRange,
        epoch: PublicDataPlaneEpoch,
    ) -> Option<CoverageForRange> {
        if !range.is_valid() {
            return None;
        }
        let mut next_block = range.from_block;
        let mut covered_to = None;
        let mut source = None;
        let mut has_rows = false;
        for record in &self.records {
            if record.epoch != epoch || record.range.to_block < next_block {
                continue;
            }
            if record.range.from_block > next_block {
                break;
            }
            let record_to = record.range.to_block.min(range.to_block);
            if record_to < next_block {
                continue;
            }
            covered_to = Some(record_to);
            source.get_or_insert(record.source);
            has_rows |= record.row_count > 0;
            if record_to >= range.to_block {
                break;
            }
            next_block = record_to.saturating_add(1);
        }
        covered_to.map(|covered_to| CoverageForRange {
            covered_to,
            source: source.unwrap_or(PublicScanSource::CachedCoverage),
            has_rows,
        })
    }

    fn empty_coverage_prefix_for_range(
        &self,
        range: PublicScanRange,
        epoch: PublicDataPlaneEpoch,
    ) -> Option<u64> {
        if !range.is_valid() {
            return None;
        }
        let mut next_block = range.from_block;
        let mut covered_to = None;
        for record in &self.records {
            if record.epoch != epoch || record.range.to_block < next_block {
                continue;
            }
            if record.range.from_block > next_block || record.row_count != 0 {
                break;
            }
            let record_to = record.range.to_block.min(range.to_block);
            if record_to < next_block {
                continue;
            }
            covered_to = Some(record_to);
            if record_to >= range.to_block {
                break;
            }
            next_block = record_to.saturating_add(1);
        }
        covered_to
    }

    #[cfg(test)]
    fn records(&self) -> &[PublicScanCoverageRecord] {
        &self.records
    }
}

#[derive(Debug, Default)]
struct ChainPublicDataPlaneState {
    coverage: PublicCoverageStore,
    diagnostics: Vec<PublicDataPlaneDiagnostic>,
    poi_corpora: BTreeMap<PublicPoiCorpusKey, LocalPoiCaches>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct WalletScanArtifactChunkCacheReset {
    blob_entries_removed: u64,
    files_removed: u64,
}

impl ChainPublicDataPlaneState {
    fn insert_canonical_coverage(&mut self, record: PublicScanCoverageRecord) {
        self.coverage.insert_canonical(record);
    }

    fn coverage_for_range(
        &self,
        range: PublicScanRange,
        epoch: PublicDataPlaneEpoch,
    ) -> Option<CoverageForRange> {
        self.coverage.coverage_for_range(range, epoch)
    }

    fn empty_coverage_prefix_for_range(
        &self,
        range: PublicScanRange,
        epoch: PublicDataPlaneEpoch,
    ) -> Option<u64> {
        self.coverage.empty_coverage_prefix_for_range(range, epoch)
    }

    fn push_diagnostic(&mut self, diagnostic: PublicDataPlaneDiagnostic) {
        self.diagnostics.push(diagnostic);
        let overflow = self
            .diagnostics
            .len()
            .saturating_sub(PUBLIC_DATA_PLANE_DIAGNOSTIC_LIMIT);
        if overflow > 0 {
            self.diagnostics.drain(0..overflow);
        }
    }
}

#[derive(Clone)]
pub(crate) struct ChainPublicDataPlane {
    db: Arc<DbStore>,
    epoch: Arc<AtomicU64>,
    state: Arc<Mutex<ChainPublicDataPlaneState>>,
    commit_fence: Arc<Mutex<()>>,
    poi_cache_service: Option<Arc<PoiCacheService>>,
}

impl ChainPublicDataPlane {
    #[must_use]
    pub(crate) fn new(db: Arc<DbStore>, epoch: Arc<AtomicU64>) -> Self {
        Self {
            db,
            epoch,
            state: Arc::new(Mutex::new(ChainPublicDataPlaneState::default())),
            commit_fence: Arc::new(Mutex::new(())),
            poi_cache_service: None,
        }
    }

    #[must_use]
    pub(crate) fn with_poi_cache_service(mut self, service: Arc<PoiCacheService>) -> Self {
        self.poi_cache_service = Some(service);
        self
    }

    pub(crate) fn shutdown(&self) {
        if let Some(service) = self.poi_cache_service.as_ref() {
            service.shutdown();
        }
    }

    #[must_use]
    pub(crate) fn current_epoch(&self) -> PublicDataPlaneEpoch {
        PublicDataPlaneEpoch::new(self.epoch.load(Ordering::Acquire))
    }

    #[must_use]
    pub(crate) fn begin_public_scan_read(&self) -> PublicScanReadScope {
        PublicScanReadScope::new(self.current_epoch())
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
        let _commit_guard = self.commit_fence.lock().await;
        let (previous_epoch, new_epoch, coverage_entries_removed, diagnostics_removed) = {
            let mut state = self.state.lock().await;
            let previous_epoch = self.current_epoch();
            let coverage_entries_removed = state.coverage.len();
            let diagnostics_removed = state.diagnostics.len();
            state.coverage.clear();
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

        let txid_reset = reset_txid_public_cache(self.db.as_ref())
            .await
            .map_err(|err| PublicDataPlaneError::PublicCacheReset {
                reason: err.to_string(),
            })?;
        let wallet_scan_chunk_reset = self
            .reset_wallet_scan_artifact_chunk_cache()
            .map_err(|reason| PublicDataPlaneError::PublicCacheReset { reason })?;
        let poi_cache_entries_removed = if let Some(service) = self.poi_cache_service.as_ref() {
            service.reset_poi_artifact_cache().await.map_err(|err| {
                PublicDataPlaneError::PublicCacheReset {
                    reason: err.to_string(),
                }
            })?
        } else {
            self.clear_in_memory_poi_corpora().await;
            clear_poi_artifact_cache_for_reset(&self.db).map_err(|err| {
                PublicDataPlaneError::PublicCacheReset {
                    reason: err.to_string(),
                }
            })?
        };
        Ok(PublicSyncCacheReset {
            previous_epoch,
            new_epoch,
            coverage_entries_removed,
            diagnostics_removed,
            wallet_scan_artifact_chunk_entries_removed: wallet_scan_chunk_reset
                .blob_entries_removed,
            wallet_scan_artifact_chunk_files_removed: wallet_scan_chunk_reset.files_removed,
            txid_blob_entries_removed: txid_reset.blob_entries_removed,
            txid_files_removed: txid_reset.files_removed,
            poi_cache_entries_removed,
        })
    }

    pub(crate) async fn ensure_poi_corpus(
        &self,
        key: PublicPoiCorpusKey,
    ) -> Result<PublicPoiCorpusHandle, PublicDataPlaneError> {
        if let Some(existing) = self.state.lock().await.poi_corpora.get(&key).cloned() {
            return Ok(PublicPoiCorpusHandle {
                local_caches: existing,
            });
        }
        let Some(service) = self.poi_cache_service.as_ref() else {
            return Err(PublicDataPlaneError::PoiCorpusUnavailable {
                chain_id: key.chain_id,
                txid_version: key.txid_version,
            });
        };
        let local_caches = service.start_chain(key.chain_id).await;
        let mut state = self.state.lock().await;
        let local_caches = state
            .poi_corpora
            .entry(key)
            .or_insert_with(|| local_caches.clone())
            .clone();
        Ok(PublicPoiCorpusHandle { local_caches })
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
        let local_caches = corpus.local_caches();
        let caches = local_caches.read().await;
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

    async fn clear_in_memory_poi_corpora(&self) {
        let corpora = self
            .state
            .lock()
            .await
            .poi_corpora
            .values()
            .cloned()
            .collect::<Vec<_>>();
        for corpus in corpora {
            corpus.write().await.clear();
        }
    }

    pub(crate) fn cached_txid_latest_validated(
        &self,
        key: &PublicTxidCacheKey,
    ) -> Result<Option<PublicTxidLatestValidated>, TxidPublicCacheError> {
        let cache = TxidPublicCache::new(self.db.as_ref(), key.as_cache_key());
        cache
            .cached_latest_validated()
            .map(|latest| latest.map(Into::into))
    }

    pub(crate) async fn sync_txid_public_cache(
        &self,
        request: PublicTxidSyncRequest<'_>,
    ) -> Result<(), TxidPublicCacheError> {
        let cache = TxidPublicCache::new(self.db.as_ref(), request.key.as_cache_key());
        cache
            .sync_with_artifact_source(
                request.endpoint,
                request.http_client,
                request.latest.into(),
                request.indexed_artifact_source,
            )
            .await
    }

    pub(crate) fn txid_public_proof(
        &self,
        request: PublicTxidProofRequest,
    ) -> Result<PublicTxidProof, TxidPublicCacheError> {
        let key = request.key.as_cache_key();
        let cache = TxidPublicCache::new(self.db.as_ref(), key);
        let latest =
            cache
                .cached_latest_validated()?
                .ok_or(TxidPublicCacheError::CacheNotReady {
                    next_index: 0,
                    required_index: request.target.txid_index().unwrap_or(0),
                })?;
        let (expected_leaf_hash, output_start_global) = request.target.proof_inputs();
        let proof = match request.target {
            PublicTxidProofTarget::KnownIndex { txid_index, .. } => {
                txid_public_proof_for_recovered_output_at_index(
                    self.db.as_ref(),
                    key,
                    txid_index,
                    expected_leaf_hash,
                    output_start_global,
                    latest.txid_index,
                    latest.merkleroot,
                )
            }
            PublicTxidProofTarget::UnknownIndex { .. } => txid_public_proof_for_recovered_output(
                self.db.as_ref(),
                key,
                expected_leaf_hash,
                output_start_global,
                latest.txid_index,
                latest.merkleroot,
            ),
        }?;
        if proof.target_txid_index > latest.txid_index || proof.root_txid_index > latest.txid_index
        {
            return Err(TxidPublicCacheError::MetadataMismatch(
                "TXID proof extends beyond its validated marker".to_string(),
            ));
        }
        Ok(PublicTxidProof {
            latest_validated: latest.into(),
            target_txid_index: proof.target_txid_index,
            root_txid_index: proof.root_txid_index,
            proof: proof.proof,
        })
    }

    pub(crate) fn cached_wallet_scan_artifact_chunk(
        &self,
        descriptor: &IndexedArtifactDescriptor,
    ) -> Option<VerifiedIndexedArtifactChunk> {
        if !wallet_scan_artifact_descriptor_matches_cache_kind(descriptor) {
            return None;
        }
        let id = wallet_scan_artifact_chunk_blob_id(descriptor);
        let meta = match self
            .db
            .get_blob_meta(WALLET_SCAN_ARTIFACT_CHUNK_BLOB_KIND, &id)
        {
            Ok(Some(meta)) => meta,
            Ok(None) => return None,
            Err(err) => {
                debug!(?err, cid = %descriptor.cid, "failed to read wallet-scan artifact chunk cache metadata");
                return None;
            }
        };
        if meta.format_version != WALLET_SCAN_ARTIFACT_CHUNK_CACHE_FORMAT_VERSION
            || meta.source_hash != Some(descriptor.sha256.0)
        {
            debug!(cid = %descriptor.cid, "wallet-scan artifact chunk cache metadata did not match descriptor");
            return None;
        }
        let path = self.db.resolve_path(&meta.relative_path);
        let bytes = match fs::read(&path) {
            Ok(bytes) => bytes,
            Err(err) if err.kind() == ErrorKind::NotFound => return None,
            Err(err) => {
                debug!(?err, path = %path.display(), cid = %descriptor.cid, "failed to read cached wallet-scan artifact chunk");
                return None;
            }
        };
        let content_hash: [u8; 32] = Sha256::digest(&bytes).into();
        if content_hash != meta.content_hash {
            debug!(cid = %descriptor.cid, "cached wallet-scan artifact chunk content hash mismatch");
            return None;
        }
        match verify_chunk_bytes(descriptor.clone(), bytes) {
            Ok(chunk) => Some(chunk),
            Err(err) => {
                debug!(?err, cid = %descriptor.cid, "cached wallet-scan artifact chunk failed descriptor verification");
                None
            }
        }
    }

    pub(crate) async fn retain_wallet_scan_artifact_chunks(
        &self,
        chunks: &[VerifiedIndexedArtifactChunk],
        retention_descriptors: &[IndexedArtifactDescriptor],
        read_scope: PublicScanReadScope,
    ) -> usize {
        let Ok(_permit) = self
            .public_cache_commit_permit(
                read_scope,
                "stale wallet-scan artifact chunk retention epoch",
            )
            .await
        else {
            return 0;
        };
        let mut retained = 0_usize;
        for chunk in chunks {
            if !wallet_scan_artifact_descriptor_is_stable(&chunk.descriptor, retention_descriptors)
            {
                continue;
            }
            match self.retain_wallet_scan_artifact_chunk(chunk) {
                Ok(()) => retained = retained.saturating_add(1),
                Err(reason) => {
                    warn!(cid = %chunk.descriptor.cid, %reason, "failed to retain wallet-scan artifact chunk")
                }
            }
        }
        retained
    }

    fn retain_wallet_scan_artifact_chunk(
        &self,
        chunk: &VerifiedIndexedArtifactChunk,
    ) -> Result<(), String> {
        if !wallet_scan_artifact_descriptor_matches_cache_kind(&chunk.descriptor) {
            return Ok(());
        }
        let id = wallet_scan_artifact_chunk_blob_id(&chunk.descriptor);
        let name = wallet_scan_artifact_chunk_file_name(&chunk.descriptor);
        let path = self
            .db
            .blob_path(WALLET_SCAN_ARTIFACT_CHUNK_BLOB_KIND, &name);
        write_wallet_scan_artifact_chunk_file(self.db.as_ref(), &path, &chunk.bytes)
            .map_err(|err| err.to_string())?;
        let now = wallet_scan_artifact_now_epoch_secs().map_err(|err| err.to_string())?;
        let existing = self
            .db
            .get_blob_meta(WALLET_SCAN_ARTIFACT_CHUNK_BLOB_KIND, &id)
            .map_err(|err| err.to_string())?;
        self.db
            .put_blob_meta(
                WALLET_SCAN_ARTIFACT_CHUNK_BLOB_KIND,
                &id,
                &BlobMeta {
                    format_version: WALLET_SCAN_ARTIFACT_CHUNK_CACHE_FORMAT_VERSION,
                    relative_path: DbStore::relative_blob_path(
                        WALLET_SCAN_ARTIFACT_CHUNK_BLOB_KIND,
                        &name,
                    ),
                    content_hash: Sha256::digest(&chunk.bytes).into(),
                    source_hash: Some(chunk.descriptor.sha256.0),
                    created_at: existing.map_or(now, |meta| meta.created_at),
                    updated_at: now,
                    last_accessed_at: now,
                    last_block: chunk.descriptor.metadata.checkpoint_block,
                },
            )
            .map_err(|err| err.to_string())?;
        Ok(())
    }

    fn reset_wallet_scan_artifact_chunk_cache(
        &self,
    ) -> Result<WalletScanArtifactChunkCacheReset, String> {
        let cache_dir = self
            .db
            .blob_dir()
            .join(WALLET_SCAN_ARTIFACT_CHUNK_BLOB_KIND);
        let files_removed = match count_path_entries(&cache_dir) {
            Ok(files_removed) => {
                match fs::remove_dir_all(&cache_dir) {
                    Ok(()) => {}
                    Err(err) if err.kind() == ErrorKind::NotFound => {}
                    Err(err) => return Err(err.to_string()),
                }
                files_removed
            }
            Err(err) if err.kind() == ErrorKind::NotFound => 0,
            Err(err) => return Err(err.to_string()),
        };
        let blob_entries_removed = self
            .db
            .clear_blob_meta_kind(WALLET_SCAN_ARTIFACT_CHUNK_BLOB_KIND)
            .map_err(|err| err.to_string())?;
        self.db
            .ensure_blob_dir(WALLET_SCAN_ARTIFACT_CHUNK_BLOB_KIND)
            .map_err(|err| err.to_string())?;
        Ok(WalletScanArtifactChunkCacheReset {
            blob_entries_removed,
            files_removed,
        })
    }

    pub(crate) async fn record_public_scan_coverage(
        &self,
        write: PublicScanCoverageWrite,
    ) -> Result<PublicDataPlaneEpoch, PublicDataPlaneError> {
        if !write.range.is_valid() {
            return Err(PublicDataPlaneError::InvalidRange {
                from_block: write.range.from_block,
                to_block: write.range.to_block,
            });
        }
        let mut state = self.state.lock().await;
        let current_epoch = self.current_epoch();
        let captured_epoch = write.read_scope.epoch();
        if current_epoch != captured_epoch {
            state.push_diagnostic(PublicDataPlaneDiagnostic {
                kind: PublicDataPlaneDiagnosticKind::CoverageRejected,
                source: Some(write.source),
                range: Some(write.range),
                reason: "stale coverage epoch".to_string(),
                epoch: current_epoch,
            });
            return Err(PublicDataPlaneError::StaleEpoch {
                expected: current_epoch.value,
                actual: captured_epoch.value,
            });
        }

        state.insert_canonical_coverage(PublicScanCoverageRecord {
            range: write.range,
            source: write.source,
            row_count: write.row_count,
            epoch: current_epoch,
        });
        state.push_diagnostic(PublicDataPlaneDiagnostic {
            kind: PublicDataPlaneDiagnosticKind::CoverageRecorded,
            source: Some(write.source),
            range: Some(write.range),
            reason: format!("recorded {} public rows", write.row_count),
            epoch: current_epoch,
        });
        Ok(current_epoch)
    }

    pub(crate) async fn record_source_decision(
        &self,
        kind: PublicDataPlaneDiagnosticKind,
        source: PublicScanSource,
        range: PublicScanRange,
        read_scope: PublicScanReadScope,
        reason: impl Into<String>,
    ) {
        let mut state = self.state.lock().await;
        state.push_diagnostic(PublicDataPlaneDiagnostic {
            kind,
            source: Some(source),
            range: Some(range),
            reason: reason.into(),
            epoch: read_scope.epoch(),
        });
    }

    #[cfg(test)]
    pub(crate) async fn validate_public_scan_read(
        &self,
        range: PublicScanRange,
        source: PublicScanSource,
        read_scope: PublicScanReadScope,
    ) -> Result<(), PublicDataPlaneError> {
        if !range.is_valid() {
            return Err(PublicDataPlaneError::InvalidRange {
                from_block: range.from_block,
                to_block: range.to_block,
            });
        }
        let mut state = self.state.lock().await;
        let current_epoch = self.current_epoch();
        Self::validate_public_scan_read_locked(&mut state, current_epoch, range, source, read_scope)
    }

    pub(crate) async fn public_scan_commit_permit(
        &self,
        range: PublicScanRange,
        source: PublicScanSource,
        read_scope: PublicScanReadScope,
    ) -> Result<PublicScanCommitPermit, PublicDataPlaneError> {
        if !range.is_valid() {
            return Err(PublicDataPlaneError::InvalidRange {
                from_block: range.from_block,
                to_block: range.to_block,
            });
        }
        let commit_guard = Arc::clone(&self.commit_fence).lock_owned().await;
        {
            let mut state = self.state.lock().await;
            let current_epoch = self.current_epoch();
            Self::validate_public_scan_read_locked(
                &mut state,
                current_epoch,
                range,
                source,
                read_scope,
            )?;
        }
        Ok(PublicScanCommitPermit {
            _guard: commit_guard,
        })
    }

    async fn public_cache_commit_permit(
        &self,
        read_scope: PublicScanReadScope,
        reason: impl Into<String>,
    ) -> Result<PublicCacheCommitPermit, PublicDataPlaneError> {
        let commit_guard = Arc::clone(&self.commit_fence).lock_owned().await;
        let mut state = self.state.lock().await;
        let current_epoch = self.current_epoch();
        if current_epoch != read_scope.epoch() {
            state.push_diagnostic(PublicDataPlaneDiagnostic {
                kind: PublicDataPlaneDiagnosticKind::CoverageRejected,
                source: None,
                range: None,
                reason: reason.into(),
                epoch: current_epoch,
            });
            return Err(PublicDataPlaneError::StaleEpoch {
                expected: current_epoch.value,
                actual: read_scope.epoch().value,
            });
        }
        Ok(PublicCacheCommitPermit {
            _guard: commit_guard,
        })
    }

    pub(crate) async fn invalidate_public_scan_coverage_from(
        &self,
        from_block: u64,
    ) -> PublicDataPlaneEpoch {
        let _commit_guard = self.commit_fence.lock().await;
        let mut state = self.state.lock().await;
        let previous_epoch = self.current_epoch();
        let affected = state.coverage.invalidate_from(from_block);
        let new_epoch = self.bump_epoch_locked(previous_epoch);
        state.coverage.restamp_epoch(new_epoch);
        state.push_diagnostic(PublicDataPlaneDiagnostic {
            kind: PublicDataPlaneDiagnosticKind::CoverageInvalidated,
            source: None,
            range: Some(PublicScanRange::new(from_block, u64::MAX)),
            reason: format!("invalidated {affected} public coverage records"),
            epoch: new_epoch,
        });
        new_epoch
    }

    pub(crate) async fn cached_empty_wallet_scan_apply(
        &self,
        from_block: u64,
        to_block: u64,
    ) -> Option<WalletScanApply> {
        if from_block > to_block {
            return None;
        }
        let state = self.state.lock().await;
        let epoch = self.current_epoch();
        let read_scope = PublicScanReadScope::new(epoch);
        let range = PublicScanRange::new(from_block, to_block);
        let covered_to = state.empty_coverage_prefix_for_range(range, epoch)?;
        Some(WalletScanApply::empty_coverage(
            from_block,
            covered_to,
            read_scope,
            PublicScanSource::CachedCoverage,
        ))
    }

    fn bump_epoch_locked(&self, previous_epoch: PublicDataPlaneEpoch) -> PublicDataPlaneEpoch {
        let new_epoch = PublicDataPlaneEpoch::new(previous_epoch.value.saturating_add(1));
        self.epoch.store(new_epoch.value, Ordering::Release);
        new_epoch
    }

    fn validate_public_scan_read_locked(
        state: &mut ChainPublicDataPlaneState,
        current_epoch: PublicDataPlaneEpoch,
        range: PublicScanRange,
        source: PublicScanSource,
        read_scope: PublicScanReadScope,
    ) -> Result<(), PublicDataPlaneError> {
        let captured_epoch = read_scope.epoch();
        if current_epoch == captured_epoch {
            return Ok(());
        }
        state.push_diagnostic(PublicDataPlaneDiagnostic {
            kind: PublicDataPlaneDiagnosticKind::CoverageRejected,
            source: Some(source),
            range: Some(range),
            reason: "stale scan apply epoch".to_string(),
            epoch: current_epoch,
        });
        Err(PublicDataPlaneError::StaleEpoch {
            expected: current_epoch.value,
            actual: captured_epoch.value,
        })
    }
}

fn wallet_scan_artifact_descriptor_matches_cache_kind(
    descriptor: &IndexedArtifactDescriptor,
) -> bool {
    descriptor.dataset_kind == IndexedDatasetKind::WalletScan
        && descriptor.range.kind == IndexedArtifactRangeKind::Block
}

fn wallet_scan_artifact_descriptor_is_stable(
    descriptor: &IndexedArtifactDescriptor,
    selected_descriptors: &[IndexedArtifactDescriptor],
) -> bool {
    if !wallet_scan_artifact_descriptor_matches_cache_kind(descriptor) {
        return false;
    }
    if descriptor.metadata.chunk_sealed || descriptor.metadata.stream_complete {
        return true;
    }
    selected_descriptors.iter().any(|other| {
        wallet_scan_artifact_same_stream(descriptor, other)
            && other.range.start > descriptor.range.start
    })
}

fn wallet_scan_artifact_same_stream(
    left: &IndexedArtifactDescriptor,
    right: &IndexedArtifactDescriptor,
) -> bool {
    left.dataset_kind == right.dataset_kind
        && left.scope == right.scope
        && left.range.kind == right.range.kind
}

fn wallet_scan_artifact_chunk_blob_id(descriptor: &IndexedArtifactDescriptor) -> String {
    format!(
        "{:?}|{}|{:?}|{}|{}|{}|{}|{}|{}|{:?}|{}|{}|{}|{}|{}",
        descriptor.dataset_kind,
        format_scope(&descriptor.scope),
        descriptor.range.kind,
        descriptor.range.start,
        descriptor.range.end,
        descriptor.row_count,
        descriptor.cid,
        descriptor.byte_size,
        descriptor.encoding_version,
        descriptor.compression,
        descriptor
            .metadata
            .catalog_generation
            .map_or_else(|| "none".to_string(), |generation| generation.to_string()),
        descriptor
            .metadata
            .stream_partition
            .as_deref()
            .unwrap_or("none"),
        descriptor.metadata.stream_complete,
        descriptor.metadata.chunk_sealed,
        descriptor
            .metadata
            .checkpoint_block
            .map_or_else(|| "none".to_string(), |checkpoint| checkpoint.to_string()),
    )
}

fn wallet_scan_artifact_chunk_file_name(descriptor: &IndexedArtifactDescriptor) -> String {
    format!(
        "wallet-scan-artifact-chunk-{}.bin",
        safe_file_component(&descriptor.cid)
    )
}

fn safe_file_component(value: &str) -> String {
    value
        .chars()
        .map(|ch| {
            if ch.is_ascii_alphanumeric() || ch == '-' || ch == '_' {
                ch
            } else {
                '_'
            }
        })
        .collect()
}

fn write_wallet_scan_artifact_chunk_file(
    db: &DbStore,
    path: &Path,
    bytes: &[u8],
) -> Result<(), std::io::Error> {
    db.ensure_blob_dir(WALLET_SCAN_ARTIFACT_CHUNK_BLOB_KIND)
        .map_err(std::io::Error::other)?;
    let nonce = WALLET_SCAN_ARTIFACT_CHUNK_TEMP_COUNTER.fetch_add(1, Ordering::Relaxed);
    let temp_path = path.with_extension(format!("tmp.{}.{nonce}", std::process::id()));
    fs::write(&temp_path, bytes)?;
    fs::rename(temp_path, path)?;
    Ok(())
}

fn count_path_entries(path: &Path) -> Result<u64, std::io::Error> {
    if path.is_file() {
        return Ok(1);
    }
    let mut entries = 0_u64;
    for entry in fs::read_dir(path)? {
        let entry = entry?;
        let entry_path = entry.path();
        if entry_path.is_dir() {
            entries = entries.saturating_add(count_path_entries(&entry_path)?);
        } else {
            entries = entries.saturating_add(1);
        }
    }
    Ok(entries)
}

fn wallet_scan_artifact_now_epoch_secs() -> Result<u64, std::time::SystemTimeError> {
    Ok(SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs())
}

#[derive(Debug, Clone, Copy)]
struct CoverageForRange {
    covered_to: u64,
    source: PublicScanSource,
    has_rows: bool,
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::fs;
    use std::path::PathBuf;
    use std::sync::mpsc as std_mpsc;
    use std::time::{Duration, SystemTime, UNIX_EPOCH};

    use crate::indexed_artifacts::{
        ChainScope, ChainType, CompressionAlgorithm, DatasetDescriptorMetadata,
        INDEXED_ARTIFACT_CHUNK_FORMAT_VERSION, IndexedArtifactRange,
    };
    use crate::types::{PoiArtifactManifestSource, PoiArtifactSourceConfig};
    use alloy::primitives::Address;
    use local_db::{BlobMeta, DbConfig, PoiArtifactCacheRecord, PoiArtifactDescriptorRecord};
    use poi::cache::{PoiCache, PoiCacheIdentity};
    use poi::poi::PoiEventType;
    use sha2::{Digest, Sha256};

    #[tokio::test]
    async fn poi_corpus_registry_reuses_chain_scoped_handle() {
        let (data_plane, root_dir) = test_data_plane_with_poi_service("poi-corpus-reuse");
        let key = PublicPoiCorpusKey::new(EVM_CHAIN_TYPE, 1, DEFAULT_TXID_VERSION);
        let first = data_plane
            .ensure_poi_corpus(key.clone())
            .await
            .expect("first POI corpus");

        let second = data_plane
            .ensure_poi_corpus(key.clone())
            .await
            .expect("second POI corpus");
        assert!(Arc::ptr_eq(&first.local_caches(), &second.local_caches()));
        assert_eq!(data_plane.state.lock().await.poi_corpora.len(), 1);
        let list_key = FixedBytes::from([0x11; 32]);
        let mut cache = PoiCache::new(PoiCacheIdentity::new(
            key.chain_type,
            key.chain_id,
            &key.txid_version,
            list_key,
        ));
        cache
            .apply_verified_artifact_events(&[poi::artifacts::SnapshotEvent {
                event_index: 0,
                blinded_commitment: [0x22; 32],
                signature: [0_u8; 64],
                event_type: PoiEventType::Transact,
            }])
            .expect("apply POI event");
        first.local_caches().write().await.insert(list_key, cache);
        assert!(
            data_plane
                .poi_corpus_ready_for_lists(key.clone(), &[list_key])
                .await
        );
        data_plane
            .reset_public_cache()
            .await
            .expect("reset public cache");
        assert!(
            !data_plane
                .poi_corpus_ready_for_lists(key, &[list_key])
                .await
        );
        drop(data_plane);
        fs::remove_dir_all(root_dir).expect("remove temp db dir");
    }

    #[tokio::test]
    async fn poi_corpus_requires_chain_owned_service() {
        let (data_plane, root_dir) = test_data_plane("poi-corpus-no-service");
        let key = PublicPoiCorpusKey::new(EVM_CHAIN_TYPE, 1, DEFAULT_TXID_VERSION);

        let error = match data_plane.ensure_poi_corpus(key).await {
            Ok(_) => panic!("POI corpus should require a chain-owned service"),
            Err(error) => error,
        };

        assert_eq!(
            error,
            PublicDataPlaneError::PoiCorpusUnavailable {
                chain_id: 1,
                txid_version: DEFAULT_TXID_VERSION.to_string(),
            }
        );
        drop(data_plane);
        fs::remove_dir_all(root_dir).expect("remove temp db dir");
    }

    #[tokio::test]
    async fn txid_latest_marker_read_is_data_plane_operation() {
        let (data_plane, root_dir) = test_data_plane("txid-latest-empty");
        let key = PublicTxidCacheKey::new(test_wallet_scan_scope(), DEFAULT_TXID_VERSION);

        assert_eq!(
            data_plane
                .cached_txid_latest_validated(&key)
                .expect("read empty TXID public cache"),
            None
        );

        drop(data_plane);
        fs::remove_dir_all(root_dir).expect("remove temp db dir");
    }

    #[tokio::test]
    async fn public_scan_coverage_rejects_stale_epoch_write() {
        let (data_plane, root_dir) = test_data_plane("stale-coverage-write");
        data_plane.invalidate_public_scan_coverage_from(100).await;

        let error = data_plane
            .record_public_scan_coverage(PublicScanCoverageWrite {
                range: PublicScanRange::new(100, 110),
                source: PublicScanSource::Rpc,
                row_count: 0,
                read_scope: PublicScanReadScope::new(PublicDataPlaneEpoch::new(0)),
            })
            .await
            .expect_err("stale coverage must be rejected");

        assert_eq!(
            error,
            PublicDataPlaneError::StaleEpoch {
                expected: 1,
                actual: 0,
            }
        );
        assert!(matches!(
            data_plane
                .cached_public_scan_coverage(PublicScanRange::new(100, 110))
                .await,
            PublicCoverageAnswer::Missing { .. }
        ));
        drop(data_plane);
        fs::remove_dir_all(root_dir).expect("remove temp db dir");
    }

    #[tokio::test]
    async fn cached_empty_wallet_scan_apply_reuses_only_empty_cached_coverage() {
        let (data_plane, root_dir) = test_data_plane("cached-empty-coverage");
        data_plane
            .record_public_scan_coverage(PublicScanCoverageWrite {
                range: PublicScanRange::new(100, 110),
                source: PublicScanSource::IndexedArtifacts,
                row_count: 0,
                read_scope: data_plane.begin_public_scan_read(),
            })
            .await
            .expect("record empty coverage");
        data_plane
            .record_public_scan_coverage(PublicScanCoverageWrite {
                range: PublicScanRange::new(111, 120),
                source: PublicScanSource::Squid,
                row_count: 1,
                read_scope: data_plane.begin_public_scan_read(),
            })
            .await
            .expect("record non-empty coverage");

        let apply = data_plane
            .cached_empty_wallet_scan_apply(100, 120)
            .await
            .expect("empty prefix coverage is reusable");
        assert_eq!(apply.from_block, 100);
        assert_eq!(apply.to_block, 110);
        assert_eq!(apply.rows.source, PublicScanSource::CachedCoverage);
        assert!(
            data_plane
                .cached_empty_wallet_scan_apply(111, 120)
                .await
                .is_none(),
            "coverage with rows cannot be replayed without row data"
        );
        drop(data_plane);
        fs::remove_dir_all(root_dir).expect("remove temp db dir");
    }

    #[tokio::test]
    async fn duplicate_public_coverage_writes_replace_canonical_coverage() {
        let (data_plane, root_dir) = test_data_plane("duplicate-coverage-row-count");
        let range = PublicScanRange::new(100, 110);
        for _ in 0..2 {
            data_plane
                .record_public_scan_coverage(PublicScanCoverageWrite {
                    range,
                    source: PublicScanSource::Rpc,
                    row_count: 3,
                    read_scope: data_plane.begin_public_scan_read(),
                })
                .await
                .expect("record duplicate coverage");
        }

        let answer = data_plane.cached_public_scan_coverage(range).await;

        assert!(matches!(
            answer,
            PublicCoverageAnswer::CoveredWithRows {
                range: PublicScanRange {
                    from_block: 100,
                    to_block: 110
                },
                ..
            }
        ));
        assert_eq!(data_plane.state.lock().await.coverage.len(), 1);
        drop(data_plane);
        fs::remove_dir_all(root_dir).expect("remove temp db dir");
    }

    #[tokio::test]
    async fn overlapping_public_coverage_writes_preserve_replayable_remainders() {
        let (data_plane, root_dir) = test_data_plane("overlapping-coverage-remainders");
        data_plane
            .record_public_scan_coverage(PublicScanCoverageWrite {
                range: PublicScanRange::new(100, 200),
                source: PublicScanSource::Rpc,
                row_count: 0,
                read_scope: data_plane.begin_public_scan_read(),
            })
            .await
            .expect("record wide coverage");
        data_plane
            .record_public_scan_coverage(PublicScanCoverageWrite {
                range: PublicScanRange::new(150, 200),
                source: PublicScanSource::Rpc,
                row_count: 0,
                read_scope: data_plane.begin_public_scan_read(),
            })
            .await
            .expect("record overlapping suffix coverage");

        assert_eq!(data_plane.state.lock().await.coverage.len(), 2);
        assert_eq!(
            data_plane
                .cached_public_scan_coverage(PublicScanRange::new(100, 149))
                .await,
            PublicCoverageAnswer::ReplayableEmpty {
                range: PublicScanRange::new(100, 149),
                source: PublicScanSource::Rpc,
                epoch: PublicDataPlaneEpoch::new(0),
            }
        );
        let apply = data_plane
            .cached_empty_wallet_scan_apply(100, 200)
            .await
            .expect("overlapping empty coverage remains replayable");
        assert_eq!(apply.from_block, 100);
        assert_eq!(apply.to_block, 200);
        assert_eq!(apply.rows.source, PublicScanSource::CachedCoverage);

        drop(data_plane);
        fs::remove_dir_all(root_dir).expect("remove temp db dir");
    }

    #[tokio::test]
    async fn row_bearing_cached_coverage_is_not_replayable_empty() {
        let (data_plane, root_dir) = test_data_plane("partial-coverage-no-row-count");
        data_plane
            .record_public_scan_coverage(PublicScanCoverageWrite {
                range: PublicScanRange::new(100, 120),
                source: PublicScanSource::Rpc,
                row_count: 7,
                read_scope: data_plane.begin_public_scan_read(),
            })
            .await
            .expect("record aggregate coverage");

        let answer = data_plane
            .cached_public_scan_coverage(PublicScanRange::new(100, 110))
            .await;

        assert_eq!(
            answer,
            PublicCoverageAnswer::CoveredWithRows {
                range: PublicScanRange::new(100, 110),
                source: PublicScanSource::Rpc,
                epoch: PublicDataPlaneEpoch::new(0),
            }
        );
        assert_eq!(
            data_plane.state.lock().await.coverage.records()[0].row_count,
            7
        );
        assert!(
            data_plane
                .cached_empty_wallet_scan_apply(100, 110)
                .await
                .is_none(),
            "row-bearing coverage must not be replayed as empty coverage"
        );
        drop(data_plane);
        fs::remove_dir_all(root_dir).expect("remove temp db dir");
    }

    #[tokio::test]
    async fn invalidation_removes_or_restamps_stale_coverage_records() {
        let (data_plane, root_dir) = test_data_plane("coverage-invalidation-stale-cleanup");
        data_plane
            .record_public_scan_coverage(PublicScanCoverageWrite {
                range: PublicScanRange::new(1, 9),
                source: PublicScanSource::Rpc,
                row_count: 0,
                read_scope: data_plane.begin_public_scan_read(),
            })
            .await
            .expect("record retained coverage");
        data_plane
            .record_public_scan_coverage(PublicScanCoverageWrite {
                range: PublicScanRange::new(10, 20),
                source: PublicScanSource::Rpc,
                row_count: 0,
                read_scope: data_plane.begin_public_scan_read(),
            })
            .await
            .expect("record invalidated coverage");

        let new_epoch = data_plane.invalidate_public_scan_coverage_from(10).await;

        let state = data_plane.state.lock().await;
        assert_eq!(state.coverage.len(), 1);
        assert_eq!(
            state.coverage.records()[0].range,
            PublicScanRange::new(1, 9)
        );
        assert_eq!(state.coverage.records()[0].epoch, new_epoch);
        drop(state);
        assert!(matches!(
            data_plane
                .cached_public_scan_coverage(PublicScanRange::new(1, 9))
                .await,
            PublicCoverageAnswer::ReplayableEmpty { .. }
        ));
        assert!(matches!(
            data_plane
                .cached_public_scan_coverage(PublicScanRange::new(10, 20))
                .await,
            PublicCoverageAnswer::Missing { .. }
        ));
        drop(data_plane);
        fs::remove_dir_all(root_dir).expect("remove temp db dir");
    }

    #[tokio::test]
    async fn invalidation_trims_spanning_coverage_record() {
        let (data_plane, root_dir) = test_data_plane("coverage-invalidation-trim");
        data_plane
            .record_public_scan_coverage(PublicScanCoverageWrite {
                range: PublicScanRange::new(1, 20),
                source: PublicScanSource::Rpc,
                row_count: 0,
                read_scope: data_plane.begin_public_scan_read(),
            })
            .await
            .expect("record spanning coverage");

        let new_epoch = data_plane.invalidate_public_scan_coverage_from(10).await;

        let state = data_plane.state.lock().await;
        assert_eq!(state.coverage.len(), 1);
        assert_eq!(
            state.coverage.records()[0].range,
            PublicScanRange::new(1, 9)
        );
        assert_eq!(state.coverage.records()[0].epoch, new_epoch);
        drop(state);
        assert!(matches!(
            data_plane
                .cached_public_scan_coverage(PublicScanRange::new(1, 9))
                .await,
            PublicCoverageAnswer::ReplayableEmpty { .. }
        ));
        assert!(matches!(
            data_plane
                .cached_public_scan_coverage(PublicScanRange::new(10, 20))
                .await,
            PublicCoverageAnswer::Missing { .. }
        ));
        drop(data_plane);
        fs::remove_dir_all(root_dir).expect("remove temp db dir");
    }

    #[tokio::test]
    async fn public_cache_reset_clears_coverage_and_advances_epoch() {
        let (data_plane, root_dir) = test_data_plane("public-cache-reset-coverage");
        data_plane
            .record_public_scan_coverage(PublicScanCoverageWrite {
                range: PublicScanRange::new(1, 2),
                source: PublicScanSource::Rpc,
                row_count: 0,
                read_scope: data_plane.begin_public_scan_read(),
            })
            .await
            .expect("record coverage");
        data_plane
            .record_source_decision(
                PublicDataPlaneDiagnosticKind::SourceSelected,
                PublicScanSource::Rpc,
                PublicScanRange::new(1, 2),
                data_plane.begin_public_scan_read(),
                "test",
            )
            .await;

        let reset = data_plane
            .reset_public_cache()
            .await
            .expect("reset public cache");
        assert_eq!(reset.previous_epoch, PublicDataPlaneEpoch::new(0));
        assert_eq!(reset.new_epoch, PublicDataPlaneEpoch::new(1));
        assert_eq!(reset.coverage_entries_removed, 1);
        assert!(reset.diagnostics_removed >= 1);
        assert!(
            data_plane
                .cached_empty_wallet_scan_apply(1, 2)
                .await
                .is_none()
        );
        drop(data_plane);
        fs::remove_dir_all(root_dir).expect("remove temp db dir");
    }

    #[tokio::test]
    async fn public_cache_reset_clears_durable_public_txid_and_poi_cache() {
        let (db, data_plane, root_dir) = test_data_plane_with_db("public-cache-reset-durable");
        let txid_kind = "txid_public_cache";
        let txid_name = "stale.msgpack";
        let txid_id = "stale-entry";
        let txid_path = db.blob_path(txid_kind, txid_name);
        db.ensure_blob_dir(txid_kind).expect("ensure txid blob dir");
        fs::write(&txid_path, b"stale txid cache").expect("write stale txid blob");
        db.put_blob_meta(
            txid_kind,
            txid_id,
            &BlobMeta {
                format_version: 1,
                relative_path: DbStore::relative_blob_path(txid_kind, txid_name),
                content_hash: Sha256::digest(b"stale txid cache").into(),
                source_hash: None,
                created_at: 1,
                updated_at: 1,
                last_accessed_at: 1,
                last_block: None,
            },
        )
        .expect("put txid blob meta");
        let descriptor = PoiArtifactDescriptorRecord {
            cid: "cid".to_string(),
            sha256: "sha256".to_string(),
            byte_size: 1,
        };
        let list_key = FixedBytes::from([7_u8; 32]);
        db.put_poi_artifact_cache(&PoiArtifactCacheRecord {
            chain_type: 0,
            chain_id: 1,
            txid_version: "v2".to_string(),
            list_key,
            last_accepted_manifest_sequence: 1,
            base_descriptor: descriptor.clone(),
            applied_delta_descriptors: Vec::new(),
            blocked_shields_descriptor: descriptor,
            current_tip_index: 0,
            current_tip_root: FixedBytes::from([9_u8; 32]),
            cache_payload: vec![1, 2, 3],
            updated_at: 1,
        })
        .expect("put poi artifact cache");
        let wallet_scan_chunk = test_wallet_scan_chunk(1, 2, &[1, 2, 3], |metadata| {
            metadata.chunk_sealed = true;
        });
        assert_eq!(
            data_plane
                .retain_wallet_scan_artifact_chunks(
                    std::slice::from_ref(&wallet_scan_chunk),
                    std::slice::from_ref(&wallet_scan_chunk.descriptor),
                    data_plane.begin_public_scan_read(),
                )
                .await,
            1
        );

        assert!(
            db.get_blob_meta(txid_kind, txid_id)
                .expect("get txid blob meta")
                .is_some()
        );
        assert!(
            db.get_poi_artifact_cache(0, 1, "v2", &list_key)
                .expect("get poi cache")
                .is_some()
        );

        let reset = data_plane
            .reset_public_cache()
            .await
            .expect("reset public cache");

        assert_eq!(reset.txid_blob_entries_removed, 1);
        assert!(reset.txid_files_removed >= 1);
        assert_eq!(reset.wallet_scan_artifact_chunk_entries_removed, 1);
        assert!(reset.wallet_scan_artifact_chunk_files_removed >= 1);
        assert_eq!(reset.poi_cache_entries_removed, 1);
        assert!(
            db.get_blob_meta(txid_kind, txid_id)
                .expect("get txid blob meta after reset")
                .is_none()
        );
        assert!(!txid_path.exists());
        assert!(
            db.get_poi_artifact_cache(0, 1, "v2", &list_key)
                .expect("get poi cache after reset")
                .is_none()
        );
        assert!(
            data_plane
                .cached_wallet_scan_artifact_chunk(&wallet_scan_chunk.descriptor)
                .is_none()
        );

        drop(data_plane);
        drop(db);
        fs::remove_dir_all(root_dir).expect("remove temp db dir");
    }

    #[tokio::test]
    async fn wallet_scan_artifact_chunk_cache_reuses_only_stable_descriptor_matches() {
        let (db, data_plane, root_dir) = test_data_plane_with_db("wallet-scan-chunk-cache");
        let stable_chunk = test_wallet_scan_chunk(1, 10, &[1, 2, 3], |_| {});
        let transient_tail = test_wallet_scan_chunk(11, 20, &[4, 5, 6], |_| {});
        let selected = vec![
            stable_chunk.descriptor.clone(),
            transient_tail.descriptor.clone(),
        ];

        let retained = data_plane
            .retain_wallet_scan_artifact_chunks(
                &[stable_chunk.clone(), transient_tail.clone()],
                &selected,
                data_plane.begin_public_scan_read(),
            )
            .await;

        assert_eq!(retained, 1);
        assert_eq!(
            data_plane
                .cached_wallet_scan_artifact_chunk(&stable_chunk.descriptor)
                .expect("stable chunk cached")
                .bytes,
            stable_chunk.bytes
        );
        assert!(
            data_plane
                .cached_wallet_scan_artifact_chunk(&transient_tail.descriptor)
                .is_none(),
            "unsealed final wallet-scan tails stay transient"
        );

        let mut mismatched_descriptor = stable_chunk.descriptor.clone();
        mismatched_descriptor.metadata.chunk_sealed = true;
        assert!(
            data_plane
                .cached_wallet_scan_artifact_chunk(&mismatched_descriptor)
                .is_none(),
            "descriptor identity must match before cached bytes are reused"
        );

        let sealed_tail = test_wallet_scan_chunk(21, 30, &[7, 8, 9], |metadata| {
            metadata.chunk_sealed = true;
        });
        assert_eq!(
            data_plane
                .retain_wallet_scan_artifact_chunks(
                    std::slice::from_ref(&sealed_tail),
                    std::slice::from_ref(&sealed_tail.descriptor),
                    data_plane.begin_public_scan_read(),
                )
                .await,
            1
        );
        assert!(
            data_plane
                .cached_wallet_scan_artifact_chunk(&sealed_tail.descriptor)
                .is_some(),
            "explicitly sealed final chunks are retained"
        );

        let context_only_successor = test_wallet_scan_chunk(41, 50, &[10, 11, 12], |_| {});
        let predecessor = test_wallet_scan_chunk(31, 40, &[13, 14, 15], |_| {});
        assert_eq!(
            data_plane
                .retain_wallet_scan_artifact_chunks(
                    std::slice::from_ref(&predecessor),
                    &[
                        predecessor.descriptor.clone(),
                        context_only_successor.descriptor.clone(),
                    ],
                    data_plane.begin_public_scan_read(),
                )
                .await,
            1,
            "planner retention context may include chunks outside the request"
        );
        let predecessor_id = wallet_scan_artifact_chunk_blob_id(&predecessor.descriptor);
        let mut predecessor_meta = db
            .get_blob_meta(WALLET_SCAN_ARTIFACT_CHUNK_BLOB_KIND, &predecessor_id)
            .expect("read predecessor meta")
            .expect("predecessor cached");
        predecessor_meta.last_accessed_at = 0;
        db.put_blob_meta(
            WALLET_SCAN_ARTIFACT_CHUNK_BLOB_KIND,
            &predecessor_id,
            &predecessor_meta,
        )
        .expect("reset access time");
        assert!(
            data_plane
                .cached_wallet_scan_artifact_chunk(&predecessor.descriptor)
                .is_some(),
            "verified cache hit should be reused"
        );
        let untouched_meta = db
            .get_blob_meta(WALLET_SCAN_ARTIFACT_CHUNK_BLOB_KIND, &predecessor_id)
            .expect("read predecessor meta after cache hit")
            .expect("predecessor meta retained");
        assert_eq!(
            untouched_meta.last_accessed_at, 0,
            "verified cache hits must remain read-only"
        );

        drop(data_plane);
        drop(db);
        fs::remove_dir_all(root_dir).expect("remove temp db dir");
    }

    #[tokio::test]
    async fn public_data_plane_diagnostics_record_source_fallback() {
        let (data_plane, root_dir) = test_data_plane("data-plane-diagnostics");
        let stale_scope = data_plane.begin_public_scan_read();
        data_plane.invalidate_public_scan_coverage_from(10).await;
        data_plane
            .record_source_decision(
                PublicDataPlaneDiagnosticKind::SourceSelected,
                PublicScanSource::IndexedArtifacts,
                PublicScanRange::new(10, 20),
                stale_scope,
                "artifact source selected",
            )
            .await;
        data_plane
            .record_source_decision(
                PublicDataPlaneDiagnosticKind::SourceFallback,
                PublicScanSource::Squid,
                PublicScanRange::new(10, 20),
                data_plane.begin_public_scan_read(),
                "artifact failed before checkpoint",
            )
            .await;

        let diagnostics = data_plane.diagnostics().await;
        assert_eq!(diagnostics.events.len(), 3);
        assert_eq!(
            diagnostics.events[1].kind,
            PublicDataPlaneDiagnosticKind::SourceSelected
        );
        assert_eq!(
            diagnostics.events[1].source,
            Some(PublicScanSource::IndexedArtifacts)
        );
        assert_eq!(diagnostics.events[1].epoch, stale_scope.epoch());
        assert_eq!(
            diagnostics.events[2].kind,
            PublicDataPlaneDiagnosticKind::SourceFallback
        );
        assert_eq!(diagnostics.events[2].source, Some(PublicScanSource::Squid));
        drop(data_plane);
        fs::remove_dir_all(root_dir).expect("remove temp db dir");
    }

    #[tokio::test]
    async fn public_scan_epoch_validation_rejects_stale_apply_epoch() {
        let (data_plane, root_dir) = test_data_plane("stale-apply-epoch");
        data_plane.invalidate_public_scan_coverage_from(10).await;

        let error = data_plane
            .validate_public_scan_read(
                PublicScanRange::new(10, 20),
                PublicScanSource::CachedCoverage,
                PublicScanReadScope::new(PublicDataPlaneEpoch::new(0)),
            )
            .await
            .expect_err("stale apply epoch must be rejected");

        assert_eq!(
            error,
            PublicDataPlaneError::StaleEpoch {
                expected: 1,
                actual: 0,
            }
        );
        drop(data_plane);
        fs::remove_dir_all(root_dir).expect("remove temp db dir");
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn validated_public_scan_commit_blocks_epoch_invalidation_until_commit_finishes() {
        let (data_plane, root_dir) = test_data_plane("validated-commit-epoch-guard");
        let read_scope = data_plane.begin_public_scan_read();
        let range = PublicScanRange::new(10, 20);
        let (entered_tx, entered_rx) = tokio::sync::oneshot::channel();
        let (release_tx, release_rx) = std_mpsc::channel();
        let commit_plane = data_plane.clone();
        let commit_task = tokio::spawn(async move {
            let permit = commit_plane
                .public_scan_commit_permit(range, PublicScanSource::Rpc, read_scope)
                .await
                .expect("validated commit");
            let _ = entered_tx.send(());
            release_rx.recv().expect("release commit");
            drop(permit);
        });
        entered_rx.await.expect("commit closure entered");

        let invalidate_plane = data_plane.clone();
        let invalidate_task = tokio::spawn(async move {
            invalidate_plane
                .invalidate_public_scan_coverage_from(10)
                .await
        });
        tokio::time::sleep(Duration::from_millis(50)).await;
        assert!(
            !invalidate_task.is_finished(),
            "epoch invalidation must wait for the guarded commit section"
        );

        release_tx.send(()).expect("release commit");
        commit_task.await.expect("commit task");
        assert_eq!(
            invalidate_task.await.expect("invalidate task"),
            PublicDataPlaneEpoch::new(1)
        );
        drop(data_plane);
        fs::remove_dir_all(root_dir).expect("remove temp db dir");
    }

    fn test_data_plane(name: &str) -> (ChainPublicDataPlane, PathBuf) {
        let (db, root_dir) = test_db(name);
        let data_plane = ChainPublicDataPlane::new(db, Arc::new(AtomicU64::new(0)));
        (data_plane, root_dir)
    }

    fn test_data_plane_with_poi_service(name: &str) -> (ChainPublicDataPlane, PathBuf) {
        let (db, root_dir) = test_db(name);
        let poi_cache_service = PoiCacheService::new(
            Arc::clone(&db),
            PoiArtifactSourceConfig {
                trusted_publisher_pubkey: FixedBytes::from([0x42; 32]),
                manifest_source: PoiArtifactManifestSource::Url(
                    Url::parse("http://127.0.0.1:1/poi-manifest.json").expect("POI manifest URL"),
                ),
                gateway_urls: Vec::new(),
                max_manifest_age: None,
            },
            None,
        )
        .with_poi_rpc_url(Url::parse("http://127.0.0.1:1").expect("POI RPC URL"));
        let data_plane = ChainPublicDataPlane::new(db, Arc::new(AtomicU64::new(0)))
            .with_poi_cache_service(Arc::new(poi_cache_service));
        (data_plane, root_dir)
    }

    fn test_data_plane_with_db(name: &str) -> (Arc<DbStore>, ChainPublicDataPlane, PathBuf) {
        let (db, root_dir) = test_db(name);
        let data_plane = ChainPublicDataPlane::new(Arc::clone(&db), Arc::new(AtomicU64::new(0)));
        (db, data_plane, root_dir)
    }

    fn test_db(name: &str) -> (Arc<DbStore>, PathBuf) {
        let root_dir = temp_db_root(name);
        let db = Arc::new(
            DbStore::open(DbConfig {
                root_dir: root_dir.clone(),
            })
            .expect("open db"),
        );
        (db, root_dir)
    }

    fn test_wallet_scan_chunk<F>(
        start: u64,
        end: u64,
        bytes: &[u8],
        update_metadata: F,
    ) -> VerifiedIndexedArtifactChunk
    where
        F: FnOnce(&mut DatasetDescriptorMetadata),
    {
        let mut metadata = DatasetDescriptorMetadata {
            catalog_generation: Some(1),
            checkpoint_block: Some(end),
            ..Default::default()
        };
        update_metadata(&mut metadata);
        let descriptor = IndexedArtifactDescriptor {
            dataset_kind: IndexedDatasetKind::WalletScan,
            scope: test_wallet_scan_scope(),
            range: IndexedArtifactRange {
                kind: IndexedArtifactRangeKind::Block,
                start,
                end,
            },
            row_count: 0,
            cid: format!("test-wallet-scan-{start}-{end}"),
            sha256: FixedBytes::from_slice(&Sha256::digest(bytes)),
            byte_size: u64::try_from(bytes.len()).expect("test chunk byte size"),
            encoding_version: INDEXED_ARTIFACT_CHUNK_FORMAT_VERSION,
            compression: CompressionAlgorithm::None,
            metadata,
        };
        VerifiedIndexedArtifactChunk {
            descriptor,
            bytes: bytes.to_vec(),
        }
    }

    fn test_wallet_scan_scope() -> ChainScope {
        ChainScope {
            chain_type: ChainType::Evm,
            chain_id: 1,
            railgun_contract: Address::from([0x11; 20]),
        }
    }

    fn temp_db_root(name: &str) -> PathBuf {
        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system time")
            .as_nanos();
        std::env::temp_dir().join(format!("sync-service-data-plane-{name}-{unique}"))
    }
}
