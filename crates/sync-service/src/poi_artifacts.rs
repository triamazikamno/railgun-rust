use std::collections::BTreeMap;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, LazyLock, Mutex, MutexGuard};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use alloy::hex;
use alloy::primitives::FixedBytes;
use broadcaster_core::tree::normalize_tree_position;
use local_db::{
    DbStore, PoiArtifactCacheRecord, PoiArtifactDescriptorRecord, PoiCacheRecordSource,
    PoiCorpusRpcHealthRecord, PoiCorpusValidationRecord, StoredRecord,
};
use poi::artifacts::{
    ArtifactDescriptor, BlockedShieldsArtifact, BlockedShieldsArtifactError, Manifest,
    ManifestEntry, ManifestError, Snapshot, SnapshotError, SnapshotKind, SnapshotReader,
};
use poi::cache::{PoiCache, PoiCacheError, PoiCacheIdentity, PoiCacheRootValidation};
use poi::poi::BlockedShield;
use thiserror::Error;
use tokio::sync::{OwnedRwLockReadGuard, OwnedRwLockWriteGuard, RwLock};
use tracing::{debug, warn};
use url::Url;

use crate::trustless_artifacts::{self, TrustlessArtifactError, TrustlessArtifactFetcher};
use crate::types::{PoiArtifactCachePhase, PoiArtifactManifestSource, PoiArtifactSourceConfig};

const BLOCKED_SHIELDS_LIST_KEY_FIELD: &str = "blocked_shields.list_key";
const ENTRY_LIST_KEY_FIELD: &str = "entry.list_key";

static POI_ARTIFACT_CACHE_SYNC_STATE: LazyLock<Mutex<PoiArtifactCacheSyncState>> =
    LazyLock::new(|| Mutex::new(PoiArtifactCacheSyncState::default()));

#[derive(Default)]
struct PoiArtifactCacheSyncState {
    authorities: BTreeMap<PathBuf, Arc<PoiCorpusAuthority>>,
}

#[derive(Debug)]
pub(crate) struct PoiCorpusAuthority {
    generation: Arc<AtomicU64>,
    access: Arc<RwLock<()>>,
}

impl PoiCorpusAuthority {
    pub(crate) fn new(generation: u64) -> Self {
        Self {
            generation: Arc::new(AtomicU64::new(generation)),
            access: Arc::new(RwLock::new(())),
        }
    }

    pub(crate) async fn read_access(&self) -> OwnedRwLockReadGuard<()> {
        Arc::clone(&self.access).read_owned().await
    }

    async fn reset_access(&self) -> OwnedRwLockWriteGuard<()> {
        Arc::clone(&self.access).write_owned().await
    }

    pub(crate) fn generation(&self) -> &AtomicU64 {
        self.generation.as_ref()
    }

    pub(crate) fn generation_cell(&self) -> Arc<AtomicU64> {
        Arc::clone(&self.generation)
    }
}

impl PoiArtifactCacheSyncState {
    fn lock() -> MutexGuard<'static, Self> {
        POI_ARTIFACT_CACHE_SYNC_STATE
            .lock()
            .expect("POI artifact cache sync state lock poisoned")
    }

    fn authority(&mut self, db: &DbStore) -> Result<Arc<PoiCorpusAuthority>, local_db::DbError> {
        if let Some(authority) = self.authorities.get(db.root_dir()) {
            return Ok(Arc::clone(authority));
        }
        let authority = Arc::new(PoiCorpusAuthority::new(db.poi_artifact_cache_generation()?));
        self.authorities
            .insert(db.root_dir().to_path_buf(), Arc::clone(&authority));
        Ok(authority)
    }

    fn generation_cell(&mut self, db: &DbStore) -> Result<Arc<AtomicU64>, local_db::DbError> {
        Ok(self.authority(db)?.generation_cell())
    }

    fn publish_generation(&mut self, db: &DbStore, generation: u64) {
        let authority = self
            .authorities
            .entry(db.root_dir().to_path_buf())
            .or_insert_with(|| Arc::new(PoiCorpusAuthority::new(generation)));
        authority.generation.store(generation, Ordering::Release);
    }
}

pub(crate) fn with_poi_artifact_cache_generation<R>(
    generation: &AtomicU64,
    operation: impl FnOnce(u64) -> R,
) -> R {
    let _sync_guard = PoiArtifactCacheSyncState::lock();
    operation(generation.load(Ordering::Acquire))
}

pub(crate) fn poi_artifact_cache_generation_cell(
    db: &DbStore,
) -> Result<Arc<AtomicU64>, local_db::DbError> {
    Ok(PoiArtifactCacheSyncState::lock()
        .authority(db)?
        .generation_cell())
}

pub(crate) fn poi_corpus_authority(
    db: &DbStore,
) -> Result<Arc<PoiCorpusAuthority>, local_db::DbError> {
    PoiArtifactCacheSyncState::lock().authority(db)
}

fn lock_poi_artifact_cache_sync() -> MutexGuard<'static, PoiArtifactCacheSyncState> {
    POI_ARTIFACT_CACHE_SYNC_STATE
        .lock()
        .expect("POI artifact cache sync state lock poisoned")
}

#[derive(Clone, Copy)]
pub(crate) struct PoiArtifactProgressEvent {
    pub(crate) phase: PoiArtifactCachePhase,
    pub(crate) current_event_index: Option<u64>,
    pub(crate) target_event_index: Option<u64>,
}

type PoiArtifactProgressObserver = Arc<dyn Fn(PoiArtifactProgressEvent) + Send + Sync>;

pub(crate) struct PoiArtifactIngestor {
    config: PoiArtifactSourceConfig,
    client: reqwest::Client,
    progress_observer: Option<PoiArtifactProgressObserver>,
}

impl PoiArtifactIngestor {
    pub(crate) const fn new(config: PoiArtifactSourceConfig, client: reqwest::Client) -> Self {
        Self {
            config,
            client,
            progress_observer: None,
        }
    }

    pub(crate) fn with_progress_observer(
        mut self,
        observer: impl Fn(PoiArtifactProgressEvent) + Send + Sync + 'static,
    ) -> Self {
        self.progress_observer = Some(Arc::new(observer));
        self
    }

    fn report_progress(
        &self,
        phase: PoiArtifactCachePhase,
        current_event_index: Option<u64>,
        target_event_index: Option<u64>,
    ) {
        if let Some(observer) = self.progress_observer.as_ref() {
            observer(PoiArtifactProgressEvent {
                phase,
                current_event_index,
                target_event_index,
            });
        }
    }

    pub(crate) async fn fetch_manifest(
        &self,
        last_accepted_sequence: Option<u64>,
        now: SystemTime,
    ) -> Result<Manifest, PoiArtifactError> {
        match &self.config.manifest_source {
            PoiArtifactManifestSource::Url(url) => {
                let started = Instant::now();
                let (manifest, bytes) = self
                    .fetch_manifest_from_url(url, last_accepted_sequence, now)
                    .await?;
                debug!(
                    url = %url,
                    bytes,
                    manifest_sequence = manifest.sequence,
                    entries = manifest.entries.len(),
                    elapsed_ms = started.elapsed().as_millis(),
                    "fetched POI artifact manifest from explicit URL"
                );
                Ok(manifest)
            }
            PoiArtifactManifestSource::Cid(cid) => {
                self.fetch_manifest_from_cid(cid, last_accepted_sequence, now)
                    .await
            }
            PoiArtifactManifestSource::IpnsName(name) => {
                self.fetch_manifest_from_ipns_name(name, last_accepted_sequence, now)
                    .await
            }
        }
    }

    async fn fetch_manifest_from_url(
        &self,
        manifest_url: &Url,
        last_accepted_sequence: Option<u64>,
        now: SystemTime,
    ) -> Result<(Manifest, usize), PoiArtifactError> {
        let bytes = self.fetch_url(manifest_url).await?;
        self.verify_manifest_bytes(&bytes, last_accepted_sequence, now)
    }

    async fn fetch_manifest_from_cid(
        &self,
        cid: &str,
        last_accepted_sequence: Option<u64>,
        now: SystemTime,
    ) -> Result<Manifest, PoiArtifactError> {
        let started = Instant::now();
        let bytes = TrustlessArtifactFetcher::new(&self.client, &self.config.gateway_urls)
            .fetch_manifest_cid(cid)
            .await?;
        let (manifest, bytes_len) =
            self.verify_manifest_bytes(&bytes, last_accepted_sequence, now)?;
        debug!(
            cid,
            bytes = bytes_len,
            manifest_sequence = manifest.sequence,
            entries = manifest.entries.len(),
            elapsed_ms = started.elapsed().as_millis(),
            "fetched trustless POI artifact manifest CID"
        );
        Ok(manifest)
    }

    async fn fetch_manifest_from_ipns_name(
        &self,
        name: &str,
        last_accepted_sequence: Option<u64>,
        now: SystemTime,
    ) -> Result<Manifest, PoiArtifactError> {
        let started = Instant::now();
        let fetcher = TrustlessArtifactFetcher::new(&self.client, &self.config.gateway_urls);
        let candidates = fetcher.resolve_ipns_manifest_candidates(name, now).await?;
        let candidate_count = candidates.len();
        let mut last_error = None;
        for (candidate_index, candidate) in candidates.into_iter().enumerate() {
            match fetcher.fetch_manifest_cid(&candidate.cid.to_string()).await {
                Ok(bytes) => {
                    match self.verify_manifest_bytes(&bytes, last_accepted_sequence, now) {
                        Ok((manifest, bytes_len)) => {
                            debug!(
                                ipns_name = name,
                                cid = %candidate.cid,
                                ipns_sequence = candidate.sequence,
                                candidate_index,
                                candidate_count,
                                bytes = bytes_len,
                                manifest_sequence = manifest.sequence,
                                entries = manifest.entries.len(),
                                elapsed_ms = started.elapsed().as_millis(),
                                "fetched trustless POI artifact manifest through verified IPNS"
                            );
                            return Ok(manifest);
                        }
                        Err(err) => {
                            debug!(
                                ?err,
                                ipns_name = name,
                                cid = %candidate.cid,
                                ipns_sequence = candidate.sequence,
                                candidate_index,
                                candidate_count,
                                elapsed_ms = started.elapsed().as_millis(),
                                "verified IPNS manifest candidate failed manifest acceptance"
                            );
                            last_error = Some(err);
                        }
                    }
                }
                Err(err) => {
                    debug!(
                        ?err,
                        ipns_name = name,
                        cid = %candidate.cid,
                        ipns_sequence = candidate.sequence,
                        candidate_index,
                        candidate_count,
                        elapsed_ms = started.elapsed().as_millis(),
                        "verified IPNS manifest CID fetch failed"
                    );
                    last_error = Some(PoiArtifactError::Trustless(err));
                }
            }
        }
        Err(last_error.unwrap_or(PoiArtifactError::NoGateways))
    }

    fn verify_manifest_bytes(
        &self,
        bytes: &[u8],
        last_accepted_sequence: Option<u64>,
        now: SystemTime,
    ) -> Result<(Manifest, usize), PoiArtifactError> {
        let manifest: Manifest = serde_json::from_slice(bytes).map_err(PoiArtifactError::Json)?;
        manifest.verify_trusted_signature(&self.config.trusted_publisher_pubkey.0)?;
        validate_manifest_sequence(&manifest, last_accepted_sequence)?;
        validate_manifest_freshness(
            &manifest,
            last_accepted_sequence,
            self.config.max_manifest_age,
            now,
        )?;
        Ok((manifest, bytes.len()))
    }

    pub(crate) async fn fetch_artifact(
        &self,
        descriptor: &ArtifactDescriptor,
    ) -> Result<Vec<u8>, PoiArtifactError> {
        let started = Instant::now();
        let bytes = TrustlessArtifactFetcher::new(&self.client, &self.config.gateway_urls)
            .fetch_artifact_cid(&descriptor.cid, descriptor.byte_size)
            .await?;
        descriptor.verify_bytes(&bytes)?;
        debug!(
            cid = %descriptor.cid,
            bytes = bytes.len(),
            elapsed_ms = started.elapsed().as_millis(),
            "fetched verified POI artifact"
        );
        Ok(bytes)
    }

    async fn fetch_verified_cache_from_entry(
        &self,
        identity: PoiCacheIdentity,
        manifest_sequence: u64,
        entry: ManifestEntry,
        cache_generation: u64,
    ) -> Result<PoiArtifactRefresh, PoiArtifactError> {
        let started = Instant::now();
        let mut cache = PoiCache::new(identity.clone());
        let target_index = Some(entry.current_tip_index);

        let base_started = Instant::now();
        self.report_progress(
            PoiArtifactCachePhase::DownloadingBase,
            Some(0),
            target_index,
        );
        let base_bytes = self.fetch_artifact(&entry.base).await?;
        let base = SnapshotReader::read(&base_bytes)?;
        let mut next_start = validate_snapshot(&base, &identity, &entry, SnapshotKind::Base, 0)?;
        cache.apply_verified_artifact_events(&base.events)?;
        self.report_progress(
            PoiArtifactCachePhase::ApplyingDeltas,
            Some(next_start.saturating_sub(1)),
            target_index,
        );
        let base_elapsed_ms = base_started.elapsed().as_millis();

        let deltas_started = Instant::now();
        let mut delta_events = 0_usize;
        for delta_descriptor in &entry.deltas {
            self.report_progress(
                PoiArtifactCachePhase::ApplyingDeltas,
                Some(next_start.saturating_sub(1)),
                target_index,
            );
            let delta_bytes = self.fetch_artifact(delta_descriptor).await?;
            let delta = SnapshotReader::read(&delta_bytes)?;
            next_start =
                validate_snapshot(&delta, &identity, &entry, SnapshotKind::Delta, next_start)?;
            delta_events = delta_events.saturating_add(delta.events.len());
            cache.apply_verified_artifact_events(&delta.events)?;
            self.report_progress(
                PoiArtifactCachePhase::ApplyingDeltas,
                Some(next_start.saturating_sub(1)),
                target_index,
            );
        }
        let deltas_elapsed_ms = deltas_started.elapsed().as_millis();

        let final_index = next_start
            .checked_sub(1)
            .ok_or(PoiArtifactError::RangeOverflow)?;
        if final_index != entry.current_tip_index {
            return Err(PoiArtifactError::ReplayTipMismatch {
                expected: entry.current_tip_index,
                actual: final_index,
            });
        }

        let blocked_started = Instant::now();
        self.report_progress(
            PoiArtifactCachePhase::SyncingBlockedShields,
            Some(final_index),
            target_index,
        );
        let blocked_bytes = self.fetch_artifact(&entry.blocked_shields).await?;
        let blocked = BlockedShieldsArtifact::read(&blocked_bytes)?;
        let blocked_records = validate_blocked_shields_artifact(&blocked, &identity)?;
        cache.replace_blocked_shields(&blocked_records)?;
        let blocked_elapsed_ms = blocked_started.elapsed().as_millis();

        let root_started = Instant::now();
        self.report_progress(
            PoiArtifactCachePhase::ValidatingRoots,
            Some(final_index),
            target_index,
        );
        verify_manifest_root(&mut cache, &entry)?;
        cache.accept_current_roots();
        let accepted_roots = cache.current_roots();
        let root_validation_elapsed_ms = root_started.elapsed().as_millis();
        debug!(
            chain_id = identity.chain_id,
            list_key = %hex::encode(identity.list_key),
            manifest_sequence,
            roots = accepted_roots.len(),
            "accepted POI artifact cache refresh"
        );
        debug!(
            chain_id = identity.chain_id,
            list_key = %hex::encode(identity.list_key),
            manifest_sequence,
            base_events = base.events.len(),
            delta_count = entry.deltas.len(),
            delta_events,
            blocked_records = blocked_records.len(),
            base_elapsed_ms,
            deltas_elapsed_ms,
            blocked_elapsed_ms,
            root_validation_elapsed_ms,
            elapsed_ms = started.elapsed().as_millis(),
            "full POI artifact cache replay complete"
        );

        Ok(PoiArtifactRefresh {
            manifest_sequence,
            cache: cache.clone(),
            entry,
            cache_generation,
            corpus_advanced: true,
        })
    }

    #[cfg(test)]
    pub(crate) async fn prepare_cache_with_optional_preloaded(
        &self,
        db: &DbStore,
        identity: PoiCacheIdentity,
        preloaded: Option<PersistedPoiArtifactCache>,
        now: SystemTime,
    ) -> Result<PoiArtifactRefresh, PoiArtifactError> {
        let observed_manifest = self.fetch_observed_manifest(db, now).await?;
        self.prepare_cache_with_observed_manifest(db, identity, preloaded, &observed_manifest)
            .await
    }

    pub(crate) async fn fetch_observed_manifest(
        &self,
        db: &DbStore,
        now: SystemTime,
    ) -> Result<ObservedPoiManifest, PoiArtifactError> {
        let trust_store = PoiPublisherTrustStore::new(db, self.config.trusted_publisher_pubkey);
        let last_sequence = trust_store.watermark()?;
        self.report_progress(PoiArtifactCachePhase::FetchingManifest, None, None);
        let manifest = self.fetch_manifest(last_sequence, now).await?;
        trust_store.observe(manifest)
    }

    pub(crate) async fn prepare_cache_with_observed_manifest(
        &self,
        db: &DbStore,
        identity: PoiCacheIdentity,
        preloaded: Option<PersistedPoiArtifactCache>,
        observed_manifest: &ObservedPoiManifest,
    ) -> Result<PoiArtifactRefresh, PoiArtifactError> {
        let load_started = Instant::now();
        let preloaded = match preloaded {
            Some(preloaded) => Some(preloaded),
            None => load_persisted_cache_for_publisher(
                db,
                &identity,
                self.config.trusted_publisher_pubkey,
            )?,
        };
        self.prepare_cache_with_preloaded(
            db,
            identity,
            preloaded,
            load_started.elapsed().as_millis(),
            observed_manifest,
        )
        .await
    }

    async fn prepare_cache_with_preloaded(
        &self,
        db: &DbStore,
        identity: PoiCacheIdentity,
        persisted: Option<PersistedPoiArtifactCache>,
        load_persisted_elapsed_ms: u128,
        observed_manifest: &ObservedPoiManifest,
    ) -> Result<PoiArtifactRefresh, PoiArtifactError> {
        let started = Instant::now();
        let cache_generation = if let Some(persisted) = persisted.as_ref() {
            persisted.cache_generation
        } else {
            let generation = poi_artifact_cache_generation_cell(db)?;
            with_poi_artifact_cache_generation(&generation, |generation| generation)
        };
        let refresh_started = Instant::now();
        let refresh = self
            .refresh_verified_cache(
                identity.clone(),
                persisted,
                observed_manifest,
                cache_generation,
            )
            .await?;
        let refresh_elapsed_ms = refresh_started.elapsed().as_millis();
        debug!(
            chain_id = identity.chain_id,
            list_key = %hex::encode(identity.list_key),
            manifest_sequence = refresh.manifest_sequence,
            load_persisted_elapsed_ms,
            refresh_elapsed_ms,
            elapsed_ms = started.elapsed().as_millis(),
            "prepared publisher-attested POI artifact candidate"
        );
        Ok(refresh)
    }

    async fn refresh_verified_cache(
        &self,
        identity: PoiCacheIdentity,
        persisted: Option<PersistedPoiArtifactCache>,
        observed_manifest: &ObservedPoiManifest,
        cache_generation: u64,
    ) -> Result<PoiArtifactRefresh, PoiArtifactError> {
        let manifest = observed_manifest.manifest();
        let entry = manifest_entry_for_identity(manifest, &identity)?.clone();

        if let Some(persisted) = persisted.as_ref()
            && persisted.record.current_tip_index >= entry.current_tip_index
        {
            if persisted.record.current_tip_index == entry.current_tip_index
                && persisted.record.current_tip_root != entry.current_tip_merkleroot
            {
                return Err(PoiArtifactError::CorpusTipRootConflict {
                    tip_index: entry.current_tip_index,
                });
            }
            return Ok(PoiArtifactRefresh {
                manifest_sequence: manifest.sequence,
                cache: persisted.cache.clone(),
                entry,
                cache_generation,
                corpus_advanced: false,
            });
        }

        if let Some(persisted) = persisted {
            if let Some(refresh) = self
                .try_incremental_refresh(
                    &identity,
                    manifest.sequence,
                    &entry,
                    &persisted,
                    cache_generation,
                )
                .await?
            {
                return Ok(refresh);
            }

            match self
                .try_artifact_suffix_merge(
                    &identity,
                    manifest.sequence,
                    &entry,
                    &persisted,
                    cache_generation,
                )
                .await
            {
                Ok(Some(refresh)) => return Ok(refresh),
                Ok(None) => {}
                Err(err) => debug!(
                    ?err,
                    chain_id = identity.chain_id,
                    list_key = %hex::encode(identity.list_key),
                    manifest_sequence = manifest.sequence,
                    "artifact suffix POI cache merge skipped"
                ),
            }
        }

        self.fetch_verified_cache_from_entry(identity, manifest.sequence, entry, cache_generation)
            .await
    }

    async fn try_incremental_refresh(
        &self,
        identity: &PoiCacheIdentity,
        manifest_sequence: u64,
        entry: &ManifestEntry,
        persisted: &PersistedPoiArtifactCache,
        cache_generation: u64,
    ) -> Result<Option<PoiArtifactRefresh>, PoiArtifactError> {
        let started = Instant::now();
        if !descriptor_matches_record(&entry.base, &persisted.record.base_descriptor) {
            return Ok(None);
        }
        if persisted.record.current_tip_index > entry.current_tip_index {
            return Ok(None);
        }

        let applied_delta_count =
            common_delta_prefix_len(&persisted.record.applied_delta_descriptors, &entry.deltas);
        if applied_delta_count != persisted.record.applied_delta_descriptors.len() {
            return Ok(None);
        }

        let mut cache = persisted.cache.clone();
        let mut next_start = persisted
            .record
            .current_tip_index
            .checked_add(1)
            .ok_or(PoiArtifactError::RangeOverflow)?;
        let target_index = Some(entry.current_tip_index);

        let deltas_started = Instant::now();
        let mut delta_events = 0_usize;
        for delta_descriptor in entry.deltas.iter().skip(applied_delta_count) {
            self.report_progress(
                PoiArtifactCachePhase::ApplyingDeltas,
                Some(next_start.saturating_sub(1)),
                target_index,
            );
            let delta_bytes = self.fetch_artifact(delta_descriptor).await?;
            let delta = SnapshotReader::read(&delta_bytes)?;
            next_start =
                validate_snapshot(&delta, identity, entry, SnapshotKind::Delta, next_start)?;
            delta_events = delta_events.saturating_add(delta.events.len());
            cache.apply_verified_artifact_events(&delta.events)?;
            self.report_progress(
                PoiArtifactCachePhase::ApplyingDeltas,
                Some(next_start.saturating_sub(1)),
                target_index,
            );
        }
        let deltas_elapsed_ms = deltas_started.elapsed().as_millis();

        let final_index = next_start
            .checked_sub(1)
            .ok_or(PoiArtifactError::RangeOverflow)?;
        if final_index != entry.current_tip_index {
            return Err(PoiArtifactError::ReplayTipMismatch {
                expected: entry.current_tip_index,
                actual: final_index,
            });
        }

        let blocked_started = Instant::now();
        self.report_progress(
            PoiArtifactCachePhase::SyncingBlockedShields,
            Some(final_index),
            target_index,
        );
        let mut blocked_records_count = 0_usize;
        let blocked_refreshed = !descriptor_matches_record(
            &entry.blocked_shields,
            &persisted.record.blocked_shields_descriptor,
        );
        if blocked_refreshed {
            let blocked_bytes = self.fetch_artifact(&entry.blocked_shields).await?;
            let blocked = BlockedShieldsArtifact::read(&blocked_bytes)?;
            let blocked_records = validate_blocked_shields_artifact(&blocked, identity)?;
            blocked_records_count = blocked_records.len();
            cache.replace_blocked_shields(&blocked_records)?;
        }
        let blocked_elapsed_ms = blocked_started.elapsed().as_millis();

        let root_started = Instant::now();
        self.report_progress(
            PoiArtifactCachePhase::ValidatingRoots,
            Some(final_index),
            target_index,
        );
        verify_manifest_root(&mut cache, entry)?;
        cache.accept_current_roots();
        let root_validation_elapsed_ms = root_started.elapsed().as_millis();
        debug!(
            chain_id = identity.chain_id,
            list_key = %hex::encode(identity.list_key),
            manifest_sequence,
            applied_delta_count,
            new_delta_count = entry.deltas.len().saturating_sub(applied_delta_count),
            delta_events,
            blocked_refreshed,
            blocked_records = blocked_records_count,
            deltas_elapsed_ms,
            blocked_elapsed_ms,
            root_validation_elapsed_ms,
            elapsed_ms = started.elapsed().as_millis(),
            "incremental POI artifact cache replay complete"
        );
        Ok(Some(PoiArtifactRefresh {
            manifest_sequence,
            cache,
            entry: entry.clone(),
            cache_generation,
            corpus_advanced: true,
        }))
    }

    async fn try_artifact_suffix_merge(
        &self,
        identity: &PoiCacheIdentity,
        manifest_sequence: u64,
        entry: &ManifestEntry,
        persisted: &PersistedPoiArtifactCache,
        cache_generation: u64,
    ) -> Result<Option<PoiArtifactRefresh>, ArtifactSuffixMergeError> {
        let started = Instant::now();
        let local_tip_index = persisted.record.current_tip_index;
        let artifact_tip_index = entry.current_tip_index;
        if local_tip_index >= artifact_tip_index {
            return Ok(None);
        }

        let start_index = local_tip_index
            .checked_add(1)
            .ok_or(ArtifactSuffixMergeError::RangeOverflow)?;
        let (start_tree, _) = normalize_tree_position(0, start_index);
        let (artifact_tip_tree, _) = normalize_tree_position(0, artifact_tip_index);
        if start_tree != artifact_tip_tree {
            debug!(
                chain_id = identity.chain_id,
                list_key = %hex::encode(identity.list_key),
                manifest_sequence,
                start_index,
                artifact_tip_index,
                start_tree,
                artifact_tip_tree,
                "artifact suffix POI cache merge skipped across tree boundary"
            );
            return Ok(None);
        }

        let mut cache = persisted.cache.clone();
        let artifact_started = Instant::now();
        let outcome = self
            .apply_artifact_suffix(identity, &mut cache, entry, local_tip_index)
            .await?;
        let artifact_elapsed_ms = artifact_started.elapsed().as_millis();

        let root_started = Instant::now();
        self.report_progress(
            PoiArtifactCachePhase::ValidatingRoots,
            Some(artifact_tip_index),
            Some(artifact_tip_index),
        );
        verify_manifest_root(&mut cache, entry)?;
        cache.accept_current_roots();
        let root_validation_elapsed_ms = root_started.elapsed().as_millis();

        let blocked_started = Instant::now();
        self.report_progress(
            PoiArtifactCachePhase::SyncingBlockedShields,
            Some(artifact_tip_index),
            Some(artifact_tip_index),
        );
        let mut blocked_records_count = 0_usize;
        let blocked_refreshed = !descriptor_matches_record(
            &entry.blocked_shields,
            &persisted.record.blocked_shields_descriptor,
        );
        if blocked_refreshed {
            blocked_records_count = self
                .refresh_blocked_shields(identity, &entry.blocked_shields, &mut cache)
                .await?;
        }
        let blocked_elapsed_ms = blocked_started.elapsed().as_millis();

        debug!(
            chain_id = identity.chain_id,
            list_key = %hex::encode(identity.list_key),
            manifest_sequence,
            local_tip_index,
            artifact_tip_index,
            base_events = outcome.base_events,
            base_applied_events = outcome.base_applied_events,
            delta_count = outcome.delta_count,
            delta_events = outcome.delta_events,
            delta_applied_events = outcome.delta_applied_events,
            skipped_events = outcome.skipped_events,
            blocked_refreshed,
            blocked_records = blocked_records_count,
            proxy_root_elapsed_ms = 0_u128,
            artifact_elapsed_ms,
            root_validation_elapsed_ms,
            blocked_elapsed_ms,
            elapsed_ms = started.elapsed().as_millis(),
            "artifact suffix POI cache merge complete"
        );

        Ok(Some(PoiArtifactRefresh {
            manifest_sequence,
            cache,
            entry: entry.clone(),
            cache_generation,
            corpus_advanced: true,
        }))
    }

    async fn apply_artifact_suffix(
        &self,
        identity: &PoiCacheIdentity,
        cache: &mut PoiCache,
        entry: &ManifestEntry,
        local_tip_index: u64,
    ) -> Result<ArtifactSuffixMergeOutcome, PoiArtifactError> {
        let mut outcome = ArtifactSuffixMergeOutcome::default();
        let mut expected_artifact_start = 0;
        let mut expected_apply_index = local_tip_index
            .checked_add(1)
            .ok_or(PoiArtifactError::RangeOverflow)?;
        let target_index = Some(entry.current_tip_index);

        self.report_progress(
            PoiArtifactCachePhase::DownloadingBase,
            Some(local_tip_index),
            target_index,
        );
        let base_bytes = self.fetch_artifact(&entry.base).await?;
        let base = SnapshotReader::read(&base_bytes)?;
        expected_artifact_start = validate_snapshot(
            &base,
            identity,
            entry,
            SnapshotKind::Base,
            expected_artifact_start,
        )?;
        outcome.base_events = base.events.len();
        let applied = apply_snapshot_suffix_events(cache, &base, &mut expected_apply_index)?;
        outcome.base_applied_events = applied;
        outcome.skipped_events = outcome
            .skipped_events
            .saturating_add(base.events.len().saturating_sub(applied));
        self.report_progress(
            PoiArtifactCachePhase::ApplyingDeltas,
            Some(expected_apply_index.saturating_sub(1)),
            target_index,
        );

        for delta_descriptor in &entry.deltas {
            self.report_progress(
                PoiArtifactCachePhase::ApplyingDeltas,
                Some(expected_apply_index.saturating_sub(1)),
                target_index,
            );
            let delta_bytes = self.fetch_artifact(delta_descriptor).await?;
            let delta = SnapshotReader::read(&delta_bytes)?;
            expected_artifact_start = validate_snapshot(
                &delta,
                identity,
                entry,
                SnapshotKind::Delta,
                expected_artifact_start,
            )?;
            outcome.delta_count += 1;
            outcome.delta_events = outcome.delta_events.saturating_add(delta.events.len());
            let applied = apply_snapshot_suffix_events(cache, &delta, &mut expected_apply_index)?;
            outcome.delta_applied_events = outcome.delta_applied_events.saturating_add(applied);
            outcome.skipped_events = outcome
                .skipped_events
                .saturating_add(delta.events.len().saturating_sub(applied));
            self.report_progress(
                PoiArtifactCachePhase::ApplyingDeltas,
                Some(expected_apply_index.saturating_sub(1)),
                target_index,
            );
        }

        let final_index = expected_apply_index
            .checked_sub(1)
            .ok_or(PoiArtifactError::RangeOverflow)?;
        if final_index != entry.current_tip_index {
            return Err(PoiArtifactError::ReplayTipMismatch {
                expected: entry.current_tip_index,
                actual: final_index,
            });
        }

        Ok(outcome)
    }

    async fn refresh_blocked_shields(
        &self,
        identity: &PoiCacheIdentity,
        descriptor: &ArtifactDescriptor,
        cache: &mut PoiCache,
    ) -> Result<usize, PoiArtifactError> {
        let blocked_bytes = self.fetch_artifact(descriptor).await?;
        let blocked = BlockedShieldsArtifact::read(&blocked_bytes)?;
        let blocked_records = validate_blocked_shields_artifact(&blocked, identity)?;
        cache.replace_blocked_shields(&blocked_records)?;
        Ok(blocked_records.len())
    }

    async fn fetch_url(&self, url: &Url) -> Result<Vec<u8>, PoiArtifactError> {
        let started = Instant::now();
        let bytes = trustless_artifacts::fetch_manifest_url(&self.client, url).await?;
        debug!(
            url = %url,
            bytes = bytes.len(),
            elapsed_ms = started.elapsed().as_millis(),
            "fetched POI artifact URL"
        );
        Ok(bytes)
    }
}

pub(crate) struct PoiArtifactRefresh {
    pub(crate) manifest_sequence: u64,
    pub(crate) cache: PoiCache,
    pub(crate) entry: ManifestEntry,
    pub(crate) cache_generation: u64,
    pub(crate) corpus_advanced: bool,
}

#[derive(Clone)]
pub(crate) struct ObservedPoiManifest {
    manifest: Manifest,
}

impl ObservedPoiManifest {
    #[must_use]
    pub(crate) const fn manifest(&self) -> &Manifest {
        &self.manifest
    }
}

struct PoiPublisherTrustStore<'a> {
    db: &'a DbStore,
    publisher_pubkey: FixedBytes<32>,
}

impl<'a> PoiPublisherTrustStore<'a> {
    const fn new(db: &'a DbStore, publisher_pubkey: FixedBytes<32>) -> Self {
        Self {
            db,
            publisher_pubkey,
        }
    }

    fn watermark(&self) -> Result<Option<u64>, PoiArtifactError> {
        let _sync_state = lock_poi_artifact_cache_sync();
        publisher_manifest_watermark(self.db, self.publisher_pubkey)
    }

    fn observe(&self, manifest: Manifest) -> Result<ObservedPoiManifest, PoiArtifactError> {
        let _sync_state = lock_poi_artifact_cache_sync();
        let previous = publisher_manifest_watermark(self.db, self.publisher_pubkey)?;
        validate_manifest_sequence(&manifest, previous)?;
        let (accepted_sequence, _) = advance_publisher_manifest_watermark(
            self.db,
            self.publisher_pubkey,
            manifest.sequence,
        )?;
        if accepted_sequence != manifest.sequence {
            return Err(PoiArtifactError::ManifestSequenceRollback {
                previous: accepted_sequence,
                received: manifest.sequence,
            });
        }
        Ok(ObservedPoiManifest { manifest })
    }
}

#[derive(Clone)]
pub(crate) struct PersistedPoiArtifactCache {
    pub(crate) record: PoiArtifactCacheRecord,
    pub(crate) cache: PoiCache,
    pub(crate) cache_generation: u64,
}

pub(crate) struct PoiCorpusStore<'a> {
    db: &'a DbStore,
    generation: u64,
    publisher_pubkey: FixedBytes<32>,
}

impl<'a> PoiCorpusStore<'a> {
    pub(crate) const fn new(
        db: &'a DbStore,
        generation: u64,
        publisher_pubkey: FixedBytes<32>,
    ) -> Self {
        Self {
            db,
            generation,
            publisher_pubkey,
        }
    }

    pub(crate) fn load(
        &self,
        identity: &PoiCacheIdentity,
    ) -> Result<Option<PersistedPoiArtifactCache>, PoiArtifactError> {
        load_persisted_cache_for_publisher(self.db, identity, self.publisher_pubkey)
    }

    pub(crate) fn commit_artifact(
        &self,
        cache: &PoiCache,
        refresh: &PoiArtifactRefresh,
    ) -> Result<PersistedPoiArtifactCache, PoiArtifactError> {
        persist_prepared_corpus(self.db, cache, refresh, self.publisher_pubkey)?;
        self.load(cache.identity())?
            .ok_or(PoiArtifactError::MissingCommittedCorpus)
    }

    pub(crate) fn commit_public_rpc(
        &self,
        cache: &PoiCache,
        range_start_index: u64,
    ) -> Result<PersistedPoiArtifactCache, PoiArtifactError> {
        persist_public_rpc_cache_with_publisher(
            self.db,
            cache,
            self.generation,
            range_start_index,
            Some(self.publisher_pubkey),
        )?;
        self.load(cache.identity())?
            .ok_or(PoiArtifactError::MissingCommittedCorpus)
    }
}

pub(crate) fn load_poi_rpc_health(
    db: &DbStore,
    identity: &PoiCacheIdentity,
    generation: u64,
    legacy_last_successful_rpc_sync_at_ms: Option<u64>,
) -> Result<Option<u64>, PoiArtifactError> {
    let mut sync_state = lock_poi_artifact_cache_sync();
    let current_generation = sync_state.generation_cell(db)?.load(Ordering::Acquire);
    if current_generation != generation {
        return Err(PoiArtifactError::StalePublicCacheGeneration {
            expected: current_generation,
            actual: generation,
        });
    }
    match db.inspect_poi_corpus_rpc_health(
        identity.chain_type,
        identity.chain_id,
        &identity.txid_version,
        &identity.list_key,
    )? {
        StoredRecord::Valid(health) if health.cache_generation == generation => {
            Ok(health.last_successful_rpc_sync_at_ms)
        }
        StoredRecord::Valid(_) => Ok(None),
        StoredRecord::Corrupt { key } => {
            warn!(%key, "ignoring corrupt advisory PPOI RPC health");
            Ok(None)
        }
        StoredRecord::Missing => {
            if legacy_last_successful_rpc_sync_at_ms.is_some() {
                db.put_poi_corpus_rpc_health(&PoiCorpusRpcHealthRecord {
                    chain_type: identity.chain_type,
                    chain_id: identity.chain_id,
                    txid_version: identity.txid_version.clone(),
                    list_key: identity.list_key,
                    cache_generation: generation,
                    last_successful_rpc_sync_at_ms: legacy_last_successful_rpc_sync_at_ms,
                    updated_at: 0,
                })?;
            }
            Ok(legacy_last_successful_rpc_sync_at_ms)
        }
    }
}

pub(crate) fn record_poi_rpc_success(
    db: &DbStore,
    identity: &PoiCacheIdentity,
    generation: u64,
) -> Result<(), PoiArtifactError> {
    let mut sync_state = lock_poi_artifact_cache_sync();
    let current_generation = sync_state.generation_cell(db)?.load(Ordering::Acquire);
    if current_generation != generation {
        return Err(PoiArtifactError::StalePublicCacheGeneration {
            expected: current_generation,
            actual: generation,
        });
    }
    db.put_poi_corpus_rpc_health(&PoiCorpusRpcHealthRecord {
        chain_type: identity.chain_type,
        chain_id: identity.chain_id,
        txid_version: identity.txid_version.clone(),
        list_key: identity.list_key,
        cache_generation: generation,
        last_successful_rpc_sync_at_ms: Some(unix_time_ms()),
        updated_at: 0,
    })?;
    Ok(())
}

fn publisher_manifest_watermark(
    db: &DbStore,
    publisher_pubkey: FixedBytes<32>,
) -> Result<Option<u64>, PoiArtifactError> {
    match db.inspect_poi_publisher_manifest_watermark(&publisher_pubkey)? {
        StoredRecord::Valid(record) => return Ok(Some(record.accepted_sequence)),
        StoredRecord::Corrupt { key } => {
            return Err(local_db::DbError::InvalidPpoiSidecarRecord {
                kind: "publisher manifest watermark",
                key,
            }
            .into());
        }
        StoredRecord::Missing => {}
    }

    let mut accepted_sequence = None;
    let scan = db.scan_poi_artifact_caches()?;
    if !scan.invalid_keys.is_empty() {
        return Err(PoiArtifactError::AmbiguousPublisherWatermarkMigration {
            invalid_records: scan.invalid_keys.len(),
        });
    }
    for mut record in scan.records {
        normalize_legacy_artifact_metadata(&mut record);
        let identity = PoiCacheIdentity::new(
            record.chain_type,
            record.chain_id,
            record.txid_version.clone(),
            record.list_key,
        );
        if validate_persisted_record(&record, &identity, Some(publisher_pubkey)).is_ok()
            && let Some(sequence) = publisher_sequence_for_record(&record, publisher_pubkey)
        {
            let sequence = sequence.max(record.legacy_observed_manifest_sequence);
            accepted_sequence =
                Some(accepted_sequence.map_or(sequence, |accepted: u64| accepted.max(sequence)));
        }
    }
    let accepted_sequence = accepted_sequence.filter(|sequence| *sequence > 0);
    if let Some(sequence) = accepted_sequence {
        db.advance_poi_publisher_manifest_watermark(publisher_pubkey, sequence)?;
    }
    Ok(accepted_sequence)
}

fn advance_publisher_manifest_watermark(
    db: &DbStore,
    publisher_pubkey: FixedBytes<32>,
    accepted_sequence: u64,
) -> Result<(u64, bool), PoiArtifactError> {
    let (record, advanced) =
        db.advance_poi_publisher_manifest_watermark(publisher_pubkey, accepted_sequence)?;
    Ok((record.accepted_sequence, advanced))
}

fn publisher_sequence_for_record(
    record: &PoiArtifactCacheRecord,
    expected_publisher_pubkey: FixedBytes<32>,
) -> Option<u64> {
    match &record.validation {
        PoiCorpusValidationRecord::PublisherAttested {
            publisher_pubkey,
            manifest_sequence,
            ..
        }
        | PoiCorpusValidationRecord::PublisherAndListSigned {
            publisher_pubkey,
            manifest_sequence,
            ..
        } if *publisher_pubkey == expected_publisher_pubkey => Some(*manifest_sequence),
        _ => None,
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct PoiArtifactCacheReset {
    pub(crate) removed: u64,
    pub(crate) generation: u64,
}

#[derive(Debug, Default)]
struct ArtifactSuffixMergeOutcome {
    base_events: usize,
    base_applied_events: usize,
    delta_count: usize,
    delta_events: usize,
    delta_applied_events: usize,
    skipped_events: usize,
}

#[derive(Debug, Error)]
pub(crate) enum PoiArtifactError {
    #[error("POI artifact source has no gateway URLs configured")]
    NoGateways,
    #[error("POI artifact manifest JSON decode failed")]
    Json(#[source] serde_json::Error),
    #[error("POI artifact manifest verification failed")]
    Manifest(#[from] ManifestError),
    #[error("POI snapshot verification failed")]
    Snapshot(#[from] SnapshotError),
    #[error("blocked-shields artifact verification failed")]
    BlockedShieldsArtifact(#[from] BlockedShieldsArtifactError),
    #[error("POI artifact upstream signature verification failed")]
    Verify(#[from] poi::artifacts::VerifyError),
    #[error("POI artifact trustless retrieval failed")]
    Trustless(#[from] TrustlessArtifactError),
    #[error("POI artifact cache replay failed")]
    Cache(#[from] PoiCacheError),
    #[error("POI artifact cache persistence failed")]
    Db(#[from] local_db::DbError),
    #[error("manifest sequence rollback: previous={previous}, received={received}")]
    ManifestSequenceRollback { previous: u64, received: u64 },
    #[error("artifact candidate uses manifest sequence {candidate} before durable observation")]
    UnobservedManifestSequence { candidate: u64 },
    #[error(
        "publisher watermark migration is ambiguous because {invalid_records} legacy PPOI corpus records are corrupt"
    )]
    AmbiguousPublisherWatermarkMigration { invalid_records: usize },
    #[error("manifest is stale on first run: age={age:?}, max={max:?}")]
    ManifestStale { age: Duration, max: Duration },
    #[error("manifest issued_at_ms is in the future")]
    ManifestIssuedInFuture,
    #[error("manifest does not contain entry for chain_id={chain_id} list_key={list_key}")]
    MissingManifestEntry { chain_id: u64, list_key: String },
    #[error("stale POI artifact cache refresh: expected generation {expected}, actual {actual}")]
    StalePublicCacheGeneration { expected: u64, actual: u64 },
    #[cfg(test)]
    #[error("invalid hex in {field}: {value}")]
    InvalidHex { field: &'static str, value: String },
    #[cfg(test)]
    #[error("{field} has {actual} bytes, expected {expected}")]
    InvalidByteLen {
        field: &'static str,
        expected: usize,
        actual: usize,
    },
    #[error("snapshot scope mismatch for {field}: expected {expected}, got {actual}")]
    SnapshotScopeMismatch {
        field: &'static str,
        expected: String,
        actual: String,
    },
    #[error("snapshot kind mismatch: expected {expected:?}, got {actual:?}")]
    SnapshotKindMismatch {
        expected: SnapshotKind,
        actual: SnapshotKind,
    },
    #[error("snapshot start index mismatch: expected {expected}, got {actual}")]
    SnapshotStartMismatch { expected: u64, actual: u64 },
    #[error("snapshot range overflow")]
    RangeOverflow,
    #[error("artifact replay tip mismatch: expected {expected}, got {actual}")]
    ReplayTipMismatch { expected: u64, actual: u64 },
    #[error("artifact suffix event index mismatch: expected {expected}, got {actual}")]
    ArtifactSuffixEventIndexMismatch { expected: u64, actual: u64 },
    #[error("replayed POI root missing for tree {tree_number}")]
    MissingReplayRoot { tree_number: u32 },
    #[error("POI corpus root missing for tree {tree_number}")]
    MissingCacheRoot { tree_number: u32 },
    #[error("POI corpus candidate conflicts with the durable root at tip {tip_index}")]
    CorpusTipRootConflict { tip_index: u64 },
    #[error("persisted POI corpus is empty")]
    EmptyPersistedCorpus,
    #[error(
        "persisted POI corpus cursor mismatch: next event {next_event_index}, next leaf {next_leaf_index}"
    )]
    PersistedCursorMismatch {
        next_event_index: u64,
        next_leaf_index: u64,
    },
    #[error("persisted POI corpus tip mismatch: metadata {metadata}, payload {payload}")]
    PersistedTipMismatch { metadata: u64, payload: u64 },
    #[error("persisted POI corpus record identity does not match its payload")]
    PersistedIdentityMismatch,
    #[error("persisted POI corpus root is missing for tree {tree_number}")]
    MissingPersistedRoot { tree_number: u32 },
    #[error("persisted POI corpus root does not match its payload at tip {tip_index}")]
    PersistedRootMismatch { tip_index: u64 },
    #[error("persisted POI corpus payload does not retain validated current roots")]
    PersistedRootsNotValidated,
    #[error("persisted POI corpus artifact metadata is inconsistent: {reason}")]
    PersistedArtifactMetadata { reason: &'static str },
    #[error("persisted POI corpus artifact root does not match its payload at tip {tip_index}")]
    PersistedArtifactRootMismatch { tip_index: u64 },
    #[error("persisted POI corpus validation provenance is inconsistent: {reason}")]
    PersistedValidationProvenance { reason: &'static str },
    #[error("POI corpus commit completed without a readable durable corpus")]
    MissingCommittedCorpus,
    #[error("replayed POI root mismatch: expected {expected}, got {actual}")]
    ReplayRootMismatch { expected: String, actual: String },
}

#[derive(Debug, Error)]
enum ArtifactSuffixMergeError {
    #[error("POI artifact validation failed")]
    Artifact(#[from] PoiArtifactError),
    #[error("POI artifact suffix merge range overflow")]
    RangeOverflow,
}

const fn normalize_legacy_artifact_metadata(record: &mut PoiArtifactCacheRecord) {
    if record.artifact_tip_index.is_none()
        && matches!(record.source, PoiCacheRecordSource::IndexedArtifacts)
    {
        record.artifact_tip_index = Some(record.current_tip_index);
        record.artifact_tip_root = Some(record.current_tip_root);
    }
}

fn validate_persisted_corpus(
    record: &PoiArtifactCacheRecord,
    cache: &PoiCache,
    expected_publisher_pubkey: Option<FixedBytes<32>>,
) -> Result<(), PoiArtifactError> {
    let next_event_index = cache.progress().next_event_index;
    let next_leaf_index = cache.progress().next_leaf_index;
    if next_event_index == 0 {
        return Err(PoiArtifactError::EmptyPersistedCorpus);
    }
    if next_event_index != next_leaf_index {
        return Err(PoiArtifactError::PersistedCursorMismatch {
            next_event_index,
            next_leaf_index,
        });
    }
    let payload_tip_index = next_event_index - 1;
    if record.current_tip_index != payload_tip_index {
        return Err(PoiArtifactError::PersistedTipMismatch {
            metadata: record.current_tip_index,
            payload: payload_tip_index,
        });
    }
    let roots = cache.clone().current_roots();
    let (tree_number, _) = normalize_tree_position(0, payload_tip_index);
    let payload_tip_root = roots
        .get(&tree_number)
        .ok_or(PoiArtifactError::MissingPersistedRoot { tree_number })?;
    if record.current_tip_root != *payload_tip_root {
        return Err(PoiArtifactError::PersistedRootMismatch {
            tip_index: payload_tip_index,
        });
    }
    if !matches!(
        &cache.progress().root_validation,
        PoiCacheRootValidation::Validated { roots: validated } if validated == &roots
    ) {
        return Err(PoiArtifactError::PersistedRootsNotValidated);
    }

    match (record.artifact_tip_index, record.artifact_tip_root) {
        (Some(index), Some(root)) if index <= payload_tip_index => {
            if cache.root_at_global_index(index) != Some(root) {
                return Err(PoiArtifactError::PersistedArtifactRootMismatch { tip_index: index });
            }
        }
        (None, None) => {}
        (Some(_), Some(_)) => {
            return Err(PoiArtifactError::PersistedArtifactMetadata {
                reason: "artifact tip exceeds serving tip",
            });
        }
        _ => {
            return Err(PoiArtifactError::PersistedArtifactMetadata {
                reason: "artifact tip index and root must be present together",
            });
        }
    }

    match &record.validation {
        PoiCorpusValidationRecord::Legacy => {
            if expected_publisher_pubkey.is_some()
                && matches!(record.source, PoiCacheRecordSource::IndexedArtifacts)
            {
                return Err(PoiArtifactError::PersistedValidationProvenance {
                    reason: "legacy artifact evidence does not identify the configured publisher",
                });
            }
        }
        PoiCorpusValidationRecord::PublisherAttested {
            publisher_pubkey,
            manifest_root,
            artifact_tip_index,
            ..
        } => {
            if expected_publisher_pubkey.is_some_and(|expected| expected != *publisher_pubkey)
                || !matches!(record.source, PoiCacheRecordSource::IndexedArtifacts)
                || record.artifact_tip_index != Some(*artifact_tip_index)
                || record.artifact_tip_root != Some(*manifest_root)
                || *artifact_tip_index != payload_tip_index
            {
                return Err(PoiArtifactError::PersistedValidationProvenance {
                    reason: "publisher-attested evidence does not match the serving artifact tip",
                });
            }
        }
        PoiCorpusValidationRecord::ListSignedRanges {
            list_key,
            from_index,
        } => {
            if !matches!(record.source, PoiCacheRecordSource::PublicRpc)
                || list_key != &record.list_key
                || record.artifact_tip_index.is_some()
                || *from_index > next_event_index
            {
                return Err(PoiArtifactError::PersistedValidationProvenance {
                    reason: "list-signed evidence does not match the public range corpus",
                });
            }
        }
        PoiCorpusValidationRecord::PublisherAndListSigned {
            publisher_pubkey,
            manifest_root,
            artifact_tip_index,
            list_key,
            list_signed_from_index,
            ..
        } => {
            if expected_publisher_pubkey.is_some_and(|expected| expected != *publisher_pubkey)
                || !matches!(record.source, PoiCacheRecordSource::PublicRpc)
                || list_key != &record.list_key
                || record.artifact_tip_index != Some(*artifact_tip_index)
                || record.artifact_tip_root != Some(*manifest_root)
                || *artifact_tip_index >= next_event_index
                || *list_signed_from_index != artifact_tip_index.saturating_add(1)
                || *list_signed_from_index > next_event_index
            {
                return Err(PoiArtifactError::PersistedValidationProvenance {
                    reason: "mixed publisher/list evidence does not match corpus boundaries",
                });
            }
        }
    }
    Ok(())
}

fn validate_persisted_record(
    record: &PoiArtifactCacheRecord,
    expected_identity: &PoiCacheIdentity,
    expected_publisher_pubkey: Option<FixedBytes<32>>,
) -> Result<PoiCache, PoiArtifactError> {
    if record.chain_type != expected_identity.chain_type
        || record.chain_id != expected_identity.chain_id
        || record.txid_version != expected_identity.txid_version
        || record.list_key != expected_identity.list_key
    {
        return Err(PoiArtifactError::PersistedIdentityMismatch);
    }
    let cache = PoiCache::from_bytes(&record.cache_payload, expected_identity)?;
    validate_persisted_corpus(record, &cache, expected_publisher_pubkey)?;
    Ok(cache)
}

#[cfg(test)]
pub(crate) fn load_persisted_cache(
    db: &DbStore,
    identity: &PoiCacheIdentity,
) -> Result<Option<PersistedPoiArtifactCache>, PoiArtifactError> {
    load_persisted_cache_with_publisher(db, identity, None)
}

pub(crate) fn load_persisted_cache_for_publisher(
    db: &DbStore,
    identity: &PoiCacheIdentity,
    publisher_pubkey: FixedBytes<32>,
) -> Result<Option<PersistedPoiArtifactCache>, PoiArtifactError> {
    load_persisted_cache_with_publisher(db, identity, Some(publisher_pubkey))
}

fn load_persisted_cache_with_publisher(
    db: &DbStore,
    identity: &PoiCacheIdentity,
    publisher_pubkey: Option<FixedBytes<32>>,
) -> Result<Option<PersistedPoiArtifactCache>, PoiArtifactError> {
    let mut sync_state = lock_poi_artifact_cache_sync();
    let cache_generation = sync_state.generation_cell(db)?.load(Ordering::Acquire);
    let Some(mut record) = db.get_poi_artifact_cache(
        identity.chain_type,
        identity.chain_id,
        &identity.txid_version,
        &identity.list_key,
    )?
    else {
        return Ok(None);
    };
    normalize_legacy_artifact_metadata(&mut record);
    let cache = validate_persisted_record(&record, identity, publisher_pubkey)?;
    Ok(Some(PersistedPoiArtifactCache {
        record,
        cache,
        cache_generation,
    }))
}

#[cfg(test)]
pub(crate) fn persist_refresh(
    db: &DbStore,
    identity: &PoiCacheIdentity,
    refresh: &PoiArtifactRefresh,
) -> Result<(), PoiArtifactError> {
    persist_refresh_with_publisher(db, identity, refresh, FixedBytes::ZERO)
}

#[cfg(test)]
pub(crate) fn persist_refresh_with_publisher(
    db: &DbStore,
    _identity: &PoiCacheIdentity,
    refresh: &PoiArtifactRefresh,
    publisher_pubkey: FixedBytes<32>,
) -> Result<(), PoiArtifactError> {
    advance_publisher_manifest_watermark(db, publisher_pubkey, refresh.manifest_sequence)?;
    persist_prepared_corpus(db, &refresh.cache, refresh, publisher_pubkey)?;
    Ok(())
}

pub(crate) fn persist_prepared_corpus(
    db: &DbStore,
    cache: &PoiCache,
    refresh: &PoiArtifactRefresh,
    publisher_pubkey: FixedBytes<32>,
) -> Result<bool, PoiArtifactError> {
    let current_generation = poi_artifact_cache_generation_cell(db)?.load(Ordering::Acquire);
    if refresh.cache_generation != current_generation {
        return Err(PoiArtifactError::StalePublicCacheGeneration {
            expected: current_generation,
            actual: refresh.cache_generation,
        });
    }
    let identity = cache.identity();
    let current_tip_index = cache.progress().next_event_index.saturating_sub(1);
    let (tree_number, _) = normalize_tree_position(0, current_tip_index);
    let current_tip_root = *cache
        .clone()
        .current_roots()
        .get(&tree_number)
        .ok_or(PoiArtifactError::MissingCacheRoot { tree_number })?;
    let record = PoiArtifactCacheRecord {
        chain_type: identity.chain_type,
        chain_id: identity.chain_id,
        txid_version: identity.txid_version.clone(),
        list_key: identity.list_key,
        source: PoiCacheRecordSource::IndexedArtifacts,
        validation: PoiCorpusValidationRecord::PublisherAttested {
            publisher_pubkey,
            manifest_sequence: refresh.manifest_sequence,
            manifest_root: refresh.entry.current_tip_merkleroot,
            artifact_tip_index: refresh.entry.current_tip_index,
        },
        legacy_observed_manifest_sequence: refresh.manifest_sequence,
        base_descriptor: descriptor_record(&refresh.entry.base),
        applied_delta_descriptors: refresh.entry.deltas.iter().map(descriptor_record).collect(),
        blocked_shields_descriptor: descriptor_record(&refresh.entry.blocked_shields),
        artifact_tip_index: Some(refresh.entry.current_tip_index),
        artifact_tip_root: Some(refresh.entry.current_tip_merkleroot),
        current_tip_index,
        current_tip_root,
        cache_payload: cache.to_bytes()?,
        legacy_last_successful_rpc_sync_at_ms: None,
        updated_at: unix_time_ms(),
    };
    let mut sync_state = lock_poi_artifact_cache_sync();
    let current_generation = sync_state.generation_cell(db)?.load(Ordering::Acquire);
    if refresh.cache_generation != current_generation {
        return Err(PoiArtifactError::StalePublicCacheGeneration {
            expected: current_generation,
            actual: refresh.cache_generation,
        });
    }
    let global_sequence = publisher_manifest_watermark(db, publisher_pubkey)?.ok_or(
        PoiArtifactError::UnobservedManifestSequence {
            candidate: refresh.manifest_sequence,
        },
    )?;
    if refresh.manifest_sequence < global_sequence {
        return Ok(false);
    }
    if refresh.manifest_sequence > global_sequence {
        return Err(PoiArtifactError::UnobservedManifestSequence {
            candidate: refresh.manifest_sequence,
        });
    }
    persist_corpus_record_monotonic(db, record, Some(publisher_pubkey))
}

#[cfg(test)]
pub(crate) fn persist_public_rpc_cache(
    db: &DbStore,
    cache: &PoiCache,
    cache_generation: u64,
    range_start_index: u64,
) -> Result<bool, PoiArtifactError> {
    persist_public_rpc_cache_with_publisher(db, cache, cache_generation, range_start_index, None)
}

fn persist_public_rpc_cache_with_publisher(
    db: &DbStore,
    cache: &PoiCache,
    cache_generation: u64,
    range_start_index: u64,
    publisher_pubkey: Option<FixedBytes<32>>,
) -> Result<bool, PoiArtifactError> {
    let identity = cache.identity();
    let current_tip_index = cache.progress().next_event_index.saturating_sub(1);
    let (tree_number, _) = normalize_tree_position(0, current_tip_index);
    let current_tip_root = *cache
        .clone()
        .current_roots()
        .get(&tree_number)
        .ok_or(PoiArtifactError::MissingCacheRoot { tree_number })?;
    let record = PoiArtifactCacheRecord {
        chain_type: identity.chain_type,
        chain_id: identity.chain_id,
        txid_version: identity.txid_version.clone(),
        list_key: identity.list_key,
        source: PoiCacheRecordSource::PublicRpc,
        validation: PoiCorpusValidationRecord::ListSignedRanges {
            list_key: identity.list_key,
            from_index: range_start_index,
        },
        legacy_observed_manifest_sequence: 0,
        base_descriptor: empty_descriptor_record(),
        applied_delta_descriptors: Vec::new(),
        blocked_shields_descriptor: empty_descriptor_record(),
        artifact_tip_index: None,
        artifact_tip_root: None,
        current_tip_index,
        current_tip_root,
        cache_payload: cache.to_bytes()?,
        legacy_last_successful_rpc_sync_at_ms: None,
        updated_at: unix_time_ms(),
    };
    let mut sync_state = lock_poi_artifact_cache_sync();
    let current_generation = sync_state.generation_cell(db)?.load(Ordering::Acquire);
    if cache_generation != current_generation {
        return Err(PoiArtifactError::StalePublicCacheGeneration {
            expected: current_generation,
            actual: cache_generation,
        });
    }
    persist_corpus_record_monotonic(db, record, publisher_pubkey)
}

fn persist_corpus_record_monotonic(
    db: &DbStore,
    mut candidate: PoiArtifactCacheRecord,
    publisher_pubkey: Option<FixedBytes<32>>,
) -> Result<bool, PoiArtifactError> {
    let candidate_identity = PoiCacheIdentity::new(
        candidate.chain_type,
        candidate.chain_id,
        candidate.txid_version.clone(),
        candidate.list_key,
    );
    let candidate_cache =
        validate_persisted_record(&candidate, &candidate_identity, publisher_pubkey)?;
    let existing = db.inspect_poi_artifact_cache(
        candidate.chain_type,
        candidate.chain_id,
        &candidate.txid_version,
        &candidate.list_key,
    )?;
    let existing = match existing {
        StoredRecord::Missing => None,
        StoredRecord::Corrupt { key } => {
            warn!(%key, "replacing corrupt durable PPOI corpus");
            None
        }
        StoredRecord::Valid(mut existing) => {
            normalize_legacy_artifact_metadata(&mut existing);
            let identity = PoiCacheIdentity::new(
                existing.chain_type,
                existing.chain_id,
                existing.txid_version.clone(),
                existing.list_key,
            );
            match validate_persisted_record(&existing, &identity, publisher_pubkey) {
                Ok(_) => Some(existing),
                Err(error) => {
                    warn!(?error, key = %existing.key(), "replacing semantically corrupt durable PPOI corpus");
                    None
                }
            }
        }
    };
    if let Some(existing) = existing {
        if existing.current_tip_index > candidate.current_tip_index {
            return Ok(false);
        }
        if existing.current_tip_index == candidate.current_tip_index
            && existing.current_tip_root != candidate.current_tip_root
        {
            return Err(PoiArtifactError::CorpusTipRootConflict {
                tip_index: candidate.current_tip_index,
            });
        }
        if existing.current_tip_index == candidate.current_tip_index
            && matches!(candidate.source, PoiCacheRecordSource::IndexedArtifacts)
        {
            return Ok(false);
        }
        if matches!(candidate.source, PoiCacheRecordSource::PublicRpc) {
            candidate.legacy_observed_manifest_sequence =
                existing.legacy_observed_manifest_sequence;
            if candidate.artifact_tip_index.is_none() {
                candidate.artifact_tip_index = existing.artifact_tip_index;
                candidate.artifact_tip_root = existing.artifact_tip_root;
                candidate.base_descriptor = existing.base_descriptor;
                candidate.applied_delta_descriptors = existing.applied_delta_descriptors;
                candidate.blocked_shields_descriptor = existing.blocked_shields_descriptor;
            }
            candidate.validation =
                extend_validation_with_list_ranges(existing.validation, &candidate.validation);
        }
    }
    validate_persisted_corpus(&candidate, &candidate_cache, publisher_pubkey)?;
    db.put_poi_artifact_cache(&candidate)?;
    Ok(true)
}

fn extend_validation_with_list_ranges(
    existing: PoiCorpusValidationRecord,
    candidate: &PoiCorpusValidationRecord,
) -> PoiCorpusValidationRecord {
    let PoiCorpusValidationRecord::ListSignedRanges {
        list_key,
        from_index,
    } = candidate
    else {
        return existing;
    };
    match existing {
        PoiCorpusValidationRecord::PublisherAttested {
            publisher_pubkey,
            manifest_sequence,
            manifest_root,
            artifact_tip_index,
        } => PoiCorpusValidationRecord::PublisherAndListSigned {
            publisher_pubkey,
            manifest_sequence,
            manifest_root,
            artifact_tip_index,
            list_key: *list_key,
            list_signed_from_index: *from_index,
        },
        PoiCorpusValidationRecord::PublisherAndListSigned {
            publisher_pubkey,
            manifest_sequence,
            manifest_root,
            artifact_tip_index,
            list_key,
            list_signed_from_index,
        } => PoiCorpusValidationRecord::PublisherAndListSigned {
            publisher_pubkey,
            manifest_sequence,
            manifest_root,
            artifact_tip_index,
            list_key,
            list_signed_from_index: list_signed_from_index.min(*from_index),
        },
        PoiCorpusValidationRecord::ListSignedRanges {
            list_key,
            from_index: existing_from_index,
        } => PoiCorpusValidationRecord::ListSignedRanges {
            list_key,
            from_index: existing_from_index.min(*from_index),
        },
        PoiCorpusValidationRecord::Legacy => PoiCorpusValidationRecord::Legacy,
    }
}

fn unix_time_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |duration| {
            u64::try_from(duration.as_millis()).unwrap_or(u64::MAX)
        })
}

const fn empty_descriptor_record() -> PoiArtifactDescriptorRecord {
    PoiArtifactDescriptorRecord {
        cid: String::new(),
        sha256: String::new(),
        byte_size: 0,
    }
}

const fn validate_manifest_sequence(
    manifest: &Manifest,
    last_accepted_sequence: Option<u64>,
) -> Result<(), PoiArtifactError> {
    if let Some(previous) = last_accepted_sequence
        && manifest.sequence < previous
    {
        return Err(PoiArtifactError::ManifestSequenceRollback {
            previous,
            received: manifest.sequence,
        });
    }
    Ok(())
}

fn validate_manifest_freshness(
    manifest: &Manifest,
    last_accepted_sequence: Option<u64>,
    max_age: Option<Duration>,
    now: SystemTime,
) -> Result<(), PoiArtifactError> {
    if last_accepted_sequence.is_some() {
        return Ok(());
    }
    let Some(max_age) = max_age else {
        return Ok(());
    };
    let issued_at = UNIX_EPOCH + Duration::from_millis(manifest.issued_at_ms);
    let age = now
        .duration_since(issued_at)
        .map_err(|_| PoiArtifactError::ManifestIssuedInFuture)?;
    if age > max_age {
        return Err(PoiArtifactError::ManifestStale { age, max: max_age });
    }
    Ok(())
}

fn manifest_entry_for_identity<'a>(
    manifest: &'a Manifest,
    identity: &PoiCacheIdentity,
) -> Result<&'a ManifestEntry, PoiArtifactError> {
    for entry in &manifest.entries {
        if entry.chain_id == identity.chain_id && entry.list_key == identity.list_key {
            return Ok(entry);
        }
    }
    Err(PoiArtifactError::MissingManifestEntry {
        chain_id: identity.chain_id,
        list_key: hex::encode_prefixed(identity.list_key.as_slice()),
    })
}

fn validate_snapshot(
    snapshot: &Snapshot,
    identity: &PoiCacheIdentity,
    entry: &ManifestEntry,
    expected_kind: SnapshotKind,
    expected_start: u64,
) -> Result<u64, PoiArtifactError> {
    if snapshot.header.kind != expected_kind {
        return Err(PoiArtifactError::SnapshotKindMismatch {
            expected: expected_kind,
            actual: snapshot.header.kind,
        });
    }
    if snapshot.header.start_index != expected_start {
        return Err(PoiArtifactError::SnapshotStartMismatch {
            expected: expected_start,
            actual: snapshot.header.start_index,
        });
    }
    require_scope_bytes("list_key", &snapshot.header.list_key, &identity.list_key.0)?;
    require_scope_value("chain_id", snapshot.header.chain_id, identity.chain_id)?;
    require_scope_value(
        "chain_type",
        snapshot.header.chain_type,
        identity.chain_type,
    )?;
    require_scope_bytes(
        ENTRY_LIST_KEY_FIELD,
        &entry.list_key.0,
        &identity.list_key.0,
    )?;
    require_scope_value("entry.chain_id", entry.chain_id, identity.chain_id)?;

    snapshot
        .header
        .end_index
        .checked_add(1)
        .ok_or(PoiArtifactError::RangeOverflow)
}

fn apply_snapshot_suffix_events(
    cache: &mut PoiCache,
    snapshot: &Snapshot,
    expected_index: &mut u64,
) -> Result<usize, PoiArtifactError> {
    let mut suffix_events = Vec::new();
    for event in &snapshot.events {
        if event.event_index < *expected_index {
            continue;
        }
        if event.event_index != *expected_index {
            return Err(PoiArtifactError::ArtifactSuffixEventIndexMismatch {
                expected: *expected_index,
                actual: event.event_index,
            });
        }
        suffix_events.push(event.clone());
        *expected_index = expected_index
            .checked_add(1)
            .ok_or(PoiArtifactError::RangeOverflow)?;
    }
    if !suffix_events.is_empty() {
        cache.apply_verified_artifact_events(&suffix_events)?;
    }
    Ok(suffix_events.len())
}

fn validate_blocked_shields_artifact(
    artifact: &BlockedShieldsArtifact,
    identity: &PoiCacheIdentity,
) -> Result<Vec<BlockedShield>, PoiArtifactError> {
    require_scope_value(
        "blocked_shields.format_version",
        artifact.format_version,
        poi::artifacts::snapshot::format::FORMAT_VERSION,
    )?;
    require_scope_bytes(
        BLOCKED_SHIELDS_LIST_KEY_FIELD,
        &artifact.list_key.0,
        &identity.list_key.0,
    )?;
    require_scope_value(
        "blocked_shields.chain_id",
        artifact.chain_id,
        identity.chain_id,
    )?;
    require_scope_value(
        "blocked_shields.chain_type",
        artifact.chain_type,
        identity.chain_type,
    )?;
    Ok(artifact
        .blocked_shields
        .iter()
        .cloned()
        .map(poi::artifacts::BlockedShieldArtifactRecord::into_signed_blocked_shield)
        .collect())
}

fn verify_manifest_root(
    cache: &mut PoiCache,
    entry: &ManifestEntry,
) -> Result<(), PoiArtifactError> {
    let expected_root = entry.current_tip_merkleroot;
    let (tree_number, _) = normalize_tree_position(0, entry.current_tip_index);
    let roots = cache.current_roots();
    let actual = roots
        .get(&tree_number)
        .copied()
        .ok_or(PoiArtifactError::MissingReplayRoot { tree_number })?;
    if actual != expected_root {
        return Err(PoiArtifactError::ReplayRootMismatch {
            expected: hex::encode_prefixed(expected_root.as_slice()),
            actual: hex::encode_prefixed(actual.as_slice()),
        });
    }
    Ok(())
}

fn require_scope_bytes(
    field: &'static str,
    actual: &[u8; 32],
    expected: &[u8; 32],
) -> Result<(), PoiArtifactError> {
    if actual == expected {
        return Ok(());
    }
    Err(PoiArtifactError::SnapshotScopeMismatch {
        field,
        expected: hex::encode_prefixed(expected),
        actual: hex::encode_prefixed(actual),
    })
}

fn require_scope_value<T>(
    field: &'static str,
    actual: T,
    expected: T,
) -> Result<(), PoiArtifactError>
where
    T: Copy + PartialEq + ToString,
{
    if actual == expected {
        return Ok(());
    }
    Err(PoiArtifactError::SnapshotScopeMismatch {
        field,
        expected: expected.to_string(),
        actual: actual.to_string(),
    })
}

#[cfg(test)]
fn decode_fixed_hex<const N: usize>(
    field: &'static str,
    value: &str,
) -> Result<[u8; N], PoiArtifactError> {
    let bytes = hex::decode(value.strip_prefix("0x").unwrap_or(value)).map_err(|_| {
        PoiArtifactError::InvalidHex {
            field,
            value: value.to_string(),
        }
    })?;
    bytes
        .try_into()
        .map_err(|bytes: Vec<u8>| PoiArtifactError::InvalidByteLen {
            field,
            expected: N,
            actual: bytes.len(),
        })
}

fn descriptor_record(descriptor: &ArtifactDescriptor) -> PoiArtifactDescriptorRecord {
    PoiArtifactDescriptorRecord {
        cid: descriptor.cid.clone(),
        sha256: hex::encode_prefixed(descriptor.sha256.as_slice()),
        byte_size: descriptor.byte_size,
    }
}

fn descriptor_matches_record(
    descriptor: &ArtifactDescriptor,
    record: &PoiArtifactDescriptorRecord,
) -> bool {
    descriptor.cid == record.cid
        && hex::encode_prefixed(descriptor.sha256.as_slice()) == record.sha256
        && descriptor.byte_size == record.byte_size
}

fn common_delta_prefix_len(
    records: &[PoiArtifactDescriptorRecord],
    descriptors: &[ArtifactDescriptor],
) -> usize {
    records
        .iter()
        .zip(descriptors.iter())
        .take_while(|(record, descriptor)| descriptor_matches_record(descriptor, record))
        .count()
}

pub(crate) async fn clear_poi_artifact_cache_for_reset(
    db: &DbStore,
) -> Result<PoiArtifactCacheReset, local_db::DbError> {
    let authority = poi_corpus_authority(db)?;
    let _reset_access = authority.reset_access().await;
    let mut sync_state = lock_poi_artifact_cache_sync();
    let (removed, generation) = db.clear_poi_artifact_cache_with_generation()?;
    sync_state.publish_generation(db, generation);
    Ok(PoiArtifactCacheReset {
        removed,
        generation,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::io::{Read, Write};
    use std::net::TcpListener;
    use std::path::PathBuf;
    use std::sync::mpsc::{self, Receiver};

    use cid::Cid;
    use ed25519_dalek::{Signer, SigningKey};
    use local_db::DbConfig;
    use multihash_codetable::{Code, MultihashDigest};
    use poi::artifacts::{
        SnapshotEvent, SnapshotHeader, SnapshotHeaderInput, SnapshotWriter, snapshot::format,
    };
    use poi::poi::{PoiEventType, PoiStatus, PoiSyncedListEvent, SignedPoiEvent};

    #[test]
    fn manifest_sequence_rollback_is_rejected() {
        let manifest = Manifest::new(2, 1_700_000_000_000, 4, FixedBytes::ZERO, vec![]);

        assert!(matches!(
            validate_manifest_sequence(&manifest, Some(5)),
            Err(PoiArtifactError::ManifestSequenceRollback {
                previous: 5,
                received: 4,
            })
        ));
    }

    #[test]
    fn public_rpc_cache_persistence_does_not_own_publisher_watermark() {
        let root_dir = temp_db_root("rpc-cache-sequence-watermark");
        fs::create_dir_all(&root_dir).expect("create temp DB root");
        let db = DbStore::open(DbConfig {
            root_dir: root_dir.clone(),
        })
        .expect("open temp DB");
        let identity = test_identity();
        let mut cache = PoiCache::new(identity.clone());
        cache
            .apply_verified_artifact_events(&[SnapshotEvent {
                event_index: 0,
                blinded_commitment: [0x41_u8; 32],
                signature: [0_u8; 64],
                event_type: PoiEventType::Transact,
            }])
            .expect("apply test event");
        cache.accept_current_roots();
        let generation = poi_artifact_cache_generation_cell(&db)
            .expect("cache generation")
            .load(Ordering::Acquire);
        let publisher_pubkey = FixedBytes::from([0x40; 32]);
        db.advance_poi_publisher_manifest_watermark(publisher_pubkey, 7)
            .expect("seed publisher watermark");

        PoiCorpusStore::new(&db, generation, publisher_pubkey)
            .commit_public_rpc(&cache, 0)
            .expect("persist public RPC cache");
        let persisted = load_persisted_cache_for_publisher(&db, &identity, publisher_pubkey)
            .expect("load public RPC cache")
            .expect("public RPC cache record");

        assert_eq!(persisted.record.source, PoiCacheRecordSource::PublicRpc);
        assert_eq!(persisted.record.legacy_observed_manifest_sequence, 0);
        assert_eq!(
            publisher_manifest_watermark(&db, publisher_pubkey).expect("load publisher watermark"),
            Some(7)
        );
        drop(db);
        fs::remove_dir_all(root_dir).expect("remove temp DB root");
    }

    #[test]
    fn rpc_only_corpus_cannot_recover_publisher_watermark() {
        let root_dir = temp_db_root("rpc-cache-no-publisher-watermark");
        fs::create_dir_all(&root_dir).expect("create temp DB root");
        let db = DbStore::open(DbConfig {
            root_dir: root_dir.clone(),
        })
        .expect("open temp DB");
        let identity = test_identity();
        let cache = test_cache(&identity, &[0x42]);
        let generation = poi_artifact_cache_generation_cell(&db)
            .expect("cache generation")
            .load(Ordering::Acquire);
        persist_public_rpc_cache(&db, &cache, generation, 0).expect("persist RPC-only corpus");
        let mut record = db
            .get_poi_artifact_cache(
                identity.chain_type,
                identity.chain_id,
                &identity.txid_version,
                &identity.list_key,
            )
            .expect("load RPC-only corpus")
            .expect("RPC-only corpus");
        record.legacy_observed_manifest_sequence = 99;
        db.put_poi_artifact_cache(&record)
            .expect("persist legacy observational sequence");

        assert_eq!(
            publisher_manifest_watermark(&db, FixedBytes::from([0x41; 32]))
                .expect("derive publisher watermark"),
            None
        );

        drop(db);
        fs::remove_dir_all(root_dir).expect("remove temp DB root");
    }

    #[test]
    fn malformed_persisted_tip_is_rejected_and_does_not_block_valid_replacement() {
        let root_dir = temp_db_root("malformed-persisted-tip");
        fs::create_dir_all(&root_dir).expect("create temp DB root");
        let db = DbStore::open(DbConfig {
            root_dir: root_dir.clone(),
        })
        .expect("open temp DB");
        let identity = test_identity();
        let cache = test_cache(&identity, &[0x31]);
        let root = test_cache_root(&cache);
        let entry = test_entry(&identity, 0, root.0);
        let mut malformed = persisted_cache(&identity, cache.clone(), 0, root, &entry).record;
        malformed.current_tip_index = 50;
        db.put_poi_artifact_cache(&malformed)
            .expect("persist malformed corpus");

        assert!(matches!(
            load_persisted_cache(&db, &identity),
            Err(PoiArtifactError::PersistedTipMismatch {
                metadata: 50,
                payload: 0,
            })
        ));

        let generation = poi_artifact_cache_generation_cell(&db)
            .expect("cache generation")
            .load(Ordering::Acquire);
        assert!(
            persist_public_rpc_cache(&db, &cache, generation, 0).expect("replace malformed corpus")
        );
        let recovered = load_persisted_cache(&db, &identity)
            .expect("load replacement corpus")
            .expect("replacement corpus");
        assert_eq!(recovered.record.current_tip_index, 0);
        assert_eq!(recovered.record.current_tip_root, root);

        drop(db);
        fs::remove_dir_all(root_dir).expect("remove temp DB root");
    }

    #[test]
    fn persisted_root_and_validation_provenance_must_match_payload() {
        let root_dir = temp_db_root("malformed-persisted-root");
        fs::create_dir_all(&root_dir).expect("create temp DB root");
        let db = DbStore::open(DbConfig {
            root_dir: root_dir.clone(),
        })
        .expect("open temp DB");
        let identity = test_identity();
        let cache = test_cache(&identity, &[0x32]);
        let root = test_cache_root(&cache);
        let entry = test_entry(&identity, 0, root.0);
        let mut malformed = persisted_cache(&identity, cache.clone(), 0, root, &entry).record;
        malformed.current_tip_root = FixedBytes::from([0xff; 32]);
        db.put_poi_artifact_cache(&malformed)
            .expect("persist mismatched root");
        assert!(matches!(
            load_persisted_cache(&db, &identity),
            Err(PoiArtifactError::PersistedRootMismatch { tip_index: 0 })
        ));

        let generation = poi_artifact_cache_generation_cell(&db)
            .expect("cache generation")
            .load(Ordering::Acquire);
        persist_public_rpc_cache(&db, &cache, generation, 0)
            .expect("replace root-mismatched corpus");
        let mut malformed = db
            .get_poi_artifact_cache(
                identity.chain_type,
                identity.chain_id,
                &identity.txid_version,
                &identity.list_key,
            )
            .expect("load public corpus")
            .expect("public corpus");
        malformed.validation = PoiCorpusValidationRecord::ListSignedRanges {
            list_key: FixedBytes::from([0xee; 32]),
            from_index: 0,
        };
        db.put_poi_artifact_cache(&malformed)
            .expect("persist mismatched provenance");
        assert!(matches!(
            load_persisted_cache(&db, &identity),
            Err(PoiArtifactError::PersistedValidationProvenance { .. })
        ));

        drop(db);
        fs::remove_dir_all(root_dir).expect("remove temp DB root");
    }

    #[test]
    fn publisher_attested_root_must_match_the_payload_at_its_artifact_tip() {
        let root_dir = temp_db_root("publisher-root-payload-binding");
        fs::create_dir_all(&root_dir).expect("create temp DB root");
        let db = DbStore::open(DbConfig {
            root_dir: root_dir.clone(),
        })
        .expect("open temp DB");
        let identity = test_identity();
        let cache = test_cache(&identity, &[0x39]);
        let root = test_cache_root(&cache);
        let publisher_pubkey = FixedBytes::from([0x43; 32]);
        let generation = poi_artifact_cache_generation_cell(&db)
            .expect("cache generation")
            .load(Ordering::Acquire);
        let refresh = PoiArtifactRefresh {
            manifest_sequence: 4,
            cache: cache.clone(),
            entry: test_entry(&identity, 0, root.0),
            cache_generation: generation,
            corpus_advanced: true,
        };
        advance_publisher_manifest_watermark(&db, publisher_pubkey, 4)
            .expect("observe publisher manifest");
        persist_prepared_corpus(&db, &cache, &refresh, publisher_pubkey)
            .expect("persist valid publisher corpus");

        let mut malformed = db
            .get_poi_artifact_cache(
                identity.chain_type,
                identity.chain_id,
                &identity.txid_version,
                &identity.list_key,
            )
            .expect("load publisher corpus")
            .expect("publisher corpus");
        let unrelated_root = FixedBytes::from([0xfe; 32]);
        malformed.artifact_tip_root = Some(unrelated_root);
        malformed.validation = PoiCorpusValidationRecord::PublisherAttested {
            publisher_pubkey,
            manifest_sequence: 4,
            manifest_root: unrelated_root,
            artifact_tip_index: 0,
        };
        db.put_poi_artifact_cache(&malformed)
            .expect("persist mismatched publisher root");

        assert!(matches!(
            load_persisted_cache_for_publisher(&db, &identity, publisher_pubkey),
            Err(PoiArtifactError::PersistedArtifactRootMismatch { tip_index: 0 })
        ));

        drop(db);
        fs::remove_dir_all(root_dir).expect("remove temp DB root");
    }

    #[test]
    fn persisted_record_identity_must_match_payload_identity() {
        let identity = test_identity();
        let cache = test_cache(&identity, &[0x3a]);
        let root = test_cache_root(&cache);
        let entry = test_entry(&identity, 0, root.0);
        let mut record = persisted_cache(&identity, cache, 0, root, &entry).record;
        record.chain_id = 137;

        assert!(matches!(
            validate_persisted_record(&record, &identity, None),
            Err(PoiArtifactError::PersistedIdentityMismatch)
        ));
    }

    #[test]
    fn persisted_artifact_and_watermark_are_scoped_to_configured_publisher() {
        let root_dir = temp_db_root("publisher-scoped-persistence");
        fs::create_dir_all(&root_dir).expect("create temp DB root");
        let db = DbStore::open(DbConfig {
            root_dir: root_dir.clone(),
        })
        .expect("open temp DB");
        let identity = test_identity();
        let cache = test_cache(&identity, &[0x33]);
        let root = test_cache_root(&cache);
        let generation = poi_artifact_cache_generation_cell(&db)
            .expect("cache generation")
            .load(Ordering::Acquire);
        let old_publisher = FixedBytes::from([0x44; 32]);
        let new_publisher = FixedBytes::from([0x45; 32]);
        let refresh = PoiArtifactRefresh {
            manifest_sequence: 9,
            cache: cache.clone(),
            entry: test_entry(&identity, 0, root.0),
            cache_generation: generation,
            corpus_advanced: true,
        };
        advance_publisher_manifest_watermark(&db, old_publisher, 9)
            .expect("observe old-publisher manifest");
        persist_prepared_corpus(&db, &cache, &refresh, old_publisher)
            .expect("persist old-publisher corpus");

        assert!(matches!(
            load_persisted_cache_for_publisher(&db, &identity, new_publisher),
            Err(PoiArtifactError::PersistedValidationProvenance { .. })
        ));
        assert_eq!(
            publisher_manifest_watermark(&db, new_publisher)
                .expect("derive new-publisher watermark"),
            None
        );
        assert_eq!(
            publisher_manifest_watermark(&db, old_publisher).expect("load old-publisher watermark"),
            Some(9)
        );

        drop(db);
        fs::remove_dir_all(root_dir).expect("remove temp DB root");
    }

    #[tokio::test]
    async fn stale_generation_rpc_health_cannot_overwrite_current_health() {
        let root_dir = temp_db_root("generation-fenced-rpc-health");
        fs::create_dir_all(&root_dir).expect("create temp DB root");
        let db = DbStore::open(DbConfig {
            root_dir: root_dir.clone(),
        })
        .expect("open temp DB");
        let identity = test_identity();
        let reset = clear_poi_artifact_cache_for_reset(&db)
            .await
            .expect("advance generation");
        db.put_poi_corpus_rpc_health(&PoiCorpusRpcHealthRecord {
            chain_type: identity.chain_type,
            chain_id: identity.chain_id,
            txid_version: identity.txid_version.clone(),
            list_key: identity.list_key,
            cache_generation: reset.generation,
            last_successful_rpc_sync_at_ms: Some(777),
            updated_at: 0,
        })
        .expect("persist current-generation health");

        assert!(matches!(
            record_poi_rpc_success(&db, &identity, 0),
            Err(PoiArtifactError::StalePublicCacheGeneration {
                expected: 1,
                actual: 0,
            })
        ));
        let retained = db
            .get_poi_corpus_rpc_health(
                identity.chain_type,
                identity.chain_id,
                &identity.txid_version,
                &identity.list_key,
            )
            .expect("load retained health")
            .expect("retained health");
        assert_eq!(retained.cache_generation, reset.generation);
        assert_eq!(retained.last_successful_rpc_sync_at_ms, Some(777));

        drop(db);
        fs::remove_dir_all(root_dir).expect("remove temp DB root");
    }

    #[test]
    fn corrupt_rpc_health_does_not_invalidate_or_block_valid_corpus() {
        let root_dir = temp_db_root("corrupt-advisory-rpc-health");
        fs::create_dir_all(&root_dir).expect("create temp DB root");
        let db = DbStore::open(DbConfig {
            root_dir: root_dir.clone(),
        })
        .expect("open temp DB");
        let identity = test_identity();
        let cache = test_cache(&identity, &[0x47]);
        let root = test_cache_root(&cache);
        let publisher_pubkey = FixedBytes::from([0x48; 32]);
        let generation = poi_artifact_cache_generation_cell(&db)
            .expect("cache generation")
            .load(Ordering::Acquire);
        let refresh = PoiArtifactRefresh {
            manifest_sequence: 1,
            cache: cache.clone(),
            entry: test_entry(&identity, 0, root.0),
            cache_generation: generation,
            corpus_advanced: true,
        };
        persist_refresh_with_publisher(&db, &identity, &refresh, publisher_pubkey)
            .expect("persist valid publisher corpus");
        let health_key = PoiCorpusRpcHealthRecord::key_for(
            identity.chain_type,
            identity.chain_id,
            &identity.txid_version,
            &identity.list_key,
        );
        db.put_app_settings_record(&health_key, b"not-msgpack")
            .expect("corrupt RPC health sidecar");

        let loaded = load_persisted_cache_for_publisher(&db, &identity, publisher_pubkey)
            .expect("load valid corpus despite corrupt health")
            .expect("persisted corpus");
        assert_eq!(loaded.record.current_tip_index, 0);
        assert_eq!(
            load_poi_rpc_health(&db, &identity, generation, None)
                .expect("ignore corrupt advisory health"),
            None
        );

        let next_refresh = PoiArtifactRefresh {
            manifest_sequence: 2,
            cache: cache.clone(),
            entry: test_entry(&identity, 0, root.0),
            cache_generation: generation,
            corpus_advanced: true,
        };
        advance_publisher_manifest_watermark(&db, publisher_pubkey, 2)
            .expect("observe next publisher manifest");
        let committed = PoiCorpusStore::new(&db, generation, publisher_pubkey)
            .commit_artifact(&cache, &next_refresh)
            .expect("commit artifact despite corrupt health");
        assert_eq!(committed.record.current_tip_index, 0);

        drop(db);
        fs::remove_dir_all(root_dir).expect("remove temp DB root");
    }

    #[test]
    fn legacy_rpc_health_migrates_once_and_sidecar_remains_authoritative() {
        let root_dir = temp_db_root("legacy-rpc-health-migration");
        fs::create_dir_all(&root_dir).expect("create temp DB root");
        let db = DbStore::open(DbConfig {
            root_dir: root_dir.clone(),
        })
        .expect("open temp DB");
        let identity = test_identity();
        let cache = test_cache(&identity, &[0x49]);
        let root = test_cache_root(&cache);
        let publisher_pubkey = FixedBytes::from([0x4a; 32]);
        let generation = poi_artifact_cache_generation_cell(&db)
            .expect("cache generation")
            .load(Ordering::Acquire);
        let refresh = PoiArtifactRefresh {
            manifest_sequence: 1,
            cache,
            entry: test_entry(&identity, 0, root.0),
            cache_generation: generation,
            corpus_advanced: true,
        };
        persist_refresh_with_publisher(&db, &identity, &refresh, publisher_pubkey)
            .expect("persist valid publisher corpus");
        let mut legacy = db
            .get_poi_artifact_cache(
                identity.chain_type,
                identity.chain_id,
                &identity.txid_version,
                &identity.list_key,
            )
            .expect("load corpus")
            .expect("corpus");
        legacy.legacy_last_successful_rpc_sync_at_ms = Some(123);
        db.put_poi_artifact_cache(&legacy)
            .expect("persist legacy RPC health");

        let migrated = load_persisted_cache_for_publisher(&db, &identity, publisher_pubkey)
            .expect("load corpus with legacy health")
            .expect("persisted corpus");
        assert_eq!(
            load_poi_rpc_health(
                &db,
                &identity,
                generation,
                migrated.record.legacy_last_successful_rpc_sync_at_ms,
            )
            .expect("migrate legacy health"),
            Some(123)
        );

        legacy.legacy_last_successful_rpc_sync_at_ms = Some(999);
        db.put_poi_artifact_cache(&legacy)
            .expect("change legacy RPC health after migration");
        let retained = load_persisted_cache_for_publisher(&db, &identity, publisher_pubkey)
            .expect("load corpus after legacy health changed")
            .expect("persisted corpus");
        assert_eq!(
            load_poi_rpc_health(
                &db,
                &identity,
                generation,
                retained.record.legacy_last_successful_rpc_sync_at_ms,
            )
            .expect("load sidecar-owned health"),
            Some(123)
        );

        drop(db);
        fs::remove_dir_all(root_dir).expect("remove temp DB root");
    }

    #[test]
    fn metadata_only_manifest_does_not_claim_unapplied_artifacts_or_regress_sequence() {
        let root_dir = temp_db_root("artifact-metadata-watermark");
        fs::create_dir_all(&root_dir).expect("create temp DB root");
        let db = DbStore::open(DbConfig {
            root_dir: root_dir.clone(),
        })
        .expect("open temp DB");
        let identity = test_identity();
        let cache = test_cache(&identity, &[0x41]);
        let root = test_cache_root(&cache);
        let generation = poi_artifact_cache_generation_cell(&db)
            .expect("cache generation")
            .load(Ordering::Acquire);
        let initial_entry = test_entry(&identity, 0, root.0);
        let initial_refresh = PoiArtifactRefresh {
            manifest_sequence: 7,
            cache: cache.clone(),
            entry: initial_entry,
            cache_generation: generation,
            corpus_advanced: true,
        };
        advance_publisher_manifest_watermark(&db, FixedBytes::from([0x55; 32]), 7)
            .expect("observe initial manifest");
        assert!(
            persist_prepared_corpus(&db, &cache, &initial_refresh, FixedBytes::from([0x55; 32]),)
                .expect("persist initial artifact corpus")
        );

        advance_publisher_manifest_watermark(&db, FixedBytes::from([0x55; 32]), 8)
            .expect("observe newer manifest");
        let after_metadata = load_persisted_cache(&db, &identity)
            .expect("load corpus after metadata update")
            .expect("persisted corpus");
        assert_eq!(after_metadata.record.legacy_observed_manifest_sequence, 7);
        assert_eq!(
            publisher_manifest_watermark(&db, FixedBytes::from([0x55; 32]))
                .expect("load observed publisher watermark"),
            Some(8)
        );
        assert_eq!(after_metadata.record.base_descriptor.cid, "base");
        assert_eq!(
            after_metadata.record.applied_delta_descriptors[0].cid,
            "delta"
        );
        assert_eq!(
            after_metadata.record.blocked_shields_descriptor.cid,
            "blocked"
        );

        let older_cache = test_cache(&identity, &[0x41, 0x42]);
        let older_root = test_cache_root(&older_cache);
        let older_refresh = PoiArtifactRefresh {
            manifest_sequence: 7,
            cache: older_cache.clone(),
            entry: test_entry(&identity, 1, older_root.0),
            cache_generation: generation,
            corpus_advanced: true,
        };
        assert!(
            !persist_prepared_corpus(
                &db,
                &older_cache,
                &older_refresh,
                FixedBytes::from([0x55; 32]),
            )
            .expect("reject older artifact sequence")
        );
        let retained = load_persisted_cache(&db, &identity)
            .expect("load retained corpus")
            .expect("persisted corpus");
        assert_eq!(retained.record.legacy_observed_manifest_sequence, 7);
        assert_eq!(retained.record.current_tip_index, 0);
        assert_eq!(retained.record.base_descriptor.cid, "base");

        drop(db);
        fs::remove_dir_all(root_dir).expect("remove temp DB root");
    }

    #[tokio::test]
    async fn equal_tip_artifact_cannot_replace_rpc_blocked_shield_state() {
        let root_dir = temp_db_root("equal-tip-artifact-no-replacement");
        fs::create_dir_all(&root_dir).expect("create temp DB root");
        let db = DbStore::open(DbConfig {
            root_dir: root_dir.clone(),
        })
        .expect("open temp DB");
        let signing_key = SigningKey::from_bytes(&[0x5a; 32]);
        let identity = signed_identity(&signing_key);
        let cache = test_cache(&identity, &[0x5b]);
        let root = test_cache_root(&cache);
        let generation = poi_artifact_cache_generation_cell(&db)
            .expect("cache generation")
            .load(Ordering::Acquire);
        persist_public_rpc_cache(&db, &cache, generation, 0).expect("persist RPC-derived corpus");
        let before = db
            .get_poi_artifact_cache(
                identity.chain_type,
                identity.chain_id,
                &identity.txid_version,
                &identity.list_key,
            )
            .expect("load RPC corpus")
            .expect("RPC corpus");

        let mut entry = test_entry(&identity, 0, root.0);
        entry.blocked_shields = descriptor("changed-blocked-shields");
        let mut manifest = Manifest::new(2, 9_500, 2, FixedBytes::ZERO, vec![entry]);
        manifest
            .sign_manifest(&signing_key)
            .expect("sign equal-tip manifest");
        let server =
            spawn_manifest_server(200, serde_json::to_vec(&manifest).expect("manifest JSON"));
        let ingestor = manifest_ingestor(
            &signing_key,
            PoiArtifactManifestSource::Url(server.url.clone()),
            Vec::new(),
            Some(Duration::from_secs(1)),
        );

        let refresh = ingestor
            .prepare_cache_with_optional_preloaded(
                &db,
                identity.clone(),
                None,
                UNIX_EPOCH + Duration::from_secs(10),
            )
            .await
            .expect("prepare equal-tip artifact observation");
        assert!(!refresh.corpus_advanced);
        let after = db
            .get_poi_artifact_cache(
                identity.chain_type,
                identity.chain_id,
                &identity.txid_version,
                &identity.list_key,
            )
            .expect("load retained RPC corpus")
            .expect("retained RPC corpus");
        assert_eq!(after, before);

        drop(db);
        fs::remove_dir_all(root_dir).expect("remove temp DB root");
    }

    #[test]
    fn delayed_artifact_cannot_overwrite_equal_tip_rpc_blocked_shield_state() {
        let root_dir = temp_db_root("delayed-artifact-equal-tip-race");
        fs::create_dir_all(&root_dir).expect("create temp DB root");
        let db = DbStore::open(DbConfig {
            root_dir: root_dir.clone(),
        })
        .expect("open temp DB");
        let identity = test_identity();
        let artifact_cache = test_cache(&identity, &[0x5c, 0x5d]);
        let artifact_root = test_cache_root(&artifact_cache);
        let generation = poi_artifact_cache_generation_cell(&db)
            .expect("cache generation")
            .load(Ordering::Acquire);
        let publisher_pubkey = FixedBytes::from([0x5e; 32]);
        let refresh = PoiArtifactRefresh {
            manifest_sequence: 3,
            cache: artifact_cache.clone(),
            entry: test_entry(&identity, 1, artifact_root.0),
            cache_generation: generation,
            corpus_advanced: true,
        };
        advance_publisher_manifest_watermark(&db, publisher_pubkey, 3)
            .expect("observe delayed artifact manifest");

        let blocked_commitment = FixedBytes::from([0x5f; 32]);
        let mut rpc_cache = artifact_cache;
        rpc_cache
            .apply_blocked_shields(&[blocked_shield(blocked_commitment)])
            .expect("apply newer RPC blocked-shield state");
        assert!(
            persist_public_rpc_cache_with_publisher(
                &db,
                &rpc_cache,
                generation,
                0,
                Some(publisher_pubkey),
            )
            .expect("persist equal-tip RPC corpus")
        );

        assert!(
            !persist_prepared_corpus(&db, &refresh.cache, &refresh, publisher_pubkey)
                .expect("reject delayed equal-tip artifact")
        );
        let retained = load_persisted_cache_for_publisher(&db, &identity, publisher_pubkey)
            .expect("load retained RPC corpus")
            .expect("retained RPC corpus");
        assert_eq!(
            retained.cache.status(&blocked_commitment),
            poi::poi::PoiStatus::ShieldBlocked
        );

        drop(db);
        fs::remove_dir_all(root_dir).expect("remove temp DB root");
    }

    #[test]
    fn public_range_extension_preserves_artifact_and_list_validation_provenance() {
        let root_dir = temp_db_root("mixed-validation-provenance");
        fs::create_dir_all(&root_dir).expect("create temp DB root");
        let db = DbStore::open(DbConfig {
            root_dir: root_dir.clone(),
        })
        .expect("open temp DB");
        let identity = test_identity();
        let artifact_cache = test_cache(&identity, &[0x51]);
        let artifact_root = test_cache_root(&artifact_cache);
        let generation = poi_artifact_cache_generation_cell(&db)
            .expect("cache generation")
            .load(Ordering::Acquire);
        let publisher_pubkey = FixedBytes::from([0x66; 32]);
        let refresh = PoiArtifactRefresh {
            manifest_sequence: 7,
            cache: artifact_cache.clone(),
            entry: test_entry(&identity, 0, artifact_root.0),
            cache_generation: generation,
            corpus_advanced: true,
        };
        advance_publisher_manifest_watermark(&db, publisher_pubkey, 7)
            .expect("observe artifact manifest");
        assert!(
            persist_prepared_corpus(&db, &artifact_cache, &refresh, publisher_pubkey,)
                .expect("persist artifact corpus")
        );

        let rpc_cache = test_cache(&identity, &[0x51, 0x52]);
        assert!(
            persist_public_rpc_cache(&db, &rpc_cache, generation, 1)
                .expect("persist public range extension")
        );
        let persisted = load_persisted_cache(&db, &identity)
            .expect("load mixed corpus")
            .expect("persisted mixed corpus");
        assert!(matches!(
            persisted.record.validation.clone(),
            PoiCorpusValidationRecord::PublisherAndListSigned {
                publisher_pubkey: actual_publisher,
                manifest_sequence: 7,
                manifest_root,
                artifact_tip_index: 0,
                list_key,
                list_signed_from_index: 1,
            } if actual_publisher == publisher_pubkey
                && manifest_root == artifact_root
                && list_key == identity.list_key
        ));

        let mut malformed = persisted.record;
        let unrelated_root = FixedBytes::from([0xef; 32]);
        malformed.artifact_tip_root = Some(unrelated_root);
        if let PoiCorpusValidationRecord::PublisherAndListSigned { manifest_root, .. } =
            &mut malformed.validation
        {
            *manifest_root = unrelated_root;
        }
        db.put_poi_artifact_cache(&malformed)
            .expect("persist mismatched mixed artifact root");
        assert!(matches!(
            load_persisted_cache_for_publisher(&db, &identity, publisher_pubkey),
            Err(PoiArtifactError::PersistedArtifactRootMismatch { tip_index: 0 })
        ));

        drop(db);
        fs::remove_dir_all(root_dir).expect("remove temp DB root");
    }

    #[test]
    fn artifact_manifest_sequence_watermark_is_enforced_across_lists() {
        let root_dir = temp_db_root("global-artifact-sequence-watermark");
        fs::create_dir_all(&root_dir).expect("create temp DB root");
        let db = DbStore::open(DbConfig {
            root_dir: root_dir.clone(),
        })
        .expect("open temp DB");
        let generation = poi_artifact_cache_generation_cell(&db)
            .expect("cache generation")
            .load(Ordering::Acquire);
        let first_identity = test_identity();
        let first_cache = test_cache(&first_identity, &[0x61]);
        let first_root = test_cache_root(&first_cache);
        let first_refresh = PoiArtifactRefresh {
            manifest_sequence: 10,
            cache: first_cache.clone(),
            entry: test_entry(&first_identity, 0, first_root.0),
            cache_generation: generation,
            corpus_advanced: true,
        };
        advance_publisher_manifest_watermark(&db, FixedBytes::from([0x77; 32]), 9)
            .expect("observe delayed sequence 9 candidate");
        advance_publisher_manifest_watermark(&db, FixedBytes::from([0x77; 32]), 10)
            .expect("observe global manifest sequence 10");
        assert!(
            persist_prepared_corpus(
                &db,
                &first_cache,
                &first_refresh,
                FixedBytes::from([0x77; 32]),
            )
            .expect("persist first list at sequence 10")
        );

        let second_identity = PoiCacheIdentity::new(
            first_identity.chain_type,
            first_identity.chain_id,
            first_identity.txid_version,
            FixedBytes::from([0x88; 32]),
        );
        let second_cache = test_cache(&second_identity, &[0x71]);
        let second_root = test_cache_root(&second_cache);
        let older_refresh = PoiArtifactRefresh {
            manifest_sequence: 9,
            cache: second_cache.clone(),
            entry: test_entry(&second_identity, 0, second_root.0),
            cache_generation: generation,
            corpus_advanced: true,
        };
        assert!(
            !persist_prepared_corpus(
                &db,
                &second_cache,
                &older_refresh,
                FixedBytes::from([0x77; 32]),
            )
            .expect("reject older sequence for second list")
        );
        assert!(
            load_persisted_cache(&db, &second_identity)
                .expect("load rejected second list")
                .is_none()
        );

        let current_refresh = PoiArtifactRefresh {
            manifest_sequence: 10,
            cache: second_cache.clone(),
            entry: test_entry(&second_identity, 0, second_root.0),
            cache_generation: generation,
            corpus_advanced: true,
        };
        assert!(
            persist_prepared_corpus(
                &db,
                &second_cache,
                &current_refresh,
                FixedBytes::from([0x77; 32]),
            )
            .expect("accept current sequence for second list")
        );

        drop(db);
        fs::remove_dir_all(root_dir).expect("remove temp DB root");
    }

    #[test]
    fn global_artifact_watermark_does_not_reject_other_list_rpc_progress() {
        let root_dir = temp_db_root("global-watermark-independent-rpc");
        fs::create_dir_all(&root_dir).expect("create temp DB root");
        let db = DbStore::open(DbConfig {
            root_dir: root_dir.clone(),
        })
        .expect("open temp DB");
        let generation = poi_artifact_cache_generation_cell(&db)
            .expect("cache generation")
            .load(Ordering::Acquire);
        let publisher_pubkey = FixedBytes::from([0x79; 32]);
        let artifact_identity = test_identity();
        let artifact_cache = test_cache(&artifact_identity, &[0x7a]);
        let artifact_root = test_cache_root(&artifact_cache);
        let refresh = PoiArtifactRefresh {
            manifest_sequence: 10,
            cache: artifact_cache.clone(),
            entry: test_entry(&artifact_identity, 0, artifact_root.0),
            cache_generation: generation,
            corpus_advanced: true,
        };
        advance_publisher_manifest_watermark(&db, publisher_pubkey, 10)
            .expect("observe global manifest sequence 10");
        persist_prepared_corpus(&db, &artifact_cache, &refresh, publisher_pubkey)
            .expect("persist artifact at global sequence 10");

        let rpc_identity = PoiCacheIdentity::new(
            artifact_identity.chain_type,
            artifact_identity.chain_id,
            artifact_identity.txid_version,
            FixedBytes::from([0x7b; 32]),
        );
        let store = PoiCorpusStore::new(&db, generation, publisher_pubkey);
        let first_rpc_cache = test_cache(&rpc_identity, &[0x7c]);
        let first = store
            .commit_public_rpc(&first_rpc_cache, 0)
            .expect("commit new RPC-only corpus below global artifact watermark");
        assert_eq!(first.record.current_tip_index, 0);
        assert!(matches!(
            first.record.validation,
            PoiCorpusValidationRecord::ListSignedRanges { .. }
        ));

        let advanced_rpc_cache = test_cache(&rpc_identity, &[0x7c, 0x7d]);
        let advanced = store
            .commit_public_rpc(&advanced_rpc_cache, 1)
            .expect("advance existing RPC-only corpus below global artifact watermark");
        assert_eq!(advanced.record.current_tip_index, 1);
        assert_eq!(advanced.record.legacy_observed_manifest_sequence, 0);
        assert_eq!(
            publisher_manifest_watermark(&db, publisher_pubkey)
                .expect("load retained publisher watermark"),
            Some(10)
        );

        drop(db);
        fs::remove_dir_all(root_dir).expect("remove temp DB root");
    }

    #[test]
    fn stale_first_run_manifest_is_rejected() {
        let manifest = Manifest::new(2, 1_000, 1, FixedBytes::ZERO, vec![]);
        let now = UNIX_EPOCH + Duration::from_secs(10);

        assert!(matches!(
            validate_manifest_freshness(&manifest, None, Some(Duration::from_secs(1)), now),
            Err(PoiArtifactError::ManifestStale { .. })
        ));
        validate_manifest_freshness(&manifest, Some(1), Some(Duration::from_secs(1)), now)
            .expect("persisted sequence skips first-run freshness check");
    }

    #[tokio::test]
    async fn explicit_manifest_url_reports_http_failure() {
        let signing_key = SigningKey::from_bytes(&[12_u8; 32]);
        let failing_server = spawn_manifest_server(500, Vec::new());
        let ingestor = manifest_ingestor(
            &signing_key,
            PoiArtifactManifestSource::Url(failing_server.url.clone()),
            Vec::new(),
            None,
        );

        let error = ingestor
            .fetch_manifest(None, UNIX_EPOCH + Duration::from_secs(10))
            .await
            .expect_err("manifest URL fails");

        assert!(matches!(
            error,
            PoiArtifactError::Trustless(TrustlessArtifactError::HttpStatus { .. })
        ));
        assert_eq!(failing_server.request_path(), "/");
    }

    #[tokio::test]
    async fn explicit_manifest_url_does_not_require_gateways() {
        let signing_key = SigningKey::from_bytes(&[12_u8; 32]);
        let fresh = signed_manifest(&signing_key, 9_500, 2);
        let manifest_server = spawn_manifest_server(200, serde_json::to_vec(&fresh).expect("JSON"));
        let ingestor = manifest_ingestor(
            &signing_key,
            PoiArtifactManifestSource::Url(manifest_server.url.clone()),
            Vec::new(),
            Some(Duration::from_secs(1)),
        );

        let manifest = ingestor
            .fetch_manifest(None, UNIX_EPOCH + Duration::from_secs(10))
            .await
            .expect("explicit manifest URL");

        assert_eq!(manifest.sequence, 2);
        assert_eq!(manifest_server.request_path(), "/");
    }

    #[tokio::test]
    async fn authenticated_manifest_is_observed_before_entry_processing() {
        let root_dir = temp_db_root("manifest-observed-before-entry");
        fs::create_dir_all(&root_dir).expect("create temp DB root");
        let db = DbStore::open(DbConfig {
            root_dir: root_dir.clone(),
        })
        .expect("open temp DB");
        let signing_key = SigningKey::from_bytes(&[0x12; 32]);
        let sequence_10 = signed_manifest(&signing_key, 9_500, 10);
        let first_server = spawn_manifest_server(
            200,
            serde_json::to_vec(&sequence_10).expect("sequence 10 JSON"),
        );
        let first_ingestor = manifest_ingestor(
            &signing_key,
            PoiArtifactManifestSource::Url(first_server.url.clone()),
            Vec::new(),
            Some(Duration::from_secs(1)),
        );
        let identity = test_identity();

        assert!(matches!(
            first_ingestor
                .prepare_cache_with_optional_preloaded(
                    &db,
                    identity.clone(),
                    None,
                    UNIX_EPOCH + Duration::from_secs(10),
                )
                .await,
            Err(PoiArtifactError::MissingManifestEntry { .. })
        ));
        assert_eq!(
            publisher_manifest_watermark(
                &db,
                FixedBytes::from(signing_key.verifying_key().to_bytes()),
            )
            .expect("load observed watermark"),
            Some(10)
        );
        assert!(
            db.get_poi_artifact_cache(
                identity.chain_type,
                identity.chain_id,
                &identity.txid_version,
                &identity.list_key,
            )
            .expect("load absent corpus")
            .is_none()
        );

        let sequence_9 = signed_manifest(&signing_key, 9_500, 9);
        let second_server = spawn_manifest_server(
            200,
            serde_json::to_vec(&sequence_9).expect("sequence 9 JSON"),
        );
        let second_ingestor = manifest_ingestor(
            &signing_key,
            PoiArtifactManifestSource::Url(second_server.url.clone()),
            Vec::new(),
            Some(Duration::from_secs(1)),
        );
        assert!(matches!(
            second_ingestor
                .fetch_observed_manifest(&db, UNIX_EPOCH + Duration::from_secs(10))
                .await,
            Err(PoiArtifactError::ManifestSequenceRollback {
                previous: 10,
                received: 9,
            })
        ));

        drop(db);
        fs::remove_dir_all(root_dir).expect("remove temp DB root");
    }

    #[tokio::test]
    async fn cid_manifest_fetch_uses_trustless_car() {
        let signing_key = SigningKey::from_bytes(&[12_u8; 32]);
        let fresh = signed_manifest(&signing_key, 9_500, 2);
        let manifest_bytes = serde_json::to_vec(&fresh).expect("manifest JSON");
        let cid = raw_cid(&manifest_bytes);
        let manifest_server =
            spawn_manifest_server(200, raw_car_bytes(cid, &[(cid, manifest_bytes)]));
        let ingestor = manifest_ingestor(
            &signing_key,
            PoiArtifactManifestSource::Cid(cid.to_string()),
            vec![manifest_server.url.clone()],
            Some(Duration::from_secs(1)),
        );

        let manifest = ingestor
            .fetch_manifest(None, UNIX_EPOCH + Duration::from_secs(10))
            .await
            .expect("trustless manifest CID");

        assert_eq!(manifest.sequence, 2);
        assert_eq!(
            manifest_server.request_path(),
            format!("/ipfs/{cid}?format=car&dag-scope=entity")
        );
    }

    #[tokio::test]
    async fn artifact_fetch_uses_trustless_car_before_descriptor_verification() {
        let signing_key = SigningKey::from_bytes(&[12_u8; 32]);
        let artifact_bytes = b"verified artifact bytes".to_vec();
        let cid = raw_cid(&artifact_bytes);
        let artifact_server =
            spawn_manifest_server(200, raw_car_bytes(cid, &[(cid, artifact_bytes.clone())]));
        let ingestor = manifest_ingestor(
            &signing_key,
            PoiArtifactManifestSource::Url(artifact_server.url.clone()),
            vec![artifact_server.url.clone()],
            None,
        );
        let descriptor = ArtifactDescriptor::from_bytes(cid.to_string(), &artifact_bytes);

        let fetched = ingestor
            .fetch_artifact(&descriptor)
            .await
            .expect("trustless artifact CID");

        assert_eq!(fetched, artifact_bytes);
        assert_eq!(
            artifact_server.request_path(),
            format!("/ipfs/{cid}?format=car&dag-scope=entity")
        );
    }

    #[tokio::test]
    async fn artifact_suffix_merge_applies_only_missing_artifact_events() {
        let signing_key = SigningKey::from_bytes(&[13_u8; 32]);
        let identity = signed_identity(&signing_key);
        let mut events = vec![
            signed_proxy_event(&signing_key, 0, 0x10, [0_u8; 32]),
            signed_proxy_event(&signing_key, 1, 0x11, [0_u8; 32]),
            signed_proxy_event(&signing_key, 2, 0x12, [0_u8; 32]),
        ];
        let mut cache = PoiCache::new(identity.clone());
        cache
            .apply_verified_artifact_events(&[snapshot_event_from_proxy(&events[0])])
            .expect("apply initial event");
        let root_0 = root_for_tip(&mut cache, 0);
        cache.accept_current_roots();

        let mut expected = cache.clone();
        expected
            .apply_verified_artifact_events(&[
                snapshot_event_from_proxy(&events[1]),
                snapshot_event_from_proxy(&events[2]),
            ])
            .expect("apply expected events");
        let root_2 = root_for_tip(&mut expected, 2);

        events[0].validated_merkleroot = hex::encode_prefixed(root_0.as_slice());
        events[2].validated_merkleroot = hex::encode_prefixed(root_2.as_slice());

        let base_bytes =
            snapshot_artifact_bytes(&identity, SnapshotKind::Base, 0, 2, &events, root_2);
        let base_cid = raw_cid(&base_bytes);
        let base_descriptor = ArtifactDescriptor::from_bytes(base_cid.to_string(), &base_bytes);
        let artifact_server =
            spawn_manifest_server(200, raw_car_bytes(base_cid, &[(base_cid, base_bytes)]));
        let ingestor = manifest_ingestor(
            &signing_key,
            PoiArtifactManifestSource::Url(artifact_server.url.clone()),
            vec![artifact_server.url.clone()],
            None,
        );
        let mut entry = test_entry(&identity, 2, root_2.0);
        entry.base = base_descriptor;
        entry.deltas = Vec::new();
        let persisted = persisted_cache(&identity, cache, 0, root_0, &entry);

        let mut refresh = ingestor
            .try_artifact_suffix_merge(&identity, 5, &entry, &persisted, persisted.cache_generation)
            .await
            .expect("artifact suffix merge")
            .expect("merge result");

        assert_eq!(refresh.manifest_sequence, 5);
        assert_eq!(refresh.entry.current_tip_index, 2);
        assert_eq!(refresh.cache.progress().next_event_index, 3);
        assert_eq!(root_for_tip(&mut refresh.cache, 2), root_2);
        assert_eq!(
            artifact_server.request_path(),
            format!("/ipfs/{base_cid}?format=car&dag-scope=entity")
        );
    }

    #[tokio::test]
    async fn artifact_suffix_merge_applies_missing_delta_events() {
        let signing_key = SigningKey::from_bytes(&[18_u8; 32]);
        let identity = signed_identity(&signing_key);
        let mut events = [
            signed_proxy_event(&signing_key, 0, 0x10, [0_u8; 32]),
            signed_proxy_event(&signing_key, 1, 0x11, [0_u8; 32]),
            signed_proxy_event(&signing_key, 2, 0x12, [0_u8; 32]),
            signed_proxy_event(&signing_key, 3, 0x13, [0_u8; 32]),
        ];
        let mut cache = PoiCache::new(identity.clone());
        cache
            .apply_verified_artifact_events(&[
                snapshot_event_from_proxy(&events[0]),
                snapshot_event_from_proxy(&events[1]),
            ])
            .expect("apply local events");
        let root_1 = root_for_tip(&mut cache, 1);
        cache.accept_current_roots();

        let mut expected = cache.clone();
        expected
            .apply_verified_artifact_events(&[
                snapshot_event_from_proxy(&events[2]),
                snapshot_event_from_proxy(&events[3]),
            ])
            .expect("apply expected events");
        let root_3 = root_for_tip(&mut expected, 3);

        events[1].validated_merkleroot = hex::encode_prefixed(root_1.as_slice());
        events[3].validated_merkleroot = hex::encode_prefixed(root_3.as_slice());

        let base_bytes =
            snapshot_artifact_bytes(&identity, SnapshotKind::Base, 0, 1, &events[0..=1], root_1);
        let base_cid = raw_cid(&base_bytes);
        let base_descriptor = ArtifactDescriptor::from_bytes(base_cid.to_string(), &base_bytes);
        let delta_bytes =
            snapshot_artifact_bytes(&identity, SnapshotKind::Delta, 2, 3, &events[2..=3], root_3);
        let delta_cid = raw_cid(&delta_bytes);
        let delta_descriptor = ArtifactDescriptor::from_bytes(delta_cid.to_string(), &delta_bytes);
        let artifact_server = spawn_json_rpc(vec![
            raw_car_bytes(base_cid, &[(base_cid, base_bytes)]),
            raw_car_bytes(delta_cid, &[(delta_cid, delta_bytes)]),
        ]);
        let ingestor = manifest_ingestor(
            &signing_key,
            PoiArtifactManifestSource::Url(artifact_server.url.clone()),
            vec![artifact_server.url.clone()],
            None,
        );
        let mut entry = test_entry(&identity, 3, root_3.0);
        entry.base = base_descriptor;
        entry.deltas = vec![delta_descriptor];
        let persisted = persisted_cache(&identity, cache, 1, root_1, &entry);

        let mut refresh = ingestor
            .try_artifact_suffix_merge(&identity, 5, &entry, &persisted, persisted.cache_generation)
            .await
            .expect("artifact suffix merge")
            .expect("merge result");

        assert_eq!(refresh.cache.progress().next_event_index, 4);
        assert_eq!(root_for_tip(&mut refresh.cache, 3), root_3);
        assert_eq!(
            artifact_server.request_path(),
            format!("/ipfs/{base_cid}?format=car&dag-scope=entity")
        );
        assert_eq!(
            artifact_server.request_path(),
            format!("/ipfs/{delta_cid}?format=car&dag-scope=entity")
        );
    }

    #[tokio::test]
    async fn artifact_suffix_merge_replaces_changed_blocked_shields() {
        let signing_key = SigningKey::from_bytes(&[17_u8; 32]);
        let identity = signed_identity(&signing_key);
        let mut events = vec![
            signed_proxy_event(&signing_key, 0, 0x10, [0_u8; 32]),
            signed_proxy_event(&signing_key, 1, 0x11, [0_u8; 32]),
        ];
        let blocked_commitment = FixedBytes::from([0x44; 32]);
        let mut cache = PoiCache::new(identity.clone());
        cache
            .apply_verified_artifact_events(&[snapshot_event_from_proxy(&events[0])])
            .expect("apply initial event");
        cache
            .apply_blocked_shields(&[blocked_shield(blocked_commitment)])
            .expect("apply old blocked shield");
        assert_eq!(cache.status(&blocked_commitment), PoiStatus::ShieldBlocked);
        let root_0 = root_for_tip(&mut cache, 0);
        cache.accept_current_roots();

        let mut expected = cache.clone();
        expected
            .apply_verified_artifact_events(&[snapshot_event_from_proxy(&events[1])])
            .expect("apply expected event");
        let root_1 = root_for_tip(&mut expected, 1);
        events[0].validated_merkleroot = hex::encode_prefixed(root_0.as_slice());
        events[1].validated_merkleroot = hex::encode_prefixed(root_1.as_slice());

        let base_bytes =
            snapshot_artifact_bytes(&identity, SnapshotKind::Base, 0, 1, &events, root_1);
        let base_cid = raw_cid(&base_bytes);
        let base_descriptor = ArtifactDescriptor::from_bytes(base_cid.to_string(), &base_bytes);

        let empty_blocked = BlockedShieldsArtifact::from_signed_records(
            format::FORMAT_VERSION,
            &identity.list_key.0,
            identity.chain_id,
            identity.chain_type,
            &[0_u8; 32],
            &[],
        );
        let empty_blocked_bytes = empty_blocked.to_bytes().expect("blocked artifact bytes");
        let empty_blocked_cid = raw_cid(&empty_blocked_bytes);
        let empty_blocked_descriptor =
            ArtifactDescriptor::from_bytes(empty_blocked_cid.to_string(), &empty_blocked_bytes);
        let artifact_server = spawn_json_rpc(vec![
            raw_car_bytes(base_cid, &[(base_cid, base_bytes)]),
            raw_car_bytes(
                empty_blocked_cid,
                &[(empty_blocked_cid, empty_blocked_bytes)],
            ),
        ]);
        let ingestor = manifest_ingestor(
            &signing_key,
            PoiArtifactManifestSource::Url(artifact_server.url.clone()),
            vec![artifact_server.url.clone()],
            None,
        );
        let mut entry = test_entry(&identity, 1, root_1.0);
        entry.base = base_descriptor;
        entry.deltas = Vec::new();
        entry.blocked_shields = empty_blocked_descriptor;
        let mut persisted = persisted_cache(&identity, cache, 0, root_0, &entry);
        persisted.record.blocked_shields_descriptor = descriptor_record(&descriptor("old-blocked"));

        let refresh = ingestor
            .try_artifact_suffix_merge(&identity, 5, &entry, &persisted, persisted.cache_generation)
            .await
            .expect("artifact suffix merge")
            .expect("merge result");

        assert_eq!(
            refresh.cache.status(&blocked_commitment),
            PoiStatus::Missing
        );
        assert_eq!(
            artifact_server.request_path(),
            format!("/ipfs/{base_cid}?format=car&dag-scope=entity")
        );
        assert_eq!(
            artifact_server.request_path(),
            format!("/ipfs/{empty_blocked_cid}?format=car&dag-scope=entity")
        );
    }

    #[tokio::test]
    async fn artifact_suffix_merge_skips_ranges_crossing_tree_boundary() {
        let signing_key = SigningKey::from_bytes(&[16_u8; 32]);
        let identity = signed_identity(&signing_key);
        let local_tip_index = broadcaster_core::tree::TREE_LEAF_COUNT - 2;
        let boundary_index = broadcaster_core::tree::TREE_LEAF_COUNT - 1;
        let artifact_tip_index = broadcaster_core::tree::TREE_LEAF_COUNT;

        let mut local_event = signed_proxy_event(&signing_key, local_tip_index, 0x10, [0_u8; 32]);
        let mut cache = PoiCache::new(identity.clone());
        cache
            .apply_verified_artifact_events(&[snapshot_event_from_proxy(&local_event)])
            .expect("apply local event");
        let local_root = root_for_tip(&mut cache, local_tip_index);
        cache.accept_current_roots();

        let mut boundary_event = signed_proxy_event(&signing_key, boundary_index, 0x22, [0x55; 32]);
        let mut tip_event = signed_proxy_event(&signing_key, artifact_tip_index, 0x33, [0_u8; 32]);
        let mut expected = cache.clone();
        expected
            .apply_verified_artifact_events(&[
                snapshot_event_from_proxy(&boundary_event),
                snapshot_event_from_proxy(&tip_event),
            ])
            .expect("apply expected events");
        let artifact_tip_root = root_for_tip(&mut expected, artifact_tip_index);

        local_event.validated_merkleroot = hex::encode_prefixed(local_root.as_slice());
        tip_event.validated_merkleroot = hex::encode_prefixed(artifact_tip_root.as_slice());
        boundary_event.validated_merkleroot = hex::encode_prefixed([0x55; 32]);

        let proxy = spawn_json_rpc(Vec::new());
        let ingestor = manifest_ingestor(
            &signing_key,
            PoiArtifactManifestSource::Url(proxy.url.clone()),
            Vec::new(),
            None,
        );
        let entry = test_entry(&identity, artifact_tip_index, artifact_tip_root.0);
        let persisted = persisted_cache(&identity, cache, local_tip_index, local_root, &entry);

        let refresh = ingestor
            .try_artifact_suffix_merge(&identity, 5, &entry, &persisted, persisted.cache_generation)
            .await
            .expect("artifact suffix merge decision");

        assert!(refresh.is_none());
    }

    #[tokio::test]
    async fn artifact_suffix_merge_accepts_publisher_root_without_proxy() {
        let signing_key = SigningKey::from_bytes(&[14_u8; 32]);
        let identity = signed_identity(&signing_key);
        let events = vec![
            signed_proxy_event(&signing_key, 0, 0x10, [0_u8; 32]),
            signed_proxy_event(&signing_key, 1, 0x11, [0_u8; 32]),
        ];
        let mut cache = PoiCache::new(identity.clone());
        cache
            .apply_verified_artifact_events(&[snapshot_event_from_proxy(&events[0])])
            .expect("apply initial event");
        let root_0 = root_for_tip(&mut cache, 0);
        cache.accept_current_roots();

        let mut expected = cache.clone();
        expected
            .apply_verified_artifact_events(&[snapshot_event_from_proxy(&events[1])])
            .expect("apply expected event");
        let root_1 = root_for_tip(&mut expected, 1);
        let base_bytes =
            snapshot_artifact_bytes(&identity, SnapshotKind::Base, 0, 1, &events, root_1);
        let base_cid = raw_cid(&base_bytes);
        let base_descriptor = ArtifactDescriptor::from_bytes(base_cid.to_string(), &base_bytes);
        let artifact_server =
            spawn_manifest_server(200, raw_car_bytes(base_cid, &[(base_cid, base_bytes)]));
        let ingestor = manifest_ingestor(
            &signing_key,
            PoiArtifactManifestSource::Url(artifact_server.url.clone()),
            vec![artifact_server.url.clone()],
            None,
        );
        let mut entry = test_entry(&identity, 1, root_1.0);
        entry.base = base_descriptor;
        entry.deltas = Vec::new();
        let persisted = persisted_cache(&identity, cache, 0, root_0, &entry);

        let refresh = ingestor
            .try_artifact_suffix_merge(&identity, 5, &entry, &persisted, persisted.cache_generation)
            .await
            .expect("publisher-attested artifact merge")
            .expect("merge result");

        assert_eq!(refresh.cache.progress().next_event_index, 2);
        let mut refreshed_cache = refresh.cache;
        assert_eq!(root_for_tip(&mut refreshed_cache, 1), root_1);
    }

    #[test]
    fn snapshot_ranges_must_be_base_then_contiguous_deltas() {
        let identity = test_identity();
        let entry = test_entry(&identity, 2, [0_u8; 32]);
        let base = snapshot(&identity, SnapshotKind::Base, 0, 1);
        let delta = snapshot(&identity, SnapshotKind::Delta, 2, 2);
        let gap = snapshot(&identity, SnapshotKind::Delta, 3, 3);

        let next = validate_snapshot(&base, &identity, &entry, SnapshotKind::Base, 0)
            .expect("valid base snapshot");
        assert_eq!(next, 2);
        let next = validate_snapshot(&delta, &identity, &entry, SnapshotKind::Delta, next)
            .expect("valid contiguous delta");
        assert_eq!(next, 3);
        assert!(matches!(
            validate_snapshot(&gap, &identity, &entry, SnapshotKind::Delta, 2),
            Err(PoiArtifactError::SnapshotStartMismatch {
                expected: 2,
                actual: 3,
            })
        ));
    }

    #[test]
    fn replayed_cache_root_must_match_manifest_tip() {
        let identity = test_identity();
        let mut cache = PoiCache::new(identity.clone());
        cache
            .apply_verified_artifact_events(&[SnapshotEvent {
                event_index: 0,
                blinded_commitment: [0x44; 32],
                signature: [0_u8; 64],
                event_type: PoiEventType::Transact,
            }])
            .expect("apply event");
        let root = cache.current_roots().remove(&0).expect("root");
        let entry = test_entry(&identity, 0, *root);

        verify_manifest_root(&mut cache, &entry).expect("matching replay root");

        let mismatched = test_entry(&identity, 0, [0x55; 32]);
        assert!(matches!(
            verify_manifest_root(&mut cache, &mismatched),
            Err(PoiArtifactError::ReplayRootMismatch { .. })
        ));
    }

    #[tokio::test]
    async fn stale_poi_artifact_refresh_cannot_repopulate_after_reset() {
        let root_dir = temp_db_root("stale-poi-refresh-after-reset");
        let db = DbStore::open(DbConfig {
            root_dir: root_dir.clone(),
        })
        .expect("open db");
        let identity = test_identity();
        let cache = test_cache(&identity, &[0x44]);
        let root = test_cache_root(&cache);
        let entry = test_entry(&identity, 0, root.0);
        let persisted = persisted_cache(&identity, cache, 0, root, &entry);
        db.put_poi_artifact_cache(&persisted.record)
            .expect("store initial POI artifact cache");
        let loaded = load_persisted_cache(&db, &identity)
            .expect("load persisted cache")
            .expect("persisted cache exists");
        let refresh = PoiArtifactRefresh {
            manifest_sequence: 5,
            cache: loaded.cache.clone(),
            entry,
            cache_generation: loaded.cache_generation,
            corpus_advanced: true,
        };

        let reset = clear_poi_artifact_cache_for_reset(&db)
            .await
            .expect("reset POI artifact cache");
        let error = persist_refresh(&db, &identity, &refresh)
            .expect_err("stale refresh must not repopulate after reset");

        assert_eq!(reset.removed, 1);
        assert_eq!(reset.generation, 1);
        assert_eq!(
            poi_artifact_cache_generation_cell(&db)
                .expect("load reset generation")
                .load(Ordering::Acquire),
            reset.generation
        );
        assert!(matches!(
            error,
            PoiArtifactError::StalePublicCacheGeneration { .. }
        ));
        assert!(
            db.get_poi_artifact_cache(
                identity.chain_type,
                identity.chain_id,
                &identity.txid_version,
                &identity.list_key,
            )
            .expect("load POI artifact cache after stale persist")
            .is_none()
        );

        drop(db);
        let reopened = DbStore::open(DbConfig {
            root_dir: root_dir.clone(),
        })
        .expect("reopen db");
        assert_eq!(
            poi_artifact_cache_generation_cell(&reopened)
                .expect("load persisted reset generation")
                .load(Ordering::Acquire),
            reset.generation
        );
        drop(reopened);
        fs::remove_dir_all(root_dir).expect("remove temp db dir");
    }

    #[test]
    fn publisher_attested_blocked_shields_skip_per_record_signature_verification() {
        let list_key = [
            0xea, 0x4a, 0x6c, 0x63, 0xe2, 0x9c, 0x52, 0x0a, 0xbe, 0xf5, 0x50, 0x7b, 0x13, 0x2e,
            0xc5, 0xf9, 0x95, 0x47, 0x76, 0xae, 0xbe, 0xbe, 0x7b, 0x92, 0x42, 0x1e, 0xea, 0x69,
            0x14, 0x46, 0xd2, 0x2c,
        ];
        let identity = PoiCacheIdentity::new(0, 1, "V2_PoseidonMerkle", FixedBytes::from(list_key));
        let signed = poi::poi::SignedBlockedShield {
            commitment_hash: "0x2222222222222222222222222222222222222222222222222222222222222222"
                .to_string(),
            blinded_commitment:
                "0x3333333333333333333333333333333333333333333333333333333333333333".to_string(),
            block_reason: None,
            signature: "intentionally-not-an-ed25519-signature".to_string(),
        };
        let artifact = BlockedShieldsArtifact::from_signed_records(
            format::FORMAT_VERSION,
            &list_key,
            identity.chain_id,
            identity.chain_type,
            &[0_u8; 32],
            &[signed],
        );

        let records = validate_blocked_shields_artifact(&artifact, &identity)
            .expect("valid blocked-shields scope");
        assert_eq!(records.len(), 1);
    }

    #[test]
    fn publisher_attested_snapshot_skips_per_event_signature_verification() {
        let identity = test_identity();
        let mut artifact = snapshot(&identity, SnapshotKind::Base, 0, 0);
        artifact.events.push(SnapshotEvent {
            event_index: 0,
            blinded_commitment: [0x44; 32],
            signature: [0_u8; 64],
            event_type: PoiEventType::Transact,
        });

        assert_eq!(
            validate_snapshot(
                &artifact,
                &identity,
                &test_entry(&identity, 0, [0_u8; 32]),
                SnapshotKind::Base,
                0,
            )
            .expect("publisher-attested event structure"),
            1
        );
    }

    fn test_identity() -> PoiCacheIdentity {
        PoiCacheIdentity::new(0, 1, "V2_PoseidonMerkle", FixedBytes::from([0x11; 32]))
    }

    fn temp_db_root(name: &str) -> PathBuf {
        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system time")
            .as_nanos();
        std::env::temp_dir().join(format!("sync-service-poi-artifacts-{name}-{unique}"))
    }

    fn signed_identity(signing_key: &SigningKey) -> PoiCacheIdentity {
        PoiCacheIdentity::new(
            0,
            1,
            "V2_PoseidonMerkle",
            FixedBytes::from(signing_key.verifying_key().to_bytes()),
        )
    }

    fn signed_manifest(signing_key: &SigningKey, issued_at_ms: u64, sequence: u64) -> Manifest {
        let mut manifest = Manifest::new(2, issued_at_ms, sequence, FixedBytes::ZERO, vec![]);
        manifest.sign_manifest(signing_key).expect("sign manifest");
        manifest
    }

    fn manifest_ingestor(
        signing_key: &SigningKey,
        manifest_source: PoiArtifactManifestSource,
        gateway_urls: Vec<Url>,
        max_manifest_age: Option<Duration>,
    ) -> PoiArtifactIngestor {
        PoiArtifactIngestor::new(
            PoiArtifactSourceConfig {
                trusted_publisher_pubkey: FixedBytes::from(signing_key.verifying_key().to_bytes()),
                manifest_source,
                gateway_urls,
                max_manifest_age,
            },
            reqwest::Client::new(),
        )
    }

    struct MockManifestServer {
        url: Url,
        requests: Receiver<String>,
    }

    impl MockManifestServer {
        fn request_path(&self) -> String {
            self.requests
                .recv_timeout(Duration::from_secs(2))
                .expect("manifest request path")
        }
    }

    fn spawn_manifest_server(status: u16, body: Vec<u8>) -> MockManifestServer {
        spawn_status_server(status, body)
    }

    fn spawn_status_server(status: u16, body: Vec<u8>) -> MockManifestServer {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind manifest server");
        let url = Url::parse(&format!(
            "http://{}",
            listener.local_addr().expect("local addr")
        ))
        .expect("manifest server URL");
        let (tx, requests) = mpsc::channel();
        std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().expect("accept request");
            let mut request = Vec::new();
            let mut buf = [0_u8; 1024];
            loop {
                let read = stream.read(&mut buf).expect("read request");
                assert!(read > 0, "manifest client closed before request headers");
                request.extend_from_slice(&buf[..read]);
                if request.windows(4).any(|window| window == b"\r\n\r\n") {
                    break;
                }
            }
            let request_text = String::from_utf8_lossy(&request);
            let path = request_text
                .split_whitespace()
                .nth(1)
                .expect("request path")
                .to_string();
            tx.send(path).expect("record request path");

            let reason = if status == 200 { "OK" } else { "ERROR" };
            let response = format!(
                "HTTP/1.1 {status} {reason}\r\nContent-Length: {}\r\nContent-Type: application/json\r\nConnection: close\r\n\r\n",
                body.len()
            );
            stream
                .write_all(response.as_bytes())
                .expect("write response headers");
            stream.write_all(&body).expect("write response body");
        });

        MockManifestServer { url, requests }
    }

    fn spawn_json_rpc(responses: Vec<Vec<u8>>) -> MockManifestServer {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind JSON-RPC server");
        let url = Url::parse(&format!(
            "http://{}",
            listener.local_addr().expect("local addr")
        ))
        .expect("JSON-RPC server URL");
        let (tx, requests) = mpsc::channel();
        std::thread::spawn(move || {
            for body in responses {
                let (mut stream, _) = listener.accept().expect("accept request");
                let mut request = Vec::new();
                let mut buf = [0_u8; 1024];
                loop {
                    let read = stream.read(&mut buf).expect("read request");
                    assert!(read > 0, "client closed before request headers");
                    request.extend_from_slice(&buf[..read]);
                    if request.windows(4).any(|window| window == b"\r\n\r\n") {
                        break;
                    }
                }
                let request_text = String::from_utf8_lossy(&request);
                let path = request_text
                    .split_whitespace()
                    .nth(1)
                    .expect("request path")
                    .to_string();
                tx.send(path).expect("record request path");

                let response = format!(
                    "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nContent-Type: application/json\r\nConnection: close\r\n\r\n",
                    body.len()
                );
                stream
                    .write_all(response.as_bytes())
                    .expect("write response headers");
                stream.write_all(&body).expect("write response body");
            }
        });

        MockManifestServer { url, requests }
    }

    fn test_entry(
        identity: &PoiCacheIdentity,
        current_tip_index: u64,
        current_tip_merkleroot: [u8; 32],
    ) -> ManifestEntry {
        ManifestEntry {
            list_key: identity.list_key,
            chain_id: identity.chain_id,
            base: descriptor("base"),
            deltas: vec![descriptor("delta")],
            retained_deltas: Vec::new(),
            blocked_shields: descriptor("blocked"),
            current_tip_index,
            current_tip_merkleroot: FixedBytes::from(current_tip_merkleroot),
        }
    }

    fn descriptor(cid: &str) -> ArtifactDescriptor {
        ArtifactDescriptor {
            cid: cid.to_string(),
            sha256: FixedBytes::ZERO,
            byte_size: 0,
        }
    }

    fn test_cache(identity: &PoiCacheIdentity, commitment_bytes: &[u8]) -> PoiCache {
        let events = commitment_bytes
            .iter()
            .enumerate()
            .map(|(index, byte)| SnapshotEvent {
                event_index: index as u64,
                blinded_commitment: [*byte; 32],
                signature: [0_u8; 64],
                event_type: PoiEventType::Transact,
            })
            .collect::<Vec<_>>();
        let mut cache = PoiCache::new(identity.clone());
        cache
            .apply_verified_artifact_events(&events)
            .expect("apply test artifact events");
        cache.accept_current_roots();
        cache
    }

    fn test_cache_root(cache: &PoiCache) -> FixedBytes<32> {
        *cache
            .clone()
            .current_roots()
            .get(&0)
            .expect("test cache root")
    }

    fn persisted_cache(
        identity: &PoiCacheIdentity,
        cache: PoiCache,
        current_tip_index: u64,
        current_tip_root: FixedBytes<32>,
        entry: &ManifestEntry,
    ) -> PersistedPoiArtifactCache {
        PersistedPoiArtifactCache {
            record: PoiArtifactCacheRecord {
                chain_type: identity.chain_type,
                chain_id: identity.chain_id,
                txid_version: identity.txid_version.clone(),
                list_key: identity.list_key,
                source: PoiCacheRecordSource::IndexedArtifacts,
                validation: PoiCorpusValidationRecord::Legacy,
                legacy_observed_manifest_sequence: 4,
                base_descriptor: descriptor_record(&descriptor("old-base")),
                applied_delta_descriptors: Vec::new(),
                blocked_shields_descriptor: descriptor_record(&entry.blocked_shields),
                artifact_tip_index: Some(current_tip_index),
                artifact_tip_root: Some(current_tip_root),
                current_tip_index,
                current_tip_root,
                cache_payload: cache.to_bytes().expect("cache bytes"),
                legacy_last_successful_rpc_sync_at_ms: None,
                updated_at: 0,
            },
            cache,
            cache_generation: 0,
        }
    }

    fn signed_proxy_event(
        signing_key: &SigningKey,
        index: u64,
        commitment_byte: u8,
        validated_root: [u8; 32],
    ) -> PoiSyncedListEvent {
        let blinded_commitment = FixedBytes::from([commitment_byte; 32]);
        let blinded_commitment_hex = hex::encode_prefixed(blinded_commitment.as_slice());
        let message = format!(
            r#"{{"index":{index},"blindedCommitment":"{blinded_commitment_hex}","type":"Transact"}}"#
        );
        let signature = signing_key.sign(message.as_bytes()).to_bytes();
        PoiSyncedListEvent {
            signed_poi_event: SignedPoiEvent {
                index,
                blinded_commitment,
                signature: hex::encode_prefixed(signature),
                event_type: PoiEventType::Transact,
            },
            validated_merkleroot: hex::encode_prefixed(validated_root),
        }
    }

    fn blocked_shield(blinded_commitment: FixedBytes<32>) -> BlockedShield {
        BlockedShield {
            commitment_hash: hex::encode_prefixed([0x55; 32]),
            blinded_commitment: hex::encode_prefixed(blinded_commitment.as_slice()),
            block_reason: None,
            signature: String::new(),
        }
    }

    fn snapshot_event_from_proxy(event: &PoiSyncedListEvent) -> SnapshotEvent {
        SnapshotEvent {
            event_index: event.signed_poi_event.index,
            blinded_commitment: event.signed_poi_event.blinded_commitment.0,
            signature: decode_fixed_hex(
                "signedPOIEvent.signature",
                &event.signed_poi_event.signature,
            )
            .expect("signature"),
            event_type: event.signed_poi_event.event_type,
        }
    }

    fn snapshot_artifact_bytes(
        identity: &PoiCacheIdentity,
        kind: SnapshotKind,
        start_index: u64,
        end_index: u64,
        events: &[PoiSyncedListEvent],
        tip_merkleroot: FixedBytes<32>,
    ) -> Vec<u8> {
        let records = events
            .iter()
            .map(snapshot_event_from_proxy)
            .collect::<Vec<_>>();
        let header = SnapshotHeaderInput {
            list_key: identity.list_key.0,
            chain_id: identity.chain_id,
            chain_type: identity.chain_type,
            kind,
            start_index,
            end_index,
            tip_merkleroot: tip_merkleroot.0,
            upstream_endpoint_hash: [0_u8; 32],
            created_at_unix_seconds: 1_700_000_000,
        };
        SnapshotWriter::write(&header, &records).expect("snapshot artifact bytes")
    }

    fn root_for_tip(cache: &mut PoiCache, tip_index: u64) -> FixedBytes<32> {
        let (tree_number, _) = normalize_tree_position(0, tip_index);
        *cache
            .current_roots()
            .get(&tree_number)
            .expect("tip tree root")
    }

    fn raw_cid(bytes: &[u8]) -> Cid {
        Cid::new_v1(0x55, Code::Sha2_256.digest(bytes))
    }

    fn raw_car_bytes(root: Cid, blocks: &[(Cid, Vec<u8>)]) -> Vec<u8> {
        let header = raw_car_header(root);
        let mut car = Vec::new();
        write_varint(header.len(), &mut car);
        car.extend_from_slice(&header);
        for (cid, block) in blocks {
            let cid_bytes = cid.to_bytes();
            write_varint(cid_bytes.len() + block.len(), &mut car);
            car.extend_from_slice(&cid_bytes);
            car.extend_from_slice(block);
        }
        car
    }

    fn raw_car_header(root: Cid) -> Vec<u8> {
        let mut header = Vec::new();
        header.push(0xa2);
        write_cbor_text("roots", &mut header);
        header.push(0x81);
        header.extend_from_slice(&[0xd8, 0x2a]);
        let mut cid_link = vec![0_u8];
        cid_link.extend_from_slice(&root.to_bytes());
        write_cbor_bytes(&cid_link, &mut header);
        write_cbor_text("version", &mut header);
        header.push(0x01);
        header
    }

    fn write_cbor_text(value: &str, out: &mut Vec<u8>) {
        write_cbor_len(0x60, value.len(), out);
        out.extend_from_slice(value.as_bytes());
    }

    fn write_cbor_bytes(value: &[u8], out: &mut Vec<u8>) {
        write_cbor_len(0x40, value.len(), out);
        out.extend_from_slice(value);
    }

    fn write_cbor_len(major: u8, len: usize, out: &mut Vec<u8>) {
        match len {
            0..=23 => out.push(major | u8::try_from(len).expect("small len")),
            24..=0xff => {
                out.extend_from_slice(&[major | 0x18, u8::try_from(len).expect("u8 len")]);
            }
            0x100..=0xffff => {
                out.push(major | 0x19);
                out.extend_from_slice(&u16::try_from(len).expect("u16 len").to_be_bytes());
            }
            _ => panic!("fixture length too large"),
        }
    }

    fn write_varint(mut value: usize, out: &mut Vec<u8>) {
        while value >= 0x80 {
            out.push((u8::try_from(value & 0x7f).expect("varint byte")) | 0x80);
            value >>= 7;
        }
        out.push(u8::try_from(value).expect("varint final byte"));
    }

    fn snapshot(
        identity: &PoiCacheIdentity,
        kind: SnapshotKind,
        start_index: u64,
        end_index: u64,
    ) -> Snapshot {
        Snapshot {
            header: SnapshotHeader {
                format_version: format::FORMAT_VERSION,
                header_len: format::HEADER_LEN_U16,
                list_key: identity.list_key.0,
                chain_id: identity.chain_id,
                chain_type: identity.chain_type,
                kind,
                start_index,
                end_index,
                event_count: end_index - start_index + 1,
                blocked_shield_count: 0,
                tip_merkleroot: [0_u8; 32],
                upstream_endpoint_hash: [0_u8; 32],
                created_at_unix_seconds: 1_700_000_000,
                events_offset: format::HEADER_LEN_U64,
                blocked_shields_offset: format::HEADER_LEN_U64,
            },
            events: Vec::new(),
            blocked_shields: Vec::new(),
        }
    }
}
