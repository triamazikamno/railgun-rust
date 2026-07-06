use std::collections::BTreeMap;
use std::path::PathBuf;
use std::sync::{Arc, LazyLock, Mutex, MutexGuard};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use alloy::hex;
#[cfg(test)]
use alloy::primitives::FixedBytes;
use broadcaster_core::tree::normalize_tree_position;
use local_db::{DbStore, PoiArtifactCacheRecord, PoiArtifactDescriptorRecord};
use poi::artifacts::{
    ArtifactDescriptor, BlockedShieldsArtifact, BlockedShieldsArtifactError, Manifest,
    ManifestEntry, ManifestError, Snapshot, SnapshotError, SnapshotKind, SnapshotReader,
    verify_blocked_shield,
};
use poi::cache::{PoiCache, PoiCacheError, PoiCacheIdentity};
use poi::poi::{BlockedShield, PoiRpcClient};
use thiserror::Error;
use tracing::debug;
use url::Url;

use crate::trustless_artifacts::{self, TrustlessArtifactError, TrustlessArtifactFetcher};
use crate::types::{PoiArtifactCachePhase, PoiArtifactManifestSource, PoiArtifactSourceConfig};

const BLOCKED_SHIELDS_LIST_KEY_FIELD: &str = "blocked_shields.list_key";
const ENTRY_LIST_KEY_FIELD: &str = "entry.list_key";

static POI_ARTIFACT_CACHE_SYNC_STATE: LazyLock<Mutex<PoiArtifactCacheSyncState>> =
    LazyLock::new(|| Mutex::new(PoiArtifactCacheSyncState::default()));

#[derive(Default)]
struct PoiArtifactCacheSyncState {
    generations: BTreeMap<PathBuf, u64>,
}

impl PoiArtifactCacheSyncState {
    fn lock() -> MutexGuard<'static, Self> {
        POI_ARTIFACT_CACHE_SYNC_STATE
            .lock()
            .expect("POI artifact cache sync lock poisoned")
    }

    fn generation(&mut self, db: &DbStore) -> u64 {
        *self
            .generations
            .entry(db.root_dir().to_path_buf())
            .or_insert(0)
    }

    fn bump_generation(&mut self, db: &DbStore) -> u64 {
        let generation = self
            .generations
            .entry(db.root_dir().to_path_buf())
            .or_insert(0);
        *generation = generation.saturating_add(1);
        *generation
    }
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
        proxy_client: &PoiRpcClient,
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
        for record in &blocked_records {
            verify_blocked_shield(record, &identity.list_key.0)?;
        }
        cache.replace_blocked_shields(&blocked_records)?;
        let blocked_elapsed_ms = blocked_started.elapsed().as_millis();

        let root_started = Instant::now();
        self.report_progress(
            PoiArtifactCachePhase::ValidatingRoots,
            Some(final_index),
            target_index,
        );
        verify_manifest_root(&mut cache, &entry)?;
        if !cache.validate_roots(proxy_client).await? {
            return Err(PoiArtifactError::RootRejected);
        }
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
            cache,
            entry,
            cache_generation,
        })
    }

    pub(crate) async fn refresh_persisted_cache_with_proxy(
        &self,
        db: &DbStore,
        identity: PoiCacheIdentity,
        now: SystemTime,
        proxy_client: Option<&PoiRpcClient>,
    ) -> Result<PoiArtifactRefresh, PoiArtifactError> {
        let load_started = Instant::now();
        let persisted = load_persisted_cache(db, &identity)?;
        let load_persisted_elapsed_ms = load_started.elapsed().as_millis();
        self.refresh_persisted_cache_with_preloaded_and_proxy(
            db,
            identity,
            persisted,
            load_persisted_elapsed_ms,
            now,
            proxy_client,
        )
        .await
    }

    pub(crate) async fn refresh_persisted_cache_with_optional_preloaded_and_proxy(
        &self,
        db: &DbStore,
        identity: PoiCacheIdentity,
        preloaded: Option<PersistedPoiArtifactCache>,
        now: SystemTime,
        proxy_client: Option<&PoiRpcClient>,
    ) -> Result<PoiArtifactRefresh, PoiArtifactError> {
        if let Some(preloaded) = preloaded {
            self.refresh_persisted_cache_with_preloaded_and_proxy(
                db,
                identity,
                Some(preloaded),
                0,
                now,
                proxy_client,
            )
            .await
        } else {
            self.refresh_persisted_cache_with_proxy(db, identity, now, proxy_client)
                .await
        }
    }

    pub(crate) async fn refresh_persisted_cache_with_preloaded_and_proxy(
        &self,
        db: &DbStore,
        identity: PoiCacheIdentity,
        persisted: Option<PersistedPoiArtifactCache>,
        load_persisted_elapsed_ms: u128,
        now: SystemTime,
        proxy_client: Option<&PoiRpcClient>,
    ) -> Result<PoiArtifactRefresh, PoiArtifactError> {
        let started = Instant::now();
        let last_sequence = persisted
            .as_ref()
            .map(|persisted| persisted.record.last_accepted_manifest_sequence);
        let cache_generation = persisted.as_ref().map_or_else(
            || {
                let mut state = PoiArtifactCacheSyncState::lock();
                state.generation(db)
            },
            |persisted| persisted.cache_generation,
        );
        let refresh_started = Instant::now();
        let refresh = self
            .refresh_verified_cache(
                identity.clone(),
                persisted,
                last_sequence,
                now,
                proxy_client,
                cache_generation,
            )
            .await?;
        let refresh_elapsed_ms = refresh_started.elapsed().as_millis();
        let persist_started = Instant::now();
        persist_refresh(db, refresh.identity(), &refresh)?;
        let persist_elapsed_ms = persist_started.elapsed().as_millis();
        debug!(
            chain_id = identity.chain_id,
            list_key = %hex::encode(identity.list_key),
            manifest_sequence = refresh.manifest_sequence,
            load_persisted_elapsed_ms,
            refresh_elapsed_ms,
            persist_elapsed_ms,
            elapsed_ms = started.elapsed().as_millis(),
            "persisted POI artifact cache refresh complete"
        );
        Ok(refresh)
    }

    async fn refresh_verified_cache(
        &self,
        identity: PoiCacheIdentity,
        persisted: Option<PersistedPoiArtifactCache>,
        last_accepted_sequence: Option<u64>,
        now: SystemTime,
        proxy_client: Option<&PoiRpcClient>,
        cache_generation: u64,
    ) -> Result<PoiArtifactRefresh, PoiArtifactError> {
        self.report_progress(PoiArtifactCachePhase::FetchingManifest, None, None);
        let manifest = self.fetch_manifest(last_accepted_sequence, now).await?;
        let entry = manifest_entry_for_identity(&manifest, &identity)?.clone();

        if let Some(persisted) = persisted.as_ref()
            && let Some(refresh) = try_reuse_matching_tip(
                &identity,
                manifest.sequence,
                &entry,
                persisted,
                cache_generation,
            )?
        {
            return Ok(refresh);
        }

        let proxy_client = proxy_client.ok_or(PoiArtifactError::RootValidationUnavailable)?;

        if let Some(persisted) = persisted {
            if let Some(refresh) = self
                .try_incremental_refresh(
                    &identity,
                    manifest.sequence,
                    &entry,
                    &persisted,
                    proxy_client,
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
                    proxy_client,
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

        self.fetch_verified_cache_from_entry(
            identity,
            manifest.sequence,
            entry,
            proxy_client,
            cache_generation,
        )
        .await
    }

    async fn try_incremental_refresh(
        &self,
        identity: &PoiCacheIdentity,
        manifest_sequence: u64,
        entry: &ManifestEntry,
        persisted: &PersistedPoiArtifactCache,
        proxy_client: &PoiRpcClient,
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
            for record in &blocked_records {
                verify_blocked_shield(record, &identity.list_key.0)?;
            }
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
        if !cache.validate_roots(proxy_client).await? {
            return Err(PoiArtifactError::RootRejected);
        }
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
        }))
    }

    async fn try_artifact_suffix_merge(
        &self,
        identity: &PoiCacheIdentity,
        manifest_sequence: u64,
        entry: &ManifestEntry,
        persisted: &PersistedPoiArtifactCache,
        proxy_client: &PoiRpcClient,
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
        if !cache
            .validate_roots(proxy_client)
            .await
            .map_err(PoiArtifactError::from)?
        {
            return Err(PoiArtifactError::RootRejected.into());
        }
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
        for record in &blocked_records {
            verify_blocked_shield(record, &identity.list_key.0)?;
        }
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
}

impl PoiArtifactRefresh {
    fn identity(&self) -> &PoiCacheIdentity {
        self.cache.identity()
    }
}

pub(crate) struct PersistedPoiArtifactCache {
    pub(crate) record: PoiArtifactCacheRecord,
    pub(crate) cache: PoiCache,
    pub(crate) cache_generation: u64,
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
    #[error("POI artifact root validation requires a POI RPC client")]
    RootValidationUnavailable,
    #[error("POI artifact roots were rejected by the POI RPC")]
    RootRejected,
    #[error("manifest sequence rollback: previous={previous}, received={received}")]
    ManifestSequenceRollback { previous: u64, received: u64 },
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

pub(crate) fn load_persisted_cache(
    db: &DbStore,
    identity: &PoiCacheIdentity,
) -> Result<Option<PersistedPoiArtifactCache>, PoiArtifactError> {
    let mut state = PoiArtifactCacheSyncState::lock();
    let cache_generation = state.generation(db);
    let Some(record) = db.get_poi_artifact_cache(
        identity.chain_type,
        identity.chain_id,
        &identity.txid_version,
        &identity.list_key,
    )?
    else {
        return Ok(None);
    };
    let cache = PoiCache::from_bytes(&record.cache_payload, identity)?;
    Ok(Some(PersistedPoiArtifactCache {
        record,
        cache,
        cache_generation,
    }))
}

pub(crate) fn persist_refresh(
    db: &DbStore,
    identity: &PoiCacheIdentity,
    refresh: &PoiArtifactRefresh,
) -> Result<(), PoiArtifactError> {
    let cache_payload = refresh.cache.to_bytes()?;
    let record = PoiArtifactCacheRecord {
        chain_type: identity.chain_type,
        chain_id: identity.chain_id,
        txid_version: identity.txid_version.clone(),
        list_key: identity.list_key,
        last_accepted_manifest_sequence: refresh.manifest_sequence,
        base_descriptor: descriptor_record(&refresh.entry.base),
        applied_delta_descriptors: refresh.entry.deltas.iter().map(descriptor_record).collect(),
        blocked_shields_descriptor: descriptor_record(&refresh.entry.blocked_shields),
        current_tip_index: refresh.entry.current_tip_index,
        current_tip_root: refresh.entry.current_tip_merkleroot,
        cache_payload,
        updated_at: 0,
    };
    let mut state = PoiArtifactCacheSyncState::lock();
    let current_generation = state.generation(db);
    if refresh.cache_generation != current_generation {
        return Err(PoiArtifactError::StalePublicCacheGeneration {
            expected: current_generation,
            actual: refresh.cache_generation,
        });
    }
    db.put_poi_artifact_cache(&record)?;
    Ok(())
}

fn validate_manifest_sequence(
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
        .map(|record| record.into_signed_blocked_shield())
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

fn try_reuse_matching_tip(
    identity: &PoiCacheIdentity,
    manifest_sequence: u64,
    entry: &ManifestEntry,
    persisted: &PersistedPoiArtifactCache,
    cache_generation: u64,
) -> Result<Option<PoiArtifactRefresh>, PoiArtifactError> {
    let entry_tip_root = entry.current_tip_merkleroot;
    if persisted.record.current_tip_index == entry.current_tip_index
        && persisted.record.current_tip_root == entry_tip_root
        && descriptor_matches_record(
            &entry.blocked_shields,
            &persisted.record.blocked_shields_descriptor,
        )
    {
        debug!(
            chain_id = identity.chain_id,
            list_key = %hex::encode(identity.list_key),
            manifest_sequence,
            tip_index = entry.current_tip_index,
            "reusing persisted POI artifact cache with matching manifest tip root"
        );
        return Ok(Some(PoiArtifactRefresh {
            manifest_sequence,
            cache: persisted.cache.clone(),
            entry: entry.clone(),
            cache_generation,
        }));
    }
    Ok(None)
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

pub(crate) fn clear_poi_artifact_cache_for_reset(db: &DbStore) -> Result<u64, local_db::DbError> {
    let mut state = PoiArtifactCacheSyncState::lock();
    state.bump_generation(db);
    db.clear_poi_artifact_cache()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::io::{Read, Write};
    use std::net::TcpListener;
    use std::sync::mpsc::{self, Receiver};

    use cid::Cid;
    use ed25519_dalek::{Signer, SigningKey};
    use local_db::DbConfig;
    use multihash_codetable::{Code, MultihashDigest};
    use poi::artifacts::{
        SnapshotEvent, SnapshotHeader, SnapshotHeaderInput, SnapshotWriter, snapshot::format,
    };
    use poi::poi::{PoiEventType, PoiStatus, PoiSyncedListEvent, SignedPoiEvent};
    use serde_json::json;

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
        let proxy = spawn_json_rpc(vec![json_rpc_result(true)]);
        let client = PoiRpcClient::new(proxy.url.clone());
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

        let refresh = ingestor
            .try_artifact_suffix_merge(
                &identity,
                5,
                &entry,
                &persisted,
                &client,
                persisted.cache_generation,
            )
            .await
            .expect("artifact suffix merge")
            .expect("merge result");

        assert_eq!(refresh.manifest_sequence, 5);
        assert_eq!(refresh.entry.current_tip_index, 2);
        assert_eq!(refresh.cache.progress().next_event_index, 3);
        assert_eq!(root_for_tip(&mut refresh.cache.clone(), 2), root_2);
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
        let proxy = spawn_json_rpc(vec![json_rpc_result(true)]);
        let client = PoiRpcClient::new(proxy.url.clone());
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

        let refresh = ingestor
            .try_artifact_suffix_merge(
                &identity,
                5,
                &entry,
                &persisted,
                &client,
                persisted.cache_generation,
            )
            .await
            .expect("artifact suffix merge")
            .expect("merge result");

        assert_eq!(refresh.cache.progress().next_event_index, 4);
        assert_eq!(root_for_tip(&mut refresh.cache.clone(), 3), root_3);
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
        let proxy = spawn_json_rpc(vec![json_rpc_result(true)]);
        let client = PoiRpcClient::new(proxy.url.clone());
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
            .try_artifact_suffix_merge(
                &identity,
                5,
                &entry,
                &persisted,
                &client,
                persisted.cache_generation,
            )
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
        let client = PoiRpcClient::new(proxy.url.clone());
        let ingestor = manifest_ingestor(
            &signing_key,
            PoiArtifactManifestSource::Url(proxy.url.clone()),
            Vec::new(),
            None,
        );
        let entry = test_entry(&identity, artifact_tip_index, artifact_tip_root.0);
        let persisted = persisted_cache(&identity, cache, local_tip_index, local_root, &entry);

        let refresh = ingestor
            .try_artifact_suffix_merge(
                &identity,
                5,
                &entry,
                &persisted,
                &client,
                persisted.cache_generation,
            )
            .await
            .expect("artifact suffix merge decision");

        assert!(refresh.is_none());
    }

    #[tokio::test]
    async fn artifact_suffix_merge_skips_when_proxy_root_disagrees() {
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
        let proxy = spawn_json_rpc(vec![json_rpc_result(false)]);
        let client = PoiRpcClient::new(proxy.url.clone());
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

        let error = match ingestor
            .try_artifact_suffix_merge(
                &identity,
                5,
                &entry,
                &persisted,
                &client,
                persisted.cache_generation,
            )
            .await
        {
            Ok(_) => panic!("root validation should fail"),
            Err(error) => error,
        };

        assert!(matches!(
            error,
            ArtifactSuffixMergeError::Artifact(PoiArtifactError::RootRejected)
        ));
    }

    #[tokio::test]
    async fn artifact_suffix_merge_reports_proxy_request_failure_for_fallback() {
        let signing_key = SigningKey::from_bytes(&[15_u8; 32]);
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
        let proxy = spawn_status_server(500, Vec::new());
        let client = PoiRpcClient::new(proxy.url.clone());
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

        let error = match ingestor
            .try_artifact_suffix_merge(
                &identity,
                5,
                &entry,
                &persisted,
                &client,
                persisted.cache_generation,
            )
            .await
        {
            Ok(_) => panic!("proxy request failure"),
            Err(error) => error,
        };

        assert!(matches!(
            error,
            ArtifactSuffixMergeError::Artifact(PoiArtifactError::Cache(PoiCacheError::Rpc(
                poi::error::PoiRpcError::HttpStatus { .. }
            )))
        ));
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

    #[test]
    fn stale_poi_artifact_refresh_cannot_repopulate_after_reset() {
        let root_dir = temp_db_root("stale-poi-refresh-after-reset");
        let db = DbStore::open(DbConfig {
            root_dir: root_dir.clone(),
        })
        .expect("open db");
        let identity = test_identity();
        let cache = PoiCache::new(identity.clone());
        let entry = test_entry(&identity, 0, [0_u8; 32]);
        let persisted = persisted_cache(&identity, cache, 0, FixedBytes::ZERO, &entry);
        db.put_poi_artifact_cache(&persisted.record)
            .expect("store initial POI artifact cache");
        let loaded = load_persisted_cache(&db, &identity)
            .expect("load persisted cache")
            .expect("persisted cache exists");
        let refresh = PoiArtifactRefresh {
            manifest_sequence: 5,
            cache: loaded.cache.clone(),
            entry: entry.clone(),
            cache_generation: loaded.cache_generation,
        };

        let removed = clear_poi_artifact_cache_for_reset(&db).expect("reset POI artifact cache");
        let error = persist_refresh(&db, &identity, &refresh)
            .expect_err("stale refresh must not repopulate after reset");

        assert_eq!(removed, 1);
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
        fs::remove_dir_all(root_dir).expect("remove temp db dir");
    }

    #[test]
    fn blocked_shield_artifact_scope_and_signatures_are_verified() {
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
                "0x3333333333333333333333333333333333333333333333333333333333333333"
                    .to_string(),
            block_reason: None,
            signature: "d6af83166868a93f3f3702f30ccf36a343193613925c3817752339b938eba3c6796adf2652544be5c0fc027025c889340fcdd3762313a66398f970d37a67ae03"
                .to_string(),
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
        for record in &records {
            verify_blocked_shield(record, &list_key).expect("valid blocked-shield signature");
        }

        assert_eq!(records.len(), 1);
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
                last_accepted_manifest_sequence: 4,
                base_descriptor: descriptor_record(&descriptor("old-base")),
                applied_delta_descriptors: Vec::new(),
                blocked_shields_descriptor: descriptor_record(&entry.blocked_shields),
                current_tip_index,
                current_tip_root,
                cache_payload: cache.to_bytes().expect("cache bytes"),
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

    fn json_rpc_result<T: serde::Serialize>(result: T) -> Vec<u8> {
        serde_json::to_vec(&json!({
            "jsonrpc": "2.0",
            "id": 1,
            "result": result,
        }))
        .expect("JSON-RPC response")
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
            24..=0xff => out.extend_from_slice(&[major | 24, u8::try_from(len).expect("u8 len")]),
            0x100..=0xffff => {
                out.push(major | 25);
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
