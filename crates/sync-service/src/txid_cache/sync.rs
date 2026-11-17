use super::sync_session::{TxidSyncRequest, TxidSyncSession};
use super::validated::TxidPublicLocalLatestStatus;
use super::{
    DbStore, FixedBytes, IndexedArtifactSourceConfig, IndexedRailgunTransaction, NonZeroUsize,
    QuickSyncClient, TXID_CACHE_BLOB_KIND, TXID_CACHE_PAGE_SIZE, TXID_CACHE_SYNC_LOCK,
    TxidPublicCache, TxidPublicCacheError, TxidPublicCacheKey, TxidPublicCacheManifest,
    TxidPublicCachePage, TxidPublicCacheReadScope, TxidPublicCacheReset, TxidPublicCacheSyncState,
    TxidPublicCacheWritePermit, TxidPublicLatestValidated, Url, artifact, debug, info,
    rebuild_index_for_manifest, update_index_for_page, warn,
};
#[derive(Debug, thiserror::Error)]
#[error("{error}")]
pub(crate) struct TxidPublicCacheResetFailure {
    pub(crate) reset: TxidPublicCacheReset,
    #[source]
    pub(crate) error: TxidPublicCacheError,
}

pub(crate) async fn reset_txid_public_cache(
    db: &DbStore,
) -> Result<TxidPublicCacheReset, TxidPublicCacheResetFailure> {
    let mut reset = TxidPublicCacheReset {
        blob_entries_removed: 0,
    };
    db.ensure_blob_kind_purge_supported(TXID_CACHE_BLOB_KIND)
        .map_err(|error| TxidPublicCacheResetFailure {
            reset,
            error: error.into(),
        })?;
    let _guard = TXID_CACHE_SYNC_LOCK.lock().await;
    TxidPublicCacheSyncState::lock().bump_generation(db);
    reset.blob_entries_removed =
        db.clear_blob_meta_kind(TXID_CACHE_BLOB_KIND)
            .map_err(|error| TxidPublicCacheResetFailure {
                reset,
                error: error.into(),
            })?;
    db.purge_blob_kind(TXID_CACHE_BLOB_KIND)
        .map_err(|error| TxidPublicCacheResetFailure {
            reset,
            error: error.into(),
        })?;
    Ok(reset)
}

impl TxidPublicCache<'_> {
    pub(crate) async fn sync_with_artifact_source_maintained(
        &self,
        endpoint: Option<&Url>,
        http_client: Option<&reqwest::Client>,
        latest: TxidPublicLatestValidated,
        indexed_artifact_source: Option<&IndexedArtifactSourceConfig>,
        maintenance_scheduler: &crate::indexed_artifacts::IndexedArtifactMaintenanceScheduler,
        maintenance_db: std::sync::Arc<DbStore>,
    ) -> Result<(), TxidPublicCacheError> {
        let maintenance = self
            .sync_with_artifact_source_plan(endpoint, http_client, latest, indexed_artifact_source)
            .await?;
        if let Some(maintenance) = maintenance {
            self.schedule_artifact_maintenance(maintenance_scheduler, &maintenance_db, maintenance);
        }
        Ok(())
    }

    async fn sync_with_artifact_source_plan(
        &self,
        endpoint: Option<&Url>,
        http_client: Option<&reqwest::Client>,
        latest: TxidPublicLatestValidated,
        indexed_artifact_source: Option<&IndexedArtifactSourceConfig>,
    ) -> Result<Option<artifact::TxidPublicArtifactMaintenance>, TxidPublicCacheError> {
        let artifact_provenance_required = indexed_artifact_source.is_some() && endpoint.is_none();
        let Some(start) = self
            .prepare_artifact_sync(latest, artifact_provenance_required)
            .await?
        else {
            return Ok(None);
        };
        let fetched = match indexed_artifact_source {
            Some(config) => Some(
                self.fetch_artifact_plan(
                    config,
                    http_client,
                    start.from_index,
                    Some(latest.txid_index),
                )
                .await,
            ),
            None => None,
        };
        let artifact_plan = match fetched {
            Some(Ok(plan)) => Some(plan),
            Some(Err(_err)) if endpoint.is_some() => {
                warn!(
                    chain_id = self.key.chain_id,
                    txid_version = self.key.txid_version,
                    category = "artifact_source_unavailable",
                    "TXID public cache artifact source unavailable; continuing with the configured source"
                );
                None
            }
            Some(Err(err)) => return Err(err),
            None => None,
        };

        self.sync_inner(TxidSyncRequest {
            endpoint,
            http_client,
            latest,
            artifact_chunks: artifact_plan.as_ref().map(|plan| plan.required.as_slice()),
            force_validated_refresh: start.force_validated_refresh,
            read_scope: start.read_scope,
            indexed_artifact_source_configured: indexed_artifact_source.is_some(),
            artifact_start_index: Some(start.from_index),
        })
        .await?;
        Ok(artifact_plan.map(|plan| {
            artifact::TxidPublicArtifactMaintenance::new(plan.stable_current, start.read_scope)
        }))
    }

    /// Reconciles the manifest with `latest` under a write permit, which is
    /// released before returning so the artifact fetch runs without it. Returns
    /// `None` when the cache already covers `latest`.
    async fn prepare_artifact_sync(
        &self,
        latest: TxidPublicLatestValidated,
        artifact_provenance_required: bool,
    ) -> Result<Option<ArtifactSyncStart>, TxidPublicCacheError> {
        let permit = self.begin_write().await;
        let read_scope = permit.scope();
        let cache = permit.cache();
        let mut manifest = cache.load_or_new_manifest()?;
        let (progress_reconciled, local_status) =
            manifest.reconcile_markers_with_latest(&permit, latest)?;
        let force_validated_refresh = local_status
            == TxidPublicLocalLatestStatus::NeedsValidatedRefresh
            || (progress_reconciled && manifest.validated_cached_txid_index.is_none());
        let already_covered = local_status == TxidPublicLocalLatestStatus::Satisfied
            && (!artifact_provenance_required || manifest.artifact_covers_latest(latest));
        if already_covered {
            manifest.commit_covered_latest(&permit, latest, progress_reconciled)?;
            debug!(
                chain_id = self.key.chain_id,
                txid_version = self.key.txid_version,
                latest_validated_txid_index = latest.txid_index,
                "TXID public cache already covers latest validated range"
            );
            return Ok(None);
        }
        let from_index = if force_validated_refresh && manifest.artifact_cached_txid_index.is_none()
        {
            0
        } else {
            manifest.artifact_fetch_start_index(latest, local_status)
        };
        Ok(Some(ArtifactSyncStart {
            from_index,
            force_validated_refresh,
            read_scope,
        }))
    }

    /// Builds the artifact source and fetches the chunks from `from_index` on.
    async fn fetch_artifact_plan(
        &self,
        config: &IndexedArtifactSourceConfig,
        http_client: Option<&reqwest::Client>,
        from_index: u64,
        to_index: Option<u64>,
    ) -> Result<artifact::TxidPublicArtifactChunkPlan, TxidPublicCacheError> {
        self.artifact_source(config, http_client)?
            .fetch_current_chunks(self, from_index, to_index)
            .await
    }

    async fn sync_inner(&self, request: TxidSyncRequest<'_>) -> Result<(), TxidPublicCacheError> {
        let permit = self.begin_write_for_scope(request.read_scope).await?;
        let started = std::time::Instant::now();
        let mut session = TxidSyncSession::new(self.key, &permit, &request)?;
        let Some(local_status) = session.reconcile_and_finish_if_covered()? else {
            return Ok(());
        };
        session.apply_artifact_chunks(
            request.artifact_chunks,
            request.artifact_start_index,
            local_status,
        )?;
        let refresh = session.refresh_from_graphql().await?;
        session.finish(refresh, started)
    }

    pub(crate) async fn sync_to_graph_tip(
        &self,
        endpoint: &Url,
        http_client: Option<&reqwest::Client>,
    ) -> Result<u64, TxidPublicCacheError> {
        let permit = self.begin_write().await;
        let started = std::time::Instant::now();
        let cache = permit.cache();
        let mut manifest = cache.load_or_new_manifest()?;
        let client = match http_client.cloned() {
            Some(http_client) => QuickSyncClient::with_http_client(endpoint.clone(), http_client),
            None => QuickSyncClient::new(endpoint.clone()),
        };

        if manifest.next_txid_index > i32::MAX as u64 {
            return Err(TxidPublicCacheError::Sync(
                merkletree::errors::SyncError::UnexpectedFormat(format!(
                    "public TXID page offset {} exceeds GraphQL Int max {}",
                    manifest.next_txid_index,
                    i32::MAX
                )),
            ));
        }
        manifest.validate_exact_append_start(&permit)?;
        let mut fetched_rows = 0_u64;
        loop {
            let start_index = manifest.next_txid_index;
            let page_started = std::time::Instant::now();
            let rows = client
                .fetch_public_txid_page(start_index, TXID_CACHE_PAGE_SIZE)
                .await?;
            if rows.is_empty() {
                break;
            }
            if rows.len() > TXID_CACHE_PAGE_SIZE.get() {
                return Err(TxidPublicCacheError::MetadataMismatch(
                    "Squid TXID page exceeded the requested page size".to_string(),
                ));
            }
            let row_count = u64::try_from(rows.len()).map_err(|_| {
                TxidPublicCacheError::MetadataMismatch("TXID page row count overflows".to_string())
            })?;
            let page = TxidPublicCachePage::from_indexed_transactions(self.key, start_index, rows);
            manifest.append_page_after_prefix_validation(&permit, &page)?;
            update_index_for_page(&permit, &page)?;
            fetched_rows = fetched_rows.saturating_add(row_count);
            debug!(
                chain_id = self.key.chain_id,
                start_index,
                row_count,
                next_txid_index = manifest.next_txid_index,
                fetched_rows,
                page_elapsed_ms = page_started.elapsed().as_millis(),
                "TXID public cache background page fetched"
            );
            if row_count < TXID_CACHE_PAGE_SIZE.get() as u64 {
                break;
            }
        }

        rebuild_index_for_manifest(&manifest, &permit)?;

        manifest.write_to(&permit)?;
        debug!(
            chain_id = self.key.chain_id,
            txid_version = self.key.txid_version,
            next_txid_index = manifest.next_txid_index,
            fetched_rows,
            elapsed_ms = started.elapsed().as_millis(),
            "TXID public cache background sync complete"
        );
        Ok(fetched_rows)
    }

    pub(crate) async fn sync_to_indexed_tip_maintained(
        &self,
        endpoint: Option<&Url>,
        http_client: Option<&reqwest::Client>,
        indexed_artifact_source: Option<&IndexedArtifactSourceConfig>,
        maintenance_scheduler: &crate::indexed_artifacts::IndexedArtifactMaintenanceScheduler,
        maintenance_db: std::sync::Arc<DbStore>,
    ) -> Result<u64, TxidPublicCacheError> {
        let (fetched_rows, maintenance) = self
            .sync_to_indexed_tip_plan(endpoint, http_client, indexed_artifact_source)
            .await?;
        if let Some(maintenance) = maintenance {
            self.schedule_artifact_maintenance(maintenance_scheduler, &maintenance_db, maintenance);
        }
        Ok(fetched_rows)
    }

    async fn sync_to_indexed_tip_plan(
        &self,
        endpoint: Option<&Url>,
        http_client: Option<&reqwest::Client>,
        indexed_artifact_source: Option<&IndexedArtifactSourceConfig>,
    ) -> Result<(u64, Option<artifact::TxidPublicArtifactMaintenance>), TxidPublicCacheError> {
        let mut maintenance_after_graphql = None;
        if let Some(config) = indexed_artifact_source {
            match self
                .background_artifact_sync(config, endpoint.is_some(), http_client)
                .await?
            {
                BackgroundArtifactSync::Done(applied_rows, maintenance) => {
                    return Ok((applied_rows, Some(maintenance)));
                }
                BackgroundArtifactSync::FallBackToGraphql(maintenance) => {
                    maintenance_after_graphql = maintenance;
                }
            }
        }

        let fetched_rows = match endpoint {
            Some(endpoint) => self.sync_to_graph_tip(endpoint, http_client).await?,
            None => 0,
        };
        Ok((fetched_rows, maintenance_after_graphql))
    }

    /// Applies the artifact chunks past the cached artifact marker. GraphQL
    /// continues the sync when an endpoint is configured and the artifacts
    /// added nothing to a cache that had no artifact marker yet, or failed.
    async fn background_artifact_sync(
        &self,
        config: &IndexedArtifactSourceConfig,
        endpoint_available: bool,
        http_client: Option<&reqwest::Client>,
    ) -> Result<BackgroundArtifactSync, TxidPublicCacheError> {
        let (read_scope, from_index, artifact_marker) = {
            let permit = self.begin_write().await;
            let read_scope = permit.scope();
            let manifest = permit.cache().load_or_new_manifest()?;
            let artifact_marker = manifest.artifact_cached_txid_index;
            let from_index = artifact_marker.map_or(0, |index| index.saturating_add(1));
            (read_scope, from_index, artifact_marker)
        };
        let plan = match self
            .fetch_artifact_plan(config, http_client, from_index, None)
            .await
        {
            Ok(plan) => plan,
            Err(_err) if endpoint_available => {
                warn!(
                    chain_id = self.key.chain_id,
                    txid_version = self.key.txid_version,
                    category = "artifact_source_unavailable",
                    "TXID public cache background artifact source unavailable; falling back to GraphQL"
                );
                return Ok(BackgroundArtifactSync::FallBackToGraphql(None));
            }
            Err(err) => return Err(err),
        };
        let maintenance =
            artifact::TxidPublicArtifactMaintenance::new(plan.stable_current, read_scope);
        let graphql_needed = endpoint_available && artifact_marker.is_none();
        if plan.required.is_empty() {
            return Ok(BackgroundArtifactSync::without_progress(
                maintenance,
                graphql_needed,
            ));
        }
        match self
            .apply_artifact_chunks_only(&plan.required, from_index, read_scope)
            .await
        {
            Ok(applied_rows) if applied_rows > 0 => {
                Ok(BackgroundArtifactSync::Done(applied_rows, maintenance))
            }
            Ok(_) => Ok(BackgroundArtifactSync::without_progress(
                maintenance,
                graphql_needed,
            )),
            Err(err) if endpoint_available => {
                warn!(
                    ?err,
                    chain_id = self.key.chain_id,
                    txid_version = self.key.txid_version,
                    category = "artifact_source_unavailable",
                    "TXID public cache background artifact apply unavailable; falling back to GraphQL"
                );
                Ok(BackgroundArtifactSync::FallBackToGraphql(Some(maintenance)))
            }
            Err(err) => Err(err),
        }
    }

    pub(crate) fn cached_latest_validated(
        &self,
    ) -> Result<Option<TxidPublicLatestValidated>, TxidPublicCacheError> {
        let Some(manifest) = self.load_manifest()? else {
            return Ok(None);
        };
        manifest.validate_for(self.key)?;
        let Some(txid_index) = manifest.latest_validated_txid_index else {
            return Ok(None);
        };
        let latest = TxidPublicLatestValidated {
            txid_index,
            merkleroot: manifest.latest_validated_merkleroot,
        };
        match manifest.local_latest_status(self.db, latest)? {
            TxidPublicLocalLatestStatus::Satisfied => Ok(Some(latest)),
            TxidPublicLocalLatestStatus::NeedsRows
            | TxidPublicLocalLatestStatus::NeedsValidatedRefresh => Ok(None),
        }
    }

    fn artifact_source(
        &self,
        config: &IndexedArtifactSourceConfig,
        http_client: Option<&reqwest::Client>,
    ) -> Result<artifact::TxidPublicArtifactSource, TxidPublicCacheError> {
        let scope = self.key.artifact_scope()?;
        Ok(artifact::TxidPublicArtifactSource::new(
            config,
            http_client,
            scope,
            self.key.txid_version,
        ))
    }

    fn schedule_artifact_maintenance(
        &self,
        scheduler: &crate::indexed_artifacts::IndexedArtifactMaintenanceScheduler,
        db: &std::sync::Arc<DbStore>,
        mut maintenance: artifact::TxidPublicArtifactMaintenance,
    ) {
        let chain_type = self.key.chain_type;
        let chain_id = self.key.chain_id;
        let railgun_contract = self.key.railgun_contract;
        let txid_version = self.key.txid_version.to_string();
        let read_scope = maintenance.read_scope();
        for chunk in maintenance.take_stable_current() {
            let scheduler_key = crate::indexed_artifacts::IndexedArtifactMaintenanceKey::txid_chunk(
                &chunk.descriptor,
                &txid_version,
                read_scope.generation(),
            );
            let retained_payload_bytes = chunk.bytes.len() as u64;
            let chunk_cid = chunk.descriptor.cid.clone();
            let maintenance_db = std::sync::Arc::clone(db);
            let maintenance_txid_version = txid_version.clone();
            let admission =
                scheduler.try_schedule(scheduler_key, retained_payload_bytes, async move {
                    let key = TxidPublicCacheKey {
                        chain_type,
                        chain_id,
                        railgun_contract,
                        txid_version: &maintenance_txid_version,
                    };
                    let cache = TxidPublicCache::new(maintenance_db.as_ref(), key);
                    artifact::TxidPublicArtifactMaintenance::retain_stable_chunk(
                        &cache, chunk, read_scope,
                    )
                    .await;
                });
            if admission != crate::indexed_artifacts::IndexedArtifactMaintenanceAdmission::Admitted
            {
                debug!(
                    ?admission,
                    chain_id,
                    txid_version = self.key.txid_version,
                    cid = %chunk_cid,
                    "stable public TXID artifact maintenance was not admitted"
                );
            }
        }
    }

    async fn apply_artifact_chunks_only(
        &self,
        chunks: &[crate::indexed_artifacts::VerifiedIndexedArtifactChunk],
        artifact_start_index: u64,
        read_scope: TxidPublicCacheReadScope,
    ) -> Result<u64, TxidPublicCacheError> {
        let permit = self.begin_write_for_scope(read_scope).await?;
        let mut manifest = permit.cache().load_or_new_manifest()?;
        manifest.apply_artifact_chunks_with_progress_guard(
            &permit,
            chunks,
            None,
            None,
            artifact_start_index,
        )
    }
}

/// Where a foreground artifact sync starts, decided under the write permit.
struct ArtifactSyncStart {
    from_index: u64,
    force_validated_refresh: bool,
    read_scope: TxidPublicCacheReadScope,
}

/// What the background artifact pass leaves for the GraphQL pass.
enum BackgroundArtifactSync {
    /// The artifacts finished this sync; GraphQL is skipped.
    Done(u64, artifact::TxidPublicArtifactMaintenance),
    /// GraphQL runs next; the maintenance, if any, is scheduled after it.
    FallBackToGraphql(Option<artifact::TxidPublicArtifactMaintenance>),
}

impl BackgroundArtifactSync {
    /// The outcome when the artifacts added no rows: GraphQL continues only if it
    /// is needed.
    const fn without_progress(
        maintenance: artifact::TxidPublicArtifactMaintenance,
        graphql_needed: bool,
    ) -> Self {
        if graphql_needed {
            Self::FallBackToGraphql(Some(maintenance))
        } else {
            Self::Done(0, maintenance)
        }
    }
}

impl TxidPublicCacheManifest {
    /// Reconciles the validated markers with `latest`, clears them when local
    /// rows need a validated refresh, and writes the manifest if either changed.
    fn reconcile_markers_with_latest(
        &mut self,
        permit: &TxidPublicCacheWritePermit<'_>,
        latest: TxidPublicLatestValidated,
    ) -> Result<(bool, TxidPublicLocalLatestStatus), TxidPublicCacheError> {
        let progress_reconciled = self.reconcile_validated_progress_for_latest(latest);
        let local_status = self.local_latest_status(permit.db(), latest)?;
        let mut markers_changed = false;
        if progress_reconciled && local_status == TxidPublicLocalLatestStatus::Satisfied {
            self.commit_latest_validated_if_supported(permit.db(), latest)?;
        }
        if local_status == TxidPublicLocalLatestStatus::NeedsValidatedRefresh {
            markers_changed = self.clear_validated_markers_for_latest(latest);
        }
        if progress_reconciled || markers_changed {
            self.write_to(permit)?;
        }
        Ok((progress_reconciled, local_status))
    }

    /// Local rows already cover `latest`: commits its markers again, with the
    /// index rebuilt, when progress was reconciled or the markers disagree.
    fn commit_covered_latest(
        &mut self,
        permit: &TxidPublicCacheWritePermit<'_>,
        latest: TxidPublicLatestValidated,
        progress_reconciled: bool,
    ) -> Result<(), TxidPublicCacheError> {
        let markers_stale = progress_reconciled
            || !self.latest_validated_matches(latest)
            || !self.latest_checkpoint_matches(latest);
        if markers_stale {
            self.commit_latest_validated_if_supported(permit.db(), latest)?;
            rebuild_index_for_manifest(self, permit)?;
            self.write_to(permit)?;
        }
        Ok(())
    }

    fn apply_artifact_chunks_with_progress_guard(
        &mut self,
        permit: &TxidPublicCacheWritePermit<'_>,
        chunks: &[crate::indexed_artifacts::VerifiedIndexedArtifactChunk],
        to_index: Option<u64>,
        latest_validated_merkleroot: Option<FixedBytes<32>>,
        artifact_start_index: u64,
    ) -> Result<u64, TxidPublicCacheError> {
        let key = permit.key();
        let artifact_started = std::time::Instant::now();
        let (artifact_manifest, applied_rows) = self.apply_artifact_chunks_staged(
            permit,
            chunks,
            to_index,
            latest_validated_merkleroot,
            artifact_start_index,
        )?;
        *self = artifact_manifest;
        self.write_to(permit)?;
        if applied_rows > 0 {
            rebuild_index_for_manifest(self, permit)?;
        }
        info!(
            chain_id = key.chain_id,
            txid_version = key.txid_version,
            applied_rows,
            validated_cached_txid_index = ?self.validated_cached_txid_index,
            elapsed_ms = artifact_started.elapsed().as_millis(),
            "TXID public cache artifact chunks applied"
        );
        Ok(applied_rows)
    }

    pub(super) async fn refresh_validated_range(
        &mut self,
        permit: &TxidPublicCacheWritePermit<'_>,
        client: &QuickSyncClient,
        start_index: u64,
        end_index: u64,
        latest_validated_merkleroot: Option<FixedBytes<32>>,
    ) -> Result<(u64, Option<u64>), TxidPublicCacheError> {
        if start_index > self.next_txid_index {
            return Err(TxidPublicCacheError::MissingLeaf {
                index: self.next_txid_index,
            });
        }
        if start_index > end_index {
            return Err(TxidPublicCacheError::MetadataMismatch(
                "TXID public cache validated refresh range is inverted".to_string(),
            ));
        }

        let exact_append = start_index == self.next_txid_index;
        if exact_append {
            self.validate_exact_append_start(permit)?;
        } else {
            self.validate_published_manifest(permit.db())?;
        }

        let mut candidate = (!exact_append).then(|| self.clone());
        if let Some(candidate) = candidate.as_mut() {
            candidate.invalidate_checkpoints_from(start_index);
        }
        let mut next_index = start_index;
        let mut fetched_rows = 0_u64;

        while next_index <= end_index {
            let (rows, row_count) =
                fetch_validated_refresh_page(client, next_index, end_index).await?;
            let page =
                TxidPublicCachePage::from_indexed_transactions(self.cache_key(), next_index, rows);
            if exact_append {
                self.append_page_after_prefix_validation(permit, &page)?;
                update_index_for_page(permit, &page)?;
            } else {
                candidate
                    .as_mut()
                    .expect("corrective TXID refresh has a candidate manifest")
                    .insert_or_replace_staged_page(permit, &page)?;
            }
            fetched_rows = fetched_rows.saturating_add(row_count);
            next_index = next_index.checked_add(row_count).ok_or_else(|| {
                TxidPublicCacheError::MetadataMismatch("TXID refresh index overflow".to_string())
            })?;
        }

        let refreshed_to = next_index.checked_sub(1);
        if let Some(mut candidate) = candidate {
            let refreshed_to = refreshed_to.ok_or_else(|| {
                TxidPublicCacheError::MetadataMismatch(
                    "TXID public cache validated refresh did not fetch any rows".to_string(),
                )
            })?;
            candidate.validated_cached_txid_index = Some(refreshed_to);
            let latest = TxidPublicLatestValidated {
                txid_index: refreshed_to,
                merkleroot: latest_validated_merkleroot,
            };
            let status = candidate.local_latest_status(permit.db(), latest)?;
            if status != TxidPublicLocalLatestStatus::Satisfied {
                return Err(candidate.unsupported_latest_error(latest, status, true));
            }
            *self = candidate;
        }
        Ok((fetched_rows, refreshed_to))
    }

    pub(super) fn apply_artifact_chunks_staged(
        &self,
        permit: &TxidPublicCacheWritePermit<'_>,
        chunks: &[crate::indexed_artifacts::VerifiedIndexedArtifactChunk],
        to_index: Option<u64>,
        latest_validated_merkleroot: Option<FixedBytes<32>>,
        artifact_start_index: u64,
    ) -> Result<(Self, u64), TxidPublicCacheError> {
        let mut artifact_manifest = self.clone();
        let applied_rows = artifact_manifest.apply_artifact_chunks_bounded(
            permit,
            chunks,
            to_index,
            latest_validated_merkleroot,
            artifact_start_index,
        )?;
        Ok((artifact_manifest, applied_rows))
    }
}

/// Fetches the next page of a validated refresh. Each page must be full: an
/// empty or short page means the indexer has not reached `end_index` yet.
async fn fetch_validated_refresh_page(
    client: &QuickSyncClient,
    next_index: u64,
    end_index: u64,
) -> Result<(Vec<IndexedRailgunTransaction>, u64), TxidPublicCacheError> {
    let remaining = end_index.saturating_sub(next_index).saturating_add(1);
    let limit = NonZeroUsize::new(remaining.min(TXID_CACHE_PAGE_SIZE.get() as u64) as usize)
        .expect("validated TXID refresh limit is non-zero");
    let rows = client.fetch_public_txid_page(next_index, limit).await?;
    if rows.is_empty() {
        return Err(TxidPublicCacheError::CacheNotReady {
            next_index,
            required_index: end_index,
        });
    }
    if rows.len() > limit.get() {
        return Err(TxidPublicCacheError::MetadataMismatch(
            "Squid TXID page exceeded the requested validated range".to_string(),
        ));
    }
    let row_count = u64::try_from(rows.len()).map_err(|_| {
        TxidPublicCacheError::MetadataMismatch("TXID page row count overflows".to_string())
    })?;
    if row_count < limit.get() as u64 {
        return Err(TxidPublicCacheError::CacheNotReady {
            next_index: next_index.saturating_add(row_count),
            required_index: end_index,
        });
    }
    Ok((rows, row_count))
}

#[cfg(test)]
impl TxidPublicCache<'_> {
    pub(super) async fn sync(
        &self,
        endpoint: &Url,
        http_client: Option<&reqwest::Client>,
        latest: TxidPublicLatestValidated,
    ) -> Result<(), TxidPublicCacheError> {
        let permit = self.begin_write().await;
        let read_scope = permit.scope();
        drop(permit);
        self.sync_inner(TxidSyncRequest {
            endpoint: Some(endpoint),
            http_client,
            latest,
            artifact_chunks: None,
            force_validated_refresh: false,
            read_scope,
            indexed_artifact_source_configured: false,
            artifact_start_index: None,
        })
        .await
    }

    pub(super) async fn sync_with_artifact_source(
        &self,
        endpoint: Option<&Url>,
        http_client: Option<&reqwest::Client>,
        latest: TxidPublicLatestValidated,
        indexed_artifact_source: Option<&IndexedArtifactSourceConfig>,
    ) -> Result<(), TxidPublicCacheError> {
        let maintenance = self
            .sync_with_artifact_source_plan(endpoint, http_client, latest, indexed_artifact_source)
            .await?;
        if let Some(maintenance) = maintenance {
            maintenance.run(self).await;
        }
        Ok(())
    }

    pub(super) async fn sync_with_artifact_chunks(
        &self,
        endpoint: &Url,
        http_client: Option<&reqwest::Client>,
        latest: TxidPublicLatestValidated,
        artifact_chunks: Option<&[crate::indexed_artifacts::VerifiedIndexedArtifactChunk]>,
    ) -> Result<(), TxidPublicCacheError> {
        let permit = self.begin_write().await;
        let read_scope = permit.scope();
        drop(permit);
        self.sync_inner(TxidSyncRequest {
            endpoint: Some(endpoint),
            http_client,
            latest,
            artifact_chunks,
            force_validated_refresh: false,
            read_scope,
            indexed_artifact_source_configured: true,
            artifact_start_index: None,
        })
        .await
    }

    pub(super) async fn sync_to_indexed_tip(
        &self,
        endpoint: Option<&Url>,
        http_client: Option<&reqwest::Client>,
        indexed_artifact_source: Option<&IndexedArtifactSourceConfig>,
    ) -> Result<u64, TxidPublicCacheError> {
        let (fetched_rows, maintenance) = self
            .sync_to_indexed_tip_plan(endpoint, http_client, indexed_artifact_source)
            .await?;
        if let Some(maintenance) = maintenance {
            maintenance.run(self).await;
        }
        Ok(fetched_rows)
    }

    pub(super) async fn sync_until_recovered_output_with_page_size(
        &self,
        endpoint: &Url,
        http_client: Option<&reqwest::Client>,
        tx_hash: FixedBytes<32>,
        output_commitment: FixedBytes<32>,
        page_size: NonZeroUsize,
    ) -> Result<super::types::test_support::TxidPublicCachedTransaction, TxidPublicCacheError> {
        use super::proof::test_support::{
            find_public_recovery_transaction_in_manifest, find_target_row_in_page,
        };

        let permit = self.begin_write().await;
        let started = std::time::Instant::now();
        let cache = permit.cache();
        let mut manifest = cache.load_or_new_manifest()?;
        match find_public_recovery_transaction_in_manifest(
            &manifest,
            &permit,
            tx_hash,
            output_commitment,
        ) {
            Ok(row) => return Ok(row.into()),
            Err(TxidPublicCacheError::MissingTarget) => {}
            Err(err) => return Err(err),
        }
        let client = match http_client.cloned() {
            Some(http_client) => QuickSyncClient::with_http_client(endpoint.clone(), http_client),
            None => QuickSyncClient::new(endpoint.clone()),
        };

        let mut next_index = manifest
            .validated_cached_txid_index
            .map_or(0, |index| index.saturating_add(1))
            .min(manifest.next_txid_index);
        if next_index == manifest.next_txid_index {
            manifest.validate_exact_append_start(&permit)?;
        }
        let mut fetched_rows = 0_u64;
        loop {
            let start_index = next_index;
            let rows = client
                .fetch_public_txid_page(start_index, page_size)
                .await?;
            if rows.is_empty() {
                manifest.write_to(&permit)?;
                return Err(TxidPublicCacheError::MissingTarget);
            }
            let row_count = rows.len() as u64;
            let page = TxidPublicCachePage::from_indexed_transactions(self.key, start_index, rows);
            if start_index < manifest.next_txid_index {
                manifest.insert_or_replace_staged_page(&permit, &page)?;
                rebuild_index_for_manifest(&manifest, &permit)?;
            } else {
                manifest.append_page_after_prefix_validation(&permit, &page)?;
                update_index_for_page(&permit, &page)?;
            }
            next_index = start_index.saturating_add(row_count);
            fetched_rows = fetched_rows.saturating_add(row_count);
            manifest.write_to(&permit)?;
            debug!(
                chain_id = self.key.chain_id,
                start_index,
                row_count,
                next_txid_index = manifest.next_txid_index,
                "TXID public cache recovery page synced"
            );

            if let Some(row) =
                find_target_row_in_page(&manifest, &page, tx_hash, output_commitment)?
            {
                info!(
                    chain_id = self.key.chain_id,
                    txid_version = self.key.txid_version,
                    target_txid_index = row.txid_index,
                    fetched_rows,
                    elapsed_ms = started.elapsed().as_millis(),
                    "TXID public cache recovery target synced"
                );
                return Ok(row.into());
            }
            if row_count < page_size.get() as u64 {
                return Err(TxidPublicCacheError::MissingTarget);
            }
        }
    }

    pub(super) async fn put_latest_validated(
        &self,
        latest: TxidPublicLatestValidated,
    ) -> Result<(), TxidPublicCacheError> {
        let permit = self.begin_write().await;
        let mut manifest = permit.cache().load_or_new_manifest()?;
        manifest.set_latest_validated(latest);
        manifest.write_to(&permit)
    }
}
