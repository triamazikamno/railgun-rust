use super::{
    DbStore, DenseMerkleTree, ErrorKind, FixedBytes, IndexedArtifactSourceConfig, NonZeroUsize,
    QuickSyncClient, TREE_LEAF_COUNT, TXID_CACHE_BLOB_KIND, TXID_CACHE_PAGE_SIZE,
    TXID_CACHE_SYNC_LOCK, TxidPublicCache, TxidPublicCacheError, TxidPublicCacheKey,
    TxidPublicCacheManifest, TxidPublicCachePage, TxidPublicCacheReadScope, TxidPublicCacheReset,
    TxidPublicCacheSyncState, TxidPublicCacheWritePermit, TxidPublicLatestValidated, Url, artifact,
    debug, info, read_tree_leaves, rebuild_index_for_manifest, update_index_for_page, warn,
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
        let (artifact_from_index, force_validated_refresh, read_scope) = {
            let permit = self.begin_write().await;
            let read_scope = permit.scope();
            let cache = permit.cache();
            let mut manifest = cache.load_or_new_manifest()?;
            let progress_reconciled = manifest.reconcile_validated_progress_for_latest(latest);
            let local_status = manifest.local_latest_status(permit.db(), latest)?;
            let mut markers_changed = false;
            if progress_reconciled && local_status == TxidPublicLocalLatestStatus::Satisfied {
                manifest.commit_latest_validated_if_supported(permit.db(), latest)?;
            }
            if local_status == TxidPublicLocalLatestStatus::NeedsValidatedRefresh {
                markers_changed = manifest.clear_validated_markers_for_latest(latest);
            }
            if progress_reconciled || markers_changed {
                manifest.write_to(&permit)?;
            }
            let force_validated_refresh = local_status
                == TxidPublicLocalLatestStatus::NeedsValidatedRefresh
                || (progress_reconciled && manifest.validated_cached_txid_index.is_none());
            let artifact_provenance_required =
                indexed_artifact_source.is_some() && endpoint.is_none();
            if local_status == TxidPublicLocalLatestStatus::Satisfied
                && (!artifact_provenance_required || manifest.artifact_covers_latest(latest))
            {
                if progress_reconciled || !manifest.latest_validated_matches(latest) {
                    manifest.commit_latest_validated_if_supported(permit.db(), latest)?;
                    rebuild_index_for_manifest(&manifest, &permit)?;
                    manifest.write_to(&permit)?;
                }
                debug!(
                    chain_id = self.key.chain_id,
                    txid_version = self.key.txid_version,
                    latest_validated_txid_index = latest.txid_index,
                    "TXID public cache already covers latest validated range"
                );
                return Ok(None);
            }
            (
                if force_validated_refresh && manifest.artifact_cached_txid_index.is_none() {
                    0
                } else {
                    manifest.artifact_fetch_start_index(latest, local_status)
                },
                force_validated_refresh,
                read_scope,
            )
        };
        let artifact_fetch = match indexed_artifact_source {
            Some(config) => match self.artifact_source(config, http_client) {
                Ok(source) => match source
                    .fetch_current_chunks(self, artifact_from_index, Some(latest.txid_index))
                    .await
                {
                    Ok(plan) => Some((source, plan)),
                    Err(_err) if endpoint.is_some() => {
                        warn!(
                            chain_id = self.key.chain_id,
                            txid_version = self.key.txid_version,
                            category = "artifact_source_unavailable",
                            "TXID public cache artifact source unavailable; continuing with the configured source"
                        );
                        None
                    }
                    Err(err) => return Err(err),
                },
                Err(_err) if endpoint.is_some() => {
                    warn!(
                        chain_id = self.key.chain_id,
                        txid_version = self.key.txid_version,
                        category = "artifact_source_unavailable",
                        "TXID public cache artifact source unavailable; continuing with the configured source"
                    );
                    None
                }
                Err(err) => return Err(err),
            },
            None => None,
        };
        let artifact_chunk_refs = artifact_fetch
            .as_ref()
            .map(|(_source, plan)| plan.required.as_slice());

        self.sync_inner(
            endpoint,
            http_client,
            latest,
            artifact_chunk_refs,
            force_validated_refresh,
            read_scope,
            indexed_artifact_source.is_some(),
            Some(artifact_from_index),
        )
        .await?;
        Ok(artifact_fetch.map(|(_source, plan)| {
            artifact::TxidPublicArtifactMaintenance::new(plan.stable_current, read_scope)
        }))
    }

    async fn sync_inner(
        &self,
        endpoint: Option<&Url>,
        http_client: Option<&reqwest::Client>,
        latest: TxidPublicLatestValidated,
        artifact_chunks: Option<&[crate::indexed_artifacts::VerifiedIndexedArtifactChunk]>,
        force_validated_refresh: bool,
        read_scope: TxidPublicCacheReadScope,
        indexed_artifact_source_configured: bool,
        artifact_start_index: Option<u64>,
    ) -> Result<(), TxidPublicCacheError> {
        let permit = self.begin_write_for_scope(read_scope).await?;
        let started = std::time::Instant::now();
        let cache = permit.cache();
        let mut manifest = cache.load_or_new_manifest()?;
        let artifact_provenance_required = indexed_artifact_source_configured && endpoint.is_none();
        let progress_reconciled = manifest.reconcile_validated_progress_for_latest(latest);
        let local_status = manifest.local_latest_status(permit.db(), latest)?;
        let mut force_validated_refresh = force_validated_refresh
            || (progress_reconciled && manifest.validated_cached_txid_index.is_none())
            || (local_status == TxidPublicLocalLatestStatus::NeedsValidatedRefresh);
        if force_validated_refresh {
            let _markers_changed = manifest.clear_validated_markers_for_latest(latest);
        }
        if !force_validated_refresh
            && manifest.commit_latest_validated_if_supported(permit.db(), latest)?
                == TxidPublicLocalLatestStatus::Satisfied
            && (!artifact_provenance_required || manifest.artifact_covers_latest(latest))
        {
            manifest.write_to(&permit)?;
            debug!(
                chain_id = self.key.chain_id,
                txid_version = self.key.txid_version,
                latest_validated_txid_index = latest.txid_index,
                validated_cached_txid_index = ?manifest.validated_cached_txid_index,
                "TXID public cache already covers latest validated range after artifact fetch"
            );
            return Ok(());
        }

        let mut fetched_rows = 0_u64;
        if let Some(chunks) = artifact_chunks.filter(|chunks| !chunks.is_empty()) {
            let artifact_start_index = artifact_start_index.unwrap_or_else(|| {
                if force_validated_refresh && manifest.artifact_cached_txid_index.is_none() {
                    0
                } else {
                    manifest.artifact_fetch_start_index(latest, local_status)
                }
            });
            match manifest.apply_artifact_chunks_staged(
                &permit,
                chunks,
                Some(latest.txid_index),
                latest.merkleroot,
                artifact_start_index,
            ) {
                Ok((artifact_manifest, applied_rows)) => {
                    manifest = artifact_manifest;
                    fetched_rows = fetched_rows.saturating_add(applied_rows);
                    manifest.write_to(&permit)?;
                    rebuild_index_for_manifest(&manifest, &permit)?;
                }
                Err(err) if endpoint.is_some() => {
                    warn!(
                        ?err,
                        chain_id = self.key.chain_id,
                        txid_version = self.key.txid_version,
                        "TXID public cache artifact apply failed before durable progress; falling back to GraphQL"
                    );
                    force_validated_refresh = true;
                    let _markers_changed = manifest.clear_validated_markers_for_latest(latest);
                }
                Err(err) => return Err(err),
            }
        } else {
            debug!(
                chain_id = self.key.chain_id,
                txid_version = self.key.txid_version,
                graphql_available = endpoint.is_some(),
                "TXID public cache artifact chunks unavailable"
            );
        }

        let client = endpoint.map(|endpoint| match http_client.cloned() {
            Some(http_client) => QuickSyncClient::with_http_client(endpoint.clone(), http_client),
            None => QuickSyncClient::new(endpoint.clone()),
        });
        let local_status = manifest.local_latest_status(permit.db(), latest)?;
        let refresh_start = manifest
            .validated_cached_txid_index
            .map_or(0, |index| index.saturating_add(1));
        let refresh_needed = refresh_start <= latest.txid_index;
        if refresh_needed {
            let Some(client) = client.as_ref() else {
                if artifact_provenance_required && !manifest.artifact_covers_latest(latest) {
                    return Err(TxidPublicCacheError::CacheNotReady {
                        next_index: manifest
                            .artifact_cached_txid_index
                            .map_or(0, |index| index.saturating_add(1)),
                        required_index: latest.txid_index,
                    });
                }
                return Err(manifest.unsupported_latest_error(
                    latest,
                    local_status,
                    force_validated_refresh,
                ));
            };
            let refresh = manifest
                .refresh_validated_range(
                    &permit,
                    client,
                    refresh_start,
                    latest.txid_index,
                    latest.merkleroot,
                )
                .await?;
            fetched_rows = fetched_rows.saturating_add(refresh.0);
            if refresh.1 == Some(latest.txid_index) {
                manifest.validated_cached_txid_index = Some(latest.txid_index);
            }
        }

        debug!(
            chain_id = self.key.chain_id,
            txid_version = self.key.txid_version,
            latest_validated_txid_index = latest.txid_index,
            validated_cached_txid_index = ?manifest.validated_cached_txid_index,
            next_txid_index = manifest.next_txid_index,
            append_start = refresh_start,
            refresh_needed,
            "TXID public cache sync started"
        );
        if artifact_provenance_required && !manifest.artifact_covers_latest(latest) {
            return Err(TxidPublicCacheError::CacheNotReady {
                next_index: manifest
                    .artifact_cached_txid_index
                    .map_or(0, |index| index.saturating_add(1)),
                required_index: latest.txid_index,
            });
        }
        let latest_status = manifest.commit_latest_validated_if_supported(permit.db(), latest)?;
        if latest_status != TxidPublicLocalLatestStatus::Satisfied {
            return Err(manifest.unsupported_latest_error(
                latest,
                latest_status,
                force_validated_refresh,
            ));
        }

        rebuild_index_for_manifest(&manifest, &permit)?;
        manifest.write_to(&permit)?;
        info!(
            chain_id = self.key.chain_id,
            txid_version = self.key.txid_version,
            latest_validated_txid_index = latest.txid_index,
            validated_cached_txid_index = ?manifest.validated_cached_txid_index,
            next_txid_index = manifest.next_txid_index,
            fetched_rows,
            append_start = refresh_start,
            refresh_needed,
            elapsed_ms = started.elapsed().as_millis(),
            "TXID public cache sync complete"
        );
        Ok(())
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
            let (read_scope, from_index, artifact_marker) = {
                let permit = self.begin_write().await;
                let read_scope = permit.scope();
                let manifest = permit.cache().load_or_new_manifest()?;
                let artifact_marker = manifest.artifact_cached_txid_index;
                let from_index = artifact_marker.map_or(0, |index| index.saturating_add(1));
                (read_scope, from_index, artifact_marker)
            };
            let source = match self.artifact_source(config, http_client) {
                Ok(source) => Some(source),
                Err(_err) if endpoint.is_some() => {
                    warn!(
                        chain_id = self.key.chain_id,
                        txid_version = self.key.txid_version,
                        category = "artifact_source_unavailable",
                        "TXID public cache background artifact source unavailable; falling back to GraphQL"
                    );
                    None
                }
                Err(err) => return Err(err),
            };
            if let Some(source) = source {
                match source.fetch_current_chunks(self, from_index, None).await {
                    Ok(plan) if !plan.required.is_empty() => {
                        let maintenance = artifact::TxidPublicArtifactMaintenance::new(
                            plan.stable_current,
                            read_scope,
                        );
                        match self
                            .apply_artifact_chunks_only(&plan.required, from_index, read_scope)
                            .await
                        {
                            Ok(applied_rows) if applied_rows > 0 => {
                                return Ok((applied_rows, Some(maintenance)));
                            }
                            Ok(_) if endpoint.is_none() || artifact_marker.is_some() => {
                                return Ok((0, Some(maintenance)));
                            }
                            Ok(_) => {
                                maintenance_after_graphql = Some(maintenance);
                            }
                            Err(err) if endpoint.is_some() => {
                                warn!(
                                    ?err,
                                    chain_id = self.key.chain_id,
                                    txid_version = self.key.txid_version,
                                    category = "artifact_source_unavailable",
                                    "TXID public cache background artifact apply unavailable; falling back to GraphQL"
                                );
                                maintenance_after_graphql = Some(maintenance);
                            }
                            Err(err) => return Err(err),
                        }
                    }
                    Ok(plan) => {
                        let maintenance = artifact::TxidPublicArtifactMaintenance::new(
                            plan.stable_current,
                            read_scope,
                        );
                        if endpoint.is_none() || artifact_marker.is_some() {
                            return Ok((0, Some(maintenance)));
                        }
                        maintenance_after_graphql = Some(maintenance);
                    }
                    Err(_err) if endpoint.is_some() => {
                        warn!(
                            chain_id = self.key.chain_id,
                            txid_version = self.key.txid_version,
                            category = "artifact_source_unavailable",
                            "TXID public cache background artifact source unavailable; falling back to GraphQL"
                        );
                    }
                    Err(err) => return Err(err),
                }
            }
        }

        let fetched_rows = match endpoint {
            Some(endpoint) => self.sync_to_graph_tip(endpoint, http_client).await?,
            None => 0,
        };
        Ok((fetched_rows, maintenance_after_graphql))
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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum TxidPublicLocalLatestStatus {
    Satisfied,
    NeedsRows,
    NeedsValidatedRefresh,
}

impl TxidPublicCacheManifest {
    const fn clear_all_validated_markers(&mut self) {
        self.validated_cached_txid_index = None;
        self.latest_validated_txid_index = None;
        self.latest_validated_merkleroot = None;
        self.artifact_cached_txid_index = None;
    }

    fn clear_validated_markers_for_latest(&mut self, latest: TxidPublicLatestValidated) -> bool {
        let before = (
            self.validated_cached_txid_index,
            self.latest_validated_txid_index,
            self.latest_validated_merkleroot,
            self.artifact_cached_txid_index,
        );
        if let Some(artifact_bound) = self.artifact_cached_txid_index {
            if artifact_bound == latest.txid_index {
                self.clear_all_validated_markers();
            } else {
                self.latest_validated_txid_index = None;
                self.latest_validated_merkleroot = None;
                self.validated_cached_txid_index = Some(artifact_bound.min(latest.txid_index));
            }
        } else {
            self.clear_all_validated_markers();
        }
        before
            != (
                self.validated_cached_txid_index,
                self.latest_validated_txid_index,
                self.latest_validated_merkleroot,
                self.artifact_cached_txid_index,
            )
    }

    fn commit_latest_validated_if_supported(
        &mut self,
        db: &DbStore,
        latest: TxidPublicLatestValidated,
    ) -> Result<TxidPublicLocalLatestStatus, TxidPublicCacheError> {
        let status = self.local_latest_status(db, latest)?;
        if status == TxidPublicLocalLatestStatus::Satisfied {
            self.set_latest_validated(latest);
            if self
                .validated_cached_txid_index
                .is_none_or(|index| index < latest.txid_index)
            {
                self.validated_cached_txid_index = Some(latest.txid_index);
            }
        }
        Ok(status)
    }

    const fn set_latest_validated(&mut self, latest: TxidPublicLatestValidated) {
        self.latest_validated_txid_index = Some(latest.txid_index);
        self.latest_validated_merkleroot = latest.merkleroot;
    }

    fn unsupported_latest_error(
        &self,
        latest: TxidPublicLatestValidated,
        status: TxidPublicLocalLatestStatus,
        force_validated_refresh: bool,
    ) -> TxidPublicCacheError {
        match status {
            TxidPublicLocalLatestStatus::Satisfied => TxidPublicCacheError::MetadataMismatch(
                "supported latest marker unexpectedly rejected".to_string(),
            ),
            TxidPublicLocalLatestStatus::NeedsRows if !force_validated_refresh => {
                TxidPublicCacheError::CacheNotReady {
                    next_index: self
                        .validated_cached_txid_index
                        .map_or(0, |index| index.saturating_add(1)),
                    required_index: latest.txid_index,
                }
            }
            TxidPublicLocalLatestStatus::NeedsRows
            | TxidPublicLocalLatestStatus::NeedsValidatedRefresh => {
                TxidPublicCacheError::RootMismatch
            }
        }
    }

    fn latest_validated_matches(&self, latest: TxidPublicLatestValidated) -> bool {
        self.latest_validated_txid_index == Some(latest.txid_index)
            && self.latest_validated_merkleroot == latest.merkleroot
    }

    fn artifact_covers_latest(&self, latest: TxidPublicLatestValidated) -> bool {
        self.artifact_cached_txid_index
            .is_some_and(|index| index >= latest.txid_index)
    }

    pub(super) fn reconcile_validated_progress_for_latest(
        &mut self,
        latest: TxidPublicLatestValidated,
    ) -> bool {
        let rollback_required = self
            .latest_validated_txid_index
            .is_some_and(|index| index > latest.txid_index)
            || self
                .validated_cached_txid_index
                .is_some_and(|index| index > latest.txid_index)
            || (self.latest_validated_txid_index == Some(latest.txid_index)
                && self.latest_validated_merkleroot != latest.merkleroot
                && latest.merkleroot.is_some());
        if rollback_required {
            if self.latest_validated_txid_index == Some(latest.txid_index)
                && self.latest_validated_merkleroot != latest.merkleroot
                && latest.merkleroot.is_some()
            {
                if let Some(artifact_bound) = self
                    .artifact_cached_txid_index
                    .filter(|bound| *bound < latest.txid_index)
                {
                    self.latest_validated_txid_index = None;
                    self.latest_validated_merkleroot = None;
                    self.validated_cached_txid_index = Some(artifact_bound);
                } else {
                    self.clear_all_validated_markers();
                }
                return true;
            }
            self.validated_cached_txid_index = self
                .validated_cached_txid_index
                .map(|index| index.min(latest.txid_index));
            return true;
        }
        false
    }

    fn local_latest_status(
        &self,
        db: &DbStore,
        latest: TxidPublicLatestValidated,
    ) -> Result<TxidPublicLocalLatestStatus, TxidPublicCacheError> {
        if self
            .validated_cached_txid_index
            .is_none_or(|index| index < latest.txid_index)
        {
            return Ok(TxidPublicLocalLatestStatus::NeedsRows);
        }
        match self.validate_contiguous_rows_through(db, latest.txid_index) {
            Ok(()) => {}
            Err(
                TxidPublicCacheError::MissingLeaf { .. }
                | TxidPublicCacheError::MetadataMismatch(_)
                | TxidPublicCacheError::Decode(_),
            ) => {
                return Ok(TxidPublicLocalLatestStatus::NeedsValidatedRefresh);
            }
            Err(TxidPublicCacheError::Io(err)) if err.kind() == ErrorKind::NotFound => {
                return Ok(TxidPublicLocalLatestStatus::NeedsValidatedRefresh);
            }
            Err(err) => return Err(err),
        }
        let Some(expected_root) = latest.merkleroot else {
            return Ok(TxidPublicLocalLatestStatus::Satisfied);
        };
        let tree = latest.txid_index / TREE_LEAF_COUNT;
        let leaf_count = latest.txid_index % TREE_LEAF_COUNT + 1;
        let leaves = match read_tree_leaves(self, db, tree, leaf_count) {
            Ok(leaves) => leaves,
            Err(TxidPublicCacheError::MissingLeaf { .. }) => {
                return Ok(TxidPublicLocalLatestStatus::NeedsValidatedRefresh);
            }
            Err(err) => return Err(err),
        };
        let actual_root = DenseMerkleTree::from_ordered_leaves(leaves, leaf_count).root();
        if FixedBytes::from(actual_root.to_be_bytes::<32>()) == expected_root {
            Ok(TxidPublicLocalLatestStatus::Satisfied)
        } else {
            Ok(TxidPublicLocalLatestStatus::NeedsValidatedRefresh)
        }
    }

    fn validate_contiguous_rows_through(
        &self,
        db: &DbStore,
        txid_index: u64,
    ) -> Result<(), TxidPublicCacheError> {
        let mut expected_index = 0_u64;
        for page_ref in &self.pages {
            if expected_index > txid_index {
                return Ok(());
            }
            let page_ref_end = page_ref.start_index.saturating_add(page_ref.row_count);
            if page_ref_end <= expected_index {
                continue;
            }
            if page_ref.start_index > expected_index {
                return Err(TxidPublicCacheError::MissingLeaf {
                    index: expected_index,
                });
            }
            let page = page_ref.read(db, self.cache_key())?;
            if page.rows.len() as u64 != page_ref.row_count {
                return Err(TxidPublicCacheError::MetadataMismatch(
                    "page row count mismatch".to_string(),
                ));
            }
            for row in page.rows {
                if row.txid_index < expected_index {
                    continue;
                }
                if row.txid_index != expected_index {
                    return Err(TxidPublicCacheError::MissingLeaf {
                        index: expected_index,
                    });
                }
                if row.txid_index == txid_index {
                    return Ok(());
                }
                expected_index = expected_index.checked_add(1).ok_or_else(|| {
                    TxidPublicCacheError::MetadataMismatch("txid index overflow".to_string())
                })?;
            }
        }
        Err(TxidPublicCacheError::MissingLeaf {
            index: expected_index,
        })
    }

    fn artifact_fetch_start_index(
        &self,
        latest: TxidPublicLatestValidated,
        local_status: TxidPublicLocalLatestStatus,
    ) -> u64 {
        if local_status == TxidPublicLocalLatestStatus::NeedsValidatedRefresh
            || self
                .latest_validated_txid_index
                .is_some_and(|index| index > latest.txid_index)
            || (self.latest_validated_txid_index == Some(latest.txid_index)
                && self.latest_validated_merkleroot != latest.merkleroot)
        {
            return 0;
        }
        self.artifact_cached_txid_index
            .map_or(0, |index| index.saturating_add(1))
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

    async fn refresh_validated_range(
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
        let mut next_index = start_index;
        let mut fetched_rows = 0_u64;

        while next_index <= end_index {
            let remaining = end_index.saturating_sub(next_index).saturating_add(1);
            let limit =
                NonZeroUsize::new(remaining.min(TXID_CACHE_PAGE_SIZE.get() as u64) as usize)
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

    fn apply_artifact_chunks_staged(
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
        self.sync_inner(
            Some(endpoint),
            http_client,
            latest,
            None,
            false,
            read_scope,
            false,
            None,
        )
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
        self.sync_inner(
            Some(endpoint),
            http_client,
            latest,
            artifact_chunks,
            false,
            read_scope,
            true,
            None,
        )
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
