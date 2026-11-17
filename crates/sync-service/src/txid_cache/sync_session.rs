//! One `sync_inner` run: the request, and the session that holds its write
//! permit and manifest through the reconcile, artifact, GraphQL refresh and
//! finish stages.

use super::validated::TxidPublicLocalLatestStatus;
use super::{
    QuickSyncClient, TxidPublicCacheError, TxidPublicCacheKey, TxidPublicCacheManifest,
    TxidPublicCacheReadScope, TxidPublicCacheWritePermit, TxidPublicLatestValidated, Url, debug,
    info, rebuild_index_for_manifest, warn,
};

/// One sync of the cache towards `latest`: verified artifact chunks first, when
/// there are any, then a GraphQL refresh of the validated range.
pub(super) struct TxidSyncRequest<'a> {
    pub(super) endpoint: Option<&'a Url>,
    pub(super) http_client: Option<&'a reqwest::Client>,
    pub(super) latest: TxidPublicLatestValidated,
    pub(super) artifact_chunks:
        Option<&'a [crate::indexed_artifacts::VerifiedIndexedArtifactChunk]>,
    pub(super) force_validated_refresh: bool,
    pub(super) read_scope: TxidPublicCacheReadScope,
    pub(super) indexed_artifact_source_configured: bool,
    pub(super) artifact_start_index: Option<u64>,
}

/// The manifest and progress of one `sync_inner` run, under its write permit.
pub(super) struct TxidSyncSession<'a> {
    key: TxidPublicCacheKey<'a>,
    permit: &'a TxidPublicCacheWritePermit<'a>,
    endpoint: Option<&'a Url>,
    http_client: Option<&'a reqwest::Client>,
    latest: TxidPublicLatestValidated,
    manifest: TxidPublicCacheManifest,
    artifact_provenance_required: bool,
    force_validated_refresh: bool,
    fetched_rows: u64,
}

/// Where the GraphQL refresh started and whether it ran, for the sync logs.
#[derive(Clone, Copy)]
pub(super) struct ValidatedRefresh {
    start: u64,
    needed: bool,
}

impl<'a> TxidSyncSession<'a> {
    pub(super) fn new(
        key: TxidPublicCacheKey<'a>,
        permit: &'a TxidPublicCacheWritePermit<'a>,
        request: &TxidSyncRequest<'a>,
    ) -> Result<Self, TxidPublicCacheError> {
        let cache = permit.cache();
        let manifest = cache.load_or_new_manifest()?;
        Ok(Self {
            key,
            permit,
            endpoint: request.endpoint,
            http_client: request.http_client,
            latest: request.latest,
            manifest,
            artifact_provenance_required: request.indexed_artifact_source_configured
                && request.endpoint.is_none(),
            force_validated_refresh: request.force_validated_refresh,
            fetched_rows: 0,
        })
    }

    /// Reconciles the markers with `latest` and decides whether a validated
    /// refresh is forced. Returns `None` once the cache is shown to cover
    /// `latest`; otherwise returns the local status from before any marker was
    /// cleared, which picks the artifact start index.
    pub(super) fn reconcile_and_finish_if_covered(
        &mut self,
    ) -> Result<Option<TxidPublicLocalLatestStatus>, TxidPublicCacheError> {
        let latest = self.latest;
        let progress_reconciled = self
            .manifest
            .reconcile_validated_progress_for_latest(latest);
        let local_status = self
            .manifest
            .local_latest_status(self.permit.db(), latest)?;
        self.force_validated_refresh = self.force_validated_refresh
            || (progress_reconciled && self.manifest.validated_cached_txid_index.is_none())
            || (local_status == TxidPublicLocalLatestStatus::NeedsValidatedRefresh);
        if self.force_validated_refresh {
            let _markers_changed = self.manifest.clear_validated_markers_for_latest(latest);
            return Ok(Some(local_status));
        }
        let latest_status = self
            .manifest
            .commit_latest_validated_if_supported(self.permit.db(), latest)?;
        let covered = latest_status == TxidPublicLocalLatestStatus::Satisfied
            && (!self.artifact_provenance_required || self.manifest.artifact_covers_latest(latest));
        if !covered {
            return Ok(Some(local_status));
        }
        self.manifest.write_to(self.permit)?;
        debug!(
            chain_id = self.key.chain_id,
            txid_version = self.key.txid_version,
            latest_validated_txid_index = latest.txid_index,
            validated_cached_txid_index = ?self.manifest.validated_cached_txid_index,
            "TXID public cache already covers latest validated range after artifact fetch"
        );
        Ok(None)
    }

    /// Applies the verified artifact chunks. With GraphQL available, a failed
    /// apply falls back to a forced validated refresh.
    pub(super) fn apply_artifact_chunks(
        &mut self,
        chunks: Option<&[crate::indexed_artifacts::VerifiedIndexedArtifactChunk]>,
        artifact_start_index: Option<u64>,
        local_status: TxidPublicLocalLatestStatus,
    ) -> Result<(), TxidPublicCacheError> {
        let Some(chunks) = chunks.filter(|chunks| !chunks.is_empty()) else {
            debug!(
                chain_id = self.key.chain_id,
                txid_version = self.key.txid_version,
                graphql_available = self.endpoint.is_some(),
                "TXID public cache artifact chunks unavailable"
            );
            return Ok(());
        };
        let latest = self.latest;
        let artifact_start_index = artifact_start_index.unwrap_or_else(|| {
            if self.force_validated_refresh && self.manifest.artifact_cached_txid_index.is_none() {
                0
            } else {
                self.manifest
                    .artifact_fetch_start_index(latest, local_status)
            }
        });
        match self.manifest.apply_artifact_chunks_staged(
            self.permit,
            chunks,
            Some(latest.txid_index),
            latest.merkleroot,
            artifact_start_index,
        ) {
            Ok((artifact_manifest, applied_rows)) => {
                self.manifest = artifact_manifest;
                self.fetched_rows = self.fetched_rows.saturating_add(applied_rows);
                self.manifest.write_to(self.permit)?;
                rebuild_index_for_manifest(&self.manifest, self.permit)?;
            }
            Err(err) if self.endpoint.is_some() => {
                warn!(
                    ?err,
                    chain_id = self.key.chain_id,
                    txid_version = self.key.txid_version,
                    "TXID public cache artifact apply failed before durable progress; falling back to GraphQL"
                );
                self.force_validated_refresh = true;
                let _markers_changed = self.manifest.clear_validated_markers_for_latest(latest);
            }
            Err(err) => return Err(err),
        }
        Ok(())
    }

    /// Refreshes the validated range past the cached marker through GraphQL.
    pub(super) async fn refresh_from_graphql(
        &mut self,
    ) -> Result<ValidatedRefresh, TxidPublicCacheError> {
        let client = self
            .endpoint
            .map(|endpoint| match self.http_client.cloned() {
                Some(http_client) => {
                    QuickSyncClient::with_http_client(endpoint.clone(), http_client)
                }
                None => QuickSyncClient::new(endpoint.clone()),
            });
        let latest = self.latest;
        let local_status = self
            .manifest
            .local_latest_status(self.permit.db(), latest)?;
        let start = self
            .manifest
            .validated_cached_txid_index
            .map_or(0, |index| index.saturating_add(1));
        let refresh = ValidatedRefresh {
            start,
            needed: start <= latest.txid_index,
        };
        if !refresh.needed {
            return Ok(refresh);
        }
        let Some(client) = client.as_ref() else {
            self.require_artifact_provenance()?;
            return Err(self.manifest.unsupported_latest_error(
                latest,
                local_status,
                self.force_validated_refresh,
            ));
        };
        let (refreshed_rows, refreshed_to) = self
            .manifest
            .refresh_validated_range(
                self.permit,
                client,
                refresh.start,
                latest.txid_index,
                latest.merkleroot,
            )
            .await?;
        self.fetched_rows = self.fetched_rows.saturating_add(refreshed_rows);
        if refreshed_to == Some(latest.txid_index) {
            self.manifest.validated_cached_txid_index = Some(latest.txid_index);
        }
        Ok(refresh)
    }

    /// Commits `latest`, then rebuilds the index and writes the manifest.
    pub(super) fn finish(
        mut self,
        refresh: ValidatedRefresh,
        started: std::time::Instant,
    ) -> Result<(), TxidPublicCacheError> {
        let latest = self.latest;
        debug!(
            chain_id = self.key.chain_id,
            txid_version = self.key.txid_version,
            latest_validated_txid_index = latest.txid_index,
            validated_cached_txid_index = ?self.manifest.validated_cached_txid_index,
            next_txid_index = self.manifest.next_txid_index,
            append_start = refresh.start,
            refresh_needed = refresh.needed,
            "TXID public cache sync started"
        );
        self.require_artifact_provenance()?;
        let latest_status = self
            .manifest
            .commit_latest_validated_if_supported(self.permit.db(), latest)?;
        if latest_status != TxidPublicLocalLatestStatus::Satisfied {
            return Err(self.manifest.unsupported_latest_error(
                latest,
                latest_status,
                self.force_validated_refresh,
            ));
        }

        rebuild_index_for_manifest(&self.manifest, self.permit)?;
        self.manifest.write_to(self.permit)?;
        info!(
            chain_id = self.key.chain_id,
            txid_version = self.key.txid_version,
            latest_validated_txid_index = latest.txid_index,
            validated_cached_txid_index = ?self.manifest.validated_cached_txid_index,
            next_txid_index = self.manifest.next_txid_index,
            fetched_rows = self.fetched_rows,
            append_start = refresh.start,
            refresh_needed = refresh.needed,
            elapsed_ms = started.elapsed().as_millis(),
            "TXID public cache sync complete"
        );
        Ok(())
    }

    /// Without a GraphQL endpoint, artifact rows must reach `latest`.
    fn require_artifact_provenance(&self) -> Result<(), TxidPublicCacheError> {
        if self.artifact_provenance_required && !self.manifest.artifact_covers_latest(self.latest) {
            return Err(TxidPublicCacheError::CacheNotReady {
                next_index: self
                    .manifest
                    .artifact_cached_txid_index
                    .map_or(0, |index| index.saturating_add(1)),
                required_index: self.latest.txid_index,
            });
        }
        Ok(())
    }
}
