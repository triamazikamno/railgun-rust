#[allow(clippy::wildcard_imports)]
use super::*;

impl TxidPublicCacheManifest {
    pub(crate) fn apply_artifact_chunks_bounded(
        &mut self,
        permit: &TxidPublicCacheWritePermit<'_>,
        chunks: &[VerifiedIndexedArtifactChunk],
        to_index: Option<u64>,
        latest_validated_merkleroot: Option<FixedBytes<32>>,
        artifact_start_index: u64,
    ) -> Result<u64, TxidPublicCacheError> {
        let db = permit.db();
        let marker_start = self
            .artifact_cached_txid_index
            .map_or(0, |index| index.saturating_add(1));
        let next_range_start = if self.artifact_cached_txid_index.is_none() {
            artifact_start_index
        } else {
            marker_start
        };
        let backfill_artifact_checkpoints =
            self.checkpoints.is_empty() && self.artifact_cached_txid_index.is_some();
        if to_index.is_some_and(|to_index| to_index < next_range_start)
            && !backfill_artifact_checkpoints
        {
            return Ok(0);
        }
        let chunks = chunks
            .iter()
            .filter(|chunk| {
                backfill_artifact_checkpoints || chunk.descriptor.range.end >= next_range_start
            })
            .cloned()
            .collect::<Vec<_>>();
        let Some(first_chunk) = chunks.first() else {
            return Ok(0);
        };
        let stager_start = if backfill_artifact_checkpoints {
            first_chunk.descriptor.range.start
        } else {
            chunks
                .iter()
                .filter_map(|chunk| {
                    let range = &chunk.descriptor.range;
                    (range.start <= next_range_start && next_range_start <= range.end)
                        .then_some(range.start)
                })
                .min()
                .unwrap_or(next_range_start)
        };
        let mut stager = VerifiedIndexedArtifactChunkStager::new(
            IndexedDatasetKind::PublicTxid,
            first_chunk.descriptor.scope.clone(),
            IndexedArtifactRangeKind::TxidIndex,
            stager_start,
        );
        stager.stage_many(chunks.iter().cloned())?;
        let ready = stager.drain_contiguous()?;
        if !backfill_artifact_checkpoints {
            let mutation_start = ready
                .iter()
                .filter_map(|chunk| {
                    let applied_range_end = to_index
                        .map_or(chunk.descriptor.range.end, |to_index| {
                            chunk.descriptor.range.end.min(to_index)
                        });
                    let apply_range_start = next_range_start.max(chunk.descriptor.range.start);
                    (applied_range_end >= apply_range_start).then_some(apply_range_start)
                })
                .min();
            if let Some(mutation_start) = mutation_start {
                self.invalidate_checkpoints_from(mutation_start);
            }
        }
        debug!(target: LOG_TARGET,
            staged_chunks = chunks.len(),
            ready_chunks = ready.len(),
            next_range_start,
            stager_start,
            "staged public TXID artifact chunks for ordered apply"
        );

        let mut applied_rows = 0_u64;
        let retained_latest = self.latest_validated_txid_index;
        let mut background_changed_retained_latest = false;
        for chunk in &ready {
            let mut pages = Vec::<TxidPublicCachePage>::try_from(chunk)?;
            if backfill_artifact_checkpoints
                && self
                    .artifact_cached_txid_index
                    .is_some_and(|bound| chunk.descriptor.range.end <= bound)
            {
                verify_declared_merkle_root(
                    chunk.descriptor.metadata.root.as_ref(),
                    self,
                    db,
                    chunk.descriptor.range.start,
                    chunk.descriptor.range.end,
                    &pages,
                )?;
                self.insert_checkpoint(
                    chunk.descriptor.range.end,
                    chunk.descriptor.metadata.root.ok_or_else(|| {
                        TxidPublicCacheError::MetadataMismatch(
                            "public_txid artifact missing Merkle root metadata".to_string(),
                        )
                    })?,
                    TxidPublicCheckpointSource::IndexedArtifact,
                )?;
                continue;
            }
            let applied_range_end = to_index.map_or(chunk.descriptor.range.end, |to_index| {
                chunk.descriptor.range.end.min(to_index)
            });
            if applied_range_end < chunk.descriptor.range.start {
                continue;
            }
            verify_declared_merkle_root(
                chunk.descriptor.metadata.root.as_ref(),
                self,
                db,
                chunk.descriptor.range.start,
                chunk.descriptor.range.end,
                &pages,
            )?;
            let apply_range_start = next_range_start.max(chunk.descriptor.range.start);
            if apply_range_start != chunk.descriptor.range.start
                || applied_range_end != chunk.descriptor.range.end
            {
                pages = truncate_pages_to_range(pages, apply_range_start, applied_range_end)?;
            }
            let latest_root_verified = if to_index == Some(applied_range_end)
                && let Some(latest_validated_merkleroot) = latest_validated_merkleroot
            {
                verify_declared_merkle_root(
                    Some(&latest_validated_merkleroot),
                    self,
                    db,
                    apply_range_start,
                    applied_range_end,
                    &pages,
                )?;
                true
            } else {
                false
            };
            let bounded_authority_verified =
                applied_range_end < chunk.descriptor.range.end && latest_root_verified;
            if to_index.is_none()
                && !pages.is_empty()
                && retained_latest.is_some_and(|latest| apply_range_start <= latest)
            {
                background_changed_retained_latest = true;
            }
            for page in pages {
                let row_count = page.rows.len() as u64;
                if page.start_index < self.next_txid_index {
                    self.insert_or_replace_staged_page(permit, &page)?;
                } else {
                    self.append_staged_page(permit, &page)?;
                }
                applied_rows = applied_rows.saturating_add(row_count);
            }
            self.validated_cached_txid_index = Some(applied_range_end);
            let full_authenticated_chunk = applied_range_end == chunk.descriptor.range.end
                && (apply_range_start == chunk.descriptor.range.start
                    || self.artifact_cached_txid_index.is_some());
            if full_authenticated_chunk || bounded_authority_verified {
                self.artifact_cached_txid_index = Some(
                    self.artifact_cached_txid_index
                        .map_or(applied_range_end, |index| index.max(applied_range_end)),
                );
            }
            if full_authenticated_chunk {
                self.insert_checkpoint(
                    chunk.descriptor.range.end,
                    chunk.descriptor.metadata.root.ok_or_else(|| {
                        TxidPublicCacheError::MetadataMismatch(
                            "public_txid artifact missing Merkle root metadata".to_string(),
                        )
                    })?,
                    TxidPublicCheckpointSource::IndexedArtifact,
                )?;
            } else if bounded_authority_verified {
                self.insert_checkpoint(
                    applied_range_end,
                    latest_validated_merkleroot.expect("bounded authority has latest root"),
                    TxidPublicCheckpointSource::LatestValidated,
                )?;
            }
            debug!(target: LOG_TARGET,
                cid = %chunk.descriptor.cid,
                range_start = chunk.descriptor.range.start,
                range_end = chunk.descriptor.range.end,
                applied_range_end,
                row_count = chunk.descriptor.row_count,
                validated_cached_txid_index = applied_range_end,
                "applied public TXID artifact chunk"
            );
            if to_index.is_some_and(|to_index| applied_range_end >= to_index) {
                break;
            }
        }
        if background_changed_retained_latest {
            self.latest_validated_txid_index = None;
            self.latest_validated_merkleroot = None;
        }
        Ok(applied_rows)
    }
}

#[cfg(test)]
impl TxidPublicCacheManifest {
    pub(in crate::txid_cache) fn apply_artifact_chunks(
        &mut self,
        permit: &TxidPublicCacheWritePermit<'_>,
        chunks: &[VerifiedIndexedArtifactChunk],
    ) -> Result<u64, TxidPublicCacheError> {
        let artifact_start_index = self
            .validated_cached_txid_index
            .map_or(0, |index| index.saturating_add(1));
        self.apply_artifact_chunks_bounded(permit, chunks, None, None, artifact_start_index)
    }
}
