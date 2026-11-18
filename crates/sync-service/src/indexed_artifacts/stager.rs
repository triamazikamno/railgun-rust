//! Holds verified chunks until they drain in contiguous range order.

#[allow(clippy::wildcard_imports)]
use super::*;

#[derive(Debug, Clone)]
pub struct VerifiedIndexedArtifactChunkStager {
    dataset_kind: IndexedDatasetKind,
    scope: ChainScope,
    range_kind: IndexedArtifactRangeKind,
    next_range_start: u64,
    staged: BTreeMap<u64, VerifiedIndexedArtifactChunk>,
}

impl VerifiedIndexedArtifactChunkStager {
    #[must_use]
    pub const fn new(
        dataset_kind: IndexedDatasetKind,
        scope: ChainScope,
        range_kind: IndexedArtifactRangeKind,
        next_range_start: u64,
    ) -> Self {
        Self {
            dataset_kind,
            scope,
            range_kind,
            next_range_start,
            staged: BTreeMap::new(),
        }
    }

    #[must_use]
    pub const fn next_range_start(&self) -> u64 {
        self.next_range_start
    }

    #[must_use]
    pub fn staged_len(&self) -> usize {
        self.staged.len()
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.staged.is_empty()
    }

    pub fn stage(
        &mut self,
        chunk: VerifiedIndexedArtifactChunk,
    ) -> Result<(), IndexedArtifactManifestError> {
        self.validate_stage_compatibility(&chunk.descriptor)?;
        self.validate_stage_progress(&chunk.descriptor)?;
        self.staged.insert(chunk.descriptor.range.start, chunk);
        Ok(())
    }

    pub fn stage_many(
        &mut self,
        chunks: impl IntoIterator<Item = VerifiedIndexedArtifactChunk>,
    ) -> Result<(), IndexedArtifactManifestError> {
        for chunk in chunks {
            self.stage(chunk)?;
        }
        Ok(())
    }

    pub fn drain_contiguous(
        &mut self,
    ) -> Result<Vec<VerifiedIndexedArtifactChunk>, IndexedArtifactManifestError> {
        let mut ready = Vec::new();
        while let Some(chunk) = self.staged.get(&self.next_range_start) {
            let next_range_start = chunk.descriptor.range.end.checked_add(1).ok_or(
                IndexedArtifactManifestError::StagedChunkRangeEndOverflow {
                    end: chunk.descriptor.range.end,
                },
            )?;
            let Some(chunk) = self.staged.remove(&self.next_range_start) else {
                break;
            };
            self.next_range_start = next_range_start;
            ready.push(chunk);
        }
        Ok(ready)
    }

    /// Checks that `descriptor` matches this stager's dataset, scope and range
    /// kind, and that its range is well formed.
    fn validate_stage_compatibility(
        &self,
        descriptor: &IndexedArtifactDescriptor,
    ) -> Result<(), IndexedArtifactManifestError> {
        if descriptor.dataset_kind != self.dataset_kind {
            return Err(IndexedArtifactManifestError::StagedChunkDatasetMismatch {
                expected: self.dataset_kind,
                actual: descriptor.dataset_kind,
            });
        }
        if descriptor.scope != self.scope {
            return Err(IndexedArtifactManifestError::StagedChunkScopeMismatch {
                expected: format_scope(&self.scope),
                actual: format_scope(&descriptor.scope),
            });
        }
        if descriptor.range.kind != self.range_kind {
            return Err(IndexedArtifactManifestError::StagedChunkRangeKindMismatch {
                expected: self.range_kind,
                actual: descriptor.range.kind,
            });
        }
        if descriptor.range.start > descriptor.range.end {
            return Err(IndexedArtifactManifestError::StagedChunkInvalidRange {
                start: descriptor.range.start,
                end: descriptor.range.end,
            });
        }
        Ok(())
    }

    /// Checks that `descriptor` starts at or after the drained progress and
    /// does not conflict with a staged chunk.
    fn validate_stage_progress(
        &self,
        descriptor: &IndexedArtifactDescriptor,
    ) -> Result<(), IndexedArtifactManifestError> {
        if descriptor.range.start < self.next_range_start {
            return Err(IndexedArtifactManifestError::StagedChunkBeforeProgress {
                next_range_start: self.next_range_start,
                chunk_start: descriptor.range.start,
                chunk_end: descriptor.range.end,
            });
        }
        if self.staged.contains_key(&descriptor.range.start) {
            return Err(
                IndexedArtifactManifestError::StagedChunkDuplicateRangeStart {
                    start: descriptor.range.start,
                },
            );
        }
        if let Some(existing) = self
            .staged
            .range(..=descriptor.range.end)
            .next_back()
            .map(|(_, chunk)| &chunk.descriptor.range)
            && existing.end >= descriptor.range.start
        {
            return Err(IndexedArtifactManifestError::StagedChunkRangeOverlap {
                existing_start: existing.start,
                existing_end: existing.end,
                chunk_start: descriptor.range.start,
                chunk_end: descriptor.range.end,
            });
        }
        if let Some(existing) = self
            .staged
            .range(descriptor.range.start..)
            .next()
            .map(|(_, chunk)| &chunk.descriptor.range)
            && existing.start <= descriptor.range.end
        {
            return Err(IndexedArtifactManifestError::StagedChunkRangeOverlap {
                existing_start: existing.start,
                existing_end: existing.end,
                chunk_start: descriptor.range.start,
                chunk_end: descriptor.range.end,
            });
        }
        Ok(())
    }
}
