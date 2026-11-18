//! Bounded chunk retrieval under a compressed in-flight byte budget, with hedged requests.

#[allow(clippy::wildcard_imports)]
use super::*;

const SLOW_INDEXED_ARTIFACT_CHUNK_FETCH: Duration = Duration::from_secs(3);

struct FetchedIndexedArtifactChunk {
    index: usize,
    in_flight_byte_charge: u64,
    chunk: VerifiedIndexedArtifactChunk,
    /// The batch preference this chunk was dispatched under.
    batch_preferred_gateway_index: Option<usize>,
    preferred_gateway_index: usize,
    gateway_index: usize,
    gateway_count: usize,
    hedged: bool,
    elapsed_ms: u128,
}

/// Compressed gateway bytes in flight for one chunk batch. First attempts and
/// hedge attempts draw from the same budget.
struct ChunkByteBudget {
    max_in_flight_bytes: u64,
    state: std::sync::Mutex<ChunkByteBudgetState>,
}

#[derive(Default)]
struct ChunkByteBudgetState {
    in_flight_bytes: u64,
    max_observed_in_flight_bytes: u64,
}

impl ChunkByteBudget {
    fn new(max_in_flight_bytes: u64) -> Self {
        Self {
            max_in_flight_bytes,
            state: std::sync::Mutex::default(),
        }
    }

    fn state(&self) -> std::sync::MutexGuard<'_, ChunkByteBudgetState> {
        self.state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    /// Charges `bytes` if they fit under the budget now.
    fn try_charge(&self, bytes: u64) -> bool {
        let mut state = self.state();
        let next_in_flight_bytes = state.in_flight_bytes.saturating_add(bytes);
        if next_in_flight_bytes > self.max_in_flight_bytes {
            return false;
        }
        state.in_flight_bytes = next_in_flight_bytes;
        state.max_observed_in_flight_bytes =
            state.max_observed_in_flight_bytes.max(next_in_flight_bytes);
        true
    }

    fn release(&self, bytes: u64) {
        let mut state = self.state();
        state.in_flight_bytes = state.in_flight_bytes.saturating_sub(bytes);
    }

    /// Charges a hedge attempt's `bytes` if they fit now. The charge lasts as
    /// long as the returned guard.
    fn try_charge_hedge(&self, bytes: u64) -> Option<HedgeByteCharge<'_>> {
        if !self.try_charge(bytes) {
            return None;
        }
        Some(HedgeByteCharge {
            budget: self,
            bytes,
        })
    }

    fn in_flight_bytes(&self) -> u64 {
        self.state().in_flight_bytes
    }

    fn max_observed_in_flight_bytes(&self) -> u64 {
        self.state().max_observed_in_flight_bytes
    }
}

/// Releases a hedge attempt's byte charge when the attempt ends.
struct HedgeByteCharge<'a> {
    budget: &'a ChunkByteBudget,
    bytes: u64,
}

impl Drop for HedgeByteCharge<'_> {
    fn drop(&mut self) {
        self.budget.release(self.bytes);
    }
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub(crate) struct IndexedArtifactChunkFetchMetrics {
    pub(crate) slowest_chunk_elapsed_ms: u128,
    pub(crate) byte_budget_waits: u64,
    pub(crate) max_observed_in_flight_chunks: usize,
    pub(crate) max_observed_in_flight_bytes: u64,
}

pub(crate) struct IndexedArtifactChunkFetchBatch {
    pub(crate) chunks: Vec<VerifiedIndexedArtifactChunk>,
    pub(crate) metrics: IndexedArtifactChunkFetchMetrics,
}

impl IndexedArtifactManifestClient {
    pub async fn fetch_chunks_bounded(
        &self,
        descriptors: &[IndexedArtifactDescriptor],
    ) -> Result<Vec<VerifiedIndexedArtifactChunk>, IndexedArtifactManifestError> {
        self.fetch_chunks_bounded_with_preferred_gateway(descriptors, None)
            .await
    }

    pub(crate) async fn fetch_chunks_bounded_with_preferred_gateway(
        &self,
        descriptors: &[IndexedArtifactDescriptor],
        preferred_gateway_index: Option<usize>,
    ) -> Result<Vec<VerifiedIndexedArtifactChunk>, IndexedArtifactManifestError> {
        self.fetch_chunks_bounded_with_verified_progress(
            descriptors,
            preferred_gateway_index,
            |_, _, _| {},
        )
        .await
        .map(|batch| batch.chunks)
    }

    pub async fn fetch_chunks_bounded_with_progress<F>(
        &self,
        descriptors: &[IndexedArtifactDescriptor],
        preferred_gateway_index: Option<usize>,
        mut on_chunk_verified: F,
    ) -> Result<Vec<VerifiedIndexedArtifactChunk>, IndexedArtifactManifestError>
    where
        F: FnMut(usize, usize),
    {
        self.fetch_chunks_bounded_with_verified_progress(
            descriptors,
            preferred_gateway_index,
            |_, completed_chunks, total_chunks| {
                on_chunk_verified(completed_chunks, total_chunks);
            },
        )
        .await
        .map(|batch| batch.chunks)
    }

    pub(crate) async fn fetch_chunks_bounded_with_verified_progress<F>(
        &self,
        descriptors: &[IndexedArtifactDescriptor],
        preferred_gateway_index: Option<usize>,
        mut on_chunk_verified: F,
    ) -> Result<IndexedArtifactChunkFetchBatch, IndexedArtifactManifestError>
    where
        F: FnMut(&VerifiedIndexedArtifactChunk, usize, usize),
    {
        let total_chunks = descriptors.len();
        let concurrency = self.config.concurrency;
        if concurrency == 0 {
            return Err(IndexedArtifactManifestError::InvalidChunkConcurrency);
        }
        let batch_started = Instant::now();
        let max_in_flight_bytes = self.config.max_in_flight_bytes;
        for descriptor in descriptors {
            descriptor.decoded_envelope_byte_size_charge()?;
        }
        let fetcher = self.fetcher();
        let byte_budget = ChunkByteBudget::new(max_in_flight_bytes);
        let mut batch =
            ChunkFetchBatchState::new(total_chunks, concurrency, preferred_gateway_index);
        let mut in_flight = FuturesUnordered::new();

        while batch.next_index < descriptors.len() || !in_flight.is_empty() {
            while let Some(dispatch) = batch.admit(descriptors, &byte_budget, in_flight.len())? {
                in_flight.push(fetch_and_verify_chunk(&fetcher, &byte_budget, dispatch));
                batch.max_observed_in_flight_chunks =
                    batch.max_observed_in_flight_chunks.max(in_flight.len());
            }

            let Some(completed) = in_flight.next().await else {
                continue;
            };
            let fetched = completed?;
            batch.record(fetched, &byte_budget, &mut on_chunk_verified);
        }

        Ok(batch.finish(&byte_budget, batch_started))
    }
}

/// What one chunk fetch needs from the batch when it is dispatched.
struct ChunkDispatch {
    index: usize,
    descriptor: IndexedArtifactDescriptor,
    in_flight_byte_charge: u64,
    /// The batch preference at dispatch time.
    batch_preferred_gateway_index: Option<usize>,
    preferred_gateway_index: usize,
}

/// Fetches one dispatched chunk, hedged while the byte budget has room, and
/// verifies it against its descriptor.
async fn fetch_and_verify_chunk(
    fetcher: &TrustlessArtifactFetcher<'_>,
    byte_budget: &ChunkByteBudget,
    dispatch: ChunkDispatch,
) -> Result<FetchedIndexedArtifactChunk, IndexedArtifactManifestError> {
    let ChunkDispatch {
        index,
        descriptor,
        in_flight_byte_charge,
        batch_preferred_gateway_index,
        preferred_gateway_index,
    } = dispatch;
    let byte_size = descriptor.byte_size;
    let cid = descriptor.cid.clone();
    let dataset_kind = descriptor.dataset_kind;
    let range_start = descriptor.range.start;
    let range_end = descriptor.range.end;
    let started = Instant::now();
    let mut hedged = false;
    let result = fetcher
        .fetch_artifact_cid_with_metadata_hedged(
            &descriptor.cid,
            descriptor.byte_size,
            preferred_gateway_index,
            || {
                // A hedge starts only if its bytes fit the batch budget now;
                // otherwise the first attempt continues alone.
                let charge = byte_budget.try_charge_hedge(in_flight_byte_charge);
                hedged = charge.is_some();
                charge
            },
        )
        .await;
    let fetched = match result {
        Ok(fetched) => fetched,
        Err(err) => {
            debug!(target: LOG_TARGET,
                ?err,
                cid = %cid,
                dataset_kind = ?dataset_kind,
                range_start,
                range_end,
                byte_size,
                index,
                preferred_gateway_index,
                hedged,
                elapsed_ms = started.elapsed().as_millis(),
                "indexed artifact chunk fetch failed"
            );
            return Err(err.into());
        }
    };
    let gateway_index = fetched.gateway_index();
    let gateway_count = fetched.gateway_count();
    let chunk = match verify_chunk_bytes(descriptor, fetched.into_bytes()) {
        Ok(chunk) => chunk,
        Err(err) => {
            debug!(target: LOG_TARGET,
                ?err,
                cid = %cid,
                dataset_kind = ?dataset_kind,
                range_start,
                range_end,
                byte_size,
                index,
                gateway_index,
                gateway_count,
                elapsed_ms = started.elapsed().as_millis(),
                "indexed artifact chunk verification failed"
            );
            return Err(err);
        }
    };
    Ok(FetchedIndexedArtifactChunk {
        index,
        in_flight_byte_charge,
        chunk,
        batch_preferred_gateway_index,
        preferred_gateway_index,
        gateway_index,
        gateway_count,
        hedged,
        elapsed_ms: started.elapsed().as_millis(),
    })
}

/// Dispatch and completion state of one chunk batch.
struct ChunkFetchBatchState {
    total_chunks: usize,
    concurrency: usize,
    results: Vec<(usize, VerifiedIndexedArtifactChunk)>,
    next_index: usize,
    completed_chunks: usize,
    max_observed_in_flight_chunks: usize,
    byte_budget_waits: u64,
    slowest_chunk_elapsed_ms: u128,
    batch_preferred_gateway_index: Option<usize>,
}

impl ChunkFetchBatchState {
    fn new(
        total_chunks: usize,
        concurrency: usize,
        batch_preferred_gateway_index: Option<usize>,
    ) -> Self {
        Self {
            total_chunks,
            concurrency,
            results: Vec::with_capacity(total_chunks),
            next_index: 0,
            completed_chunks: 0,
            max_observed_in_flight_chunks: 0,
            byte_budget_waits: 0,
            slowest_chunk_elapsed_ms: 0,
            batch_preferred_gateway_index,
        }
    }

    /// Takes the next descriptor for dispatch if the concurrency limit and the
    /// byte budget have room for it now.
    fn admit(
        &mut self,
        descriptors: &[IndexedArtifactDescriptor],
        byte_budget: &ChunkByteBudget,
        in_flight_chunks: usize,
    ) -> Result<Option<ChunkDispatch>, IndexedArtifactManifestError> {
        if self.next_index >= descriptors.len() || in_flight_chunks >= self.concurrency {
            return Ok(None);
        }
        let descriptor = descriptors[self.next_index].clone();
        // Retrieval and decoded-resident memory are separate resources. This budget limits
        // compressed gateway bytes; decode_chunk_bytes enforces the dataset output limit.
        let in_flight_byte_charge = descriptor.byte_size;
        let max_in_flight_bytes = byte_budget.max_in_flight_bytes;
        if in_flight_byte_charge > max_in_flight_bytes {
            return Err(IndexedArtifactManifestError::ChunkExceedsInFlightBudget {
                cid: descriptor.cid,
                byte_size: in_flight_byte_charge,
                max_in_flight_bytes,
            });
        }
        if !byte_budget.try_charge(in_flight_byte_charge) {
            self.byte_budget_waits = self.byte_budget_waits.saturating_add(1);
            debug!(target: LOG_TARGET,
                dataset_kind = ?descriptor.dataset_kind,
                range_start = descriptor.range.start,
                range_end = descriptor.range.end,
                next_index = self.next_index,
                next_byte_size = descriptor.byte_size,
                next_in_flight_byte_charge = in_flight_byte_charge,
                in_flight_chunks,
                in_flight_bytes = byte_budget.in_flight_bytes(),
                max_in_flight_bytes,
                configured_concurrency = self.concurrency,
                "indexed artifact chunk in-flight byte budget saturated"
            );
            return Ok(None);
        }
        let index = self.next_index;
        // Without a batch preference, e.g. the gateway that served the manifest,
        // chunks spread across gateways by content hash.
        let preferred_gateway_index = self
            .batch_preferred_gateway_index
            .unwrap_or_else(|| preferred_artifact_gateway_index(&descriptor));
        self.next_index += 1;
        Ok(Some(ChunkDispatch {
            index,
            descriptor,
            in_flight_byte_charge,
            batch_preferred_gateway_index: self.batch_preferred_gateway_index,
            preferred_gateway_index,
        }))
    }

    /// Accounts for a verified chunk as it completes.
    fn record<F>(
        &mut self,
        fetched: FetchedIndexedArtifactChunk,
        byte_budget: &ChunkByteBudget,
        on_chunk_verified: &mut F,
    ) where
        F: FnMut(&VerifiedIndexedArtifactChunk, usize, usize),
    {
        byte_budget.release(fetched.in_flight_byte_charge);
        self.completed_chunks += 1;
        let completed_chunks = self.completed_chunks;
        let total_chunks = self.total_chunks;
        on_chunk_verified(&fetched.chunk, completed_chunks, total_chunks);
        self.slowest_chunk_elapsed_ms = self.slowest_chunk_elapsed_ms.max(fetched.elapsed_ms);
        if fetched.elapsed_ms >= SLOW_INDEXED_ARTIFACT_CHUNK_FETCH.as_millis() {
            info!(target: LOG_TARGET,
                dataset_kind = ?fetched.chunk.descriptor.dataset_kind,
                range_start = fetched.chunk.descriptor.range.start,
                range_end = fetched.chunk.descriptor.range.end,
                byte_size = fetched.chunk.descriptor.byte_size,
                index = fetched.index,
                preferred_gateway_index = fetched.preferred_gateway_index,
                completed_chunks,
                total_chunks,
                gateway_index = fetched.gateway_index,
                gateway_count = fetched.gateway_count,
                hedged = fetched.hedged,
                elapsed_ms = fetched.elapsed_ms,
                "slow indexed artifact chunk fetch verified"
            );
        } else {
            debug!(target: LOG_TARGET,
                cid = %fetched.chunk.descriptor.cid,
                dataset_kind = ?fetched.chunk.descriptor.dataset_kind,
                range_start = fetched.chunk.descriptor.range.start,
                range_end = fetched.chunk.descriptor.range.end,
                byte_size = fetched.chunk.descriptor.byte_size,
                in_flight_byte_charge = fetched.in_flight_byte_charge,
                index = fetched.index,
                preferred_gateway_index = fetched.preferred_gateway_index,
                completed_chunks,
                total_chunks,
                gateway_index = fetched.gateway_index,
                gateway_count = fetched.gateway_count,
                hedged = fetched.hedged,
                elapsed_ms = fetched.elapsed_ms,
                "indexed artifact chunk fetch verified"
            );
        }
        // Later chunks follow the gateway that won a chunk dispatched under this preference.
        self.follow_preferred_gateway(&fetched);
        self.results.push((fetched.index, fetched.chunk));
    }

    fn follow_preferred_gateway(&mut self, fetched: &FetchedIndexedArtifactChunk) {
        let Some(previous_gateway_index) = self.batch_preferred_gateway_index else {
            return;
        };
        if fetched.batch_preferred_gateway_index != self.batch_preferred_gateway_index {
            return;
        }
        if fetched.gateway_index == previous_gateway_index % fetched.gateway_count {
            return;
        }
        debug!(target: LOG_TARGET,
            dataset_kind = ?fetched.chunk.descriptor.dataset_kind,
            range_start = fetched.chunk.descriptor.range.start,
            range_end = fetched.chunk.descriptor.range.end,
            previous_gateway_index,
            gateway_index = fetched.gateway_index,
            gateway_count = fetched.gateway_count,
            "indexed artifact chunk batch moved preferred gateway"
        );
        self.batch_preferred_gateway_index = Some(fetched.gateway_index);
    }

    fn finish(
        self,
        byte_budget: &ChunkByteBudget,
        batch_started: Instant,
    ) -> IndexedArtifactChunkFetchBatch {
        let Self {
            total_chunks,
            concurrency,
            mut results,
            max_observed_in_flight_chunks,
            byte_budget_waits,
            slowest_chunk_elapsed_ms,
            ..
        } = self;
        let max_in_flight_bytes = byte_budget.max_in_flight_bytes;
        let max_observed_in_flight_bytes = byte_budget.max_observed_in_flight_bytes();
        debug!(target: LOG_TARGET,
            total_chunks,
            configured_concurrency = concurrency,
            max_observed_in_flight_chunks,
            max_observed_in_flight_bytes,
            max_in_flight_bytes,
            byte_budget_waits,
            slowest_chunk_elapsed_ms,
            elapsed_ms = batch_started.elapsed().as_millis(),
            "indexed artifact chunk fetch batch complete"
        );

        results.sort_unstable_by_key(|(index, _)| *index);
        IndexedArtifactChunkFetchBatch {
            chunks: results.into_iter().map(|(_, chunk)| chunk).collect(),
            metrics: IndexedArtifactChunkFetchMetrics {
                slowest_chunk_elapsed_ms,
                byte_budget_waits,
                max_observed_in_flight_chunks,
                max_observed_in_flight_bytes,
            },
        }
    }
}

pub(super) fn preferred_artifact_gateway_index(descriptor: &IndexedArtifactDescriptor) -> usize {
    usize::from(descriptor.sha256[0])
}

#[cfg(test)]
mod tests;
