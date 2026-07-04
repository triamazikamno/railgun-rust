use super::*;

use crate::indexed_artifacts::{
    ChainScope, ChainType, IndexedArtifactManifestClient, IndexedArtifactRangeKind,
    IndexedArtifactStreamCatalog, IndexedArtifactStreamPartitionPolicy, IndexedArtifactStreamPlan,
    IndexedArtifactStreamPlanRequest, IndexedDatasetKind, VerifiedIndexedArtifactChunk,
    VerifiedIndexedArtifactChunkStager, decode_indexed_artifact_chunk,
};

use broadcaster_core::transact::{
    compute_railgun_txid_parts, railgun_txid_leaf_hash_with_output_start,
};
use merkletree::tree::DenseMerkleTree;
use tracing::debug;

const PUBLIC_TXID_RECORD_SECTION_ID: u16 = 1;

pub(crate) async fn fetch_txid_public_artifact_chunks(
    config: &IndexedArtifactSourceConfig,
    http_client: Option<&reqwest::Client>,
    scope: &ChainScope,
    txid_version: &str,
    from_index: u64,
    to_index: Option<u64>,
) -> Result<Vec<VerifiedIndexedArtifactChunk>, TxidPublicCacheError> {
    let client = IndexedArtifactManifestClient::new(
        config.clone(),
        http_client.cloned().unwrap_or_default(),
    );
    let manifest = client
        .fetch_manifest(scope, None, SystemTime::now())
        .await?;
    let Some(chain_entry) = manifest.chains.iter().find(|entry| entry.scope == *scope) else {
        return Ok(Vec::new());
    };
    let range_end = to_index.unwrap_or(u64::MAX);

    let mut catalogs = Vec::new();
    for catalog_descriptor in chain_entry.catalogs.iter().filter(|catalog| {
        catalog.matches_range(
            IndexedDatasetKind::PublicTxid,
            scope,
            IndexedArtifactRangeKind::TxidIndex,
            from_index,
            range_end,
        )
    }) {
        let catalog = client
            .fetch_catalog(catalog_descriptor)
            .await?
            .into_stream_catalog();
        catalogs.push(IndexedArtifactStreamCatalog::new(
            catalog.descriptor,
            catalog.chunks,
        ));
    }
    let plan = IndexedArtifactStreamPlan::plan(
        &catalogs,
        &IndexedArtifactStreamPlanRequest::new(
            IndexedDatasetKind::PublicTxid,
            scope.clone(),
            IndexedArtifactRangeKind::TxidIndex,
            from_index,
            range_end,
            IndexedArtifactStreamPartitionPolicy::Exact(txid_version.to_string()),
        ),
    )
    .map_err(|err| TxidPublicCacheError::MetadataMismatch(err.to_string()))?;
    client
        .fetch_chunks_bounded(&plan.required_current_chunks)
        .await
        .map_err(Into::into)
}

impl TxidPublicCacheManifest {
    #[cfg(test)]
    pub(crate) fn apply_artifact_chunks(
        &mut self,
        db: &DbStore,
        key: TxidPublicCacheKey<'_>,
        chunks: &[VerifiedIndexedArtifactChunk],
    ) -> Result<u64, TxidPublicCacheError> {
        self.apply_artifact_chunks_bounded(db, key, chunks, None, None)
    }

    pub(crate) fn apply_artifact_chunks_bounded(
        &mut self,
        db: &DbStore,
        key: TxidPublicCacheKey<'_>,
        chunks: &[VerifiedIndexedArtifactChunk],
        to_index: Option<u64>,
        latest_validated_merkleroot: Option<FixedBytes<32>>,
    ) -> Result<u64, TxidPublicCacheError> {
        let Some(next_range_start) = self
            .validated_cached_txid_index
            .map_or(Some(0), |index| index.checked_add(1))
        else {
            return Ok(0);
        };
        if to_index.is_some_and(|to_index| to_index < next_range_start) {
            return Ok(0);
        }
        let chunks = chunks
            .iter()
            .filter(|chunk| chunk.descriptor.range.end >= next_range_start)
            .cloned()
            .collect::<Vec<_>>();
        let Some(first_chunk) = chunks.first() else {
            return Ok(0);
        };
        let stager_start = chunks
            .iter()
            .filter_map(|chunk| {
                let range = &chunk.descriptor.range;
                (range.start <= next_range_start && next_range_start <= range.end)
                    .then_some(range.start)
            })
            .min()
            .unwrap_or(next_range_start);
        let mut stager = VerifiedIndexedArtifactChunkStager::new(
            IndexedDatasetKind::PublicTxid,
            first_chunk.descriptor.scope.clone(),
            IndexedArtifactRangeKind::TxidIndex,
            stager_start,
        );
        stager.stage_many(chunks.iter().cloned())?;
        let ready = stager.drain_contiguous()?;
        debug!(
            staged_chunks = chunks.len(),
            ready_chunks = ready.len(),
            next_range_start,
            stager_start,
            "staged public TXID artifact chunks for ordered apply"
        );

        let mut applied_rows = 0_u64;
        for chunk in &ready {
            let (pages, applied_range_end) = materialize_pages_for_apply(chunk, to_index)?;
            if pages.is_empty() {
                continue;
            }
            if applied_range_end == chunk.descriptor.range.end {
                verify_declared_merkle_root(
                    &chunk.descriptor.metadata.root,
                    self,
                    db,
                    chunk.descriptor.range.start,
                    applied_range_end,
                    &pages,
                )?;
            } else {
                let full_pages = Vec::<TxidPublicCachePage>::try_from(chunk)?;
                verify_declared_merkle_root(
                    &chunk.descriptor.metadata.root,
                    self,
                    db,
                    chunk.descriptor.range.start,
                    chunk.descriptor.range.end,
                    &full_pages,
                )?;
            }
            if to_index == Some(applied_range_end) && latest_validated_merkleroot.is_some() {
                verify_declared_merkle_root(
                    &latest_validated_merkleroot,
                    self,
                    db,
                    chunk.descriptor.range.start,
                    applied_range_end,
                    &pages,
                )?;
            }
            for page in pages {
                let row_count = page.rows.len() as u64;
                if page.start_index < self.next_txid_index {
                    self.insert_or_replace_staged_artifact_page(db, key, &page)?;
                } else {
                    self.append_staged_artifact_page(db, key, &page)?;
                }
                applied_rows = applied_rows.saturating_add(row_count);
            }
            self.validated_cached_txid_index = Some(applied_range_end);
            debug!(
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
        Ok(applied_rows)
    }
}

impl TryFrom<&VerifiedIndexedArtifactChunk> for Vec<TxidPublicCachePage> {
    type Error = TxidPublicCacheError;

    fn try_from(chunk: &VerifiedIndexedArtifactChunk) -> Result<Self, Self::Error> {
        let envelope = decode_indexed_artifact_chunk(chunk)?;
        if envelope.header.dataset_kind != IndexedDatasetKind::PublicTxid {
            return Err(TxidPublicCacheError::MetadataMismatch(
                "artifact chunk is not public_txid".to_string(),
            ));
        }
        if envelope.header.scope.chain_type != ChainType::Evm {
            return Err(TxidPublicCacheError::MetadataMismatch(
                "artifact chunk is not an EVM chain chunk".to_string(),
            ));
        }
        if envelope.header.range.kind != IndexedArtifactRangeKind::TxidIndex {
            return Err(TxidPublicCacheError::MetadataMismatch(
                "artifact chunk range is not txid_index".to_string(),
            ));
        }
        let payload = envelope
            .section_payload(PUBLIC_TXID_RECORD_SECTION_ID)
            .map_err(crate::indexed_artifacts::IndexedArtifactManifestError::from)?;
        let rows = PublicTxidCursor::new(payload).read_rows(
            envelope.header.range.start,
            envelope.header.range.end,
            envelope.header.row_count,
        )?;
        TxidPublicCachePage::pages_from_rows(rows)
    }
}

fn verify_declared_merkle_root(
    expected: &Option<FixedBytes<32>>,
    manifest: &TxidPublicCacheManifest,
    db: &DbStore,
    range_start: u64,
    range_end: u64,
    pages: &[TxidPublicCachePage],
) -> Result<(), TxidPublicCacheError> {
    let Some(expected) = expected else {
        return Err(TxidPublicCacheError::MetadataMismatch(
            "public_txid artifact missing Merkle root metadata".to_string(),
        ));
    };
    if range_start / TREE_LEAF_COUNT != range_end / TREE_LEAF_COUNT {
        return Err(TxidPublicCacheError::MetadataMismatch(
            "public_txid artifact root spans multiple TXID trees".to_string(),
        ));
    }
    let expected = U256::from_be_slice(expected.as_slice());
    let tree = range_end / TREE_LEAF_COUNT;
    let tree_start = tree * TREE_LEAF_COUNT;
    let leaf_count = range_end
        .checked_sub(tree_start)
        .and_then(|count| count.checked_add(1))
        .ok_or_else(|| {
            TxidPublicCacheError::MetadataMismatch("public_txid root range overflow".to_string())
        })?;
    let leaf_capacity = usize::try_from(leaf_count).map_err(|_| {
        TxidPublicCacheError::MetadataMismatch("public_txid root range too large".to_string())
    })?;
    let mut leaves = if range_start > tree_start {
        read_tree_leaves(manifest, db, tree, range_start - tree_start)?
    } else {
        Vec::with_capacity(leaf_capacity)
    };
    leaves.reserve(leaf_capacity.saturating_sub(leaves.len()));
    let mut new_rows = pages.iter().flat_map(|page| page.rows.iter());
    for txid_index in range_start..=range_end {
        let Some(row) = new_rows.next() else {
            return Err(TxidPublicCacheError::MissingLeaf { index: txid_index });
        };
        if row.txid_index != txid_index {
            return Err(TxidPublicCacheError::MetadataMismatch(format!(
                "public_txid artifact root verification expected index {txid_index}, got {}",
                row.txid_index
            )));
        }
        leaves.push(U256::from_be_bytes(row.txid_leaf_hash.0));
    }
    let actual = DenseMerkleTree::from_ordered_leaves(leaves, leaf_count).root();
    if actual != expected {
        return Err(TxidPublicCacheError::MetadataMismatch(
            "public_txid artifact Merkle root mismatch".to_string(),
        ));
    }
    Ok(())
}

fn materialize_pages_for_apply(
    chunk: &VerifiedIndexedArtifactChunk,
    to_index: Option<u64>,
) -> Result<(Vec<TxidPublicCachePage>, u64), TxidPublicCacheError> {
    let applied_range_end = to_index.map_or(chunk.descriptor.range.end, |to_index| {
        chunk.descriptor.range.end.min(to_index)
    });
    if applied_range_end < chunk.descriptor.range.start {
        return Ok((Vec::new(), applied_range_end));
    }
    let mut pages = Vec::<TxidPublicCachePage>::try_from(chunk)?;
    if applied_range_end < chunk.descriptor.range.end {
        pages = truncate_pages_to_range_end(pages, applied_range_end)?;
    }
    Ok((pages, applied_range_end))
}

fn truncate_pages_to_range_end(
    pages: Vec<TxidPublicCachePage>,
    range_end: u64,
) -> Result<Vec<TxidPublicCachePage>, TxidPublicCacheError> {
    let rows = pages
        .into_iter()
        .flat_map(|page| page.rows)
        .take_while(|row| row.txid_index <= range_end)
        .collect::<Vec<_>>();
    TxidPublicCachePage::pages_from_rows(rows)
}

struct PublicTxidCursor<'a> {
    bytes: &'a [u8],
    position: usize,
}

impl<'a> PublicTxidCursor<'a> {
    const fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, position: 0 }
    }

    const fn is_eof(&self) -> bool {
        self.position == self.bytes.len()
    }

    fn read_row(&mut self) -> Result<TxidPublicCacheRow, TxidPublicCacheError> {
        let txid_index = self.read_u64("txid_index")?;
        let id = self.read_string("id")?;
        let block_number = self.read_u64("block_number")?;
        let block_timestamp = self.read_u64("block_timestamp")?;
        let _block_hash = self.read_fixed_bytes("block_hash")?;
        let transaction_hash = self.read_fixed_bytes("transaction_hash")?;
        let _first_log_index = self.read_u64("first_log_index")?;
        let _last_log_index = self.read_u64("last_log_index")?;
        let merkle_root = self.read_fixed_bytes("merkle_root")?;
        let nullifiers = self.read_u256_vec("nullifiers")?;
        let commitments = self.read_u256_vec("commitments")?;
        let bound_params_hash = U256::from_be_bytes(self.read_fixed_bytes("bound_params_hash")?);
        let has_unshield = self.read_bool("has_unshield")?;
        let utxo_tree_in = self.read_u64("utxo_tree_in")?;
        let utxo_tree_out = self.read_u64("utxo_tree_out")?;
        let utxo_batch_start_position_out = self.read_u64("utxo_batch_start_position_out")?;
        let railgun_txid = compute_railgun_txid_parts(&nullifiers, &commitments, bound_params_hash);
        let output_start_global = u128::from(utxo_tree_out)
            .saturating_mul(u128::from(TREE_LEAF_COUNT))
            .saturating_add(u128::from(utxo_batch_start_position_out));
        let txid_leaf_hash = FixedBytes::from(
            railgun_txid_leaf_hash_with_output_start(
                railgun_txid,
                utxo_tree_in,
                U256::from(output_start_global),
            )
            .to_be_bytes::<32>(),
        );
        Ok(TxidPublicCacheRow {
            txid_index,
            txid_leaf_hash,
            transaction: TxidPublicCacheTransaction {
                id,
                transaction_hash: FixedBytes::from(transaction_hash),
                block_number,
                block_timestamp,
                merkle_root: U256::from_be_bytes(merkle_root),
                nullifiers,
                commitments,
                bound_params_hash,
                has_unshield,
                utxo_tree_in,
                utxo_tree_out,
                utxo_batch_start_position_out,
            },
        })
    }

    fn read_rows(
        &mut self,
        expected_start: u64,
        expected_end: u64,
        row_count: u64,
    ) -> Result<Vec<TxidPublicCacheRow>, TxidPublicCacheError> {
        let expected_count = expected_end
            .checked_sub(expected_start)
            .and_then(|count| count.checked_add(1))
            .ok_or_else(|| {
                TxidPublicCacheError::MetadataMismatch(
                    "public_txid artifact range overflow".to_string(),
                )
            })?;
        if row_count != expected_count {
            return Err(TxidPublicCacheError::MetadataMismatch(format!(
                "public_txid artifact row count mismatch: expected {expected_count}, got {row_count}"
            )));
        }
        let mut rows = Vec::new();
        let mut expected_index = expected_start;
        for _ in 0..row_count {
            let row = self.read_row()?;
            if row.txid_index != expected_index {
                return Err(TxidPublicCacheError::MetadataMismatch(format!(
                    "public_txid artifact index gap: expected {expected_index}, got {}",
                    row.txid_index
                )));
            }
            expected_index = expected_index.checked_add(1).ok_or_else(|| {
                TxidPublicCacheError::MetadataMismatch("txid index overflow".to_string())
            })?;
            rows.push(row);
        }
        if rows.last().map(|row| row.txid_index) != Some(expected_end) {
            return Err(TxidPublicCacheError::MetadataMismatch(
                "public_txid artifact range end mismatch".to_string(),
            ));
        }
        if !self.is_eof() {
            return Err(TxidPublicCacheError::MetadataMismatch(
                "public_txid artifact has trailing bytes".to_string(),
            ));
        }
        Ok(rows)
    }

    fn read_u8(&mut self, field: &'static str) -> Result<u8, TxidPublicCacheError> {
        Ok(self.read_exact(1, field)?[0])
    }

    fn read_bool(&mut self, field: &'static str) -> Result<bool, TxidPublicCacheError> {
        match self.read_u8(field)? {
            0 => Ok(false),
            1 => Ok(true),
            other => Err(TxidPublicCacheError::MetadataMismatch(format!(
                "invalid bool byte {other} in {field}"
            ))),
        }
    }

    fn read_u16(&mut self, field: &'static str) -> Result<u16, TxidPublicCacheError> {
        let bytes = self.read_exact(2, field)?;
        Ok(u16::from_le_bytes([bytes[0], bytes[1]]))
    }

    fn read_u32(&mut self, field: &'static str) -> Result<u32, TxidPublicCacheError> {
        let bytes = self.read_exact(4, field)?;
        Ok(u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
    }

    fn read_u64(&mut self, field: &'static str) -> Result<u64, TxidPublicCacheError> {
        let bytes = self.read_exact(8, field)?;
        Ok(u64::from_le_bytes([
            bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5], bytes[6], bytes[7],
        ]))
    }

    fn read_string(&mut self, field: &'static str) -> Result<String, TxidPublicCacheError> {
        let length = self.read_u16(field)? as usize;
        let bytes = self.read_exact(length, field)?;
        std::str::from_utf8(bytes)
            .map(str::to_string)
            .map_err(|err| {
                TxidPublicCacheError::MetadataMismatch(format!("invalid utf8 in {field}: {err}"))
            })
    }

    fn read_fixed_bytes(&mut self, field: &'static str) -> Result<[u8; 32], TxidPublicCacheError> {
        self.read_exact(32, field)?.try_into().map_err(|_| {
            TxidPublicCacheError::MetadataMismatch(format!("invalid fixed bytes in {field}"))
        })
    }

    fn read_u256_vec(&mut self, field: &'static str) -> Result<Vec<U256>, TxidPublicCacheError> {
        let count = self.read_u32(field)? as usize;
        let byte_count = count.checked_mul(32).ok_or_else(|| {
            TxidPublicCacheError::MetadataMismatch(format!(
                "public_txid artifact {field} byte count overflow"
            ))
        })?;
        if self.bytes.len().saturating_sub(self.position) < byte_count {
            return Err(TxidPublicCacheError::MetadataMismatch(format!(
                "public_txid artifact ended while reading {field}"
            )));
        }
        let mut values = Vec::with_capacity(count);
        for _ in 0..count {
            values.push(U256::from_be_bytes(self.read_fixed_bytes(field)?));
        }
        Ok(values)
    }

    fn read_exact(
        &mut self,
        length: usize,
        field: &'static str,
    ) -> Result<&'a [u8], TxidPublicCacheError> {
        let end = self.position.checked_add(length).ok_or_else(|| {
            TxidPublicCacheError::MetadataMismatch(format!(
                "public_txid artifact overflow in {field}"
            ))
        })?;
        let value = self.bytes.get(self.position..end).ok_or_else(|| {
            TxidPublicCacheError::MetadataMismatch(format!(
                "public_txid artifact ended while reading {field}"
            ))
        })?;
        self.position = end;
        Ok(value)
    }
}
