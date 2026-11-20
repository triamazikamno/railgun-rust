#[allow(clippy::wildcard_imports)]
use super::*;

impl TryFrom<&VerifiedIndexedArtifactChunk> for Vec<TxidPublicCachePage> {
    type Error = TxidPublicCacheError;

    fn try_from(chunk: &VerifiedIndexedArtifactChunk) -> Result<Self, Self::Error> {
        materialize_artifact_pages(chunk, TXID_CACHE_PAGE_SIZE)
    }
}

pub(super) fn materialize_artifact_pages(
    chunk: &VerifiedIndexedArtifactChunk,
    page_size: NonZeroUsize,
) -> Result<Vec<TxidPublicCachePage>, TxidPublicCacheError> {
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
    let mut rows = PublicTxidCursor::new(payload).read_rows(
        envelope.header.range.start,
        envelope.header.range.end,
        envelope.header.row_count,
    )?;
    if envelope
        .header
        .sections
        .iter()
        .any(|section| section.section_id == PUBLIC_TXID_UNSHIELD_PREIMAGE_SECTION_ID)
    {
        let payload = envelope
            .section_payload(PUBLIC_TXID_UNSHIELD_PREIMAGE_SECTION_ID)
            .map_err(crate::indexed_artifacts::IndexedArtifactManifestError::from)?;
        attach_unshield_preimages(payload, &mut rows)?;
    }
    if chunk.descriptor.metadata.stream_partition.is_some() {
        return Err(TxidPublicCacheError::MetadataMismatch(
            "format-v1 public_txid artifact has unsupported stream partition metadata".to_string(),
        ));
    }
    let key = TxidPublicCacheKey {
        chain_type: 0,
        chain_id: chunk.descriptor.scope.chain_id,
        railgun_contract: chunk.descriptor.scope.railgun_contract,
        txid_version: DEFAULT_TXID_VERSION,
    };
    TxidPublicCachePage::pages_from_rows(key, rows, page_size)
}

pub(super) fn verify_declared_merkle_root(
    expected: Option<&FixedBytes<32>>,
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

pub(super) fn truncate_pages_to_range(
    mut pages: Vec<TxidPublicCachePage>,
    range_start: u64,
    range_end: u64,
) -> Result<Vec<TxidPublicCachePage>, TxidPublicCacheError> {
    for page in &mut pages {
        page.rows
            .retain(|row| row.txid_index >= range_start && row.txid_index <= range_end);
    }
    pages.retain(|page| !page.rows.is_empty());
    for page in &mut pages {
        page.start_index = page
            .rows
            .first()
            .ok_or_else(|| {
                TxidPublicCacheError::MetadataMismatch(
                    "truncated public_txid page cannot be empty".to_string(),
                )
            })?
            .txid_index;
    }
    Ok(pages)
}
