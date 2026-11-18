//! Manifest, catalog and chunk verification against trusted descriptors.

#[allow(clippy::wildcard_imports)]
use super::*;

pub fn validate_manifest(
    manifest: &IndexedArtifactManifest,
    config: &IndexedArtifactSourceConfig,
    expected_scope: &ChainScope,
    last_accepted_sequence: Option<u64>,
    now: SystemTime,
) -> Result<(), IndexedArtifactManifestError> {
    if manifest.format_version != INDEXED_ARTIFACT_MANIFEST_FORMAT_VERSION {
        return Err(IndexedArtifactManifestError::UnsupportedManifestVersion {
            version: manifest.format_version,
        });
    }
    manifest.verify_trusted_signature(&config.trusted_publisher_pubkey.0)?;
    validate_manifest_sequence(manifest.sequence, last_accepted_sequence)?;
    validate_manifest_freshness(
        manifest.sequence,
        manifest.issued_at_ms,
        last_accepted_sequence,
        config.max_manifest_age,
        now,
    )?;
    validate_manifest_scope(manifest, expected_scope)
}

pub fn verify_catalog_bytes(
    descriptor: &IndexedArtifactDescriptor,
    bytes: &[u8],
) -> Result<IndexedArtifactCatalog, IndexedArtifactManifestError> {
    validate_catalog_descriptor_for_expansion(descriptor)?;
    let actual_size =
        u64::try_from(bytes.len()).map_err(|_| IndexedArtifactManifestError::ByteSizeOverflow)?;
    if actual_size != descriptor.byte_size {
        return Err(IndexedArtifactManifestError::ArtifactByteSizeMismatch {
            cid: descriptor.cid.clone(),
            expected: descriptor.byte_size,
            actual: actual_size,
        });
    }
    let actual_hash = Sha256::digest(bytes);
    if actual_hash.as_slice() != descriptor.sha256.as_slice() {
        return Err(IndexedArtifactManifestError::ArtifactHashMismatch {
            cid: descriptor.cid.clone(),
            expected: hex::encode_prefixed(descriptor.sha256.as_slice()),
            actual: hex::encode_prefixed(actual_hash),
        });
    }

    let catalog: IndexedArtifactCatalog = serde_json::from_slice(bytes)?;
    if catalog.format_version != INDEXED_ARTIFACT_CATALOG_FORMAT_VERSION {
        return Err(IndexedArtifactManifestError::UnsupportedCatalogVersion {
            version: catalog.format_version,
        });
    }
    if catalog.dataset_kind != descriptor.dataset_kind {
        return Err(IndexedArtifactManifestError::CatalogDatasetMismatch {
            expected: descriptor.dataset_kind,
            actual: catalog.dataset_kind,
        });
    }
    if catalog.scope != descriptor.scope {
        return Err(IndexedArtifactManifestError::CatalogScopeMismatch {
            expected: format_scope(&descriptor.scope),
            actual: format_scope(&catalog.scope),
        });
    }
    for chunk in &catalog.chunks {
        validate_chunk_descriptor_scope(descriptor, chunk)?;
    }
    validate_catalog_descriptor_aggregate(descriptor, &catalog.chunks)?;
    Ok(catalog)
}

pub fn verify_chunk_bytes(
    descriptor: IndexedArtifactDescriptor,
    bytes: Vec<u8>,
) -> Result<VerifiedIndexedArtifactChunk, IndexedArtifactManifestError> {
    let actual_size =
        u64::try_from(bytes.len()).map_err(|_| IndexedArtifactManifestError::ByteSizeOverflow)?;
    if actual_size != descriptor.byte_size {
        return Err(IndexedArtifactManifestError::ArtifactByteSizeMismatch {
            cid: descriptor.cid,
            expected: descriptor.byte_size,
            actual: actual_size,
        });
    }
    let actual_hash = Sha256::digest(&bytes);
    if actual_hash.as_slice() != descriptor.sha256.as_slice() {
        return Err(IndexedArtifactManifestError::ArtifactHashMismatch {
            cid: descriptor.cid,
            expected: hex::encode_prefixed(descriptor.sha256.as_slice()),
            actual: hex::encode_prefixed(actual_hash),
        });
    }
    Ok(VerifiedIndexedArtifactChunk { descriptor, bytes })
}

pub fn decode_indexed_artifact_chunk(
    chunk: &VerifiedIndexedArtifactChunk,
) -> Result<IndexedArtifactChunkEnvelope, IndexedArtifactManifestError> {
    railgun_indexed_artifacts::decode_chunk_bytes(&chunk.descriptor, &chunk.bytes)
        .map_err(Into::into)
}

fn validate_chunk_descriptor_scope(
    catalog: &IndexedArtifactDescriptor,
    chunk: &IndexedArtifactDescriptor,
) -> Result<(), IndexedArtifactManifestError> {
    if chunk.dataset_kind != catalog.dataset_kind {
        return Err(IndexedArtifactManifestError::CatalogChunkDatasetMismatch {
            expected: catalog.dataset_kind,
            actual: chunk.dataset_kind,
        });
    }
    if chunk.scope != catalog.scope {
        return Err(IndexedArtifactManifestError::CatalogScopeMismatch {
            expected: format_scope(&catalog.scope),
            actual: format_scope(&chunk.scope),
        });
    }
    if chunk.range.kind != catalog.range.kind
        || chunk.range.start < catalog.range.start
        || chunk.range.end > catalog.range.end
    {
        return Err(IndexedArtifactManifestError::CatalogChunkRangeMismatch {
            catalog_start: catalog.range.start,
            catalog_end: catalog.range.end,
            chunk_start: chunk.range.start,
            chunk_end: chunk.range.end,
        });
    }
    chunk.decoded_envelope_byte_size_charge()?;
    Ok(())
}

pub(super) fn validate_catalog_descriptor_for_expansion(
    descriptor: &IndexedArtifactDescriptor,
) -> Result<(), IndexedArtifactManifestError> {
    if descriptor.range.start > descriptor.range.end {
        return Err(
            IndexedArtifactManifestError::CatalogDescriptorInvalidRange {
                cid: descriptor.cid.clone(),
                start: descriptor.range.start,
                end: descriptor.range.end,
            },
        );
    }
    Ok(())
}

fn validate_catalog_descriptor_aggregate(
    descriptor: &IndexedArtifactDescriptor,
    chunks: &[IndexedArtifactDescriptor],
) -> Result<(), IndexedArtifactManifestError> {
    if chunks.is_empty() {
        if descriptor.row_count != 0 {
            return Err(IndexedArtifactManifestError::EmptyCatalogRowCountMismatch {
                cid: descriptor.cid.clone(),
                row_count: descriptor.row_count,
            });
        }
        return Ok(());
    }

    let mut aggregate_start = u64::MAX;
    let mut aggregate_end = 0_u64;
    let mut aggregate_row_count = 0_u64;
    for chunk in chunks {
        if chunk.range.start > chunk.range.end {
            return Err(IndexedArtifactManifestError::CatalogChunkInvalidRange {
                cid: chunk.cid.clone(),
                start: chunk.range.start,
                end: chunk.range.end,
            });
        }
        aggregate_start = aggregate_start.min(chunk.range.start);
        aggregate_end = aggregate_end.max(chunk.range.end);
        aggregate_row_count = aggregate_row_count
            .checked_add(chunk.row_count)
            .ok_or_else(
                || IndexedArtifactManifestError::CatalogAggregateRowCountOverflow {
                    cid: descriptor.cid.clone(),
                },
            )?;
    }

    let allows_sparse_chunks = descriptor.dataset_kind == IndexedDatasetKind::WalletScan
        && descriptor.range.kind == IndexedArtifactRangeKind::Block;
    if !allows_sparse_chunks
        && (descriptor.range.start != aggregate_start || descriptor.range.end != aggregate_end)
    {
        return Err(
            IndexedArtifactManifestError::CatalogAggregateRangeMismatch {
                expected_start: descriptor.range.start,
                expected_end: descriptor.range.end,
                actual_start: aggregate_start,
                actual_end: aggregate_end,
            },
        );
    }
    if descriptor.row_count != aggregate_row_count {
        return Err(
            IndexedArtifactManifestError::CatalogAggregateRowCountMismatch {
                expected: descriptor.row_count,
                actual: aggregate_row_count,
            },
        );
    }
    Ok(())
}

const fn validate_manifest_sequence(
    sequence: u64,
    last_accepted_sequence: Option<u64>,
) -> Result<(), IndexedArtifactManifestError> {
    if let Some(previous) = last_accepted_sequence
        && sequence < previous
    {
        return Err(IndexedArtifactManifestError::ManifestSequenceRollback {
            previous,
            received: sequence,
        });
    }
    Ok(())
}

fn validate_manifest_freshness(
    sequence: u64,
    issued_at_ms: u64,
    last_accepted_sequence: Option<u64>,
    max_age: Option<Duration>,
    now: SystemTime,
) -> Result<(), IndexedArtifactManifestError> {
    if last_accepted_sequence.is_some_and(|previous| sequence <= previous) {
        return Ok(());
    }
    let Some(max_age) = max_age else {
        return Ok(());
    };
    let issued_at = UNIX_EPOCH + Duration::from_millis(issued_at_ms);
    let age = now
        .duration_since(issued_at)
        .map_err(|_| IndexedArtifactManifestError::ManifestIssuedInFuture)?;
    if age > max_age {
        return Err(IndexedArtifactManifestError::ManifestStale { age, max: max_age });
    }
    Ok(())
}

fn validate_manifest_scope(
    manifest: &IndexedArtifactManifest,
    expected_scope: &ChainScope,
) -> Result<(), IndexedArtifactManifestError> {
    let chain = manifest
        .chains
        .iter()
        .find(|entry| entry.scope == *expected_scope)
        .ok_or_else(|| IndexedArtifactManifestError::MissingChainScope {
            chain_id: expected_scope.chain_id,
            railgun_contract: hex::encode_prefixed(expected_scope.railgun_contract.as_slice()),
        })?;
    for catalog in &chain.catalogs {
        if catalog.scope != chain.scope {
            return Err(IndexedArtifactManifestError::CatalogScopeMismatch {
                expected: format_scope(&chain.scope),
                actual: format_scope(&catalog.scope),
            });
        }
    }
    Ok(())
}
