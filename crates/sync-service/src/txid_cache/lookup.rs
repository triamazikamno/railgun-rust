use super::{
    DbStore, FixedBytes, TREE_LEAF_COUNT, TxidPublicCacheEntry, TxidPublicCacheError,
    TxidPublicCacheKey, TxidPublicCacheManifest, TxidPublicCacheRow, U256,
};

pub(crate) fn validated_transactions_for_outer_hash(
    db: &DbStore,
    key: TxidPublicCacheKey<'_>,
    transaction_hash: FixedBytes<32>,
) -> Result<Vec<TxidPublicCacheEntry>, TxidPublicCacheError> {
    let cache = super::TxidPublicCache::new(db, key);
    let manifest = cache
        .load_manifest()?
        .ok_or(TxidPublicCacheError::CacheNotReady {
            next_index: 0,
            required_index: 0,
        })?;
    manifest.validate_for(key)?;
    let latest_validated_txid_index =
        manifest
            .latest_validated_txid_index
            .ok_or(TxidPublicCacheError::CacheNotReady {
                next_index: 0,
                required_index: 0,
            })?;
    if manifest
        .validated_cached_txid_index
        .is_none_or(|index| index < latest_validated_txid_index)
    {
        return Err(TxidPublicCacheError::CacheNotReady {
            next_index: manifest
                .validated_cached_txid_index
                .map_or(0, |index| index.saturating_add(1)),
            required_index: latest_validated_txid_index,
        });
    }

    let mut matches = Vec::new();
    let mut expected_index = 0_u64;
    for page_ref in &manifest.pages {
        if expected_index > latest_validated_txid_index {
            break;
        }
        let page_end = page_ref
            .start_index
            .checked_add(page_ref.row_count)
            .ok_or_else(|| {
                TxidPublicCacheError::MetadataMismatch(
                    "validated TXID page range overflows".to_string(),
                )
            })?;
        if page_ref.start_index < expected_index || page_end <= expected_index {
            return Err(TxidPublicCacheError::MetadataMismatch(format!(
                "validated TXID page coverage overlaps at index {expected_index}"
            )));
        }
        if page_ref.start_index > expected_index {
            return Err(TxidPublicCacheError::MissingLeaf {
                index: expected_index,
            });
        }

        let page = page_ref.read(db, manifest.cache_key())?;
        for row in page.rows {
            if row.txid_index != expected_index {
                return if row.txid_index < expected_index {
                    Err(TxidPublicCacheError::MetadataMismatch(format!(
                        "validated TXID rows overlap at index {expected_index}"
                    )))
                } else {
                    Err(TxidPublicCacheError::MissingLeaf {
                        index: expected_index,
                    })
                };
            }
            let is_latest = row.txid_index == latest_validated_txid_index;
            if row.transaction.transaction_hash == transaction_hash {
                matches.push(row.into());
            }
            if is_latest {
                return Ok(matches);
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

pub(crate) fn artifact_bounded_transactions_for_outer_hash(
    db: &DbStore,
    key: TxidPublicCacheKey<'_>,
    transaction_hash: FixedBytes<32>,
) -> Result<Vec<TxidPublicCacheEntry>, TxidPublicCacheError> {
    let cache = super::TxidPublicCache::new(db, key);
    let manifest = cache
        .load_manifest()?
        .ok_or(TxidPublicCacheError::CacheNotReady {
            next_index: 0,
            required_index: 0,
        })?;
    manifest.validate_for(key)?;
    let bound = manifest
        .artifact_cached_txid_index
        .ok_or(TxidPublicCacheError::CacheNotReady {
            next_index: 0,
            required_index: 0,
        })?;
    let mut matches = Vec::new();
    let mut expected_index = 0_u64;
    for page_ref in &manifest.pages {
        if expected_index > bound {
            break;
        }
        let page_end = page_ref
            .start_index
            .checked_add(page_ref.row_count)
            .ok_or_else(|| {
                TxidPublicCacheError::MetadataMismatch(
                    "artifact-bounded TXID page range overflows".to_string(),
                )
            })?;
        if page_ref.start_index < expected_index || page_end <= expected_index {
            return Err(TxidPublicCacheError::MetadataMismatch(format!(
                "artifact-bounded TXID page coverage overlaps at index {expected_index}"
            )));
        }
        if page_ref.start_index > expected_index {
            return Err(TxidPublicCacheError::MissingLeaf {
                index: expected_index,
            });
        }
        let page = page_ref.read(db, manifest.cache_key())?;
        for row in page.rows {
            if row.txid_index > bound {
                break;
            }
            if row.txid_index != expected_index {
                return if row.txid_index < expected_index {
                    Err(TxidPublicCacheError::MetadataMismatch(format!(
                        "artifact-bounded TXID rows overlap at index {expected_index}"
                    )))
                } else {
                    Err(TxidPublicCacheError::MissingLeaf {
                        index: expected_index,
                    })
                };
            }
            if row.transaction.transaction_hash == transaction_hash {
                matches.push(row.clone().into());
            }
            expected_index = expected_index.checked_add(1).ok_or_else(|| {
                TxidPublicCacheError::MetadataMismatch("txid index overflow".to_string())
            })?;
            if expected_index > bound {
                break;
            }
        }
    }
    if expected_index <= bound {
        return Err(TxidPublicCacheError::MissingLeaf {
            index: expected_index,
        });
    }
    Ok(matches)
}

pub(super) fn find_target_row(
    manifest: &TxidPublicCacheManifest,
    db: &DbStore,
    expected_leaf_hash: FixedBytes<32>,
    output_start_global: u128,
) -> Result<TxidPublicCacheRow, TxidPublicCacheError> {
    let mut found = None;
    for page_ref in &manifest.pages {
        let page = page_ref.read(db, manifest.cache_key())?;
        for row in page.rows {
            if row.txid_leaf_hash == expected_leaf_hash
                && row.transaction.output_start_global() == output_start_global
            {
                if found.is_some() {
                    return Err(TxidPublicCacheError::AmbiguousTarget);
                }
                found = Some(row);
            }
        }
    }
    found.ok_or(TxidPublicCacheError::MissingTarget)
}

pub(super) fn read_tree_leaves(
    manifest: &TxidPublicCacheManifest,
    db: &DbStore,
    tree: u64,
    leaf_count: u64,
) -> Result<Vec<U256>, TxidPublicCacheError> {
    let start = tree.saturating_mul(TREE_LEAF_COUNT);
    let mut leaves = vec![None; leaf_count as usize];
    for page_ref in &manifest.pages {
        let page_end = page_ref.start_index.saturating_add(page_ref.row_count);
        let range_end = start.saturating_add(leaf_count);
        if page_end <= start || page_ref.start_index >= range_end {
            continue;
        }
        let page = page_ref.read(db, manifest.cache_key())?;
        for row in page.rows {
            if row.txid_index >= start && row.txid_index < range_end {
                let index = (row.txid_index - start) as usize;
                leaves[index] = Some(U256::from_be_bytes(row.txid_leaf_hash.0));
            }
        }
    }
    leaves
        .into_iter()
        .enumerate()
        .map(|(index, leaf)| {
            leaf.ok_or_else(|| TxidPublicCacheError::MissingLeaf {
                index: start + index as u64,
            })
        })
        .collect()
}
