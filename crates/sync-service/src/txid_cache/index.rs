use super::*;

pub(super) fn write_blob_file(
    db: &DbStore,
    path: &Path,
    bytes: &[u8],
) -> Result<(), TxidPublicCacheError> {
    db.ensure_blob_dir(TXID_CACHE_BLOB_KIND)?;
    let nonce = TXID_CACHE_TEMP_COUNTER.fetch_add(1, Ordering::Relaxed);
    let temp_path = path.with_extension(format!("tmp.{}.{nonce}", std::process::id()));
    fs::write(&temp_path, bytes)?;
    fs::rename(temp_path, path)?;
    Ok(())
}

impl TxidPublicCachePageRef {
    pub(super) fn read(
        &self,
        db: &DbStore,
        key: TxidPublicCacheKey<'_>,
    ) -> Result<TxidPublicCachePage, TxidPublicCacheError> {
        let bytes = fs::read(db.resolve_path(&self.relative_path))?;
        let page: TxidPublicCachePage = rmp_serde::from_slice(&bytes)?;
        if page.format_version != TXID_CACHE_FORMAT_VERSION
            || page.chain_type != key.chain_type
            || page.chain_id != key.chain_id
            || page.railgun_contract != key.railgun_contract
            || page.txid_version != key.txid_version
            || page.start_index != self.start_index
            || page.rows.len() as u64 != self.row_count
        {
            return Err(TxidPublicCacheError::MetadataMismatch(
                "page metadata mismatch".to_string(),
            ));
        }
        Ok(page)
    }
}

pub(super) fn update_index_for_page(
    permit: &TxidPublicCacheWritePermit<'_>,
    page: &TxidPublicCachePage,
) -> Result<(), TxidPublicCacheError> {
    let db = permit.db();
    let key = permit.key();
    let mut entries_by_shard: BTreeMap<u8, Vec<TxidPublicCacheIndexEntry>> = BTreeMap::new();
    for (row_offset, row) in page.rows.iter().enumerate() {
        entries_by_shard
            .entry(index_shard(row.transaction.transaction_hash))
            .or_default()
            .push(TxidPublicCacheIndexEntry {
                transaction_hash: row.transaction.transaction_hash,
                txid_index: row.txid_index,
                page_start_index: page.start_index,
                row_offset: row_offset as u64,
            });
    }
    let page_end = page.start_index.saturating_add(page.rows.len() as u64);
    for (shard, mut new_entries) in entries_by_shard {
        let mut index = load_index_shard(db, key, shard)?;
        index
            .entries
            .retain(|entry| entry.txid_index < page.start_index || entry.txid_index >= page_end);
        index.entries.append(&mut new_entries);
        index.entries.sort_by_key(|entry| entry.txid_index);
        write_index_shard(permit, &index)?;
    }
    Ok(())
}

pub(super) fn rebuild_index_for_manifest(
    manifest: &TxidPublicCacheManifest,
    permit: &TxidPublicCacheWritePermit<'_>,
) -> Result<(), TxidPublicCacheError> {
    let db = permit.db();
    clear_index_shards(permit)?;
    for page_ref in &manifest.pages {
        let page = page_ref.read(db, manifest.cache_key())?;
        update_index_for_page(permit, &page)?;
    }
    Ok(())
}

pub(super) fn clear_index_shards(
    permit: &TxidPublicCacheWritePermit<'_>,
) -> Result<(), TxidPublicCacheError> {
    let db = permit.db();
    let key = permit.key();
    for shard in u8::MIN..=u8::MAX {
        let path = db.blob_path(TXID_CACHE_BLOB_KIND, &index_shard_file_name(key, shard));
        match fs::remove_file(path) {
            Ok(()) => {}
            Err(err) if err.kind() == ErrorKind::NotFound => {}
            Err(err) => return Err(err.into()),
        }
    }
    Ok(())
}

#[cfg(test)]
pub(super) fn index_entries_for_hash(
    db: &DbStore,
    key: TxidPublicCacheKey<'_>,
    tx_hash: FixedBytes<32>,
) -> Result<Vec<TxidPublicCacheIndexEntry>, TxidPublicCacheError> {
    let index = load_index_shard(db, key, index_shard(tx_hash))?;
    Ok(index
        .entries
        .into_iter()
        .filter(|entry| entry.transaction_hash == tx_hash)
        .collect())
}

pub(super) fn load_index_shard(
    db: &DbStore,
    key: TxidPublicCacheKey<'_>,
    shard: u8,
) -> Result<TxidPublicCacheIndexShard, TxidPublicCacheError> {
    let path = db.blob_path(TXID_CACHE_BLOB_KIND, &index_shard_file_name(key, shard));
    match fs::read(path) {
        Ok(bytes) => {
            let index: TxidPublicCacheIndexShard = rmp_serde::from_slice(&bytes)?;
            if index.format_version == TXID_CACHE_FORMAT_VERSION && index.shard == shard {
                if index.chain_type == key.chain_type
                    && index.chain_id == key.chain_id
                    && index.railgun_contract == key.railgun_contract
                    && index.txid_version == key.txid_version
                {
                    Ok(index)
                } else {
                    Ok(empty_index_shard(key, shard))
                }
            } else {
                Ok(empty_index_shard(key, shard))
            }
        }
        Err(err) if err.kind() == ErrorKind::NotFound => Ok(empty_index_shard(key, shard)),
        Err(err) => Err(err.into()),
    }
}

pub(super) fn write_index_shard(
    permit: &TxidPublicCacheWritePermit<'_>,
    index: &TxidPublicCacheIndexShard,
) -> Result<(), TxidPublicCacheError> {
    let db = permit.db();
    let key = permit.key();
    if index.format_version != TXID_CACHE_FORMAT_VERSION
        || index.chain_type != key.chain_type
        || index.chain_id != key.chain_id
        || index.railgun_contract != key.railgun_contract
        || index.txid_version != key.txid_version
    {
        return Err(TxidPublicCacheError::MetadataMismatch(
            "index shard cache identity mismatch".to_string(),
        ));
    }
    let path = db.blob_path(
        TXID_CACHE_BLOB_KIND,
        &index_shard_file_name(key, index.shard),
    );
    let bytes = rmp_serde::to_vec_named(index)?;
    write_blob_file(db, &path, &bytes)
}

pub(super) fn empty_index_shard(
    key: TxidPublicCacheKey<'_>,
    shard: u8,
) -> TxidPublicCacheIndexShard {
    TxidPublicCacheIndexShard {
        format_version: TXID_CACHE_FORMAT_VERSION,
        chain_type: key.chain_type,
        chain_id: key.chain_id,
        railgun_contract: key.railgun_contract,
        txid_version: key.txid_version.to_string(),
        shard,
        entries: Vec::new(),
    }
}

pub(super) const fn index_shard(tx_hash: FixedBytes<32>) -> u8 {
    tx_hash.0[0]
}
