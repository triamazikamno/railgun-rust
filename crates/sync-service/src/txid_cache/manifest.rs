use super::{
    BlobMeta, DbStore, Digest, ErrorKind, FixedBytes, Sha256, TXID_CACHE_BLOB_KIND,
    TXID_CACHE_FORMAT_VERSION, TXID_CACHE_PAGE_SIZE, TxidPublicCache, TxidPublicCacheError,
    TxidPublicCacheKey, TxidPublicCacheManifest, TxidPublicCachePage, TxidPublicCachePageRef,
    TxidPublicCacheRow, TxidPublicCacheWritePermit, TxidPublicCheckpoint,
    TxidPublicCheckpointSource, cache_id, fs, manifest_file_name, now_epoch_secs, page_file_name,
    staged_page_file_name, warn, write_blob_file,
};
use std::collections::BTreeMap;

#[derive(Debug, Clone, Copy)]
enum TxidPublicCachePageWriteMode {
    Stable,
    StagedPage,
}

impl From<TxidPublicCacheKey<'_>> for TxidPublicCacheManifest {
    fn from(key: TxidPublicCacheKey<'_>) -> Self {
        Self {
            format_version: TXID_CACHE_FORMAT_VERSION,
            chain_type: key.chain_type,
            chain_id: key.chain_id,
            railgun_contract: key.railgun_contract,
            txid_version: key.txid_version.to_string(),
            page_size: TXID_CACHE_PAGE_SIZE.get(),
            next_txid_index: 0,
            latest_validated_txid_index: None,
            latest_validated_merkleroot: None,
            validated_cached_txid_index: None,
            artifact_cached_txid_index: None,
            checkpoints: BTreeMap::new(),
            pages: Vec::new(),
        }
    }
}

impl TxidPublicCache<'_> {
    pub(super) fn load_or_new_manifest(
        &self,
    ) -> Result<TxidPublicCacheManifest, TxidPublicCacheError> {
        if let Some(manifest) = self.load_manifest()? {
            match manifest.validate_for(self.key) {
                Ok(()) => return Ok(manifest),
                Err(err) => {
                    warn!(
                        ?err,
                        chain_id = self.key.chain_id,
                        txid_version = self.key.txid_version,
                        "resetting incompatible TXID public cache manifest"
                    );
                }
            }
        }
        Ok(self.key.into())
    }

    pub(super) fn load_manifest(
        &self,
    ) -> Result<Option<TxidPublicCacheManifest>, TxidPublicCacheError> {
        let id = cache_id(self.key);
        let Some(meta) = self.db.get_blob_meta(TXID_CACHE_BLOB_KIND, &id)? else {
            return Ok(None);
        };
        if meta.format_version != TXID_CACHE_FORMAT_VERSION {
            return Ok(None);
        }
        let path = self.db.resolve_path(&meta.relative_path);
        match fs::read(path) {
            Ok(bytes) => Ok(Some(rmp_serde::from_slice(&bytes)?)),
            Err(err) if err.kind() == ErrorKind::NotFound => Ok(None),
            Err(err) => Err(err.into()),
        }
    }
}

impl TxidPublicCacheManifest {
    fn validate_page_coverage(page: &TxidPublicCachePage) -> Result<u64, TxidPublicCacheError> {
        if page.rows.is_empty() {
            return Err(TxidPublicCacheError::MetadataMismatch(
                "TXID public cache page cannot be empty".to_string(),
            ));
        }
        for (offset, row) in page.rows.iter().enumerate() {
            let expected_index = page
                .start_index
                .checked_add(u64::try_from(offset).map_err(|_| {
                    TxidPublicCacheError::MetadataMismatch(
                        "TXID public cache page row index overflows".to_string(),
                    )
                })?)
                .ok_or_else(|| {
                    TxidPublicCacheError::MetadataMismatch(
                        "TXID public cache page row index overflows".to_string(),
                    )
                })?;
            if row.txid_index != expected_index {
                return Err(TxidPublicCacheError::MetadataMismatch(format!(
                    "TXID public cache page row coverage expected index {expected_index}, got {}",
                    row.txid_index
                )));
            }
        }
        page.start_index
            .checked_add(page.rows.len() as u64)
            .ok_or_else(|| {
                TxidPublicCacheError::MetadataMismatch(
                    "TXID public cache page range overflows".to_string(),
                )
            })
    }

    pub(super) fn validate_for(
        &self,
        key: TxidPublicCacheKey<'_>,
    ) -> Result<(), TxidPublicCacheError> {
        if self.format_version != TXID_CACHE_FORMAT_VERSION {
            return Err(TxidPublicCacheError::MetadataMismatch(format!(
                "unsupported format version {}",
                self.format_version
            )));
        }
        if self.chain_type != key.chain_type
            || self.chain_id != key.chain_id
            || self.railgun_contract != key.railgun_contract
            || self.txid_version != key.txid_version
        {
            return Err(TxidPublicCacheError::MetadataMismatch(
                "cache identity mismatch".to_string(),
            ));
        }
        for (index, checkpoint) in &self.checkpoints {
            if *index != checkpoint.txid_index {
                return Err(TxidPublicCacheError::MetadataMismatch(
                    "TXID checkpoint index mismatch".to_string(),
                ));
            }
            if *index >= self.next_txid_index {
                return Err(TxidPublicCacheError::MetadataMismatch(
                    "TXID checkpoint is beyond cached rows".to_string(),
                ));
            }
        }
        if let Some(index) = self.latest_validated_txid_index
            && let Some(root) = self.latest_validated_merkleroot
            && self
                .checkpoints
                .get(&index)
                .is_some_and(|checkpoint| checkpoint.merkleroot != root)
        {
            return Err(TxidPublicCacheError::RootMismatch);
        }
        Ok(())
    }

    pub(super) fn cache_key(&self) -> TxidPublicCacheKey<'_> {
        TxidPublicCacheKey {
            chain_type: self.chain_type,
            chain_id: self.chain_id,
            railgun_contract: self.railgun_contract,
            txid_version: &self.txid_version,
        }
    }

    pub(super) fn write_to(
        &self,
        permit: &TxidPublicCacheWritePermit<'_>,
    ) -> Result<(), TxidPublicCacheError> {
        let db = permit.db();
        let key = permit.key();
        self.validate_for(key)?;
        let name = manifest_file_name(key);
        let path = db.blob_path(TXID_CACHE_BLOB_KIND, &name);
        let bytes = rmp_serde::to_vec_named(self)?;
        write_blob_file(db, &path, &bytes)?;
        let now = now_epoch_secs()?;
        let id = cache_id(key);
        let existing = db.get_blob_meta(TXID_CACHE_BLOB_KIND, &id)?;
        db.put_blob_meta(
            TXID_CACHE_BLOB_KIND,
            &id,
            &BlobMeta {
                format_version: TXID_CACHE_FORMAT_VERSION,
                relative_path: DbStore::relative_blob_path(TXID_CACHE_BLOB_KIND, &name),
                content_hash: Sha256::digest(&bytes).into(),
                source_hash: None,
                source_sequence: None,
                created_at: existing.map_or(now, |meta| meta.created_at),
                updated_at: now,
                last_accessed_at: now,
                last_block: None,
            },
        )?;
        Ok(())
    }

    pub(super) fn insert_checkpoint(
        &mut self,
        txid_index: u64,
        merkleroot: FixedBytes<32>,
        source: TxidPublicCheckpointSource,
    ) -> Result<(), TxidPublicCacheError> {
        if txid_index >= self.next_txid_index {
            return Err(TxidPublicCacheError::MissingLeaf { index: txid_index });
        }
        if let Some(existing) = self.checkpoints.get(&txid_index) {
            if existing.merkleroot != merkleroot {
                return Err(TxidPublicCacheError::RootMismatch);
            }
            return Ok(());
        }
        self.checkpoints.insert(
            txid_index,
            TxidPublicCheckpoint {
                txid_index,
                merkleroot,
                source,
            },
        );
        Ok(())
    }

    pub(super) fn checkpoint_root(
        &self,
        txid_index: u64,
    ) -> Result<FixedBytes<32>, TxidPublicCacheError> {
        self.checkpoints
            .get(&txid_index)
            .map(|checkpoint| checkpoint.merkleroot)
            .ok_or(TxidPublicCacheError::CacheNotReady {
                next_index: self
                    .checkpoints
                    .keys()
                    .next_back()
                    .map_or(0, |index| index.saturating_add(1)),
                required_index: txid_index,
            })
    }

    pub(super) fn invalidate_checkpoints_from(&mut self, mutation_start: u64) {
        self.checkpoints
            .retain(|txid_index, _| *txid_index < mutation_start);
    }

    pub(super) fn append_page_after_prefix_validation(
        &mut self,
        permit: &TxidPublicCacheWritePermit<'_>,
        page: &TxidPublicCachePage,
    ) -> Result<(), TxidPublicCacheError> {
        if page.start_index != self.next_txid_index {
            return Err(TxidPublicCacheError::MetadataMismatch(
                "TXID public cache append is not an exact next-index append".to_string(),
            ));
        }
        page.validate_for(self.cache_key())?;
        let page_end = Self::validate_page_coverage(page)?;
        self.append_page_after_validation_with_mode(
            permit,
            page,
            page_end,
            TxidPublicCachePageWriteMode::Stable,
        )
    }

    pub(super) fn append_staged_page(
        &mut self,
        permit: &TxidPublicCacheWritePermit<'_>,
        page: &TxidPublicCachePage,
    ) -> Result<(), TxidPublicCacheError> {
        self.append_page_with_mode(permit, page, TxidPublicCachePageWriteMode::StagedPage)
    }

    fn append_page_with_mode(
        &mut self,
        permit: &TxidPublicCacheWritePermit<'_>,
        page: &TxidPublicCachePage,
        mode: TxidPublicCachePageWriteMode,
    ) -> Result<(), TxidPublicCacheError> {
        if page.start_index != self.next_txid_index {
            return Err(TxidPublicCacheError::MetadataMismatch(
                "TXID public cache append is not an exact next-index append".to_string(),
            ));
        }
        let page_end = Self::validate_page_coverage(page)?;
        self.append_page_after_validation_with_mode(permit, page, page_end, mode)
    }

    fn append_page_after_validation_with_mode(
        &mut self,
        permit: &TxidPublicCacheWritePermit<'_>,
        page: &TxidPublicCachePage,
        page_end: u64,
        mode: TxidPublicCachePageWriteMode,
    ) -> Result<(), TxidPublicCacheError> {
        let page_ref = page.write_with_mode(permit, mode)?;
        self.next_txid_index = page_end;
        self.pages.push(page_ref);
        Ok(())
    }

    pub(super) fn insert_or_replace_staged_page(
        &mut self,
        permit: &TxidPublicCacheWritePermit<'_>,
        page: &TxidPublicCachePage,
    ) -> Result<(), TxidPublicCacheError> {
        self.replace_page_with_mode(permit, page, TxidPublicCachePageWriteMode::StagedPage)
    }

    fn replace_page_with_mode(
        &mut self,
        permit: &TxidPublicCacheWritePermit<'_>,
        page: &TxidPublicCachePage,
        mode: TxidPublicCachePageWriteMode,
    ) -> Result<(), TxidPublicCacheError> {
        let db = permit.db();
        page.validate_for(self.cache_key())?;
        let page_end = Self::validate_page_coverage(page)?;
        if page.start_index > self.next_txid_index {
            return Err(TxidPublicCacheError::MissingLeaf {
                index: self.next_txid_index,
            });
        }
        let mut pages = Vec::with_capacity(self.pages.len() + 1);
        for page_ref in self.pages.iter().cloned() {
            let existing_end = page_ref
                .start_index
                .checked_add(page_ref.row_count)
                .ok_or_else(|| {
                    TxidPublicCacheError::MetadataMismatch(
                        "TXID public cache page range overflows".to_string(),
                    )
                })?;
            if existing_end <= page.start_index || page_ref.start_index >= page_end {
                pages.push(page_ref);
                continue;
            }

            let existing = page_ref.read(db, self.cache_key())?;
            let before_rows: Vec<_> = existing
                .rows
                .iter()
                .take_while(|row| row.txid_index < page.start_index)
                .cloned()
                .collect();
            if let Some(page_ref) =
                TxidPublicCachePage::write_rows_with_mode(permit, before_rows, mode)?
            {
                pages.push(page_ref);
            }

            let after_rows: Vec<_> = existing
                .rows
                .into_iter()
                .filter(|row| row.txid_index >= page_end)
                .collect();
            if let Some(page_ref) =
                TxidPublicCachePage::write_rows_with_mode(permit, after_rows, mode)?
            {
                pages.push(page_ref);
            }
        }

        pages.push(page.write_with_mode(permit, mode)?);
        pages.sort_by_key(|page_ref| page_ref.start_index);
        self.next_txid_index = self.next_txid_index.max(page_end);
        self.pages = pages;
        Ok(())
    }

    pub(super) fn validate_exact_append_start(
        &self,
        permit: &TxidPublicCacheWritePermit<'_>,
    ) -> Result<(), TxidPublicCacheError> {
        self.validate_published_manifest(permit.db())
    }

    pub(super) fn validate_published_manifest(
        &self,
        db: &DbStore,
    ) -> Result<(), TxidPublicCacheError> {
        if self.next_txid_index == 0 {
            if self.pages.is_empty() {
                return Ok(());
            }
            return Err(TxidPublicCacheError::MetadataMismatch(
                "TXID public cache manifest has pages beyond its published tip".to_string(),
            ));
        }
        for page_ref in &self.pages {
            let page_end = page_ref
                .start_index
                .checked_add(page_ref.row_count)
                .ok_or_else(|| {
                    TxidPublicCacheError::MetadataMismatch(
                        "TXID public cache page range overflows".to_string(),
                    )
                })?;
            if page_ref.start_index >= self.next_txid_index || page_end > self.next_txid_index {
                return Err(TxidPublicCacheError::MetadataMismatch(
                    "TXID public cache manifest has a referenced suffix beyond its published tip"
                        .to_string(),
                ));
            }
        }
        self.validate_published_prefix(db, self.next_txid_index - 1)
    }

    pub(super) fn validate_published_prefix(
        &self,
        db: &DbStore,
        target_index: u64,
    ) -> Result<(), TxidPublicCacheError> {
        if self.next_txid_index == 0 {
            return if target_index == u64::MAX {
                Ok(())
            } else {
                Err(TxidPublicCacheError::MissingLeaf { index: 0 })
            };
        }
        if target_index >= self.next_txid_index {
            return Err(TxidPublicCacheError::MissingLeaf {
                index: self.next_txid_index,
            });
        }

        let mut expected_index = 0_u64;
        for page_ref in &self.pages {
            page_ref
                .start_index
                .checked_add(page_ref.row_count)
                .ok_or_else(|| {
                    TxidPublicCacheError::MetadataMismatch(
                        "TXID public cache page range overflows".to_string(),
                    )
                })?;
            if page_ref.row_count == 0 {
                return Err(TxidPublicCacheError::MetadataMismatch(
                    "TXID public cache page cannot be empty".to_string(),
                ));
            }
            if page_ref.start_index < expected_index {
                return Err(TxidPublicCacheError::MetadataMismatch(format!(
                    "TXID public cache page coverage overlaps at index {expected_index}"
                )));
            }
            if page_ref.start_index > expected_index {
                return Err(TxidPublicCacheError::MissingLeaf {
                    index: expected_index,
                });
            }

            let page = page_ref.read(db, self.cache_key())?;
            page.validate_for(self.cache_key())?;
            if page.start_index != page_ref.start_index
                || page.rows.len() as u64 != page_ref.row_count
            {
                return Err(TxidPublicCacheError::MetadataMismatch(
                    "TXID public cache page reference does not match its payload".to_string(),
                ));
            }
            for row in page.rows {
                if row.txid_index != expected_index {
                    return Err(TxidPublicCacheError::MetadataMismatch(format!(
                        "TXID public cache row coverage expected index {expected_index}, got {}",
                        row.txid_index
                    )));
                }
                if expected_index == target_index {
                    return Ok(());
                }
                expected_index = expected_index.checked_add(1).ok_or_else(|| {
                    TxidPublicCacheError::MetadataMismatch(
                        "TXID public cache row index overflows".to_string(),
                    )
                })?;
            }
        }
        Err(TxidPublicCacheError::MissingLeaf {
            index: expected_index,
        })
    }
}

impl TxidPublicCachePage {
    fn write_with_mode(
        &self,
        permit: &TxidPublicCacheWritePermit<'_>,
        mode: TxidPublicCachePageWriteMode,
    ) -> Result<TxidPublicCachePageRef, TxidPublicCacheError> {
        let db = permit.db();
        let key = permit.key();
        self.validate_for(key)?;
        let name = match mode {
            TxidPublicCachePageWriteMode::Stable => page_file_name(key, self.start_index),
            TxidPublicCachePageWriteMode::StagedPage => {
                staged_page_file_name(key, self.start_index)
            }
        };
        let path = db.blob_path(TXID_CACHE_BLOB_KIND, &name);
        let bytes = rmp_serde::to_vec_named(self)?;
        write_blob_file(db, &path, &bytes)?;
        Ok(TxidPublicCachePageRef {
            start_index: self.start_index,
            row_count: self.rows.len() as u64,
            relative_path: DbStore::relative_blob_path(TXID_CACHE_BLOB_KIND, &name),
        })
    }

    fn write_rows_with_mode(
        permit: &TxidPublicCacheWritePermit<'_>,
        rows: Vec<TxidPublicCacheRow>,
        mode: TxidPublicCachePageWriteMode,
    ) -> Result<Option<TxidPublicCachePageRef>, TxidPublicCacheError> {
        if rows.is_empty() {
            return Ok(None);
        }
        let page = Self::from_rows(permit.key(), rows)?;
        page.write_with_mode(permit, mode).map(Some)
    }
}
