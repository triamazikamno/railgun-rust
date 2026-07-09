use super::*;

#[derive(Debug, Clone, Copy)]
enum TxidPublicCachePageWriteMode {
    Stable,
    StagedArtifact,
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
                created_at: existing.map_or(now, |meta| meta.created_at),
                updated_at: now,
                last_accessed_at: now,
                last_block: None,
            },
        )?;
        Ok(())
    }

    pub(super) fn append_page(
        &mut self,
        permit: &TxidPublicCacheWritePermit<'_>,
        page: &TxidPublicCachePage,
    ) -> Result<(), TxidPublicCacheError> {
        self.append_page_with_mode(permit, page, TxidPublicCachePageWriteMode::Stable)
    }

    pub(super) fn append_staged_artifact_page(
        &mut self,
        permit: &TxidPublicCacheWritePermit<'_>,
        page: &TxidPublicCachePage,
    ) -> Result<(), TxidPublicCacheError> {
        self.append_page_with_mode(permit, page, TxidPublicCachePageWriteMode::StagedArtifact)
    }

    fn append_page_with_mode(
        &mut self,
        permit: &TxidPublicCacheWritePermit<'_>,
        page: &TxidPublicCachePage,
        mode: TxidPublicCachePageWriteMode,
    ) -> Result<(), TxidPublicCacheError> {
        let page_ref = page.write_with_mode(permit, mode)?;
        self.next_txid_index = self
            .next_txid_index
            .max(page.start_index.saturating_add(page.rows.len() as u64));
        self.pages.push(page_ref);
        self.pages.sort_by_key(|page_ref| page_ref.start_index);
        Ok(())
    }

    pub(super) fn insert_or_replace_page(
        &mut self,
        permit: &TxidPublicCacheWritePermit<'_>,
        page: &TxidPublicCachePage,
    ) -> Result<(), TxidPublicCacheError> {
        self.insert_or_replace_page_with_mode(permit, page, TxidPublicCachePageWriteMode::Stable)
    }

    pub(super) fn insert_or_replace_staged_artifact_page(
        &mut self,
        permit: &TxidPublicCacheWritePermit<'_>,
        page: &TxidPublicCachePage,
    ) -> Result<(), TxidPublicCacheError> {
        self.insert_or_replace_page_with_mode(
            permit,
            page,
            TxidPublicCachePageWriteMode::StagedArtifact,
        )
    }

    fn insert_or_replace_page_with_mode(
        &mut self,
        permit: &TxidPublicCacheWritePermit<'_>,
        page: &TxidPublicCachePage,
        mode: TxidPublicCachePageWriteMode,
    ) -> Result<(), TxidPublicCacheError> {
        let db = permit.db();
        let page_end = page.start_index.saturating_add(page.rows.len() as u64);
        let mut pages = Vec::with_capacity(self.pages.len() + 1);
        for page_ref in std::mem::take(&mut self.pages) {
            let existing_end = page_ref.start_index.saturating_add(page_ref.row_count);
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
            TxidPublicCachePageWriteMode::StagedArtifact => {
                staged_artifact_page_file_name(key, self.start_index)
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
