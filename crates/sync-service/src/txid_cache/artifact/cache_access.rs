#[allow(clippy::wildcard_imports)]
use super::*;

impl TxidPublicCache<'_> {
    pub(in crate::txid_cache) fn cached_artifact_chunk(
        &self,
        descriptor: &IndexedArtifactDescriptor,
    ) -> Option<VerifiedIndexedArtifactChunk> {
        let scope = self.key.artifact_scope().ok()?;
        if descriptor.dataset_kind != IndexedDatasetKind::PublicTxid
            || descriptor.range.kind != IndexedArtifactRangeKind::TxidIndex
            || descriptor.scope != scope
            || self.key.txid_version != DEFAULT_TXID_VERSION
            || descriptor.metadata.stream_partition.is_some()
        {
            return None;
        }
        let id = artifact_chunk_blob_id(self.key, &descriptor.cid);
        let meta = match self.db.get_blob_meta(TXID_CACHE_BLOB_KIND, &id) {
            Ok(Some(meta)) => meta,
            Ok(None) => return None,
            Err(err) => {
                debug!(target: LOG_TARGET,?err, cid = %descriptor.cid, "failed to read public TXID artifact chunk cache metadata");
                return None;
            }
        };
        if meta.format_version != TXID_CACHE_FORMAT_VERSION
            || meta.source_hash != Some(descriptor.sha256.0)
        {
            debug!(target: LOG_TARGET,cid = %descriptor.cid, "public TXID artifact chunk cache metadata did not match descriptor");
            return None;
        }
        let path = self.db.resolve_path(&meta.relative_path);
        let bytes = match fs::read(&path) {
            Ok(bytes) => bytes,
            Err(err) if err.kind() == ErrorKind::NotFound => return None,
            Err(err) => {
                debug!(target: LOG_TARGET,?err, path = %path.display(), cid = %descriptor.cid, "failed to read cached public TXID artifact chunk");
                return None;
            }
        };
        let content_hash: [u8; 32] = Sha256::digest(&bytes).into();
        if content_hash != meta.content_hash {
            debug!(target: LOG_TARGET,cid = %descriptor.cid, "cached public TXID artifact chunk content hash mismatch");
            return None;
        }
        match verify_chunk_bytes(descriptor.clone(), bytes) {
            Ok(chunk) => Some(chunk),
            Err(err) => {
                debug!(target: LOG_TARGET,?err, cid = %descriptor.cid, "cached public TXID artifact chunk failed descriptor verification");
                None
            }
        }
    }
}

impl TxidPublicCacheWritePermit<'_> {
    pub(in crate::txid_cache) fn retain_artifact_chunks(
        &self,
        chunks: &[VerifiedIndexedArtifactChunk],
    ) -> Result<usize, TxidPublicCacheError> {
        let now = now_epoch_secs()?;
        let cache = self.cache();
        let manifest = cache.load_or_new_manifest()?;
        let db = self.db();
        let key = self.key();
        for chunk in chunks {
            if chunk.descriptor.scope != key.artifact_scope()?
                || key.txid_version != DEFAULT_TXID_VERSION
                || chunk.descriptor.metadata.stream_partition.is_some()
            {
                return Err(TxidPublicCacheError::MetadataMismatch(
                    "retained public_txid artifact cache identity mismatch".to_string(),
                ));
            }
            let pages = Vec::<TxidPublicCachePage>::try_from(chunk)?;
            verify_declared_merkle_root(
                chunk.descriptor.metadata.root.as_ref(),
                &manifest,
                db,
                chunk.descriptor.range.start,
                chunk.descriptor.range.end,
                &pages,
            )?;
            let id = artifact_chunk_blob_id(key, &chunk.descriptor.cid);
            let name = artifact_chunk_file_name(key, &chunk.descriptor.cid);
            let path = db.blob_path(TXID_CACHE_BLOB_KIND, &name);
            write_blob_file(db, &path, &chunk.bytes)?;
            let existing = db.get_blob_meta(TXID_CACHE_BLOB_KIND, &id)?;
            db.put_blob_meta(
                TXID_CACHE_BLOB_KIND,
                &id,
                &BlobMeta {
                    format_version: TXID_CACHE_FORMAT_VERSION,
                    relative_path: DbStore::relative_blob_path(TXID_CACHE_BLOB_KIND, &name),
                    content_hash: Sha256::digest(&chunk.bytes).into(),
                    source_hash: Some(chunk.descriptor.sha256.0),
                    source_sequence: None,
                    created_at: existing.map_or(now, |meta| meta.created_at),
                    updated_at: now,
                    last_accessed_at: now,
                    last_block: chunk.descriptor.metadata.checkpoint_block,
                },
            )?;
        }
        Ok(chunks.len())
    }
}
