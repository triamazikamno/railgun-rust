//! The on-disk cache of verified wallet-scan artifact chunks.

use crate::indexed_artifacts::{
    IndexedArtifactDescriptor, IndexedArtifactRangeKind, IndexedDatasetKind,
    VerifiedIndexedArtifactChunk, format_scope, verify_chunk_bytes,
};
use crate::public_cache::{
    WALLET_SCAN_ARTIFACT_CHUNK_BLOB_KIND, wallet_scan_artifact_cache_commit_access,
    wallet_scan_artifact_transient_commit_access,
};
use local_db::{BlobMeta, DbStore};
use sha2::{Digest, Sha256};
use std::fs;
use std::io::ErrorKind;
use std::path::Path;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};
use tracing::{debug, warn};

use super::{ChainPublicDataPlane, PublicScanReadScope};

const WALLET_SCAN_ARTIFACT_CHUNK_CACHE_FORMAT_VERSION: u32 = 1;

static WALLET_SCAN_ARTIFACT_CHUNK_TEMP_COUNTER: AtomicU64 = AtomicU64::new(0);

impl ChainPublicDataPlane {
    pub(crate) fn cached_wallet_scan_artifact_chunk(
        &self,
        descriptor: &IndexedArtifactDescriptor,
    ) -> Option<VerifiedIndexedArtifactChunk> {
        if !wallet_scan_artifact_descriptor_matches_cache_kind(descriptor) {
            return None;
        }
        let id = wallet_scan_artifact_chunk_blob_id(descriptor);
        self.cached_wallet_scan_artifact_chunk_with_id(descriptor, &id)
    }

    pub(crate) fn cached_wallet_scan_transient_artifact_chunk(
        &self,
        descriptor: &IndexedArtifactDescriptor,
    ) -> Option<VerifiedIndexedArtifactChunk> {
        if !wallet_scan_artifact_descriptor_matches_cache_kind(descriptor) {
            return None;
        }
        let id = wallet_scan_artifact_transient_slot_id(descriptor);
        self.cached_wallet_scan_artifact_chunk_with_id(descriptor, &id)
    }

    fn cached_wallet_scan_artifact_chunk_with_id(
        &self,
        descriptor: &IndexedArtifactDescriptor,
        id: &str,
    ) -> Option<VerifiedIndexedArtifactChunk> {
        let meta = match self
            .db
            .get_blob_meta(WALLET_SCAN_ARTIFACT_CHUNK_BLOB_KIND, id)
        {
            Ok(Some(meta)) => meta,
            Ok(None) => return None,
            Err(err) => {
                debug!(?err, cid = %descriptor.cid, "failed to read wallet-scan artifact chunk cache metadata");
                return None;
            }
        };
        if meta.format_version != WALLET_SCAN_ARTIFACT_CHUNK_CACHE_FORMAT_VERSION
            || meta.source_hash != Some(descriptor.sha256.0)
        {
            debug!(cid = %descriptor.cid, "wallet-scan artifact chunk cache metadata did not match descriptor");
            return None;
        }
        let path = self.db.resolve_path(&meta.relative_path);
        let bytes = match fs::read(&path) {
            Ok(bytes) => bytes,
            Err(err) if err.kind() == ErrorKind::NotFound => return None,
            Err(err) => {
                debug!(?err, path = %path.display(), cid = %descriptor.cid, "failed to read cached wallet-scan artifact chunk");
                return None;
            }
        };
        let content_hash: [u8; 32] = Sha256::digest(&bytes).into();
        if content_hash != meta.content_hash {
            debug!(cid = %descriptor.cid, "cached wallet-scan artifact chunk content hash mismatch");
            return None;
        }
        match verify_chunk_bytes(descriptor.clone(), bytes) {
            Ok(chunk) => Some(chunk),
            Err(err) => {
                debug!(?err, cid = %descriptor.cid, "cached wallet-scan artifact chunk failed descriptor verification");
                None
            }
        }
    }

    pub(crate) async fn retain_wallet_scan_artifact_chunks_for_generation(
        &self,
        chunks: &[VerifiedIndexedArtifactChunk],
        read_scope: PublicScanReadScope,
        cache_generation: u64,
    ) -> usize {
        let Ok(_permit) = self
            .public_cache_commit_permit(
                read_scope,
                "stale wallet-scan artifact chunk retention epoch",
            )
            .await
        else {
            return 0;
        };
        let Some(_maintenance_access) =
            wallet_scan_artifact_cache_commit_access(self.db.as_ref(), cache_generation).await
        else {
            return 0;
        };
        let mut retained = 0_usize;
        for chunk in chunks {
            if !wallet_scan_artifact_descriptor_matches_cache_kind(&chunk.descriptor) {
                continue;
            }
            if self
                .cached_wallet_scan_artifact_chunk(&chunk.descriptor)
                .is_some()
            {
                continue;
            }
            match self.retain_wallet_scan_artifact_chunk(chunk) {
                Ok(()) => retained = retained.saturating_add(1),
                Err(reason) => {
                    warn!(cid = %chunk.descriptor.cid, %reason, "failed to retain wallet-scan artifact chunk");
                }
            }
        }
        retained
    }

    pub(crate) async fn retain_wallet_scan_transient_artifact_chunk_for_generation(
        &self,
        chunk: &VerifiedIndexedArtifactChunk,
        read_scope: PublicScanReadScope,
        cache_generation: u64,
        manifest_sequence: u64,
    ) -> bool {
        let Ok(_permit) = self
            .public_cache_commit_permit(
                read_scope,
                "stale wallet-scan transient artifact chunk retention epoch",
            )
            .await
        else {
            return false;
        };
        let Some(_maintenance_access) =
            wallet_scan_artifact_cache_commit_access(self.db.as_ref(), cache_generation).await
        else {
            return false;
        };
        let _transient_commit =
            wallet_scan_artifact_transient_commit_access(self.db.as_ref()).await;
        if !wallet_scan_artifact_descriptor_matches_cache_kind(&chunk.descriptor) {
            return false;
        }
        let slot_id = wallet_scan_artifact_transient_slot_id(&chunk.descriptor);
        let existing = match self
            .db
            .get_blob_meta(WALLET_SCAN_ARTIFACT_CHUNK_BLOB_KIND, &slot_id)
        {
            Ok(existing) => existing,
            Err(reason) => {
                warn!(cid = %chunk.descriptor.cid, %reason, "failed to read wallet-scan transient artifact metadata");
                return false;
            }
        };
        if existing
            .as_ref()
            .and_then(|meta| meta.source_sequence)
            .is_some_and(|sequence| sequence > manifest_sequence)
        {
            return false;
        }
        if self
            .cached_wallet_scan_transient_artifact_chunk(&chunk.descriptor)
            .is_some()
        {
            return true;
        }
        match self.retain_wallet_scan_transient_artifact_chunk(chunk, manifest_sequence) {
            Ok(()) => true,
            Err(reason) => {
                warn!(cid = %chunk.descriptor.cid, %reason, "failed to retain wallet-scan transient artifact chunk");
                false
            }
        }
    }

    fn retain_wallet_scan_artifact_chunk(
        &self,
        chunk: &VerifiedIndexedArtifactChunk,
    ) -> Result<(), String> {
        if !wallet_scan_artifact_descriptor_matches_cache_kind(&chunk.descriptor) {
            return Ok(());
        }
        let id = wallet_scan_artifact_chunk_blob_id(&chunk.descriptor);
        let name = wallet_scan_artifact_chunk_file_name(&chunk.descriptor);
        self.retain_wallet_scan_artifact_chunk_with_storage(chunk, &id, &name, None)
    }

    fn retain_wallet_scan_transient_artifact_chunk(
        &self,
        chunk: &VerifiedIndexedArtifactChunk,
        manifest_sequence: u64,
    ) -> Result<(), String> {
        if !wallet_scan_artifact_descriptor_matches_cache_kind(&chunk.descriptor) {
            return Ok(());
        }
        let id = wallet_scan_artifact_transient_slot_id(&chunk.descriptor);
        let name = wallet_scan_artifact_transient_file_name(&chunk.descriptor);
        self.retain_wallet_scan_artifact_chunk_with_storage(
            chunk,
            &id,
            &name,
            Some(manifest_sequence),
        )
    }

    fn retain_wallet_scan_artifact_chunk_with_storage(
        &self,
        chunk: &VerifiedIndexedArtifactChunk,
        id: &str,
        name: &str,
        source_sequence: Option<u64>,
    ) -> Result<(), String> {
        let path = self
            .db
            .blob_path(WALLET_SCAN_ARTIFACT_CHUNK_BLOB_KIND, name);
        write_wallet_scan_artifact_chunk_file(self.db.as_ref(), &path, &chunk.bytes)
            .map_err(|err| err.to_string())?;
        let now = wallet_scan_artifact_now_epoch_secs().map_err(|err| err.to_string())?;
        let existing = self
            .db
            .get_blob_meta(WALLET_SCAN_ARTIFACT_CHUNK_BLOB_KIND, id)
            .map_err(|err| err.to_string())?;
        self.db
            .put_blob_meta(
                WALLET_SCAN_ARTIFACT_CHUNK_BLOB_KIND,
                id,
                &BlobMeta {
                    format_version: WALLET_SCAN_ARTIFACT_CHUNK_CACHE_FORMAT_VERSION,
                    relative_path: DbStore::relative_blob_path(
                        WALLET_SCAN_ARTIFACT_CHUNK_BLOB_KIND,
                        name,
                    ),
                    content_hash: Sha256::digest(&chunk.bytes).into(),
                    source_hash: Some(chunk.descriptor.sha256.0),
                    source_sequence,
                    created_at: existing.map_or(now, |meta| meta.created_at),
                    updated_at: now,
                    last_accessed_at: now,
                    last_block: chunk.descriptor.metadata.checkpoint_block,
                },
            )
            .map_err(|err| err.to_string())?;
        Ok(())
    }
}

fn wallet_scan_artifact_descriptor_matches_cache_kind(
    descriptor: &IndexedArtifactDescriptor,
) -> bool {
    descriptor.dataset_kind == IndexedDatasetKind::WalletScan
        && descriptor.range.kind == IndexedArtifactRangeKind::Block
}

pub(super) fn wallet_scan_artifact_chunk_blob_id(descriptor: &IndexedArtifactDescriptor) -> String {
    format!(
        "{:?}|{}|{:?}|{}|{}|{}|{}|{}|{}|{:?}|{}",
        descriptor.dataset_kind,
        format_scope(&descriptor.scope),
        descriptor.range.kind,
        descriptor.range.start,
        descriptor.range.end,
        descriptor.row_count,
        descriptor.cid,
        descriptor.byte_size,
        descriptor.encoding_version,
        descriptor.compression,
        descriptor
            .metadata
            .checkpoint_block
            .map_or_else(|| "none".to_string(), |checkpoint| checkpoint.to_string()),
    )
}

fn wallet_scan_artifact_chunk_file_name(descriptor: &IndexedArtifactDescriptor) -> String {
    format!(
        "wallet-scan-artifact-chunk-{}.bin",
        safe_file_component(&descriptor.cid)
    )
}

pub(super) fn wallet_scan_artifact_transient_slot_id(
    descriptor: &IndexedArtifactDescriptor,
) -> String {
    format!(
        "transient|{:?}|{}|{:?}|{}",
        descriptor.dataset_kind,
        format_scope(&descriptor.scope),
        descriptor.range.kind,
        descriptor
            .metadata
            .stream_partition
            .as_deref()
            .unwrap_or("default"),
    )
}

fn wallet_scan_artifact_transient_file_name(descriptor: &IndexedArtifactDescriptor) -> String {
    let slot = wallet_scan_artifact_transient_slot_id(descriptor);
    format!(
        "wallet-scan-artifact-transient-{}.bin",
        alloy::hex::encode(Sha256::digest(slot.as_bytes())),
    )
}

fn safe_file_component(value: &str) -> String {
    value
        .chars()
        .map(|ch| {
            if ch.is_ascii_alphanumeric() || ch == '-' || ch == '_' {
                ch
            } else {
                '_'
            }
        })
        .collect()
}

fn write_wallet_scan_artifact_chunk_file(
    db: &DbStore,
    path: &Path,
    bytes: &[u8],
) -> Result<(), std::io::Error> {
    db.ensure_blob_dir(WALLET_SCAN_ARTIFACT_CHUNK_BLOB_KIND)
        .map_err(std::io::Error::other)?;
    let nonce = WALLET_SCAN_ARTIFACT_CHUNK_TEMP_COUNTER.fetch_add(1, Ordering::Relaxed);
    let temp_path = path.with_extension(format!("tmp.{}.{nonce}", std::process::id()));
    fs::write(&temp_path, bytes)?;
    fs::rename(temp_path, path)?;
    Ok(())
}

fn wallet_scan_artifact_now_epoch_secs() -> Result<u64, std::time::SystemTimeError> {
    Ok(SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs())
}

#[cfg(test)]
impl ChainPublicDataPlane {
    pub(crate) async fn retain_wallet_scan_artifact_chunks(
        &self,
        chunks: &[VerifiedIndexedArtifactChunk],
        read_scope: PublicScanReadScope,
    ) -> usize {
        let cache_generation = self.wallet_scan_artifact_cache_generation();
        self.retain_wallet_scan_artifact_chunks_for_generation(chunks, read_scope, cache_generation)
            .await
    }
}
