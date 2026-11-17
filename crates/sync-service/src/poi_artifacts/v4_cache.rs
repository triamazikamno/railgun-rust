use std::collections::BTreeMap;
use std::fs;
use std::io::Read;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, LazyLock, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};

use alloy::hex;
use local_db::{BlobMeta, CanonicalBlobMetaIdentity, DbStore};
use poi::artifacts::v4::{
    BlockedShieldsArtifact, CheckpointCatalog, EventArtifact, EventArtifactDescriptor,
    ManifestEntry, PublicationId, Scope,
};
use poi::poi::BlockedShield;
use sha2::{Digest, Sha256};
use thiserror::Error;
use tokio::sync::RwLock;

use super::{ObservedManifest, PoiArtifactError};
use crate::trustless_artifacts::TrustlessArtifactFetchResult;

pub(crate) const POI_V4_RAW_CHUNK_BLOB_KIND: &str = "poi_v4_artifact_chunks";
const RAW_CHUNK_CACHE_FORMAT_VERSION: u32 = 1;

static RAW_CHUNK_AUTHORITIES: LazyLock<Mutex<BTreeMap<PathBuf, Arc<RawChunkCacheAuthority>>>> =
    LazyLock::new(|| Mutex::new(BTreeMap::new()));

struct RawChunkCacheAuthority {
    access: Arc<RwLock<()>>,
    generation: AtomicU64,
}

impl RawChunkCacheAuthority {
    fn new() -> Self {
        Self {
            access: Arc::new(RwLock::new(())),
            generation: AtomicU64::new(0),
        }
    }
}

pub struct FetchedArtifact(TrustlessArtifactFetchResult);

impl FetchedArtifact {
    pub(crate) const fn from_trustless(fetched: TrustlessArtifactFetchResult) -> Self {
        Self(fetched)
    }
}

#[derive(Debug, Clone)]
pub struct VerifiedCatalog {
    publication: PublicationId,
    entry: ManifestEntry,
    catalog: CheckpointCatalog,
}

impl VerifiedCatalog {
    #[must_use]
    pub const fn publication(&self) -> PublicationId {
        self.publication
    }

    #[must_use]
    pub const fn entry(&self) -> &ManifestEntry {
        &self.entry
    }

    pub(crate) fn chunks(&self) -> &[EventArtifactDescriptor] {
        &self.catalog.chunks
    }
}

#[derive(Clone)]
pub(crate) struct RawChunkAdmission {
    authority: Arc<RawChunkCacheAuthority>,
    generation: u64,
    publication: PublicationId,
}

impl std::fmt::Debug for RawChunkAdmission {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("RawChunkAdmission")
            .field("generation", &self.generation)
            .field("publication", &self.publication)
            .finish_non_exhaustive()
    }
}

impl PartialEq for RawChunkAdmission {
    fn eq(&self, other: &Self) -> bool {
        Arc::ptr_eq(&self.authority, &other.authority)
            && self.generation == other.generation
            && self.publication == other.publication
    }
}

impl Eq for RawChunkAdmission {}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CurrentChunk {
    descriptor: EventArtifactDescriptor,
    entry: ManifestEntry,
    admission: RawChunkAdmission,
    durable_cache_member: bool,
}

impl CurrentChunk {
    pub(crate) const fn descriptor(&self) -> &EventArtifactDescriptor {
        &self.descriptor
    }

    pub(crate) fn verify_fetched(
        self,
        fetched: FetchedArtifact,
    ) -> Result<TransportVerifiedChunk, RawChunkCacheError> {
        let fetched = fetched.0;
        if fetched.verified_cid() != self.descriptor.artifact.cid {
            return Err(RawChunkCacheError::CidMismatch {
                expected: self.descriptor.artifact.cid,
                actual: fetched.verified_cid().to_string(),
            });
        }
        let artifact = self.descriptor.verify_bytes(fetched.bytes())?;
        Ok(TransportVerifiedChunk {
            descriptor: self.descriptor,
            entry: self.entry,
            bytes: fetched.into_bytes(),
            artifact,
            admission: self.admission,
            durable_cache_member: self.durable_cache_member,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TransportVerifiedChunk {
    descriptor: EventArtifactDescriptor,
    entry: ManifestEntry,
    bytes: Vec<u8>,
    artifact: EventArtifact,
    admission: RawChunkAdmission,
    durable_cache_member: bool,
}

impl TransportVerifiedChunk {
    pub(crate) fn verify_event_signatures(
        self,
    ) -> Result<SemanticVerifiedChunk, RawChunkCacheError> {
        self.artifact.verify_signatures()?;
        Ok(SemanticVerifiedChunk {
            descriptor: self.descriptor,
            entry: self.entry,
            bytes: self.bytes,
            artifact: self.artifact,
            admission: self.admission,
            durable_cache_member: self.durable_cache_member,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SemanticVerifiedChunk {
    descriptor: EventArtifactDescriptor,
    entry: ManifestEntry,
    bytes: Vec<u8>,
    artifact: EventArtifact,
    admission: RawChunkAdmission,
    durable_cache_member: bool,
}

impl SemanticVerifiedChunk {
    pub(crate) const fn artifact(&self) -> &EventArtifact {
        &self.artifact
    }

    pub(crate) const fn publication(&self) -> PublicationId {
        self.admission.publication
    }

    pub(crate) const fn entry(&self) -> &ManifestEntry {
        &self.entry
    }
}

#[derive(Debug, Clone)]
pub struct VerifiedBlockedShields {
    publication: PublicationId,
    entry: ManifestEntry,
    records: Vec<BlockedShield>,
}

impl VerifiedBlockedShields {
    pub(crate) const fn publication(&self) -> PublicationId {
        self.publication
    }

    pub(crate) const fn entry(&self) -> &ManifestEntry {
        &self.entry
    }

    pub(crate) fn records(&self) -> &[BlockedShield] {
        &self.records
    }
}

impl ObservedManifest {
    pub(crate) fn verify_checkpoint_catalog(
        &self,
        scope: &Scope,
        fetched: FetchedArtifact,
    ) -> Result<VerifiedCatalog, PoiArtifactError> {
        let fetched = fetched.0;
        let entry = self.entry(scope)?.clone();
        if fetched.verified_cid() != entry.checkpoint_catalog.artifact.cid {
            return Err(RawChunkCacheError::CidMismatch {
                expected: entry.checkpoint_catalog.artifact.cid,
                actual: fetched.verified_cid().to_string(),
            }
            .into());
        }
        let catalog = entry.checkpoint_catalog.verify_bytes(fetched.bytes())?;
        Ok(VerifiedCatalog {
            publication: self.publication_id,
            entry,
            catalog,
        })
    }

    pub(crate) fn verify_blocked_shields(
        &self,
        scope: &Scope,
        fetched: FetchedArtifact,
    ) -> Result<VerifiedBlockedShields, PoiArtifactError> {
        let fetched = fetched.0;
        let entry = self.entry(scope)?.clone();
        if fetched.verified_cid() != entry.blocked_shields.artifact.cid {
            return Err(RawChunkCacheError::CidMismatch {
                expected: entry.blocked_shields.artifact.cid,
                actual: fetched.verified_cid().to_string(),
            }
            .into());
        }
        let artifact: BlockedShieldsArtifact =
            entry.blocked_shields.verify_bytes(fetched.bytes())?;
        Ok(VerifiedBlockedShields {
            publication: self.publication_id,
            entry,
            records: artifact.into_signed_records(),
        })
    }

    pub(crate) fn current_graph_chunk(
        &self,
        scope: &Scope,
        catalog: Option<&VerifiedCatalog>,
        descriptor: &EventArtifactDescriptor,
        admission: RawChunkAdmission,
    ) -> Result<CurrentChunk, RawChunkCacheError> {
        let entry = self
            .entry(scope)
            .map_err(|_| RawChunkCacheError::NotInCurrentGraph)?;
        let direct_member = entry.current_tail.as_ref() == Some(descriptor)
            || entry
                .retained_bridges
                .iter()
                .any(|candidate| candidate == descriptor);
        let checkpoint_member = catalog.is_some_and(|catalog| {
            catalog.publication == self.publication_id
                && catalog.entry.scope == *scope
                && catalog.entry.checkpoint_catalog == entry.checkpoint_catalog
                && catalog
                    .catalog
                    .chunks
                    .iter()
                    .any(|candidate| candidate == descriptor)
        });
        if !direct_member && !checkpoint_member {
            return Err(RawChunkCacheError::NotInCurrentGraph);
        }
        Ok(CurrentChunk {
            descriptor: descriptor.clone(),
            entry: entry.clone(),
            admission,
            durable_cache_member: checkpoint_member,
        })
    }
}

pub(crate) struct RawChunkCache<'a> {
    db: &'a DbStore,
}

impl<'a> RawChunkCache<'a> {
    pub(crate) const fn new(db: &'a DbStore) -> Self {
        Self { db }
    }

    pub(crate) fn admission(&self, publication: PublicationId) -> RawChunkAdmission {
        let authority = raw_chunk_authority(self.db);
        RawChunkAdmission {
            generation: authority.generation.load(Ordering::Acquire),
            authority,
            publication,
        }
    }

    pub(crate) async fn get(
        &self,
        current: &CurrentChunk,
    ) -> Result<Option<SemanticVerifiedChunk>, RawChunkCacheError> {
        let authority = self.validate_admission_owner(&current.admission)?;
        let _access = Arc::clone(&authority.access).read_owned().await;
        Self::validate_admission_generation(&current.admission)?;
        let _publisher_fence = super::lock_poi_artifact_publication();
        self.require_current_publication(current.admission.publication)?;
        self.get_unfenced(current)
    }

    fn get_unfenced(
        &self,
        current: &CurrentChunk,
    ) -> Result<Option<SemanticVerifiedChunk>, RawChunkCacheError> {
        let descriptor = current.descriptor();
        descriptor.validate()?;
        let chunk_identity = chunk_blob_identity(descriptor)?;
        let identity_hash = descriptor_identity_hash(descriptor)?;
        let id = hex::encode(identity_hash);
        let Some(meta) = self.db.get_blob_meta(POI_V4_RAW_CHUNK_BLOB_KIND, &id)? else {
            return Ok(None);
        };
        let expected_path = chunk_identity.relative_path();
        if meta.format_version != RAW_CHUNK_CACHE_FORMAT_VERSION
            || meta.relative_path != expected_path
            || meta.source_hash != Some(identity_hash)
            || meta.content_hash != descriptor.artifact.sha256.0
        {
            return Ok(None);
        }
        let Some(file) = self.db.open_blob_meta_file(&chunk_identity)? else {
            return Ok(None);
        };
        if file.metadata()?.len() != descriptor.artifact.byte_size {
            return Ok(None);
        }
        let Some(bytes) = read_bounded_exact(file, descriptor.artifact.byte_size)? else {
            return Ok(None);
        };
        let content_hash: [u8; 32] = Sha256::digest(&bytes).into();
        if content_hash != meta.content_hash {
            return Ok(None);
        }
        let Ok(artifact) = descriptor.verify_bytes(&bytes) else {
            return Ok(None);
        };
        if artifact.verify_signatures().is_err() {
            return Ok(None);
        }
        Ok(Some(SemanticVerifiedChunk {
            descriptor: descriptor.clone(),
            entry: current.entry.clone(),
            bytes,
            artifact,
            admission: current.admission.clone(),
            durable_cache_member: current.durable_cache_member,
        }))
    }

    pub(crate) async fn retain(
        &self,
        chunk: &SemanticVerifiedChunk,
    ) -> Result<RawChunkRetainOutcome, RawChunkCacheError> {
        Ok(self
            .retain_with_fence(chunk, || true)
            .await?
            .expect("unconditional POI artifact raw chunk retention fence accepts"))
    }

    pub(crate) async fn retain_with_fence(
        &self,
        chunk: &SemanticVerifiedChunk,
        is_current: impl FnOnce() -> bool,
    ) -> Result<Option<RawChunkRetainOutcome>, RawChunkCacheError> {
        if !chunk.durable_cache_member {
            return Err(RawChunkCacheError::NotDurableCheckpointChunk);
        }
        let authority = self.validate_admission_owner(&chunk.admission)?;
        let _access = Arc::clone(&authority.access).read_owned().await;
        Self::validate_admission_generation(&chunk.admission)?;
        let _publisher_fence = super::lock_poi_artifact_publication();
        self.require_current_publication(chunk.admission.publication)?;
        if !is_current() {
            return Ok(None);
        }
        let current = CurrentChunk {
            descriptor: chunk.descriptor.clone(),
            entry: chunk.entry.clone(),
            admission: chunk.admission.clone(),
            durable_cache_member: true,
        };
        if self.get_unfenced(&current)?.is_some() {
            return Ok(Some(RawChunkRetainOutcome::AlreadyRetained));
        }
        let identity_hash = descriptor_identity_hash(&chunk.descriptor)?;
        let id = hex::encode(identity_hash);
        let name = chunk_file_name(&chunk.descriptor);
        self.db
            .replace_blob_file_atomic(POI_V4_RAW_CHUNK_BLOB_KIND, &name, &chunk.bytes)?;
        let now = now_epoch_secs()?;
        let existing = self.db.get_blob_meta(POI_V4_RAW_CHUNK_BLOB_KIND, &id)?;
        self.db.put_blob_meta(
            POI_V4_RAW_CHUNK_BLOB_KIND,
            &id,
            &BlobMeta {
                format_version: RAW_CHUNK_CACHE_FORMAT_VERSION,
                relative_path: DbStore::relative_blob_path(POI_V4_RAW_CHUNK_BLOB_KIND, &name),
                content_hash: chunk.descriptor.artifact.sha256.0,
                source_hash: Some(identity_hash),
                source_sequence: None,
                created_at: existing.map_or(now, |meta| meta.created_at),
                updated_at: now,
                last_accessed_at: now,
                last_block: None,
            },
        )?;
        Ok(Some(RawChunkRetainOutcome::Retained))
    }

    fn validate_admission_owner(
        &self,
        admission: &RawChunkAdmission,
    ) -> Result<Arc<RawChunkCacheAuthority>, RawChunkCacheError> {
        let authority = raw_chunk_authority(self.db);
        if !Arc::ptr_eq(&admission.authority, &authority) {
            return Err(RawChunkCacheError::WrongDatabaseAdmission);
        }
        Ok(authority)
    }

    fn validate_admission_generation(
        admission: &RawChunkAdmission,
    ) -> Result<(), RawChunkCacheError> {
        let actual = admission.authority.generation.load(Ordering::Acquire);
        if admission.generation != actual {
            return Err(RawChunkCacheError::StaleAdmission {
                expected: actual,
                actual: admission.generation,
            });
        }
        Ok(())
    }

    fn require_current_publication(
        &self,
        publication: PublicationId,
    ) -> Result<(), RawChunkCacheError> {
        if !self.publication_is_current(publication)? {
            return Err(RawChunkCacheError::StalePublication);
        }
        Ok(())
    }

    fn publication_is_current(
        &self,
        publication: PublicationId,
    ) -> Result<bool, RawChunkCacheError> {
        Ok(self
            .db
            .get_poi_publisher_manifest_watermark(&publication.publisher_pubkey)?
            .is_some_and(|watermark| {
                watermark.accepted_sequence == publication.sequence
                    && watermark.accepted_manifest_hash == Some(publication.manifest_body_hash)
            }))
    }
}

fn read_bounded_exact(
    file: fs::File,
    expected_size: u64,
) -> Result<Option<Vec<u8>>, std::io::Error> {
    let limit = expected_size
        .checked_add(1)
        .ok_or_else(|| std::io::Error::other("POI artifact raw chunk read limit overflow"))?;
    let capacity = usize::try_from(limit)
        .map_err(|_| std::io::Error::other("POI artifact raw chunk read limit exceeds usize"))?;
    let mut bytes = Vec::with_capacity(capacity);
    file.take(limit).read_to_end(&mut bytes)?;
    if u64::try_from(bytes.len()).ok() != Some(expected_size) {
        return Ok(None);
    }
    Ok(Some(bytes))
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RawChunkRetainOutcome {
    Retained,
    AlreadyRetained,
}

#[derive(Debug, Error)]
pub(crate) enum RawChunkCacheError {
    #[error("POI artifact descriptor is not a member of the observed current graph")]
    NotInCurrentGraph,
    #[error("POI artifact raw chunk caching is limited to checkpoint-catalog chunks")]
    NotDurableCheckpointChunk,
    #[error("trustless artifact CID mismatch: expected {expected}, got {actual}")]
    CidMismatch { expected: String, actual: String },
    #[error("POI artifact raw chunk admission belongs to another database authority")]
    WrongDatabaseAdmission,
    #[error("stale POI artifact raw chunk admission: expected generation {expected}, got {actual}")]
    StaleAdmission { expected: u64, actual: u64 },
    #[error("POI artifact raw chunk publication is no longer current")]
    StalePublication,
    #[error("POI artifact descriptor encoding failed")]
    DescriptorEncoding(#[source] serde_json::Error),
    #[error(transparent)]
    V4(#[from] poi::artifacts::v4::Error),
    #[error(transparent)]
    Db(#[from] local_db::DbError),
    #[error(transparent)]
    Io(#[from] std::io::Error),
    #[error(transparent)]
    Time(#[from] std::time::SystemTimeError),
}

#[derive(Debug, Error)]
#[error("{error}")]
pub(crate) struct RawChunkCacheResetFailure {
    pub(crate) entries_removed: u64,
    #[source]
    pub(crate) error: RawChunkCacheError,
}

pub(crate) async fn reset_raw_chunk_cache(db: &DbStore) -> Result<u64, RawChunkCacheResetFailure> {
    let mut entries_removed = 0;
    db.ensure_blob_kind_purge_supported(POI_V4_RAW_CHUNK_BLOB_KIND)
        .map_err(RawChunkCacheError::from)
        .map_err(|error| RawChunkCacheResetFailure {
            entries_removed,
            error,
        })?;
    let authority = raw_chunk_authority(db);
    let _access = Arc::clone(&authority.access).write_owned().await;
    authority.generation.fetch_add(1, Ordering::AcqRel);
    entries_removed = db
        .clear_blob_meta_kind(POI_V4_RAW_CHUNK_BLOB_KIND)
        .map_err(RawChunkCacheError::from)
        .map_err(|error| RawChunkCacheResetFailure {
            entries_removed,
            error,
        })?;
    db.purge_blob_kind(POI_V4_RAW_CHUNK_BLOB_KIND)
        .map_err(RawChunkCacheError::from)
        .map_err(|error| RawChunkCacheResetFailure {
            entries_removed,
            error,
        })?;
    Ok(entries_removed)
}

fn raw_chunk_authority(db: &DbStore) -> Arc<RawChunkCacheAuthority> {
    let mut authorities = RAW_CHUNK_AUTHORITIES
        .lock()
        .expect("POI artifact raw chunk authority lock poisoned");
    Arc::clone(
        authorities
            .entry(db.root_dir().to_path_buf())
            .or_insert_with(|| Arc::new(RawChunkCacheAuthority::new())),
    )
}

fn descriptor_identity_hash(
    descriptor: &EventArtifactDescriptor,
) -> Result<[u8; 32], RawChunkCacheError> {
    let bytes = serde_json::to_vec(descriptor).map_err(RawChunkCacheError::DescriptorEncoding)?;
    Ok(Sha256::digest(bytes).into())
}

fn chunk_file_name(descriptor: &EventArtifactDescriptor) -> String {
    format!(
        "poi-v4-artifact-{}.bin",
        hex::encode(Sha256::digest(descriptor.artifact.cid.as_bytes()))
    )
}

fn chunk_blob_identity(
    descriptor: &EventArtifactDescriptor,
) -> Result<CanonicalBlobMetaIdentity, local_db::DbError> {
    CanonicalBlobMetaIdentity::from_leaf(POI_V4_RAW_CHUNK_BLOB_KIND, &chunk_file_name(descriptor))
}

fn now_epoch_secs() -> Result<u64, std::time::SystemTimeError> {
    Ok(SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs())
}

#[cfg(test)]
mod tests;
