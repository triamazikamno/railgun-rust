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
        let _publisher_fence = super::lock_poi_artifact_cache_sync();
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
        let _publisher_fence = super::lock_poi_artifact_cache_sync();
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
mod tests {
    use std::sync::atomic::{AtomicU64, Ordering};

    use alloy::primitives::FixedBytes;
    use broadcaster_core::tree::TREE_LEAF_COUNT;
    use ed25519_dalek::{Signer, SigningKey};
    use local_db::DbConfig;
    use poi::artifacts::v4::{
        ArtifactEncoding, BlockedShieldsArtifact, BlockedShieldsDescriptor, CheckpointCatalog,
        Compression, EventArtifact, EventArtifactKind, FORMAT_VERSION, Manifest, ManifestEntry,
        Scope,
    };
    use poi::artifacts::verify::{canonical_blocked_shield_message, canonical_poi_event_message};
    use poi::artifacts::{ArtifactDescriptor, SnapshotEvent};
    use poi::cache::{PoiCache, PoiCacheIdentity};
    use poi::poi::{PoiEventType, SignedBlockedShield, SignedPoiEvent};

    use super::*;
    use crate::poi_artifacts::{
        CorpusCommitOutcome, load_persisted_cache_for_publisher, persist_prepared_corpus,
        prepare_candidate,
        test_support::{observe_manifest, poi_v4_manifest_envelope_signing_message},
    };

    static TEMP_DB_COUNTER: AtomicU64 = AtomicU64::new(0);

    fn chunk_relative_path(descriptor: &EventArtifactDescriptor) -> String {
        chunk_blob_identity(descriptor)
            .expect("generated POI artifact raw chunk name is a canonical blob identity")
            .relative_path()
    }

    fn test_path(name: &str) -> PathBuf {
        let unique = TEMP_DB_COUNTER.fetch_add(1, Ordering::Relaxed);
        std::env::temp_dir().join(format!(
            "sync-service-poi-v4-raw-cache-{name}-{}-{unique}",
            std::process::id()
        ))
    }

    #[tokio::test]
    async fn exact_identity_hit_miss_same_range_replacement_and_shared_descriptor_reuse() {
        let (db, root) = test_db("exact-identity");
        let signing_key = SigningKey::from_bytes(&[0x11; 32]);
        let first = graph(&signing_key, 1, 0x21, "bafy-first");
        let observed = observe_manifest(
            &db,
            FixedBytes::from(signing_key.verifying_key().to_bytes()),
            first.manifest,
            None,
            SystemTime::now(),
        )
        .expect("observe first manifest");
        let catalog = observed
            .verify_checkpoint_catalog(
                &first.scope,
                FetchedArtifact::from_trustless(TrustlessArtifactFetchResult::verified_for_test(
                    first.catalog_descriptor_cid,
                    first.catalog_bytes,
                )),
            )
            .expect("verify current catalog");
        let cache = RawChunkCache::new(&db);
        let admission = cache.admission(observed.publication_id());
        let current = observed
            .current_graph_chunk(
                &first.scope,
                Some(&catalog),
                &first.chunk_descriptor,
                admission,
            )
            .expect("select current chunk");
        let verified = current
            .clone()
            .verify_fetched(FetchedArtifact::from_trustless(
                TrustlessArtifactFetchResult::verified_for_test(
                    first.chunk_descriptor.artifact.cid.clone(),
                    first.chunk_bytes,
                ),
            ))
            .expect("verify fetched chunk")
            .verify_event_signatures()
            .expect("verify event signatures");
        assert_eq!(
            cache.retain(&verified).await.expect("retain chunk"),
            RawChunkRetainOutcome::Retained
        );
        assert_eq!(
            &cache
                .get(&current)
                .await
                .expect("read exact chunk")
                .expect("exact chunk hit")
                .bytes,
            &verified.bytes
        );

        let replacement = graph(&signing_key, 2, 0x22, "bafy-replacement");
        let replacement_observed = observe_manifest(
            &db,
            FixedBytes::from(signing_key.verifying_key().to_bytes()),
            replacement.manifest,
            None,
            SystemTime::now(),
        )
        .expect("observe replacement manifest");
        let replacement_catalog = replacement_observed
            .verify_checkpoint_catalog(
                &replacement.scope,
                FetchedArtifact::from_trustless(TrustlessArtifactFetchResult::verified_for_test(
                    replacement.catalog_descriptor_cid,
                    replacement.catalog_bytes,
                )),
            )
            .expect("verify replacement catalog");
        let replacement_current = replacement_observed
            .current_graph_chunk(
                &replacement.scope,
                Some(&replacement_catalog),
                &replacement.chunk_descriptor,
                cache.admission(replacement_observed.publication_id()),
            )
            .expect("select replacement chunk");
        assert!(
            cache
                .get(&replacement_current)
                .await
                .expect("replacement lookup")
                .is_none()
        );
        let replacement_verified = replacement_current
            .clone()
            .verify_fetched(FetchedArtifact::from_trustless(
                TrustlessArtifactFetchResult::verified_for_test(
                    replacement.chunk_descriptor.artifact.cid.clone(),
                    replacement.chunk_bytes,
                ),
            ))
            .expect("verify replacement chunk")
            .verify_event_signatures()
            .expect("verify replacement signatures");
        assert_eq!(
            cache
                .retain(&replacement_verified)
                .await
                .expect("retain replacement"),
            RawChunkRetainOutcome::Retained
        );
        assert!(
            cache
                .get(&replacement_current)
                .await
                .expect("read retained replacement")
                .is_some()
        );
        assert!(matches!(
            cache
                .get(&current)
                .await
                .expect_err("superseded admission must be stale"),
            RawChunkCacheError::StalePublication
        ));
        assert!(matches!(
            cache
                .retain(&verified)
                .await
                .expect_err("reject stale raw write"),
            RawChunkCacheError::StalePublication
        ));

        let reused = graph(&signing_key, 3, 0x21, "bafy-first");
        let reused_observed = observe_manifest(
            &db,
            FixedBytes::from(signing_key.verifying_key().to_bytes()),
            reused.manifest,
            None,
            SystemTime::now(),
        )
        .expect("observe reused manifest");
        let reused_catalog = reused_observed
            .verify_checkpoint_catalog(
                &reused.scope,
                FetchedArtifact::from_trustless(TrustlessArtifactFetchResult::verified_for_test(
                    reused.catalog_descriptor_cid,
                    reused.catalog_bytes,
                )),
            )
            .expect("verify reused catalog");
        let reused_current = reused_observed
            .current_graph_chunk(
                &reused.scope,
                Some(&reused_catalog),
                &reused.chunk_descriptor,
                cache.admission(reused_observed.publication_id()),
            )
            .expect("select reused chunk");
        assert!(
            cache
                .get(&reused_current)
                .await
                .expect("shared descriptor lookup")
                .is_some()
        );

        drop(db);
        fs::remove_dir_all(root).expect("remove test db");
    }

    #[tokio::test]
    async fn current_tail_and_bridge_semantic_chunks_are_not_durable_cache_members() {
        let (db, root) = test_db("semantic-chunks-not-durable");
        let signing_key = SigningKey::from_bytes(&[0x2c; 32]);

        for (sequence, kind, cid) in [
            (1, EventArtifactKind::CurrentTail, "bafy-direct-tail"),
            (2, EventArtifactKind::Bridge, "bafy-direct-bridge"),
        ] {
            let mut graph = graph(&signing_key, sequence, 0x2d, cid);
            let mut artifact =
                EventArtifact::read(&graph.chunk_bytes).expect("read checkpoint artifact");
            artifact.kind = kind;
            let bytes = artifact.to_bytes().expect("encode direct manifest chunk");
            let descriptor = artifact
                .descriptor(cid)
                .expect("describe direct manifest chunk");
            let entry = &mut graph.manifest.entries[0];
            match kind {
                EventArtifactKind::CurrentTail => {
                    let catalog = CheckpointCatalog::new(graph.scope.clone(), Vec::new())
                        .expect("build empty checkpoint catalog");
                    graph.catalog_bytes = catalog.to_bytes().expect("encode empty catalog");
                    graph.catalog_descriptor_cid = "bafy-empty-checkpoint-catalog".to_string();
                    entry.checkpoint_catalog = catalog
                        .descriptor(graph.catalog_descriptor_cid.clone())
                        .expect("describe empty checkpoint catalog");
                    entry.current_tail = Some(descriptor.clone());
                }
                EventArtifactKind::Bridge => {
                    entry.retained_bridges = vec![descriptor.clone()];
                }
                EventArtifactKind::Checkpoint => unreachable!(),
            }
            graph
                .manifest
                .sign_manifest(&signing_key)
                .expect("sign direct-member manifest");

            let observed = observe_manifest(
                &db,
                FixedBytes::from(signing_key.verifying_key().to_bytes()),
                graph.manifest,
                None,
                SystemTime::now(),
            )
            .expect("observe direct-member manifest");
            let catalog = observed
                .verify_checkpoint_catalog(
                    &graph.scope,
                    FetchedArtifact::from_trustless(
                        TrustlessArtifactFetchResult::verified_for_test(
                            graph.catalog_descriptor_cid,
                            graph.catalog_bytes,
                        ),
                    ),
                )
                .expect("verify checkpoint catalog");
            let cache = RawChunkCache::new(&db);
            let current = observed
                .current_graph_chunk(
                    &graph.scope,
                    Some(&catalog),
                    &descriptor,
                    cache.admission(observed.publication_id()),
                )
                .expect("select direct manifest chunk");
            assert!(
                cache
                    .get(&current)
                    .await
                    .expect("read absent direct manifest chunk")
                    .is_none()
            );
            let semantic = current
                .verify_fetched(FetchedArtifact::from_trustless(
                    TrustlessArtifactFetchResult::verified_for_test(cid, bytes),
                ))
                .expect("verify direct manifest chunk")
                .verify_event_signatures()
                .expect("verify direct manifest signatures");
            assert!(matches!(
                cache.retain(&semantic).await,
                Err(RawChunkCacheError::NotDurableCheckpointChunk)
            ));
            let id = hex::encode(
                descriptor_identity_hash(&descriptor).expect("direct descriptor identity"),
            );
            assert!(
                db.get_blob_meta(POI_V4_RAW_CHUNK_BLOB_KIND, &id)
                    .expect("read absent direct metadata")
                    .is_none()
            );
        }

        drop(db);
        fs::remove_dir_all(root).expect("remove test db");
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn raw_chunk_metadata_is_written_only_after_atomic_replace() {
        use std::os::unix::fs::symlink;

        let (db, root) = test_db("raw-metadata-after-file");
        let signing_key = SigningKey::from_bytes(&[0x8f; 32]);
        let graph = graph(&signing_key, 1, 0x90, "bafy-raw-metadata-after-file");
        let (current, verified) = observe_graph_chunk(&db, &signing_key, graph);
        let external = root.join("external-raw-write");
        fs::create_dir_all(&external).expect("create external raw directory");
        symlink(&external, db.blob_dir().join(POI_V4_RAW_CHUNK_BLOB_KIND))
            .expect("symlink raw chunk kind");
        let id = hex::encode(
            descriptor_identity_hash(current.descriptor()).expect("descriptor identity"),
        );

        assert!(matches!(
            RawChunkCache::new(&db).retain(&verified).await,
            Err(RawChunkCacheError::Db(
                local_db::DbError::InvalidBlobRelativePath { .. }
            ))
        ));
        assert!(
            db.get_blob_meta(POI_V4_RAW_CHUNK_BLOB_KIND, &id)
                .expect("read raw metadata after failed file replace")
                .is_none()
        );
        assert!(
            fs::read_dir(&external)
                .expect("read external raw directory")
                .next()
                .is_none()
        );

        drop(db);
        fs::remove_dir_all(root).expect("remove test db");
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn exact_lookup_rejects_symlink_leaf_without_touching_target_or_metadata() {
        use std::os::unix::fs::symlink;

        let (db, root) = test_db("lookup-symlink-leaf");
        let signing_key = SigningKey::from_bytes(&[0x91; 32]);
        let graph = graph(&signing_key, 1, 0x92, "bafy-lookup-symlink-leaf");
        let (current, verified) = observe_graph_chunk(&db, &signing_key, graph);
        let cache = RawChunkCache::new(&db);
        cache.retain(&verified).await.expect("retain exact chunk");
        let id = hex::encode(
            descriptor_identity_hash(current.descriptor()).expect("descriptor identity"),
        );
        let path = db.resolve_path(&chunk_relative_path(current.descriptor()));
        fs::remove_file(&path).expect("remove retained file");
        let external = root.join("external-symlink-target");
        fs::write(&external, b"external sentinel").expect("write external target");
        symlink(&external, &path).expect("replace cache leaf with symlink");

        let result = tokio::time::timeout(std::time::Duration::from_secs(1), cache.get(&current))
            .await
            .expect("symlink lookup must not hang");
        assert!(matches!(
            result,
            Err(RawChunkCacheError::Db(
                local_db::DbError::UnsafeBlobEntry { .. }
            ))
        ));
        assert_eq!(
            fs::read(&external).expect("read external target"),
            b"external sentinel"
        );
        assert!(
            fs::symlink_metadata(&path)
                .expect("read retained symlink")
                .file_type()
                .is_symlink()
        );
        assert!(
            db.get_blob_meta(POI_V4_RAW_CHUNK_BLOB_KIND, &id)
                .expect("read retained metadata")
                .is_some()
        );

        drop(db);
        fs::remove_dir_all(root).expect("remove test db");
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn exact_lookup_rejects_symlinked_blob_kind_without_touching_external_target() {
        use std::os::unix::fs::symlink;

        let (db, root) = test_db("lookup-symlink-kind");
        let signing_key = SigningKey::from_bytes(&[0x93; 32]);
        let graph = graph(&signing_key, 1, 0x94, "bafy-lookup-symlink-kind");
        let (current, verified) = observe_graph_chunk(&db, &signing_key, graph);
        let cache = RawChunkCache::new(&db);
        cache.retain(&verified).await.expect("retain exact chunk");
        let id = hex::encode(
            descriptor_identity_hash(current.descriptor()).expect("descriptor identity"),
        );
        let kind_dir = db.blob_dir().join(POI_V4_RAW_CHUNK_BLOB_KIND);
        let original_dir = db.blob_dir().join("original-raw-chunks");
        fs::rename(&kind_dir, &original_dir).expect("move original raw directory");
        let external_dir = root.join("external-kind-target");
        fs::create_dir_all(&external_dir).expect("create external target directory");
        let file_name = chunk_file_name(current.descriptor());
        let external = external_dir.join(file_name);
        fs::write(&external, b"external sentinel").expect("write external target");
        symlink(&external_dir, &kind_dir).expect("symlink raw kind directory");

        let result = tokio::time::timeout(std::time::Duration::from_secs(1), cache.get(&current))
            .await
            .expect("symlinked-kind lookup must not hang");
        assert!(matches!(
            result,
            Err(RawChunkCacheError::Db(
                local_db::DbError::UnsafeBlobEntry { .. }
            ))
        ));
        assert_eq!(
            fs::read(&external).expect("read external target"),
            b"external sentinel"
        );
        assert!(
            db.get_blob_meta(POI_V4_RAW_CHUNK_BLOB_KIND, &id)
                .expect("read retained metadata")
                .is_some()
        );

        drop(db);
        fs::remove_dir_all(root).expect("remove test db");
    }

    #[tokio::test]
    async fn exact_lookup_treats_oversized_truncated_and_equal_size_hash_corruption_as_misses() {
        let (db, root) = test_db("lookup-regular-file-misses");
        let signing_key = SigningKey::from_bytes(&[0x97; 32]);
        let graph = graph(&signing_key, 1, 0x98, "bafy-lookup-regular-misses");
        let (current, verified) = observe_graph_chunk(&db, &signing_key, graph);
        let cache = RawChunkCache::new(&db);
        cache.retain(&verified).await.expect("retain exact chunk");
        let id = hex::encode(
            descriptor_identity_hash(current.descriptor()).expect("descriptor identity"),
        );
        let path = db.resolve_path(&chunk_relative_path(current.descriptor()));
        let expected_size = usize::try_from(current.descriptor().artifact.byte_size)
            .expect("descriptor size fits usize");

        fs::write(&path, vec![0x99; expected_size + 1]).expect("write oversized regular file");
        assert!(
            cache
                .get(&current)
                .await
                .expect("oversized lookup")
                .is_none()
        );
        assert_eq!(
            fs::metadata(&path).expect("oversized metadata").len(),
            current.descriptor().artifact.byte_size + 1
        );

        fs::write(&path, vec![0x9a; expected_size - 1]).expect("write truncated regular file");
        assert!(
            cache
                .get(&current)
                .await
                .expect("truncated lookup")
                .is_none()
        );

        let mut corrupt = verified.bytes.clone();
        corrupt[0] ^= 0xff;
        fs::write(&path, &corrupt).expect("write equal-size hash corruption");
        assert!(
            cache
                .get(&current)
                .await
                .expect("hash-corrupt lookup")
                .is_none()
        );
        assert!(path.exists());
        fs::remove_file(&path).expect("remove corrupt regular file");
        assert!(cache.get(&current).await.expect("missing lookup").is_none());
        assert!(!path.exists());
        assert!(
            db.get_blob_meta(POI_V4_RAW_CHUNK_BLOB_KIND, &id)
                .expect("read retained metadata")
                .is_some()
        );

        drop(db);
        fs::remove_dir_all(root).expect("remove test db");
    }

    #[tokio::test]
    async fn exact_lookup_rejects_descriptor_hard_cap_before_metadata_or_open() {
        let (db, root) = test_db("lookup-hard-cap");
        let signing_key = SigningKey::from_bytes(&[0x9b; 32]);
        let graph = graph(&signing_key, 1, 0x9c, "bafy-lookup-hard-cap");
        let (mut current, _) = observe_graph_chunk(&db, &signing_key, graph);
        current.descriptor.artifact.byte_size = poi::artifacts::v4::EVENT_ARTIFACT_MAX_BYTES + 1;

        assert!(matches!(
            RawChunkCache::new(&db).get(&current).await,
            Err(RawChunkCacheError::V4(
                poi::artifacts::v4::Error::EventArtifactByteLimitExceeded { .. }
            ))
        ));

        drop(db);
        fs::remove_dir_all(root).expect("remove test db");
    }

    #[test]
    fn bounded_exact_read_detects_growth_and_truncation_after_opened_length_check() {
        use std::io::Write;

        let root = test_path("bounded-read-races");
        fs::create_dir_all(&root).expect("create bounded-read directory");
        let path = root.join("chunk.bin");
        let expected = b"exact bytes";
        fs::write(&path, expected).expect("write exact file");
        let opened = fs::File::open(&path).expect("open exact file before growth");
        assert_eq!(opened.metadata().expect("opened metadata").len(), 11);
        fs::OpenOptions::new()
            .append(true)
            .open(&path)
            .expect("open append handle")
            .write_all(b"x")
            .expect("grow opened file");
        assert!(
            read_bounded_exact(opened, 11)
                .expect("bounded growth read")
                .is_none()
        );

        fs::write(&path, expected).expect("restore exact file");
        let opened = fs::File::open(&path).expect("open exact file before truncation");
        assert_eq!(opened.metadata().expect("opened metadata").len(), 11);
        fs::OpenOptions::new()
            .write(true)
            .open(&path)
            .expect("open truncation handle")
            .set_len(5)
            .expect("truncate opened file");
        assert!(
            read_bounded_exact(opened, 11)
                .expect("bounded truncation read")
                .is_none()
        );

        fs::remove_dir_all(root).expect("remove bounded-read directory");
    }

    #[tokio::test]
    async fn signature_invalid_regular_cache_file_is_a_repairable_miss() {
        let (db, root) = test_db("lookup-invalid-signature");
        let signing_key = SigningKey::from_bytes(&[0x9d; 32]);
        let graph = graph_with_signature(
            &signing_key,
            1,
            0x9e,
            "bafy-lookup-invalid-signature",
            false,
        );
        let observed = observe_manifest(
            &db,
            FixedBytes::from(signing_key.verifying_key().to_bytes()),
            graph.manifest,
            None,
            SystemTime::now(),
        )
        .expect("observe invalid-event-signature graph");
        let catalog = observed
            .verify_checkpoint_catalog(
                &graph.scope,
                FetchedArtifact::from_trustless(TrustlessArtifactFetchResult::verified_for_test(
                    graph.catalog_descriptor_cid,
                    graph.catalog_bytes,
                )),
            )
            .expect("verify invalid-signature catalog");
        let current = observed
            .current_graph_chunk(
                &graph.scope,
                Some(&catalog),
                &graph.chunk_descriptor,
                RawChunkCache::new(&db).admission(observed.publication_id()),
            )
            .expect("select invalid-signature current chunk");
        let id = hex::encode(
            descriptor_identity_hash(current.descriptor()).expect("descriptor identity"),
        );
        let file_name = chunk_file_name(current.descriptor());
        let path = db.blob_path(POI_V4_RAW_CHUNK_BLOB_KIND, &file_name);
        db.ensure_blob_dir(POI_V4_RAW_CHUNK_BLOB_KIND)
            .expect("create raw chunk directory");
        fs::write(&path, &graph.chunk_bytes).expect("write invalid-signature regular file");
        db.put_blob_meta(
            POI_V4_RAW_CHUNK_BLOB_KIND,
            &id,
            &BlobMeta {
                format_version: RAW_CHUNK_CACHE_FORMAT_VERSION,
                relative_path: DbStore::relative_blob_path(POI_V4_RAW_CHUNK_BLOB_KIND, &file_name),
                content_hash: current.descriptor().artifact.sha256.0,
                source_hash: Some(
                    descriptor_identity_hash(current.descriptor()).expect("descriptor identity"),
                ),
                source_sequence: None,
                created_at: 1,
                updated_at: 1,
                last_accessed_at: 1,
                last_block: None,
            },
        )
        .expect("persist invalid-signature metadata");

        assert!(
            RawChunkCache::new(&db)
                .get(&current)
                .await
                .expect("invalid-signature lookup")
                .is_none()
        );
        assert!(path.exists());
        assert!(
            db.get_blob_meta(POI_V4_RAW_CHUNK_BLOB_KIND, &id)
                .expect("read invalid-signature metadata")
                .is_some()
        );

        drop(db);
        fs::remove_dir_all(root).expect("remove test db");
    }

    #[test]
    fn authenticated_duplicate_scope_advances_watermark_before_graph_rejection() {
        let (db, root) = test_db("duplicate-scope-watermark");
        let signing_key = SigningKey::from_bytes(&[0x2a; 32]);
        let mut graph = graph(&signing_key, 9, 0x2b, "bafy-duplicate-scope");
        let duplicate = graph.manifest.entries[0].clone();
        graph.manifest.entries.push(duplicate);
        graph.manifest.publisher_signature = Some(FixedBytes::from(
            signing_key
                .sign(&poi_v4_manifest_envelope_signing_message(&graph.manifest))
                .to_bytes(),
        ));
        let publisher = FixedBytes::from(signing_key.verifying_key().to_bytes());

        assert!(matches!(
            observe_manifest(&db, publisher, graph.manifest, None, SystemTime::now()),
            Err(super::super::PoiArtifactError::Format(
                poi::artifacts::v4::Error::DuplicateScope
            ))
        ));
        assert_eq!(
            db.get_poi_publisher_manifest_watermark(&publisher)
                .expect("read durable watermark")
                .expect("watermark exists")
                .accepted_sequence,
            9
        );

        drop(db);
        fs::remove_dir_all(root).expect("remove test db");
    }

    #[test]
    fn candidate_replay_rejects_wrong_declared_end_root() {
        let (db, root) = test_db("wrong-replay-root");
        let signing_key = SigningKey::from_bytes(&[0x54; 32]);
        let graph = graph_with_options(
            &signing_key,
            1,
            0x55,
            "bafy-wrong-root",
            true,
            Some(FixedBytes::from([0xff; 32])),
        );
        let publisher = FixedBytes::from(signing_key.verifying_key().to_bytes());
        let observed = observe_manifest(&db, publisher, graph.manifest, None, SystemTime::now())
            .expect("observe manifest");
        let catalog = observed
            .verify_checkpoint_catalog(
                &graph.scope,
                FetchedArtifact::from_trustless(TrustlessArtifactFetchResult::verified_for_test(
                    graph.catalog_descriptor_cid,
                    graph.catalog_bytes,
                )),
            )
            .expect("verify catalog");
        let current = observed
            .current_graph_chunk(
                &graph.scope,
                Some(&catalog),
                &graph.chunk_descriptor,
                RawChunkCache::new(&db).admission(observed.publication_id()),
            )
            .expect("select chunk");
        let semantic = current
            .verify_fetched(FetchedArtifact::from_trustless(
                TrustlessArtifactFetchResult::verified_for_test(
                    graph.chunk_descriptor.artifact.cid,
                    graph.chunk_bytes,
                ),
            ))
            .expect("verify transport")
            .verify_event_signatures()
            .expect("verify signatures");
        let candidate = prepare_candidate(&db, &observed, &catalog).expect("prepare candidate");
        assert!(matches!(
            candidate.replay_chunk(&semantic),
            Err(super::super::CandidateError::RootMismatch { .. })
        ));
        drop(db);
        fs::remove_dir_all(root).expect("remove test db");
    }

    #[tokio::test]
    async fn delayed_retention_rejects_reset_and_cross_database_admissions() {
        let (db, root) = test_db("admission-reset");
        let (other_db, other_root) = test_db("admission-other-db");
        let signing_key = SigningKey::from_bytes(&[0x49; 32]);
        let graph = graph(&signing_key, 1, 0x4a, "bafy-admission");
        let (current, verified) = observe_graph_chunk(&db, &signing_key, graph);

        reset_raw_chunk_cache(&db).await.expect("reset raw cache");
        assert!(matches!(
            RawChunkCache::new(&db)
                .retain(&verified)
                .await
                .expect_err("pre-reset admission must be stale"),
            RawChunkCacheError::StaleAdmission { .. }
        ));
        let id = hex::encode(
            descriptor_identity_hash(current.descriptor()).expect("descriptor identity"),
        );
        assert!(
            db.get_blob_meta(POI_V4_RAW_CHUNK_BLOB_KIND, &id)
                .expect("read raw metadata")
                .is_none()
        );
        let fresh = self::graph(&signing_key, 2, 0x4b, "bafy-admission-fresh");
        let (_, fresh_verified) = observe_graph_chunk(&db, &signing_key, fresh);
        assert_eq!(
            RawChunkCache::new(&db)
                .retain(&fresh_verified)
                .await
                .expect("post-reset admission retains"),
            RawChunkRetainOutcome::Retained
        );
        assert!(matches!(
            RawChunkCache::new(&other_db)
                .retain(&verified)
                .await
                .expect_err("cross-database admission must fail"),
            RawChunkCacheError::WrongDatabaseAdmission
        ));

        drop(other_db);
        drop(db);
        fs::remove_dir_all(other_root).expect("remove other test db");
        fs::remove_dir_all(root).expect("remove test db");
    }

    #[tokio::test]
    async fn cancelled_attempt_fence_prevents_raw_chunk_publication() {
        let (db, root) = test_db("cancelled-retain-fence");
        let signing_key = SigningKey::from_bytes(&[0x4c; 32]);
        let graph = graph(&signing_key, 1, 0x4d, "bafy-cancelled-retain");
        let (current, verified) = observe_graph_chunk(&db, &signing_key, graph);
        let cache = RawChunkCache::new(&db);

        assert_eq!(
            cache
                .retain_with_fence(&verified, || false)
                .await
                .expect("fenced retain"),
            None
        );
        assert!(cache.get(&current).await.expect("cache lookup").is_none());

        drop(db);
        fs::remove_dir_all(root).expect("remove test db");
    }

    #[test]
    fn transport_verified_chunk_with_invalid_event_signature_cannot_become_semantic() {
        let (db, root) = test_db("invalid-event-signature");
        let signing_key = SigningKey::from_bytes(&[0x4e; 32]);
        let graph = graph_with_signature(&signing_key, 1, 0x4f, "bafy-invalid-signature", false);
        let observed = observe_manifest(
            &db,
            FixedBytes::from(signing_key.verifying_key().to_bytes()),
            graph.manifest,
            None,
            SystemTime::now(),
        )
        .expect("observe manifest");
        let catalog = observed
            .verify_checkpoint_catalog(
                &graph.scope,
                FetchedArtifact::from_trustless(TrustlessArtifactFetchResult::verified_for_test(
                    graph.catalog_descriptor_cid,
                    graph.catalog_bytes,
                )),
            )
            .expect("verify catalog");
        let current = observed
            .current_graph_chunk(
                &graph.scope,
                Some(&catalog),
                &graph.chunk_descriptor,
                RawChunkCache::new(&db).admission(observed.publication_id()),
            )
            .expect("select chunk");
        let transport = current
            .verify_fetched(FetchedArtifact::from_trustless(
                TrustlessArtifactFetchResult::verified_for_test(
                    graph.chunk_descriptor.artifact.cid,
                    graph.chunk_bytes,
                ),
            ))
            .expect("transport verification succeeds");
        match transport
            .verify_event_signatures()
            .expect_err("invalid event signature cannot produce a semantic chunk")
        {
            RawChunkCacheError::V4(poi::artifacts::v4::Error::EventVerify {
                event_index,
                source,
            }) => {
                assert_eq!(event_index, 0);
                assert!(matches!(
                    source,
                    poi::artifacts::verify::VerifyError::Signature(_)
                ));
            }
            other => panic!("unexpected semantic verification error: {other:?}"),
        }

        drop(db);
        fs::remove_dir_all(root).expect("remove test db");
    }

    #[test]
    fn current_graph_rejects_manifest_swap_and_descriptor_mutation_before_cache() {
        let (db, root) = test_db("manifest-swap");
        let signing_key = SigningKey::from_bytes(&[0x4f; 32]);
        let graph = graph(&signing_key, 1, 0x50, "bafy-current-chunk");
        let observed = observe_manifest(
            &db,
            FixedBytes::from(signing_key.verifying_key().to_bytes()),
            graph.manifest,
            None,
            SystemTime::now(),
        )
        .expect("observe manifest");
        let catalog = observed
            .verify_checkpoint_catalog(
                &graph.scope,
                FetchedArtifact::from_trustless(TrustlessArtifactFetchResult::verified_for_test(
                    graph.catalog_descriptor_cid,
                    graph.catalog_bytes,
                )),
            )
            .expect("verify catalog");
        let current = observed
            .current_graph_chunk(
                &graph.scope,
                Some(&catalog),
                &graph.chunk_descriptor,
                RawChunkCache::new(&db).admission(observed.publication_id()),
            )
            .expect("select current graph chunk");
        assert!(matches!(
            current.verify_fetched(FetchedArtifact::from_trustless(
                TrustlessArtifactFetchResult::verified_for_test(
                    "bafy-swapped-manifest-chunk",
                    graph.chunk_bytes.clone(),
                ),
            )),
            Err(RawChunkCacheError::CidMismatch { .. })
        ));

        let mut mutated = graph.chunk_descriptor;
        mutated.end_root = FixedBytes::from([0xff; 32]);
        assert!(matches!(
            observed.current_graph_chunk(
                &graph.scope,
                Some(&catalog),
                &mutated,
                RawChunkCache::new(&db).admission(observed.publication_id()),
            ),
            Err(RawChunkCacheError::NotInCurrentGraph)
        ));

        drop(db);
        fs::remove_dir_all(root).expect("remove test db");
    }

    #[test]
    fn v4_corpus_evidence_commits_atomically_only_at_current_observed_sequence() {
        let (db, root) = test_db("atomic-corpus");
        let signing_key = SigningKey::from_bytes(&[0x51; 32]);
        let graph = graph(&signing_key, 7, 0x52, "bafy-corpus");
        let publisher = FixedBytes::from(signing_key.verifying_key().to_bytes());
        let observed = observe_manifest(&db, publisher, graph.manifest, None, SystemTime::now())
            .expect("observe corpus manifest");
        let catalog = observed
            .verify_checkpoint_catalog(
                &graph.scope,
                FetchedArtifact::from_trustless(TrustlessArtifactFetchResult::verified_for_test(
                    graph.catalog_descriptor_cid,
                    graph.catalog_bytes,
                )),
            )
            .expect("verify corpus catalog");
        let identity = PoiCacheIdentity::new(
            graph.scope.chain_type,
            graph.scope.chain_id,
            graph.scope.txid_version.clone(),
            graph.scope.list_key,
        );
        let raw_cache = RawChunkCache::new(&db);
        let current = observed
            .current_graph_chunk(
                &graph.scope,
                Some(&catalog),
                &graph.chunk_descriptor,
                raw_cache.admission(observed.publication_id()),
            )
            .expect("select corpus chunk");
        let chunk = current
            .verify_fetched(FetchedArtifact::from_trustless(
                TrustlessArtifactFetchResult::verified_for_test(
                    graph.chunk_descriptor.artifact.cid.clone(),
                    graph.chunk_bytes,
                ),
            ))
            .expect("verify corpus transport")
            .verify_event_signatures()
            .expect("verify corpus signatures");
        let blocked = observed
            .verify_blocked_shields(
                &graph.scope,
                FetchedArtifact::from_trustless(TrustlessArtifactFetchResult::verified_for_test(
                    graph.blocked_descriptor_cid,
                    graph.blocked_bytes,
                )),
            )
            .expect("verify blocked shields");
        let generation = db
            .poi_artifact_cache_generation()
            .expect("load corpus generation");
        let missing_blocked =
            prepare_candidate(&db, &observed, &catalog).expect("prepare incomplete candidate");
        let missing_blocked = missing_blocked
            .replay_chunk(&chunk)
            .expect("replay incomplete candidate");
        assert!(matches!(
            missing_blocked.finish(),
            Err(super::super::CandidateError::MissingBlockedShields)
        ));
        let candidate =
            prepare_candidate(&db, &observed, &catalog).expect("prepare corpus candidate");
        let candidate = candidate.replay_chunk(&chunk).expect("replay chunk");
        let candidate = candidate
            .install_blocked_shields(&blocked)
            .expect("install blocked shields");
        let candidate = candidate.finish().expect("finish candidate");

        assert_eq!(
            persist_prepared_corpus(&db, candidate).expect("commit corpus"),
            CorpusCommitOutcome::Applied
        );
        let persisted = load_persisted_cache_for_publisher(&db, &identity, publisher)
            .expect("load corpus")
            .expect("corpus present");
        assert_eq!(persisted.cache_generation, generation);
        assert!(matches!(
            persisted.record.validation,
            local_db::PoiCorpusValidationRecord::PublisherAttestedV4 {
                manifest_sequence: 7,
                format_version: FORMAT_VERSION,
                ..
            }
        ));

        let mut restarted =
            prepare_candidate(&db, &observed, &catalog).expect("prepare restart candidate");
        assert!(restarted.starting_record.is_some());
        restarted.restart_from_genesis();
        assert!(restarted.starting_record.is_none());

        let mut newer = Manifest::new(1_700_000_000_001, 8, publisher, Vec::new());
        newer
            .sign_manifest(&signing_key)
            .expect("sign newer manifest");
        observe_manifest(&db, publisher, newer, None, SystemTime::now())
            .expect("observe newer manifest");
        let stale_candidate =
            prepare_candidate(&db, &observed, &catalog).expect("prepare stale candidate");
        let stale_candidate = stale_candidate
            .install_blocked_shields(&blocked)
            .expect("install stale blocked shields");
        let stale_candidate = stale_candidate.finish().expect("finish stale candidate");
        assert_eq!(
            persist_prepared_corpus(&db, stale_candidate).expect("reject stale corpus candidate"),
            CorpusCommitOutcome::Stale
        );

        drop(db);
        fs::remove_dir_all(root).expect("remove test db");
    }

    #[test]
    fn ahead_corpus_replaces_blocked_snapshot_without_event_regression_and_survives_restart() {
        let (db, root) = test_db("ahead-blocked-replacement");
        let signing_key = SigningKey::from_bytes(&[0x5d; 32]);
        let publisher = FixedBytes::from(signing_key.verifying_key().to_bytes());
        let initial = graph_with_commitments(
            &signing_key,
            1,
            &[0x61, 0x62],
            "bafy-ahead-initial",
            true,
            None,
        );
        let (initial_observed, initial_catalog, initial_chunk, initial_blocked) =
            verified_graph(&db, &signing_key, initial);
        let initial_candidate = prepare_candidate(&db, &initial_observed, &initial_catalog)
            .expect("prepare initial corpus");
        let initial_candidate = initial_candidate
            .replay_chunk(&initial_chunk)
            .expect("replay initial corpus");
        let initial_candidate = initial_candidate
            .install_blocked_shields(&initial_blocked)
            .expect("install initial blocked snapshot");
        persist_prepared_corpus(
            &db,
            initial_candidate.finish().expect("finish initial corpus"),
        )
        .expect("persist initial corpus");

        let replacement_blocked = signed_blocked_shield(&signing_key, 0x90);
        let replacement = graph_with_commitments_and_blocked(
            &signing_key,
            2,
            &[0x61],
            "bafy-ahead-prefix",
            true,
            None,
            std::slice::from_ref(&replacement_blocked),
        );
        let (observed, catalog, _, blocked) = verified_graph(&db, &signing_key, replacement);
        let identity = PoiCacheIdentity::new(0, 1, "V2_PoseidonMerkle", publisher);
        let initial_record = db
            .get_poi_artifact_cache(0, 1, "V2_PoseidonMerkle", &publisher)
            .expect("load initial durable row")
            .expect("initial durable row");
        let initial_cache = PoiCache::from_bytes(&initial_record.cache_payload, &identity)
            .expect("decode initial durable corpus");
        let ahead_root = initial_cache.root_at_global_index(1).expect("ahead root");
        let prefix_root = initial_cache.root_at_global_index(0).expect("prefix root");
        let checkpoint_catalog = match &initial_record.validation {
            local_db::PoiCorpusValidationRecord::PublisherAttestedV4 {
                checkpoint_catalog, ..
            } => checkpoint_catalog.clone(),
            other => panic!("expected initial v4 provenance, got {other:?}"),
        };
        let variants = vec![
            (
                local_db::PoiCacheRecordSource::IndexedArtifacts,
                local_db::PoiCorpusValidationRecord::PublisherAttested {
                    publisher_pubkey: publisher,
                    manifest_sequence: 1,
                    manifest_root: ahead_root,
                    artifact_tip_index: 1,
                },
            ),
            (
                local_db::PoiCacheRecordSource::IndexedArtifacts,
                initial_record.validation.clone(),
            ),
            (
                local_db::PoiCacheRecordSource::PublicRpc,
                local_db::PoiCorpusValidationRecord::PublisherAndListSigned {
                    publisher_pubkey: publisher,
                    manifest_sequence: 1,
                    manifest_root: prefix_root,
                    artifact_tip_index: 0,
                    list_key: publisher,
                    list_signed_from_index: 1,
                },
            ),
            (
                local_db::PoiCacheRecordSource::PublicRpc,
                local_db::PoiCorpusValidationRecord::PublisherV4AndListSigned {
                    publisher_pubkey: publisher,
                    manifest_sequence: 1,
                    manifest_body_hash: match &initial_record.validation {
                        local_db::PoiCorpusValidationRecord::PublisherAttestedV4 {
                            manifest_body_hash,
                            ..
                        } => *manifest_body_hash,
                        _ => unreachable!(),
                    },
                    manifest_root: prefix_root,
                    artifact_tip_index: 0,
                    format_version: FORMAT_VERSION,
                    checkpoint_catalog,
                    list_key: publisher,
                    list_signed_from_index: 1,
                },
            ),
        ];
        for (source, validation) in variants {
            let mut before = db
                .get_poi_artifact_cache(0, 1, "V2_PoseidonMerkle", &publisher)
                .expect("load durable row before variant")
                .expect("durable row before variant");
            before.source = source;
            before.validation = validation;
            before.artifact_tip_index = match &before.validation {
                local_db::PoiCorpusValidationRecord::PublisherAttested {
                    artifact_tip_index,
                    ..
                }
                | local_db::PoiCorpusValidationRecord::PublisherAttestedV4 {
                    artifact_tip_index,
                    ..
                }
                | local_db::PoiCorpusValidationRecord::PublisherAndListSigned {
                    artifact_tip_index,
                    ..
                }
                | local_db::PoiCorpusValidationRecord::PublisherV4AndListSigned {
                    artifact_tip_index,
                    ..
                } => Some(*artifact_tip_index),
                _ => unreachable!(),
            };
            before.artifact_tip_root = match &before.validation {
                local_db::PoiCorpusValidationRecord::PublisherAttested {
                    manifest_root, ..
                }
                | local_db::PoiCorpusValidationRecord::PublisherAttestedV4 {
                    manifest_root, ..
                }
                | local_db::PoiCorpusValidationRecord::PublisherAndListSigned {
                    manifest_root,
                    ..
                }
                | local_db::PoiCorpusValidationRecord::PublisherV4AndListSigned {
                    manifest_root,
                    ..
                } => Some(*manifest_root),
                _ => unreachable!(),
            };
            before.base_descriptor.cid = "preserved-base".to_string();
            before.applied_delta_descriptors = vec![local_db::PoiArtifactDescriptorRecord {
                cid: "preserved-delta".to_string(),
                sha256: "preserved-hash".to_string(),
                byte_size: 17,
            }];
            db.put_poi_artifact_cache(&before)
                .expect("install provenance variant");

            let mut candidate =
                prepare_candidate(&db, &observed, &catalog).expect("prepare ahead corpus");
            assert_eq!(candidate.next_event_index(), 2);
            assert_eq!(candidate.root_at(0), catalog.entry().current_root);
            candidate.preserve_ahead_events();
            let candidate = candidate
                .install_blocked_shields(&blocked)
                .expect("install replacement blocked snapshot");
            let candidate = candidate.finish().expect("finish ahead candidate");
            assert_eq!(candidate.cache().progress().next_event_index, 2);
            assert_eq!(
                candidate.cache().commitment_at_global_index(1),
                Some(FixedBytes::from([0x62; 32]))
            );
            assert_eq!(
                persist_prepared_corpus(&db, candidate).expect("persist ahead candidate"),
                CorpusCommitOutcome::Applied
            );
            let after = load_persisted_cache_for_publisher(&db, &identity, publisher)
                .expect("reload preserved provenance")
                .expect("preserved corpus present")
                .record;
            assert_eq!(after.source, before.source);
            assert_eq!(after.validation, before.validation);
            assert_eq!(after.base_descriptor, before.base_descriptor);
            assert_eq!(
                after.applied_delta_descriptors,
                before.applied_delta_descriptors
            );
            assert_eq!(after.artifact_tip_index, before.artifact_tip_index);
            assert_eq!(after.artifact_tip_root, before.artifact_tip_root);
            assert_eq!(after.current_tip_index, before.current_tip_index);
            assert_eq!(after.current_tip_root, before.current_tip_root);
        }

        let persisted = load_persisted_cache_for_publisher(&db, &identity, publisher)
            .expect("load ahead corpus")
            .expect("ahead corpus present");
        assert_eq!(persisted.cache.progress().next_event_index, 2);
        assert_eq!(persisted.cache.root_at_global_index(1), Some(ahead_root));
        assert_eq!(
            persisted.cache.commitment_at_global_index(1),
            Some(FixedBytes::from([0x62; 32]))
        );
        assert_eq!(
            persisted.cache.status(&FixedBytes::from([0x90; 32])),
            railgun_wallet::PoiStatus::ShieldBlocked
        );
        assert!(matches!(
            persisted.record.validation,
            local_db::PoiCorpusValidationRecord::PublisherV4AndListSigned {
                manifest_sequence: 1,
                artifact_tip_index: 0,
                list_signed_from_index: 1,
                ..
            }
        ));

        let mut stale =
            prepare_candidate(&db, &observed, &catalog).expect("prepare stale ahead corpus");
        stale.preserve_ahead_events();
        let stale = stale
            .install_blocked_shields(&blocked)
            .expect("install stale blocked snapshot");
        let stale = stale.finish().expect("finish stale ahead candidate");
        let conflicting =
            graph_with_commitments(&signing_key, 3, &[0x7f], "bafy-ahead-conflict", true, None);
        let (conflicting_observed, conflicting_catalog, _, conflicting_blocked) =
            verified_graph(&db, &signing_key, conflicting);
        assert_eq!(
            persist_prepared_corpus(&db, stale).expect("reject stale ahead candidate"),
            CorpusCommitOutcome::Stale
        );
        let mut conflicting_candidate =
            prepare_candidate(&db, &conflicting_observed, &conflicting_catalog)
                .expect("prepare conflicting prefix");
        conflicting_candidate.preserve_ahead_events();
        let conflicting_candidate = conflicting_candidate
            .install_blocked_shields(&conflicting_blocked)
            .expect("install conflicting blocked snapshot in isolation");
        assert!(matches!(
            conflicting_candidate.finish(),
            Err(super::super::CandidateError::RootMismatch { .. })
        ));

        let matching = graph_with_commitments(
            &signing_key,
            4,
            &[0x61],
            "bafy-ahead-missing-blocked",
            true,
            None,
        );
        let (matching_observed, matching_catalog, _, _) =
            verified_graph(&db, &signing_key, matching);
        let mut missing_blocked = prepare_candidate(&db, &matching_observed, &matching_catalog)
            .expect("prepare missing-blocked ahead corpus");
        missing_blocked.preserve_ahead_events();
        assert!(matches!(
            missing_blocked.finish(),
            Err(super::super::CandidateError::MissingBlockedShields)
        ));

        drop(db);
        let reopened = DbStore::open(DbConfig {
            root_dir: root.clone(),
        })
        .expect("reopen ahead corpus DB");
        let reopened = load_persisted_cache_for_publisher(&reopened, &identity, publisher)
            .expect("load reopened ahead corpus")
            .expect("reopened ahead corpus present");
        assert_eq!(reopened.cache.progress().next_event_index, 2);
        assert_eq!(reopened.cache.root_at_global_index(1), Some(ahead_root));
        assert_eq!(
            reopened.cache.status(&FixedBytes::from([0x90; 32])),
            railgun_wallet::PoiStatus::ShieldBlocked
        );

        fs::remove_dir_all(root).expect("remove test db");
    }

    #[test]
    fn candidate_validates_partial_overlap_before_applying_suffix() {
        let (db, root) = test_db("partial-overlap");
        let signing_key = SigningKey::from_bytes(&[0x61; 32]);
        let publisher = FixedBytes::from(signing_key.verifying_key().to_bytes());

        let first =
            graph_with_commitments(&signing_key, 1, &[0x62], "bafy-overlap-first", true, None);
        let (first_observed, first_catalog, first_chunk, first_blocked) =
            verified_graph(&db, &signing_key, first);
        let first_candidate = prepare_candidate(&db, &first_observed, &first_catalog)
            .expect("prepare first candidate");
        let first_candidate = first_candidate
            .replay_chunk(&first_chunk)
            .expect("replay first chunk");
        let first_candidate = first_candidate
            .install_blocked_shields(&first_blocked)
            .expect("install first blocked snapshot");
        persist_prepared_corpus(
            &db,
            first_candidate.finish().expect("finish first candidate"),
        )
        .expect("persist first candidate");

        let extending = graph_with_commitments(
            &signing_key,
            2,
            &[0x62, 0x63],
            "bafy-overlap-extending",
            true,
            None,
        );
        let (observed, catalog, chunk, blocked) = verified_graph(&db, &signing_key, extending);
        let candidate =
            prepare_candidate(&db, &observed, &catalog).expect("prepare suffix candidate");
        assert_eq!(candidate.next_event_index(), 1);
        let candidate = candidate
            .replay_chunk(&chunk)
            .expect("validate overlap and replay suffix");
        assert_eq!(candidate.next_event_index(), 2);
        let candidate = candidate
            .install_blocked_shields(&blocked)
            .expect("install extending blocked snapshot");
        assert!(candidate.finish().is_ok());

        let conflicting = graph_with_commitments(
            &signing_key,
            3,
            &[0x64, 0x65],
            "bafy-overlap-conflict",
            true,
            None,
        );
        let (observed, catalog, chunk, _) = verified_graph(&db, &signing_key, conflicting);
        let candidate =
            prepare_candidate(&db, &observed, &catalog).expect("prepare conflicting candidate");
        assert!(matches!(
            candidate.replay_chunk(&chunk),
            Err(super::super::CandidateError::Replay { .. })
        ));
        assert_eq!(
            db.get_poi_publisher_manifest_watermark(&publisher)
                .expect("read watermark")
                .expect("watermark exists")
                .accepted_sequence,
            3
        );

        drop(db);
        fs::remove_dir_all(root).expect("remove test db");
    }

    #[test]
    fn candidate_authenticates_non_boundary_and_fully_consumed_start_roots() {
        let (db, root) = test_db("descriptor-start-root-replay");
        let signing_key = SigningKey::from_bytes(&[0x66; 32]);
        let first = graph_with_commitments(
            &signing_key,
            1,
            &[0x67, 0x68],
            "bafy-start-root-first",
            true,
            None,
        );
        let (first_observed, first_catalog, first_chunk, first_blocked) =
            verified_graph(&db, &signing_key, first);
        let first_candidate = prepare_candidate(&db, &first_observed, &first_catalog)
            .expect("prepare start-root base");
        let first_candidate = first_candidate
            .replay_chunk(&first_chunk)
            .expect("replay start-root base");
        let first_candidate = first_candidate
            .install_blocked_shields(&first_blocked)
            .expect("install start-root base blocked snapshot");
        persist_prepared_corpus(
            &db,
            first_candidate.finish().expect("finish start-root base"),
        )
        .expect("persist start-root base");

        let extending = graph_with_commitments(
            &signing_key,
            2,
            &[0x67, 0x68, 0x69],
            "bafy-start-root-extending",
            true,
            None,
        );
        let (observed, catalog, full_chunk, _) = verified_graph(&db, &signing_key, extending);
        let candidate = || {
            prepare_candidate(&db, &observed, &catalog)
                .expect("prepare descriptor-relative candidate")
        };
        let expected_start = candidate().root_at(0).expect("root before range start one");
        let wrong_start = FixedBytes::from([0xfe; 32]);
        assert_ne!(wrong_start, expected_start);

        let non_boundary_artifact = EventArtifact::new(
            full_chunk.artifact.scope.clone(),
            EventArtifactKind::Bridge,
            Some(wrong_start),
            full_chunk.artifact.end_root,
            full_chunk.artifact.events[1..].to_vec(),
        )
        .expect("build conflicting non-boundary artifact");
        let non_boundary = semantic_chunk_from_artifact(
            &full_chunk,
            non_boundary_artifact,
            "bafy-conflicting-non-boundary",
        );
        let rejected = candidate();
        assert!(matches!(
            rejected.replay_chunk(&non_boundary),
            Err(super::super::CandidateError::RootMismatch { .. })
        ));

        let matching_artifact = EventArtifact::new(
            full_chunk.artifact.scope.clone(),
            EventArtifactKind::Bridge,
            Some(expected_start),
            full_chunk.artifact.end_root,
            full_chunk.artifact.events[1..].to_vec(),
        )
        .expect("build matching non-boundary artifact");
        let matching = semantic_chunk_from_artifact(
            &full_chunk,
            matching_artifact,
            "bafy-matching-non-boundary",
        );
        let accepted = candidate();
        let accepted = accepted
            .replay_chunk(&matching)
            .expect("matching non-boundary start root");
        assert_eq!(accepted.next_event_index(), 3);

        let fully_consumed_end = candidate().root_at(1).expect("fully consumed end root");
        let fully_consumed_artifact = EventArtifact::new(
            full_chunk.artifact.scope.clone(),
            EventArtifactKind::Bridge,
            Some(wrong_start),
            fully_consumed_end,
            full_chunk.artifact.events[1..2].to_vec(),
        )
        .expect("build conflicting fully consumed artifact");
        let fully_consumed = semantic_chunk_from_artifact(
            &full_chunk,
            fully_consumed_artifact,
            "bafy-conflicting-fully-consumed",
        );
        let rejected = candidate();
        assert!(matches!(
            rejected.replay_chunk(&fully_consumed),
            Err(super::super::CandidateError::RootMismatch { .. })
        ));

        let matching_consumed_artifact = EventArtifact::new(
            full_chunk.artifact.scope.clone(),
            EventArtifactKind::Bridge,
            Some(expected_start),
            fully_consumed_end,
            full_chunk.artifact.events[1..2].to_vec(),
        )
        .expect("build matching fully consumed artifact");
        let matching_consumed = semantic_chunk_from_artifact(
            &full_chunk,
            matching_consumed_artifact,
            "bafy-matching-fully-consumed",
        );
        let consumed = candidate();
        let consumed_before = consumed.cache.to_bytes().expect("serialize consumed base");
        let consumed = consumed
            .replay_chunk(&matching_consumed)
            .expect("matching fully consumed descriptor");
        assert_eq!(consumed.next_event_index(), 2);
        assert_eq!(
            consumed
                .cache
                .to_bytes()
                .expect("serialize consumed result"),
            consumed_before
        );

        drop(db);
        fs::remove_dir_all(root).expect("remove test db");
    }

    #[test]
    fn candidate_rejects_tree_boundary_prior_root_conflict() {
        let (db, root) = test_db("tree-boundary-start-root");
        let signing_key = SigningKey::from_bytes(&[0x6a; 32]);
        let graph = graph(&signing_key, 1, 0x6b, "bafy-tree-boundary-template");
        let (observed, catalog, template, _) = verified_graph(&db, &signing_key, graph);
        let mut candidate =
            prepare_candidate(&db, &observed, &catalog).expect("prepare boundary candidate");
        let mut cache = PoiCache::new(candidate.cache.identity().clone());
        let base_events = (0..=TREE_LEAF_COUNT)
            .map(boundary_snapshot_event)
            .collect::<Vec<_>>();
        cache
            .apply_verified_artifact_events(&base_events)
            .expect("apply tree-boundary durable prefix");
        let descriptor_start = TREE_LEAF_COUNT;
        let next_event_index = descriptor_start + 1;
        let expected_start = cache
            .root_at_global_index(descriptor_start - 1)
            .expect("root before tree boundary");
        let current_root = cache
            .root_at_global_index(next_event_index - 1)
            .expect("current root inside next tree");
        assert_ne!(expected_start, current_root);
        let suffix_event = boundary_snapshot_event(next_event_index);
        let mut completed = cache.clone();
        completed
            .apply_verified_artifact_events(std::slice::from_ref(&suffix_event))
            .expect("apply unchanged boundary suffix to reference cache");
        let end_root = completed
            .root_at_global_index(next_event_index)
            .expect("reference suffix end root");
        let wrong_start = FixedBytes::from([0xfd; 32]);
        assert_ne!(wrong_start, expected_start);
        let artifact = EventArtifact::new(
            template.artifact.scope.clone(),
            EventArtifactKind::Bridge,
            Some(wrong_start),
            end_root,
            vec![
                base_events
                    .last()
                    .expect("tree-boundary overlap event")
                    .clone(),
                suffix_event,
            ],
        )
        .expect("build tree-boundary conflict artifact");
        let descriptor = artifact
            .descriptor("bafy-tree-boundary-conflict")
            .expect("describe tree-boundary conflict");
        let bytes = artifact.to_bytes().expect("encode tree-boundary conflict");
        let mut entry = template.entry.clone();
        entry.event_count = next_event_index + 1;
        entry.current_tip_index = Some(next_event_index);
        entry.current_root = Some(end_root);
        candidate.cache = cache;
        candidate.entry = entry.clone();
        let chunk = SemanticVerifiedChunk {
            descriptor,
            entry,
            bytes,
            artifact,
            admission: template.admission,
            durable_cache_member: template.durable_cache_member,
        };
        assert!(matches!(
            candidate.replay_chunk(&chunk),
            Err(super::super::CandidateError::RootMismatch { .. })
        ));

        drop(db);
        fs::remove_dir_all(root).expect("remove test db");
    }

    #[test]
    fn persisted_publisher_legacy_candidate_uses_durable_start_root_and_complete_restart_replays() {
        let (db, root) = test_db("publisher-legacy-start-root");
        let signing_key = SigningKey::from_bytes(&[0x6c; 32]);
        let publisher = FixedBytes::from(signing_key.verifying_key().to_bytes());
        let initial = graph_with_commitments(
            &signing_key,
            1,
            &[0x6d],
            "bafy-legacy-start-initial",
            true,
            None,
        );
        let (initial_observed, initial_catalog, initial_chunk, initial_blocked) =
            verified_graph(&db, &signing_key, initial);
        let initial_candidate = prepare_candidate(&db, &initial_observed, &initial_catalog)
            .expect("prepare legacy-start base");
        let initial_candidate = initial_candidate
            .replay_chunk(&initial_chunk)
            .expect("replay legacy-start base");
        let initial_candidate = initial_candidate
            .install_blocked_shields(&initial_blocked)
            .expect("install legacy-start blocked snapshot");
        persist_prepared_corpus(
            &db,
            initial_candidate
                .finish()
                .expect("finish legacy-start base"),
        )
        .expect("persist legacy-start base");

        let mut record = db
            .get_poi_artifact_cache(0, 1, "V2_PoseidonMerkle", &publisher)
            .expect("read base record")
            .expect("base record");
        record.source = local_db::PoiCacheRecordSource::IndexedArtifacts;
        record.validation = local_db::PoiCorpusValidationRecord::PublisherAttested {
            publisher_pubkey: publisher,
            manifest_sequence: 1,
            manifest_root: record.current_tip_root,
            artifact_tip_index: record.current_tip_index,
        };
        record.artifact_tip_index = Some(record.current_tip_index);
        record.artifact_tip_root = Some(record.current_tip_root);
        db.put_poi_artifact_cache(&record)
            .expect("replace base provenance with publisher legacy");

        let extending = graph_with_commitments(
            &signing_key,
            2,
            &[0x6d, 0x6e],
            "bafy-legacy-start-extending",
            true,
            None,
        );
        let (observed, catalog, chunk, _) = verified_graph(&db, &signing_key, extending);
        let legacy = prepare_candidate(&db, &observed, &catalog).expect("prepare publisher legacy");
        let legacy_start_root = legacy.root_at(0).expect("publisher legacy durable root");
        assert_eq!(
            legacy
                .expected_descriptor_start_root(1)
                .expect("legacy descriptor start root"),
            Some(legacy_start_root)
        );
        let legacy_suffix_artifact = EventArtifact::new(
            chunk.artifact.scope.clone(),
            EventArtifactKind::Bridge,
            Some(legacy_start_root),
            chunk.artifact.end_root,
            chunk.artifact.events[1..].to_vec(),
        )
        .expect("build publisher legacy suffix");
        let legacy_suffix = semantic_chunk_from_artifact(
            &chunk,
            legacy_suffix_artifact,
            "bafy-publisher-legacy-suffix",
        );
        let legacy = legacy
            .replay_chunk(&legacy_suffix)
            .expect("publisher legacy suffix uses durable descriptor start root");
        assert_eq!(legacy.next_event_index(), 2);
        legacy
            .validate_canonical_boundaries()
            .expect("publisher legacy cache matches canonical boundaries");

        let mut restarted =
            prepare_candidate(&db, &observed, &catalog).expect("prepare complete restart");
        restarted.restart_from_genesis();
        let restarted = restarted
            .replay_chunk(&chunk)
            .expect("complete restart route replays from genesis");
        assert_eq!(restarted.next_event_index(), 2);

        drop(db);
        fs::remove_dir_all(root).expect("remove test db");
    }

    #[test]
    fn canonical_boundaries_accept_partial_checkpoint_and_tail_but_ignore_retained_bridges() {
        let (db, root) = test_db("canonical-partial-tail");
        let signing_key = SigningKey::from_bytes(&[0x6f; 32]);
        let graph = graph(&signing_key, 1, 0x70, "bafy-canonical-template");
        let (observed, catalog, template, _) = verified_graph(&db, &signing_key, graph);
        let mut candidate = prepare_candidate(&db, &observed, &catalog)
            .expect("prepare canonical-boundary candidate");
        let mut cache = PoiCache::new(candidate.cache.identity().clone());
        let events = (0..3).map(boundary_snapshot_event).collect::<Vec<_>>();
        cache
            .apply_verified_artifact_events(&events)
            .expect("apply canonical-boundary events");
        let checkpoint_root = cache
            .root_at_global_index(1)
            .expect("partial checkpoint root");
        let tail_root = cache.root_at_global_index(2).expect("current tail root");
        let mut checkpoint = template.descriptor.clone();
        checkpoint.kind = EventArtifactKind::Checkpoint;
        checkpoint.range = poi::artifacts::v4::EventRange {
            start_index: 0,
            end_index: 1,
        };
        checkpoint.row_count = 2;
        checkpoint.start_root = None;
        checkpoint.end_root = checkpoint_root;
        let mut tail = template.descriptor;
        tail.kind = EventArtifactKind::CurrentTail;
        tail.range = poi::artifacts::v4::EventRange {
            start_index: 2,
            end_index: 2,
        };
        tail.row_count = 1;
        tail.start_root = Some(checkpoint_root);
        tail.end_root = tail_root;
        let mut unused_bridge = tail.clone();
        unused_bridge.kind = EventArtifactKind::Bridge;
        unused_bridge.start_root = Some(FixedBytes::from([0xff; 32]));

        candidate.cache = cache;
        candidate.entry.event_count = 3;
        candidate.entry.current_tip_index = Some(2);
        candidate.entry.current_root = Some(tail_root);
        candidate.entry.current_tail = Some(tail.clone());
        candidate.entry.retained_bridges = vec![unused_bridge];
        candidate.canonical_boundaries.checkpoint_descriptors = vec![checkpoint];
        candidate.canonical_boundaries.current_tail = Some(tail);
        candidate.blocked_state = super::super::CandidateBlockedState::Verified;

        candidate
            .validate_canonical_boundaries()
            .expect("matching partial checkpoint and tail boundaries");
        assert!(candidate.finish().is_ok());

        drop(db);
        fs::remove_dir_all(root).expect("remove test db");
    }

    #[test]
    fn changed_completed_tree_with_same_event_count_and_current_tip_root_fails_finalization() {
        let (db, root) = test_db("changed-completed-tree");
        let signing_key = SigningKey::from_bytes(&[0x71; 32]);
        let graph = graph(&signing_key, 1, 0x72, "bafy-completed-tree-template");
        let (observed, catalog, template, _) = verified_graph(&db, &signing_key, graph);
        let mut candidate =
            prepare_candidate(&db, &observed, &catalog).expect("prepare completed-tree candidate");
        let mut canonical_cache = PoiCache::new(candidate.cache.identity().clone());
        let events = (0..=TREE_LEAF_COUNT)
            .map(boundary_snapshot_event)
            .collect::<Vec<_>>();
        canonical_cache
            .apply_verified_artifact_events(&events)
            .expect("apply canonical multi-tree history");
        let canonical_first_checkpoint_root = canonical_cache
            .root_at_global_index(32_767)
            .expect("canonical first checkpoint root");
        let canonical_completed_root = canonical_cache
            .root_at_global_index(TREE_LEAF_COUNT - 1)
            .expect("canonical completed-tree root");
        let current_tip_root = canonical_cache
            .root_at_global_index(TREE_LEAF_COUNT)
            .expect("canonical current-tree tip root");
        let mut changed_cache = canonical_cache.clone();
        let mut changed_first = boundary_snapshot_event(0);
        changed_first.blinded_commitment = [0xfc; 32];
        changed_cache
            .apply_verified_artifact_events(std::slice::from_ref(&changed_first))
            .expect("replace completed-tree event");
        assert_ne!(
            changed_cache.root_at_global_index(TREE_LEAF_COUNT - 1),
            Some(canonical_completed_root)
        );
        assert_eq!(
            changed_cache.root_at_global_index(TREE_LEAF_COUNT),
            Some(current_tip_root)
        );

        let mut first_checkpoint = template.descriptor.clone();
        first_checkpoint.range = poi::artifacts::v4::EventRange {
            start_index: 0,
            end_index: 32_767,
        };
        first_checkpoint.row_count = 32_768;
        first_checkpoint.start_root = None;
        first_checkpoint.end_root = canonical_first_checkpoint_root;
        let mut second_checkpoint = template.descriptor.clone();
        second_checkpoint.range = poi::artifacts::v4::EventRange {
            start_index: 32_768,
            end_index: TREE_LEAF_COUNT - 1,
        };
        second_checkpoint.row_count = 32_768;
        second_checkpoint.start_root = Some(canonical_first_checkpoint_root);
        second_checkpoint.end_root = canonical_completed_root;
        let mut tail = template.descriptor;
        tail.kind = EventArtifactKind::CurrentTail;
        tail.range = poi::artifacts::v4::EventRange {
            start_index: TREE_LEAF_COUNT,
            end_index: TREE_LEAF_COUNT,
        };
        tail.row_count = 1;
        tail.start_root = Some(canonical_completed_root);
        tail.end_root = current_tip_root;

        candidate.cache = changed_cache;
        candidate.entry.event_count = TREE_LEAF_COUNT + 1;
        candidate.entry.current_tip_index = Some(TREE_LEAF_COUNT);
        candidate.entry.current_root = Some(current_tip_root);
        candidate.entry.current_tail = Some(tail.clone());
        candidate.canonical_boundaries.checkpoint_descriptors =
            vec![first_checkpoint, second_checkpoint];
        candidate.canonical_boundaries.current_tail = Some(tail);
        candidate.blocked_state = super::super::CandidateBlockedState::Verified;

        assert_eq!(candidate.next_event_index(), candidate.entry.event_count);
        assert_eq!(candidate.current_root(), candidate.entry.current_root);
        assert!(matches!(
            candidate.validate_canonical_boundaries(),
            Err(super::super::CandidateError::RootMismatch { .. })
        ));
        assert!(matches!(
            candidate.finish(),
            Err(super::super::CandidateError::RootMismatch { .. })
        ));

        drop(db);
        fs::remove_dir_all(root).expect("remove test db");
    }

    #[test]
    fn ahead_blocked_only_boundary_failure_preserves_durable_events_and_blocked_state() {
        let (db, root) = test_db("ahead-boundary-failure");
        let signing_key = SigningKey::from_bytes(&[0x73; 32]);
        let publisher = FixedBytes::from(signing_key.verifying_key().to_bytes());
        let initial_blocked = signed_blocked_shield(&signing_key, 0x74);
        let initial = graph_with_commitments_and_blocked(
            &signing_key,
            1,
            &[0x75, 0x76],
            "bafy-ahead-boundary-initial",
            true,
            None,
            std::slice::from_ref(&initial_blocked),
        );
        let (initial_observed, initial_catalog, initial_chunk, initial_blocked_artifact) =
            verified_graph(&db, &signing_key, initial);
        let initial_candidate = prepare_candidate(&db, &initial_observed, &initial_catalog)
            .expect("prepare ahead-boundary base");
        let initial_candidate = initial_candidate
            .replay_chunk(&initial_chunk)
            .expect("replay ahead-boundary base");
        let initial_candidate = initial_candidate
            .install_blocked_shields(&initial_blocked_artifact)
            .expect("install ahead-boundary base blocked state");
        persist_prepared_corpus(
            &db,
            initial_candidate
                .finish()
                .expect("finish ahead-boundary base"),
        )
        .expect("persist ahead-boundary base");
        let identity = PoiCacheIdentity::new(0, 1, "V2_PoseidonMerkle", publisher);
        let before = load_persisted_cache_for_publisher(&db, &identity, publisher)
            .expect("load ahead-boundary base")
            .expect("ahead-boundary base exists");

        let replacement_blocked = signed_blocked_shield(&signing_key, 0x77);
        let prefix = graph_with_commitments_and_blocked(
            &signing_key,
            2,
            &[0x75],
            "bafy-ahead-boundary-prefix",
            true,
            None,
            std::slice::from_ref(&replacement_blocked),
        );
        let (observed, catalog, _, blocked) = verified_graph(&db, &signing_key, prefix);
        let mut candidate =
            prepare_candidate(&db, &observed, &catalog).expect("prepare ahead candidate");
        assert!(candidate.next_event_index() > candidate.entry.event_count);
        candidate.preserve_ahead_events();
        let mut candidate = candidate
            .install_blocked_shields(&blocked)
            .expect("stage replacement blocked state");
        candidate.canonical_boundaries.checkpoint_descriptors[0].end_root =
            FixedBytes::from([0xfb; 32]);

        assert!(matches!(
            candidate.finish(),
            Err(super::super::CandidateError::RootMismatch { .. })
        ));
        let after = load_persisted_cache_for_publisher(&db, &identity, publisher)
            .expect("reload ahead-boundary base")
            .expect("ahead-boundary base remains");
        assert_eq!(after.record.cache_payload, before.record.cache_payload);
        assert_eq!(
            after.record.current_tip_index,
            before.record.current_tip_index
        );
        assert_eq!(
            after.record.current_tip_root,
            before.record.current_tip_root
        );
        assert_eq!(
            after.cache.status(&FixedBytes::from([0x74; 32])),
            railgun_wallet::PoiStatus::ShieldBlocked
        );
        assert_ne!(
            after.cache.status(&FixedBytes::from([0x77; 32])),
            railgun_wallet::PoiStatus::ShieldBlocked
        );

        drop(db);
        fs::remove_dir_all(root).expect("remove test db");
    }

    struct TestGraph {
        scope: Scope,
        manifest: Manifest,
        catalog_descriptor_cid: String,
        catalog_bytes: Vec<u8>,
        chunk_descriptor: EventArtifactDescriptor,
        chunk_bytes: Vec<u8>,
        blocked_descriptor_cid: String,
        blocked_bytes: Vec<u8>,
    }

    fn graph(signing_key: &SigningKey, sequence: u64, commitment: u8, cid: &str) -> TestGraph {
        graph_with_signature(signing_key, sequence, commitment, cid, true)
    }

    fn graph_with_signature(
        signing_key: &SigningKey,
        sequence: u64,
        commitment: u8,
        cid: &str,
        valid_signature: bool,
    ) -> TestGraph {
        graph_with_options(
            signing_key,
            sequence,
            commitment,
            cid,
            valid_signature,
            None,
        )
    }

    fn graph_with_options(
        signing_key: &SigningKey,
        sequence: u64,
        commitment: u8,
        cid: &str,
        valid_signature: bool,
        declared_root: Option<FixedBytes<32>>,
    ) -> TestGraph {
        graph_with_commitments(
            signing_key,
            sequence,
            &[commitment],
            cid,
            valid_signature,
            declared_root,
        )
    }

    fn graph_with_commitments(
        signing_key: &SigningKey,
        sequence: u64,
        commitments: &[u8],
        cid: &str,
        valid_signature: bool,
        declared_root: Option<FixedBytes<32>>,
    ) -> TestGraph {
        graph_with_commitments_and_blocked(
            signing_key,
            sequence,
            commitments,
            cid,
            valid_signature,
            declared_root,
            &[],
        )
    }

    fn graph_with_commitments_and_blocked(
        signing_key: &SigningKey,
        sequence: u64,
        commitments: &[u8],
        cid: &str,
        valid_signature: bool,
        declared_root: Option<FixedBytes<32>>,
        blocked_shields: &[SignedBlockedShield],
    ) -> TestGraph {
        assert!(!commitments.is_empty(), "test graph requires events");
        let scope = Scope::new(
            FixedBytes::from(signing_key.verifying_key().to_bytes()),
            0,
            1,
            "V2_PoseidonMerkle",
        );
        let events = commitments
            .iter()
            .copied()
            .enumerate()
            .map(|(index, commitment)| {
                let index = u64::try_from(index).expect("test event index");
                let mut signed_event = SignedPoiEvent {
                    index,
                    blinded_commitment: FixedBytes::from([commitment; 32]),
                    signature: String::new(),
                    event_type: PoiEventType::Shield,
                };
                signed_event.signature = hex::encode_prefixed(
                    signing_key
                        .sign(&canonical_poi_event_message(&signed_event))
                        .to_bytes(),
                );
                let mut signature = signing_key
                    .sign(&canonical_poi_event_message(&signed_event))
                    .to_bytes();
                if !valid_signature {
                    signature[0] ^= 1;
                }
                SnapshotEvent {
                    event_index: index,
                    blinded_commitment: [commitment; 32],
                    signature,
                    event_type: PoiEventType::Shield,
                }
            })
            .collect::<Vec<_>>();
        let mut root_cache = PoiCache::new(PoiCacheIdentity::new(
            scope.chain_type,
            scope.chain_id,
            scope.txid_version.clone(),
            scope.list_key,
        ));
        root_cache
            .apply_verified_artifact_events(&events)
            .expect("apply root event");
        root_cache.accept_current_roots();
        let replayed_root = *root_cache.current_roots().get(&0).expect("test chunk root");
        let root = declared_root.unwrap_or(replayed_root);
        let chunk = EventArtifact::new(
            scope.clone(),
            EventArtifactKind::Checkpoint,
            None,
            root,
            events,
        )
        .expect("build chunk");
        let chunk_bytes = chunk.to_bytes().expect("encode chunk");
        let chunk_descriptor = chunk.descriptor(cid).expect("describe chunk");
        let catalog = CheckpointCatalog::new(scope.clone(), vec![chunk_descriptor.clone()])
            .expect("build catalog");
        let catalog_bytes = catalog.to_bytes().expect("encode catalog");
        let catalog_descriptor_cid = format!("bafy-catalog-{sequence}-{}", commitments[0]);
        let catalog_descriptor = catalog
            .descriptor(catalog_descriptor_cid.clone())
            .expect("describe catalog");
        let blocked = BlockedShieldsArtifact::from_signed_records(scope.clone(), blocked_shields);
        let blocked_bytes = blocked.to_bytes().expect("encode blocked shields");
        let blocked_descriptor_cid = format!("bafy-blocked-{sequence}-{}", commitments[0]);
        let event_count = u64::try_from(commitments.len()).expect("test event count");
        let entry = ManifestEntry {
            scope: scope.clone(),
            event_count,
            current_tip_index: Some(event_count - 1),
            current_root: Some(root),
            checkpoint_catalog: catalog_descriptor,
            current_tail: None,
            retained_bridges: Vec::new(),
            blocked_shields: BlockedShieldsDescriptor {
                artifact: ArtifactDescriptor::from_bytes(
                    blocked_descriptor_cid.clone(),
                    &blocked_bytes,
                ),
                format_version: FORMAT_VERSION,
                scope: scope.clone(),
                row_count: u64::try_from(blocked_shields.len()).expect("test blocked-shield count"),
                encoding: ArtifactEncoding::CanonicalJson,
                compression: Compression::Identity,
            },
        };
        let mut manifest =
            Manifest::new(1_700_000_000_000, sequence, FixedBytes::ZERO, vec![entry]);
        manifest.sign_manifest(signing_key).expect("sign manifest");
        TestGraph {
            scope,
            manifest,
            catalog_descriptor_cid,
            catalog_bytes,
            chunk_descriptor,
            chunk_bytes,
            blocked_descriptor_cid,
            blocked_bytes,
        }
    }

    fn semantic_chunk_from_artifact(
        template: &SemanticVerifiedChunk,
        artifact: EventArtifact,
        cid: &str,
    ) -> SemanticVerifiedChunk {
        let descriptor = artifact
            .descriptor(cid)
            .expect("describe semantic test chunk");
        let bytes = artifact.to_bytes().expect("encode semantic test chunk");
        SemanticVerifiedChunk {
            descriptor,
            entry: template.entry.clone(),
            bytes,
            artifact,
            admission: template.admission.clone(),
            durable_cache_member: template.durable_cache_member,
        }
    }

    fn boundary_snapshot_event(event_index: u64) -> SnapshotEvent {
        let mut blinded_commitment = [0_u8; 32];
        blinded_commitment[24..].copy_from_slice(&event_index.saturating_add(1).to_be_bytes());
        SnapshotEvent {
            event_index,
            blinded_commitment,
            signature: [0_u8; 64],
            event_type: PoiEventType::Shield,
        }
    }

    fn signed_blocked_shield(signing_key: &SigningKey, marker: u8) -> SignedBlockedShield {
        let mut record = SignedBlockedShield {
            commitment_hash: hex::encode_prefixed([marker.wrapping_add(1); 32]),
            blinded_commitment: hex::encode_prefixed([marker; 32]),
            block_reason: Some(format!("blocked-{marker}")),
            signature: String::new(),
        };
        record.signature = hex::encode_prefixed(
            signing_key
                .sign(&canonical_blocked_shield_message(&record))
                .to_bytes(),
        );
        record
    }

    fn observe_graph_chunk(
        db: &DbStore,
        signing_key: &SigningKey,
        graph: TestGraph,
    ) -> (CurrentChunk, SemanticVerifiedChunk) {
        let observed = observe_manifest(
            db,
            FixedBytes::from(signing_key.verifying_key().to_bytes()),
            graph.manifest,
            None,
            SystemTime::now(),
        )
        .expect("observe manifest");
        let catalog = observed
            .verify_checkpoint_catalog(
                &graph.scope,
                FetchedArtifact::from_trustless(TrustlessArtifactFetchResult::verified_for_test(
                    graph.catalog_descriptor_cid,
                    graph.catalog_bytes,
                )),
            )
            .expect("verify catalog");
        let current = observed
            .current_graph_chunk(
                &graph.scope,
                Some(&catalog),
                &graph.chunk_descriptor,
                RawChunkCache::new(db).admission(observed.publication_id()),
            )
            .expect("select current chunk");
        let verified = current
            .clone()
            .verify_fetched(FetchedArtifact::from_trustless(
                TrustlessArtifactFetchResult::verified_for_test(
                    graph.chunk_descriptor.artifact.cid,
                    graph.chunk_bytes,
                ),
            ))
            .expect("verify fetched chunk")
            .verify_event_signatures()
            .expect("verify event signatures");
        (current, verified)
    }

    fn verified_graph(
        db: &DbStore,
        signing_key: &SigningKey,
        graph: TestGraph,
    ) -> (
        super::super::ObservedManifest,
        VerifiedCatalog,
        SemanticVerifiedChunk,
        VerifiedBlockedShields,
    ) {
        let observed = observe_manifest(
            db,
            FixedBytes::from(signing_key.verifying_key().to_bytes()),
            graph.manifest,
            None,
            SystemTime::now(),
        )
        .expect("observe test graph");
        let catalog = observed
            .verify_checkpoint_catalog(
                &graph.scope,
                FetchedArtifact::from_trustless(TrustlessArtifactFetchResult::verified_for_test(
                    graph.catalog_descriptor_cid,
                    graph.catalog_bytes,
                )),
            )
            .expect("verify test catalog");
        let current = observed
            .current_graph_chunk(
                &graph.scope,
                Some(&catalog),
                &graph.chunk_descriptor,
                RawChunkCache::new(db).admission(observed.publication_id()),
            )
            .expect("select test chunk");
        let chunk = current
            .verify_fetched(FetchedArtifact::from_trustless(
                TrustlessArtifactFetchResult::verified_for_test(
                    graph.chunk_descriptor.artifact.cid,
                    graph.chunk_bytes,
                ),
            ))
            .expect("verify test transport")
            .verify_event_signatures()
            .expect("verify test signatures");
        let blocked = observed
            .verify_blocked_shields(
                &graph.scope,
                FetchedArtifact::from_trustless(TrustlessArtifactFetchResult::verified_for_test(
                    graph.blocked_descriptor_cid,
                    graph.blocked_bytes,
                )),
            )
            .expect("verify test blocked snapshot");
        (observed, catalog, chunk, blocked)
    }

    fn test_db(name: &str) -> (DbStore, PathBuf) {
        let root = test_path(name);
        let db = DbStore::open(DbConfig {
            root_dir: root.clone(),
        })
        .expect("open test db");
        (db, root)
    }
}
