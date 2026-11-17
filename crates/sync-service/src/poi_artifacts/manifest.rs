//! Publisher manifest observation, ordering and freshness, and the durable publisher watermark.

use std::sync::{LazyLock, Mutex, MutexGuard};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use alloy::hex;
use alloy::primitives::FixedBytes;
use local_db::{
    DbStore, PoiArtifactCacheRecord, PoiCorpusValidationRecord, PoiPublisherManifestObservation,
    PoiPublisherManifestWatermarkRecord, StoredRecord,
};
use poi::artifacts::v4::{Manifest, ManifestEntry, PublicationId, Scope};
use poi::cache::PoiCacheIdentity;

use super::PoiArtifactError;
use super::validation::{normalize_legacy_artifact_metadata, validate_persisted_record};

static POI_ARTIFACT_PUBLICATION_FENCE: LazyLock<Mutex<()>> = LazyLock::new(|| Mutex::new(()));

pub(super) fn lock_poi_artifact_publication() -> MutexGuard<'static, ()> {
    POI_ARTIFACT_PUBLICATION_FENCE
        .lock()
        .expect("POI artifact publication fence poisoned")
}

#[derive(Clone)]
pub struct ObservedManifest {
    pub(super) manifest: Manifest,
    pub(super) publication_id: PublicationId,
    /// Configured index of the gateway that served the manifest bytes, used as
    /// the first choice for its checkpoint catalogs. Transport metadata only;
    /// it is not persisted.
    serving_gateway_index: Option<usize>,
}

impl ObservedManifest {
    #[must_use]
    pub const fn manifest(&self) -> &Manifest {
        &self.manifest
    }

    #[must_use]
    pub const fn publication_id(&self) -> PublicationId {
        self.publication_id
    }

    pub(crate) const fn serving_gateway_index(&self) -> Option<usize> {
        self.serving_gateway_index
    }

    pub(crate) const fn set_serving_gateway_index(&mut self, gateway_index: usize) {
        self.serving_gateway_index = Some(gateway_index);
    }

    pub(super) fn entry(&self, scope: &Scope) -> Result<&ManifestEntry, PoiArtifactError> {
        self.manifest
            .entries
            .iter()
            .find(|entry| entry.scope == *scope)
            .ok_or_else(|| PoiArtifactError::MissingManifestEntry {
                chain_id: scope.chain_id,
                list_key: hex::encode_prefixed(scope.list_key.as_slice()),
                txid_version: scope.txid_version.clone(),
            })
    }
}

pub(crate) fn observe_manifest_with_clock<F>(
    db: &DbStore,
    trusted_publisher_pubkey: FixedBytes<32>,
    manifest: Manifest,
    max_age: Option<Duration>,
    acceptance_time: &F,
) -> Result<ObservedManifest, PoiArtifactError>
where
    F: Fn() -> SystemTime + ?Sized,
{
    manifest.verify_trusted_signature_envelope(&trusted_publisher_pubkey.0)?;
    let publication_id = manifest.publication_id_envelope()?;
    let _publication_fence = lock_poi_artifact_publication();
    let previous = publisher_manifest_watermark(db, trusted_publisher_pubkey)?;
    let exact_replay = validate_manifest_order(&publication_id, previous.as_ref())?;
    if !exact_replay {
        // Keep this sample inside the observation fences and adjacent to freshness and persistence.
        validate_manifest_freshness(&manifest, max_age, acceptance_time())?;
    }
    match db.observe_poi_v4_publisher_manifest(
        trusted_publisher_pubkey,
        publication_id.sequence,
        publication_id.manifest_body_hash,
    )? {
        PoiPublisherManifestObservation::Accepted { .. } => {}
        PoiPublisherManifestObservation::Rollback { record } => {
            return Err(PoiArtifactError::ManifestSequenceRollback {
                previous: record.accepted_sequence,
                received: manifest.sequence,
            });
        }
        PoiPublisherManifestObservation::Equivocation { .. } => {
            return Err(PoiArtifactError::ManifestSequenceEquivocation {
                sequence: manifest.sequence,
            });
        }
    }
    manifest.validate()?;
    Ok(ObservedManifest {
        manifest,
        publication_id,
        serving_gateway_index: None,
    })
}

/// Returns the durable publisher manifest sequence, including a migrated
/// hashless floor, for use as the IPNS resolution sequence floor.
pub(crate) fn publisher_manifest_sequence(
    db: &DbStore,
    publisher_pubkey: FixedBytes<32>,
) -> Result<Option<u64>, PoiArtifactError> {
    let _publication_fence = lock_poi_artifact_publication();
    Ok(publisher_manifest_watermark(db, publisher_pubkey)?.map(|record| record.accepted_sequence))
}

pub(super) fn publisher_manifest_watermark(
    db: &DbStore,
    publisher_pubkey: FixedBytes<32>,
) -> Result<Option<PoiPublisherManifestWatermarkRecord>, PoiArtifactError> {
    match db.inspect_poi_publisher_manifest_watermark(&publisher_pubkey)? {
        StoredRecord::Valid(record) => return Ok(Some(record)),
        StoredRecord::Corrupt { key } => {
            return Err(local_db::DbError::InvalidPpoiSidecarRecord {
                kind: "publisher manifest watermark",
                key,
            }
            .into());
        }
        StoredRecord::Missing => {}
    }

    let mut accepted_sequence = None;
    let scan = db.scan_poi_artifact_caches()?;
    if !scan.invalid_keys.is_empty() {
        return Err(PoiArtifactError::AmbiguousPublisherWatermarkMigration {
            invalid_records: scan.invalid_keys.len(),
        });
    }
    for mut record in scan.records {
        normalize_legacy_artifact_metadata(&mut record);
        let identity = PoiCacheIdentity::new(
            record.chain_type,
            record.chain_id,
            record.txid_version.clone(),
            record.list_key,
        );
        if validate_persisted_record(&record, &identity, Some(publisher_pubkey)).is_ok()
            && let Some(sequence) = publisher_sequence_for_record(&record, publisher_pubkey)
        {
            let sequence = sequence.max(record.legacy_observed_manifest_sequence);
            accepted_sequence =
                Some(accepted_sequence.map_or(sequence, |accepted: u64| accepted.max(sequence)));
        }
    }
    let accepted_sequence = accepted_sequence.filter(|sequence| *sequence > 0);
    if let Some(sequence) = accepted_sequence {
        let (record, _) =
            db.advance_poi_publisher_manifest_watermark(publisher_pubkey, sequence)?;
        return Ok(Some(record));
    }
    Ok(None)
}

fn publisher_sequence_for_record(
    record: &PoiArtifactCacheRecord,
    expected_publisher_pubkey: FixedBytes<32>,
) -> Option<u64> {
    match &record.validation {
        PoiCorpusValidationRecord::PublisherAttested {
            publisher_pubkey,
            manifest_sequence,
            ..
        }
        | PoiCorpusValidationRecord::PublisherAndListSigned {
            publisher_pubkey,
            manifest_sequence,
            ..
        }
        | PoiCorpusValidationRecord::PublisherAttestedV4 {
            publisher_pubkey,
            manifest_sequence,
            ..
        }
        | PoiCorpusValidationRecord::PublisherV4AndListSigned {
            publisher_pubkey,
            manifest_sequence,
            ..
        } if *publisher_pubkey == expected_publisher_pubkey => Some(*manifest_sequence),
        _ => None,
    }
}

fn validate_manifest_order(
    publication: &PublicationId,
    previous: Option<&PoiPublisherManifestWatermarkRecord>,
) -> Result<bool, PoiArtifactError> {
    let Some(previous) = previous else {
        return Ok(false);
    };
    if publication.sequence < previous.accepted_sequence {
        return Err(PoiArtifactError::ManifestSequenceRollback {
            previous: previous.accepted_sequence,
            received: publication.sequence,
        });
    }
    if publication.sequence != previous.accepted_sequence {
        return Ok(false);
    }
    match previous.accepted_manifest_hash {
        Some(hash) if hash == publication.manifest_body_hash => Ok(true),
        Some(_) => Err(PoiArtifactError::ManifestSequenceEquivocation {
            sequence: publication.sequence,
        }),
        None => Ok(false),
    }
}

fn validate_manifest_freshness(
    manifest: &Manifest,
    max_age: Option<Duration>,
    now: SystemTime,
) -> Result<(), PoiArtifactError> {
    let issued_at = UNIX_EPOCH + Duration::from_millis(manifest.issued_at_ms);
    let age = now
        .duration_since(issued_at)
        .map_err(|_| PoiArtifactError::ManifestIssuedInFuture)?;
    if let Some(max_age) = max_age
        && age > max_age
    {
        return Err(PoiArtifactError::ManifestStale { age, max: max_age });
    }
    Ok(())
}
