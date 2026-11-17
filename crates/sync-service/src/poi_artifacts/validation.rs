//! Payload and provenance validation of persisted POI corpora.

use std::collections::BTreeMap;

use alloy::primitives::FixedBytes;
use broadcaster_core::tree::normalize_tree_position;
use local_db::{
    PoiArtifactCacheRecord, PoiCacheRecordSource, PoiCorpusValidationRecord,
    PoiV4CatalogIdentityRecord,
};
use poi::cache::{PoiCache, PoiCacheIdentity};

use super::PoiArtifactError;

pub(super) const fn normalize_legacy_artifact_metadata(record: &mut PoiArtifactCacheRecord) {
    if record.artifact_tip_index.is_none()
        && matches!(record.source, PoiCacheRecordSource::IndexedArtifacts)
    {
        record.artifact_tip_index = Some(record.current_tip_index);
        record.artifact_tip_root = Some(record.current_tip_root);
    }
}

pub(super) fn validate_materialized_corpus_payload(
    record: &PoiArtifactCacheRecord,
    cache: &PoiCache,
) -> Result<(), PoiArtifactError> {
    let roots = cache.current_roots_readonly();
    if cache.validated_roots() != Some(&roots) {
        return Err(PoiArtifactError::PersistedRootsNotValidated);
    }
    validate_corpus_payload_with_roots(record, cache, &roots)
}

fn validate_anchored_corpus_payload(
    record: &PoiArtifactCacheRecord,
    cache: &PoiCache,
) -> Result<(), PoiArtifactError> {
    let roots = cache
        .validated_roots()
        .ok_or(PoiArtifactError::PersistedRootsNotValidated)?;
    validate_corpus_payload_metadata_with_roots(record, cache, roots)?;
    Ok(())
}

fn validate_corpus_payload_with_roots(
    record: &PoiArtifactCacheRecord,
    cache: &PoiCache,
    roots: &BTreeMap<u32, FixedBytes<32>>,
) -> Result<(), PoiArtifactError> {
    if let Some((index, root)) = validate_corpus_payload_metadata_with_roots(record, cache, roots)?
        && cache.root_at_global_index(index) != Some(root)
    {
        return Err(PoiArtifactError::PersistedArtifactRootMismatch { tip_index: index });
    }
    Ok(())
}

fn validate_corpus_payload_metadata_with_roots(
    record: &PoiArtifactCacheRecord,
    cache: &PoiCache,
    roots: &BTreeMap<u32, FixedBytes<32>>,
) -> Result<Option<(u64, FixedBytes<32>)>, PoiArtifactError> {
    let next_event_index = cache.progress().next_event_index;
    let next_leaf_index = cache.progress().next_leaf_index;
    if next_event_index == 0 {
        return Err(PoiArtifactError::EmptyPersistedCorpus);
    }
    if next_event_index != next_leaf_index {
        return Err(PoiArtifactError::PersistedCursorMismatch {
            next_event_index,
            next_leaf_index,
        });
    }
    let payload_tip_index = next_event_index - 1;
    if record.current_tip_index != payload_tip_index {
        return Err(PoiArtifactError::PersistedTipMismatch {
            metadata: record.current_tip_index,
            payload: payload_tip_index,
        });
    }
    let (tree_number, _) = normalize_tree_position(0, payload_tip_index);
    let payload_tip_root = roots
        .get(&tree_number)
        .ok_or(PoiArtifactError::MissingPersistedRoot { tree_number })?;
    if record.current_tip_root != *payload_tip_root {
        return Err(PoiArtifactError::PersistedRootMismatch {
            tip_index: payload_tip_index,
        });
    }
    match (record.artifact_tip_index, record.artifact_tip_root) {
        (Some(index), Some(root)) if index <= payload_tip_index => Ok(Some((index, root))),
        (None, None) => Ok(None),
        (Some(_), Some(_)) => Err(PoiArtifactError::PersistedArtifactMetadata {
            reason: "artifact tip exceeds serving tip",
        }),
        _ => Err(PoiArtifactError::PersistedArtifactMetadata {
            reason: "artifact tip index and root must be present together",
        }),
    }
}

pub(super) fn validate_materialized_corpus(
    record: &PoiArtifactCacheRecord,
    cache: &PoiCache,
    expected_publisher_pubkey: Option<FixedBytes<32>>,
) -> Result<(), PoiArtifactError> {
    validate_materialized_corpus_payload(record, cache)?;
    validate_corpus_provenance(record, cache, expected_publisher_pubkey)
}

pub(super) fn validate_anchored_corpus(
    record: &PoiArtifactCacheRecord,
    cache: &PoiCache,
    expected_publisher_pubkey: Option<FixedBytes<32>>,
) -> Result<(), PoiArtifactError> {
    validate_anchored_corpus_payload(record, cache)?;
    validate_corpus_provenance(record, cache, expected_publisher_pubkey)
}

pub(super) fn validate_corpus_provenance(
    record: &PoiArtifactCacheRecord,
    cache: &PoiCache,
    expected_publisher_pubkey: Option<FixedBytes<32>>,
) -> Result<(), PoiArtifactError> {
    let provenance = CorpusProvenance {
        record,
        expected_publisher_pubkey,
        next_event_index: cache.progress().next_event_index,
    };
    let (valid, reason) = match &record.validation {
        PoiCorpusValidationRecord::Legacy => (
            provenance.legacy_allowed(),
            "legacy artifact evidence does not identify the configured publisher",
        ),
        PoiCorpusValidationRecord::PublisherAttested {
            publisher_pubkey,
            manifest_root,
            artifact_tip_index,
            ..
        } => (
            provenance.publisher_attested_allowed(
                publisher_pubkey,
                *manifest_root,
                *artifact_tip_index,
            ),
            "publisher-attested evidence does not match the serving artifact tip",
        ),
        PoiCorpusValidationRecord::ListSignedRanges {
            list_key,
            from_index,
        } => (
            provenance.list_signed_allowed(list_key, *from_index),
            "list-signed evidence does not match the public range corpus",
        ),
        PoiCorpusValidationRecord::PublisherAndListSigned {
            publisher_pubkey,
            manifest_root,
            artifact_tip_index,
            list_key,
            list_signed_from_index,
            ..
        } => (
            provenance.publisher_prefix_allowed(
                publisher_pubkey,
                *manifest_root,
                *artifact_tip_index,
            ) && provenance.list_suffix_follows(
                list_key,
                *list_signed_from_index,
                *artifact_tip_index,
            ),
            "mixed publisher/list evidence does not match corpus boundaries",
        ),
        PoiCorpusValidationRecord::PublisherAttestedV4 {
            publisher_pubkey,
            manifest_body_hash,
            manifest_root,
            artifact_tip_index,
            format_version,
            checkpoint_catalog,
            ..
        } => (
            provenance.publisher_attested_allowed(
                publisher_pubkey,
                *manifest_root,
                *artifact_tip_index,
            ) && v4_manifest_complete(
                *format_version,
                manifest_body_hash.as_ref(),
                checkpoint_catalog,
            ),
            "v4 publisher evidence does not match the serving corpus",
        ),
        PoiCorpusValidationRecord::PublisherV4AndListSigned {
            publisher_pubkey,
            manifest_body_hash,
            manifest_root,
            artifact_tip_index,
            format_version,
            checkpoint_catalog,
            list_key,
            list_signed_from_index,
            ..
        } => (
            provenance.publisher_prefix_allowed(
                publisher_pubkey,
                *manifest_root,
                *artifact_tip_index,
            ) && v4_manifest_complete(
                *format_version,
                manifest_body_hash.as_ref(),
                checkpoint_catalog,
            ) && provenance.list_suffix_follows(
                list_key,
                *list_signed_from_index,
                *artifact_tip_index,
            ),
            "mixed v4 publisher/list evidence does not match corpus boundaries",
        ),
    };
    if valid {
        Ok(())
    } else {
        Err(PoiArtifactError::PersistedValidationProvenance { reason })
    }
}

/// What a persisted corpus record's validation evidence is checked against.
struct CorpusProvenance<'a> {
    record: &'a PoiArtifactCacheRecord,
    expected_publisher_pubkey: Option<FixedBytes<32>>,
    next_event_index: u64,
}

impl CorpusProvenance<'_> {
    const fn payload_tip_index(&self) -> u64 {
        self.next_event_index.saturating_sub(1)
    }

    fn sourced_from(&self, source: PoiCacheRecordSource) -> bool {
        self.record.source == source
    }

    /// The configured publisher, if any, signed the evidence, and the record
    /// serves its artifact tip.
    fn publisher_serves_tip(
        &self,
        publisher_pubkey: &FixedBytes<32>,
        manifest_root: FixedBytes<32>,
        artifact_tip_index: u64,
    ) -> bool {
        self.expected_publisher_pubkey
            .is_none_or(|expected| expected == *publisher_pubkey)
            && self.record.artifact_tip_index == Some(artifact_tip_index)
            && self.record.artifact_tip_root == Some(manifest_root)
    }

    /// The list-signed range covers this record's list, starts right after the
    /// artifact tip and does not start past the corpus.
    fn list_suffix_follows(
        &self,
        list_key: &FixedBytes<32>,
        list_signed_from_index: u64,
        artifact_tip_index: u64,
    ) -> bool {
        *list_key == self.record.list_key
            && list_signed_from_index == artifact_tip_index.saturating_add(1)
            && list_signed_from_index <= self.next_event_index
    }

    /// Legacy evidence names no publisher, so it cannot back an artifact corpus
    /// once a publisher is configured.
    fn legacy_allowed(&self) -> bool {
        !(self.expected_publisher_pubkey.is_some()
            && self.sourced_from(PoiCacheRecordSource::IndexedArtifacts))
    }

    fn list_signed_allowed(&self, list_key: &FixedBytes<32>, from_index: u64) -> bool {
        self.sourced_from(PoiCacheRecordSource::PublicRpc)
            && *list_key == self.record.list_key
            && self.record.artifact_tip_index.is_none()
            && from_index <= self.next_event_index
    }

    /// Publisher evidence for an artifact corpus that ends at its artifact tip.
    fn publisher_attested_allowed(
        &self,
        publisher_pubkey: &FixedBytes<32>,
        manifest_root: FixedBytes<32>,
        artifact_tip_index: u64,
    ) -> bool {
        self.publisher_serves_tip(publisher_pubkey, manifest_root, artifact_tip_index)
            && self.sourced_from(PoiCacheRecordSource::IndexedArtifacts)
            && artifact_tip_index == self.payload_tip_index()
    }

    /// Publisher evidence for the artifact prefix of a public range corpus.
    fn publisher_prefix_allowed(
        &self,
        publisher_pubkey: &FixedBytes<32>,
        manifest_root: FixedBytes<32>,
        artifact_tip_index: u64,
    ) -> bool {
        self.publisher_serves_tip(publisher_pubkey, manifest_root, artifact_tip_index)
            && self.sourced_from(PoiCacheRecordSource::PublicRpc)
            && artifact_tip_index < self.next_event_index
    }
}

/// V4 publisher evidence names the v4 format, its manifest body and a usable
/// checkpoint catalog.
fn v4_manifest_complete(
    format_version: u16,
    manifest_body_hash: Option<&FixedBytes<32>>,
    checkpoint_catalog: &PoiV4CatalogIdentityRecord,
) -> bool {
    format_version == poi::artifacts::v4::FORMAT_VERSION
        && manifest_body_hash.is_some()
        && !checkpoint_catalog.cid.is_empty()
        && checkpoint_catalog.byte_size != 0
        && checkpoint_catalog.descriptor_hash != FixedBytes::ZERO
}

pub(super) fn validate_persisted_record(
    record: &PoiArtifactCacheRecord,
    expected_identity: &PoiCacheIdentity,
    expected_publisher_pubkey: Option<FixedBytes<32>>,
) -> Result<PoiCache, PoiArtifactError> {
    if record.chain_type != expected_identity.chain_type
        || record.chain_id != expected_identity.chain_id
        || record.txid_version != expected_identity.txid_version
        || record.list_key != expected_identity.list_key
    {
        return Err(PoiArtifactError::PersistedIdentityMismatch);
    }
    let cache = PoiCache::from_bytes(&record.cache_payload, expected_identity)?;
    validate_materialized_corpus(record, &cache, expected_publisher_pubkey)?;
    Ok(cache)
}
