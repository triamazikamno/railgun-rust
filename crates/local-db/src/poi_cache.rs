use alloy::hex;
use alloy::primitives::FixedBytes;
use redb::{ReadableDatabase, ReadableTable, ReadableTableMetadata, WriteTransaction};
use serde::{Deserialize, Serialize};

use super::{
    DbError, DbStore, POI_ARTIFACT_CACHE_TABLE, POI_CORPUS_JOURNAL_TABLE, POI_SIDECAR_STATE_TABLE,
    PoiCorpusJournalCommitOutcome, decode, encode, now_epoch_secs,
};

pub(crate) const POI_ARTIFACT_CACHE_GENERATION_KEY: &str = "poi_artifact_cache_generation";
pub(crate) const POI_SIDECAR_KEY_PREFIX: &str = "railgun:ppoi-sidecar:v1:";
const POI_PUBLISHER_MANIFEST_WATERMARK_KEY_PREFIX: &str =
    "railgun:ppoi-sidecar:v1:publisher-manifest-watermark:";
const POI_CORPUS_RPC_HEALTH_KEY_PREFIX: &str = "railgun:ppoi-sidecar:v1:corpus-rpc-health:";

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PoiArtifactDescriptorRecord {
    pub cid: String,
    pub sha256: String,
    pub byte_size: u64,
}

#[derive(Debug, Clone, Copy, Default, Serialize, Deserialize, PartialEq, Eq)]
pub enum PoiCacheRecordSource {
    #[default]
    IndexedArtifacts,
    PublicRpc,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub enum PoiCorpusValidationRecord {
    #[default]
    Legacy,
    PublisherAttested {
        publisher_pubkey: FixedBytes<32>,
        manifest_sequence: u64,
        manifest_root: FixedBytes<32>,
        #[serde(default)]
        artifact_tip_index: u64,
    },
    ListSignedRanges {
        list_key: FixedBytes<32>,
        #[serde(default)]
        from_index: u64,
    },
    PublisherAndListSigned {
        publisher_pubkey: FixedBytes<32>,
        manifest_sequence: u64,
        manifest_root: FixedBytes<32>,
        artifact_tip_index: u64,
        list_key: FixedBytes<32>,
        list_signed_from_index: u64,
    },
    PublisherAttestedV4 {
        publisher_pubkey: FixedBytes<32>,
        manifest_sequence: u64,
        #[serde(default)]
        manifest_body_hash: Option<FixedBytes<32>>,
        manifest_root: FixedBytes<32>,
        artifact_tip_index: u64,
        format_version: u16,
        checkpoint_catalog: PoiV4CatalogIdentityRecord,
    },
    PublisherV4AndListSigned {
        publisher_pubkey: FixedBytes<32>,
        manifest_sequence: u64,
        #[serde(default)]
        manifest_body_hash: Option<FixedBytes<32>>,
        manifest_root: FixedBytes<32>,
        artifact_tip_index: u64,
        format_version: u16,
        checkpoint_catalog: PoiV4CatalogIdentityRecord,
        list_key: FixedBytes<32>,
        list_signed_from_index: u64,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PoiV4CatalogIdentityRecord {
    pub cid: String,
    pub sha256: FixedBytes<32>,
    pub byte_size: u64,
    pub descriptor_hash: FixedBytes<32>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PoiArtifactCacheRecord {
    pub chain_type: u8,
    pub chain_id: u64,
    pub txid_version: String,
    pub list_key: FixedBytes<32>,
    #[serde(default)]
    pub cache_generation: u64,
    #[serde(default)]
    pub source: PoiCacheRecordSource,
    #[serde(default)]
    pub validation: PoiCorpusValidationRecord,
    // Compatibility metadata only. The publisher watermark sidecar owns rollback protection.
    #[serde(default, rename = "last_accepted_manifest_sequence")]
    pub legacy_observed_manifest_sequence: u64,
    pub base_descriptor: PoiArtifactDescriptorRecord,
    pub applied_delta_descriptors: Vec<PoiArtifactDescriptorRecord>,
    pub blocked_shields_descriptor: PoiArtifactDescriptorRecord,
    #[serde(default)]
    pub artifact_tip_index: Option<u64>,
    #[serde(default)]
    pub artifact_tip_root: Option<FixedBytes<32>>,
    pub current_tip_index: u64,
    pub current_tip_root: FixedBytes<32>,
    #[serde(with = "serde_bytes")]
    pub cache_payload: Vec<u8>,
    // Compatibility metadata only. The RPC-health sidecar owns current source health.
    #[serde(default, rename = "last_successful_rpc_sync_at_ms")]
    pub legacy_last_successful_rpc_sync_at_ms: Option<u64>,
    /// Unix timestamp in seconds, overwritten by `DbStore` corpus persistence methods.
    pub updated_at: u64,
}

#[derive(Debug)]
pub struct PoiArtifactCacheRecordScan {
    pub records: Vec<PoiArtifactCacheRecord>,
    pub invalid_keys: Vec<String>,
}

#[derive(Debug)]
pub enum StoredRecord<T> {
    Missing,
    Valid(T),
    Corrupt { key: String },
}

impl PoiArtifactCacheRecord {
    #[must_use]
    pub fn key(&self) -> String {
        Self::key_for(
            self.chain_type,
            self.chain_id,
            &self.txid_version,
            &self.list_key,
        )
    }

    #[must_use]
    pub fn key_for(
        chain_type: u8,
        chain_id: u64,
        txid_version: &str,
        list_key: &FixedBytes<32>,
    ) -> String {
        format!(
            "{chain_type}|{chain_id}|{txid_version}|{}",
            hex::encode(list_key)
        )
    }

    #[must_use]
    pub fn metadata_only(&self) -> Self {
        Self {
            chain_type: self.chain_type,
            chain_id: self.chain_id,
            txid_version: self.txid_version.clone(),
            list_key: self.list_key,
            cache_generation: self.cache_generation,
            source: self.source,
            validation: self.validation.clone(),
            legacy_observed_manifest_sequence: self.legacy_observed_manifest_sequence,
            base_descriptor: self.base_descriptor.clone(),
            applied_delta_descriptors: self.applied_delta_descriptors.clone(),
            blocked_shields_descriptor: self.blocked_shields_descriptor.clone(),
            artifact_tip_index: self.artifact_tip_index,
            artifact_tip_root: self.artifact_tip_root,
            current_tip_index: self.current_tip_index,
            current_tip_root: self.current_tip_root,
            cache_payload: Vec::new(),
            legacy_last_successful_rpc_sync_at_ms: self.legacy_last_successful_rpc_sync_at_ms,
            updated_at: self.updated_at,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PoiPublisherManifestWatermarkRecord {
    pub publisher_pubkey: FixedBytes<32>,
    pub accepted_sequence: u64,
    #[serde(default)]
    pub accepted_manifest_hash: Option<FixedBytes<32>>,
    pub updated_at: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PoiPublisherManifestObservation {
    Accepted {
        record: PoiPublisherManifestWatermarkRecord,
        changed: bool,
    },
    Rollback {
        record: PoiPublisherManifestWatermarkRecord,
    },
    Equivocation {
        record: PoiPublisherManifestWatermarkRecord,
    },
}

impl PoiPublisherManifestWatermarkRecord {
    #[must_use]
    pub fn key(&self) -> String {
        Self::key_for(&self.publisher_pubkey)
    }

    #[must_use]
    pub fn key_for(publisher_pubkey: &FixedBytes<32>) -> String {
        format!(
            "{POI_PUBLISHER_MANIFEST_WATERMARK_KEY_PREFIX}{}",
            hex::encode(publisher_pubkey)
        )
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PoiCorpusRpcHealthRecord {
    pub chain_type: u8,
    pub chain_id: u64,
    pub txid_version: String,
    pub list_key: FixedBytes<32>,
    pub cache_generation: u64,
    pub last_successful_rpc_sync_at_ms: Option<u64>,
    pub updated_at: u64,
}

impl PoiCorpusRpcHealthRecord {
    #[must_use]
    pub fn key(&self) -> String {
        Self::key_for(
            self.chain_type,
            self.chain_id,
            &self.txid_version,
            &self.list_key,
        )
    }

    #[must_use]
    pub fn key_for(
        chain_type: u8,
        chain_id: u64,
        txid_version: &str,
        list_key: &FixedBytes<32>,
    ) -> String {
        format!(
            "{POI_CORPUS_RPC_HEALTH_KEY_PREFIX}{chain_type:02x}:{chain_id:016x}:{}:{}",
            hex::encode(txid_version.as_bytes()),
            hex::encode(list_key)
        )
    }
}

impl DbStore {
    pub fn get_poi_artifact_cache(
        &self,
        chain_type: u8,
        chain_id: u64,
        txid_version: &str,
        list_key: &FixedBytes<32>,
    ) -> Result<Option<PoiArtifactCacheRecord>, DbError> {
        match self.inspect_poi_artifact_cache(chain_type, chain_id, txid_version, list_key)? {
            StoredRecord::Missing => Ok(None),
            StoredRecord::Valid(record) => Ok(Some(record)),
            StoredRecord::Corrupt { key } => Err(DbError::InvalidPpoiCorpusRecord { key }),
        }
    }

    pub fn inspect_poi_artifact_cache(
        &self,
        chain_type: u8,
        chain_id: u64,
        txid_version: &str,
        list_key: &FixedBytes<32>,
    ) -> Result<StoredRecord<PoiArtifactCacheRecord>, DbError> {
        let key = PoiArtifactCacheRecord::key_for(chain_type, chain_id, txid_version, list_key);
        let txn = self.db.begin_read()?;
        let table = txn.open_table(POI_ARTIFACT_CACHE_TABLE)?;
        let Some(value) = table.get(key.as_str())? else {
            return Ok(StoredRecord::Missing);
        };
        match decode::<PoiArtifactCacheRecord>(value.value()) {
            Ok(record) if record.key() == key => Ok(StoredRecord::Valid(record)),
            Ok(_) | Err(DbError::Decode(_)) => Ok(StoredRecord::Corrupt { key }),
            Err(error) => Err(error),
        }
    }

    pub fn put_poi_artifact_cache(&self, record: &PoiArtifactCacheRecord) -> Result<(), DbError> {
        let mut record = record.clone();
        record.updated_at = now_epoch_secs()?;
        let key = record.key();
        let data = encode(&record)?;
        let txn = self.db.begin_write()?;
        {
            let mut table = txn.open_table(POI_ARTIFACT_CACHE_TABLE)?;
            table.insert(key.as_str(), data.as_slice())?;
        }
        txn.commit()?;
        Ok(())
    }

    pub fn scan_poi_artifact_caches(&self) -> Result<PoiArtifactCacheRecordScan, DbError> {
        let txn = self.db.begin_read()?;
        let table = txn.open_table(POI_ARTIFACT_CACHE_TABLE)?;
        let mut records = Vec::new();
        let mut invalid_keys = Vec::new();
        for entry in table.range::<&str>(..)? {
            let (key, value) = entry?;
            let key = key.value().to_string();
            match decode::<PoiArtifactCacheRecord>(value.value()) {
                Ok(record) if record.key() == key => records.push(record),
                Ok(_) | Err(DbError::Decode(_)) => invalid_keys.push(key),
                Err(error) => return Err(error),
            }
        }
        Ok(PoiArtifactCacheRecordScan {
            records,
            invalid_keys,
        })
    }

    pub fn poi_artifact_cache_generation(&self) -> Result<u64, DbError> {
        let txn = self.db.begin_read()?;
        let table = txn.open_table(POI_SIDECAR_STATE_TABLE)?;
        match table.get(POI_ARTIFACT_CACHE_GENERATION_KEY)? {
            Some(value) => decode(value.value()),
            None => Ok(0),
        }
    }

    pub fn clear_poi_artifact_cache(&self) -> Result<u64, DbError> {
        self.clear_poi_artifact_cache_with_generation()
            .map(|(removed, _)| removed)
    }

    pub fn clear_poi_artifact_cache_with_generation(&self) -> Result<(u64, u64), DbError> {
        let txn = self.db.begin_write()?;
        let generation = {
            let mut table = txn.open_table(POI_SIDECAR_STATE_TABLE)?;
            let current = match table.get(POI_ARTIFACT_CACHE_GENERATION_KEY)? {
                Some(value) => decode(value.value())?,
                None => 0_u64,
            };
            let generation = current
                .checked_add(1)
                .ok_or_else(|| std::io::Error::other("POI artifact cache generation overflow"))?;
            let encoded = encode(&generation)?;
            table.insert(POI_ARTIFACT_CACHE_GENERATION_KEY, encoded.as_slice())?;
            generation
        };
        let removed = {
            let mut table = txn.open_table(POI_ARTIFACT_CACHE_TABLE)?;
            let removed = table.len()?;
            table.retain(|_, _| false)?;
            removed
        };
        {
            let mut table = txn.open_table(POI_CORPUS_JOURNAL_TABLE)?;
            table.retain(|_, _| false)?;
        }
        txn.commit()?;
        Ok((removed, generation))
    }

    pub fn get_poi_publisher_manifest_watermark(
        &self,
        publisher_pubkey: &FixedBytes<32>,
    ) -> Result<Option<PoiPublisherManifestWatermarkRecord>, DbError> {
        match self.inspect_poi_publisher_manifest_watermark(publisher_pubkey)? {
            StoredRecord::Missing => Ok(None),
            StoredRecord::Valid(record) => Ok(Some(record)),
            StoredRecord::Corrupt { key } => Err(DbError::InvalidPpoiSidecarRecord {
                kind: "publisher manifest watermark",
                key,
            }),
        }
    }

    pub fn inspect_poi_publisher_manifest_watermark(
        &self,
        publisher_pubkey: &FixedBytes<32>,
    ) -> Result<StoredRecord<PoiPublisherManifestWatermarkRecord>, DbError> {
        let key = PoiPublisherManifestWatermarkRecord::key_for(publisher_pubkey);
        let txn = self.db.begin_read()?;
        let table = txn.open_table(POI_SIDECAR_STATE_TABLE)?;
        let Some(value) = table.get(key.as_str())? else {
            return Ok(StoredRecord::Missing);
        };
        match decode::<PoiPublisherManifestWatermarkRecord>(value.value()) {
            Ok(record) if record.publisher_pubkey == *publisher_pubkey => {
                Ok(StoredRecord::Valid(record))
            }
            Ok(_) | Err(DbError::Decode(_)) => Ok(StoredRecord::Corrupt { key }),
            Err(error) => Err(error),
        }
    }

    pub fn advance_poi_publisher_manifest_watermark(
        &self,
        publisher_pubkey: FixedBytes<32>,
        accepted_sequence: u64,
    ) -> Result<(PoiPublisherManifestWatermarkRecord, bool), DbError> {
        let key = PoiPublisherManifestWatermarkRecord::key_for(&publisher_pubkey);
        let txn = self.db.begin_write()?;
        let record = {
            let mut table = txn.open_table(POI_SIDECAR_STATE_TABLE)?;
            if let Some(value) = table.get(key.as_str())? {
                let record: PoiPublisherManifestWatermarkRecord = decode(value.value())?;
                if record.publisher_pubkey != publisher_pubkey {
                    return Err(DbError::InvalidPpoiSidecarRecord {
                        kind: "publisher manifest watermark",
                        key,
                    });
                }
                if record.accepted_sequence >= accepted_sequence {
                    return Ok((record, false));
                }
            }
            let record = PoiPublisherManifestWatermarkRecord {
                publisher_pubkey,
                accepted_sequence,
                accepted_manifest_hash: None,
                updated_at: now_epoch_secs()?,
            };
            let data = encode(&record)?;
            table.insert(key.as_str(), data.as_slice())?;
            record
        };
        txn.commit()?;
        Ok((record, true))
    }

    pub fn observe_poi_v4_publisher_manifest(
        &self,
        publisher_pubkey: FixedBytes<32>,
        accepted_sequence: u64,
        manifest_hash: FixedBytes<32>,
    ) -> Result<PoiPublisherManifestObservation, DbError> {
        let key = PoiPublisherManifestWatermarkRecord::key_for(&publisher_pubkey);
        let txn = self.db.begin_write()?;
        let observation = {
            let mut table = txn.open_table(POI_SIDECAR_STATE_TABLE)?;
            let existing = match table.get(key.as_str())? {
                Some(value) => {
                    let record: PoiPublisherManifestWatermarkRecord = decode(value.value())?;
                    if record.publisher_pubkey != publisher_pubkey {
                        return Err(DbError::InvalidPpoiSidecarRecord {
                            kind: "publisher manifest watermark",
                            key,
                        });
                    }
                    Some(record)
                }
                None => None,
            };
            if let Some(record) = existing {
                if accepted_sequence < record.accepted_sequence {
                    return Ok(PoiPublisherManifestObservation::Rollback { record });
                }
                if accepted_sequence == record.accepted_sequence
                    && let Some(accepted_hash) = record.accepted_manifest_hash
                {
                    return Ok(if accepted_hash == manifest_hash {
                        PoiPublisherManifestObservation::Accepted {
                            record,
                            changed: false,
                        }
                    } else {
                        PoiPublisherManifestObservation::Equivocation { record }
                    });
                }
            }
            let record = PoiPublisherManifestWatermarkRecord {
                publisher_pubkey,
                accepted_sequence,
                accepted_manifest_hash: Some(manifest_hash),
                updated_at: now_epoch_secs()?,
            };
            let data = encode(&record)?;
            table.insert(key.as_str(), data.as_slice())?;
            PoiPublisherManifestObservation::Accepted {
                record,
                changed: true,
            }
        };
        txn.commit()?;
        Ok(observation)
    }

    pub fn get_poi_corpus_rpc_health(
        &self,
        chain_type: u8,
        chain_id: u64,
        txid_version: &str,
        list_key: &FixedBytes<32>,
    ) -> Result<Option<PoiCorpusRpcHealthRecord>, DbError> {
        match self.inspect_poi_corpus_rpc_health(chain_type, chain_id, txid_version, list_key)? {
            StoredRecord::Missing => Ok(None),
            StoredRecord::Valid(record) => Ok(Some(record)),
            StoredRecord::Corrupt { key } => Err(DbError::InvalidPpoiSidecarRecord {
                kind: "corpus RPC health",
                key,
            }),
        }
    }

    pub fn inspect_poi_corpus_rpc_health(
        &self,
        chain_type: u8,
        chain_id: u64,
        txid_version: &str,
        list_key: &FixedBytes<32>,
    ) -> Result<StoredRecord<PoiCorpusRpcHealthRecord>, DbError> {
        let key = PoiCorpusRpcHealthRecord::key_for(chain_type, chain_id, txid_version, list_key);
        let txn = self.db.begin_read()?;
        let table = txn.open_table(POI_SIDECAR_STATE_TABLE)?;
        let Some(value) = table.get(key.as_str())? else {
            return Ok(StoredRecord::Missing);
        };
        match decode::<PoiCorpusRpcHealthRecord>(value.value()) {
            Ok(record)
                if record.chain_type == chain_type
                    && record.chain_id == chain_id
                    && record.txid_version == txid_version
                    && record.list_key == *list_key =>
            {
                Ok(StoredRecord::Valid(record))
            }
            Ok(_) | Err(DbError::Decode(_)) => Ok(StoredRecord::Corrupt { key }),
            Err(error) => Err(error),
        }
    }

    pub fn put_poi_corpus_rpc_health(
        &self,
        record: &PoiCorpusRpcHealthRecord,
    ) -> Result<(), DbError> {
        let mut record = record.clone();
        record.updated_at = now_epoch_secs()?;
        let key = record.key();
        let data = encode(&record)?;
        let txn = self.db.begin_write()?;
        {
            let mut table = txn.open_table(POI_SIDECAR_STATE_TABLE)?;
            table.insert(key.as_str(), data.as_slice())?;
        }
        txn.commit()?;
        Ok(())
    }

    #[doc(hidden)]
    #[cfg(any(test, feature = "test-utils"))]
    pub fn put_raw_poi_sidecar_state_for_test(
        &self,
        key: &str,
        value: &[u8],
    ) -> Result<(), DbError> {
        let txn = self.db.begin_write()?;
        {
            let mut table = txn.open_table(POI_SIDECAR_STATE_TABLE)?;
            table.insert(key, value)?;
        }
        txn.commit()?;
        Ok(())
    }
}

#[derive(Debug, Clone, Copy)]
pub(crate) enum PoiCommitContextConflict {
    Generation(u64),
    PublisherSequence(Option<u64>),
    PublisherManifest(Option<FixedBytes<32>>),
}

impl PoiCommitContextConflict {
    pub(crate) const fn into_journal_outcome(self) -> PoiCorpusJournalCommitOutcome {
        match self {
            Self::Generation(actual) => {
                PoiCorpusJournalCommitOutcome::GenerationConflict { actual }
            }
            Self::PublisherSequence(actual) => {
                PoiCorpusJournalCommitOutcome::PublisherSequenceConflict { actual }
            }
            Self::PublisherManifest(actual) => {
                PoiCorpusJournalCommitOutcome::PublisherManifestConflict { actual }
            }
        }
    }
}

pub(crate) fn poi_commit_context_conflict(
    txn: &WriteTransaction,
    expected_generation: u64,
    expected_publisher: Option<(FixedBytes<32>, u64)>,
    expected_manifest_hash: Option<FixedBytes<32>>,
) -> Result<Option<PoiCommitContextConflict>, DbError> {
    let generation = {
        let table = txn.open_table(POI_SIDECAR_STATE_TABLE)?;
        match table.get(POI_ARTIFACT_CACHE_GENERATION_KEY)? {
            Some(value) => decode(value.value())?,
            None => 0_u64,
        }
    };
    if generation != expected_generation {
        return Ok(Some(PoiCommitContextConflict::Generation(generation)));
    }
    let Some((publisher_pubkey, expected_sequence)) = expected_publisher else {
        return Ok(None);
    };
    let watermark_key = PoiPublisherManifestWatermarkRecord::key_for(&publisher_pubkey);
    let actual = {
        let table = txn.open_table(POI_SIDECAR_STATE_TABLE)?;
        match table.get(watermark_key.as_str())? {
            Some(value) => {
                let watermark: PoiPublisherManifestWatermarkRecord = decode(value.value())?;
                if watermark.publisher_pubkey != publisher_pubkey {
                    return Err(DbError::InvalidPpoiSidecarRecord {
                        kind: "publisher manifest watermark",
                        key: watermark_key,
                    });
                }
                Some((
                    watermark.accepted_sequence,
                    watermark.accepted_manifest_hash,
                ))
            }
            None => None,
        }
    };
    if actual.map(|(sequence, _)| sequence) != Some(expected_sequence) {
        return Ok(Some(PoiCommitContextConflict::PublisherSequence(
            actual.map(|(sequence, _)| sequence),
        )));
    }
    if let Some(expected_hash) = expected_manifest_hash
        && actual.and_then(|(_, hash)| hash) != Some(expected_hash)
    {
        return Ok(Some(PoiCommitContextConflict::PublisherManifest(
            actual.and_then(|(_, hash)| hash),
        )));
    }
    Ok(None)
}
