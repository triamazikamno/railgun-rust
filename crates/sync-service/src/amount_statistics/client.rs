//! Manifest resolution and snapshot download through the shared gateway pool, with every check
//! a snapshot must pass before it is used.

use std::sync::Arc;
use std::time::SystemTime;

use alloy::hex;
use alloy::primitives::FixedBytes;
use railgun_indexed_artifacts::{
    AMOUNT_STATISTICS_MAX_COMPRESSED_BYTES, AMOUNT_STATISTICS_SNAPSHOT_ENCODING_VERSION,
    AmountStatisticsChainEntry, AmountStatisticsError, AmountStatisticsManifestEnvelope,
    AmountStatisticsSnapshot, AmountStatisticsSnapshotDescriptor,
    decode_amount_statistics_snapshot,
};
use sha2::{Digest, Sha256};
use tracing::debug;
use trustless_artifacts::GatewayPool;

use super::{AmountStatisticsRefreshError, AmountStatisticsSource, StoredAmountStatistics};
use crate::indexed_artifacts::{
    ChainScope, CompressionAlgorithm, format_scope, validate_manifest_freshness,
    validate_manifest_sequence,
};
use crate::trustless_artifacts::TrustlessArtifactFetcher;

#[derive(Debug)]
pub(super) enum FetchedAmountStatistics {
    /// The accepted manifest names the held snapshot, which was not downloaded again.
    Held { sequence: u64 },
    New {
        record: StoredAmountStatistics,
        snapshot: Arc<AmountStatisticsSnapshot>,
    },
}

pub(super) struct AmountStatisticsClient {
    source: AmountStatisticsSource,
    http_client: reqwest::Client,
    gateway_pool: GatewayPool,
}

impl AmountStatisticsClient {
    pub(super) fn new(source: AmountStatisticsSource, http_client: reqwest::Client) -> Self {
        let gateway_pool = source.artifacts.gateway_pool.clone().unwrap_or_default();
        Self {
            source,
            http_client,
            gateway_pool,
        }
    }

    pub(super) const fn source(&self) -> &AmountStatisticsSource {
        &self.source
    }

    fn fetcher(&self) -> TrustlessArtifactFetcher<'_> {
        TrustlessArtifactFetcher::new_with_pool(
            &self.http_client,
            &self.source.artifacts.gateway_urls,
            self.gateway_pool.clone(),
        )
    }

    /// Resolves the manifest and, unless its entry names the `held` snapshot, downloads and
    /// verifies the snapshot it names.
    pub(super) async fn fetch(
        &self,
        held: Option<&StoredAmountStatistics>,
        now: SystemTime,
    ) -> Result<FetchedAmountStatistics, AmountStatisticsRefreshError> {
        let (sequence, entry) = self
            .fetch_manifest_entry(held.map(|held| held.sequence), now)
            .await?;
        let descriptor = &entry.snapshot;
        if held.is_some_and(|held| held.cid == descriptor.cid && held.sha256 == descriptor.sha256) {
            return Ok(FetchedAmountStatistics::Held { sequence });
        }
        let bytes = self
            .fetcher()
            .fetch_artifact_cid(&descriptor.cid, descriptor.byte_size)
            .await?;
        verify_descriptor_bytes(descriptor, &bytes)?;
        let snapshot = decode_snapshot(&bytes, &self.source.scope)?;
        if snapshot.covered_block != entry.covered_block {
            return Err(AmountStatisticsRefreshError::CoveredBlockMismatch {
                expected: entry.covered_block.number,
                actual: snapshot.covered_block.number,
            });
        }
        Ok(FetchedAmountStatistics::New {
            record: StoredAmountStatistics {
                source: self.source.identity(),
                sequence,
                cid: descriptor.cid.clone(),
                sha256: descriptor.sha256,
                snapshot: bytes.into(),
            },
            snapshot: Arc::new(snapshot),
        })
    }

    /// The manifest sequence and this chain's entry from the first IPNS candidate, highest
    /// IPNS sequence first, whose manifest passes every check.
    async fn fetch_manifest_entry(
        &self,
        last_accepted_sequence: Option<u64>,
        now: SystemTime,
    ) -> Result<(u64, AmountStatisticsChainEntry), AmountStatisticsRefreshError> {
        let fetcher = self.fetcher();
        let candidates = fetcher
            .resolve_ipns_manifest_candidates(&self.source.ipns_name, last_accepted_sequence)
            .await?;
        let candidate_count = candidates.len();
        let mut last_error = None;
        for (candidate_index, candidate) in candidates.into_iter().enumerate() {
            let accepted = match fetcher
                .fetch_manifest_cid_with_metadata_from_gateway(
                    &candidate.cid.to_string(),
                    Some(candidate.gateway_index()),
                )
                .await
            {
                Ok(fetched) => self.accept_manifest(fetched.bytes(), last_accepted_sequence, now),
                Err(error) => Err(error.into()),
            };
            match accepted {
                Ok(accepted) => return Ok(accepted),
                Err(error) => {
                    debug!(
                        ?error,
                        ipns_name = %self.source.ipns_name,
                        cid = %candidate.cid,
                        ipns_sequence = candidate.sequence,
                        candidate_index,
                        candidate_count,
                        "amount statistics IPNS candidate failed manifest acceptance"
                    );
                    last_error = Some(error);
                }
            }
        }
        Err(last_error.unwrap_or(AmountStatisticsRefreshError::NoValidManifest))
    }

    /// Verifies the signature over the envelope's body string before parsing it, then the
    /// rollback floor, freshness, this chain's entry and its snapshot descriptor.
    fn accept_manifest(
        &self,
        bytes: &[u8],
        last_accepted_sequence: Option<u64>,
        now: SystemTime,
    ) -> Result<(u64, AmountStatisticsChainEntry), AmountStatisticsRefreshError> {
        let manifest = AmountStatisticsManifestEnvelope::from_json_slice(bytes)?
            .verify_trusted(&self.source.artifacts.trusted_publisher_pubkey.0)?;
        validate_manifest_sequence(manifest.sequence, last_accepted_sequence)?;
        validate_manifest_freshness(
            manifest.sequence,
            manifest.issued_at_ms,
            last_accepted_sequence,
            self.source.artifacts.max_manifest_age,
            now,
        )?;
        let entry = manifest
            .chains
            .into_iter()
            .find(|entry| entry.scope == self.source.scope)
            .ok_or_else(|| AmountStatisticsRefreshError::MissingChainScope {
                scope: format_scope(&self.source.scope),
            })?;
        validate_snapshot_descriptor(&entry.snapshot)?;
        Ok((manifest.sequence, entry))
    }
}

/// Rejects a descriptor this version cannot use before anything is downloaded.
fn validate_snapshot_descriptor(
    descriptor: &AmountStatisticsSnapshotDescriptor,
) -> Result<(), AmountStatisticsRefreshError> {
    if descriptor.encoding_version != AMOUNT_STATISTICS_SNAPSHOT_ENCODING_VERSION {
        return Err(
            AmountStatisticsError::UnsupportedEncodingVersion(descriptor.encoding_version).into(),
        );
    }
    if descriptor.compression != CompressionAlgorithm::Zstd {
        return Err(AmountStatisticsRefreshError::UnsupportedCompression(
            descriptor.compression,
        ));
    }
    if descriptor.byte_size > AMOUNT_STATISTICS_MAX_COMPRESSED_BYTES {
        return Err(AmountStatisticsError::CompressedTooLarge {
            actual: descriptor.byte_size,
            maximum: AMOUNT_STATISTICS_MAX_COMPRESSED_BYTES,
        }
        .into());
    }
    Ok(())
}

fn verify_descriptor_bytes(
    descriptor: &AmountStatisticsSnapshotDescriptor,
    bytes: &[u8],
) -> Result<(), AmountStatisticsRefreshError> {
    let actual = u64::try_from(bytes.len()).unwrap_or(u64::MAX);
    if actual != descriptor.byte_size {
        return Err(AmountStatisticsRefreshError::SnapshotByteSizeMismatch {
            expected: descriptor.byte_size,
            actual,
        });
    }
    let actual_hash = FixedBytes::<32>::from_slice(&Sha256::digest(bytes));
    if actual_hash != descriptor.sha256 {
        return Err(AmountStatisticsRefreshError::SnapshotHashMismatch {
            expected: hex::encode_prefixed(descriptor.sha256),
            actual: hex::encode_prefixed(actual_hash),
        });
    }
    Ok(())
}

/// Decodes snapshot bytes within the size limits and checks they describe `scope`.
pub(super) fn decode_snapshot(
    bytes: &[u8],
    scope: &ChainScope,
) -> Result<AmountStatisticsSnapshot, AmountStatisticsRefreshError> {
    let snapshot = decode_amount_statistics_snapshot(bytes)?;
    if snapshot.scope != *scope {
        return Err(AmountStatisticsRefreshError::SnapshotScopeMismatch {
            expected: format_scope(scope),
            actual: format_scope(&snapshot.scope),
        });
    }
    Ok(snapshot)
}
