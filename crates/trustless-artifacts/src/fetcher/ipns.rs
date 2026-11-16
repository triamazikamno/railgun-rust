//! IPNS name resolution to manifest CID candidates, and IPNS record
//! verification.

use std::cmp::Reverse;
use std::collections::{HashMap, HashSet};
use std::str;
use std::time::{Instant, SystemTime};

use chrono::Utc;
use cid::{Cid, Version};
use futures::{StreamExt, stream::FuturesUnordered};
use libp2p_identity::{PeerId, PublicKey};
use quick_protobuf::BytesReader;
use tracing::debug;
use url::Url;

use super::{TrustlessArtifactFetcher, parse_cid};
use crate::error::{TrustlessArtifactError, TrustlessHttpSource};
use crate::http::{fetch_response_bytes_with_timeouts, ipns_record_gateway_url};
use crate::pool::{GatewayAttempt, GatewayCapability, GatewaySelectionPolicy};
use crate::{
    IPNS_EARLY_CLOSE_GRACE, IPNS_RECORD_ACCEPT, IPNS_RECORD_MAX_BYTES, LIBP2P_KEY_CODEC,
    MAX_CONCURRENT_IPNS_GATEWAY_REQUESTS,
};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IpnsManifestCandidate {
    pub sequence: u64,
    pub cid: Cid,
    pub(crate) eol: chrono::DateTime<Utc>,
    gateway_index: usize,
}

impl IpnsManifestCandidate {
    /// The configured index of the first gateway whose record with this
    /// sequence and CID arrived.
    #[must_use]
    pub const fn gateway_index(&self) -> usize {
        self.gateway_index
    }
}

/// An IPNS request outcome with its unsettled gateway attempt. The attempt is
/// settled when the phase results are collected, after the acceptance sample.
type IpnsRecordRequestResult = (
    GatewayAttempt,
    u128,
    Result<IpnsManifestCandidate, TrustlessArtifactError>,
);

impl TrustlessArtifactFetcher<'_> {
    /// Resolves an IPNS name to verified manifest CID candidates, highest
    /// sequence first.
    ///
    /// A resolution phase closes `IPNS_EARLY_CLOSE_GRACE` after the first
    /// qualifying record arrives, or when every attempt has settled. A record
    /// qualifies when it is verified, unexpired on arrival, and at or above
    /// `sequence_floor` when one is supplied, so a lagging gateway cannot close
    /// resolution early.
    pub async fn resolve_ipns_manifest_candidates(
        &self,
        name: &str,
        sequence_floor: Option<u64>,
    ) -> Result<Vec<IpnsManifestCandidate>, TrustlessArtifactError> {
        self.resolve_ipns_manifest_candidates_with_clock(name, sequence_floor, &SystemTime::now)
            .await
    }

    /// Like [`Self::resolve_ipns_manifest_candidates`], reading time from
    /// `acceptance_time`. Arrival reads only decide when a phase stops
    /// waiting; one acceptance sample after the phase closes decides which
    /// candidates are returned.
    pub async fn resolve_ipns_manifest_candidates_with_clock<F>(
        &self,
        name: &str,
        sequence_floor: Option<u64>,
        acceptance_time: &F,
    ) -> Result<Vec<IpnsManifestCandidate>, TrustlessArtifactError>
    where
        F: Fn() -> SystemTime + Sync + ?Sized,
    {
        if self.gateways.is_empty() {
            return Err(TrustlessArtifactError::NoGateways);
        }

        let peer_id = expected_ipns_peer_id(name)?;
        let mut errors = Vec::new();
        let gateway_count = self.gateways.len();
        let mut reserved_identities = HashSet::with_capacity(gateway_count);
        let phase_one = self
            .fetch_ipns_phase(
                name,
                peer_id,
                GatewaySelectionPolicy::HealthyOnly,
                &mut reserved_identities,
                sequence_floor,
                acceptance_time,
            )
            .await;
        let mut candidates = Vec::new();
        self.collect_ipns_phase_results(
            name,
            phase_one,
            chrono::DateTime::<Utc>::from(acceptance_time()),
            &mut candidates,
            &mut errors,
        );
        if !candidates.is_empty() {
            return finalize_ipns_candidates(candidates, errors);
        }

        let phase_two = self
            .fetch_ipns_phase(
                name,
                peer_id,
                GatewaySelectionPolicy::AllowCoolingFallback,
                &mut reserved_identities,
                sequence_floor,
                acceptance_time,
            )
            .await;
        self.collect_ipns_phase_results(
            name,
            phase_two,
            chrono::DateTime::<Utc>::from(acceptance_time()),
            &mut candidates,
            &mut errors,
        );
        finalize_ipns_candidates(candidates, errors)
    }

    /// Queries gateways concurrently until every attempt settles, or until
    /// `IPNS_EARLY_CLOSE_GRACE` after the first qualifying record. Attempts
    /// still pending at close are dropped, which releases their reservations
    /// without a recorded failure.
    async fn fetch_ipns_phase<F>(
        &self,
        name: &str,
        peer_id: PeerId,
        policy: GatewaySelectionPolicy,
        reserved_identities: &mut HashSet<u64>,
        sequence_floor: Option<u64>,
        acceptance_time: &F,
    ) -> Vec<IpnsRecordRequestResult>
    where
        F: Fn() -> SystemTime + Sync + ?Sized,
    {
        let gateway_count = self.gateways.len();
        let mut requests = FuturesUnordered::new();
        let mut results = Vec::with_capacity(gateway_count);
        let mut close_at: Option<tokio::time::Instant> = None;
        loop {
            // Free slots keep filling until the grace deadline, which cancels
            // whatever is still pending.
            while requests.len() < MAX_CONCURRENT_IPNS_GATEWAY_REQUESTS {
                let Some(gateway_attempt) = self.pool.select_excluding_with_policy(
                    &self.gateway_ids,
                    GatewayCapability::IpnsRecord,
                    None,
                    reserved_identities,
                    policy,
                ) else {
                    break;
                };
                reserved_identities.insert(gateway_attempt.identity);
                let gateway_index = gateway_attempt.index;
                let gateway = self.gateways.expose(gateway_index);
                let url = ipns_record_gateway_url(gateway, name);
                let source = TrustlessHttpSource::Gateway {
                    index: gateway_index,
                    count: gateway_count,
                };
                requests.push(async move {
                    let attempt_started = Instant::now();
                    let result = self
                        .fetch_ipns_record_candidate(&url, source, peer_id)
                        .await;
                    (
                        gateway_attempt,
                        attempt_started.elapsed().as_millis(),
                        result,
                    )
                });
            }
            let result = if let Some(close_at) = close_at {
                tokio::select! {
                    biased;
                    () = tokio::time::sleep_until(close_at) => {
                        debug!(
                            gateway_count,
                            ipns_name = name,
                            received = results.len(),
                            cancelled = requests.len(),
                            "POI artifact IPNS phase closed after grace window"
                        );
                        break;
                    }
                    result = requests.next() => result,
                }
            } else {
                requests.next().await
            };
            let Some(result) = result else {
                break;
            };
            // The arrival-time clock read only decides when to stop waiting.
            let qualifies = result.2.as_ref().is_ok_and(|candidate| {
                candidate.eol > chrono::DateTime::<Utc>::from(acceptance_time())
                    && sequence_floor.is_none_or(|floor| candidate.sequence >= floor)
            });
            if qualifies && close_at.is_none() {
                close_at = Some(tokio::time::Instant::now() + IPNS_EARLY_CLOSE_GRACE);
            }
            results.push(result);
        }
        results
    }

    /// Records each phase result against the single acceptance sample and
    /// settles its gateway attempt: a current verified record is a success, an
    /// expired one is a capability-scoped failure.
    fn collect_ipns_phase_results(
        &self,
        name: &str,
        results: Vec<IpnsRecordRequestResult>,
        accepted_at: chrono::DateTime<Utc>,
        candidates: &mut Vec<(usize, IpnsManifestCandidate)>,
        errors: &mut Vec<(usize, TrustlessArtifactError)>,
    ) {
        let gateway_count = self.gateways.len();
        for (gateway_attempt, elapsed_ms, result) in results {
            let gateway_index = gateway_attempt.index;
            match result {
                Ok(mut candidate) => {
                    candidate.gateway_index = gateway_index;
                    debug!(
                        gateway_index,
                        gateway_count,
                        ipns_name = name,
                        cid = %candidate.cid,
                        ipns_sequence = candidate.sequence,
                        elapsed_ms,
                        "POI artifact IPNS gateway returned verified record"
                    );
                    if candidate.eol <= accepted_at {
                        debug!(
                            gateway_index,
                            gateway_count,
                            ipns_name = name,
                            ipns_sequence = candidate.sequence,
                            eol = %candidate.eol,
                            "POI artifact IPNS gateway record expired before aggregate acceptance"
                        );
                        let error =
                            TrustlessArtifactError::ExpiredIpnsRecord { eol: candidate.eol };
                        gateway_attempt.failure(&error);
                        errors.push((gateway_index, error));
                    } else {
                        gateway_attempt.success();
                        candidates.push((gateway_index, candidate));
                    }
                }
                Err(err) => {
                    debug!(
                        ?err,
                        gateway_index,
                        gateway_count,
                        ipns_name = name,
                        elapsed_ms,
                        "POI artifact IPNS gateway failed"
                    );
                    gateway_attempt.failure(&err);
                    errors.push((gateway_index, err));
                }
            }
        }
    }

    async fn fetch_ipns_record_candidate(
        &self,
        url: &Url,
        source: TrustlessHttpSource,
        peer_id: PeerId,
    ) -> Result<IpnsManifestCandidate, TrustlessArtifactError> {
        let bytes = fetch_response_bytes_with_timeouts(
            self.client,
            url,
            source,
            Some(IPNS_RECORD_ACCEPT),
            IPNS_RECORD_MAX_BYTES,
            self.timeouts,
        )
        .await?;
        verify_ipns_record_candidate(&bytes, peer_id)
    }
}

fn finalize_ipns_candidates(
    mut candidates: Vec<(usize, IpnsManifestCandidate)>,
    errors: Vec<(usize, TrustlessArtifactError)>,
) -> Result<Vec<IpnsManifestCandidate>, TrustlessArtifactError> {
    if candidates.is_empty() {
        return Err(errors
            .into_iter()
            .max_by_key(|(gateway_index, _)| *gateway_index)
            .map_or(TrustlessArtifactError::NoValidIpnsRecords, |(_, err)| err));
    }
    // Candidates are in arrival order, so the first occurrence of each pair
    // names the gateway whose record arrived first.
    let mut first_gateway_indices = HashMap::with_capacity(candidates.len());
    for (gateway_index, candidate) in &candidates {
        first_gateway_indices
            .entry((candidate.sequence, candidate.cid))
            .or_insert(*gateway_index);
    }
    candidates
        .sort_by_key(|(gateway_index, candidate)| (Reverse(candidate.sequence), *gateway_index));
    let mut unique_candidates = Vec::with_capacity(first_gateway_indices.len());
    for (_, mut candidate) in candidates {
        if let Some(gateway_index) =
            first_gateway_indices.remove(&(candidate.sequence, candidate.cid))
        {
            candidate.gateway_index = gateway_index;
            unique_candidates.push(candidate);
        }
    }
    Ok(unique_candidates)
}

pub(crate) fn verify_ipns_record_candidate(
    bytes: &[u8],
    peer_id: PeerId,
) -> Result<IpnsManifestCandidate, TrustlessArtifactError> {
    if bytes.len() > IPNS_RECORD_MAX_BYTES {
        return Err(TrustlessArtifactError::IpnsRecordTooLarge {
            limit: IPNS_RECORD_MAX_BYTES,
        });
    }

    let record = rust_ipns::Record::decode(bytes).map_err(|source| {
        TrustlessArtifactError::InvalidIpnsRecord {
            source: source.into(),
        }
    })?;
    verify_ipns_public_key_binding(bytes, peer_id)?;
    record
        .verify_signature(peer_id)
        .map_err(|source| TrustlessArtifactError::InvalidIpnsSignature { source })?;
    if record.validity_type() != rust_ipns::ValidityType::EOL {
        return Err(TrustlessArtifactError::UnsupportedIpnsValidity);
    }
    let eol = record
        .validity()
        .map_err(|source| TrustlessArtifactError::InvalidIpnsRecord {
            source: source.into(),
        })?
        .with_timezone(&Utc);
    let data = record
        .data()
        .map_err(|source| TrustlessArtifactError::InvalidIpnsRecord {
            source: source.into(),
        })?;
    let cid = parse_ipns_value(data.value())?;
    Ok(IpnsManifestCandidate {
        sequence: data.sequence(),
        cid,
        eol,
        // The IPNS phase collector sets the gateway that returned the record.
        gateway_index: 0,
    })
}

fn parse_ipns_value(value: &[u8]) -> Result<Cid, TrustlessArtifactError> {
    let value = str::from_utf8(value)
        .map_err(|_| TrustlessArtifactError::UnsupportedIpnsValue("non-UTF8 value"))?;
    let cid = if let Some(cid) = value.strip_prefix("/ipfs/") {
        if cid.is_empty() || cid.contains('/') {
            return Err(TrustlessArtifactError::UnsupportedIpnsValue(
                "IPNS value must be /ipfs/{cid} without a path suffix",
            ));
        }
        cid
    } else if value.starts_with('/') {
        return Err(TrustlessArtifactError::UnsupportedIpnsValue(
            "IPNS value must be /ipfs/{cid} or a bare CID",
        ));
    } else {
        value
    };
    parse_cid(cid)
}

fn expected_ipns_peer_id(name: &str) -> Result<PeerId, TrustlessArtifactError> {
    let cid = parse_cid(name)?;
    if cid.version() != Version::V1 || cid.codec() != LIBP2P_KEY_CODEC {
        return Err(TrustlessArtifactError::UnsupportedIpnsName {
            name: name.to_string(),
        });
    }
    PeerId::from_bytes(&cid.hash().to_bytes())
        .map_err(|source| TrustlessArtifactError::InvalidIpnsPeerId { source })
}

fn verify_ipns_public_key_binding(
    bytes: &[u8],
    expected_peer_id: PeerId,
) -> Result<(), TrustlessArtifactError> {
    let Some(public_key_bytes) = ipns_record_public_key(bytes)? else {
        return Ok(());
    };
    let public_key = PublicKey::try_decode_protobuf(public_key_bytes)
        .map_err(|source| TrustlessArtifactError::InvalidIpnsPublicKey { source })?;
    let actual_peer_id = public_key.to_peer_id();
    if actual_peer_id != expected_peer_id {
        return Err(TrustlessArtifactError::IpnsPublicKeyMismatch {
            expected: Box::new(expected_peer_id),
            actual: Box::new(actual_peer_id),
        });
    }
    Ok(())
}

fn ipns_record_public_key(bytes: &[u8]) -> Result<Option<&[u8]>, TrustlessArtifactError> {
    let mut reader = BytesReader::from_bytes(bytes);
    let mut public_key = None;
    while !reader.is_eof() {
        match reader
            .next_tag(bytes)
            .map_err(|source| invalid_ipns_record_error(&source))?
        {
            58 => {
                let value = reader
                    .read_bytes(bytes)
                    .map_err(|source| invalid_ipns_record_error(&source))?;
                if value.is_empty() {
                    public_key = None;
                } else {
                    public_key = Some(value);
                }
            }
            tag => reader
                .read_unknown(bytes, tag)
                .map_err(|source| invalid_ipns_record_error(&source))?,
        }
    }
    Ok(public_key)
}

fn invalid_ipns_record_error(source: &quick_protobuf::Error) -> TrustlessArtifactError {
    TrustlessArtifactError::InvalidIpnsRecord {
        source: std::io::Error::new(std::io::ErrorKind::InvalidData, source.to_string()),
    }
}
