//! Manifest CID fetches, hedged across gateways, and raw block verification.

use std::collections::HashSet;
use std::time::Instant;

use blake2b_simd::Params;
use cid::Cid;
use futures::{StreamExt, future::BoxFuture, stream::FuturesUnordered};
use sha2::{Digest, Sha256};
use tracing::debug;
use url::Url;

use super::{TrustlessArtifactFetchResult, TrustlessArtifactFetcher, parse_cid};
use crate::car::RetrievalLimits;
use crate::error::{TrustlessArtifactError, TrustlessHttpSource};
use crate::http::{car_gateway_url, fetch_response_bytes_with_timeouts, raw_gateway_url};
use crate::pool::{GatewayAttempt, GatewayCapability};
use crate::{MANIFEST_CID_HEDGE_DELAY, RAW_ACCEPT, RAW_CODEC};

type ManifestCidRequestResult = (usize, usize, u128, Result<Vec<u8>, TrustlessArtifactError>);
type ManifestCidRequest<'a> = BoxFuture<'a, ManifestCidRequestResult>;

impl TrustlessArtifactFetcher<'_> {
    pub async fn fetch_manifest_cid(&self, cid: &str) -> Result<Vec<u8>, TrustlessArtifactError> {
        self.fetch_manifest_cid_with_metadata(cid)
            .await
            .map(TrustlessArtifactFetchResult::into_bytes)
    }

    pub async fn fetch_manifest_cid_with_metadata(
        &self,
        cid: &str,
    ) -> Result<TrustlessArtifactFetchResult, TrustlessArtifactError> {
        self.fetch_manifest_cid_with_metadata_from_gateway(cid, None)
            .await
    }

    /// Like [`Self::fetch_manifest_cid_with_metadata`], preferring
    /// `preferred_gateway_index` for the first attempt only. Hedged attempts
    /// are chosen by the pool.
    pub async fn fetch_manifest_cid_with_metadata_from_gateway(
        &self,
        cid: &str,
        preferred_gateway_index: Option<usize>,
    ) -> Result<TrustlessArtifactFetchResult, TrustlessArtifactError> {
        let cid = parse_cid(cid)?;
        self.fetch_verified_manifest_cid(cid, preferred_gateway_index)
            .await
    }

    pub(super) async fn fetch_verified_manifest_cid(
        &self,
        cid: Cid,
        preferred_gateway_index: Option<usize>,
    ) -> Result<TrustlessArtifactFetchResult, TrustlessArtifactError> {
        if self.gateways.is_empty() {
            return Err(TrustlessArtifactError::NoGateways);
        }
        if cid.codec() == RAW_CODEC {
            raw_multihash_policy(cid)?;
        }

        let gateway_count = self.gateways.len();
        let preferred_gateway_index = preferred_gateway_index.map(|index| index % gateway_count);
        let mut next_gateway_index = 0;
        let mut reserved_identities = HashSet::with_capacity(gateway_count);
        let mut requests: FuturesUnordered<ManifestCidRequest<'_>> = FuturesUnordered::new();
        let mut last_error = None;

        let Some(gateway_attempt) = self.pool.select_excluding(
            &self.gateway_ids,
            GatewayCapability::ManifestCid,
            preferred_gateway_index,
            &reserved_identities,
        ) else {
            return Err(TrustlessArtifactError::NoGateways);
        };
        reserved_identities.insert(gateway_attempt.identity);
        let gateway_index = gateway_attempt.index;
        let gateway = self.gateways.expose(gateway_index);
        let url = if cid.codec() == RAW_CODEC {
            raw_gateway_url(gateway, &cid)
        } else {
            car_gateway_url(gateway, &cid)
        };
        let source = TrustlessHttpSource::Gateway {
            index: gateway_index,
            count: gateway_count,
        };
        requests.push(self.manifest_cid_request(
            cid,
            gateway_index,
            0,
            url,
            source,
            gateway_attempt,
        ));
        next_gateway_index += 1;
        let mut next_launch_at = tokio::time::Instant::now() + MANIFEST_CID_HEDGE_DELAY;

        while next_gateway_index < gateway_count || !requests.is_empty() {
            if requests.is_empty() {
                let Some(gateway_attempt) = self.pool.select_excluding(
                    &self.gateway_ids,
                    GatewayCapability::ManifestCid,
                    None,
                    &reserved_identities,
                ) else {
                    break;
                };
                reserved_identities.insert(gateway_attempt.identity);
                let gateway_index = gateway_attempt.index;
                let gateway = self.gateways.expose(gateway_index);
                let url = if cid.codec() == RAW_CODEC {
                    raw_gateway_url(gateway, &cid)
                } else {
                    car_gateway_url(gateway, &cid)
                };
                let source = TrustlessHttpSource::Gateway {
                    index: gateway_index,
                    count: gateway_count,
                };
                let ordinal = next_gateway_index;
                requests.push(self.manifest_cid_request(
                    cid,
                    gateway_index,
                    ordinal,
                    url,
                    source,
                    gateway_attempt,
                ));
                next_gateway_index += 1;
                next_launch_at = tokio::time::Instant::now() + MANIFEST_CID_HEDGE_DELAY;
                continue;
            }

            // Every eligible gateway may start an attempt, one hedge delay apart,
            // while earlier attempts are still pending.
            if next_gateway_index < gateway_count {
                tokio::select! {
                    biased;
                    result = requests.next() => {
                        let Some((gateway_index, ordinal, elapsed_ms, result)) = result else { continue };
                        match result {
                            Ok(bytes) => {
                                debug!(
                                    gateway_index,
                                    gateway_count,
                                    cid = %cid,
                                    bytes = bytes.len(),
                                    elapsed_ms,
                                    attempt = manifest_attempt_role(ordinal),
                                    representation = if cid.codec() == RAW_CODEC { "raw" } else { "car" },
                                    "verified CID gateway fetch succeeded"
                                );
                                return Ok(TrustlessArtifactFetchResult {
                                    verified_cid: cid.to_string(),
                                    bytes,
                                    gateway_index,
                                    gateway_count,
                                });
                            }
                            Err(error) => {
                                debug!(
                                    ?error,
                                    gateway_index,
                                    gateway_count,
                                    cid = %cid,
                                    elapsed_ms,
                                    attempt = manifest_attempt_role(ordinal),
                                    representation = if cid.codec() == RAW_CODEC { "raw" } else { "car" },
                                    "verified CID gateway fetch failed"
                                );
                                last_error = Some(error);
                                // A failed request launches the next gateway immediately; do not wait for the hedge timer.
                                next_launch_at = tokio::time::Instant::now();
                            }
                        }
                    }
                    () = tokio::time::sleep_until(next_launch_at) => {
                        let Some(gateway_attempt) = self.pool.select_excluding(
                            &self.gateway_ids,
                            GatewayCapability::ManifestCid,
                            None,
                            &reserved_identities,
                        )
                        else {
                            next_gateway_index = gateway_count;
                            continue;
                        };
                        reserved_identities.insert(gateway_attempt.identity);
                        let gateway_index = gateway_attempt.index;
                        let gateway = self.gateways.expose(gateway_index);
                        let url = if cid.codec() == RAW_CODEC {
                            raw_gateway_url(gateway, &cid)
                        } else {
                            car_gateway_url(gateway, &cid)
                        };
                        let source = TrustlessHttpSource::Gateway {
                            index: gateway_index,
                            count: gateway_count,
                        };
                        let ordinal = next_gateway_index;
                        requests.push(self.manifest_cid_request(
                            cid,
                            gateway_index,
                            ordinal,
                            url,
                            source,
                            gateway_attempt,
                        ));
                        next_gateway_index += 1;
                        next_launch_at = tokio::time::Instant::now() + MANIFEST_CID_HEDGE_DELAY;
                    }
                }
            } else if let Some((gateway_index, ordinal, elapsed_ms, result)) = requests.next().await
            {
                match result {
                    Ok(bytes) => {
                        debug!(
                            gateway_index,
                            gateway_count,
                            cid = %cid,
                            bytes = bytes.len(),
                            elapsed_ms,
                            attempt = manifest_attempt_role(ordinal),
                            representation = if cid.codec() == RAW_CODEC { "raw" } else { "car" },
                            "verified CID gateway fetch succeeded"
                        );
                        return Ok(TrustlessArtifactFetchResult {
                            verified_cid: cid.to_string(),
                            bytes,
                            gateway_index,
                            gateway_count,
                        });
                    }
                    Err(error) => {
                        debug!(
                            ?error,
                            gateway_index,
                            gateway_count,
                            cid = %cid,
                            elapsed_ms,
                            attempt = manifest_attempt_role(ordinal),
                            representation = if cid.codec() == RAW_CODEC { "raw" } else { "car" },
                            "verified CID gateway fetch failed"
                        );
                        last_error = Some(error);
                        next_launch_at = tokio::time::Instant::now();
                    }
                }
            }
        }

        Err(last_error.unwrap_or(TrustlessArtifactError::NoGateways))
    }

    fn manifest_cid_request(
        &self,
        cid: Cid,
        gateway_index: usize,
        ordinal: usize,
        url: Url,
        source: TrustlessHttpSource,
        gateway_attempt: GatewayAttempt,
    ) -> ManifestCidRequest<'_> {
        Box::pin(async move {
            let attempt_started = Instant::now();
            let result = self.fetch_verified_cid_from_url(cid, &url, source).await;
            match &result {
                Ok(_) => gateway_attempt.success(),
                Err(error) => gateway_attempt.failure(error),
            }
            (
                gateway_index,
                ordinal,
                attempt_started.elapsed().as_millis(),
                result,
            )
        })
    }

    async fn fetch_verified_cid_from_url(
        &self,
        cid: Cid,
        url: &Url,
        source: TrustlessHttpSource,
    ) -> Result<Vec<u8>, TrustlessArtifactError> {
        let limits = RetrievalLimits::manifest();
        if cid.codec() == RAW_CODEC {
            let bytes = fetch_response_bytes_with_timeouts(
                self.client,
                url,
                source,
                Some(RAW_ACCEPT),
                limits.reconstructed_bytes,
                self.timeouts,
            )
            .await?;
            verify_raw_cid_bytes(cid, &bytes)?;
            Ok(bytes)
        } else {
            self.fetch_cid_bytes_from_url(cid, url, source, limits, None)
                .await
        }
    }
}

const fn manifest_attempt_role(ordinal: usize) -> &'static str {
    if ordinal == 0 {
        "initial"
    } else {
        "hedged_or_fallback"
    }
}

#[derive(Debug, Clone, Copy)]
enum RawMultihash {
    Identity,
    Sha2_256,
    Blake2b256,
}

const fn raw_multihash_policy(cid: Cid) -> Result<RawMultihash, TrustlessArtifactError> {
    match cid.hash().code() {
        0x00 => Ok(RawMultihash::Identity),
        0x12 => Ok(RawMultihash::Sha2_256),
        0xb220 => Ok(RawMultihash::Blake2b256),
        code => Err(TrustlessArtifactError::UnsupportedMultihash { cid, code }),
    }
}

fn verify_raw_cid_bytes(cid: Cid, bytes: &[u8]) -> Result<(), TrustlessArtifactError> {
    let multihash = raw_multihash_policy(cid)?;
    let matches = match multihash {
        RawMultihash::Identity => cid.hash().digest() == bytes,
        RawMultihash::Sha2_256 => {
            let digest = Sha256::digest(bytes);
            cid.hash().digest() == &digest[..]
        }
        RawMultihash::Blake2b256 => {
            let digest = Params::new()
                .hash_length(32)
                .to_state()
                .update(bytes)
                .finalize();
            cid.hash().digest() == digest.as_bytes()
        }
    };
    if !matches {
        return Err(TrustlessArtifactError::RawCidDigestMismatch { cid });
    }
    Ok(())
}
