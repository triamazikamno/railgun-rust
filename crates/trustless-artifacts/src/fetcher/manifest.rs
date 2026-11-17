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
        ManifestCidRace::new(self, cid)
            .run(preferred_gateway_index)
            .await
    }

    fn manifest_cid_request(
        &self,
        cid: Cid,
        ordinal: usize,
        gateway_attempt: GatewayAttempt,
    ) -> ManifestCidRequest<'_> {
        let gateway_index = gateway_attempt.index;
        let gateway = self.gateways.expose(gateway_index);
        let url = if cid.codec() == RAW_CODEC {
            raw_gateway_url(gateway, &cid)
        } else {
            car_gateway_url(gateway, &cid)
        };
        let source = TrustlessHttpSource::Gateway {
            index: gateway_index,
            count: self.gateways.len(),
        };
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

/// One manifest CID fetch. Every eligible gateway may start an attempt, one
/// hedge delay apart, while earlier attempts are still pending. The first
/// verified body wins.
struct ManifestCidRace<'f, 'a> {
    fetcher: &'f TrustlessArtifactFetcher<'a>,
    cid: Cid,
    gateway_count: usize,
    next_gateway_index: usize,
    reserved_identities: HashSet<u64>,
    requests: FuturesUnordered<ManifestCidRequest<'f>>,
    last_error: Option<TrustlessArtifactError>,
    next_launch_at: tokio::time::Instant,
}

impl<'f, 'a> ManifestCidRace<'f, 'a> {
    fn new(fetcher: &'f TrustlessArtifactFetcher<'a>, cid: Cid) -> Self {
        let gateway_count = fetcher.gateways.len();
        Self {
            fetcher,
            cid,
            gateway_count,
            next_gateway_index: 0,
            reserved_identities: HashSet::with_capacity(gateway_count),
            requests: FuturesUnordered::new(),
            last_error: None,
            // Overwritten by the first launch before the loop reads it.
            next_launch_at: tokio::time::Instant::now(),
        }
    }

    async fn run(
        mut self,
        preferred_gateway_index: Option<usize>,
    ) -> Result<TrustlessArtifactFetchResult, TrustlessArtifactError> {
        self.launch(preferred_gateway_index);
        while self.next_gateway_index < self.gateway_count || !self.requests.is_empty() {
            if self.requests.is_empty() {
                self.launch(None);
                continue;
            }

            // Every eligible gateway may start an attempt, one hedge delay apart,
            // while earlier attempts are still pending.
            let outcome = if self.next_gateway_index < self.gateway_count {
                tokio::select! {
                    biased;
                    result = self.requests.next() => result,
                    () = tokio::time::sleep_until(self.next_launch_at) => {
                        self.launch(None);
                        continue;
                    }
                }
            } else {
                self.requests.next().await
            };
            let Some(outcome) = outcome else { continue };
            if let Some(result) = self.settle(outcome) {
                return Ok(result);
            }
        }

        Err(self
            .last_error
            .unwrap_or(TrustlessArtifactError::NoGateways))
    }

    /// Starts an attempt on the next eligible gateway. When none remains, no
    /// further attempt starts, and the race ends once pending attempts settle.
    fn launch(&mut self, preferred_gateway_index: Option<usize>) {
        let Some(gateway_attempt) = self.fetcher.pool.select_excluding(
            &self.fetcher.gateway_ids,
            GatewayCapability::ManifestCid,
            preferred_gateway_index,
            &self.reserved_identities,
        ) else {
            self.next_gateway_index = self.gateway_count;
            return;
        };
        self.reserved_identities.insert(gateway_attempt.identity);
        self.requests.push(self.fetcher.manifest_cid_request(
            self.cid,
            self.next_gateway_index,
            gateway_attempt,
        ));
        self.next_gateway_index += 1;
        self.next_launch_at = tokio::time::Instant::now() + MANIFEST_CID_HEDGE_DELAY;
    }

    /// Logs a settled attempt and returns the fetch result if it succeeded.
    fn settle(
        &mut self,
        (gateway_index, ordinal, elapsed_ms, result): ManifestCidRequestResult,
    ) -> Option<TrustlessArtifactFetchResult> {
        let (cid, gateway_count) = (self.cid, self.gateway_count);
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
                Some(TrustlessArtifactFetchResult {
                    verified_cid: cid.to_string(),
                    bytes,
                    gateway_index,
                    gateway_count,
                })
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
                self.last_error = Some(error);
                // A failed request launches the next gateway immediately; do not wait for the hedge timer.
                self.next_launch_at = tokio::time::Instant::now();
                None
            }
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
