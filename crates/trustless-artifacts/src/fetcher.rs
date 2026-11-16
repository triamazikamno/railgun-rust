//! The trustless artifact fetcher and its artifact, catalog and chunk fetches.
//! Manifest and IPNS resolution live in the submodules.

use std::collections::HashSet;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
#[cfg(test)]
use std::time::Duration;
use std::time::Instant;

use cid::Cid;
use futures::{StreamExt, stream::FuturesUnordered};
use poi::SensitiveUrl;
use tracing::debug;
use url::Url;

use crate::car::{RetrievalLimits, decode_car_blocks, reconstruct_file};
use crate::error::{TrustlessArtifactError, TrustlessHttpSource, VerifiedCidError};
use crate::http::{
    HttpAttemptTimeouts, car_gateway_url, fetch_response_bytes,
    fetch_response_bytes_reporting_headers,
};
use crate::pool::{GatewayAttempt, GatewayCapability, GatewayPool, opaque_gateway_id};
use crate::{CAR_ACCEPT, CATALOG_HEDGE_DELAY, CHUNK_HEDGE_DELAY, MANIFEST_JSON_MAX_BYTES};

pub(crate) mod ipns;
mod manifest;

pub struct TrustlessArtifactFetcher<'a> {
    client: &'a reqwest::Client,
    gateways: GatewayUrls<'a>,
    gateway_ids: Vec<u64>,
    pool: GatewayPool,
    timeouts: HttpAttemptTimeouts,
}

enum GatewayUrls<'a> {
    Public(&'a [Url]),
    Poi(&'a [SensitiveUrl]),
}

impl GatewayUrls<'_> {
    const fn len(&self) -> usize {
        match self {
            Self::Public(gateways) => gateways.len(),
            Self::Poi(gateways) => gateways.len(),
        }
    }

    const fn is_empty(&self) -> bool {
        self.len() == 0
    }

    const fn expose(&self, index: usize) -> &Url {
        match self {
            Self::Public(gateways) => &gateways[index],
            Self::Poi(gateways) => gateways[index].expose_url(),
        }
    }
}

#[derive(Debug)]
pub struct TrustlessArtifactFetchResult {
    verified_cid: String,
    pub(crate) bytes: Vec<u8>,
    pub(crate) gateway_index: usize,
    pub(crate) gateway_count: usize,
}

impl TrustlessArtifactFetchResult {
    #[must_use]
    pub fn verified_cid(&self) -> &str {
        &self.verified_cid
    }

    #[must_use]
    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }

    #[must_use]
    pub const fn gateway_index(&self) -> usize {
        self.gateway_index
    }

    #[must_use]
    pub const fn gateway_count(&self) -> usize {
        self.gateway_count
    }

    #[must_use]
    pub fn into_bytes(self) -> Vec<u8> {
        self.bytes
    }

    #[doc(hidden)]
    #[cfg(any(test, feature = "test-utils"))]
    pub fn verified_for_test(cid: impl Into<String>, bytes: Vec<u8>) -> Self {
        Self {
            verified_cid: cid.into(),
            bytes,
            gateway_index: 0,
            gateway_count: 1,
        }
    }
}

impl<'a> TrustlessArtifactFetcher<'a> {
    #[must_use]
    pub fn new(client: &'a reqwest::Client, gateways: &'a [Url]) -> Self {
        Self {
            client,
            gateways: GatewayUrls::Public(gateways),
            gateway_ids: gateways.iter().map(opaque_gateway_id).collect(),
            pool: GatewayPool::new(),
            timeouts: HttpAttemptTimeouts::PRODUCTION,
        }
    }

    #[must_use]
    pub fn new_poi(client: &'a reqwest::Client, gateways: &'a [SensitiveUrl]) -> Self {
        Self {
            client,
            gateways: GatewayUrls::Poi(gateways),
            gateway_ids: gateways
                .iter()
                .map(|gateway| opaque_gateway_id(gateway.expose_url()))
                .collect(),
            pool: GatewayPool::new(),
            timeouts: HttpAttemptTimeouts::PRODUCTION,
        }
    }

    #[must_use]
    pub fn new_with_pool(
        client: &'a reqwest::Client,
        gateways: &'a [Url],
        pool: GatewayPool,
    ) -> Self {
        Self {
            client,
            gateways: GatewayUrls::Public(gateways),
            gateway_ids: gateways.iter().map(opaque_gateway_id).collect(),
            pool,
            timeouts: HttpAttemptTimeouts::PRODUCTION,
        }
    }

    #[must_use]
    pub fn new_poi_with_pool(
        client: &'a reqwest::Client,
        gateways: &'a [SensitiveUrl],
        pool: GatewayPool,
    ) -> Self {
        Self {
            client,
            gateways: GatewayUrls::Poi(gateways),
            gateway_ids: gateways
                .iter()
                .map(|gateway| opaque_gateway_id(gateway.expose_url()))
                .collect(),
            pool,
            timeouts: HttpAttemptTimeouts::PRODUCTION,
        }
    }

    pub async fn fetch_artifact_cid(
        &self,
        cid: &str,
        byte_size: u64,
    ) -> Result<Vec<u8>, TrustlessArtifactError> {
        let cid = parse_cid(cid)?;
        self.fetch_cid_bytes(cid, RetrievalLimits::artifact(byte_size)?, "artifact")
            .await
            .map(TrustlessArtifactFetchResult::into_bytes)
    }

    pub async fn fetch_artifact_cid_with_metadata_from_gateway(
        &self,
        cid: &str,
        byte_size: u64,
        preferred_gateway_index: usize,
    ) -> Result<TrustlessArtifactFetchResult, TrustlessArtifactError> {
        self.fetch_artifact_cid_with_metadata_from_gateway_bounded(
            cid,
            byte_size,
            preferred_gateway_index,
            self.gateways.len(),
        )
        .await
    }

    pub async fn fetch_artifact_cid_with_metadata_from_gateway_bounded(
        &self,
        cid: &str,
        byte_size: u64,
        preferred_gateway_index: usize,
        max_gateway_attempts: usize,
    ) -> Result<TrustlessArtifactFetchResult, TrustlessArtifactError> {
        let cid = parse_cid(cid)?;
        self.fetch_cid_bytes_from_gateway(
            cid,
            RetrievalLimits::artifact(byte_size)?,
            "artifact",
            Some(preferred_gateway_index),
            max_gateway_attempts,
        )
        .await
    }

    /// Fetches an indexed-artifact chunk, hedging a gateway that stalls before
    /// responding.
    ///
    /// Attempts fall back sequentially across the same gateways as
    /// [`Self::fetch_artifact_cid_with_metadata_from_gateway`], except that when
    /// the sole running attempt has not received response headers within
    /// `CHUNK_HEDGE_DELAY`, one concurrent attempt starts on another gateway.
    /// At most one hedge starts per chunk, so at most two attempts run at once.
    /// The first body that verifies against `cid` wins; the other attempt is
    /// cancelled and its gateway released without a recorded failure.
    ///
    /// `admit_hedge` is called at most once, after a hedge gateway has been
    /// reserved and immediately before the hedge starts. Returning `None`
    /// vetoes the hedge and the running attempt continues alone. A returned
    /// guard is held for the hedge attempt's lifetime and dropped when that
    /// attempt succeeds, fails or is cancelled, so a caller can charge the
    /// hedge to a byte budget.
    pub async fn fetch_artifact_cid_with_metadata_hedged<G>(
        &self,
        cid: &str,
        byte_size: u64,
        preferred_gateway_index: usize,
        admit_hedge: impl FnOnce() -> Option<G>,
    ) -> Result<TrustlessArtifactFetchResult, TrustlessArtifactError> {
        let cid = parse_cid(cid)?;
        let limits = RetrievalLimits::artifact(byte_size)?;
        if self.gateways.is_empty() {
            return Err(TrustlessArtifactError::NoGateways);
        }

        let gateway_count = self.gateways.len();
        let preferred_gateway_index = preferred_gateway_index % gateway_count;
        let started = tokio::time::Instant::now();
        let mut admit_hedge = Some(admit_hedge);
        let mut reserved_identities = HashSet::with_capacity(gateway_count);
        let mut attempts = FuturesUnordered::new();
        // Hedge deadline, gateway index and headers flag of the sole running
        // attempt, armed while the hedge is unused.
        let mut hedge_watch: Option<(tokio::time::Instant, usize, Arc<AtomicBool>)> = None;
        let mut hedged_gateways = None;
        let mut last_error = None;
        loop {
            if attempts.is_empty() {
                let Some(gateway_attempt) = self.pool.select_excluding(
                    &self.gateway_ids,
                    GatewayCapability::ArtifactCar,
                    reserved_identities
                        .is_empty()
                        .then_some(preferred_gateway_index),
                    &reserved_identities,
                ) else {
                    break;
                };
                reserved_identities.insert(gateway_attempt.identity);
                let headers_received = Arc::new(AtomicBool::new(false));
                if admit_hedge.is_some() {
                    hedge_watch = Some((
                        tokio::time::Instant::now() + CHUNK_HEDGE_DELAY,
                        gateway_attempt.index,
                        Arc::clone(&headers_received),
                    ));
                }
                attempts.push(self.chunk_attempt(
                    cid,
                    limits,
                    gateway_attempt,
                    headers_received,
                    None::<G>,
                ));
            }

            let hedge_at = hedge_watch.as_ref().map(|(hedge_at, _, _)| *hedge_at);
            tokio::select! {
                biased;
                result = attempts.next() => {
                    let Some((gateway_index, result)) = result else { continue };
                    match result {
                        Ok(bytes) => {
                            if let Some((first_gateway_index, hedge_gateway_index)) = hedged_gateways {
                                debug!(
                                    cid = %cid,
                                    first_gateway_index,
                                    hedge_gateway_index,
                                    winner_gateway_index = gateway_index,
                                    gateway_count,
                                    elapsed_ms = started.elapsed().as_millis(),
                                    "hedged artifact chunk fetch completed"
                                );
                            }
                            return Ok(TrustlessArtifactFetchResult {
                                verified_cid: cid.to_string(),
                                bytes,
                                gateway_index,
                                gateway_count,
                            });
                        }
                        // Any other running attempt continues; once none is
                        // left, the loop falls back to the next gateway.
                        Err(error) => last_error = Some(error),
                    }
                }
                () = tokio::time::sleep_until(hedge_at.unwrap_or(started)), if hedge_at.is_some() => {
                    let Some((_, first_gateway_index, headers_received)) = hedge_watch.take() else {
                        continue;
                    };
                    // An attempt that has received headers is progressing and is
                    // never duplicated.
                    if headers_received.load(Ordering::Relaxed) {
                        continue;
                    }
                    let Some(gateway_attempt) = self.pool.select_excluding(
                        &self.gateway_ids,
                        GatewayCapability::ArtifactCar,
                        None,
                        &reserved_identities,
                    ) else {
                        continue;
                    };
                    // A vetoed hedge drops its reservation without a recorded failure.
                    let Some(hedge_guard) = admit_hedge.take().and_then(|admit_hedge| admit_hedge())
                    else {
                        continue;
                    };
                    reserved_identities.insert(gateway_attempt.identity);
                    let hedge_gateway_index = gateway_attempt.index;
                    debug!(
                        cid = %cid,
                        first_gateway_index,
                        hedge_gateway_index,
                        gateway_count,
                        elapsed_ms = started.elapsed().as_millis(),
                        "artifact chunk hedge started"
                    );
                    hedged_gateways = Some((first_gateway_index, hedge_gateway_index));
                    attempts.push(self.chunk_attempt(
                        cid,
                        limits,
                        gateway_attempt,
                        Arc::new(AtomicBool::new(false)),
                        Some(hedge_guard),
                    ));
                }
            }
        }

        Err(last_error.unwrap_or(TrustlessArtifactError::NoGateways))
    }

    /// Fetches a catalog-sized artifact, hedging gateways that stall before
    /// responding.
    ///
    /// The first attempt starts on `preferred_gateway_index` unless the pool
    /// finds that gateway cooling. Every `CATALOG_HEDGE_DELAY` while no running
    /// attempt has received response headers, another attempt starts on the
    /// next eligible gateway. When every running attempt has failed, the next
    /// gateway starts immediately. At most `max_gateway_attempts` attempts start,
    /// bounded by the gateway count. The first body that verifies against `cid`
    /// wins; the other attempts are cancelled and their gateways released
    /// without a recorded failure. A body that fails verification counts as
    /// that gateway's failure while other attempts continue.
    pub async fn fetch_catalog_cid_with_metadata_hedged(
        &self,
        cid: &str,
        byte_size: u64,
        preferred_gateway_index: Option<usize>,
        max_gateway_attempts: usize,
    ) -> Result<TrustlessArtifactFetchResult, TrustlessArtifactError> {
        let cid = parse_cid(cid)?;
        let limits = RetrievalLimits::artifact(byte_size)?;
        if self.gateways.is_empty() {
            return Err(TrustlessArtifactError::NoGateways);
        }

        let gateway_count = self.gateways.len();
        let preferred_gateway_index = preferred_gateway_index.map(|index| index % gateway_count);
        let max_attempts = gateway_count.min(max_gateway_attempts.max(1));
        let started = tokio::time::Instant::now();
        let mut reserved_identities = HashSet::with_capacity(max_attempts);
        let mut attempts = FuturesUnordered::new();
        // Gateway index and headers flag of each running attempt.
        let mut running: Vec<(usize, Arc<AtomicBool>)> = Vec::with_capacity(max_attempts);
        let mut started_gateways = Vec::with_capacity(max_attempts);
        let mut hedge_at: Option<tokio::time::Instant> = None;
        let mut hedge_due = false;
        let mut hedged = false;
        let mut last_error = None;
        loop {
            if (hedge_due || attempts.is_empty()) && started_gateways.len() < max_attempts {
                let gateway_attempt = self.pool.select_excluding(
                    &self.gateway_ids,
                    GatewayCapability::ArtifactCar,
                    if started_gateways.is_empty() {
                        preferred_gateway_index
                    } else {
                        None
                    },
                    &reserved_identities,
                );
                if let Some(gateway_attempt) = gateway_attempt {
                    reserved_identities.insert(gateway_attempt.identity);
                    let gateway_index = gateway_attempt.index;
                    if hedge_due {
                        hedged = true;
                        debug!(
                            cid = %cid,
                            hedge_gateway_index = gateway_index,
                            attempt = started_gateways.len(),
                            gateway_count,
                            elapsed_ms = started.elapsed().as_millis(),
                            "artifact catalog hedge started"
                        );
                    }
                    started_gateways.push(gateway_index);
                    let headers_received = Arc::new(AtomicBool::new(false));
                    running.push((gateway_index, Arc::clone(&headers_received)));
                    attempts.push(self.chunk_attempt(
                        cid,
                        limits,
                        gateway_attempt,
                        headers_received,
                        None::<()>,
                    ));
                    hedge_at = (started_gateways.len() < max_attempts)
                        .then(|| tokio::time::Instant::now() + CATALOG_HEDGE_DELAY);
                }
            }
            hedge_due = false;
            if attempts.is_empty() {
                break;
            }

            tokio::select! {
                biased;
                result = attempts.next() => {
                    let Some((gateway_index, result)) = result else { continue };
                    match result {
                        Ok(bytes) => {
                            if hedged {
                                debug!(
                                    cid = %cid,
                                    ?started_gateways,
                                    winner_gateway_index = gateway_index,
                                    gateway_count,
                                    elapsed_ms = started.elapsed().as_millis(),
                                    "hedged artifact catalog fetch completed"
                                );
                            }
                            return Ok(TrustlessArtifactFetchResult {
                                verified_cid: cid.to_string(),
                                bytes,
                                gateway_index,
                                gateway_count,
                            });
                        }
                        // Other running attempts continue; once none is left,
                        // the loop starts the next gateway immediately.
                        Err(error) => {
                            running.retain(|(index, _)| *index != gateway_index);
                            last_error = Some(error);
                        }
                    }
                }
                () = tokio::time::sleep_until(hedge_at.unwrap_or(started)), if hedge_at.is_some() => {
                    // An attempt that has received headers is progressing and is
                    // never duplicated; the timer re-arms while below the cap.
                    if running
                        .iter()
                        .any(|(_, headers_received)| headers_received.load(Ordering::Relaxed))
                    {
                        hedge_at = Some(tokio::time::Instant::now() + CATALOG_HEDGE_DELAY);
                    } else {
                        hedge_at = None;
                        hedge_due = true;
                    }
                }
            }
        }

        Err(last_error.unwrap_or(TrustlessArtifactError::NoGateways))
    }

    async fn fetch_cid_bytes(
        &self,
        cid: Cid,
        limits: RetrievalLimits,
        resource: &'static str,
    ) -> Result<TrustlessArtifactFetchResult, TrustlessArtifactError> {
        self.fetch_cid_bytes_from_gateway(cid, limits, resource, None, self.gateways.len())
            .await
    }

    async fn fetch_cid_bytes_from_gateway(
        &self,
        cid: Cid,
        limits: RetrievalLimits,
        resource: &'static str,
        preferred_gateway_index: Option<usize>,
        max_gateway_attempts: usize,
    ) -> Result<TrustlessArtifactFetchResult, TrustlessArtifactError> {
        if self.gateways.is_empty() {
            return Err(TrustlessArtifactError::NoGateways);
        }

        let mut last_error = None;
        let gateway_count = self.gateways.len();
        let preferred_gateway_index = preferred_gateway_index.map(|index| index % gateway_count);
        let max_attempts = gateway_count.min(max_gateway_attempts.max(1));
        let mut reserved_identities = HashSet::with_capacity(max_attempts);
        let mut launched_attempts = 0;
        while launched_attempts < max_attempts {
            let Some(gateway_attempt) = self.pool.select_excluding(
                &self.gateway_ids,
                GatewayCapability::ArtifactCar,
                if launched_attempts == 0 {
                    preferred_gateway_index
                } else {
                    None
                },
                &reserved_identities,
            ) else {
                break;
            };
            reserved_identities.insert(gateway_attempt.identity);
            let attempt = launched_attempts;
            launched_attempts += 1;
            let gateway_index = gateway_attempt.index;
            let gateway = self.gateways.expose(gateway_index);
            let attempt_started = Instant::now();
            let url = car_gateway_url(gateway, &cid);
            let source = TrustlessHttpSource::Gateway {
                index: gateway_index,
                count: gateway_count,
            };
            match self
                .fetch_cid_bytes_from_url(cid, &url, source, limits, None)
                .await
            {
                Ok(bytes) => {
                    if attempt > 0 {
                        debug!(
                            gateway_index,
                            gateway_count,
                            preferred_gateway_index,
                            resource,
                            cid = %cid,
                            bytes = bytes.len(),
                            elapsed_ms = attempt_started.elapsed().as_millis(),
                            "POI artifact CID gateway fetch succeeded after fallback"
                        );
                    }
                    gateway_attempt.success();
                    return Ok(TrustlessArtifactFetchResult {
                        verified_cid: cid.to_string(),
                        bytes,
                        gateway_index,
                        gateway_count,
                    });
                }
                Err(err) => {
                    debug!(
                        ?err,
                        gateway_index,
                        gateway_count,
                        resource,
                        cid = %cid,
                        elapsed_ms = attempt_started.elapsed().as_millis(),
                        "POI artifact CID gateway fetch failed"
                    );
                    gateway_attempt.failure(&err);
                    last_error = Some(err);
                }
            }
        }

        Err(last_error.unwrap_or(TrustlessArtifactError::NoGateways))
    }

    /// Runs one hedged artifact attempt, for an indexed-artifact chunk or a POI
    /// checkpoint catalog, and records its gateway outcome. `_hedge_guard` is
    /// held until the attempt completes or is cancelled.
    async fn chunk_attempt<G>(
        &self,
        cid: Cid,
        limits: RetrievalLimits,
        gateway_attempt: GatewayAttempt,
        headers_received: Arc<AtomicBool>,
        _hedge_guard: Option<G>,
    ) -> (usize, Result<Vec<u8>, TrustlessArtifactError>) {
        let gateway_index = gateway_attempt.index;
        let gateway_count = self.gateways.len();
        let url = car_gateway_url(self.gateways.expose(gateway_index), &cid);
        let source = TrustlessHttpSource::Gateway {
            index: gateway_index,
            count: gateway_count,
        };
        let attempt_started = Instant::now();
        let result = self
            .fetch_cid_bytes_from_url(cid, &url, source, limits, Some(&headers_received))
            .await;
        match &result {
            Ok(_) => gateway_attempt.success(),
            Err(err) => {
                debug!(
                    ?err,
                    gateway_index,
                    gateway_count,
                    resource = "artifact",
                    cid = %cid,
                    elapsed_ms = attempt_started.elapsed().as_millis(),
                    "POI artifact CID gateway fetch failed"
                );
                gateway_attempt.failure(err);
            }
        }
        (gateway_index, result)
    }

    async fn fetch_cid_bytes_from_url(
        &self,
        cid: Cid,
        url: &Url,
        source: TrustlessHttpSource,
        limits: RetrievalLimits,
        headers_received: Option<&AtomicBool>,
    ) -> Result<Vec<u8>, TrustlessArtifactError> {
        let car_bytes = fetch_response_bytes_reporting_headers(
            self.client,
            url,
            source,
            Some(CAR_ACCEPT),
            limits.response_bytes,
            self.timeouts,
            headers_received,
        )
        .await?;
        let blocks = decode_car_blocks(&car_bytes, cid, limits.block_count).await?;
        reconstruct_file(cid, &blocks, limits)
    }
}

/// Fetches and verifies a manifest-sized artifact from the configured gateways.
pub async fn fetch_verified_cid(
    client: &reqwest::Client,
    gateways: &[Url],
    cid: &str,
) -> Result<Vec<u8>, VerifiedCidError> {
    let cid = parse_cid(cid).map_err(VerifiedCidError::from)?;
    TrustlessArtifactFetcher::new(client, gateways)
        .fetch_verified_manifest_cid(cid, None)
        .await
        .map(TrustlessArtifactFetchResult::into_bytes)
        .map_err(VerifiedCidError::from)
}

pub async fn fetch_verified_cid_with_pool(
    client: &reqwest::Client,
    gateways: &[Url],
    cid: &str,
    pool: GatewayPool,
) -> Result<Vec<u8>, VerifiedCidError> {
    let cid = parse_cid(cid).map_err(VerifiedCidError::from)?;
    TrustlessArtifactFetcher::new_with_pool(client, gateways, pool)
        .fetch_verified_manifest_cid(cid, None)
        .await
        .map(TrustlessArtifactFetchResult::into_bytes)
        .map_err(VerifiedCidError::from)
}

pub async fn fetch_manifest_url(
    client: &reqwest::Client,
    url: &Url,
) -> Result<Vec<u8>, TrustlessArtifactError> {
    fetch_response_bytes(
        client,
        url,
        TrustlessHttpSource::ExplicitManifest,
        None,
        MANIFEST_JSON_MAX_BYTES,
    )
    .await
}

fn parse_cid(value: &str) -> Result<Cid, TrustlessArtifactError> {
    Cid::try_from(value).map_err(|source| TrustlessArtifactError::InvalidCid { source })
}

#[cfg(test)]
impl TrustlessArtifactFetcher<'_> {
    pub(crate) const fn with_http_timeouts_for_test(
        mut self,
        headers: Duration,
        idle: Duration,
        total: Duration,
    ) -> Self {
        self.timeouts = HttpAttemptTimeouts {
            headers,
            idle,
            total,
        };
        self
    }
}
