//! The trustless artifact fetcher and its sequential artifact fetches. The
//! hedged chunk and catalog fetches and manifest and IPNS resolution live in
//! the submodules.

use std::collections::HashSet;
use std::sync::atomic::AtomicBool;
#[cfg(test)]
use std::time::Duration;
use std::time::Instant;

use cid::Cid;
use poi::SensitiveUrl;
use tracing::debug;
use url::Url;

use crate::car::{RetrievalLimits, decode_car_blocks, reconstruct_file};
use crate::error::{TrustlessArtifactError, TrustlessHttpSource, VerifiedCidError};
use crate::http::{
    HttpAttemptTimeouts, car_gateway_url, fetch_response_bytes,
    fetch_response_bytes_reporting_headers,
};
use crate::pool::{GatewayCapability, GatewayPool, opaque_gateway_id};
use crate::{CAR_ACCEPT, MANIFEST_JSON_MAX_BYTES};

mod hedged;
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
