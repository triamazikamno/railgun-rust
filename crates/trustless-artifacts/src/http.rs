//! Gateway HTTP requests: bounded response reading and trustless gateway URLs.

use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use cid::Cid;
use reqwest::header::{ACCEPT, HeaderValue};
use url::Url;

use crate::error::{TrustlessArtifactError, TrustlessHttpPhase, TrustlessHttpSource};
use crate::{
    ARTIFACT_HTTP_HEADERS_TIMEOUT, ARTIFACT_HTTP_IDLE_TIMEOUT, ARTIFACT_HTTP_TOTAL_TIMEOUT,
};

#[derive(Debug, Clone, Copy)]
pub(crate) struct HttpAttemptTimeouts {
    pub(crate) headers: Duration,
    pub(crate) idle: Duration,
    pub(crate) total: Duration,
}

impl HttpAttemptTimeouts {
    pub(crate) const PRODUCTION: Self = Self {
        headers: ARTIFACT_HTTP_HEADERS_TIMEOUT,
        idle: ARTIFACT_HTTP_IDLE_TIMEOUT,
        total: ARTIFACT_HTTP_TOTAL_TIMEOUT,
    };
}

pub(crate) async fn fetch_response_bytes(
    client: &reqwest::Client,
    url: &Url,
    source: TrustlessHttpSource,
    accept: Option<HeaderValue>,
    limit: usize,
) -> Result<Vec<u8>, TrustlessArtifactError> {
    fetch_response_bytes_with_timeouts(
        client,
        url,
        source,
        accept,
        limit,
        HttpAttemptTimeouts::PRODUCTION,
    )
    .await
}

pub(crate) async fn fetch_response_bytes_with_timeouts(
    client: &reqwest::Client,
    url: &Url,
    source: TrustlessHttpSource,
    accept: Option<HeaderValue>,
    limit: usize,
    timeouts: HttpAttemptTimeouts,
) -> Result<Vec<u8>, TrustlessArtifactError> {
    fetch_response_bytes_reporting_headers(client, url, source, accept, limit, timeouts, None).await
}

/// Like [`fetch_response_bytes_with_timeouts`], and sets `headers_received`
/// once the response headers have arrived.
pub(crate) async fn fetch_response_bytes_reporting_headers(
    client: &reqwest::Client,
    url: &Url,
    source: TrustlessHttpSource,
    accept: Option<HeaderValue>,
    limit: usize,
    timeouts: HttpAttemptTimeouts,
    headers_received: Option<&AtomicBool>,
) -> Result<Vec<u8>, TrustlessArtifactError> {
    let deadline = tokio::time::Instant::now() + timeouts.total;
    tokio::time::timeout_at(
        deadline,
        fetch_response_bytes_with_phase_timeouts(
            client,
            url,
            source,
            accept,
            limit,
            timeouts.headers,
            timeouts.idle,
            headers_received,
        ),
    )
    .await
    .map_err(|_| TrustlessArtifactError::HttpAttemptDeadline { origin: source })?
}

/// Bounds the wait for response headers by `headers_timeout` and each gap
/// between body chunks by `idle_timeout`.
async fn fetch_response_bytes_with_phase_timeouts(
    client: &reqwest::Client,
    url: &Url,
    source: TrustlessHttpSource,
    accept: Option<HeaderValue>,
    limit: usize,
    headers_timeout: Duration,
    idle_timeout: Duration,
    headers_received: Option<&AtomicBool>,
) -> Result<Vec<u8>, TrustlessArtifactError> {
    let mut request = client.get(url.clone());
    if let Some(accept) = accept {
        request = request.header(ACCEPT, accept);
    }
    let mut response = tokio::time::timeout(headers_timeout, request.send())
        .await
        .map_err(|_| TrustlessArtifactError::HttpTimeout {
            origin: source,
            phase: TrustlessHttpPhase::ResponseHeaders,
        })?
        .map_err(|error| TrustlessArtifactError::Http {
            origin: source,
            phase: TrustlessHttpPhase::ResponseHeaders,
            error: error.without_url(),
        })?;
    if let Some(headers_received) = headers_received {
        headers_received.store(true, Ordering::Relaxed);
    }
    let status = response.status();
    if !status.is_success() {
        return Err(TrustlessArtifactError::HttpStatus {
            origin: source,
            status,
        });
    }

    let mut bytes = Vec::new();
    while let Some(chunk) = tokio::time::timeout(idle_timeout, response.chunk())
        .await
        .map_err(|_| TrustlessArtifactError::HttpTimeout {
            origin: source,
            phase: TrustlessHttpPhase::ResponseBody,
        })?
        .map_err(|error| TrustlessArtifactError::Http {
            origin: source,
            phase: TrustlessHttpPhase::ResponseBody,
            error: error.without_url(),
        })?
    {
        let next_len = bytes.len().checked_add(chunk.len()).ok_or(
            TrustlessArtifactError::ResponseTooLarge {
                origin: source,
                limit,
            },
        )?;
        if next_len > limit {
            return Err(TrustlessArtifactError::ResponseTooLarge {
                origin: source,
                limit,
            });
        }
        bytes.extend_from_slice(&chunk);
    }
    Ok(bytes)
}

pub(crate) fn car_gateway_url(gateway: &Url, cid: &Cid) -> Url {
    let mut url = gateway_resource_url(gateway, "ipfs", &cid.to_string());
    {
        let mut query = url.query_pairs_mut();
        query.append_pair("format", "car");
        query.append_pair("dag-scope", "entity");
    }
    url
}

pub(crate) fn raw_gateway_url(gateway: &Url, cid: &Cid) -> Url {
    let mut url = gateway_resource_url(gateway, "ipfs", &cid.to_string());
    url.query_pairs_mut().append_pair("format", "raw");
    url
}

pub(crate) fn ipns_record_gateway_url(gateway: &Url, name: &str) -> Url {
    let mut url = gateway_resource_url(gateway, "ipns", name);
    url.query_pairs_mut().append_pair("format", "ipns-record");
    url
}

fn gateway_resource_url(gateway: &Url, namespace: &'static str, value: &str) -> Url {
    let mut url = gateway.clone();
    let path = gateway.path().trim_end_matches('/');
    let namespace_suffix = format!("/{namespace}");
    let new_path = if path.ends_with(&namespace_suffix) {
        format!("{path}/{value}")
    } else if path.is_empty() {
        format!("/{namespace}/{value}")
    } else {
        format!("{path}/{namespace}/{value}")
    };
    url.set_path(&new_path);
    url
}
