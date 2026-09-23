use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{Duration, Instant};

use alloy::providers::{Provider, ProviderBuilder};
use alloy_provider::DynProvider;
use rand::prelude::IndexedRandom;
use url::Url;

#[derive(Clone)]
pub struct ProviderHandle {
    pub index: usize,
    pub url: Url,
    pub provider: DynProvider,
}

/// Endpoint identity for session-scoped `eth_getLogs` span limits.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum LogSpanEndpoint {
    /// Pool provider at this index.
    Provider(usize),
    /// Optional archive provider configured outside the pool.
    Archive,
}

impl std::fmt::Display for LogSpanEndpoint {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Provider(index) => write!(f, "{index}"),
            Self::Archive => f.write_str("archive"),
        }
    }
}

/// Whether an endpoint may serve requests. Pools admit every endpoint by
/// default; callers that verify endpoints first start them as `Pending`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RpcAdmission {
    /// Not yet verified; never returned to callers.
    Pending,
    /// Verified and eligible to serve requests.
    Admitted,
    /// Rejected by verification; never returned to callers.
    Excluded,
}

struct ProviderEntry {
    url: Url,
    provider: DynProvider,
}

struct Admissions {
    /// Indexed like `QueryRpcPool::providers`.
    providers: Vec<RpcAdmission>,
    archive: RpcAdmission,
}

impl Admissions {
    fn admitted(provider_count: usize) -> Self {
        Self {
            providers: vec![RpcAdmission::Admitted; provider_count],
            archive: RpcAdmission::Admitted,
        }
    }
}

pub struct QueryRpcPool {
    providers: Vec<ProviderEntry>,
    cooldown: Duration,
    cooldowns: Mutex<HashMap<usize, Instant>>,
    http_client: Option<reqwest::Client>,
    /// Narrowest `eth_getLogs` block span each endpoint accepted this session.
    /// Never persisted, so a new pool starts again from the configured range.
    log_spans: Mutex<HashMap<LogSpanEndpoint, u64>>,
    admissions: Mutex<Admissions>,
}

impl QueryRpcPool {
    #[must_use]
    pub fn new(urls: Vec<Url>, cooldown: Duration) -> Self {
        let providers: Vec<ProviderEntry> = urls
            .into_iter()
            .map(|url| ProviderEntry {
                provider: ProviderBuilder::new().connect_http(url.clone()).erased(),
                url,
            })
            .collect();
        Self {
            admissions: Mutex::new(Admissions::admitted(providers.len())),
            providers,
            cooldown,
            cooldowns: Mutex::new(HashMap::new()),
            http_client: None,
            log_spans: Mutex::new(HashMap::new()),
        }
    }

    /// Creates a pool that routes all RPC traffic through the given
    /// pre-configured [`reqwest::Client`] (e.g. one with a SOCKS proxy).
    #[must_use]
    #[allow(clippy::needless_pass_by_value)] // Client is Arc-based; clone is cheap
    pub fn with_http_client(urls: Vec<Url>, cooldown: Duration, client: reqwest::Client) -> Self {
        let providers: Vec<ProviderEntry> = urls
            .into_iter()
            .map(|url| ProviderEntry {
                provider: ProviderBuilder::new()
                    .connect_reqwest(client.clone(), url.clone())
                    .erased(),
                url,
            })
            .collect();
        Self {
            admissions: Mutex::new(Admissions::admitted(providers.len())),
            providers,
            cooldown,
            cooldowns: Mutex::new(HashMap::new()),
            http_client: Some(client),
            log_spans: Mutex::new(HashMap::new()),
        }
    }

    /// Starts every regular endpoint as [`RpcAdmission::Pending`], so none is
    /// returned until [`Self::set_provider_admission`] admits it.
    #[must_use]
    pub fn with_pending_admission(mut self) -> Self {
        let admissions = self
            .admissions
            .get_mut()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        admissions.providers.fill(RpcAdmission::Pending);
        self
    }

    /// Starts the archive endpoint as [`RpcAdmission::Pending`], so
    /// [`Self::archive_admitted`] is false until it is admitted.
    #[must_use]
    pub fn with_pending_archive(mut self) -> Self {
        self.admissions
            .get_mut()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .archive = RpcAdmission::Pending;
        self
    }

    /// Sets the admission of the endpoint at `index`. Out-of-range indices
    /// are ignored.
    pub fn set_provider_admission(&self, index: usize, admission: RpcAdmission) {
        let mut admissions = self
            .admissions
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if let Some(slot) = admissions.providers.get_mut(index) {
            *slot = admission;
        }
    }

    pub fn set_archive_admission(&self, admission: RpcAdmission) {
        self.admissions
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .archive = admission;
    }

    #[must_use]
    pub fn provider_admission(&self, index: usize) -> Option<RpcAdmission> {
        self.admissions
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .providers
            .get(index)
            .copied()
    }

    #[must_use]
    pub fn archive_admitted(&self) -> bool {
        self.admissions
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .archive
            == RpcAdmission::Admitted
    }

    #[must_use]
    pub fn random_provider(&self) -> Option<ProviderHandle> {
        if self.providers.is_empty() {
            return None;
        }

        let admitted = self.admitted_indices();
        let now = Instant::now();
        let mut cooldowns = self
            .cooldowns
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        cooldowns.retain(|_, until| *until > now);

        let available: Vec<usize> = admitted
            .into_iter()
            .filter(|index| !cooldowns.contains_key(index))
            .collect();
        let index = *available.choose(&mut rand::rng())?;
        Some(self.handle(index))
    }

    /// Number of configured endpoints, regardless of admission or cooldown.
    #[must_use]
    pub const fn len(&self) -> usize {
        self.providers.len()
    }

    /// Whether no endpoints are configured, regardless of admission or
    /// cooldown.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.providers.is_empty()
    }

    #[must_use]
    pub const fn http_client(&self) -> Option<&reqwest::Client> {
        self.http_client.as_ref()
    }

    #[must_use]
    pub fn available_providers(&self) -> Vec<ProviderHandle> {
        if self.providers.is_empty() {
            return Vec::new();
        }

        let admitted = self.admitted_indices();
        let now = Instant::now();
        let mut cooldowns = self
            .cooldowns
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        cooldowns.retain(|_, until| *until > now);

        admitted
            .into_iter()
            .filter(|index| !cooldowns.contains_key(index))
            .map(|index| self.handle(index))
            .collect()
    }

    pub fn mark_bad_provider(&self, handle: &ProviderHandle) {
        let until = Instant::now() + self.cooldown;
        let mut cooldowns = self
            .cooldowns
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        cooldowns.insert(handle.index, until);
    }

    /// Returns the `eth_getLogs` block span to request from `endpoint`: the
    /// narrowest span learned this session, capped at `max_span`, and never 0.
    #[must_use]
    pub fn log_span(&self, endpoint: LogSpanEndpoint, max_span: u64) -> u64 {
        let max_span = max_span.max(1);
        let log_spans = self
            .log_spans
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        log_spans
            .get(&endpoint)
            .map_or(max_span, |learned| (*learned).min(max_span))
    }

    /// Records that `endpoint` needs spans of at most `span` blocks. The
    /// learned span only ever decreases and never drops below one block.
    pub fn narrow_log_span(&self, endpoint: LogSpanEndpoint, span: u64) {
        let span = span.max(1);
        let mut log_spans = self
            .log_spans
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        log_spans
            .entry(endpoint)
            .and_modify(|learned| *learned = (*learned).min(span))
            .or_insert(span);
    }

    /// Snapshot of admitted indices, taken without holding the cooldown lock.
    fn admitted_indices(&self) -> Vec<usize> {
        self.admissions
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .providers
            .iter()
            .enumerate()
            .filter(|(_, admission)| **admission == RpcAdmission::Admitted)
            .map(|(index, _)| index)
            .collect()
    }

    fn handle(&self, index: usize) -> ProviderHandle {
        let entry = &self.providers[index];
        ProviderHandle {
            index,
            url: entry.url.clone(),
            provider: entry.provider.clone(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_pool() -> QueryRpcPool {
        QueryRpcPool::new(
            vec![Url::parse("http://127.0.0.1:1").expect("rpc url")],
            Duration::from_secs(1),
        )
    }

    #[test]
    fn learned_log_spans_only_narrow_within_max_and_reset_with_pool() {
        let pool = test_pool();
        let provider = LogSpanEndpoint::Provider(0);

        assert_eq!(pool.log_span(provider, 500), 500);
        pool.narrow_log_span(provider, 50);
        assert_eq!(pool.log_span(provider, 500), 50);
        pool.narrow_log_span(provider, 200);
        assert_eq!(pool.log_span(provider, 500), 50, "spans never widen");
        assert_eq!(pool.log_span(provider, 20), 20, "spans never exceed max");
        pool.narrow_log_span(provider, 0);
        assert_eq!(pool.log_span(provider, 500), 1, "spans never reach 0");
        assert_eq!(
            pool.log_span(LogSpanEndpoint::Archive, 500),
            500,
            "endpoints learn independently"
        );

        assert_eq!(
            test_pool().log_span(provider, 500),
            500,
            "a new pool starts at max"
        );
    }

    #[test]
    fn only_admitted_endpoints_are_returned_and_admission_keeps_indices_and_spans() {
        let urls: Vec<Url> = (1..=3)
            .map(|port| Url::parse(&format!("http://127.0.0.1:{port}")).expect("rpc url"))
            .collect();
        let pool = QueryRpcPool::new(urls.clone(), Duration::from_secs(1)).with_pending_admission();

        assert!(pool.available_providers().is_empty());
        assert!(pool.random_provider().is_none());
        assert_eq!(pool.len(), 3, "len counts configured endpoints");

        pool.narrow_log_span(LogSpanEndpoint::Provider(2), 40);
        pool.set_provider_admission(0, RpcAdmission::Excluded);
        pool.set_provider_admission(2, RpcAdmission::Admitted);
        pool.set_provider_admission(99, RpcAdmission::Admitted);

        let available = pool.available_providers();
        assert_eq!(available.len(), 1);
        assert_eq!(available[0].index, 2);
        assert_eq!(available[0].url, urls[2]);
        for _ in 0..16 {
            let handle = pool.random_provider().expect("admitted provider");
            assert_eq!(handle.index, 2);
            assert_eq!(handle.url, urls[2]);
        }
        assert_eq!(
            pool.log_span(LogSpanEndpoint::Provider(2), 500),
            40,
            "admission keeps learned spans"
        );

        assert!(test_pool().archive_admitted());
        let pool = test_pool().with_pending_archive();
        assert!(!pool.archive_admitted());
        pool.set_archive_admission(RpcAdmission::Admitted);
        assert!(pool.archive_admitted());
    }
}
