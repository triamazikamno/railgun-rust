//! Hedged artifact fetches, for indexed-artifact chunks and POI checkpoint
//! catalogs.

use std::collections::HashSet;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Instant;

use cid::Cid;
use futures::{StreamExt, stream::FuturesUnordered};
use tracing::debug;

use super::{TrustlessArtifactFetchResult, TrustlessArtifactFetcher, parse_cid};
use crate::car::RetrievalLimits;
use crate::error::{TrustlessArtifactError, TrustlessHttpSource};
use crate::http::car_gateway_url;
use crate::pool::{GatewayAttempt, GatewayCapability};
use crate::{CATALOG_HEDGE_DELAY, CHUNK_HEDGE_DELAY};

impl TrustlessArtifactFetcher<'_> {
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
        ChunkRace::new(self, cid, limits, admit_hedge)
            .run(preferred_gateway_index)
            .await
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
        CatalogRace::new(self, cid, limits, max_attempts)
            .run(preferred_gateway_index)
            .await
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
}

/// One indexed-artifact chunk fetch. Attempts fall back sequentially, and one
/// hedge may start when the sole running attempt stalls before response
/// headers.
struct ChunkRace<'f, 'a, F> {
    fetcher: &'f TrustlessArtifactFetcher<'a>,
    cid: Cid,
    limits: RetrievalLimits,
    gateway_count: usize,
    started: tokio::time::Instant,
    admit_hedge: Option<F>,
    reserved_identities: HashSet<u64>,
    // Hedge deadline, gateway index and headers flag of the sole running
    // attempt, armed while the hedge is unused.
    hedge_watch: Option<(tokio::time::Instant, usize, Arc<AtomicBool>)>,
    hedged_gateways: Option<(usize, usize)>,
    last_error: Option<TrustlessArtifactError>,
}

impl<'f, 'a, F, G> ChunkRace<'f, 'a, F>
where
    F: FnOnce() -> Option<G>,
{
    fn new(
        fetcher: &'f TrustlessArtifactFetcher<'a>,
        cid: Cid,
        limits: RetrievalLimits,
        admit_hedge: F,
    ) -> Self {
        let gateway_count = fetcher.gateways.len();
        Self {
            fetcher,
            cid,
            limits,
            gateway_count,
            started: tokio::time::Instant::now(),
            admit_hedge: Some(admit_hedge),
            reserved_identities: HashSet::with_capacity(gateway_count),
            hedge_watch: None,
            hedged_gateways: None,
            last_error: None,
        }
    }

    async fn run(
        mut self,
        preferred_gateway_index: usize,
    ) -> Result<TrustlessArtifactFetchResult, TrustlessArtifactError> {
        let mut attempts = FuturesUnordered::new();
        loop {
            if attempts.is_empty() {
                let Some((gateway_attempt, headers_received)) =
                    self.next_gateway(preferred_gateway_index)
                else {
                    break;
                };
                attempts.push(self.fetcher.chunk_attempt(
                    self.cid,
                    self.limits,
                    gateway_attempt,
                    headers_received,
                    None::<G>,
                ));
            }

            let hedge_at = self.hedge_watch.as_ref().map(|(hedge_at, _, _)| *hedge_at);
            tokio::select! {
                biased;
                result = attempts.next() => {
                    let Some((gateway_index, result)) = result else { continue };
                    match result {
                        Ok(bytes) => return Ok(self.finish(gateway_index, bytes)),
                        // Any other running attempt continues; once none is
                        // left, the loop falls back to the next gateway.
                        Err(error) => self.last_error = Some(error),
                    }
                }
                () = tokio::time::sleep_until(hedge_at.unwrap_or(self.started)), if hedge_at.is_some() => {
                    let Some((gateway_attempt, hedge_guard)) = self.hedge() else { continue };
                    attempts.push(self.fetcher.chunk_attempt(
                        self.cid,
                        self.limits,
                        gateway_attempt,
                        Arc::new(AtomicBool::new(false)),
                        Some(hedge_guard),
                    ));
                }
            }
        }

        Err(self
            .last_error
            .unwrap_or(TrustlessArtifactError::NoGateways))
    }

    /// Reserves the next fallback gateway, `preferred_gateway_index` for the
    /// first attempt, and arms the hedge watch while the hedge is unused.
    fn next_gateway(
        &mut self,
        preferred_gateway_index: usize,
    ) -> Option<(GatewayAttempt, Arc<AtomicBool>)> {
        let gateway_attempt = self.fetcher.pool.select_excluding(
            &self.fetcher.gateway_ids,
            GatewayCapability::ArtifactCar,
            self.reserved_identities
                .is_empty()
                .then_some(preferred_gateway_index),
            &self.reserved_identities,
        )?;
        self.reserved_identities.insert(gateway_attempt.identity);
        let headers_received = Arc::new(AtomicBool::new(false));
        if self.admit_hedge.is_some() {
            self.hedge_watch = Some((
                tokio::time::Instant::now() + CHUNK_HEDGE_DELAY,
                gateway_attempt.index,
                Arc::clone(&headers_received),
            ));
        }
        Some((gateway_attempt, headers_received))
    }

    /// Reserves and admits the hedge gateway once the hedge deadline passes.
    /// Returns `None` when the running attempt has received headers, no
    /// gateway is eligible, or `admit_hedge` vetoes the hedge.
    fn hedge(&mut self) -> Option<(GatewayAttempt, G)> {
        let (_, first_gateway_index, headers_received) = self.hedge_watch.take()?;
        // An attempt that has received headers is progressing and is
        // never duplicated.
        if headers_received.load(Ordering::Relaxed) {
            return None;
        }
        let gateway_attempt = self.fetcher.pool.select_excluding(
            &self.fetcher.gateway_ids,
            GatewayCapability::ArtifactCar,
            None,
            &self.reserved_identities,
        )?;
        // A vetoed hedge drops its reservation without a recorded failure.
        let hedge_guard = self
            .admit_hedge
            .take()
            .and_then(|admit_hedge| admit_hedge())?;
        self.reserved_identities.insert(gateway_attempt.identity);
        let hedge_gateway_index = gateway_attempt.index;
        debug!(
            cid = %self.cid,
            first_gateway_index,
            hedge_gateway_index,
            gateway_count = self.gateway_count,
            elapsed_ms = self.started.elapsed().as_millis(),
            "artifact chunk hedge started"
        );
        self.hedged_gateways = Some((first_gateway_index, hedge_gateway_index));
        Some((gateway_attempt, hedge_guard))
    }

    fn finish(&self, gateway_index: usize, bytes: Vec<u8>) -> TrustlessArtifactFetchResult {
        if let Some((first_gateway_index, hedge_gateway_index)) = self.hedged_gateways {
            debug!(
                cid = %self.cid,
                first_gateway_index,
                hedge_gateway_index,
                winner_gateway_index = gateway_index,
                gateway_count = self.gateway_count,
                elapsed_ms = self.started.elapsed().as_millis(),
                "hedged artifact chunk fetch completed"
            );
        }
        TrustlessArtifactFetchResult {
            verified_cid: self.cid.to_string(),
            bytes,
            gateway_index,
            gateway_count: self.gateway_count,
        }
    }
}

/// One POI checkpoint catalog fetch. Another attempt starts every
/// `CATALOG_HEDGE_DELAY` while no running attempt has received response
/// headers, and at once when every running attempt has failed, up to
/// `max_attempts`.
struct CatalogRace<'f, 'a> {
    fetcher: &'f TrustlessArtifactFetcher<'a>,
    cid: Cid,
    limits: RetrievalLimits,
    gateway_count: usize,
    max_attempts: usize,
    started: tokio::time::Instant,
    reserved_identities: HashSet<u64>,
    // Gateway index and headers flag of each running attempt.
    running: Vec<(usize, Arc<AtomicBool>)>,
    started_gateways: Vec<usize>,
    hedge_at: Option<tokio::time::Instant>,
    hedge_due: bool,
    hedged: bool,
    last_error: Option<TrustlessArtifactError>,
}

impl<'f, 'a> CatalogRace<'f, 'a> {
    fn new(
        fetcher: &'f TrustlessArtifactFetcher<'a>,
        cid: Cid,
        limits: RetrievalLimits,
        max_attempts: usize,
    ) -> Self {
        Self {
            fetcher,
            cid,
            limits,
            gateway_count: fetcher.gateways.len(),
            max_attempts,
            started: tokio::time::Instant::now(),
            reserved_identities: HashSet::with_capacity(max_attempts),
            running: Vec::with_capacity(max_attempts),
            started_gateways: Vec::with_capacity(max_attempts),
            hedge_at: None,
            hedge_due: false,
            hedged: false,
            last_error: None,
        }
    }

    async fn run(
        mut self,
        preferred_gateway_index: Option<usize>,
    ) -> Result<TrustlessArtifactFetchResult, TrustlessArtifactError> {
        let mut attempts = FuturesUnordered::new();
        loop {
            if self.should_start(attempts.is_empty())
                && let Some((gateway_attempt, headers_received)) =
                    self.start_gateway(preferred_gateway_index)
            {
                attempts.push(self.fetcher.chunk_attempt(
                    self.cid,
                    self.limits,
                    gateway_attempt,
                    headers_received,
                    None::<()>,
                ));
                self.hedge_at = (self.started_gateways.len() < self.max_attempts)
                    .then(|| tokio::time::Instant::now() + CATALOG_HEDGE_DELAY);
            }
            self.hedge_due = false;
            if attempts.is_empty() {
                break;
            }

            tokio::select! {
                biased;
                result = attempts.next() => {
                    let Some((gateway_index, result)) = result else { continue };
                    match result {
                        Ok(bytes) => return Ok(self.finish(gateway_index, bytes)),
                        // Other running attempts continue; once none is left,
                        // the loop starts the next gateway immediately.
                        Err(error) => self.record_failure(gateway_index, error),
                    }
                }
                () = tokio::time::sleep_until(self.hedge_at.unwrap_or(self.started)), if self.hedge_at.is_some() => {
                    self.hedge_timer_fired();
                }
            }
        }

        Err(self
            .last_error
            .unwrap_or(TrustlessArtifactError::NoGateways))
    }

    /// Whether another attempt should start: a hedge is due or no attempt is
    /// running, and the attempt cap is not reached.
    const fn should_start(&self, attempts_empty: bool) -> bool {
        (self.hedge_due || attempts_empty) && self.started_gateways.len() < self.max_attempts
    }

    /// Reserves the next gateway, `preferred_gateway_index` for the first
    /// attempt, and records it as started and running.
    fn start_gateway(
        &mut self,
        preferred_gateway_index: Option<usize>,
    ) -> Option<(GatewayAttempt, Arc<AtomicBool>)> {
        let gateway_attempt = self.fetcher.pool.select_excluding(
            &self.fetcher.gateway_ids,
            GatewayCapability::ArtifactCar,
            if self.started_gateways.is_empty() {
                preferred_gateway_index
            } else {
                None
            },
            &self.reserved_identities,
        )?;
        self.reserved_identities.insert(gateway_attempt.identity);
        let gateway_index = gateway_attempt.index;
        if self.hedge_due {
            self.hedged = true;
            debug!(
                cid = %self.cid,
                hedge_gateway_index = gateway_index,
                attempt = self.started_gateways.len(),
                gateway_count = self.gateway_count,
                elapsed_ms = self.started.elapsed().as_millis(),
                "artifact catalog hedge started"
            );
        }
        self.started_gateways.push(gateway_index);
        let headers_received = Arc::new(AtomicBool::new(false));
        self.running
            .push((gateway_index, Arc::clone(&headers_received)));
        Some((gateway_attempt, headers_received))
    }

    fn record_failure(&mut self, gateway_index: usize, error: TrustlessArtifactError) {
        self.running.retain(|(index, _)| *index != gateway_index);
        self.last_error = Some(error);
    }

    fn hedge_timer_fired(&mut self) {
        // An attempt that has received headers is progressing and is
        // never duplicated; the timer re-arms while below the cap.
        if self
            .running
            .iter()
            .any(|(_, headers_received)| headers_received.load(Ordering::Relaxed))
        {
            self.hedge_at = Some(tokio::time::Instant::now() + CATALOG_HEDGE_DELAY);
        } else {
            self.hedge_at = None;
            self.hedge_due = true;
        }
    }

    fn finish(&self, gateway_index: usize, bytes: Vec<u8>) -> TrustlessArtifactFetchResult {
        if self.hedged {
            debug!(
                cid = %self.cid,
                started_gateways = ?self.started_gateways,
                winner_gateway_index = gateway_index,
                gateway_count = self.gateway_count,
                elapsed_ms = self.started.elapsed().as_millis(),
                "hedged artifact catalog fetch completed"
            );
        }
        TrustlessArtifactFetchResult {
            verified_cid: self.cid.to_string(),
            bytes,
            gateway_index,
            gateway_count: self.gateway_count,
        }
    }
}
