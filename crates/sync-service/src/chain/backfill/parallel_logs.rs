//! Paged log acquisition across several providers at once.

#[allow(clippy::wildcard_imports)]
use super::*;
use crate::chain::QueryRpcPool;

impl ChainConfig {
    /// Fetches `from_block..=to_block` as consecutive pages of `block_range`
    /// blocks from up to `parallelism` providers at a time, passing each page
    /// to `deliver` in block order.
    ///
    /// Each available provider is tried at most once. It reads its head first
    /// and fetches pages only when the head, less the finality depth, covers
    /// `to_block`, one page at a time. A provider whose head lags, whose head
    /// read fails, or that fails a page stops, and the next untried available
    /// provider takes its place. A failed page goes back to the queue and the
    /// endpoint failure rules apply to its provider. At most `2 * parallelism`
    /// pages are fetched ahead of the next page to deliver.
    ///
    /// Physical requests are reserved on the caller's `budget`, and the
    /// returned `get_logs_requests` is its issued count afterwards. The
    /// acquisition fails with `NoHealthyRpc` once pages remain but no provider
    /// is running and none is left to try, once `budget` is exhausted, or when
    /// `cancel` fires. The range must lie above `archive_until_block`.
    pub(in crate::chain) async fn fetch_logs_in_parallel(
        &self,
        from_block: u64,
        to_block: u64,
        parallelism: usize,
        budget: &LogRequestBudget,
        cancel: &CancellationToken,
        mut deliver: impl FnMut(LogPage) -> Result<(), ChainError>,
    ) -> (Result<(), ChainError>, ParallelLogStats) {
        let started = Instant::now();
        let mut stats = ParallelLogStats::default();
        let request = ParallelLogRequest {
            from_block,
            to_block,
            parallelism,
            budget,
            cancel,
        };
        let result = self
            .run_parallel_log_fetch(request, &mut deliver, &mut stats)
            .await;
        stats.get_logs_requests = budget.issued();
        stats.elapsed = started.elapsed();
        let outcome = match &result {
            Ok(()) => "complete",
            Err(ChainError::LogFetchCancelled) => "cancelled",
            Err(ChainError::LogRequestBudgetExceeded(_)) => "over_budget",
            Err(ChainError::NoHealthyRpc) => "no_provider",
            Err(_) => "failed",
        };
        // Per provider index: fetched pages / physical requests.
        let providers = stats
            .providers
            .iter()
            .map(|provider| {
                format!(
                    "{}:{}/{}",
                    provider.rpc_index, provider.pages, provider.get_logs_requests
                )
            })
            .collect::<Vec<_>>()
            .join(",");
        debug!(target: LOG_TARGET,
            from_block,
            to_block,
            pages = stats.pages,
            delivered_pages = stats.delivered_pages,
            eligible_providers = stats.eligible_providers,
            get_logs_requests = stats.get_logs_requests,
            request_budget = budget.limit(),
            retries = stats.retries,
            providers = %providers,
            outcome,
            elapsed_ms = stats.elapsed.as_millis(),
            "parallel log range fetch finished"
        );
        (result, stats)
    }

    async fn run_parallel_log_fetch<F>(
        &self,
        request: ParallelLogRequest<'_>,
        deliver: &mut F,
        stats: &mut ParallelLogStats,
    ) -> Result<(), ChainError>
    where
        F: FnMut(LogPage) -> Result<(), ChainError>,
    {
        let ParallelLogRequest {
            from_block,
            to_block,
            parallelism,
            budget,
            cancel,
        } = request;
        let archive_until_block = self.sync.archive_until_block;
        if archive_until_block > 0 && from_block <= archive_until_block {
            return Err(ChainError::ArchiveRpcRequired(archive_until_block));
        }
        if from_block > to_block {
            return Ok(());
        }
        let parallelism = parallelism.max(1);
        let layout = LogPageLayout::new(from_block, to_block, self.sync.block_range, parallelism);
        stats.pages = layout.pages;
        let mut schedule = LogPagerSchedule::new(layout);
        let mut tasks = FuturesUnordered::new();

        loop {
            schedule.deliver_completed(stats, deliver)?;
            if stats.delivered_pages == stats.pages {
                return Ok(());
            }
            if cancel.is_cancelled() {
                return Err(ChainError::LogFetchCancelled);
            }
            // Fill free slots, including those of stopped providers, with
            // untried providers.
            while tasks.len() + schedule.idle.len() < parallelism {
                let Some(rpc) = schedule.claim_untried_provider(&self.rpcs, stats) else {
                    break;
                };
                tasks.push(self.run_log_pager_task(rpc, LogPagerTask::Head, budget, cancel));
            }
            while let Some((rpc, task)) = schedule.assign_idle_provider(stats.delivered_pages) {
                tasks.push(self.run_log_pager_task(rpc, task, budget, cancel));
            }

            let Some(finished) = tasks.next().await else {
                return Err(ChainError::NoHealthyRpc);
            };
            if let Some(failure) = schedule.record_outcome(finished, self.finality_depth, stats) {
                schedule.record_failure(failure, &self.rpcs, stats)?;
            }
        }
    }

    /// Runs one step of a parallel log fetch on `rpc` and hands the provider
    /// back with the outcome.
    async fn run_log_pager_task(
        &self,
        rpc: ProviderHandle,
        task: LogPagerTask,
        budget: &LogRequestBudget,
        cancel: &CancellationToken,
    ) -> (ProviderHandle, LogPagerOutcome) {
        let outcome = match task {
            LogPagerTask::Head => LogPagerOutcome::Head(tokio::select! {
                biased;
                () = cancel.cancelled() => Err(ChainError::LogFetchCancelled),
                head = rpc.provider.get_block_number() => head.map_err(ChainError::from),
            }),
            LogPagerTask::Page {
                page,
                from_block,
                to_block,
            } => {
                let mut fetch = LogRangeFetch {
                    spans: self.rpcs.as_ref(),
                    max_span: self.sync.block_range,
                    cancel,
                    logical_from: from_block,
                    logical_to: to_block,
                    get_logs_requests: 0,
                    budget: Some(budget),
                };
                let result = self
                    .fetch_logs_for_logical_range(&mut fetch, &rpc, None)
                    .await;
                LogPagerOutcome::Page {
                    page,
                    get_logs_requests: fetch.get_logs_requests,
                    result,
                }
            }
        };
        (rpc, outcome)
    }
}

/// One step a provider takes in a parallel log fetch.
#[derive(Clone, Copy)]
enum LogPagerTask {
    /// Read the head once, before any page.
    Head,
    Page {
        page: u64,
        from_block: u64,
        to_block: u64,
    },
}

enum LogPagerOutcome {
    Head(Result<u64, ChainError>),
    Page {
        page: u64,
        get_logs_requests: u64,
        result: Result<Vec<Log>, ChainError>,
    },
}

/// The range, concurrency, request budget and cancellation of one parallel log fetch.
struct ParallelLogRequest<'a> {
    from_block: u64,
    to_block: u64,
    parallelism: usize,
    budget: &'a LogRequestBudget,
    cancel: &'a CancellationToken,
}

/// One parallel log fetch's pages: consecutive `page_span` block pages of the range.
#[derive(Clone, Copy)]
struct LogPageLayout {
    from_block: u64,
    to_block: u64,
    page_span: u64,
    pages: u64,
    /// How many pages may be fetched ahead of the next page to deliver.
    window: u64,
}

impl LogPageLayout {
    /// `parallelism` is already at least one; the window is twice it.
    fn new(from_block: u64, to_block: u64, block_range: u64, parallelism: usize) -> Self {
        let page_span = block_range.max(1);
        Self {
            from_block,
            to_block,
            page_span,
            pages: (to_block - from_block) / page_span + 1,
            window: u64::try_from(parallelism)
                .unwrap_or(u64::MAX)
                .saturating_mul(2),
        }
    }

    /// The first and last block of `page`.
    fn bounds(self, page: u64) -> (u64, u64) {
        let start = self.from_block + page * self.page_span;
        (
            start,
            start.saturating_add(self.page_span - 1).min(self.to_block),
        )
    }
}

/// A provider that failed a head read or a page, with the page to fetch again.
struct LogPagerFailure {
    rpc: ProviderHandle,
    err: ChainError,
    page: Option<u64>,
}

/// The providers and pages of one parallel log fetch: which providers were given a slot,
/// which wait idle for a page, and which pages failed or wait for delivery.
struct LogPagerSchedule {
    layout: LogPageLayout,
    /// Provider indexes that were given a slot; none is tried twice.
    tried: BTreeSet<usize>,
    idle: Vec<ProviderHandle>,
    failed_pages: BTreeSet<u64>,
    next_page: u64,
    completed: BTreeMap<u64, Vec<Log>>,
}

impl LogPagerSchedule {
    const fn new(layout: LogPageLayout) -> Self {
        Self {
            layout,
            tried: BTreeSet::new(),
            idle: Vec::new(),
            failed_pages: BTreeSet::new(),
            next_page: 0,
            completed: BTreeMap::new(),
        }
    }

    /// Delivers buffered pages in block order. A page counts as delivered only once
    /// `deliver` accepts it; its error ends the fetch.
    fn deliver_completed<F>(
        &mut self,
        stats: &mut ParallelLogStats,
        deliver: &mut F,
    ) -> Result<(), ChainError>
    where
        F: FnMut(LogPage) -> Result<(), ChainError>,
    {
        while let Some(logs) = self.completed.remove(&stats.delivered_pages) {
            let (_, to_block) = self.layout.bounds(stats.delivered_pages);
            deliver(LogPage { to_block, logs })?;
            stats.delivered_pages += 1;
        }
        Ok(())
    }

    /// Gives a slot to the first available provider not tried yet.
    fn claim_untried_provider(
        &mut self,
        rpcs: &QueryRpcPool,
        stats: &mut ParallelLogStats,
    ) -> Option<ProviderHandle> {
        let rpc = rpcs
            .available_providers()
            .into_iter()
            .find(|rpc| !self.tried.contains(&rpc.index))?;
        self.tried.insert(rpc.index);
        stats.providers.push(ProviderLogStats {
            rpc_index: rpc.index,
            pages: 0,
            get_logs_requests: 0,
        });
        Some(rpc)
    }

    /// The last idle provider and its next page: the lowest failed page, else the next page
    /// within the window ahead of delivery. With neither, the provider stays idle.
    fn assign_idle_provider(
        &mut self,
        delivered_pages: u64,
    ) -> Option<(ProviderHandle, LogPagerTask)> {
        let rpc = self.idle.pop()?;
        let page = if let Some(page) = self.failed_pages.pop_first() {
            page
        } else if self.next_page < self.layout.pages
            && self.next_page < delivered_pages.saturating_add(self.layout.window)
        {
            self.next_page += 1;
            self.next_page - 1
        } else {
            self.idle.push(rpc);
            return None;
        };
        let (from_block, to_block) = self.layout.bounds(page);
        let task = LogPagerTask::Page {
            page,
            from_block,
            to_block,
        };
        Some((rpc, task))
    }

    /// Records a finished pager step. A head that covers the range makes its provider idle,
    /// and a lagging head drops it; a fetched page waits for delivery. Returns the failure of
    /// a head read or a page, after the page's requests are counted.
    fn record_outcome(
        &mut self,
        (rpc, outcome): (ProviderHandle, LogPagerOutcome),
        finality_depth: u64,
        stats: &mut ParallelLogStats,
    ) -> Option<LogPagerFailure> {
        match outcome {
            LogPagerOutcome::Head(Ok(head)) => {
                if head.saturating_sub(finality_depth) >= self.layout.to_block {
                    stats.eligible_providers += 1;
                    self.idle.push(rpc);
                } else {
                    debug!(target: LOG_TARGET,
                        rpc_index = rpc.index,
                        head,
                        to_block = self.layout.to_block,
                        "log provider head does not cover the parallel fetch range"
                    );
                }
                None
            }
            LogPagerOutcome::Head(Err(err)) => Some(LogPagerFailure {
                rpc,
                err,
                page: None,
            }),
            LogPagerOutcome::Page {
                page,
                get_logs_requests,
                result,
            } => {
                let provider = stats
                    .providers
                    .iter_mut()
                    .find(|provider| provider.rpc_index == rpc.index);
                if let Some(provider) = provider {
                    provider.get_logs_requests += get_logs_requests;
                    provider.pages += u64::from(result.is_ok());
                }
                match result {
                    Ok(logs) => {
                        self.completed.insert(page, logs);
                        self.idle.push(rpc);
                        None
                    }
                    Err(err) => Some(LogPagerFailure {
                        rpc,
                        err,
                        page: Some(page),
                    }),
                }
            }
        }
    }

    /// Cancellation and an exhausted budget end the fetch. Any other failure drops the
    /// provider for this fetch, cools it down when the error warrants it, and queues its page
    /// for another provider.
    fn record_failure(
        &mut self,
        failure: LogPagerFailure,
        rpcs: &QueryRpcPool,
        stats: &mut ParallelLogStats,
    ) -> Result<(), ChainError> {
        let LogPagerFailure {
            rpc,
            err,
            page: failed_page,
        } = failure;
        if matches!(
            err,
            ChainError::LogFetchCancelled | ChainError::LogRequestBudgetExceeded(_)
        ) {
            return Err(err);
        }
        let marked_bad = err.should_mark_rpc_unhealthy();
        if marked_bad {
            rpcs.mark_bad_provider(&rpc);
        }
        if let Some(page) = failed_page {
            self.failed_pages.insert(page);
            stats.retries += 1;
        }
        debug!(target: LOG_TARGET,
            rpc_index = rpc.index,
            page = ?failed_page,
            marked_bad,
            err = %err.without_url(),
            "parallel log fetch provider failed; its page returns to the queue"
        );
        Ok(())
    }
}
