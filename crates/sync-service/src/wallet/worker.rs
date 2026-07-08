use super::*;

async fn publish_poi_refreshing(
    sender: &watch::Sender<bool>,
    value: bool,
    worker_handle: &WalletHandle,
    reset_generation: u64,
    cancel: &CancellationToken,
) {
    let authority = WalletPrivateMutationAuthority::new(worker_handle, reset_generation, cancel);
    match authority.acquire().await {
        Ok(permit) => {
            if let Err(reason) = permit.publish_poi_refreshing(sender, value) {
                debug!(?reason, cache_key = %worker_handle.cache_key, "wallet POI refresh state publication rejected");
            }
        }
        Err(reason) => {
            debug!(?reason, cache_key = %worker_handle.cache_key, "wallet POI refresh state publication skipped");
        }
    }
}

struct WalletScanCommitRequest<'a> {
    db: &'a DbStore,
    cache_store: &'a dyn WalletCacheStore,
    cfg: &'a WalletConfig,
    utxos: &'a Arc<RwLock<Vec<WalletUtxo>>>,
    worker_handle: &'a WalletHandle,
    apply: WalletScanApply,
    current_reset_generation: u64,
    event_reset_generation: u64,
    actor_state: &'a mut WalletActorState,
    cancel: &'a CancellationToken,
    last_scanned: &'a mut u64,
    persist_state: &'a mut WalletPersistState,
    live_metadata_flush: &'a mut WalletLiveMetadataFlush,
    ready_tx: &'a watch::Sender<bool>,
    readiness_tx: &'a watch::Sender<WalletReadiness>,
    poi_submitter: Option<&'a dyn PendingOutputPoiSubmitter>,
    poi_status_reader: Option<&'a dyn PoiStatusReader>,
    active_poi_list_keys: &'a [FixedBytes<32>],
    refresh_poi_statuses: bool,
    mark_syncing_on_commit: bool,
    public_data_plane: &'a ChainPublicDataPlane,
}

struct WalletScanCommitOutcome {
    result: WalletBackfillApplyResult,
    changed: bool,
}

struct WalletPoiStatusRefreshCommitRequest<'a> {
    cache_store: &'a dyn WalletCacheStore,
    cfg: &'a WalletConfig,
    utxos: &'a Arc<RwLock<Vec<WalletUtxo>>>,
    worker_handle: &'a WalletHandle,
    last_scanned: u64,
    reset_generation: u64,
    actor_state: &'a mut WalletActorState,
    persist_state: &'a mut WalletPersistState,
    ready_tx: &'a watch::Sender<bool>,
    readiness_tx: &'a watch::Sender<WalletReadiness>,
    status_reader: &'a dyn PoiStatusReader,
    active_poi_list_keys: &'a [FixedBytes<32>],
    selection: WalletPoiRefreshSelection,
    cancel: &'a CancellationToken,
}

#[derive(Debug, Clone, Copy)]
struct PendingWalletReset {
    intent_id: u64,
    from_block: u64,
    reset_generation: u64,
    replay_plan: WalletResetReplayPlan,
}

impl PendingWalletReset {
    fn merge_replay_plan(
        existing: Option<Self>,
        incoming: WalletResetReplayPlan,
    ) -> WalletResetReplayPlan {
        existing.map_or(incoming, |pending| WalletResetReplayPlan {
            start_block: pending.replay_plan.start_block.min(incoming.start_block),
            target_block: pending.replay_plan.target_block.max(incoming.target_block),
            follow_safe_head: pending.replay_plan.follow_safe_head || incoming.follow_safe_head,
        })
    }
}

struct WalletResetCommitRequest<'a> {
    cache_store: &'a dyn WalletCacheStore,
    cfg: &'a WalletConfig,
    utxos: &'a Arc<RwLock<Vec<WalletUtxo>>>,
    worker_handle: &'a WalletHandle,
    pending: PendingWalletReset,
    highest_accepted_reset_intent: u64,
    cancel: &'a CancellationToken,
    last_scanned: &'a mut u64,
    persist_state: &'a mut WalletPersistState,
    live_metadata_flush: &'a mut WalletLiveMetadataFlush,
}

struct WalletResetCommitOutcome {
    result: WalletBackfillResetResult,
    committed: bool,
}

enum WalletBackfillDoneOutcome {
    Finished,
    Rejected(WalletBackfillRejectReason),
}

const WALLET_RESET_RETRY_INTERVAL: Duration = Duration::from_secs(1);

fn wallet_sync_actor_state_record(
    cfg: &WalletConfig,
    highest_accepted_reset_intent: u64,
    pending_reset: Option<PendingWalletReset>,
) -> WalletSyncActorStateRecord {
    WalletSyncActorStateRecord {
        chain_id: cfg.chain.chain_id,
        wallet_id: cfg.cache_key.clone(),
        highest_accepted_reset_intent,
        pending_reset: pending_reset.map(|pending| WalletPendingResetRecord {
            intent_id: pending.intent_id,
            from_block: pending.from_block,
            replay_start_block: pending.replay_plan.start_block,
            replay_target_block: pending.replay_plan.target_block,
            follow_safe_head: pending.replay_plan.follow_safe_head,
        }),
        updated_at: now_epoch_secs(),
    }
}

fn reset_replay_from_block(last_scanned: u64, start_block: u64) -> u64 {
    last_scanned.saturating_add(1).max(start_block)
}

fn enqueue_reset_replay_after_commit(
    cfg: &WalletConfig,
    worker_handle: &WalletHandle,
    actor_state: &mut WalletActorState,
    pending: PendingWalletReset,
    last_scanned: u64,
    backfill_tx: &mpsc::Sender<BackfillRequest>,
    backfill_sender: &mpsc::Sender<BackfillEvent>,
) {
    let replay_from = reset_replay_from_block(last_scanned, pending.replay_plan.start_block);
    let token = worker_handle.mint_sync_token(actor_state.reset_generation);
    if !actor_state.accept_target(token, pending.replay_plan.target_block) {
        actor_state.fail_readiness(WalletReadinessError::BackfillUnavailable);
        return;
    }
    if pending.replay_plan.target_block > 0 && replay_from > pending.replay_plan.target_block {
        actor_state.retire_job(token);
        return;
    }
    let accepted_job = WalletAcceptedBackfillJob::for_actor_accepted_job(token);
    if let Err(err) = backfill_tx.try_send(BackfillRequest::add(
        cfg.cache_key.clone(),
        replay_from,
        pending.replay_plan.target_block,
        pending.replay_plan.follow_safe_head,
        replay_from,
        WalletBackfillLease::for_actor_accepted_job(accepted_job, backfill_sender.clone()),
    )) {
        warn!(?err, cache_key = %cfg.cache_key, replay_from, target_block = pending.replay_plan.target_block, "wallet reset replay enqueue failed");
        actor_state.fail_job(token, WalletReadinessError::BackfillUnavailable);
    }
}

fn persist_wallet_reset_acceptance(
    permit: &WalletPrivateMutationPermit<'_>,
    cache_store: &dyn WalletCacheStore,
    cfg: &WalletConfig,
    highest_accepted_reset_intent: u64,
    pending_reset: PendingWalletReset,
) -> Result<(), WalletCacheError> {
    let state =
        wallet_sync_actor_state_record(cfg, highest_accepted_reset_intent, Some(pending_reset));
    cache_store.put_wallet_sync_actor_state(WalletSyncActorStateCommit::new(permit, &state))
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum WalletActorJobKind {
    Backfill,
    PendingOverlay,
    IndexedCatchUp,
}

#[derive(Debug, Clone, Copy)]
struct WalletActorJob {
    reset_generation: u64,
    kind: WalletActorJobKind,
}

#[derive(Debug)]
struct WalletActorState {
    chain_id: u64,
    actor_id: u64,
    reset_generation: u64,
    last_scanned: u64,
    target_block: Option<u64>,
    readiness: WalletReadiness,
    terminal_failure: Option<WalletReadinessError>,
    shutdown: bool,
    highest_accepted_reset_intent: u64,
    pending_reset: Option<PendingWalletReset>,
    active_jobs: BTreeMap<u64, WalletActorJob>,
    highest_accepted_backfill_job_id: u64,
    latest_pending_overlay_job: Option<u64>,
    active_indexed_catch_up_job: Option<u64>,
}

impl WalletActorState {
    const fn new(
        chain_id: u64,
        actor_id: u64,
        reset_generation: u64,
        last_scanned: u64,
        highest_accepted_reset_intent: u64,
        pending_reset: Option<PendingWalletReset>,
    ) -> Self {
        Self {
            chain_id,
            actor_id,
            reset_generation,
            last_scanned,
            target_block: None,
            readiness: WalletReadiness::Syncing,
            terminal_failure: None,
            shutdown: false,
            highest_accepted_reset_intent,
            pending_reset,
            active_jobs: BTreeMap::new(),
            highest_accepted_backfill_job_id: 0,
            latest_pending_overlay_job: None,
            active_indexed_catch_up_job: None,
        }
    }

    fn update_cursor(&mut self, last_scanned: u64) {
        self.last_scanned = last_scanned;
    }

    fn validate_sync_token_current(
        &self,
        token: WalletSyncToken,
        handle: &WalletHandle,
        cancel: &CancellationToken,
    ) -> Result<(), WalletBackfillRejectReason> {
        if cancel.is_cancelled()
            || !handle.is_current_actor()
            || token.chain_id() != self.chain_id
            || token.actor_id() != self.actor_id
            || token.actor_id() != handle.actor_id
        {
            return Err(WalletBackfillRejectReason::Shutdown);
        }
        if token.reset_generation() != self.reset_generation {
            return Err(WalletBackfillRejectReason::StaleGeneration {
                expected: self.reset_generation,
                actual: token.reset_generation(),
            });
        }
        Ok(())
    }

    fn validate_active_sync_token(
        &self,
        token: WalletSyncToken,
        handle: &WalletHandle,
        kind: WalletActorJobKind,
        cancel: &CancellationToken,
    ) -> Result<(), WalletBackfillRejectReason> {
        self.validate_sync_token_current(token, handle, cancel)?;
        if !self.is_active_job(token, kind) {
            return Err(WalletBackfillRejectReason::Shutdown);
        }
        Ok(())
    }

    fn validate_reset_token_current(
        &self,
        token: WalletResetToken,
        handle: &WalletHandle,
        cancel: &CancellationToken,
    ) -> Result<(), WalletBackfillRejectReason> {
        if cancel.is_cancelled()
            || !handle.is_current_actor()
            || token.chain_id() != self.chain_id
            || token.actor_id() != self.actor_id
            || token.actor_id() != handle.actor_id
        {
            return Err(WalletBackfillRejectReason::Shutdown);
        }
        Ok(())
    }

    fn accept_job(&mut self, token: WalletSyncToken, kind: WalletActorJobKind) -> bool {
        if token.chain_id() != self.chain_id
            || token.actor_id() != self.actor_id
            || token.reset_generation() != self.reset_generation
        {
            return false;
        }
        if let Some(job) = self.active_jobs.get(&token.job_id()) {
            return job.kind == kind && job.reset_generation == token.reset_generation();
        }
        if kind == WalletActorJobKind::Backfill {
            if token.job_id() <= self.highest_accepted_backfill_job_id {
                return false;
            }
            self.highest_accepted_backfill_job_id = token.job_id();
        }
        self.active_jobs.insert(
            token.job_id(),
            WalletActorJob {
                reset_generation: token.reset_generation(),
                kind,
            },
        );
        if kind == WalletActorJobKind::PendingOverlay {
            self.latest_pending_overlay_job = Some(token.job_id());
        }
        if kind == WalletActorJobKind::IndexedCatchUp {
            self.active_indexed_catch_up_job = Some(token.job_id());
        }
        true
    }

    fn is_active_job(&self, token: WalletSyncToken, kind: WalletActorJobKind) -> bool {
        token.chain_id() == self.chain_id
            && token.actor_id() == self.actor_id
            && token.reset_generation() == self.reset_generation
            && self.active_jobs.get(&token.job_id()).is_some_and(|job| {
                job.reset_generation == token.reset_generation() && job.kind == kind
            })
    }

    fn has_active_job(&self, token: WalletSyncToken) -> bool {
        token.chain_id() == self.chain_id
            && token.actor_id() == self.actor_id
            && token.reset_generation() == self.reset_generation
            && self
                .active_jobs
                .get(&token.job_id())
                .is_some_and(|job| job.reset_generation == token.reset_generation())
    }

    fn retire_job(&mut self, token: WalletSyncToken) -> bool {
        if !self.has_active_job(token) {
            return false;
        }
        let retired = self.active_jobs.remove(&token.job_id()).is_some();
        if retired && self.active_indexed_catch_up_job == Some(token.job_id()) {
            self.active_indexed_catch_up_job = None;
        }
        retired
    }

    fn fail_job(&mut self, token: WalletSyncToken, reason: WalletReadinessError) -> bool {
        let retired = self.retire_job(token);
        if retired {
            self.terminal_failure = Some(reason);
        }
        retired
    }

    fn has_active_backfill_jobs_except(&self, token: WalletSyncToken) -> bool {
        self.active_jobs.iter().any(|(job_id, job)| {
            *job_id != token.job_id() && job.kind == WalletActorJobKind::Backfill
        })
    }

    fn readiness_blocking_target(&self, token: WalletSyncToken, last_scanned: u64) -> Option<u64> {
        let target_block = self.target_block?;
        if self.pending_reset.is_some()
            || last_scanned < target_block
            || self.has_active_backfill_jobs_except(token)
        {
            Some(target_block)
        } else {
            None
        }
    }

    fn retire_all_jobs_for_reset(&mut self) -> bool {
        let indexed_catch_up_was_active = self.active_indexed_catch_up_job.take().is_some();
        self.active_jobs.clear();
        self.latest_pending_overlay_job = None;
        self.target_block = None;
        indexed_catch_up_was_active
    }

    fn accept_indexed_catch_up(&mut self, token: WalletSyncToken) -> bool {
        if self.active_indexed_catch_up_job.is_some() {
            return false;
        }
        self.accept_job(token, WalletActorJobKind::IndexedCatchUp)
    }

    fn is_active_indexed_catch_up(&self, lease: WalletIndexedCatchUpLease) -> bool {
        self.active_indexed_catch_up_job == Some(lease.token().job_id())
            && self.is_active_job(lease.token(), WalletActorJobKind::IndexedCatchUp)
    }

    fn retire_indexed_catch_up(&mut self, lease: WalletIndexedCatchUpLease) -> bool {
        if !self.is_active_indexed_catch_up(lease) {
            return false;
        }
        self.retire_job(lease.token())
    }

    fn accept_reset(&mut self, pending: PendingWalletReset) -> bool {
        self.highest_accepted_reset_intent = pending.intent_id;
        self.pending_reset = Some(pending);
        self.reset_generation = pending.reset_generation;
        self.terminal_failure = None;
        self.retire_all_jobs_for_reset()
    }

    fn clear_pending_reset(&mut self) {
        self.pending_reset = None;
    }

    fn fail_readiness(&mut self, reason: WalletReadinessError) {
        self.terminal_failure = Some(reason);
    }

    fn clear_persistence_failure(&mut self) {
        if matches!(
            self.terminal_failure,
            Some(WalletReadinessError::PersistenceFailed)
        ) {
            self.terminal_failure = None;
        }
    }

    fn mark_shutdown(&mut self) {
        self.shutdown = true;
        self.active_jobs.clear();
        self.active_indexed_catch_up_job = None;
    }

    fn accept_target(&mut self, token: WalletSyncToken, target_block: u64) -> bool {
        if !self.accept_job(token, WalletActorJobKind::Backfill) {
            return false;
        }
        self.target_block = Some(
            self.target_block
                .map_or(target_block, |current| current.max(target_block)),
        );
        true
    }

    fn accept_pending_overlay(&mut self, token: WalletSyncToken, last_scanned: u64) -> bool {
        token.reset_generation() == self.reset_generation
            && last_scanned == self.last_scanned
            && self
                .latest_pending_overlay_job
                .is_none_or(|latest| token.job_id() > latest)
            && self.accept_job(token, WalletActorJobKind::PendingOverlay)
    }

    fn pending_overlay_is_current(&self, token: WalletSyncToken, last_scanned: u64) -> bool {
        self.has_active_job(token)
            && self.latest_pending_overlay_job == Some(token.job_id())
            && last_scanned == self.last_scanned
            && self
                .active_jobs
                .get(&token.job_id())
                .is_some_and(|job| job.kind == WalletActorJobKind::PendingOverlay)
    }

    fn derived_readiness(&self) -> WalletReadiness {
        if self.shutdown {
            return WalletReadiness::Shutdown;
        }
        if let Some(reason) = self.terminal_failure.clone() {
            return WalletReadiness::Failed(reason);
        }
        if self.pending_reset.is_some() {
            return WalletReadiness::Syncing;
        }
        if self.active_jobs.values().any(|job| {
            matches!(
                job.kind,
                WalletActorJobKind::Backfill | WalletActorJobKind::IndexedCatchUp
            )
        }) {
            return WalletReadiness::Syncing;
        }
        match self.target_block {
            Some(target_block) if target_block > 0 && self.last_scanned >= target_block => {
                WalletReadiness::Ready
            }
            _ => WalletReadiness::Syncing,
        }
    }

    fn reduce_and_publish_readiness(
        &mut self,
        permit: &WalletPrivateMutationPermit<'_>,
        ready_tx: &watch::Sender<bool>,
        readiness_tx: &watch::Sender<WalletReadiness>,
    ) -> Result<(), WalletBackfillRejectReason> {
        let readiness = self.derived_readiness();
        permit.publish_readiness(ready_tx, readiness_tx, readiness.clone())?;
        self.readiness = readiness.clone();
        Ok(())
    }
}

pub(super) enum WalletPoiStatusReaderSource<'a> {
    Local(LocalPoiStatusReader),
    Remote(&'a PoiRpcClient),
}

impl WalletPoiStatusReaderSource<'_> {
    pub(super) fn as_reader(&self) -> &dyn PoiStatusReader {
        match self {
            Self::Local(reader) => reader,
            Self::Remote(reader) => *reader,
        }
    }
}

pub(super) fn wallet_poi_status_reader_source<'a>(
    remote_client: &'a PoiRpcClient,
    cfg: &WalletConfig,
) -> WalletPoiStatusReaderSource<'a> {
    match &cfg.poi_read_source {
        PoiReadSource::IndexedArtifacts(_) => {
            let local_caches = cfg.local_poi_caches.as_ref().cloned().unwrap_or_else(|| {
                warn!(
                    cache_key = %cfg.cache_key,
                    chain_id = cfg.chain.chain_id,
                    "artifact POI read source missing local cache handle"
                );
                Arc::new(RwLock::new(BTreeMap::new()))
            });
            WalletPoiStatusReaderSource::Local(LocalPoiStatusReader::new(local_caches))
        }
        PoiReadSource::PoiProxy => WalletPoiStatusReaderSource::Remote(remote_client),
    }
}

impl WalletResetCommitRequest<'_> {
    async fn commit(self) -> WalletResetCommitOutcome {
        let request = self;
        let committed_to_before = *request.last_scanned;
        if request.cancel.is_cancelled() || !request.worker_handle.is_current_actor() {
            return WalletResetCommitOutcome {
                result: WalletBackfillResetResult::Rejected {
                    committed_to: committed_to_before,
                    reason: WalletBackfillRejectReason::Shutdown,
                },
                committed: false,
            };
        }

        let candidate_last_scanned =
            committed_to_before.min(request.pending.from_block.saturating_sub(1));
        let mut candidate = request.utxos.read().await.clone();
        let rewind = rewind_wallet_utxos(&mut candidate, request.pending.from_block);
        let authority = WalletPrivateMutationAuthority::new(
            request.worker_handle,
            request.pending.reset_generation,
            request.cancel,
        );
        let permit = match authority.acquire().await {
            Ok(permit) => permit,
            Err(reason) => {
                return WalletResetCommitOutcome {
                    result: WalletBackfillResetResult::Rejected {
                        committed_to: committed_to_before,
                        reason,
                    },
                    committed: false,
                };
            }
        };
        if request.cancel.is_cancelled() {
            return WalletResetCommitOutcome {
                result: WalletBackfillResetResult::Rejected {
                    committed_to: committed_to_before,
                    reason: WalletBackfillRejectReason::Shutdown,
                },
                committed: false,
            };
        }

        let persist_started = Instant::now();
        let sync_actor_state = wallet_sync_actor_state_record(
            request.cfg,
            request.highest_accepted_reset_intent,
            None,
        );
        if let Err(reason) = permit.revalidate() {
            return WalletResetCommitOutcome {
                result: WalletBackfillResetResult::Rejected {
                    committed_to: committed_to_before,
                    reason,
                },
                committed: false,
            };
        }
        if let Err(err) = request.cache_store.commit_wallet_private_state(
            WalletPrivateCommit::new(
                &permit,
                request.cfg.chain.chain_id,
                &candidate,
                true,
                candidate_last_scanned,
                None,
                &[],
                &rewind.removed_output_commitments,
                &[],
            )
            .with_sync_actor_state(&sync_actor_state),
        ) {
            warn!(
                ?err,
                cache_key = %request.cfg.cache_key,
                intent_id = request.pending.intent_id,
                from_block = request.pending.from_block,
                reset_generation = request.pending.reset_generation,
                "failed to persist wallet reset candidate"
            );
            return WalletResetCommitOutcome {
                result: WalletBackfillResetResult::Accepted {
                    reset_generation: request.pending.reset_generation,
                    committed_to: committed_to_before,
                    committed: false,
                },
                committed: false,
            };
        }

        {
            let mut locked = request.utxos.write().await;
            if let Err(reason) = permit.revalidate() {
                return WalletResetCommitOutcome {
                    result: WalletBackfillResetResult::Rejected {
                        committed_to: committed_to_before,
                        reason,
                    },
                    committed: false,
                };
            }
            *locked = candidate;
        }
        *request.last_scanned = candidate_last_scanned;
        if let Err(reason) = permit.set_last_scanned(candidate_last_scanned) {
            return WalletResetCommitOutcome {
                result: WalletBackfillResetResult::Rejected {
                    committed_to: candidate_last_scanned,
                    reason,
                },
                committed: false,
            };
        }
        request.persist_state.needs_full_persist = false;
        request.persist_state.pending_cache_reset = None;
        request
            .live_metadata_flush
            .mark_persisted(candidate_last_scanned, Instant::now());
        let overlay_changed = match permit
            .replace_chain_pending_overlay(WalletPendingOverlay::default())
            .await
        {
            Ok(changed) => changed,
            Err(reason) => {
                return WalletResetCommitOutcome {
                    result: WalletBackfillResetResult::Rejected {
                        committed_to: candidate_last_scanned,
                        reason,
                    },
                    committed: false,
                };
            }
        };
        if let Err(reason) = permit.notify_if_changed(rewind.changed || overlay_changed) {
            return WalletResetCommitOutcome {
                result: WalletBackfillResetResult::Rejected {
                    committed_to: candidate_last_scanned,
                    reason,
                },
                committed: false,
            };
        }
        drop(permit);

        let snapshot = request.utxos.read().await;
        let (unspent, spent) = wallet_utxo_counts(&snapshot);
        info!(
            cache_key = %request.cfg.cache_key,
            intent_id = request.pending.intent_id,
            from_block = request.pending.from_block,
            last_scanned = candidate_last_scanned,
            total = snapshot.len(),
            unspent,
            spent,
            changed = rewind.changed,
            pending_context_deletes = rewind.removed_output_commitments.len(),
            reset_generation = request.pending.reset_generation,
            persist_elapsed_ms = persist_started.elapsed().as_millis(),
            "wallet reset candidate committed"
        );

        WalletResetCommitOutcome {
            result: WalletBackfillResetResult::Accepted {
                reset_generation: request.pending.reset_generation,
                committed_to: candidate_last_scanned,
                committed: true,
            },
            committed: true,
        }
    }
}

impl WalletPoiStatusRefreshCommitRequest<'_> {
    async fn commit(self) -> Result<bool, WalletBackfillRejectReason> {
        let request = self;
        if request.cancel.is_cancelled() || !request.worker_handle.is_current_actor() {
            return Err(WalletBackfillRejectReason::Shutdown);
        }
        let started = Instant::now();
        let selection_label = request.selection.as_str();
        let mut candidate = request.utxos.read().await.clone();
        let changed = refresh_wallet_poi_statuses_selected(
            request.status_reader,
            request.cfg.chain.chain_id,
            request.active_poi_list_keys,
            &mut candidate,
            request.selection,
        )
        .await;
        if !changed {
            debug!(
                cache_key = %request.cfg.cache_key,
                selection = selection_label,
                elapsed_ms = started.elapsed().as_millis(),
                "wallet POI status refresh candidate unchanged"
            );
            return Ok(false);
        }

        let authority = WalletPrivateMutationAuthority::new(
            request.worker_handle,
            request.reset_generation,
            request.cancel,
        );
        let permit = authority.acquire().await?;
        if request.cancel.is_cancelled() {
            return Err(WalletBackfillRejectReason::Shutdown);
        }

        let persist_started = Instant::now();
        permit.revalidate()?;
        if let Err(err) = request.persist_state.persist_progress(
            request.cache_store,
            &permit,
            WalletProgressPersist {
                cache_key: &request.cfg.cache_key,
                snapshot: &candidate,
                last_scanned: request.last_scanned,
                last_scanned_block_hash: None,
                changed: true,
            },
        ) {
            warn!(?err, cache_key = %request.cfg.cache_key, selection = selection_label, "failed to persist wallet POI status refresh candidate");
            request
                .actor_state
                .fail_readiness(WalletReadinessError::PersistenceFailed);
            request.actor_state.reduce_and_publish_readiness(
                &permit,
                request.ready_tx,
                request.readiness_tx,
            )?;
            return Err(WalletBackfillRejectReason::PersistenceFailed);
        }
        request.actor_state.clear_persistence_failure();

        {
            let mut locked = request.utxos.write().await;
            permit.revalidate()?;
            *locked = candidate;
        }
        permit.notify_changed()?;
        drop(permit);
        debug!(
            cache_key = %request.cfg.cache_key,
            selection = selection_label,
            last_scanned = request.last_scanned,
            persist_elapsed_ms = persist_started.elapsed().as_millis(),
            elapsed_ms = started.elapsed().as_millis(),
            "wallet POI status refresh candidate committed"
        );
        Ok(true)
    }
}

impl WalletScanCommitRequest<'_> {
    async fn commit(self) -> WalletScanCommitOutcome {
        let request = self;
        let from_block = request.apply.from_block;
        let to_block = request.apply.to_block;
        if request.event_reset_generation != request.current_reset_generation {
            return WalletScanCommitOutcome {
                result: WalletBackfillApplyResult::Rejected {
                    committed_to: *request.last_scanned,
                    reason: WalletBackfillRejectReason::StaleGeneration {
                        expected: request.current_reset_generation,
                        actual: request.event_reset_generation,
                    },
                },
                changed: false,
            };
        }
        if request.cancel.is_cancelled() || !request.worker_handle.is_current_actor() {
            return WalletScanCommitOutcome {
                result: WalletBackfillApplyResult::Rejected {
                    committed_to: *request.last_scanned,
                    reason: WalletBackfillRejectReason::Shutdown,
                },
                changed: false,
            };
        }
        if from_block > to_block {
            return WalletScanCommitOutcome {
                result: WalletBackfillApplyResult::Rejected {
                    committed_to: *request.last_scanned,
                    reason: WalletBackfillRejectReason::ApplyFailed,
                },
                changed: false,
            };
        }
        if let Some(target_block) = request.cfg.sync_to_block
            && to_block > target_block
        {
            return WalletScanCommitOutcome {
                result: WalletBackfillApplyResult::Rejected {
                    committed_to: *request.last_scanned,
                    reason: WalletBackfillRejectReason::TargetExceeded {
                        target_block,
                        requested_to: to_block,
                    },
                },
                changed: false,
            };
        }
        if !request.apply.rows.covers(from_block, to_block) {
            return WalletScanCommitOutcome {
                result: WalletBackfillApplyResult::Rejected {
                    committed_to: *request.last_scanned,
                    reason: WalletBackfillRejectReason::ApplyFailed,
                },
                changed: false,
            };
        }
        if to_block <= *request.last_scanned {
            return WalletScanCommitOutcome {
                result: WalletBackfillApplyResult::AlreadyCovered {
                    committed_to: *request.last_scanned,
                },
                changed: false,
            };
        }
        let expected_from_block = request.last_scanned.saturating_add(1);
        if from_block != expected_from_block {
            return WalletScanCommitOutcome {
                result: WalletBackfillApplyResult::Rejected {
                    committed_to: *request.last_scanned,
                    reason: WalletBackfillRejectReason::NonContiguous {
                        expected_from: expected_from_block,
                        actual_from: from_block,
                    },
                },
                changed: false,
            };
        }
        let current_data_epoch = request.public_data_plane.current_epoch();
        let apply_data_epoch = request.apply.read_scope.epoch();
        if apply_data_epoch != current_data_epoch {
            return WalletScanCommitOutcome {
                result: WalletBackfillApplyResult::Rejected {
                    committed_to: *request.last_scanned,
                    reason: WalletBackfillRejectReason::StaleDataPlaneEpoch {
                        expected: current_data_epoch.value,
                        actual: apply_data_epoch.value,
                    },
                },
                changed: false,
            };
        }

        let source_label = request.apply.rows.source.as_str();
        let (delta, last_scanned_block_hash, log_count) = match request.apply.rows.payload {
            WalletScanRowsPayload::Rows(rows) => {
                let log_count = rows.row_count();
                let delta = WalletLogDelta::from_rows(&rows, &request.cfg.scan_keys);
                (delta, request.apply.rows.to_block_hash, log_count)
            }
            WalletScanRowsPayload::EmptyCoverage => {
                let delta = WalletLogDelta {
                    utxos: Vec::new(),
                    nullifiers: Vec::new(),
                    commitment_observations: Vec::new(),
                };
                (delta, None, 0)
            }
            #[cfg(test)]
            WalletScanRowsPayload::IndexedDeltaForTest { delta } => (*delta, None, 0),
        };

        let WalletLogDelta {
            utxos,
            nullifiers,
            commitment_observations,
        } = delta;
        let commitment_observation_count = commitment_observations.len();
        let delta = WalletLogDelta {
            utxos,
            nullifiers,
            commitment_observations: Vec::new(),
        };

        let mut candidate = request.utxos.read().await.clone();
        let rows_before = candidate.len();
        let apply_started = Instant::now();
        let outcome = apply_wallet_delta_to_vec_with_outcome(request.cfg, &mut candidate, delta);
        let mut changed = outcome.changed;
        if changed
            && request.refresh_poi_statuses
            && let Some(status_reader) = request.poi_status_reader
        {
            changed |= refresh_wallet_poi_statuses_selected(
                status_reader,
                request.cfg.chain.chain_id,
                request.active_poi_list_keys,
                &mut candidate,
                WalletPoiRefreshSelection::RequiredOrRecoverable,
            )
            .await;
        }

        let authority = WalletPrivateMutationAuthority::new(
            request.worker_handle,
            request.event_reset_generation,
            request.cancel,
        );
        let permit = match authority.acquire().await {
            Ok(permit) => permit,
            Err(reason) => {
                return WalletScanCommitOutcome {
                    result: WalletBackfillApplyResult::Rejected {
                        committed_to: *request.last_scanned,
                        reason,
                    },
                    changed: false,
                };
            }
        };
        if request.cancel.is_cancelled() {
            return WalletScanCommitOutcome {
                result: WalletBackfillApplyResult::Rejected {
                    committed_to: *request.last_scanned,
                    reason: WalletBackfillRejectReason::Shutdown,
                },
                changed: false,
            };
        }

        let pending_output_context_updates = match pending_output_poi_observation_updates(
            request.db,
            request.cfg.chain.chain_id,
            &request.cfg.cache_key,
            &commitment_observations,
        ) {
            Ok(updates) => updates,
            Err(err) => {
                warn!(?err, cache_key = %request.cfg.cache_key, from_block, to_block, "failed to prepare wallet scan pending output POI observations");
                request
                    .actor_state
                    .fail_readiness(WalletReadinessError::PersistenceFailed);
                let _ = request.actor_state.reduce_and_publish_readiness(
                    &permit,
                    request.ready_tx,
                    request.readiness_tx,
                );
                return WalletScanCommitOutcome {
                    result: WalletBackfillApplyResult::Rejected {
                        committed_to: *request.last_scanned,
                        reason: WalletBackfillRejectReason::PersistenceFailed,
                    },
                    changed: false,
                };
            }
        };

        let persist_started = Instant::now();
        let public_scan_permit = match request
            .public_data_plane
            .public_scan_commit_permit(
                crate::chain::PublicScanRange::new(from_block, to_block),
                request.apply.rows.source,
                request.apply.read_scope,
            )
            .await
        {
            Ok(permit) => permit,
            Err(err) => {
                let reason = match err {
                    crate::chain::PublicDataPlaneError::StaleEpoch { expected, actual } => {
                        WalletBackfillRejectReason::StaleDataPlaneEpoch { expected, actual }
                    }
                    crate::chain::PublicDataPlaneError::InvalidRange { .. }
                    | crate::chain::PublicDataPlaneError::PublicCacheReset { .. } => {
                        WalletBackfillRejectReason::ApplyFailed
                    }
                };
                return WalletScanCommitOutcome {
                    result: WalletBackfillApplyResult::Rejected {
                        committed_to: *request.last_scanned,
                        reason,
                    },
                    changed: false,
                };
            }
        };
        if let Err(reason) = permit.revalidate() {
            return WalletScanCommitOutcome {
                result: WalletBackfillApplyResult::Rejected {
                    committed_to: *request.last_scanned,
                    reason,
                },
                changed: false,
            };
        }

        let persisted_full_snapshot = match request
            .persist_state
            .persist_progress_with_private_effects(
                request.cache_store,
                &permit,
                WalletProgressPersist {
                    cache_key: &request.cfg.cache_key,
                    snapshot: &candidate,
                    last_scanned: to_block,
                    last_scanned_block_hash,
                    changed,
                },
                WalletProgressPrivateEffects {
                    pending_output_context_chain_id: request.cfg.chain.chain_id,
                    pending_output_context_updates: &pending_output_context_updates,
                    pending_output_context_deletes: &outcome.spent_output_commitments,
                    output_poi_recovery_updates: &[],
                },
            ) {
            Ok(persisted_full_snapshot) => persisted_full_snapshot,
            Err(err) => {
                warn!(?err, cache_key = %request.cfg.cache_key, from_block, to_block, "failed to persist wallet scan candidate");
                request
                    .actor_state
                    .fail_readiness(WalletReadinessError::PersistenceFailed);
                let _ = request.actor_state.reduce_and_publish_readiness(
                    &permit,
                    request.ready_tx,
                    request.readiness_tx,
                );
                return WalletScanCommitOutcome {
                    result: WalletBackfillApplyResult::Rejected {
                        committed_to: *request.last_scanned,
                        reason: WalletBackfillRejectReason::PersistenceFailed,
                    },
                    changed: false,
                };
            }
        };
        request.actor_state.clear_persistence_failure();

        {
            let mut locked = request.utxos.write().await;
            if let Err(reason) = permit.revalidate() {
                return WalletScanCommitOutcome {
                    result: WalletBackfillApplyResult::Rejected {
                        committed_to: *request.last_scanned,
                        reason,
                    },
                    changed: false,
                };
            }
            *locked = candidate;
        }
        *request.last_scanned = to_block;
        if let Err(reason) = permit.set_last_scanned(to_block) {
            return WalletScanCommitOutcome {
                result: WalletBackfillApplyResult::Rejected {
                    committed_to: *request.last_scanned,
                    reason,
                },
                changed: false,
            };
        }
        request
            .live_metadata_flush
            .mark_persisted(to_block, Instant::now());
        let target_block = request
            .actor_state
            .target_block
            .unwrap_or(to_block)
            .max(to_block);
        if let Err(reason) = permit.publish_progress(
            request.cfg.progress_tx.as_ref(),
            SyncProgressUpdate::new(
                SyncProgressStage::IndexingUtxos,
                from_block,
                to_block,
                target_block,
            ),
        ) {
            return WalletScanCommitOutcome {
                result: WalletBackfillApplyResult::Rejected {
                    committed_to: *request.last_scanned,
                    reason,
                },
                changed: false,
            };
        }
        if let Err(reason) = permit.notify_if_changed(changed) {
            return WalletScanCommitOutcome {
                result: WalletBackfillApplyResult::Rejected {
                    committed_to: *request.last_scanned,
                    reason,
                },
                changed: false,
            };
        }
        if request.mark_syncing_on_commit {
            request.actor_state.update_cursor(to_block);
            if let Err(reason) = request.actor_state.reduce_and_publish_readiness(
                &permit,
                request.ready_tx,
                request.readiness_tx,
            ) {
                return WalletScanCommitOutcome {
                    result: WalletBackfillApplyResult::Rejected {
                        committed_to: *request.last_scanned,
                        reason,
                    },
                    changed: false,
                };
            }
        }
        drop(public_scan_permit);
        drop(permit);

        if commitment_observation_count > 0 {
            let authority = WalletPrivateMutationAuthority::new(
                request.worker_handle,
                request.event_reset_generation,
                request.cancel,
            );
            process_pending_output_poi_observations_authorized(
                &authority,
                request.db,
                request.cache_store,
                request.cfg,
                request.active_poi_list_keys,
                request.poi_submitter,
                false,
            )
            .await;
        }

        let snapshot = request.utxos.read().await;
        let (unspent, spent) = wallet_utxo_counts(&snapshot);
        debug!(
            cache_key = %request.cfg.cache_key,
            source = source_label,
            from_block,
            to_block,
            logs = log_count,
            rows_before,
            total = snapshot.len(),
            unspent,
            spent,
            changed,
            commitment_observations = commitment_observation_count,
            persisted_full_snapshot,
            needs_full_persist = request.persist_state.needs_full_persist,
            apply_elapsed_ms = apply_started.elapsed().as_millis(),
            persist_elapsed_ms = persist_started.elapsed().as_millis(),
            "wallet scan candidate committed"
        );

        WalletScanCommitOutcome {
            result: WalletBackfillApplyResult::Committed {
                committed_to: to_block,
            },
            changed,
        }
    }
}

pub(crate) async fn spawn_wallet_worker(
    services: WalletWorkerServices,
    cfg: WalletConfig,
    actor_id: u64,
    mut live_rx: broadcast::Receiver<SharedLogBatch>,
    mut backfill_rx: mpsc::Receiver<BackfillEvent>,
    cancel: CancellationToken,
    initial_utxos: Vec<WalletUtxo>,
    initial_last_scanned: u64,
) -> Result<WalletHandle, WalletCacheError> {
    let utxos = Arc::new(RwLock::new(initial_utxos));
    let pending_overlay = Arc::new(RwLock::new(WalletPendingOverlay::default()));
    let last_scanned_state = Arc::new(AtomicU64::new(initial_last_scanned));
    let next_sync_job_id = Arc::new(AtomicU64::new(1));
    let active_actor_id = Arc::new(AtomicU64::new(actor_id));
    let authority_lock = Arc::new(Mutex::new(()));
    let WalletWorkerServices {
        db,
        rpcs,
        http_client,
        indexed_artifact_source,
        forest,
        backfill_tx,
        backfill_sender,
        public_data_plane,
    } = services;
    let cache_store = wallet_cache_store(&db, &cfg);
    let restored_sync_state =
        cache_store.get_wallet_sync_actor_state(cfg.chain.chain_id, &cfg.cache_key)?;
    let restored_pending_reset = restored_sync_state
        .as_ref()
        .and_then(|state| state.pending_reset.as_ref())
        .map(|pending| PendingWalletReset {
            intent_id: pending.intent_id,
            from_block: pending.from_block,
            reset_generation: 1,
            replay_plan: WalletResetReplayPlan::new(
                pending.replay_start_block,
                pending.replay_target_block,
                pending.follow_safe_head,
            ),
        });
    let restored_highest_reset_intent = restored_sync_state
        .as_ref()
        .map_or(0, |state| state.highest_accepted_reset_intent);
    let initial_reset_generation = u64::from(restored_pending_reset.is_some());
    let reset_generation_state = Arc::new(AtomicU64::new(initial_reset_generation));
    let (ready_tx, ready_rx) = watch::channel(false);
    let (readiness_tx, readiness_rx) = watch::channel(WalletReadiness::Syncing);
    let (rev_tx, rev_rx) = watch::channel(0_u64);
    let (poi_refresh_tx, mut poi_refresh_rx) = mpsc::channel(1);
    let (pending_overlay_tx, mut pending_overlay_rx) = mpsc::channel(8);
    let (indexed_catch_up_status_tx, mut indexed_catch_up_status_rx) = mpsc::channel(8);
    let (poi_refreshing_tx, poi_refreshing_rx) = watch::channel(false);
    let (indexed_catch_up_tx, indexed_catch_up_rx) = watch::channel(None);
    let handle = WalletHandle {
        cache_key: cfg.cache_key.clone(),
        chain_id: cfg.chain.chain_id,
        actor_id,
        active_actor_id,
        authority_lock,
        utxos: utxos.clone(),
        pending_overlay,
        last_scanned: last_scanned_state,
        reset_generation: reset_generation_state,
        next_sync_job_id,
        ready_rx,
        readiness_rx,
        rev_rx,
        poi_refreshing_rx,
        indexed_catch_up_rx,
        poi_read_source: cfg.poi_read_source.clone(),
        local_poi_caches: cfg.local_poi_caches.clone(),
        pending_overlay_tx,
        poi_refresh_tx,
        indexed_catch_up_status_tx,
        rev_tx,
        indexed_catch_up_tx,
    };
    let wait_for_initial_reset_replay = restored_pending_reset.is_some();
    let (startup_replay_tx, startup_replay_rx) = oneshot::channel();

    let chain_id = cfg.chain.chain_id;
    let worker_handle = handle.clone();
    tokio::spawn(async move {
        let mut startup_replay_tx = Some(startup_replay_tx);
        let worker_started = Instant::now();
        let mut last_scanned = initial_last_scanned;
        let snapshot = utxos.read().await;
        let (unspent, spent) = wallet_utxo_counts(&snapshot);
        info!(
            cache_key = %cfg.cache_key,
            total = snapshot.len(),
            unspent,
            spent,
            last_scanned,
            "loaded wallet cache"
        );
        drop(snapshot);

        let mut backfill_complete_block: Option<u64> = None;
        let mut live_receiver_lagged = false;
        let mut persist_state = WalletPersistState::default();
        let mut live_metadata_flush = WalletLiveMetadataFlush::new(last_scanned, worker_started);
        let poi_status_client = wallet_poi_status_client(&cfg.poi_rpc_url, http_client.as_ref());
        let active_poi_list_keys = default_active_poi_list_keys();
        let mut last_live_tail_poll = Instant::now();
        let mut pending_reset_retry = tokio::time::interval_at(
            tokio::time::Instant::now() + WALLET_RESET_RETRY_INTERVAL,
            WALLET_RESET_RETRY_INTERVAL,
        );
        pending_reset_retry.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        let preloaded_poi_caches = if cfg.manage_local_poi_cache {
            install_persisted_local_poi_caches(db.as_ref(), &cfg, &active_poi_list_keys).await
        } else {
            BTreeMap::new()
        };
        let mut startup_artifact_warmup = if cfg.manage_local_poi_cache {
            spawn_startup_artifact_poi_cache_warmup(
                Arc::clone(&db),
                http_client.clone(),
                cfg.clone(),
                active_poi_list_keys.clone(),
                preloaded_poi_caches,
            )
        } else {
            debug!(
                cache_key = %cfg.cache_key,
                chain_id = cfg.chain.chain_id,
                "wallet using externally managed artifact POI cache"
            );
            None
        };

        if poi_status_client.is_some() {
            let locked = utxos.read().await;
            debug!(
                cache_key = %cfg.cache_key,
                poi_refresh_needed = wallet_poi_status_refresh_needed(&locked, &active_poi_list_keys),
                "startup wallet POI status refresh will run after backfill if needed"
            );
        }

        let mut readiness_started = worker_started;
        let mut actor_state = WalletActorState::new(
            chain_id,
            worker_handle.actor_id,
            initial_reset_generation,
            last_scanned,
            restored_highest_reset_intent,
            restored_pending_reset,
        );
        macro_rules! publish_readiness {
            () => {{
                let authority = WalletPrivateMutationAuthority::new(
                    &worker_handle,
                    actor_state.reset_generation,
                    &cancel,
                );
                match authority.acquire().await {
                    Ok(permit) => {
                        if let Err(reason) = actor_state.reduce_and_publish_readiness(
                            &permit,
                            &ready_tx,
                            &readiness_tx,
                        ) {
                            debug!(?reason, cache_key = %cfg.cache_key, "wallet readiness publication rejected");
                        }
                    }
                    Err(reason) => {
                        debug!(?reason, cache_key = %cfg.cache_key, "wallet readiness publication skipped");
                    }
                }
            }};
        }
        macro_rules! try_commit_pending_reset {
            ($schedule_replay:expr) => {{
                if let Some(pending) = actor_state.pending_reset {
                    let outcome = WalletResetCommitRequest {
                        cache_store: cache_store.as_ref(),
                        cfg: &cfg,
                        utxos: &utxos,
                        worker_handle: &worker_handle,
                        pending,
                        highest_accepted_reset_intent: actor_state.highest_accepted_reset_intent,
                        cancel: &cancel,
                        last_scanned: &mut last_scanned,
                        persist_state: &mut persist_state,
                        live_metadata_flush: &mut live_metadata_flush,
                    }
                    .commit()
                    .await;
                    if outcome.committed {
                        actor_state.clear_pending_reset();
                        actor_state.terminal_failure = None;
                        actor_state.update_cursor(last_scanned);
                        if $schedule_replay {
                            enqueue_reset_replay_after_commit(
                                &cfg,
                                &worker_handle,
                                &mut actor_state,
                                pending,
                                last_scanned,
                                &backfill_tx,
                                &backfill_sender,
                            );
                        }
                        readiness_started = Instant::now();
                        backfill_complete_block = None;
                        live_rx = live_rx.resubscribe();
                        publish_readiness!();
                    }
                    Some(outcome)
                } else {
                    None
                }
            }};
        }
        macro_rules! apply_backfill_done {
            ($last_block:expr) => {{
                let last_block = $last_block;
                let current_reset_generation = actor_state.reset_generation;
                let should_persist = persist_state.needs_full_persist
                    || persist_state.pending_cache_reset.is_some();
                let authority = WalletPrivateMutationAuthority::new(
                    &worker_handle,
                    current_reset_generation,
                    &cancel,
                );
                let snapshot = utxos.read().await;
                let persist_result = if should_persist {
                    match authority.acquire().await {
                        Ok(permit) => {
                            let persisted = match persist_state.persist_progress(
                                cache_store.as_ref(),
                                &permit,
                                WalletProgressPersist {
                                    cache_key: &cfg.cache_key,
                                    snapshot: &snapshot,
                                    last_scanned,
                                    last_scanned_block_hash: None,
                                    changed: false,
                                },
                            ) {
                                Ok(_) => {
                                    live_metadata_flush.mark_persisted(last_scanned, Instant::now());
                                    Ok(())
                                }
                                Err(err) => {
                                    warn!(?err, cache_key = %cfg.cache_key, "failed to update wallet cache metadata");
                                    Err(WalletBackfillRejectReason::PersistenceFailed)
                                }
                            };
                            persisted
                        }
                        Err(reason) => {
                            warn!(?reason, cache_key = %cfg.cache_key, "wallet target metadata persist rejected");
                            Err(reason)
                        }
                    }
                } else {
                    Ok(())
                };
                drop(snapshot);
                if let Err(reason) = persist_result {
                    WalletBackfillDoneOutcome::Rejected(reason)
                } else {
                actor_state.clear_persistence_failure();
                let mut pre_ready_poi_status_changed = false;
                let mut pre_ready_poi_status_rejection = None;
                let mut pre_ready_poi_status_refresh_elapsed_ms = 0_u128;
                let mut pre_ready_local_cache_available = false;
                if let Some(client) = poi_status_client.as_ref() {
                    let refresh_needed = {
                        let locked = utxos.read().await;
                        wallet_poi_status_refresh_needed_for_selection(
                            &locked,
                            &active_poi_list_keys,
                            WalletPoiRefreshSelection::RequiredOrRecoverable,
                        )
                    };
                    if refresh_needed {
                        pre_ready_local_cache_available = local_poi_caches_available_for_lists(
                            &cfg,
                            &active_poi_list_keys,
                        ).await;
                        if pre_ready_local_cache_available {
                            let status_refresh_started = Instant::now();
                            let status_reader = wallet_poi_status_reader_source(client, &cfg);
                            match (WalletPoiStatusRefreshCommitRequest {
                                cache_store: cache_store.as_ref(),
                                cfg: &cfg,
                                utxos: &utxos,
                                worker_handle: &worker_handle,
                                last_scanned,
                                reset_generation: current_reset_generation,
                                actor_state: &mut actor_state,
                                persist_state: &mut persist_state,
                                ready_tx: &ready_tx,
                                readiness_tx: &readiness_tx,
                                status_reader: status_reader.as_reader(),
                                active_poi_list_keys: &active_poi_list_keys,
                                selection: WalletPoiRefreshSelection::RequiredOrRecoverable,
                                cancel: &cancel,
                            })
                            .commit()
                            .await
                            {
                                Ok(changed) => pre_ready_poi_status_changed = changed,
                                Err(reason) => {
                                    warn!(?reason, cache_key = %cfg.cache_key, "pre-ready wallet POI status refresh rejected");
                                    pre_ready_poi_status_rejection = Some(reason);
                                }
                            }
                            pre_ready_poi_status_refresh_elapsed_ms =
                                status_refresh_started.elapsed().as_millis();
                            debug!(
                                cache_key = %cfg.cache_key,
                                changed = pre_ready_poi_status_changed,
                                status_refresh_elapsed_ms = pre_ready_poi_status_refresh_elapsed_ms,
                                "pre-ready wallet POI status refresh visible"
                            );
                            tokio::task::yield_now().await;
                        }
                    }
                }
                if let Some(reason) = pre_ready_poi_status_rejection {
                    WalletBackfillDoneOutcome::Rejected(reason)
                } else {
                let snapshot = utxos.read().await;
                let (unspent, spent) = wallet_utxo_counts(&snapshot);
                backfill_complete_block = Some(last_block);
                info!(
                    cache_key = %cfg.cache_key,
                    last_scanned,
                    total = snapshot.len(),
                    unspent,
                    spent,
                    pre_ready_poi_status_changed,
                    pre_ready_local_cache_available,
                    pre_ready_poi_status_refresh_elapsed_ms,
                    ready_elapsed_ms = readiness_started.elapsed().as_millis(),
                    worker_elapsed_ms = worker_started.elapsed().as_millis(),
                    "wallet backfill complete"
                );
                drop(snapshot);
                tokio::task::yield_now().await;

                if let Some(client) = poi_status_client.as_ref() {
                    let post_ready_poi_started = Instant::now();
                    let authority = WalletPrivateMutationAuthority::new(
                        &worker_handle,
                        current_reset_generation,
                        &cancel,
                    );
                    let pending_observations_started = Instant::now();
                    process_pending_output_poi_observations_authorized(
                        &authority,
                        db.as_ref(),
                        cache_store.as_ref(),
                        &cfg,
                        &active_poi_list_keys,
                        Some(client as &dyn PendingOutputPoiSubmitter),
                        false,
                    ).await;
                    let pending_observations_elapsed_ms =
                        pending_observations_started.elapsed().as_millis();

                    let refresh_needed = {
                        let locked = utxos.read().await;
                        wallet_poi_status_refresh_needed_for_selection(
                            &locked,
                            &active_poi_list_keys,
                            WalletPoiRefreshSelection::RequiredOrRecoverable,
                        )
                    };
                    if refresh_needed {
                        publish_poi_refreshing(
                            &poi_refreshing_tx,
                            true,
                            &worker_handle,
                            current_reset_generation,
                            &cancel,
                        ).await;
                        let warmup_wait_started = Instant::now();
                        let local_cache_available = local_poi_caches_ready_for_refresh(
                            &mut startup_artifact_warmup,
                            &cfg,
                            &active_poi_list_keys,
                            "post_ready_poi_refresh",
                        ).await;
                        let warmup_wait_elapsed_ms =
                            warmup_wait_started.elapsed().as_millis();
                        if !local_cache_available {
                            log_local_poi_cache_unavailable(&cfg, "post_ready_poi_refresh");
                            publish_poi_refreshing(
                                &poi_refreshing_tx,
                                false,
                                &worker_handle,
                                current_reset_generation,
                                &cancel,
                            ).await;
                        } else {
                            let status_refresh_started = Instant::now();
                            let status_reader = wallet_poi_status_reader_source(client, &cfg);
                            let changed = match (WalletPoiStatusRefreshCommitRequest {
                                cache_store: cache_store.as_ref(),
                                cfg: &cfg,
                                utxos: &utxos,
                                worker_handle: &worker_handle,
                                last_scanned,
                                reset_generation: current_reset_generation,
                                actor_state: &mut actor_state,
                                persist_state: &mut persist_state,
                                ready_tx: &ready_tx,
                                readiness_tx: &readiness_tx,
                                status_reader: status_reader.as_reader(),
                                active_poi_list_keys: &active_poi_list_keys,
                                selection: WalletPoiRefreshSelection::RequiredOrRecoverable,
                                cancel: &cancel,
                            })
                            .commit()
                            .await
                            {
                                Ok(changed) => changed,
                                Err(reason) => {
                                    warn!(?reason, cache_key = %cfg.cache_key, "post-ready wallet POI status refresh rejected");
                                    false
                                }
                            };
                            let status_refresh_elapsed_ms =
                                status_refresh_started.elapsed().as_millis();
                            debug!(
                                cache_key = %cfg.cache_key,
                                changed,
                                status_refresh_elapsed_ms,
                                elapsed_ms = post_ready_poi_started.elapsed().as_millis(),
                                "post-ready wallet POI status refresh visible"
                            );
                            tokio::task::yield_now().await;
                            let pending_verification = verify_submitted_pending_output_pois_with_config_authorized(
                                &authority,
                                client,
                                &cfg,
                                db.as_ref(),
                                cache_store.as_ref(),
                                &active_poi_list_keys,
                            )
                            .await;
                            publish_poi_refreshing(
                                &poi_refreshing_tx,
                                false,
                                &worker_handle,
                                current_reset_generation,
                                &cancel,
                            ).await;
                            let output_recovery_started = Instant::now();
                            let recovered = recover_missing_output_pois_from_wallet(OutputPoiRecoveryRun {
                                authority: &authority,
                                db: db.as_ref(),
                                cache_store: cache_store.as_ref(),
                                cfg: &cfg,
                                rpcs: rpcs.as_ref(),
                                http_client: http_client.as_ref(),
                                indexed_artifact_source: indexed_artifact_source.as_ref(),
                                forest: &forest,
                                utxos: &utxos,
                                client,
                                active_list_keys: &active_poi_list_keys,
                                force_retry: false,
                            }).await;
                            authority
                                .notify_changed_if(recovered > 0, "post_ready_output_poi_recovery")
                                .await;
                            let output_recovery_elapsed_ms =
                                output_recovery_started.elapsed().as_millis();
                            info!(
                                cache_key = %cfg.cache_key,
                                changed,
                                recovered,
                                pending_observations_elapsed_ms,
                                local_cache_available,
                                warmup_wait_elapsed_ms,
                                status_refresh_elapsed_ms,
                                output_recovery_elapsed_ms,
                                pending_completed = pending_verification.completed,
                                pending_still_missing = pending_verification.pending,
                                pending_errors = pending_verification.errors,
                                elapsed_ms = post_ready_poi_started.elapsed().as_millis(),
                                "post-ready wallet POI maintenance complete"
                            );
                        }
                    } else {
                        debug!(
                            cache_key = %cfg.cache_key,
                            pending_observations_elapsed_ms,
                            elapsed_ms = post_ready_poi_started.elapsed().as_millis(),
                            "post-ready wallet POI status refresh not needed"
                        );
                    }
                }
                WalletBackfillDoneOutcome::Finished
                }
                }
            }};
        }
        if actor_state.pending_reset.is_some() {
            let _ = try_commit_pending_reset!(true);
        }
        if actor_state.pending_reset.is_none()
            && let Some(tx) = startup_replay_tx.take()
        {
            let _ = tx.send(());
        }

        loop {
            tokio::select! {
                _ = cancel.cancelled() => break,
                _ = pending_reset_retry.tick(), if actor_state.pending_reset.is_some() => {
                    if let Some(outcome) = try_commit_pending_reset!(true) {
                        debug!(?outcome.result, cache_key = %cfg.cache_key, "wallet pending reset retry completed");
                    }
                    if actor_state.pending_reset.is_none()
                        && let Some(tx) = startup_replay_tx.take()
                    {
                        let _ = tx.send(());
                    }
                }
                Some(refresh_request) = poi_refresh_rx.recv() => {
                    let Some(client) = poi_status_client.as_ref() else {
                        continue;
                    };
                    if actor_state.pending_reset.is_some() {
                        debug!(
                            cache_key = %cfg.cache_key,
                            "wallet POI refresh skipped while reset commit is pending"
                        );
                        continue;
                    }
                    if backfill_complete_block.is_none() {
                        debug!(
                            cache_key = %cfg.cache_key,
                            "wallet POI refresh skipped until backfill complete"
                        );
                        continue;
                    }
                    let current_reset_generation = actor_state.reset_generation;
                    publish_poi_refreshing(
                        &poi_refreshing_tx,
                        true,
                        &worker_handle,
                        current_reset_generation,
                        &cancel,
                    ).await;
                    if !local_poi_caches_ready_for_refresh(
                        &mut startup_artifact_warmup,
                        &cfg,
                        &active_poi_list_keys,
                        "manual_poi_refresh",
                    ).await {
                        log_local_poi_cache_unavailable(&cfg, "manual_poi_refresh");
                        publish_poi_refreshing(
                            &poi_refreshing_tx,
                            false,
                            &worker_handle,
                            current_reset_generation,
                            &cancel,
                        ).await;
                        continue;
                    }
                    let status_reader = wallet_poi_status_reader_source(client, &cfg);
                    let changed = match (WalletPoiStatusRefreshCommitRequest {
                        cache_store: cache_store.as_ref(),
                        cfg: &cfg,
                        utxos: &utxos,
                        worker_handle: &worker_handle,
                        last_scanned,
                        reset_generation: current_reset_generation,
                        actor_state: &mut actor_state,
                        persist_state: &mut persist_state,
                        ready_tx: &ready_tx,
                        readiness_tx: &readiness_tx,
                        status_reader: status_reader.as_reader(),
                        active_poi_list_keys: &active_poi_list_keys,
                        selection: WalletPoiRefreshSelection::Recoverable,
                        cancel: &cancel,
                    })
                    .commit()
                    .await
                    {
                        Ok(changed) => changed,
                        Err(reason) => {
                            warn!(?reason, cache_key = %cfg.cache_key, "manual wallet POI status refresh rejected");
                            publish_poi_refreshing(
                                &poi_refreshing_tx,
                                false,
                                &worker_handle,
                                current_reset_generation,
                                &cancel,
                            ).await;
                            continue;
                        }
                    };
                    let authority = WalletPrivateMutationAuthority::new(
                        &worker_handle,
                        current_reset_generation,
                        &cancel,
                    );
                    let pending_verification = verify_submitted_pending_output_pois_with_config_authorized(
                        &authority,
                        client,
                        &cfg,
                        db.as_ref(),
                        cache_store.as_ref(),
                        &active_poi_list_keys,
                    ).await;
                    let forced_pending_attempts = if refresh_request.force_output_poi_recovery {
                        force_resubmit_matching_pending_output_pois_authorized(
                            &authority,
                            db.as_ref(),
                            cache_store.as_ref(),
                            &cfg,
                            &utxos,
                            &active_poi_list_keys,
                            client as &dyn PendingOutputPoiSubmitter,
                        ).await
                    } else {
                        0
                    };
                    publish_poi_refreshing(
                        &poi_refreshing_tx,
                        false,
                        &worker_handle,
                        current_reset_generation,
                        &cancel,
                    ).await;
                    debug!(
                        cache_key = %cfg.cache_key,
                        changed,
                        pending_completed = pending_verification.completed,
                        pending_still_missing = pending_verification.pending,
                        pending_errors = pending_verification.errors,
                        "manual wallet POI refresh pending context verification complete"
                    );
                    let recovery_started = Instant::now();
                    let recovered = recover_missing_output_pois_from_wallet(OutputPoiRecoveryRun {
                        authority: &authority,
                        db: db.as_ref(),
                        cache_store: cache_store.as_ref(),
                        cfg: &cfg,
                        rpcs: rpcs.as_ref(),
                        http_client: http_client.as_ref(),
                        indexed_artifact_source: indexed_artifact_source.as_ref(),
                        forest: &forest,
                        utxos: &utxos,
                        client,
                        active_list_keys: &active_poi_list_keys,
                        force_retry: refresh_request.force_output_poi_recovery,
                    }).await;
                    let force_submission_retry = refresh_request.force_output_poi_recovery
                        && recovered == 0
                        && forced_pending_attempts == 0;
                    process_pending_output_poi_observations_authorized(
                        &authority,
                        db.as_ref(),
                        cache_store.as_ref(),
                        &cfg,
                        &active_poi_list_keys,
                        Some(client as &dyn PendingOutputPoiSubmitter),
                        force_submission_retry,
                    ).await;
                    debug!(
                        cache_key = %cfg.cache_key,
                        recovered,
                        force_submission_retry,
                        elapsed_ms = recovery_started.elapsed().as_millis(),
                        "manual wallet output POI recovery complete"
                    );
                    authority
                        .notify_changed_if(recovered > 0, "manual_output_poi_recovery")
                        .await;
                }
                Some(command) = indexed_catch_up_status_rx.recv() => {
                    let authority = WalletPrivateMutationAuthority::new(
                        &worker_handle,
                        actor_state.reset_generation,
                        &cancel,
                    );
                    match authority.acquire().await {
                        Ok(permit) => {
                            match command {
                                WalletIndexedCatchUpCommand::Claim { response } => {
                                    let token =
                                        worker_handle.mint_sync_token(actor_state.reset_generation);
                                    let lease = if actor_state.accept_indexed_catch_up(token) {
                                        if let Err(reason) = actor_state.reduce_and_publish_readiness(
                                            &permit,
                                            &ready_tx,
                                            &readiness_tx,
                                        ) {
                                            debug!(?reason, cache_key = %cfg.cache_key, "indexed wallet catch-up readiness publication rejected");
                                        }
                                        Some(WalletIndexedCatchUpLease::for_actor_accepted_job(
                                            token,
                                        ))
                                    } else {
                                        None
                                    };
                                    let _ = response.send(lease);
                                }
                                WalletIndexedCatchUpCommand::Publish { lease, status } => {
                                    if actor_state.is_active_indexed_catch_up(lease)
                                        && let Err(reason) =
                                            permit.publish_indexed_catch_up(Some(status))
                                    {
                                        debug!(?reason, cache_key = %cfg.cache_key, "indexed wallet catch-up status publication rejected");
                                    } else if !actor_state.is_active_indexed_catch_up(lease) {
                                        debug!(cache_key = %cfg.cache_key, token = ?lease.token(), "stale indexed wallet catch-up status publication ignored");
                                    }
                                }
                                WalletIndexedCatchUpCommand::Clear { lease } => {
                                    if actor_state.retire_indexed_catch_up(lease) {
                                        if let Err(reason) = permit.publish_indexed_catch_up(None) {
                                            debug!(?reason, cache_key = %cfg.cache_key, "indexed wallet catch-up status clear rejected");
                                        }
                                        if let Err(reason) = actor_state.reduce_and_publish_readiness(
                                            &permit,
                                            &ready_tx,
                                            &readiness_tx,
                                        ) {
                                            debug!(?reason, cache_key = %cfg.cache_key, "indexed wallet catch-up readiness clear rejected");
                                        }
                                    } else {
                                        debug!(cache_key = %cfg.cache_key, token = ?lease.token(), "stale indexed wallet catch-up status clear ignored");
                                    }
                                }
                            }
                        }
                        Err(reason) => {
                            if let WalletIndexedCatchUpCommand::Claim { response } = command {
                                let _ = response.send(None);
                            }
                            debug!(?reason, cache_key = %cfg.cache_key, "indexed wallet catch-up status publication skipped");
                        }
                    }
                }
                Some(request) = pending_overlay_rx.recv() => {
                    let current_reset_generation = actor_state.reset_generation;
                    if actor_state.pending_reset.is_some()
                        || request.reset_generation != current_reset_generation
                        || request.last_scanned != last_scanned
                        || !actor_state.accept_pending_overlay(request.token, request.last_scanned)
                    {
                        debug!(
                            cache_key = %cfg.cache_key,
                            token = ?request.token,
                            request_reset_generation = request.reset_generation,
                            current_reset_generation,
                            request_last_scanned = request.last_scanned,
                            current_last_scanned = last_scanned,
                            pending_reset = actor_state.pending_reset.is_some(),
                            "ignoring stale pending overlay update"
                        );
                        continue;
                    }
                    let authority = WalletPrivateMutationAuthority::new(
                        &worker_handle,
                        current_reset_generation,
                        &cancel,
                    );
                    let permit = match authority.acquire().await {
                        Ok(guard) => guard,
                        Err(reason) => {
                            debug!(?reason, cache_key = %cfg.cache_key, "pending overlay update rejected");
                            actor_state.retire_job(request.token);
                            continue;
                        }
                    };
                    if !actor_state.pending_overlay_is_current(request.token, request.last_scanned)
                        || permit.revalidate().is_err()
                    {
                        actor_state.retire_job(request.token);
                        continue;
                    }
                    let overlay = match request.update {
                        WalletPendingOverlayUpdate::Clear => WalletPendingOverlay::default(),
                        WalletPendingOverlayUpdate::PublicRows(rows) => {
                            let delta = match rows.payload {
                                WalletScanRowsPayload::Rows(rows) => {
                                    WalletLogDelta::from_rows(&rows, &cfg.scan_keys)
                                }
                                WalletScanRowsPayload::EmptyCoverage => WalletLogDelta {
                                    utxos: Vec::new(),
                                    nullifiers: Vec::new(),
                                    commitment_observations: Vec::new(),
                                },
                                #[cfg(test)]
                                WalletScanRowsPayload::IndexedDeltaForTest { delta } => *delta,
                            };
                            let confirmed = utxos.read().await;
                            if !actor_state
                                .pending_overlay_is_current(request.token, request.last_scanned)
                                || permit.revalidate().is_err()
                            {
                                actor_state.retire_job(request.token);
                                continue;
                            }
                            pending_overlay_from_delta(&cfg, &confirmed, delta)
                        }
                    };
                    let changed = match permit.replace_chain_pending_overlay(overlay).await {
                        Ok(changed) => changed,
                        Err(reason) => {
                            debug!(?reason, cache_key = %cfg.cache_key, "pending overlay update rejected before publication");
                            actor_state.retire_job(request.token);
                            continue;
                        }
                    };
                    if let Err(reason) = permit.notify_if_changed(changed) {
                        debug!(?reason, cache_key = %cfg.cache_key, "pending overlay revision publication rejected");
                    }
                    actor_state.retire_job(request.token);
                    drop(permit);
                }
                _ = tokio::time::sleep(WALLET_POI_REFRESH_INTERVAL), if poi_status_client.is_some() && backfill_complete_block.is_some() && actor_state.pending_reset.is_none() => {
                    let Some(client) = poi_status_client.as_ref() else {
                        continue;
                    };
                    let current_reset_generation = actor_state.reset_generation;
                    if cfg.manage_local_poi_cache
                        && last_live_tail_poll.elapsed() >= WALLET_POI_LIVE_TAIL_INTERVAL
                    {
                        sync_local_poi_live_tails(client, &cfg, &active_poi_list_keys).await;
                        last_live_tail_poll = Instant::now();
                    }
                    let now = now_epoch_secs();
                    let selection = WalletPoiRefreshSelection::RecoverableStale { now };
                    let refresh_needed = {
                        let locked = utxos.read().await;
                        wallet_poi_status_refresh_needed_for_selection(
                            &locked,
                            &active_poi_list_keys,
                            selection,
                        )
                    };
                    if !refresh_needed {
                        let authority = WalletPrivateMutationAuthority::new(
                            &worker_handle,
                            current_reset_generation,
                            &cancel,
                        );
                        if local_poi_caches_available_for_lists(&cfg, &active_poi_list_keys).await {
                            mark_valid_output_poi_recoveries_authorized(
                                &authority,
                                db.as_ref(),
                                cache_store.as_ref(),
                                &cfg,
                                &utxos,
                                &active_poi_list_keys,
                            ).await;
                            verify_submitted_pending_output_pois_with_config_authorized(
                                &authority,
                                client,
                                &cfg,
                                db.as_ref(),
                                cache_store.as_ref(),
                                &active_poi_list_keys,
                            ).await;
                        } else {
                            log_local_poi_cache_unavailable(&cfg, "periodic_poi_verify");
                        }
                        process_pending_output_poi_observations_authorized(
                            &authority,
                            db.as_ref(),
                            cache_store.as_ref(),
                            &cfg,
                            &active_poi_list_keys,
                            Some(client as &dyn PendingOutputPoiSubmitter),
                            false,
                        ).await;
                        continue;
                    }
                    publish_poi_refreshing(
                        &poi_refreshing_tx,
                        true,
                        &worker_handle,
                        current_reset_generation,
                        &cancel,
                    ).await;
                    if !local_poi_caches_ready_for_refresh(
                        &mut startup_artifact_warmup,
                        &cfg,
                        &active_poi_list_keys,
                        "periodic_poi_refresh",
                    ).await {
                        log_local_poi_cache_unavailable(&cfg, "periodic_poi_refresh");
                        publish_poi_refreshing(
                            &poi_refreshing_tx,
                            false,
                            &worker_handle,
                            current_reset_generation,
                            &cancel,
                        ).await;
                        continue;
                    }
                    let status_reader = wallet_poi_status_reader_source(client, &cfg);
                    let changed = match (WalletPoiStatusRefreshCommitRequest {
                        cache_store: cache_store.as_ref(),
                        cfg: &cfg,
                        utxos: &utxos,
                        worker_handle: &worker_handle,
                        last_scanned,
                        reset_generation: current_reset_generation,
                        actor_state: &mut actor_state,
                        persist_state: &mut persist_state,
                        ready_tx: &ready_tx,
                        readiness_tx: &readiness_tx,
                        status_reader: status_reader.as_reader(),
                        active_poi_list_keys: &active_poi_list_keys,
                        selection,
                        cancel: &cancel,
                    })
                    .commit()
                    .await
                    {
                        Ok(changed) => changed,
                        Err(reason) => {
                            warn!(?reason, cache_key = %cfg.cache_key, "periodic wallet POI status refresh rejected");
                            publish_poi_refreshing(
                                &poi_refreshing_tx,
                                false,
                                &worker_handle,
                                current_reset_generation,
                                &cancel,
                            ).await;
                            continue;
                        }
                    };
                    let authority = WalletPrivateMutationAuthority::new(
                        &worker_handle,
                        current_reset_generation,
                        &cancel,
                    );
                    let pending_verification = verify_submitted_pending_output_pois_with_config_authorized(
                        &authority,
                        client,
                        &cfg,
                        db.as_ref(),
                        cache_store.as_ref(),
                        &active_poi_list_keys,
                    ).await;
                    publish_poi_refreshing(
                        &poi_refreshing_tx,
                        false,
                        &worker_handle,
                        current_reset_generation,
                        &cancel,
                    ).await;
                    let recovered = recover_missing_output_pois_from_wallet(OutputPoiRecoveryRun {
                        authority: &authority,
                        db: db.as_ref(),
                        cache_store: cache_store.as_ref(),
                        cfg: &cfg,
                        rpcs: rpcs.as_ref(),
                        http_client: http_client.as_ref(),
                        indexed_artifact_source: indexed_artifact_source.as_ref(),
                        forest: &forest,
                        utxos: &utxos,
                        client,
                        active_list_keys: &active_poi_list_keys,
                        force_retry: false,
                    }).await;
                    authority
                        .notify_changed_if(recovered > 0, "periodic_output_poi_recovery")
                        .await;
                    process_pending_output_poi_observations_authorized(
                        &authority,
                        db.as_ref(),
                        cache_store.as_ref(),
                        &cfg,
                        &active_poi_list_keys,
                        Some(client as &dyn PendingOutputPoiSubmitter),
                        false,
                    ).await;
                    debug!(
                        cache_key = %cfg.cache_key,
                        changed,
                        pending_completed = pending_verification.completed,
                        pending_still_missing = pending_verification.pending,
                        pending_errors = pending_verification.errors,
                        "periodic wallet POI refresh pending context verification complete"
                    );
                }
                Some(event) = backfill_rx.recv() => {
                    match event {
                        BackfillEvent::Apply { apply, token, response } => {
                            if let Some(outcome) = try_commit_pending_reset!(true)
                                && !outcome.committed
                            {
                                actor_state.retire_job(token);
                                let reason = match outcome.result {
                                    WalletBackfillResetResult::Rejected { reason, .. } => reason,
                                    WalletBackfillResetResult::Accepted { .. } => WalletBackfillRejectReason::PersistenceFailed,
                                };
                                if reason == WalletBackfillRejectReason::PersistenceFailed {
                                    actor_state.fail_readiness(WalletReadinessError::PersistenceFailed);
                                }
                                publish_readiness!();
                                let result = WalletBackfillApplyResult::Rejected {
                                    committed_to: last_scanned,
                                    reason,
                                };
                                if let Err(err) = response.send(result) {
                                    debug!(?err, cache_key = %cfg.cache_key, "failed to send pending-reset wallet scan apply result");
                                }
                                continue;
                            }
                            let current_reset_generation = actor_state.reset_generation;
                            if let Err(reason) = actor_state.validate_active_sync_token(
                                token,
                                &worker_handle,
                                WalletActorJobKind::Backfill,
                                &cancel,
                            ) {
                                let result = WalletBackfillApplyResult::Rejected {
                                    committed_to: last_scanned,
                                    reason,
                                };
                                if let Err(err) = response.send(result) {
                                    debug!(?err, cache_key = %cfg.cache_key, "failed to send inactive wallet scan apply result");
                                }
                                continue;
                            }
                            let outcome = WalletScanCommitRequest {
                                db: db.as_ref(),
                                cache_store: cache_store.as_ref(),
                                cfg: &cfg,
                                utxos: &utxos,
                                worker_handle: &worker_handle,
                                apply,
                                current_reset_generation,
                                event_reset_generation: token.reset_generation(),
                                actor_state: &mut actor_state,
                                cancel: &cancel,
                                last_scanned: &mut last_scanned,
                                persist_state: &mut persist_state,
                                live_metadata_flush: &mut live_metadata_flush,
                                ready_tx: &ready_tx,
                                readiness_tx: &readiness_tx,
                                poi_submitter: None,
                                poi_status_reader: None,
                                active_poi_list_keys: &active_poi_list_keys,
                                refresh_poi_statuses: false,
                                mark_syncing_on_commit: true,
                                public_data_plane: &public_data_plane,
                            }
                            .commit()
                            .await;
                            actor_state.update_cursor(last_scanned);
                            if let Err(err) = response.send(outcome.result) {
                                debug!(?err, cache_key = %cfg.cache_key, "failed to send wallet scan apply result");
                            }
                        }
                        BackfillEvent::Target { target_block, token, response } => {
                            let current_reset_generation = actor_state.reset_generation;
                            if let Err(reason) = actor_state.validate_sync_token_current(
                                token,
                                &worker_handle,
                                &cancel,
                            ) {
                                let result = WalletBackfillFinishResult::Rejected {
                                    committed_to: last_scanned,
                                    reason,
                                };
                                if let Err(err) = response.send(result) {
                                    debug!(?err, cache_key = %cfg.cache_key, "failed to send stale wallet target result");
                                }
                                continue;
                            }
                            if let Some(outcome) = try_commit_pending_reset!(true)
                                && !outcome.committed
                            {
                                let reason = match outcome.result {
                                    WalletBackfillResetResult::Rejected { reason, .. } => reason,
                                    WalletBackfillResetResult::Accepted { .. } => WalletBackfillRejectReason::PersistenceFailed,
                                };
                                if reason == WalletBackfillRejectReason::PersistenceFailed {
                                    actor_state.fail_readiness(WalletReadinessError::PersistenceFailed);
                                }
                                publish_readiness!();
                                let result = WalletBackfillFinishResult::Rejected {
                                    committed_to: last_scanned,
                                    reason,
                                };
                                if let Err(err) = response.send(result) {
                                    debug!(?err, cache_key = %cfg.cache_key, "failed to send pending-reset wallet target result");
                                }
                                continue;
                            }
                            if !actor_state.accept_target(token, target_block) {
                                let result = WalletBackfillFinishResult::Rejected {
                                    committed_to: last_scanned,
                                    reason: WalletBackfillRejectReason::Shutdown,
                                };
                                if let Err(err) = response.send(result) {
                                    debug!(?err, cache_key = %cfg.cache_key, "failed to send inactive wallet target result");
                                }
                                continue;
                            }
                            if target_block == 0 || target_block > last_scanned {
                                let required_target = actor_state.target_block.unwrap_or(target_block);
                                debug!(
                                    cache_key = %cfg.cache_key,
                                    target_block = required_target,
                                    last_scanned,
                                    reset_generation = current_reset_generation,
                                    "wallet target recorded; cursor has not reached target"
                                );
                                backfill_complete_block = None;
                                publish_readiness!();
                                let result = WalletBackfillFinishResult::Accepted {
                                    committed_to: last_scanned,
                                    target_block: required_target,
                                    job: WalletAcceptedBackfillJob::for_actor_accepted_job(token),
                                };
                                if let Err(err) = response.send(result) {
                                    debug!(?err, cache_key = %cfg.cache_key, "failed to send pending wallet target result");
                                }
                                continue;
                            }
                            if let Some(required_target) =
                                actor_state.readiness_blocking_target(token, last_scanned)
                            {
                                actor_state.retire_job(token);
                                publish_readiness!();
                                let result = WalletBackfillFinishResult::Rejected {
                                    committed_to: last_scanned,
                                    reason: WalletBackfillRejectReason::TargetNotReached { target_block: required_target },
                                };
                                if let Err(err) = response.send(result) {
                                    debug!(?err, cache_key = %cfg.cache_key, "failed to send blocked wallet target result");
                                }
                                continue;
                            }
                            let finish_outcome = apply_backfill_done!(target_block);
                            let result = match finish_outcome {
                                WalletBackfillDoneOutcome::Finished => {
                                    actor_state.retire_job(token);
                                    publish_readiness!();
                                    if matches!(actor_state.readiness, WalletReadiness::Ready) {
                                        WalletBackfillFinishResult::Ready { committed_to: last_scanned }
                                    } else {
                                        WalletBackfillFinishResult::Rejected {
                                            committed_to: last_scanned,
                                            reason: WalletBackfillRejectReason::TargetNotReached {
                                                target_block: actor_state.target_block.unwrap_or(target_block),
                                            },
                                        }
                                    }
                                }
                                WalletBackfillDoneOutcome::Rejected(reason) => {
                                    if reason == WalletBackfillRejectReason::PersistenceFailed {
                                        actor_state.fail_job(
                                            token,
                                            WalletReadinessError::PersistenceFailed,
                                        );
                                    } else {
                                        actor_state.retire_job(token);
                                    }
                                    publish_readiness!();
                                    WalletBackfillFinishResult::Rejected {
                                        committed_to: last_scanned,
                                        reason,
                                    }
                                }
                            };
                            if let Err(err) = response.send(result) {
                                debug!(?err, cache_key = %cfg.cache_key, "failed to send wallet target result");
                            }
                        }
                        BackfillEvent::JobFailed { token, reason } => {
                            if actor_state.validate_active_sync_token(
                                token,
                                &worker_handle,
                                WalletActorJobKind::Backfill,
                                &cancel,
                            )
                            .is_ok()
                            {
                                actor_state.fail_job(token, reason);
                                publish_readiness!();
                            }
                        }
                        BackfillEvent::JobRetired { token } => {
                            if actor_state.validate_active_sync_token(
                                token,
                                &worker_handle,
                                WalletActorJobKind::Backfill,
                                &cancel,
                            )
                            .is_ok()
                            {
                                if actor_state.retire_job(token) {
                                    publish_readiness!();
                                }
                            }
                        }
                        BackfillEvent::Reset { token, from_block, replay_plan, response } => {
                            if let Err(reason) = actor_state.validate_reset_token_current(
                                token,
                                &worker_handle,
                                &cancel,
                            ) {
                                let result = WalletBackfillResetResult::Rejected {
                                    committed_to: last_scanned,
                                    reason,
                                };
                                if let Err(err) = response.send(result) {
                                    debug!(?err, cache_key = %cfg.cache_key, "failed to send shutdown wallet reset result");
                                }
                                continue;
                            }
                            let intent_id = token.intent_id();

                            if intent_id <= actor_state.highest_accepted_reset_intent {
                                let result = WalletBackfillResetResult::Rejected {
                                    committed_to: last_scanned,
                                    reason: WalletBackfillRejectReason::StaleResetIntent {
                                        accepted: actor_state.highest_accepted_reset_intent,
                                        actual: intent_id,
                                    },
                                };
                                if let Err(err) = response.send(result) {
                                    debug!(?err, cache_key = %cfg.cache_key, "failed to send stale wallet reset result");
                                }
                                continue;
                            }
                            let current_reset_generation = actor_state.reset_generation;
                            let acceptance_authority = WalletPrivateMutationAuthority::new(
                                &worker_handle,
                                current_reset_generation,
                                &cancel,
                            );
                            let acceptance_permit = match acceptance_authority.acquire().await {
                                Ok(permit) => permit,
                                Err(reason) => {
                                    let result = WalletBackfillResetResult::Rejected {
                                        committed_to: last_scanned,
                                        reason,
                                    };
                                    if let Err(err) = response.send(result) {
                                        debug!(?err, cache_key = %cfg.cache_key, "failed to send reset authority rejection");
                                    }
                                    continue;
                                }
                            };
                            let reset_from_block = actor_state.pending_reset
                                .map_or(from_block, |pending| pending.from_block.min(from_block));
                            let replay_plan = PendingWalletReset::merge_replay_plan(
                                actor_state.pending_reset,
                                replay_plan,
                            );
                            let next_reset_generation = current_reset_generation.wrapping_add(1);
                            let accepted_pending_reset = PendingWalletReset {
                                intent_id,
                                from_block: reset_from_block,
                                reset_generation: next_reset_generation,
                                replay_plan,
                            };
                            if let Err(reason) = acceptance_permit.revalidate() {
                                let result = WalletBackfillResetResult::Rejected {
                                    committed_to: last_scanned,
                                    reason,
                                };
                                if let Err(err) = response.send(result) {
                                    debug!(?err, cache_key = %cfg.cache_key, "failed to send reset authority rejection before persistence");
                                }
                                continue;
                            }
                            if let Err(err) = persist_wallet_reset_acceptance(
                                &acceptance_permit,
                                cache_store.as_ref(),
                                &cfg,
                                intent_id,
                                accepted_pending_reset,
                            ) {
                                warn!(?err, cache_key = %cfg.cache_key, intent_id, from_block, "failed to persist wallet reset acceptance");
                                let result = WalletBackfillResetResult::Rejected {
                                    committed_to: last_scanned,
                                    reason: WalletBackfillRejectReason::PersistenceFailed,
                                };
                                if let Err(err) = response.send(result) {
                                    debug!(?err, cache_key = %cfg.cache_key, "failed to send wallet reset persistence failure");
                                }
                                continue;
                            }
                            if let Err(reason) = acceptance_permit.set_reset_generation(next_reset_generation) {
                                let result = WalletBackfillResetResult::Rejected {
                                    committed_to: last_scanned,
                                    reason,
                                };
                                if let Err(err) = response.send(result) {
                                    debug!(?err, cache_key = %cfg.cache_key, "failed to send reset generation publication failure");
                                }
                                continue;
                            }
                            let clear_indexed_catch_up = actor_state.accept_reset(accepted_pending_reset);
                            if clear_indexed_catch_up
                                && let Err(reason) = acceptance_permit.publish_indexed_catch_up(None)
                            {
                                debug!(?reason, cache_key = %cfg.cache_key, "indexed wallet catch-up status reset clear rejected");
                            }
                            let _ = actor_state.reduce_and_publish_readiness(
                                &acceptance_permit,
                                &ready_tx,
                                &readiness_tx,
                            );
                            drop(acceptance_permit);
                            let outcome = try_commit_pending_reset!(false)
                                .expect("pending reset was installed before commit");
                            if let Err(err) = response.send(outcome.result) {
                                debug!(?err, cache_key = %cfg.cache_key, "failed to send wallet reset result");
                            }
                        }
                    }
                }
                result = live_rx.recv(), if backfill_complete_block.is_some() && actor_state.pending_reset.is_none() => {
                    match result {
                        Ok(batch) => {
                            if cfg.sync_to_block.is_some() {
                                continue;
                            }
                            if backfill_complete_block.is_none()
                                || batch.to_block <= last_scanned
                            {
                                live_receiver_lagged = false;
                                continue;
                            }
                            let expected_from_block = last_scanned.saturating_add(1);
                            if batch.from_block > expected_from_block {
                                warn!(
                                    cache_key = %cfg.cache_key,
                                    expected_from_block,
                                    batch_from_block = batch.from_block,
                                    batch_to_block = batch.to_block,
                                    live_receiver_lagged,
                                    "wallet live log gap detected; requesting backfill"
                                );
                                let current_reset_generation = actor_state.reset_generation;
                                let token = worker_handle.mint_sync_token(current_reset_generation);
                                if !actor_state.accept_job(token, WalletActorJobKind::Backfill) {
                                    actor_state
                                        .fail_readiness(WalletReadinessError::BackfillUnavailable);
                                    publish_readiness!();
                                    continue;
                                }
                                match backfill_tx.try_send(BackfillRequest::add(
                                    cfg.cache_key.clone(),
                                    expected_from_block,
                                    batch.to_block,
                                    true,
                                    expected_from_block,
                                    WalletBackfillLease::for_actor_accepted_job(
                                        WalletAcceptedBackfillJob::for_actor_accepted_job(token),
                                        backfill_sender.clone(),
                                    ),
                                )) {
                                    Ok(()) => {
                                        backfill_complete_block = None;
                                        live_rx = live_rx.resubscribe();
                                        publish_readiness!();
                                    }
                                    Err(err) => {
                                        warn!(?err, cache_key = %cfg.cache_key, "failed to request wallet live gap backfill");
                                        actor_state
                                            .fail_job(token, WalletReadinessError::BackfillUnavailable);
                                        publish_readiness!();
                                    }
                                }
                                live_receiver_lagged = false;
                                continue;
                            }
                            live_receiver_lagged = false;
                            let local_poi_cache_available = local_poi_caches_available_for_lists(
                                &cfg,
                                &active_poi_list_keys,
                            )
                            .await;
                            if !local_poi_cache_available {
                                log_local_poi_cache_unavailable(&cfg, "live_scan_poi_refresh");
                            }
                            let poi_submitter = poi_status_client
                                .as_ref()
                                .map(|client| client as &dyn PendingOutputPoiSubmitter);
                            let poi_status_reader = if local_poi_cache_available {
                                poi_status_client
                                    .as_ref()
                                    .map(|client| wallet_poi_status_reader_source(client, &cfg))
                            } else {
                                None
                            };
                            let apply = match WalletScanApply::rows_from_log_batch(
                                expected_from_block,
                                batch.to_block,
                                batch.clone(),
                                crate::types::PublicScanSource::Rpc,
                            ) {
                                Ok(apply) => apply,
                                Err(err) => {
                                    warn!(?err, cache_key = %cfg.cache_key, from_block = expected_from_block, to_block = batch.to_block, "failed to normalize wallet live logs");
                                    continue;
                                }
                            };
                            let current_reset_generation = actor_state.reset_generation;
                            let live_token = worker_handle.mint_sync_token(current_reset_generation);
                            if !actor_state.accept_job(live_token, WalletActorJobKind::Backfill) {
                                actor_state
                                    .fail_readiness(WalletReadinessError::BackfillUnavailable);
                                publish_readiness!();
                                continue;
                            }
                            let outcome = WalletScanCommitRequest {
                                db: db.as_ref(),
                                cache_store: cache_store.as_ref(),
                                cfg: &cfg,
                                utxos: &utxos,
                                worker_handle: &worker_handle,
                                apply,
                                current_reset_generation,
                                event_reset_generation: live_token.reset_generation(),
                                actor_state: &mut actor_state,
                                cancel: &cancel,
                                last_scanned: &mut last_scanned,
                                persist_state: &mut persist_state,
                                live_metadata_flush: &mut live_metadata_flush,
                                ready_tx: &ready_tx,
                                readiness_tx: &readiness_tx,
                                poi_submitter,
                                poi_status_reader: poi_status_reader.as_ref().map(WalletPoiStatusReaderSource::as_reader),
                                active_poi_list_keys: &active_poi_list_keys,
                                refresh_poi_statuses: local_poi_cache_available,
                                mark_syncing_on_commit: false,
                                public_data_plane: &public_data_plane,
                            }
                            .commit()
                            .await;
                            actor_state.update_cursor(last_scanned);
                            actor_state.retire_job(live_token);
                            publish_readiness!();
                            match outcome.result {
                                WalletBackfillApplyResult::Committed { .. }
                                | WalletBackfillApplyResult::AlreadyCovered { .. } => {
                                    if outcome.changed && let Some(client) = poi_status_client.as_ref() {
                                        let authority = WalletPrivateMutationAuthority::new(
                                            &worker_handle,
                                            current_reset_generation,
                                            &cancel,
                                        );
                                        if local_poi_cache_available {
                                            verify_submitted_pending_output_pois_with_config_authorized(
                                                &authority,
                                                client,
                                                &cfg,
                                                db.as_ref(),
                                                cache_store.as_ref(),
                                                &active_poi_list_keys,
                                            ).await;
                                            let recovered = recover_missing_output_pois_from_wallet(OutputPoiRecoveryRun {
                                                authority: &authority,
                                                db: db.as_ref(),
                                                cache_store: cache_store.as_ref(),
                                                cfg: &cfg,
                                                rpcs: rpcs.as_ref(),
                                                http_client: http_client.as_ref(),
                                                indexed_artifact_source: indexed_artifact_source.as_ref(),
                                                forest: &forest,
                                                utxos: &utxos,
                                                client,
                                                active_list_keys: &active_poi_list_keys,
                                                force_retry: false,
                                            }).await;
                                            authority
                                                .notify_changed_if(
                                                    recovered > 0,
                                                    "live_output_poi_recovery",
                                                )
                                                .await;
                                        }
                                    }
                                }
                                WalletBackfillApplyResult::Rejected { reason, .. } => {
                                    warn!(?reason, cache_key = %cfg.cache_key, "wallet live scan batch rejected");
                                }
                            }
                        }
                        Err(broadcast::error::RecvError::Closed) => break,
                        Err(broadcast::error::RecvError::Lagged(skipped)) => {
                            live_receiver_lagged = true;
                            warn!(cache_key = %cfg.cache_key, skipped, "wallet live log receiver lagged");
                        }
                    }
                }
            }
        }
        actor_state.mark_shutdown();
        publish_readiness!();
    }.instrument(tracing::info_span!("wallet", chain_id)));

    if wait_for_initial_reset_replay {
        let _ = startup_replay_rx.await;
    }

    Ok(handle)
}

pub(crate) fn wallet_cache_store(
    db: &Arc<DbStore>,
    cfg: &WalletConfig,
) -> Arc<dyn WalletCacheStore> {
    cfg.cache_store
        .clone()
        .unwrap_or_else(|| Arc::clone(db) as Arc<dyn WalletCacheStore>)
}

pub(super) fn dedupe_wallet_utxos(utxos: &mut Vec<WalletUtxo>) {
    let mut seen = HashSet::new();
    utxos.retain(|wallet_utxo| seen.insert((wallet_utxo.utxo.tree, wallet_utxo.utxo.position)));
}

fn wallet_utxo_counts(utxos: &[WalletUtxo]) -> (usize, usize) {
    let spent = utxos.iter().filter(|utxo| utxo.is_spent()).count();
    (utxos.len().saturating_sub(spent), spent)
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::collections::{BTreeMap, HashMap};
    use std::fs;
    use std::sync::{Arc, Mutex};
    use std::time::Duration;

    use alloy::primitives::{Address, FixedBytes, U256};
    use broadcaster_core::crypto::railgun::ViewingKeyData;
    use broadcaster_core::notes::Note;
    use broadcaster_core::query_rpc_pool::QueryRpcPool;
    use local_db::{DbConfig, DbStore, WalletMeta};
    use merkletree::tree::MerkleForest;
    use tokio::sync::{RwLock, broadcast, mpsc, oneshot, watch};
    use url::Url;

    use railgun_wallet::scan::{SpentNullifier, WalletLogDelta};
    use railgun_wallet::{Utxo, UtxoCommitmentKind, UtxoSource, WalletUtxo};

    use crate::chain::ChainPublicDataPlane;
    use crate::types::{
        BackfillRequest, ChainKey, LogBatch, PoiArtifactManifestSource, PoiArtifactSourceConfig,
        PoiReadSource, PublicDataPlaneEpoch, PublicScanReadScope, WalletConfig,
        WalletIndexedCatchUpSource, WalletIndexedCatchUpStatus,
    };

    fn test_public_data_plane(db: &Arc<DbStore>) -> ChainPublicDataPlane {
        ChainPublicDataPlane::new(
            Arc::clone(db),
            Arc::new(std::sync::atomic::AtomicU64::new(0)),
        )
    }

    const fn test_public_scan_read_scope() -> PublicScanReadScope {
        PublicScanReadScope::new(PublicDataPlaneEpoch::new(0))
    }

    #[derive(Debug, Clone, Copy, Default)]
    struct FailingCacheStoreState {
        store_calls: usize,
        meta_calls: usize,
        fail_next_store: bool,
        fail_next_meta: bool,
        fail_next_actor_state: bool,
        fail_next_actor_state_put: bool,
    }

    struct FailingCacheStore {
        db: Arc<DbStore>,
        state: Mutex<FailingCacheStoreState>,
        actor_state: Mutex<Option<WalletSyncActorStateRecord>>,
    }

    impl FailingCacheStore {
        fn new(db: Arc<DbStore>) -> Self {
            Self {
                db,
                state: Mutex::default(),
                actor_state: Mutex::default(),
            }
        }

        fn fail_next_store(&self) {
            self.state.lock().expect("cache state").fail_next_store = true;
        }

        fn fail_next_meta(&self) {
            self.state.lock().expect("cache state").fail_next_meta = true;
        }

        fn fail_next_actor_state(&self) {
            self.state
                .lock()
                .expect("cache state")
                .fail_next_actor_state = true;
        }

        fn fail_next_actor_state_put(&self) {
            self.state
                .lock()
                .expect("cache state")
                .fail_next_actor_state_put = true;
        }

        fn seed_actor_state(&self, state: WalletSyncActorStateRecord) {
            *self.actor_state.lock().expect("actor state") = Some(state);
        }

        fn actor_state(&self) -> Option<WalletSyncActorStateRecord> {
            self.actor_state.lock().expect("actor state").clone()
        }

        fn state(&self) -> FailingCacheStoreState {
            *self.state.lock().expect("cache state")
        }
    }

    impl WalletCacheStore for FailingCacheStore {
        fn commit_wallet_private_state(
            &self,
            commit: WalletPrivateCommit<'_>,
        ) -> Result<(), WalletCacheError> {
            if commit.replace_wallet_utxos() {
                let mut state = self.state.lock().expect("cache state");
                state.store_calls += 1;
                if state.fail_next_store {
                    state.fail_next_store = false;
                    return Err(WalletCacheError::Crypto);
                }
            } else {
                let mut state = self.state.lock().expect("cache state");
                state.meta_calls += 1;
                if state.fail_next_meta {
                    state.fail_next_meta = false;
                    return Err(WalletCacheError::Crypto);
                }
            }
            for record in commit.pending_output_context_updates() {
                self.db.put_pending_output_poi_context(record)?;
            }
            for output_commitment in commit.pending_output_context_deletes() {
                self.db.delete_pending_output_poi_context(
                    commit.pending_output_context_chain_id(),
                    commit.wallet_id(),
                    output_commitment,
                )?;
            }
            for record in commit.output_poi_recovery_updates() {
                self.db.put_output_poi_recovery(record)?;
            }
            if let Some(state) = commit.sync_actor_state() {
                self.db.put_wallet_sync_actor_state(state)?;
                *self.actor_state.lock().expect("actor state") = Some(state.clone());
            }
            Ok(())
        }

        fn load_wallet_utxos(&self, _wallet_id: &str) -> Result<Vec<WalletUtxo>, WalletCacheError> {
            Ok(Vec::new())
        }

        fn get_wallet_meta(
            &self,
            _wallet_id: &str,
        ) -> Result<Option<WalletMeta>, WalletCacheError> {
            Ok(None)
        }

        fn get_wallet_sync_actor_state(
            &self,
            _chain_id: u64,
            _wallet_id: &str,
        ) -> Result<Option<WalletSyncActorStateRecord>, WalletCacheError> {
            let mut state = self.state.lock().expect("cache state");
            if state.fail_next_actor_state {
                state.fail_next_actor_state = false;
                return Err(WalletCacheError::Crypto);
            }
            Ok(self.actor_state.lock().expect("actor state").clone())
        }

        fn put_wallet_sync_actor_state(
            &self,
            commit: WalletSyncActorStateCommit<'_>,
        ) -> Result<(), WalletCacheError> {
            let mut store_state = self.state.lock().expect("cache state");
            if store_state.fail_next_actor_state_put {
                store_state.fail_next_actor_state_put = false;
                return Err(WalletCacheError::Crypto);
            }
            drop(store_state);
            self.db.put_wallet_sync_actor_state(commit.state())?;
            *self.actor_state.lock().expect("actor state") = Some(commit.state().clone());
            Ok(())
        }
    }

    struct BlockingPoiStatusReader {
        started: tokio::sync::Mutex<Option<oneshot::Sender<()>>>,
        release: tokio::sync::Mutex<Option<oneshot::Receiver<()>>>,
        status: PoiStatus,
    }

    impl BlockingPoiStatusReader {
        fn new(started: oneshot::Sender<()>, release: oneshot::Receiver<()>) -> Self {
            Self {
                started: tokio::sync::Mutex::new(Some(started)),
                release: tokio::sync::Mutex::new(Some(release)),
                status: PoiStatus::Valid,
            }
        }
    }

    #[async_trait]
    impl PoiStatusReader for BlockingPoiStatusReader {
        async fn pois_per_list(
            &self,
            _txid_version: &str,
            _chain_type: u8,
            _chain_id: u64,
            list_keys: &[FixedBytes<32>],
            blinded_commitment_datas: &[BlindedCommitmentData],
        ) -> Result<BTreeMap<FixedBytes<32>, BTreeMap<FixedBytes<32>, PoiStatus>>, PoiError>
        {
            if let Some(started) = self.started.lock().await.take() {
                let _ = started.send(());
            }
            if let Some(release) = self.release.lock().await.take() {
                let _ = release.await;
            }
            Ok(blinded_commitment_datas
                .iter()
                .map(|data| {
                    (
                        data.blinded_commitment,
                        list_keys
                            .iter()
                            .copied()
                            .map(|list_key| (list_key, self.status))
                            .collect(),
                    )
                })
                .collect())
        }
    }

    async fn send_apply(
        handle: &WalletHandle,
        sender: &mpsc::Sender<BackfillEvent>,
        apply: WalletScanApply,
        reset_generation: u64,
    ) -> WalletBackfillApplyResult {
        send_apply_token(sender, apply, handle.mint_sync_token(reset_generation)).await
    }

    async fn send_apply_token(
        sender: &mpsc::Sender<BackfillEvent>,
        apply: WalletScanApply,
        token: WalletSyncToken,
    ) -> WalletBackfillApplyResult {
        let _ = send_target_token(sender, apply.to_block, token).await;
        let (response, result_rx) = oneshot::channel();
        sender
            .send(BackfillEvent::Apply {
                apply,
                token,
                response,
            })
            .await
            .expect("send apply");
        let result = result_rx.await.expect("apply response");
        if matches!(result, WalletBackfillApplyResult::Rejected { .. }) {
            sender
                .send(BackfillEvent::JobRetired { token })
                .await
                .expect("retire rejected apply job");
            tokio::task::yield_now().await;
        }
        result
    }

    async fn send_target(
        handle: &WalletHandle,
        sender: &mpsc::Sender<BackfillEvent>,
        target_block: u64,
        reset_generation: u64,
    ) -> WalletBackfillFinishResult {
        send_target_token(
            sender,
            target_block,
            handle.mint_sync_token(reset_generation),
        )
        .await
    }

    async fn send_target_token(
        sender: &mpsc::Sender<BackfillEvent>,
        target_block: u64,
        token: WalletSyncToken,
    ) -> WalletBackfillFinishResult {
        let (response, result_rx) = oneshot::channel();
        sender
            .send(BackfillEvent::Target {
                target_block,
                token,
                response,
            })
            .await
            .expect("send target");
        result_rx.await.expect("target response")
    }

    fn assert_target_accepted(
        result: WalletBackfillFinishResult,
        token: WalletSyncToken,
        committed_to: u64,
        target_block: u64,
    ) {
        match result {
            WalletBackfillFinishResult::Accepted {
                committed_to: actual_committed_to,
                target_block: actual_target_block,
                job,
            } => {
                assert_eq!(actual_committed_to, committed_to);
                assert_eq!(actual_target_block, target_block);
                assert_eq!(job.token(), token);
            }
            other => panic!("expected accepted target, got {other:?}"),
        }
    }

    const fn test_reset_token(intent_id: u64) -> WalletResetToken {
        WalletResetToken::for_test(1, 1, intent_id)
    }

    async fn send_reset(
        sender: &mpsc::Sender<BackfillEvent>,
        intent_id: u64,
        from_block: u64,
    ) -> WalletBackfillResetResult {
        let (response, result_rx) = oneshot::channel();
        sender
            .send(BackfillEvent::Reset {
                token: test_reset_token(intent_id),
                from_block,
                replay_plan: WalletResetReplayPlan::new(0, 0, true),
                response,
            })
            .await
            .expect("send reset");
        result_rx.await.expect("reset response")
    }

    fn logs_apply(from_block: u64, to_block: u64) -> WalletScanApply {
        WalletScanApply::rows_from_log_batch(
            from_block,
            to_block,
            logs_payload(from_block, to_block),
            crate::types::PublicScanSource::Rpc,
        )
        .expect("normalize empty log payload")
    }

    fn logs_payload(from_block: u64, to_block: u64) -> Arc<LogBatch> {
        Arc::new(LogBatch {
            from_block,
            to_block,
            logs: Vec::new(),
            block_timestamps: HashMap::new(),
            to_block_hash: None,
            read_scope: test_public_scan_read_scope(),
        })
    }

    fn indexed_delta_batch(
        from_block: u64,
        to_block: u64,
        delta: WalletLogDelta,
    ) -> WalletScanApply {
        WalletScanApply::indexed_delta_for_test(
            from_block,
            to_block,
            delta,
            test_public_scan_read_scope(),
            WalletIndexedCatchUpSource::IndexedArtifacts,
        )
    }

    fn pending_overlay_rows_from_delta(
        from_block: u64,
        to_block: u64,
        delta: WalletLogDelta,
    ) -> WalletScanRows {
        indexed_delta_batch(from_block, to_block, delta).rows
    }

    fn empty_delta() -> WalletLogDelta {
        WalletLogDelta {
            utxos: Vec::new(),
            nullifiers: Vec::new(),
            commitment_observations: Vec::new(),
        }
    }

    #[tokio::test]
    async fn wallet_worker_applies_live_batch_queued_before_done() {
        let root_dir = temp_db_root("wallet-worker-live-before-done");
        let db = Arc::new(
            DbStore::open(DbConfig {
                root_dir: root_dir.clone(),
            })
            .expect("open db"),
        );
        let (live_tx, live_rx) = broadcast::channel(8);
        let (backfill_tx, backfill_rx) = mpsc::channel(8);
        let (backfill_request_tx, _backfill_request_rx) = mpsc::channel(8);
        let cancel = CancellationToken::new();
        let handle = spawn_wallet_worker(
            WalletWorkerServices {
                db: Arc::clone(&db),
                rpcs: Arc::new(QueryRpcPool::new(
                    vec![Url::parse("http://127.0.0.1:1").expect("rpc url")],
                    Duration::from_secs(1),
                )),
                http_client: None,
                indexed_artifact_source: None,
                forest: Arc::new(RwLock::new(MerkleForest::new())),
                backfill_tx: backfill_request_tx,
                backfill_sender: backfill_tx.clone(),
                public_data_plane: test_public_data_plane(&db),
            },
            wallet_config(),
            1,
            live_rx,
            backfill_rx,
            cancel.clone(),
            Vec::new(),
            100,
        )
        .await
        .expect("spawn wallet worker");
        live_tx
            .send(Arc::new(LogBatch {
                from_block: 101,
                to_block: 101,
                logs: Vec::new(),
                block_timestamps: HashMap::new(),
                to_block_hash: None,
                read_scope: test_public_scan_read_scope(),
            }))
            .expect("live receiver");
        tokio::task::yield_now().await;
        assert_eq!(handle.last_scanned(), 100);

        let initial_token = handle.mint_sync_token(0);
        assert_eq!(
            send_target_token(&backfill_tx, 100, initial_token).await,
            WalletBackfillFinishResult::Ready { committed_to: 100 }
        );
        tokio::time::timeout(Duration::from_secs(1), async {
            while handle.last_scanned() != 101 {
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .expect("queued live batch applied after done");

        cancel.cancel();
        drop(db);
        fs::remove_dir_all(root_dir).expect("remove temp db dir");
    }

    #[tokio::test]
    async fn wallet_worker_rejects_live_batch_when_metadata_persist_fails() {
        let root_dir = temp_db_root("wallet-worker-live-persist-failure");
        let db = Arc::new(
            DbStore::open(DbConfig {
                root_dir: root_dir.clone(),
            })
            .expect("open db"),
        );
        let cache_store = Arc::new(FailingCacheStore::new(Arc::clone(&db)));
        let mut cfg = wallet_config();
        cfg.cache_store = Some(cache_store.clone());
        let (live_tx, live_rx) = broadcast::channel(8);
        let (backfill_tx, backfill_rx) = mpsc::channel(8);
        let (backfill_request_tx, _backfill_request_rx) = mpsc::channel(8);
        let cancel = CancellationToken::new();
        let handle = spawn_wallet_worker(
            WalletWorkerServices {
                db: Arc::clone(&db),
                rpcs: Arc::new(QueryRpcPool::new(
                    vec![Url::parse("http://127.0.0.1:1").expect("rpc url")],
                    Duration::from_secs(1),
                )),
                http_client: None,
                indexed_artifact_source: None,
                forest: Arc::new(RwLock::new(MerkleForest::new())),
                backfill_tx: backfill_request_tx,
                backfill_sender: backfill_tx.clone(),
                public_data_plane: test_public_data_plane(&db),
            },
            cfg,
            1,
            live_rx,
            backfill_rx,
            cancel.clone(),
            Vec::new(),
            100,
        )
        .await
        .expect("spawn wallet worker");

        let initial_token = handle.mint_sync_token(0);
        assert_eq!(
            send_target_token(&backfill_tx, 100, initial_token).await,
            WalletBackfillFinishResult::Ready { committed_to: 100 }
        );
        cache_store.fail_next_meta();
        live_tx
            .send(Arc::new(LogBatch {
                from_block: 101,
                to_block: 101,
                logs: Vec::new(),
                block_timestamps: HashMap::new(),
                to_block_hash: None,
                read_scope: test_public_scan_read_scope(),
            }))
            .expect("live receiver");

        tokio::time::timeout(Duration::from_secs(1), async {
            while !matches!(
                handle.readiness(),
                WalletReadiness::Failed(WalletReadinessError::PersistenceFailed)
            ) {
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .expect("live persist failure observed");

        assert_eq!(handle.last_scanned(), 100);
        assert!(!*handle.ready_rx.borrow());
        assert_eq!(cache_store.state().meta_calls, 1);

        cancel.cancel();
        drop(db);
        fs::remove_dir_all(root_dir).expect("remove temp db dir");
    }

    #[tokio::test]
    async fn wallet_backfill_partial_indexed_tail_leaves_wallet_non_ready() {
        let root_dir = temp_db_root("wallet-partial-indexed-tail-non-ready");
        let db = Arc::new(
            DbStore::open(DbConfig {
                root_dir: root_dir.clone(),
            })
            .expect("open db"),
        );
        let (_live_tx, live_rx) = broadcast::channel(8);
        let (backfill_tx, backfill_rx) = mpsc::channel(8);
        let (backfill_request_tx, _backfill_request_rx) = mpsc::channel(8);
        let cancel = CancellationToken::new();
        let handle = spawn_wallet_worker(
            WalletWorkerServices {
                db: Arc::clone(&db),
                rpcs: Arc::new(QueryRpcPool::new(
                    vec![Url::parse("http://127.0.0.1:1").expect("rpc url")],
                    Duration::from_secs(1),
                )),
                http_client: None,
                indexed_artifact_source: None,
                forest: Arc::new(RwLock::new(MerkleForest::new())),
                backfill_tx: backfill_request_tx,
                backfill_sender: backfill_tx.clone(),
                public_data_plane: test_public_data_plane(&db),
            },
            wallet_config(),
            1,
            live_rx,
            backfill_rx,
            cancel.clone(),
            Vec::new(),
            900,
        )
        .await
        .expect("spawn wallet worker");

        assert_eq!(
            send_target(&handle, &backfill_tx, 900, 0).await,
            WalletBackfillFinishResult::Ready { committed_to: 900 }
        );
        assert_eq!(handle.readiness(), WalletReadiness::Ready);
        assert_eq!(
            send_apply(
                &handle,
                &backfill_tx,
                indexed_delta_batch(901, 950, empty_delta()),
                0
            )
            .await,
            WalletBackfillApplyResult::Committed { committed_to: 950 }
        );

        tokio::time::timeout(Duration::from_secs(1), async {
            while handle.last_scanned() != 950 {
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .expect("partial indexed tail applied");
        assert_eq!(handle.readiness(), WalletReadiness::Syncing);
        assert!(!*handle.ready_rx.borrow());
        assert!(matches!(
            send_target(&handle, &backfill_tx, 1000, 0).await,
            WalletBackfillFinishResult::Accepted {
                committed_to: 950,
                target_block: 1000,
                ..
            }
        ));
        assert_eq!(handle.readiness(), WalletReadiness::Syncing);

        cancel.cancel();
        drop(db);
        fs::remove_dir_all(root_dir).expect("remove temp db dir");
    }

    #[tokio::test]
    async fn wallet_worker_applies_indexed_tail_delta_after_prior_wallet_delta() {
        let root_dir = temp_db_root("wallet-worker-indexed-tail-order");
        let db = Arc::new(
            DbStore::open(DbConfig {
                root_dir: root_dir.clone(),
            })
            .expect("open db"),
        );
        let (_live_tx, live_rx) = broadcast::channel(8);
        let (backfill_tx, backfill_rx) = mpsc::channel(8);
        let (backfill_request_tx, _backfill_request_rx) = mpsc::channel(8);
        let cancel = CancellationToken::new();
        let handle = spawn_wallet_worker(
            WalletWorkerServices {
                db: Arc::clone(&db),
                rpcs: Arc::new(QueryRpcPool::new(
                    vec![Url::parse("http://127.0.0.1:1").expect("rpc url")],
                    Duration::from_secs(1),
                )),
                http_client: None,
                indexed_artifact_source: None,
                forest: Arc::new(RwLock::new(MerkleForest::new())),
                backfill_tx: backfill_request_tx,
                backfill_sender: backfill_tx.clone(),
                public_data_plane: test_public_data_plane(&db),
            },
            wallet_config(),
            1,
            live_rx,
            backfill_rx,
            cancel.clone(),
            Vec::new(),
            100,
        )
        .await
        .expect("spawn wallet worker");
        let wallet_utxo = test_wallet_utxo(105, 7);
        let nullifier = wallet_utxo.utxo.nullifier(U256::ZERO);

        assert_eq!(
            send_apply(
                &handle,
                &backfill_tx,
                indexed_delta_batch(
                    101,
                    110,
                    WalletLogDelta {
                        utxos: vec![wallet_utxo.utxo.clone()],
                        nullifiers: Vec::new(),
                        commitment_observations: Vec::new(),
                    },
                ),
                0,
            )
            .await,
            WalletBackfillApplyResult::Committed { committed_to: 110 }
        );
        assert_eq!(
            send_apply(
                &handle,
                &backfill_tx,
                indexed_delta_batch(
                    111,
                    120,
                    WalletLogDelta {
                        utxos: Vec::new(),
                        nullifiers: vec![SpentNullifier {
                            tree: wallet_utxo.utxo.tree,
                            nullifier,
                            source: source(120, 0x78),
                        }],
                        commitment_observations: Vec::new(),
                    },
                ),
                0,
            )
            .await,
            WalletBackfillApplyResult::Committed { committed_to: 120 }
        );

        tokio::time::timeout(Duration::from_secs(1), async {
            while handle.last_scanned() != 120 {
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .expect("indexed deltas applied");

        let snapshot = handle.utxos.read().await;
        assert_eq!(snapshot.len(), 1);
        assert!(snapshot[0].spent.is_some());

        cancel.cancel();
        drop(snapshot);
        drop(db);
        fs::remove_dir_all(root_dir).expect("remove temp db dir");
    }

    #[tokio::test]
    async fn wallet_worker_rejects_persistence_failure_without_swapping_state() {
        let root_dir = temp_db_root("wallet-worker-apply-persist-failure");
        let db = Arc::new(
            DbStore::open(DbConfig {
                root_dir: root_dir.clone(),
            })
            .expect("open db"),
        );
        let cache_store = Arc::new(FailingCacheStore::new(Arc::clone(&db)));
        cache_store.fail_next_store();
        let mut cfg = wallet_config();
        cfg.cache_store = Some(cache_store.clone());
        let (_live_tx, live_rx) = broadcast::channel(8);
        let (backfill_tx, backfill_rx) = mpsc::channel(8);
        let (backfill_request_tx, _backfill_request_rx) = mpsc::channel(8);
        let cancel = CancellationToken::new();
        let handle = spawn_wallet_worker(
            WalletWorkerServices {
                db: Arc::clone(&db),
                rpcs: Arc::new(QueryRpcPool::new(
                    vec![Url::parse("http://127.0.0.1:1").expect("rpc url")],
                    Duration::from_secs(1),
                )),
                http_client: None,
                indexed_artifact_source: None,
                forest: Arc::new(RwLock::new(MerkleForest::new())),
                backfill_tx: backfill_request_tx,
                backfill_sender: backfill_tx.clone(),
                public_data_plane: test_public_data_plane(&db),
            },
            cfg,
            1,
            live_rx,
            backfill_rx,
            cancel.clone(),
            Vec::new(),
            100,
        )
        .await
        .expect("spawn wallet worker");

        assert_eq!(
            send_apply(
                &handle,
                &backfill_tx,
                indexed_delta_batch(
                    101,
                    110,
                    WalletLogDelta {
                        utxos: vec![test_wallet_utxo(105, 7).utxo],
                        nullifiers: Vec::new(),
                        commitment_observations: Vec::new(),
                    },
                ),
                0,
            )
            .await,
            WalletBackfillApplyResult::Rejected {
                committed_to: 100,
                reason: WalletBackfillRejectReason::PersistenceFailed,
            }
        );

        assert_eq!(handle.last_scanned(), 100);
        assert_eq!(
            handle.readiness(),
            WalletReadiness::Failed(WalletReadinessError::PersistenceFailed)
        );
        assert!(!*handle.ready_rx.borrow());
        assert_eq!(*handle.rev_rx.borrow(), 0);
        assert!(handle.utxos.read().await.is_empty());
        assert_eq!(cache_store.state().store_calls, 1);

        cancel.cancel();
        drop(db);
        fs::remove_dir_all(root_dir).expect("remove temp db dir");
    }

    #[tokio::test]
    async fn wallet_scan_persist_failure_keeps_spent_pending_output_context() {
        let root_dir = temp_db_root("wallet-worker-spent-pending-context-persist-failure");
        let db = Arc::new(
            DbStore::open(DbConfig {
                root_dir: root_dir.clone(),
            })
            .expect("open db"),
        );
        let cache_store = Arc::new(FailingCacheStore::new(Arc::clone(&db)));
        cache_store.fail_next_store();
        let mut cfg = wallet_config();
        cfg.cache_store = Some(cache_store.clone());
        let (_live_tx, live_rx) = broadcast::channel(8);
        let (backfill_tx, backfill_rx) = mpsc::channel(8);
        let (backfill_request_tx, _backfill_request_rx) = mpsc::channel(8);
        let cancel = CancellationToken::new();
        let wallet_utxo = test_wallet_utxo(105, 7);
        let output_commitment = wallet_utxo.utxo.poi.commitment;
        db.put_pending_output_poi_context(&pending_output_context_for_wallet_utxo(
            &cfg,
            &wallet_utxo,
        ))
        .expect("store pending context");
        let nullifier = wallet_utxo.utxo.nullifier(U256::ZERO);
        let handle = spawn_wallet_worker(
            WalletWorkerServices {
                db: Arc::clone(&db),
                rpcs: Arc::new(QueryRpcPool::new(
                    vec![Url::parse("http://127.0.0.1:1").expect("rpc url")],
                    Duration::from_secs(1),
                )),
                http_client: None,
                indexed_artifact_source: None,
                forest: Arc::new(RwLock::new(MerkleForest::new())),
                backfill_tx: backfill_request_tx,
                backfill_sender: backfill_tx.clone(),
                public_data_plane: test_public_data_plane(&db),
            },
            cfg.clone(),
            1,
            live_rx,
            backfill_rx,
            cancel.clone(),
            vec![wallet_utxo.clone()],
            100,
        )
        .await
        .expect("spawn wallet worker");

        assert_eq!(
            send_apply(
                &handle,
                &backfill_tx,
                indexed_delta_batch(
                    101,
                    110,
                    WalletLogDelta {
                        utxos: Vec::new(),
                        nullifiers: vec![SpentNullifier {
                            tree: wallet_utxo.utxo.tree,
                            nullifier,
                            source: source(110, 0x77),
                        }],
                        commitment_observations: Vec::new(),
                    },
                ),
                0,
            )
            .await,
            WalletBackfillApplyResult::Rejected {
                committed_to: 100,
                reason: WalletBackfillRejectReason::PersistenceFailed,
            }
        );

        assert_eq!(handle.last_scanned(), 100);
        let snapshot = handle.utxos.read().await;
        assert_eq!(snapshot.len(), 1);
        assert!(snapshot[0].spent.is_none());
        assert!(
            db.get_pending_output_poi_context(
                cfg.chain.chain_id,
                &cfg.cache_key,
                &output_commitment
            )
            .expect("load pending context")
            .is_some()
        );

        cancel.cancel();
        drop(snapshot);
        drop(db);
        fs::remove_dir_all(root_dir).expect("remove temp db dir");
    }

    #[tokio::test]
    async fn wallet_scan_commit_discards_spent_pending_context_with_progress() {
        let root_dir = temp_db_root("wallet-worker-spent-pending-context-commit");
        let db = Arc::new(
            DbStore::open(DbConfig {
                root_dir: root_dir.clone(),
            })
            .expect("open db"),
        );
        let cfg = wallet_config();
        let (_live_tx, live_rx) = broadcast::channel(8);
        let (backfill_tx, backfill_rx) = mpsc::channel(8);
        let (backfill_request_tx, _backfill_request_rx) = mpsc::channel(8);
        let cancel = CancellationToken::new();
        let wallet_utxo = test_wallet_utxo(105, 7);
        let output_commitment = wallet_utxo.utxo.poi.commitment;
        db.put_pending_output_poi_context(&pending_output_context_for_wallet_utxo(
            &cfg,
            &wallet_utxo,
        ))
        .expect("store pending context");
        let nullifier = wallet_utxo.utxo.nullifier(U256::ZERO);
        let handle = spawn_wallet_worker(
            WalletWorkerServices {
                db: Arc::clone(&db),
                rpcs: Arc::new(QueryRpcPool::new(
                    vec![Url::parse("http://127.0.0.1:1").expect("rpc url")],
                    Duration::from_secs(1),
                )),
                http_client: None,
                indexed_artifact_source: None,
                forest: Arc::new(RwLock::new(MerkleForest::new())),
                backfill_tx: backfill_request_tx,
                backfill_sender: backfill_tx.clone(),
                public_data_plane: test_public_data_plane(&db),
            },
            cfg.clone(),
            1,
            live_rx,
            backfill_rx,
            cancel.clone(),
            vec![wallet_utxo.clone()],
            100,
        )
        .await
        .expect("spawn wallet worker");

        assert_eq!(
            send_apply(
                &handle,
                &backfill_tx,
                indexed_delta_batch(
                    101,
                    110,
                    WalletLogDelta {
                        utxos: Vec::new(),
                        nullifiers: vec![SpentNullifier {
                            tree: wallet_utxo.utxo.tree,
                            nullifier,
                            source: source(110, 0x77),
                        }],
                        commitment_observations: Vec::new(),
                    },
                ),
                0,
            )
            .await,
            WalletBackfillApplyResult::Committed { committed_to: 110 }
        );

        assert_eq!(handle.last_scanned(), 110);
        let snapshot = handle.utxos.read().await;
        assert_eq!(snapshot.len(), 1);
        assert!(snapshot[0].spent.is_some());
        assert!(
            db.get_pending_output_poi_context(
                cfg.chain.chain_id,
                &cfg.cache_key,
                &output_commitment
            )
            .expect("load pending context")
            .is_none()
        );

        cancel.cancel();
        drop(snapshot);
        drop(db);
        fs::remove_dir_all(root_dir).expect("remove temp db dir");
    }

    #[tokio::test]
    async fn wallet_pending_overlay_update_runs_through_actor_mailbox() {
        let root_dir = temp_db_root("wallet-pending-overlay-mailbox");
        let db = Arc::new(
            DbStore::open(DbConfig {
                root_dir: root_dir.clone(),
            })
            .expect("open db"),
        );
        let (_live_tx, live_rx) = broadcast::channel(8);
        let (backfill_tx, backfill_rx) = mpsc::channel(8);
        let (backfill_request_tx, _backfill_request_rx) = mpsc::channel(8);
        let cancel = CancellationToken::new();
        let wallet_utxo = test_wallet_utxo(105, 7);
        let handle = spawn_wallet_worker(
            WalletWorkerServices {
                db: Arc::clone(&db),
                rpcs: Arc::new(QueryRpcPool::new(
                    vec![Url::parse("http://127.0.0.1:1").expect("rpc url")],
                    Duration::from_secs(1),
                )),
                http_client: None,
                indexed_artifact_source: None,
                forest: Arc::new(RwLock::new(MerkleForest::new())),
                backfill_tx: backfill_request_tx,
                backfill_sender: backfill_tx.clone(),
                public_data_plane: test_public_data_plane(&db),
            },
            wallet_config(),
            1,
            live_rx,
            backfill_rx,
            cancel.clone(),
            vec![wallet_utxo.clone()],
            100,
        )
        .await
        .expect("spawn wallet worker");
        let spent_source = source(101, 0xaa);
        let pending_spent = WalletPendingSpent {
            tree: wallet_utxo.utxo.tree,
            position: wallet_utxo.utxo.position,
            tx_hash: Some(spent_source.tx_hash),
            block_number: Some(spent_source.block_number),
            block_timestamp: Some(spent_source.block_timestamp),
        };

        assert!(
            handle
                .request_pending_overlay_rows(
                    pending_overlay_rows_from_delta(
                        101,
                        101,
                        WalletLogDelta {
                            utxos: Vec::new(),
                            nullifiers: vec![SpentNullifier {
                                tree: wallet_utxo.utxo.tree,
                                nullifier: wallet_utxo
                                    .utxo
                                    .nullifier(wallet_config().scan_keys.nullifying_key),
                                source: spent_source,
                            }],
                            commitment_observations: Vec::new(),
                        },
                    ),
                    0,
                    100,
                )
                .await
        );

        tokio::time::timeout(Duration::from_secs(1), async {
            loop {
                let overlay = handle.pending_overlay().await;
                if overlay.pending_spent == vec![pending_spent.clone()] {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .expect("pending overlay update applied through mailbox");

        cancel.cancel();
        drop(db);
        fs::remove_dir_all(root_dir).expect("remove temp db dir");
    }

    #[tokio::test]
    async fn wallet_pending_overlay_rejects_older_job_after_newer_overlay() {
        let root_dir = temp_db_root("wallet-pending-overlay-reverse-order");
        let db = Arc::new(
            DbStore::open(DbConfig {
                root_dir: root_dir.clone(),
            })
            .expect("open db"),
        );
        let (_live_tx, live_rx) = broadcast::channel(8);
        let (backfill_tx, backfill_rx) = mpsc::channel(8);
        let (backfill_request_tx, _backfill_request_rx) = mpsc::channel(8);
        let cancel = CancellationToken::new();
        let wallet_utxo = test_wallet_utxo(105, 7);
        let handle = spawn_wallet_worker(
            WalletWorkerServices {
                db: Arc::clone(&db),
                rpcs: Arc::new(QueryRpcPool::new(
                    vec![Url::parse("http://127.0.0.1:1").expect("rpc url")],
                    Duration::from_secs(1),
                )),
                http_client: None,
                indexed_artifact_source: None,
                forest: Arc::new(RwLock::new(MerkleForest::new())),
                backfill_tx: backfill_request_tx,
                backfill_sender: backfill_tx.clone(),
                public_data_plane: test_public_data_plane(&db),
            },
            wallet_config(),
            1,
            live_rx,
            backfill_rx,
            cancel.clone(),
            vec![wallet_utxo.clone()],
            100,
        )
        .await
        .expect("spawn wallet worker");
        let older_token = handle.mint_sync_token(0);
        let newer_token = handle.mint_sync_token(0);
        let older_source = source(101, 0xaa);
        let newer_source = source(102, 0xbb);
        let older_spent = WalletPendingSpent {
            tree: wallet_utxo.utxo.tree,
            position: wallet_utxo.utxo.position,
            tx_hash: Some(older_source.tx_hash),
            block_number: Some(older_source.block_number),
            block_timestamp: Some(older_source.block_timestamp),
        };
        let newer_spent = WalletPendingSpent {
            tx_hash: Some(newer_source.tx_hash),
            block_number: Some(newer_source.block_number),
            block_timestamp: Some(newer_source.block_timestamp),
            ..older_spent.clone()
        };
        let nullifier = wallet_utxo
            .utxo
            .nullifier(wallet_config().scan_keys.nullifying_key);

        handle
            .pending_overlay_tx
            .send(WalletPendingOverlayRequest {
                update: WalletPendingOverlayUpdate::PublicRows(pending_overlay_rows_from_delta(
                    102,
                    102,
                    WalletLogDelta {
                        utxos: Vec::new(),
                        nullifiers: vec![SpentNullifier {
                            tree: wallet_utxo.utxo.tree,
                            nullifier,
                            source: newer_source,
                        }],
                        commitment_observations: Vec::new(),
                    },
                )),
                token: newer_token,
                reset_generation: 0,
                last_scanned: 100,
            })
            .await
            .expect("send newer overlay");

        tokio::time::timeout(Duration::from_secs(1), async {
            loop {
                let overlay = handle.pending_overlay().await;
                if overlay.pending_spent == vec![newer_spent.clone()] {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .expect("newer pending overlay applied");

        handle
            .pending_overlay_tx
            .send(WalletPendingOverlayRequest {
                update: WalletPendingOverlayUpdate::PublicRows(pending_overlay_rows_from_delta(
                    101,
                    101,
                    WalletLogDelta {
                        utxos: Vec::new(),
                        nullifiers: vec![SpentNullifier {
                            tree: wallet_utxo.utxo.tree,
                            nullifier,
                            source: older_source,
                        }],
                        commitment_observations: Vec::new(),
                    },
                )),
                token: older_token,
                reset_generation: 0,
                last_scanned: 100,
            })
            .await
            .expect("send older overlay");
        tokio::time::sleep(Duration::from_millis(50)).await;

        assert_eq!(
            handle.pending_overlay().await.pending_spent,
            vec![newer_spent]
        );

        cancel.cancel();
        drop(db);
        fs::remove_dir_all(root_dir).expect("remove temp db dir");
    }

    #[tokio::test]
    async fn wallet_retired_backfill_job_rejects_late_apply() {
        let root_dir = temp_db_root("wallet-retired-job-late-apply");
        let db = Arc::new(
            DbStore::open(DbConfig {
                root_dir: root_dir.clone(),
            })
            .expect("open db"),
        );
        let (_live_tx, live_rx) = broadcast::channel(8);
        let (backfill_tx, backfill_rx) = mpsc::channel(8);
        let (backfill_request_tx, _backfill_request_rx) = mpsc::channel(8);
        let cancel = CancellationToken::new();
        let handle = spawn_wallet_worker(
            WalletWorkerServices {
                db: Arc::clone(&db),
                rpcs: Arc::new(QueryRpcPool::new(
                    vec![Url::parse("http://127.0.0.1:1").expect("rpc url")],
                    Duration::from_secs(1),
                )),
                http_client: None,
                indexed_artifact_source: None,
                forest: Arc::new(RwLock::new(MerkleForest::new())),
                backfill_tx: backfill_request_tx,
                backfill_sender: backfill_tx.clone(),
                public_data_plane: test_public_data_plane(&db),
            },
            wallet_config(),
            1,
            live_rx,
            backfill_rx,
            cancel.clone(),
            Vec::new(),
            100,
        )
        .await
        .expect("spawn wallet worker");
        let token = handle.mint_sync_token(0);

        assert_target_accepted(
            send_target_token(&backfill_tx, 150, token).await,
            token,
            100,
            150,
        );
        backfill_tx
            .send(BackfillEvent::JobRetired { token })
            .await
            .expect("retire job");
        tokio::task::yield_now().await;

        let (response, result_rx) = oneshot::channel();
        backfill_tx
            .send(BackfillEvent::Apply {
                apply: indexed_delta_batch(
                    101,
                    110,
                    WalletLogDelta {
                        utxos: Vec::new(),
                        nullifiers: Vec::new(),
                        commitment_observations: Vec::new(),
                    },
                ),
                token,
                response,
            })
            .await
            .expect("send late apply");
        assert_eq!(
            result_rx.await.expect("late apply response"),
            WalletBackfillApplyResult::Rejected {
                committed_to: 100,
                reason: WalletBackfillRejectReason::Shutdown,
            }
        );

        cancel.cancel();
        drop(db);
        fs::remove_dir_all(root_dir).expect("remove temp db dir");
    }

    #[tokio::test]
    async fn wallet_reset_rejects_stale_actor_token() {
        let root_dir = temp_db_root("wallet-reset-stale-actor-token");
        let db = Arc::new(
            DbStore::open(DbConfig {
                root_dir: root_dir.clone(),
            })
            .expect("open db"),
        );
        let (_live_tx, live_rx) = broadcast::channel(8);
        let (backfill_tx, backfill_rx) = mpsc::channel(8);
        let (backfill_request_tx, _backfill_request_rx) = mpsc::channel(8);
        let cancel = CancellationToken::new();
        let handle = spawn_wallet_worker(
            WalletWorkerServices {
                db: Arc::clone(&db),
                rpcs: Arc::new(QueryRpcPool::new(
                    vec![Url::parse("http://127.0.0.1:1").expect("rpc url")],
                    Duration::from_secs(1),
                )),
                http_client: None,
                indexed_artifact_source: None,
                forest: Arc::new(RwLock::new(MerkleForest::new())),
                backfill_tx: backfill_request_tx,
                backfill_sender: backfill_tx.clone(),
                public_data_plane: test_public_data_plane(&db),
            },
            wallet_config(),
            1,
            live_rx,
            backfill_rx,
            cancel.clone(),
            Vec::new(),
            100,
        )
        .await
        .expect("spawn wallet worker");

        let (response, result_rx) = oneshot::channel();
        backfill_tx
            .send(BackfillEvent::Reset {
                token: WalletResetToken::for_test(1, 2, 1),
                from_block: 80,
                replay_plan: WalletResetReplayPlan::new(0, 0, true),
                response,
            })
            .await
            .expect("send stale reset");
        assert_eq!(
            result_rx.await.expect("reset response"),
            WalletBackfillResetResult::Rejected {
                committed_to: 100,
                reason: WalletBackfillRejectReason::Shutdown,
            }
        );
        assert_eq!(handle.reset_generation(), 0);
        assert_eq!(handle.last_scanned(), 100);

        cancel.cancel();
        drop(db);
        fs::remove_dir_all(root_dir).expect("remove temp db dir");
    }

    #[tokio::test]
    async fn wallet_late_job_failed_for_retired_job_is_noop() {
        let root_dir = temp_db_root("wallet-late-job-failed-retired");
        let db = Arc::new(
            DbStore::open(DbConfig {
                root_dir: root_dir.clone(),
            })
            .expect("open db"),
        );
        let (_live_tx, live_rx) = broadcast::channel(8);
        let (backfill_tx, backfill_rx) = mpsc::channel(8);
        let (backfill_request_tx, _backfill_request_rx) = mpsc::channel(8);
        let cancel = CancellationToken::new();
        let handle = spawn_wallet_worker(
            WalletWorkerServices {
                db: Arc::clone(&db),
                rpcs: Arc::new(QueryRpcPool::new(
                    vec![Url::parse("http://127.0.0.1:1").expect("rpc url")],
                    Duration::from_secs(1),
                )),
                http_client: None,
                indexed_artifact_source: None,
                forest: Arc::new(RwLock::new(MerkleForest::new())),
                backfill_tx: backfill_request_tx,
                backfill_sender: backfill_tx.clone(),
                public_data_plane: test_public_data_plane(&db),
            },
            wallet_config(),
            1,
            live_rx,
            backfill_rx,
            cancel.clone(),
            Vec::new(),
            100,
        )
        .await
        .expect("spawn wallet worker");

        let token = handle.mint_sync_token(0);
        assert_target_accepted(
            send_target_token(&backfill_tx, 200, token).await,
            token,
            100,
            200,
        );
        backfill_tx
            .send(BackfillEvent::JobRetired { token })
            .await
            .expect("retire job");
        tokio::time::sleep(Duration::from_millis(25)).await;
        backfill_tx
            .send(BackfillEvent::JobFailed {
                token,
                reason: WalletReadinessError::BackfillUnavailable,
            })
            .await
            .expect("late job failure");
        tokio::time::sleep(Duration::from_millis(25)).await;

        assert!(!matches!(handle.readiness(), WalletReadiness::Failed(_)));

        cancel.cancel();
        drop(db);
        fs::remove_dir_all(root_dir).expect("remove temp db dir");
    }

    #[tokio::test]
    async fn wallet_raw_minted_token_does_not_authorize_apply() {
        let root_dir = temp_db_root("wallet-raw-token-apply-rejected");
        let db = Arc::new(
            DbStore::open(DbConfig {
                root_dir: root_dir.clone(),
            })
            .expect("open db"),
        );
        let (_live_tx, live_rx) = broadcast::channel(8);
        let (backfill_tx, backfill_rx) = mpsc::channel(8);
        let (backfill_request_tx, _backfill_request_rx) = mpsc::channel(8);
        let cancel = CancellationToken::new();
        let handle = spawn_wallet_worker(
            WalletWorkerServices {
                db: Arc::clone(&db),
                rpcs: Arc::new(QueryRpcPool::new(
                    vec![Url::parse("http://127.0.0.1:1").expect("rpc url")],
                    Duration::from_secs(1),
                )),
                http_client: None,
                indexed_artifact_source: None,
                forest: Arc::new(RwLock::new(MerkleForest::new())),
                backfill_tx: backfill_request_tx,
                backfill_sender: backfill_tx.clone(),
                public_data_plane: test_public_data_plane(&db),
            },
            wallet_config(),
            1,
            live_rx,
            backfill_rx,
            cancel.clone(),
            Vec::new(),
            100,
        )
        .await
        .expect("spawn wallet worker");
        let token = handle.mint_sync_token(0);
        let (response, result_rx) = oneshot::channel();
        backfill_tx
            .send(BackfillEvent::Apply {
                apply: indexed_delta_batch(101, 110, empty_delta()),
                token,
                response,
            })
            .await
            .expect("send raw-token apply");

        assert_eq!(
            result_rx.await.expect("raw-token apply response"),
            WalletBackfillApplyResult::Rejected {
                committed_to: 100,
                reason: WalletBackfillRejectReason::Shutdown,
            }
        );
        assert_eq!(handle.last_scanned(), 100);

        cancel.cancel();
        drop(db);
        fs::remove_dir_all(root_dir).expect("remove temp db dir");
    }

    #[tokio::test]
    async fn wallet_never_accepted_job_retired_is_noop() {
        let root_dir = temp_db_root("wallet-never-accepted-retire-noop");
        let db = Arc::new(
            DbStore::open(DbConfig {
                root_dir: root_dir.clone(),
            })
            .expect("open db"),
        );
        let (_live_tx, live_rx) = broadcast::channel(8);
        let (backfill_tx, backfill_rx) = mpsc::channel(8);
        let (backfill_request_tx, _backfill_request_rx) = mpsc::channel(8);
        let cancel = CancellationToken::new();
        let handle = spawn_wallet_worker(
            WalletWorkerServices {
                db: Arc::clone(&db),
                rpcs: Arc::new(QueryRpcPool::new(
                    vec![Url::parse("http://127.0.0.1:1").expect("rpc url")],
                    Duration::from_secs(1),
                )),
                http_client: None,
                indexed_artifact_source: None,
                forest: Arc::new(RwLock::new(MerkleForest::new())),
                backfill_tx: backfill_request_tx,
                backfill_sender: backfill_tx.clone(),
                public_data_plane: test_public_data_plane(&db),
            },
            wallet_config(),
            1,
            live_rx,
            backfill_rx,
            cancel.clone(),
            Vec::new(),
            100,
        )
        .await
        .expect("spawn wallet worker");
        let token = handle.mint_sync_token(0);

        backfill_tx
            .send(BackfillEvent::JobRetired { token })
            .await
            .expect("send never-accepted retire");
        tokio::task::yield_now().await;

        assert_target_accepted(
            send_target_token(&backfill_tx, 150, token).await,
            token,
            100,
            150,
        );

        cancel.cancel();
        drop(db);
        fs::remove_dir_all(root_dir).expect("remove temp db dir");
    }

    #[test]
    fn wallet_actor_retired_job_bookkeeping_is_bounded() {
        let mut actor_state = WalletActorState::new(1, 1, 0, 0, 0, None);

        for job_id in 1..=10_000 {
            let token = WalletSyncToken::for_test(1, 1, 0, job_id);
            assert!(actor_state.accept_job(token, WalletActorJobKind::Backfill));
            assert!(actor_state.retire_job(token));
        }

        assert!(actor_state.active_jobs.is_empty());
        assert_eq!(actor_state.highest_accepted_backfill_job_id, 10_000);
        assert!(!actor_state.accept_job(
            WalletSyncToken::for_test(1, 1, 0, 10_000),
            WalletActorJobKind::Backfill,
        ));
        assert!(actor_state.accept_job(
            WalletSyncToken::for_test(1, 1, 0, 10_001),
            WalletActorJobKind::Backfill,
        ));
    }

    #[tokio::test]
    async fn wallet_retired_backfill_job_rejects_late_target() {
        let root_dir = temp_db_root("wallet-retired-job-late-target");
        let db = Arc::new(
            DbStore::open(DbConfig {
                root_dir: root_dir.clone(),
            })
            .expect("open db"),
        );
        let (_live_tx, live_rx) = broadcast::channel(8);
        let (backfill_tx, backfill_rx) = mpsc::channel(8);
        let (backfill_request_tx, _backfill_request_rx) = mpsc::channel(8);
        let cancel = CancellationToken::new();
        let handle = spawn_wallet_worker(
            WalletWorkerServices {
                db: Arc::clone(&db),
                rpcs: Arc::new(QueryRpcPool::new(
                    vec![Url::parse("http://127.0.0.1:1").expect("rpc url")],
                    Duration::from_secs(1),
                )),
                http_client: None,
                indexed_artifact_source: None,
                forest: Arc::new(RwLock::new(MerkleForest::new())),
                backfill_tx: backfill_request_tx,
                backfill_sender: backfill_tx.clone(),
                public_data_plane: test_public_data_plane(&db),
            },
            wallet_config(),
            1,
            live_rx,
            backfill_rx,
            cancel.clone(),
            Vec::new(),
            100,
        )
        .await
        .expect("spawn wallet worker");
        let token = handle.mint_sync_token(0);

        assert_target_accepted(
            send_target_token(&backfill_tx, 150, token).await,
            token,
            100,
            150,
        );
        backfill_tx
            .send(BackfillEvent::JobRetired { token })
            .await
            .expect("retire job");
        tokio::task::yield_now().await;

        assert_eq!(
            send_target_token(&backfill_tx, 150, token).await,
            WalletBackfillFinishResult::Rejected {
                committed_to: 100,
                reason: WalletBackfillRejectReason::Shutdown,
            }
        );

        cancel.cancel();
        drop(db);
        fs::remove_dir_all(root_dir).expect("remove temp db dir");
    }

    #[tokio::test]
    async fn wallet_reset_acceptance_persist_failure_keeps_generation_current() {
        let root_dir = temp_db_root("wallet-reset-acceptance-persist-failure");
        let db = Arc::new(
            DbStore::open(DbConfig {
                root_dir: root_dir.clone(),
            })
            .expect("open db"),
        );
        let cache_store = Arc::new(FailingCacheStore::new(Arc::clone(&db)));
        let mut cfg = wallet_config();
        cfg.cache_store = Some(cache_store.clone());
        let (live_tx, live_rx) = broadcast::channel(8);
        let (backfill_tx, backfill_rx) = mpsc::channel(8);
        let (backfill_request_tx, mut backfill_request_rx) = mpsc::channel(8);
        let cancel = CancellationToken::new();
        let handle = spawn_wallet_worker(
            WalletWorkerServices {
                db: Arc::clone(&db),
                rpcs: Arc::new(QueryRpcPool::new(
                    vec![Url::parse("http://127.0.0.1:1").expect("rpc url")],
                    Duration::from_secs(1),
                )),
                http_client: None,
                indexed_artifact_source: None,
                forest: Arc::new(RwLock::new(MerkleForest::new())),
                backfill_tx: backfill_request_tx,
                backfill_sender: backfill_tx.clone(),
                public_data_plane: test_public_data_plane(&db),
            },
            cfg,
            1,
            live_rx,
            backfill_rx,
            cancel.clone(),
            Vec::new(),
            100,
        )
        .await
        .expect("spawn wallet worker");

        cache_store.fail_next_actor_state_put();
        assert_eq!(
            send_reset(&backfill_tx, 1, 50).await,
            WalletBackfillResetResult::Rejected {
                committed_to: 100,
                reason: WalletBackfillRejectReason::PersistenceFailed,
            }
        );
        assert_eq!(handle.reset_generation(), 0);

        let token = handle.mint_sync_token(handle.reset_generation());
        assert_target_accepted(
            send_target_token(&backfill_tx, 110, token).await,
            token,
            100,
            110,
        );
        let (response, result_rx) = oneshot::channel();
        backfill_tx
            .send(BackfillEvent::Apply {
                apply: indexed_delta_batch(101, 110, empty_delta()),
                token,
                response,
            })
            .await
            .expect("send post-reset-failure apply");
        assert_eq!(
            result_rx.await.expect("apply result"),
            WalletBackfillApplyResult::Committed { committed_to: 110 }
        );
        assert_eq!(
            send_target_token(&backfill_tx, 110, token).await,
            WalletBackfillFinishResult::Ready { committed_to: 110 }
        );

        live_tx
            .send(Arc::new(LogBatch {
                from_block: 120,
                to_block: 120,
                logs: Vec::new(),
                block_timestamps: HashMap::new(),
                to_block_hash: None,
                read_scope: test_public_scan_read_scope(),
            }))
            .expect("live receiver");
        let request = tokio::time::timeout(Duration::from_secs(1), backfill_request_rx.recv())
            .await
            .expect("live gap backfill requested")
            .expect("backfill request");
        let BackfillRequest::Add {
            from_block,
            to_block,
            lease,
            ..
        } = request
        else {
            panic!("expected live-gap add request");
        };
        assert_eq!(from_block, 111);
        assert_eq!(to_block, 120);
        assert_eq!(lease.token().reset_generation(), 0);

        cancel.cancel();
        drop(db);
        fs::remove_dir_all(root_dir).expect("remove temp db dir");
    }

    #[tokio::test]
    async fn wallet_pending_reset_retry_retires_rejected_target_job() {
        let root_dir = temp_db_root("wallet-reset-retry-retires-job");
        let db = Arc::new(
            DbStore::open(DbConfig {
                root_dir: root_dir.clone(),
            })
            .expect("open db"),
        );
        let cache_store = Arc::new(FailingCacheStore::new(Arc::clone(&db)));
        let mut cfg = wallet_config();
        cfg.cache_store = Some(cache_store.clone());
        let (_live_tx, live_rx) = broadcast::channel(8);
        let (backfill_tx, backfill_rx) = mpsc::channel(8);
        let (backfill_request_tx, mut backfill_request_rx) = mpsc::channel(8);
        let cancel = CancellationToken::new();
        let handle = spawn_wallet_worker(
            WalletWorkerServices {
                db: Arc::clone(&db),
                rpcs: Arc::new(QueryRpcPool::new(
                    vec![Url::parse("http://127.0.0.1:1").expect("rpc url")],
                    Duration::from_secs(1),
                )),
                http_client: None,
                indexed_artifact_source: None,
                forest: Arc::new(RwLock::new(MerkleForest::new())),
                backfill_tx: backfill_request_tx,
                backfill_sender: backfill_tx.clone(),
                public_data_plane: test_public_data_plane(&db),
            },
            cfg,
            1,
            live_rx,
            backfill_rx,
            cancel.clone(),
            vec![test_wallet_utxo(105, 7)],
            120,
        )
        .await
        .expect("spawn wallet worker");

        cache_store.fail_next_store();
        assert_eq!(
            send_reset(&backfill_tx, 1, 100).await,
            WalletBackfillResetResult::Accepted {
                reset_generation: 1,
                committed_to: 120,
                committed: false,
            }
        );
        let token = handle.mint_sync_token(1);
        cache_store.fail_next_store();
        assert_eq!(
            send_target_token(&backfill_tx, 130, token).await,
            WalletBackfillFinishResult::Rejected {
                committed_to: 120,
                reason: WalletBackfillRejectReason::PersistenceFailed,
            }
        );

        tokio::time::timeout(Duration::from_secs(2), async {
            loop {
                let state = db
                    .get_wallet_sync_actor_state(1, "test")
                    .expect("load wallet sync actor state");
                if state.is_some_and(|state| state.pending_reset.is_none()) {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .expect("pending reset retry committed");

        assert_eq!(
            send_target_token(&backfill_tx, 130, token).await,
            WalletBackfillFinishResult::Rejected {
                committed_to: 99,
                reason: WalletBackfillRejectReason::Shutdown,
            }
        );

        let replay_token = match backfill_request_rx
            .recv()
            .await
            .expect("actor-owned reset replay request")
        {
            BackfillRequest::Add { lease, .. } => lease.token(),
            BackfillRequest::Remove { .. } => panic!("expected reset replay add request"),
        };
        assert_target_accepted(
            send_target_token(&backfill_tx, 130, replay_token).await,
            replay_token,
            99,
            130,
        );
        let (response, result_rx) = oneshot::channel();
        backfill_tx
            .send(BackfillEvent::Apply {
                apply: indexed_delta_batch(100, 130, empty_delta()),
                token: replay_token,
                response,
            })
            .await
            .expect("send replay apply");
        assert_eq!(
            result_rx.await.expect("replay apply result"),
            WalletBackfillApplyResult::Committed { committed_to: 130 }
        );
        assert_eq!(
            send_target_token(&backfill_tx, 130, replay_token).await,
            WalletBackfillFinishResult::Ready { committed_to: 130 }
        );

        cancel.cancel();
        drop(db);
        fs::remove_dir_all(root_dir).expect("remove temp db dir");
    }

    #[tokio::test]
    async fn wallet_reset_boundary_ahead_of_lagging_cursor_does_not_synthesize_progress() {
        let root_dir = temp_db_root("wallet-reset-boundary-lagging-cursor");
        let db = Arc::new(
            DbStore::open(DbConfig {
                root_dir: root_dir.clone(),
            })
            .expect("open db"),
        );
        let (_live_tx, live_rx) = broadcast::channel(8);
        let (backfill_tx, backfill_rx) = mpsc::channel(8);
        let (backfill_request_tx, _backfill_request_rx) = mpsc::channel(8);
        let cancel = CancellationToken::new();
        let handle = spawn_wallet_worker(
            WalletWorkerServices {
                db: Arc::clone(&db),
                rpcs: Arc::new(QueryRpcPool::new(
                    vec![Url::parse("http://127.0.0.1:1").expect("rpc url")],
                    Duration::from_secs(1),
                )),
                http_client: None,
                indexed_artifact_source: None,
                forest: Arc::new(RwLock::new(MerkleForest::new())),
                backfill_tx: backfill_request_tx,
                backfill_sender: backfill_tx.clone(),
                public_data_plane: test_public_data_plane(&db),
            },
            wallet_config(),
            1,
            live_rx,
            backfill_rx,
            cancel.clone(),
            Vec::new(),
            50,
        )
        .await
        .expect("spawn wallet worker");

        assert_eq!(
            send_reset(&backfill_tx, 1, 100).await,
            WalletBackfillResetResult::Accepted {
                reset_generation: 1,
                committed_to: 50,
                committed: true,
            }
        );
        assert_eq!(handle.last_scanned(), 50);
        assert_eq!(
            db.get_wallet_meta("test")
                .expect("load meta")
                .expect("meta persisted")
                .last_scanned_block,
            50
        );

        cancel.cancel();
        drop(db);
        fs::remove_dir_all(root_dir).expect("remove temp db dir");
    }

    #[tokio::test]
    async fn wallet_newer_reset_merges_pending_reset_boundary() {
        let root_dir = temp_db_root("wallet-reset-newer-merge");
        let db = Arc::new(
            DbStore::open(DbConfig {
                root_dir: root_dir.clone(),
            })
            .expect("open db"),
        );
        let cache_store = Arc::new(FailingCacheStore::new(Arc::clone(&db)));
        let mut cfg = wallet_config();
        cfg.cache_store = Some(cache_store.clone());
        let (_live_tx, live_rx) = broadcast::channel(8);
        let (backfill_tx, backfill_rx) = mpsc::channel(8);
        let (backfill_request_tx, _backfill_request_rx) = mpsc::channel(8);
        let cancel = CancellationToken::new();
        let handle = spawn_wallet_worker(
            WalletWorkerServices {
                db: Arc::clone(&db),
                rpcs: Arc::new(QueryRpcPool::new(
                    vec![Url::parse("http://127.0.0.1:1").expect("rpc url")],
                    Duration::from_secs(1),
                )),
                http_client: None,
                indexed_artifact_source: None,
                forest: Arc::new(RwLock::new(MerkleForest::new())),
                backfill_tx: backfill_request_tx,
                backfill_sender: backfill_tx.clone(),
                public_data_plane: test_public_data_plane(&db),
            },
            cfg.clone(),
            1,
            live_rx,
            backfill_rx,
            cancel.clone(),
            vec![test_wallet_utxo(105, 7)],
            120,
        )
        .await
        .expect("spawn wallet worker");

        cache_store.fail_next_store();
        assert_eq!(
            send_reset(&backfill_tx, 1, 100).await,
            WalletBackfillResetResult::Accepted {
                reset_generation: 1,
                committed_to: 120,
                committed: false,
            }
        );
        assert_eq!(handle.last_scanned(), 120);
        assert_eq!(
            send_reset(&backfill_tx, 2, 80).await,
            WalletBackfillResetResult::Accepted {
                reset_generation: 2,
                committed_to: 79,
                committed: true,
            }
        );
        assert_eq!(handle.last_scanned(), 79);
        assert!(handle.utxos.read().await.is_empty());
        let state = db
            .get_wallet_sync_actor_state(cfg.chain.chain_id, &cfg.cache_key)
            .expect("load sync actor state")
            .expect("sync actor state");
        assert_eq!(state.highest_accepted_reset_intent, 2);
        assert!(state.pending_reset.is_none());
        assert_eq!(
            send_reset(&backfill_tx, 1, 70).await,
            WalletBackfillResetResult::Rejected {
                committed_to: 79,
                reason: WalletBackfillRejectReason::StaleResetIntent {
                    accepted: 2,
                    actual: 1,
                },
            }
        );

        cancel.cancel();
        drop(db);
        fs::remove_dir_all(root_dir).expect("remove temp db dir");
    }

    #[tokio::test]
    async fn wallet_reset_commit_clears_stale_pending_overlay() {
        let root_dir = temp_db_root("wallet-reset-clears-pending-overlay");
        let db = Arc::new(
            DbStore::open(DbConfig {
                root_dir: root_dir.clone(),
            })
            .expect("open db"),
        );
        let (_live_tx, live_rx) = broadcast::channel(8);
        let (backfill_tx, backfill_rx) = mpsc::channel(8);
        let (backfill_request_tx, _backfill_request_rx) = mpsc::channel(8);
        let cancel = CancellationToken::new();
        let wallet_utxo = test_wallet_utxo(105, 7);
        let handle = spawn_wallet_worker(
            WalletWorkerServices {
                db: Arc::clone(&db),
                rpcs: Arc::new(QueryRpcPool::new(
                    vec![Url::parse("http://127.0.0.1:1").expect("rpc url")],
                    Duration::from_secs(1),
                )),
                http_client: None,
                indexed_artifact_source: None,
                forest: Arc::new(RwLock::new(MerkleForest::new())),
                backfill_tx: backfill_request_tx,
                backfill_sender: backfill_tx.clone(),
                public_data_plane: test_public_data_plane(&db),
            },
            wallet_config(),
            1,
            live_rx,
            backfill_rx,
            cancel.clone(),
            vec![wallet_utxo.clone()],
            120,
        )
        .await
        .expect("spawn wallet worker");
        let spent_source = source(121, 0xaa);
        let pending_spent = WalletPendingSpent {
            tree: wallet_utxo.utxo.tree,
            position: wallet_utxo.utxo.position,
            tx_hash: Some(spent_source.tx_hash),
            block_number: Some(spent_source.block_number),
            block_timestamp: Some(spent_source.block_timestamp),
        };
        assert!(
            handle
                .request_pending_overlay_rows(
                    pending_overlay_rows_from_delta(
                        121,
                        121,
                        WalletLogDelta {
                            utxos: Vec::new(),
                            nullifiers: vec![SpentNullifier {
                                tree: wallet_utxo.utxo.tree,
                                nullifier: wallet_utxo
                                    .utxo
                                    .nullifier(wallet_config().scan_keys.nullifying_key),
                                source: spent_source,
                            }],
                            commitment_observations: Vec::new(),
                        },
                    ),
                    0,
                    120,
                )
                .await
        );
        tokio::time::timeout(Duration::from_secs(1), async {
            while handle.pending_overlay().await.pending_spent != vec![pending_spent.clone()] {
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .expect("pending overlay applied");

        assert_eq!(
            send_reset(&backfill_tx, 1, 100).await,
            WalletBackfillResetResult::Accepted {
                reset_generation: 1,
                committed_to: 99,
                committed: true,
            }
        );
        let overlay = handle.pending_overlay().await;
        assert!(overlay.pending_spent.is_empty());
        assert!(overlay.new_utxos.is_empty());

        cancel.cancel();
        drop(db);
        fs::remove_dir_all(root_dir).expect("remove temp db dir");
    }

    #[tokio::test]
    async fn wallet_live_gap_backfill_queue_full_marks_job_failed() {
        let root_dir = temp_db_root("wallet-live-gap-queue-full");
        let db = Arc::new(
            DbStore::open(DbConfig {
                root_dir: root_dir.clone(),
            })
            .expect("open db"),
        );
        let (live_tx, live_rx) = broadcast::channel(8);
        let (backfill_tx, backfill_rx) = mpsc::channel(8);
        let (backfill_request_tx, mut backfill_request_rx) = mpsc::channel(1);
        backfill_request_tx
            .try_send(BackfillRequest::Remove {
                cache_key: "blocked".to_string(),
            })
            .expect("fill backfill request queue");
        let cancel = CancellationToken::new();
        let handle = spawn_wallet_worker(
            WalletWorkerServices {
                db: Arc::clone(&db),
                rpcs: Arc::new(QueryRpcPool::new(
                    vec![Url::parse("http://127.0.0.1:1").expect("rpc url")],
                    Duration::from_secs(1),
                )),
                http_client: None,
                indexed_artifact_source: None,
                forest: Arc::new(RwLock::new(MerkleForest::new())),
                backfill_tx: backfill_request_tx,
                backfill_sender: backfill_tx.clone(),
                public_data_plane: test_public_data_plane(&db),
            },
            wallet_config(),
            1,
            live_rx,
            backfill_rx,
            cancel.clone(),
            Vec::new(),
            100,
        )
        .await
        .expect("spawn wallet worker");
        assert_eq!(
            send_target(&handle, &backfill_tx, 100, 0).await,
            WalletBackfillFinishResult::Ready { committed_to: 100 }
        );
        live_tx
            .send(Arc::new(LogBatch {
                from_block: 120,
                to_block: 120,
                logs: Vec::new(),
                block_timestamps: HashMap::new(),
                to_block_hash: None,
                read_scope: test_public_scan_read_scope(),
            }))
            .expect("live receiver");
        tokio::time::timeout(Duration::from_secs(1), async {
            loop {
                if matches!(
                    handle.readiness(),
                    WalletReadiness::Failed(WalletReadinessError::BackfillUnavailable)
                ) {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .expect("backfill unavailable readiness observed");
        assert!(backfill_request_rx.try_recv().is_ok());

        cancel.cancel();
        drop(db);
        fs::remove_dir_all(root_dir).expect("remove temp db dir");
    }

    #[tokio::test]
    async fn wallet_target_does_not_publish_ready_while_other_backfill_active() {
        let root_dir = temp_db_root("wallet-target-active-job-gate");
        let db = Arc::new(
            DbStore::open(DbConfig {
                root_dir: root_dir.clone(),
            })
            .expect("open db"),
        );
        let (_live_tx, live_rx) = broadcast::channel(8);
        let (backfill_tx, backfill_rx) = mpsc::channel(8);
        let (backfill_request_tx, _backfill_request_rx) = mpsc::channel(8);
        let cancel = CancellationToken::new();
        let handle = spawn_wallet_worker(
            WalletWorkerServices {
                db: Arc::clone(&db),
                rpcs: Arc::new(QueryRpcPool::new(
                    vec![Url::parse("http://127.0.0.1:1").expect("rpc url")],
                    Duration::from_secs(1),
                )),
                http_client: None,
                indexed_artifact_source: None,
                forest: Arc::new(RwLock::new(MerkleForest::new())),
                backfill_tx: backfill_request_tx,
                backfill_sender: backfill_tx.clone(),
                public_data_plane: test_public_data_plane(&db),
            },
            wallet_config(),
            1,
            live_rx,
            backfill_rx,
            cancel.clone(),
            Vec::new(),
            100,
        )
        .await
        .expect("spawn wallet worker");

        let initial_token = handle.mint_sync_token(0);
        assert_eq!(
            send_target_token(&backfill_tx, 100, initial_token).await,
            WalletBackfillFinishResult::Ready { committed_to: 100 }
        );
        let gap_token = handle.mint_sync_token(0);
        assert_target_accepted(
            send_target_token(&backfill_tx, 150, gap_token).await,
            gap_token,
            100,
            150,
        );
        let covered_token = handle.mint_sync_token(0);
        assert_eq!(
            send_target_token(&backfill_tx, 100, covered_token).await,
            WalletBackfillFinishResult::Rejected {
                committed_to: 100,
                reason: WalletBackfillRejectReason::TargetNotReached { target_block: 150 },
            }
        );
        assert_eq!(handle.readiness(), WalletReadiness::Syncing);
        assert!(!*handle.ready_rx.borrow());

        let (response, result_rx) = oneshot::channel();
        backfill_tx
            .send(BackfillEvent::Apply {
                apply: indexed_delta_batch(101, 110, empty_delta()),
                token: covered_token,
                response,
            })
            .await
            .expect("send late covered-token apply");
        assert_eq!(
            result_rx.await.expect("late apply result"),
            WalletBackfillApplyResult::Rejected {
                committed_to: 100,
                reason: WalletBackfillRejectReason::Shutdown,
            }
        );

        cancel.cancel();
        drop(db);
        fs::remove_dir_all(root_dir).expect("remove temp db dir");
    }

    #[tokio::test]
    async fn wallet_reset_rejects_persistence_failure_without_publishing_rewind() {
        let root_dir = temp_db_root("wallet-reset-persist-failure");
        let db = Arc::new(
            DbStore::open(DbConfig {
                root_dir: root_dir.clone(),
            })
            .expect("open db"),
        );
        let cache_store = Arc::new(FailingCacheStore::new(Arc::clone(&db)));
        let mut cfg = wallet_config();
        cfg.cache_store = Some(cache_store.clone());
        let (_live_tx, live_rx) = broadcast::channel(8);
        let (backfill_tx, backfill_rx) = mpsc::channel(8);
        let (backfill_request_tx, _backfill_request_rx) = mpsc::channel(8);
        let cancel = CancellationToken::new();
        let initial_utxo = test_wallet_utxo(105, 7);
        let handle = spawn_wallet_worker(
            WalletWorkerServices {
                db: Arc::clone(&db),
                rpcs: Arc::new(QueryRpcPool::new(
                    vec![Url::parse("http://127.0.0.1:1").expect("rpc url")],
                    Duration::from_secs(1),
                )),
                http_client: None,
                indexed_artifact_source: None,
                forest: Arc::new(RwLock::new(MerkleForest::new())),
                backfill_tx: backfill_request_tx,
                backfill_sender: backfill_tx.clone(),
                public_data_plane: test_public_data_plane(&db),
            },
            cfg,
            1,
            live_rx,
            backfill_rx,
            cancel.clone(),
            vec![initial_utxo],
            120,
        )
        .await
        .expect("spawn wallet worker");

        assert_eq!(
            send_target(&handle, &backfill_tx, 120, 0).await,
            WalletBackfillFinishResult::Ready { committed_to: 120 }
        );
        let rev_before_reset = *handle.rev_rx.borrow();
        let store_calls_before_reset = cache_store.state().store_calls;
        cache_store.fail_next_store();

        assert_eq!(
            send_reset(&backfill_tx, 1, 100).await,
            WalletBackfillResetResult::Accepted {
                reset_generation: 1,
                committed_to: 120,
                committed: false,
            }
        );

        assert_eq!(handle.reset_generation(), 1);
        assert_eq!(handle.last_scanned(), 120);
        assert_eq!(handle.readiness(), WalletReadiness::Syncing);
        assert!(!*handle.ready_rx.borrow());
        assert_eq!(*handle.rev_rx.borrow(), rev_before_reset);
        let snapshot = handle.utxos.read().await;
        assert_eq!(snapshot.len(), 1);
        assert_eq!(snapshot[0].utxo.source.block_number, 105);
        drop(snapshot);
        assert_eq!(
            cache_store.state().store_calls,
            store_calls_before_reset + 1
        );
        let state = db
            .get_wallet_sync_actor_state(1, "test")
            .expect("load wallet sync actor state")
            .expect("wallet sync actor state persisted");
        assert_eq!(state.highest_accepted_reset_intent, 1);
        assert_eq!(state.pending_reset.expect("pending reset").from_block, 100);

        tokio::time::timeout(Duration::from_secs(2), async {
            loop {
                if handle.last_scanned() == 99 {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .expect("actor-owned reset retry commits rewind");
        assert!(handle.utxos.read().await.is_empty());
        assert_eq!(handle.readiness(), WalletReadiness::Syncing);
        assert_ne!(*handle.rev_rx.borrow(), rev_before_reset);
        let state = db
            .get_wallet_sync_actor_state(1, "test")
            .expect("reload wallet sync actor state")
            .expect("wallet sync actor state persisted");
        assert!(state.pending_reset.is_none());

        cancel.cancel();
        drop(db);
        fs::remove_dir_all(root_dir).expect("remove temp db dir");
    }

    #[tokio::test]
    async fn wallet_reset_commit_discards_pending_contexts_for_rewound_outputs() {
        let root_dir = temp_db_root("wallet-reset-pending-context-cleanup");
        let db = Arc::new(
            DbStore::open(DbConfig {
                root_dir: root_dir.clone(),
            })
            .expect("open db"),
        );
        let cache_store = Arc::new(FailingCacheStore::new(Arc::clone(&db)));
        let mut cfg = wallet_config();
        cfg.cache_store = Some(cache_store.clone());
        let initial_utxo = test_wallet_utxo(105, 7);
        let output_commitment = initial_utxo.utxo.poi.commitment;
        db.put_pending_output_poi_context(&pending_output_context_for_wallet_utxo(
            &cfg,
            &initial_utxo,
        ))
        .expect("seed pending context");
        let (_live_tx, live_rx) = broadcast::channel(8);
        let (backfill_tx, backfill_rx) = mpsc::channel(8);
        let (backfill_request_tx, _backfill_request_rx) = mpsc::channel(8);
        let cancel = CancellationToken::new();
        let handle = spawn_wallet_worker(
            WalletWorkerServices {
                db: Arc::clone(&db),
                rpcs: Arc::new(QueryRpcPool::new(
                    vec![Url::parse("http://127.0.0.1:1").expect("rpc url")],
                    Duration::from_secs(1),
                )),
                http_client: None,
                indexed_artifact_source: None,
                forest: Arc::new(RwLock::new(MerkleForest::new())),
                backfill_tx: backfill_request_tx,
                backfill_sender: backfill_tx.clone(),
                public_data_plane: test_public_data_plane(&db),
            },
            cfg.clone(),
            1,
            live_rx,
            backfill_rx,
            cancel.clone(),
            vec![initial_utxo],
            120,
        )
        .await
        .expect("spawn wallet worker");

        assert_eq!(
            send_reset(&backfill_tx, 1, 100).await,
            WalletBackfillResetResult::Accepted {
                reset_generation: 1,
                committed_to: 99,
                committed: true,
            }
        );

        assert_eq!(handle.last_scanned(), 99);
        assert!(handle.utxos.read().await.is_empty());
        let state = db
            .get_wallet_sync_actor_state(cfg.chain.chain_id, &cfg.cache_key)
            .expect("load wallet sync actor state")
            .expect("wallet sync actor state persisted");
        assert_eq!(state.highest_accepted_reset_intent, 1);
        assert!(state.pending_reset.is_none());
        assert!(
            db.get_pending_output_poi_context(
                cfg.chain.chain_id,
                &cfg.cache_key,
                &output_commitment
            )
            .expect("load pending context")
            .is_none()
        );
        assert_eq!(cache_store.state().store_calls, 1);

        cancel.cancel();
        drop(db);
        fs::remove_dir_all(root_dir).expect("remove temp db dir");
    }

    #[tokio::test]
    async fn wallet_worker_restores_durable_pending_reset_before_accepting_older_intents() {
        let root_dir = temp_db_root("wallet-reset-restore-pending");
        let db = Arc::new(
            DbStore::open(DbConfig {
                root_dir: root_dir.clone(),
            })
            .expect("open db"),
        );
        let cfg = wallet_config();
        db.put_wallet_sync_actor_state(&WalletSyncActorStateRecord {
            chain_id: cfg.chain.chain_id,
            wallet_id: cfg.cache_key.clone(),
            highest_accepted_reset_intent: 7,
            pending_reset: Some(WalletPendingResetRecord {
                intent_id: 7,
                from_block: 100,
                replay_start_block: 0,
                replay_target_block: 0,
                follow_safe_head: true,
            }),
            updated_at: 1,
        })
        .expect("seed wallet sync actor state");
        let (_live_tx, live_rx) = broadcast::channel(8);
        let (backfill_tx, backfill_rx) = mpsc::channel(8);
        let (backfill_request_tx, _backfill_request_rx) = mpsc::channel(8);
        let cancel = CancellationToken::new();
        let handle = spawn_wallet_worker(
            WalletWorkerServices {
                db: Arc::clone(&db),
                rpcs: Arc::new(QueryRpcPool::new(
                    vec![Url::parse("http://127.0.0.1:1").expect("rpc url")],
                    Duration::from_secs(1),
                )),
                http_client: None,
                indexed_artifact_source: None,
                forest: Arc::new(RwLock::new(MerkleForest::new())),
                backfill_tx: backfill_request_tx,
                backfill_sender: backfill_tx.clone(),
                public_data_plane: test_public_data_plane(&db),
            },
            cfg.clone(),
            1,
            live_rx,
            backfill_rx,
            cancel.clone(),
            vec![test_wallet_utxo(105, 7)],
            120,
        )
        .await
        .expect("spawn wallet worker");

        assert_eq!(handle.reset_generation(), 1);
        assert_eq!(handle.last_scanned(), 99);
        assert!(handle.utxos.read().await.is_empty());
        assert_eq!(
            send_reset(&backfill_tx, 7, 90).await,
            WalletBackfillResetResult::Rejected {
                committed_to: 99,
                reason: WalletBackfillRejectReason::StaleResetIntent {
                    accepted: 7,
                    actual: 7,
                },
            }
        );

        let state = db
            .get_wallet_sync_actor_state(cfg.chain.chain_id, &cfg.cache_key)
            .expect("load wallet sync actor state")
            .expect("wallet sync actor state persisted");
        assert_eq!(state.highest_accepted_reset_intent, 7);
        assert!(state.pending_reset.is_none());

        cancel.cancel();
        drop(db);
        fs::remove_dir_all(root_dir).expect("remove temp db dir");
    }

    #[tokio::test]
    async fn wallet_worker_restored_pending_reset_waits_for_durable_replay() {
        let root_dir = temp_db_root("wallet-reset-restore-failed-replay");
        let db = Arc::new(
            DbStore::open(DbConfig {
                root_dir: root_dir.clone(),
            })
            .expect("open db"),
        );
        let cache_store = Arc::new(FailingCacheStore::new(Arc::clone(&db)));
        let mut cfg = wallet_config();
        cache_store.seed_actor_state(WalletSyncActorStateRecord {
            chain_id: cfg.chain.chain_id,
            wallet_id: cfg.cache_key.clone(),
            highest_accepted_reset_intent: 7,
            pending_reset: Some(WalletPendingResetRecord {
                intent_id: 7,
                from_block: 100,
                replay_start_block: 0,
                replay_target_block: 0,
                follow_safe_head: true,
            }),
            updated_at: 1,
        });
        cache_store.fail_next_store();
        cfg.cache_store = Some(cache_store.clone());
        let (_live_tx, live_rx) = broadcast::channel(8);
        let (backfill_tx, backfill_rx) = mpsc::channel(8);
        let (backfill_request_tx, _backfill_request_rx) = mpsc::channel(8);
        let cancel = CancellationToken::new();
        let handle = tokio::time::timeout(
            Duration::from_secs(2),
            spawn_wallet_worker(
                WalletWorkerServices {
                    db: Arc::clone(&db),
                    rpcs: Arc::new(QueryRpcPool::new(
                        vec![Url::parse("http://127.0.0.1:1").expect("rpc url")],
                        Duration::from_secs(1),
                    )),
                    http_client: None,
                    indexed_artifact_source: None,
                    forest: Arc::new(RwLock::new(MerkleForest::new())),
                    backfill_tx: backfill_request_tx,
                    backfill_sender: backfill_tx,
                    public_data_plane: test_public_data_plane(&db),
                },
                cfg,
                1,
                live_rx,
                backfill_rx,
                cancel.clone(),
                vec![test_wallet_utxo(105, 7)],
                120,
            ),
        )
        .await
        .expect("restored reset retry should complete before handle is returned")
        .expect("spawn wallet worker");

        assert_eq!(cache_store.state().store_calls, 2);
        assert_eq!(handle.reset_generation(), 1);
        assert_eq!(handle.last_scanned(), 99);
        assert!(handle.utxos.read().await.is_empty());
        assert_eq!(handle.readiness(), WalletReadiness::Syncing);
        assert!(
            cache_store
                .actor_state()
                .expect("restored actor state")
                .pending_reset
                .is_none()
        );

        cancel.cancel();
        drop(db);
        fs::remove_dir_all(root_dir).expect("remove temp db dir");
    }

    #[tokio::test]
    async fn wallet_worker_rejects_bootstrap_when_actor_state_read_fails() {
        let root_dir = temp_db_root("wallet-reset-actor-state-read-fails");
        let db = Arc::new(
            DbStore::open(DbConfig {
                root_dir: root_dir.clone(),
            })
            .expect("open db"),
        );
        let cache_store = Arc::new(FailingCacheStore::new(Arc::clone(&db)));
        cache_store.fail_next_actor_state();
        let mut cfg = wallet_config();
        cfg.cache_store = Some(cache_store);
        let (_live_tx, live_rx) = broadcast::channel(8);
        let (backfill_tx, backfill_rx) = mpsc::channel(8);
        let (backfill_request_tx, _backfill_request_rx) = mpsc::channel(8);
        let cancel = CancellationToken::new();

        let result = spawn_wallet_worker(
            WalletWorkerServices {
                db: Arc::clone(&db),
                rpcs: Arc::new(QueryRpcPool::new(
                    vec![Url::parse("http://127.0.0.1:1").expect("rpc url")],
                    Duration::from_secs(1),
                )),
                http_client: None,
                indexed_artifact_source: None,
                forest: Arc::new(RwLock::new(MerkleForest::new())),
                backfill_tx: backfill_request_tx,
                backfill_sender: backfill_tx,
                public_data_plane: test_public_data_plane(&db),
            },
            cfg,
            1,
            live_rx,
            backfill_rx,
            cancel.clone(),
            vec![test_wallet_utxo(105, 7)],
            120,
        )
        .await;

        assert!(matches!(result, Err(WalletCacheError::Crypto)));
        cancel.cancel();
        drop(db);
        fs::remove_dir_all(root_dir).expect("remove temp db dir");
    }

    #[tokio::test]
    async fn wallet_reset_rejects_retired_actor_without_side_effects() {
        let root_dir = temp_db_root("wallet-reset-retired-actor");
        let db = Arc::new(
            DbStore::open(DbConfig {
                root_dir: root_dir.clone(),
            })
            .expect("open db"),
        );
        let cache_store = Arc::new(FailingCacheStore::new(Arc::clone(&db)));
        let mut cfg = wallet_config();
        cfg.cache_store = Some(cache_store.clone());
        let (_live_tx, live_rx) = broadcast::channel(8);
        let (backfill_tx, backfill_rx) = mpsc::channel(8);
        let (backfill_request_tx, _backfill_request_rx) = mpsc::channel(8);
        let cancel = CancellationToken::new();
        let initial_utxo = test_wallet_utxo(105, 7);
        let handle = spawn_wallet_worker(
            WalletWorkerServices {
                db: Arc::clone(&db),
                rpcs: Arc::new(QueryRpcPool::new(
                    vec![Url::parse("http://127.0.0.1:1").expect("rpc url")],
                    Duration::from_secs(1),
                )),
                http_client: None,
                indexed_artifact_source: None,
                forest: Arc::new(RwLock::new(MerkleForest::new())),
                backfill_tx: backfill_request_tx,
                backfill_sender: backfill_tx.clone(),
                public_data_plane: test_public_data_plane(&db),
            },
            cfg,
            1,
            live_rx,
            backfill_rx,
            cancel.clone(),
            vec![initial_utxo],
            120,
        )
        .await
        .expect("spawn wallet worker");

        assert_eq!(
            send_target(&handle, &backfill_tx, 120, 0).await,
            WalletBackfillFinishResult::Ready { committed_to: 120 }
        );
        let rev_before_reset = *handle.rev_rx.borrow();
        let store_calls_before_reset = cache_store.state().store_calls;
        handle.retire_actor().await;

        assert_eq!(
            send_reset(&backfill_tx, 1, 100).await,
            WalletBackfillResetResult::Rejected {
                committed_to: 120,
                reason: WalletBackfillRejectReason::Shutdown,
            }
        );

        assert_eq!(handle.reset_generation(), 0);
        assert_eq!(handle.last_scanned(), 120);
        assert_eq!(handle.readiness(), WalletReadiness::Ready);
        assert!(*handle.ready_rx.borrow());
        assert_eq!(*handle.rev_rx.borrow(), rev_before_reset);
        let snapshot = handle.utxos.read().await;
        assert_eq!(snapshot.len(), 1);
        assert_eq!(snapshot[0].utxo.source.block_number, 105);
        assert_eq!(cache_store.state().store_calls, store_calls_before_reset);

        cancel.cancel();
        drop(snapshot);
        drop(db);
        fs::remove_dir_all(root_dir).expect("remove temp db dir");
    }

    #[tokio::test]
    async fn wallet_poi_refresh_rejects_persistence_failure_without_swapping_state() {
        let root_dir = temp_db_root("wallet-poi-refresh-persist-failure");
        let db = Arc::new(
            DbStore::open(DbConfig {
                root_dir: root_dir.clone(),
            })
            .expect("open db"),
        );
        let cache_store = Arc::new(FailingCacheStore::new(Arc::clone(&db)));
        cache_store.fail_next_store();
        let local_caches = Arc::new(RwLock::new(BTreeMap::new()));
        let mut cfg = wallet_config();
        cfg.cache_store = Some(cache_store.clone());
        cfg.poi_read_source = PoiReadSource::IndexedArtifacts(PoiArtifactSourceConfig {
            trusted_publisher_pubkey: FixedBytes::from([0x22; 32]),
            manifest_source: PoiArtifactManifestSource::Url(
                Url::parse("http://127.0.0.1:1/manifest").expect("manifest url"),
            ),
            gateway_urls: Vec::new(),
            max_manifest_age: None,
        });
        cfg.local_poi_caches = Some(local_caches);
        let (_live_tx, live_rx) = broadcast::channel(8);
        let (backfill_tx, backfill_rx) = mpsc::channel(8);
        let (backfill_request_tx, _backfill_request_rx) = mpsc::channel(8);
        let cancel = CancellationToken::new();
        let handle = spawn_wallet_worker(
            WalletWorkerServices {
                db: Arc::clone(&db),
                rpcs: Arc::new(QueryRpcPool::new(
                    vec![Url::parse("http://127.0.0.1:1").expect("rpc url")],
                    Duration::from_secs(1),
                )),
                http_client: None,
                indexed_artifact_source: None,
                forest: Arc::new(RwLock::new(MerkleForest::new())),
                backfill_tx: backfill_request_tx,
                backfill_sender: backfill_tx,
                public_data_plane: test_public_data_plane(&db),
            },
            cfg.clone(),
            1,
            live_rx,
            backfill_rx,
            cancel.clone(),
            vec![test_wallet_utxo(105, 7)],
            100,
        )
        .await
        .expect("spawn wallet worker");
        let (ready_tx, ready_rx) = watch::channel(true);
        let (readiness_tx, readiness_rx) = watch::channel(WalletReadiness::Syncing);
        let remote_client = PoiRpcClient::new(cfg.poi_rpc_url.clone());
        let status_reader = wallet_poi_status_reader_source(&remote_client, &cfg);
        let mut persist_state = WalletPersistState::default();
        let mut actor_state = WalletActorState::new(1, 1, 0, 100, 0, None);
        let active_poi_list_keys = default_active_poi_list_keys();

        let result = WalletPoiStatusRefreshCommitRequest {
            cache_store: cache_store.as_ref(),
            cfg: &cfg,
            utxos: &handle.utxos,
            worker_handle: &handle,
            last_scanned: 100,
            reset_generation: 0,
            actor_state: &mut actor_state,
            persist_state: &mut persist_state,
            ready_tx: &ready_tx,
            readiness_tx: &readiness_tx,
            status_reader: status_reader.as_reader(),
            active_poi_list_keys: &active_poi_list_keys,
            selection: WalletPoiRefreshSelection::RequiredOrRecoverable,
            cancel: &cancel,
        }
        .commit()
        .await;

        assert_eq!(result, Err(WalletBackfillRejectReason::PersistenceFailed));
        assert!(!*ready_rx.borrow());
        assert_eq!(
            *readiness_rx.borrow(),
            WalletReadiness::Failed(WalletReadinessError::PersistenceFailed)
        );
        assert_eq!(*handle.rev_rx.borrow(), 0);
        let snapshot = handle.utxos.read().await;
        assert!(snapshot[0].utxo.poi.statuses.is_empty());
        assert!(snapshot[0].utxo.poi.refreshed_at.is_none());
        assert_eq!(cache_store.state().store_calls, 1);

        cancel.cancel();
        drop(snapshot);
        drop(db);
        fs::remove_dir_all(root_dir).expect("remove temp db dir");
    }

    #[tokio::test]
    async fn wallet_poi_refresh_rejects_when_reset_arrives_during_status_fetch() {
        let root_dir = temp_db_root("wallet-poi-refresh-reset-race");
        let db = Arc::new(
            DbStore::open(DbConfig {
                root_dir: root_dir.clone(),
            })
            .expect("open db"),
        );
        let cache_store = Arc::new(FailingCacheStore::new(Arc::clone(&db)));
        let mut cfg = wallet_config();
        cfg.cache_store = Some(cache_store.clone());
        cfg.poi_read_source = PoiReadSource::PoiProxy;
        let active_poi_list_keys = default_active_poi_list_keys();
        let initial_utxo = test_wallet_utxo(105, 7);
        let (started_tx, started_rx) = oneshot::channel();
        let (release, release_rx) = oneshot::channel();
        let status_reader = Arc::new(BlockingPoiStatusReader::new(started_tx, release_rx));
        let (_live_tx, live_rx) = broadcast::channel(8);
        let (backfill_tx, backfill_rx) = mpsc::channel(8);
        let (backfill_request_tx, _backfill_request_rx) = mpsc::channel(8);
        let cancel = CancellationToken::new();
        let handle = spawn_wallet_worker(
            WalletWorkerServices {
                db: Arc::clone(&db),
                rpcs: Arc::new(QueryRpcPool::new(
                    vec![Url::parse("http://127.0.0.1:1").expect("rpc url")],
                    Duration::from_secs(1),
                )),
                http_client: None,
                indexed_artifact_source: None,
                forest: Arc::new(RwLock::new(MerkleForest::new())),
                backfill_tx: backfill_request_tx,
                backfill_sender: backfill_tx,
                public_data_plane: test_public_data_plane(&db),
            },
            cfg.clone(),
            1,
            live_rx,
            backfill_rx,
            cancel.clone(),
            vec![initial_utxo],
            100,
        )
        .await
        .expect("spawn wallet worker");
        let (ready_tx, _ready_rx) = watch::channel(true);
        let (readiness_tx, readiness_rx) = watch::channel(WalletReadiness::Syncing);
        let commit_cache_store = Arc::clone(&cache_store);
        let commit_cfg = cfg.clone();
        let commit_handle = handle.clone();
        let commit_cancel = cancel.clone();
        let commit_active_poi_list_keys = active_poi_list_keys.clone();
        let commit_status_reader = Arc::clone(&status_reader);
        let commit_task = tokio::spawn(async move {
            let mut persist_state = WalletPersistState::default();
            let mut actor_state = WalletActorState::new(1, 1, 0, 100, 0, None);
            WalletPoiStatusRefreshCommitRequest {
                cache_store: commit_cache_store.as_ref(),
                cfg: &commit_cfg,
                utxos: &commit_handle.utxos,
                worker_handle: &commit_handle,
                last_scanned: 100,
                reset_generation: 0,
                actor_state: &mut actor_state,
                persist_state: &mut persist_state,
                ready_tx: &ready_tx,
                readiness_tx: &readiness_tx,
                status_reader: commit_status_reader.as_ref(),
                active_poi_list_keys: &commit_active_poi_list_keys,
                selection: WalletPoiRefreshSelection::RequiredOrRecoverable,
                cancel: &commit_cancel,
            }
            .commit()
            .await
        });
        tokio::time::timeout(Duration::from_secs(2), started_rx)
            .await
            .expect("status request started")
            .expect("status request signal sent");

        assert_eq!(handle.advance_reset_generation().await, Some(1));
        release.send(()).expect("release status reader");
        let result = commit_task.await.expect("commit task");

        assert!(matches!(
            result,
            Err(WalletBackfillRejectReason::StaleGeneration {
                expected: 1,
                actual: 0
            })
        ));
        assert_eq!(*readiness_rx.borrow(), WalletReadiness::Syncing);
        assert_eq!(*handle.rev_rx.borrow(), 0);
        let snapshot = handle.utxos.read().await;
        assert!(snapshot[0].utxo.poi.statuses.is_empty());
        assert!(snapshot[0].utxo.poi.refreshed_at.is_none());
        assert_eq!(cache_store.state().store_calls, 0);

        cancel.cancel();
        drop(snapshot);
        drop(db);
        fs::remove_dir_all(root_dir).expect("remove temp db dir");
    }

    #[tokio::test]
    async fn wallet_scan_commit_rejects_when_reset_arrives_during_poi_refresh() {
        let root_dir = temp_db_root("wallet-scan-commit-reset-race");
        let db = Arc::new(
            DbStore::open(DbConfig {
                root_dir: root_dir.clone(),
            })
            .expect("open db"),
        );
        let cache_store = Arc::new(FailingCacheStore::new(Arc::clone(&db)));
        let mut cfg = wallet_config();
        cfg.cache_store = Some(cache_store.clone());
        cfg.poi_read_source = PoiReadSource::PoiProxy;
        let active_poi_list_keys = default_active_poi_list_keys();
        let wallet_utxo = test_wallet_utxo(105, 7);
        let (started_tx, started_rx) = oneshot::channel();
        let (release, release_rx) = oneshot::channel();
        let status_reader = Arc::new(BlockingPoiStatusReader::new(started_tx, release_rx));
        let (_live_tx, live_rx) = broadcast::channel(8);
        let (backfill_tx, backfill_rx) = mpsc::channel(8);
        let (backfill_request_tx, _backfill_request_rx) = mpsc::channel(8);
        let cancel = CancellationToken::new();
        let handle = spawn_wallet_worker(
            WalletWorkerServices {
                db: Arc::clone(&db),
                rpcs: Arc::new(QueryRpcPool::new(
                    vec![Url::parse("http://127.0.0.1:1").expect("rpc url")],
                    Duration::from_secs(1),
                )),
                http_client: None,
                indexed_artifact_source: None,
                forest: Arc::new(RwLock::new(MerkleForest::new())),
                backfill_tx: backfill_request_tx,
                backfill_sender: backfill_tx,
                public_data_plane: test_public_data_plane(&db),
            },
            cfg.clone(),
            1,
            live_rx,
            backfill_rx,
            cancel.clone(),
            Vec::new(),
            100,
        )
        .await
        .expect("spawn wallet worker");
        let (ready_tx, _ready_rx) = watch::channel(true);
        let (readiness_tx, readiness_rx) = watch::channel(WalletReadiness::Syncing);
        let commit_db = Arc::clone(&db);
        let commit_cache_store = Arc::clone(&cache_store);
        let commit_cfg = cfg.clone();
        let commit_handle = handle.clone();
        let commit_cancel = cancel.clone();
        let commit_active_poi_list_keys = active_poi_list_keys.clone();
        let commit_status_reader = Arc::clone(&status_reader);
        let commit_task = tokio::spawn(async move {
            let commit_public_data_plane = test_public_data_plane(&commit_db);
            let mut last_scanned = 100;
            let mut persist_state = WalletPersistState::default();
            let mut live_metadata_flush = WalletLiveMetadataFlush::new(100, Instant::now());
            let mut actor_state = WalletActorState::new(1, 1, 0, 100, 0, None);
            WalletScanCommitRequest {
                db: commit_db.as_ref(),
                cache_store: commit_cache_store.as_ref(),
                cfg: &commit_cfg,
                utxos: &commit_handle.utxos,
                worker_handle: &commit_handle,
                apply: indexed_delta_batch(
                    101,
                    110,
                    WalletLogDelta {
                        utxos: vec![wallet_utxo.utxo],
                        nullifiers: Vec::new(),
                        commitment_observations: Vec::new(),
                    },
                ),
                current_reset_generation: 0,
                event_reset_generation: 0,
                actor_state: &mut actor_state,
                cancel: &commit_cancel,
                last_scanned: &mut last_scanned,
                persist_state: &mut persist_state,
                live_metadata_flush: &mut live_metadata_flush,
                ready_tx: &ready_tx,
                readiness_tx: &readiness_tx,
                poi_submitter: None,
                poi_status_reader: Some(commit_status_reader.as_ref()),
                active_poi_list_keys: &commit_active_poi_list_keys,
                refresh_poi_statuses: true,
                mark_syncing_on_commit: true,
                public_data_plane: &commit_public_data_plane,
            }
            .commit()
            .await
        });
        tokio::time::timeout(Duration::from_secs(2), started_rx)
            .await
            .expect("status request started")
            .expect("status request signal sent");

        assert_eq!(handle.advance_reset_generation().await, Some(1));
        release.send(()).expect("release status reader");
        let outcome = commit_task.await.expect("commit task");

        assert!(matches!(
            outcome.result,
            WalletBackfillApplyResult::Rejected {
                reason: WalletBackfillRejectReason::StaleGeneration {
                    expected: 1,
                    actual: 0,
                },
                ..
            }
        ));
        assert!(!outcome.changed);
        assert_eq!(*readiness_rx.borrow(), WalletReadiness::Syncing);
        assert_eq!(handle.last_scanned(), 100);
        assert_eq!(*handle.rev_rx.borrow(), 0);
        assert!(handle.utxos.read().await.is_empty());
        assert_eq!(cache_store.state().store_calls, 0);

        cancel.cancel();
        drop(db);
        fs::remove_dir_all(root_dir).expect("remove temp db dir");
    }

    #[tokio::test]
    async fn wallet_scan_commit_rejects_when_public_data_epoch_changes_during_poi_refresh() {
        let root_dir = temp_db_root("wallet-scan-commit-public-epoch-race");
        let db = Arc::new(
            DbStore::open(DbConfig {
                root_dir: root_dir.clone(),
            })
            .expect("open db"),
        );
        let cache_store = Arc::new(FailingCacheStore::new(Arc::clone(&db)));
        let mut cfg = wallet_config();
        cfg.cache_store = Some(cache_store.clone());
        cfg.poi_read_source = PoiReadSource::PoiProxy;
        let active_poi_list_keys = default_active_poi_list_keys();
        let wallet_utxo = test_wallet_utxo(105, 7);
        let (started_tx, started_rx) = oneshot::channel();
        let (release, release_rx) = oneshot::channel();
        let status_reader = Arc::new(BlockingPoiStatusReader::new(started_tx, release_rx));
        let (_live_tx, live_rx) = broadcast::channel(8);
        let (backfill_tx, backfill_rx) = mpsc::channel(8);
        let (backfill_request_tx, _backfill_request_rx) = mpsc::channel(8);
        let cancel = CancellationToken::new();
        let public_data_plane = test_public_data_plane(&db);
        let handle = spawn_wallet_worker(
            WalletWorkerServices {
                db: Arc::clone(&db),
                rpcs: Arc::new(QueryRpcPool::new(
                    vec![Url::parse("http://127.0.0.1:1").expect("rpc url")],
                    Duration::from_secs(1),
                )),
                http_client: None,
                indexed_artifact_source: None,
                forest: Arc::new(RwLock::new(MerkleForest::new())),
                backfill_tx: backfill_request_tx,
                backfill_sender: backfill_tx,
                public_data_plane: public_data_plane.clone(),
            },
            cfg.clone(),
            1,
            live_rx,
            backfill_rx,
            cancel.clone(),
            Vec::new(),
            100,
        )
        .await
        .expect("spawn wallet worker");
        let (ready_tx, _ready_rx) = watch::channel(true);
        let (readiness_tx, readiness_rx) = watch::channel(WalletReadiness::Syncing);
        let commit_db = Arc::clone(&db);
        let commit_cache_store = Arc::clone(&cache_store);
        let commit_cfg = cfg.clone();
        let commit_handle = handle.clone();
        let commit_cancel = cancel.clone();
        let commit_active_poi_list_keys = active_poi_list_keys.clone();
        let commit_status_reader = Arc::clone(&status_reader);
        let commit_public_data_plane = public_data_plane.clone();
        let commit_task = tokio::spawn(async move {
            let mut last_scanned = 100;
            let mut persist_state = WalletPersistState::default();
            let mut live_metadata_flush = WalletLiveMetadataFlush::new(100, Instant::now());
            let mut actor_state = WalletActorState::new(1, 1, 0, 100, 0, None);
            WalletScanCommitRequest {
                db: commit_db.as_ref(),
                cache_store: commit_cache_store.as_ref(),
                cfg: &commit_cfg,
                utxos: &commit_handle.utxos,
                worker_handle: &commit_handle,
                apply: indexed_delta_batch(
                    101,
                    110,
                    WalletLogDelta {
                        utxos: vec![wallet_utxo.utxo],
                        nullifiers: Vec::new(),
                        commitment_observations: Vec::new(),
                    },
                ),
                current_reset_generation: 0,
                event_reset_generation: 0,
                actor_state: &mut actor_state,
                cancel: &commit_cancel,
                last_scanned: &mut last_scanned,
                persist_state: &mut persist_state,
                live_metadata_flush: &mut live_metadata_flush,
                ready_tx: &ready_tx,
                readiness_tx: &readiness_tx,
                poi_submitter: None,
                poi_status_reader: Some(commit_status_reader.as_ref()),
                active_poi_list_keys: &commit_active_poi_list_keys,
                refresh_poi_statuses: true,
                mark_syncing_on_commit: true,
                public_data_plane: &commit_public_data_plane,
            }
            .commit()
            .await
        });
        tokio::time::timeout(Duration::from_secs(2), started_rx)
            .await
            .expect("status request started")
            .expect("status request signal sent");

        public_data_plane
            .invalidate_public_scan_coverage_from(101)
            .await;
        release.send(()).expect("release status reader");
        let outcome = commit_task.await.expect("commit task");

        assert_eq!(
            outcome.result,
            WalletBackfillApplyResult::Rejected {
                committed_to: 100,
                reason: WalletBackfillRejectReason::StaleDataPlaneEpoch {
                    expected: 1,
                    actual: 0,
                },
            }
        );
        assert!(!outcome.changed);
        assert_eq!(*readiness_rx.borrow(), WalletReadiness::Syncing);
        assert_eq!(handle.last_scanned(), 100);
        assert_eq!(*handle.rev_rx.borrow(), 0);
        assert!(handle.utxos.read().await.is_empty());
        assert_eq!(cache_store.state().store_calls, 0);

        cancel.cancel();
        drop(db);
        fs::remove_dir_all(root_dir).expect("remove temp db dir");
    }

    #[tokio::test]
    async fn wallet_worker_marks_ready_after_queued_indexed_startup_delta() {
        let root_dir = temp_db_root("wallet-worker-indexed-startup-ready");
        let db = Arc::new(
            DbStore::open(DbConfig {
                root_dir: root_dir.clone(),
            })
            .expect("open db"),
        );
        let (_live_tx, live_rx) = broadcast::channel(8);
        let (backfill_tx, backfill_rx) = mpsc::channel(8);
        let (backfill_request_tx, _backfill_request_rx) = mpsc::channel(8);
        let cancel = CancellationToken::new();
        let handle = spawn_wallet_worker(
            WalletWorkerServices {
                db: Arc::clone(&db),
                rpcs: Arc::new(QueryRpcPool::new(
                    vec![Url::parse("http://127.0.0.1:1").expect("rpc url")],
                    Duration::from_secs(1),
                )),
                http_client: None,
                indexed_artifact_source: None,
                forest: Arc::new(RwLock::new(MerkleForest::new())),
                backfill_tx: backfill_request_tx,
                backfill_sender: backfill_tx.clone(),
                public_data_plane: test_public_data_plane(&db),
            },
            wallet_config(),
            1,
            live_rx,
            backfill_rx,
            cancel.clone(),
            Vec::new(),
            100,
        )
        .await
        .expect("spawn wallet worker");

        assert_eq!(
            send_apply(
                &handle,
                &backfill_tx,
                indexed_delta_batch(101, 200, empty_delta()),
                0
            )
            .await,
            WalletBackfillApplyResult::Committed { committed_to: 200 }
        );
        assert_eq!(
            send_target(&handle, &backfill_tx, 200, 0).await,
            WalletBackfillFinishResult::Ready { committed_to: 200 }
        );

        tokio::time::timeout(Duration::from_secs(1), async {
            while handle.last_scanned() != 200 || !*handle.ready_rx.borrow() {
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .expect("indexed startup done marked ready");

        cancel.cancel();
        drop(db);
        fs::remove_dir_all(root_dir).expect("remove temp db dir");
    }

    #[tokio::test]
    async fn wallet_worker_rejects_non_contiguous_log_batch() {
        let root_dir = temp_db_root("wallet-worker-log-gap");
        let db = Arc::new(
            DbStore::open(DbConfig {
                root_dir: root_dir.clone(),
            })
            .expect("open db"),
        );
        let (_live_tx, live_rx) = broadcast::channel(8);
        let (backfill_tx, backfill_rx) = mpsc::channel(8);
        let (backfill_request_tx, _backfill_request_rx) = mpsc::channel(8);
        let cancel = CancellationToken::new();
        let handle = spawn_wallet_worker(
            WalletWorkerServices {
                db: Arc::clone(&db),
                rpcs: Arc::new(QueryRpcPool::new(
                    vec![Url::parse("http://127.0.0.1:1").expect("rpc url")],
                    Duration::from_secs(1),
                )),
                http_client: None,
                indexed_artifact_source: None,
                forest: Arc::new(RwLock::new(MerkleForest::new())),
                backfill_tx: backfill_request_tx,
                backfill_sender: backfill_tx.clone(),
                public_data_plane: test_public_data_plane(&db),
            },
            wallet_config(),
            1,
            live_rx,
            backfill_rx,
            cancel.clone(),
            Vec::new(),
            100,
        )
        .await
        .expect("spawn wallet worker");

        assert_eq!(
            send_apply(&handle, &backfill_tx, logs_apply(105, 110), 0).await,
            WalletBackfillApplyResult::Rejected {
                committed_to: 100,
                reason: WalletBackfillRejectReason::NonContiguous {
                    expected_from: 101,
                    actual_from: 105,
                },
            }
        );
        assert_eq!(handle.last_scanned(), 100);

        cancel.cancel();
        drop(db);
        fs::remove_dir_all(root_dir).expect("remove temp db dir");
    }

    #[tokio::test]
    async fn wallet_worker_bounds_shared_log_payload_to_apply_range_and_target() {
        let root_dir = temp_db_root("wallet-worker-bounded-shared-log-payload");
        let db = Arc::new(
            DbStore::open(DbConfig {
                root_dir: root_dir.clone(),
            })
            .expect("open db"),
        );
        let mut cfg = wallet_config();
        cfg.sync_to_block = Some(130);
        let (_live_tx, live_rx) = broadcast::channel(8);
        let (backfill_tx, backfill_rx) = mpsc::channel(8);
        let (backfill_request_tx, _backfill_request_rx) = mpsc::channel(8);
        let cancel = CancellationToken::new();
        let handle = spawn_wallet_worker(
            WalletWorkerServices {
                db: Arc::clone(&db),
                rpcs: Arc::new(QueryRpcPool::new(
                    vec![Url::parse("http://127.0.0.1:1").expect("rpc url")],
                    Duration::from_secs(1),
                )),
                http_client: None,
                indexed_artifact_source: None,
                forest: Arc::new(RwLock::new(MerkleForest::new())),
                backfill_tx: backfill_request_tx,
                backfill_sender: backfill_tx.clone(),
                public_data_plane: test_public_data_plane(&db),
            },
            cfg,
            1,
            live_rx,
            backfill_rx,
            cancel.clone(),
            Vec::new(),
            119,
        )
        .await
        .expect("spawn wallet worker");

        assert_eq!(
            send_apply(
                &handle,
                &backfill_tx,
                WalletScanApply::rows_from_log_batch(
                    120,
                    130,
                    logs_payload(100, 199),
                    crate::types::PublicScanSource::Rpc,
                )
                .expect("normalize shared log payload"),
                0,
            )
            .await,
            WalletBackfillApplyResult::Committed { committed_to: 130 }
        );
        assert_eq!(handle.last_scanned(), 130);
        assert_eq!(
            send_apply(
                &handle,
                &backfill_tx,
                WalletScanApply::rows_from_log_batch(
                    131,
                    199,
                    logs_payload(100, 199),
                    crate::types::PublicScanSource::Rpc,
                )
                .expect("normalize shared log payload"),
                0,
            )
            .await,
            WalletBackfillApplyResult::Rejected {
                committed_to: 130,
                reason: WalletBackfillRejectReason::TargetExceeded {
                    target_block: 130,
                    requested_to: 199,
                },
            }
        );
        assert_eq!(handle.last_scanned(), 130);

        cancel.cancel();
        drop(db);
        fs::remove_dir_all(root_dir).expect("remove temp db dir");
    }

    #[tokio::test]
    async fn wallet_handle_rejects_duplicate_indexed_catch_up_claim_until_cleared() {
        let root_dir = temp_db_root("wallet-worker-indexed-catch-up-lease");
        let db = Arc::new(
            DbStore::open(DbConfig {
                root_dir: root_dir.clone(),
            })
            .expect("open db"),
        );
        let (_live_tx, live_rx) = broadcast::channel(8);
        let (backfill_tx, backfill_rx) = mpsc::channel(8);
        let (backfill_request_tx, _backfill_request_rx) = mpsc::channel(8);
        let cancel = CancellationToken::new();
        let handle = spawn_wallet_worker(
            WalletWorkerServices {
                db: Arc::clone(&db),
                rpcs: Arc::new(QueryRpcPool::new(
                    vec![Url::parse("http://127.0.0.1:1").expect("rpc url")],
                    Duration::from_secs(1),
                )),
                http_client: None,
                indexed_artifact_source: None,
                forest: Arc::new(RwLock::new(MerkleForest::new())),
                backfill_tx: backfill_request_tx,
                backfill_sender: backfill_tx.clone(),
                public_data_plane: test_public_data_plane(&db),
            },
            wallet_config(),
            1,
            live_rx,
            backfill_rx,
            cancel.clone(),
            Vec::new(),
            100,
        )
        .await
        .expect("spawn wallet worker");

        assert_eq!(
            send_target(&handle, &backfill_tx, 100, 0).await,
            WalletBackfillFinishResult::Ready { committed_to: 100 }
        );
        assert_eq!(handle.readiness(), WalletReadiness::Ready);

        let first_lease = handle
            .try_claim_indexed_catch_up()
            .await
            .expect("first indexed catch-up claim");
        assert_eq!(handle.readiness(), WalletReadiness::Syncing);
        assert!(handle.try_claim_indexed_catch_up().await.is_none());
        let first_status = WalletIndexedCatchUpStatus {
            source: WalletIndexedCatchUpSource::IndexedArtifacts,
            from_block: 101,
            target_block: 200,
        };
        handle.set_indexed_catch_up(first_lease, first_status.clone());
        tokio::time::timeout(Duration::from_secs(1), async {
            while handle.indexed_catch_up_rx.borrow().is_none() {
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .expect("indexed catch-up status published");
        assert_eq!(
            handle.indexed_catch_up_rx.borrow().as_ref(),
            Some(&first_status)
        );
        handle.clear_indexed_catch_up(first_lease);
        tokio::time::timeout(Duration::from_secs(1), async {
            while handle.indexed_catch_up_rx.borrow().is_some() {
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .expect("indexed catch-up status cleared");
        tokio::time::timeout(Duration::from_secs(1), async {
            while handle.readiness() != WalletReadiness::Ready {
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .expect("indexed catch-up readiness restored");
        let second_lease = handle
            .try_claim_indexed_catch_up()
            .await
            .expect("second indexed catch-up claim");
        let second_status = WalletIndexedCatchUpStatus {
            source: WalletIndexedCatchUpSource::Squid,
            from_block: 201,
            target_block: 300,
        };
        handle.set_indexed_catch_up(second_lease, second_status.clone());
        tokio::time::timeout(Duration::from_secs(1), async {
            while handle.indexed_catch_up_rx.borrow().as_ref() != Some(&second_status) {
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .expect("second indexed catch-up status published");

        handle.set_indexed_catch_up(first_lease, first_status);
        handle.clear_indexed_catch_up(first_lease);
        tokio::time::sleep(Duration::from_millis(25)).await;
        assert_eq!(
            handle.indexed_catch_up_rx.borrow().as_ref(),
            Some(&second_status)
        );
        assert!(send_reset(&backfill_tx, 1, 50).await.committed());
        tokio::time::timeout(Duration::from_secs(1), async {
            while handle.indexed_catch_up_rx.borrow().is_some() {
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .expect("reset cleared indexed catch-up status");
        handle.clear_indexed_catch_up(second_lease);

        cancel.cancel();
        drop(db);
        fs::remove_dir_all(root_dir).expect("remove temp db dir");
    }

    #[tokio::test]
    async fn wallet_worker_ignores_done_after_non_contiguous_indexed_delta() {
        let root_dir = temp_db_root("wallet-worker-indexed-tail-non-contiguous-done");
        let db = Arc::new(
            DbStore::open(DbConfig {
                root_dir: root_dir.clone(),
            })
            .expect("open db"),
        );
        let (_live_tx, live_rx) = broadcast::channel(8);
        let (backfill_tx, backfill_rx) = mpsc::channel(8);
        let (backfill_request_tx, _backfill_request_rx) = mpsc::channel(8);
        let cancel = CancellationToken::new();
        let handle = spawn_wallet_worker(
            WalletWorkerServices {
                db: Arc::clone(&db),
                rpcs: Arc::new(QueryRpcPool::new(
                    vec![Url::parse("http://127.0.0.1:1").expect("rpc url")],
                    Duration::from_secs(1),
                )),
                http_client: None,
                indexed_artifact_source: None,
                forest: Arc::new(RwLock::new(MerkleForest::new())),
                backfill_tx: backfill_request_tx,
                backfill_sender: backfill_tx.clone(),
                public_data_plane: test_public_data_plane(&db),
            },
            wallet_config(),
            1,
            live_rx,
            backfill_rx,
            cancel.clone(),
            Vec::new(),
            150,
        )
        .await
        .expect("spawn wallet worker");

        assert_eq!(
            send_apply(
                &handle,
                &backfill_tx,
                indexed_delta_batch(101, 200, empty_delta()),
                0
            )
            .await,
            WalletBackfillApplyResult::Rejected {
                committed_to: 150,
                reason: WalletBackfillRejectReason::NonContiguous {
                    expected_from: 151,
                    actual_from: 101,
                },
            }
        );
        assert!(matches!(
            send_target(&handle, &backfill_tx, 200, 0).await,
            WalletBackfillFinishResult::Accepted {
                committed_to: 150,
                target_block: 200,
                ..
            }
        ));
        assert_eq!(handle.last_scanned(), 150);
        assert_eq!(
            send_apply(
                &handle,
                &backfill_tx,
                indexed_delta_batch(151, 151, empty_delta()),
                0
            )
            .await,
            WalletBackfillApplyResult::Committed { committed_to: 151 }
        );

        tokio::time::timeout(Duration::from_secs(1), async {
            while handle.last_scanned() == 150 {
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .expect("marker delta processed");
        assert_eq!(handle.last_scanned(), 151);

        cancel.cancel();
        drop(db);
        fs::remove_dir_all(root_dir).expect("remove temp db dir");
    }

    #[tokio::test]
    async fn wallet_worker_ignores_stale_indexed_tail_events_after_reset() {
        let root_dir = temp_db_root("wallet-worker-indexed-tail-reset");
        let db = Arc::new(
            DbStore::open(DbConfig {
                root_dir: root_dir.clone(),
            })
            .expect("open db"),
        );
        let (_live_tx, live_rx) = broadcast::channel(8);
        let (backfill_tx, backfill_rx) = mpsc::channel(8);
        let (backfill_request_tx, _backfill_request_rx) = mpsc::channel(8);
        let cancel = CancellationToken::new();
        let handle = spawn_wallet_worker(
            WalletWorkerServices {
                db: Arc::clone(&db),
                rpcs: Arc::new(QueryRpcPool::new(
                    vec![Url::parse("http://127.0.0.1:1").expect("rpc url")],
                    Duration::from_secs(1),
                )),
                http_client: None,
                indexed_artifact_source: None,
                forest: Arc::new(RwLock::new(MerkleForest::new())),
                backfill_tx: backfill_request_tx,
                backfill_sender: backfill_tx.clone(),
                public_data_plane: test_public_data_plane(&db),
            },
            wallet_config(),
            1,
            live_rx,
            backfill_rx,
            cancel.clone(),
            Vec::new(),
            100,
        )
        .await
        .expect("spawn wallet worker");

        assert_eq!(
            send_reset(&backfill_tx, 1, 80).await,
            WalletBackfillResetResult::Accepted {
                reset_generation: 1,
                committed_to: 79,
                committed: true,
            }
        );
        tokio::time::timeout(Duration::from_secs(1), async {
            while handle.reset_generation() != 1 || handle.last_scanned() != 79 {
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .expect("reset applied");

        assert_eq!(
            send_apply(
                &handle,
                &backfill_tx,
                indexed_delta_batch(
                    101,
                    150,
                    WalletLogDelta {
                        utxos: vec![test_wallet_utxo(120, 1).utxo],
                        nullifiers: Vec::new(),
                        commitment_observations: Vec::new(),
                    },
                ),
                0,
            )
            .await,
            WalletBackfillApplyResult::Rejected {
                committed_to: 79,
                reason: WalletBackfillRejectReason::StaleGeneration {
                    expected: 1,
                    actual: 0,
                },
            }
        );
        assert!(matches!(
            send_target(&handle, &backfill_tx, 150, 0).await,
            WalletBackfillFinishResult::Rejected {
                reason: WalletBackfillRejectReason::StaleGeneration { .. },
                ..
            }
        ));
        assert!(matches!(
            send_apply(&handle, &backfill_tx, logs_apply(101, 150), 0).await,
            WalletBackfillApplyResult::Rejected {
                reason: WalletBackfillRejectReason::StaleGeneration { .. },
                ..
            }
        ));
        assert_eq!(handle.last_scanned(), 79);

        assert!(matches!(
            send_apply(
                &handle,
                &backfill_tx,
                indexed_delta_batch(101, 150, empty_delta()),
                1
            )
            .await,
            WalletBackfillApplyResult::Rejected {
                reason: WalletBackfillRejectReason::NonContiguous { .. },
                ..
            }
        ));
        let current_target_token = handle.mint_sync_token(1);
        assert_target_accepted(
            send_target_token(&backfill_tx, 150, current_target_token).await,
            current_target_token,
            79,
            150,
        );
        backfill_tx
            .send(BackfillEvent::JobRetired {
                token: current_target_token,
            })
            .await
            .expect("retire unattached current target");
        tokio::task::yield_now().await;
        assert_eq!(
            send_apply(
                &handle,
                &backfill_tx,
                indexed_delta_batch(80, 90, empty_delta()),
                1,
            )
            .await,
            WalletBackfillApplyResult::Committed { committed_to: 90 }
        );
        tokio::time::timeout(Duration::from_secs(1), async {
            while handle.last_scanned() != 90 {
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .expect("current delta applied");

        cancel.cancel();
        drop(db);
        fs::remove_dir_all(root_dir).expect("remove temp db dir");
    }

    #[tokio::test]
    async fn wallet_worker_requests_backfill_after_live_receiver_lag() {
        let root_dir = temp_db_root("wallet-worker-live-lag-gap");
        let db = Arc::new(
            DbStore::open(DbConfig {
                root_dir: root_dir.clone(),
            })
            .expect("open db"),
        );
        let (live_tx, live_rx) = broadcast::channel(8);
        let (backfill_tx, backfill_rx) = mpsc::channel(8);
        let (backfill_request_tx, mut backfill_request_rx) = mpsc::channel(8);
        let cancel = CancellationToken::new();
        let handle = spawn_wallet_worker(
            WalletWorkerServices {
                db: Arc::clone(&db),
                rpcs: Arc::new(QueryRpcPool::new(
                    vec![Url::parse("http://127.0.0.1:1").expect("rpc url")],
                    Duration::from_secs(1),
                )),
                http_client: None,
                indexed_artifact_source: None,
                forest: Arc::new(RwLock::new(MerkleForest::new())),
                backfill_tx: backfill_request_tx,
                backfill_sender: backfill_tx.clone(),
                public_data_plane: test_public_data_plane(&db),
            },
            wallet_config(),
            1,
            live_rx,
            backfill_rx,
            cancel.clone(),
            Vec::new(),
            100,
        )
        .await
        .expect("spawn wallet worker");
        for block in 101..=120 {
            live_tx
                .send(Arc::new(LogBatch {
                    from_block: block,
                    to_block: block,
                    logs: Vec::new(),
                    block_timestamps: HashMap::new(),
                    to_block_hash: None,
                    read_scope: test_public_scan_read_scope(),
                }))
                .expect("live receiver");
        }
        tokio::task::yield_now().await;
        assert_eq!(handle.last_scanned(), 100);

        assert_eq!(
            send_target(&handle, &backfill_tx, 100, 0).await,
            WalletBackfillFinishResult::Ready { committed_to: 100 }
        );
        let request = tokio::time::timeout(Duration::from_secs(1), backfill_request_rx.recv())
            .await
            .expect("live gap backfill requested")
            .expect("backfill request channel open");
        let BackfillRequest::Add {
            cache_key,
            from_block,
            to_block,
            follow_safe_head,
            lease,
            ..
        } = request
        else {
            panic!("expected add backfill request");
        };
        assert_eq!(cache_key, "test");
        assert_eq!(from_block, 101);
        assert!(to_block > from_block);
        assert!(follow_safe_head);
        assert_eq!(lease.token().reset_generation(), 0);
        assert_eq!(handle.last_scanned(), 100);

        assert_eq!(
            send_apply_token(
                &backfill_tx,
                logs_apply(from_block, to_block),
                lease.token()
            )
            .await,
            WalletBackfillApplyResult::Committed {
                committed_to: to_block
            }
        );
        assert_eq!(
            send_target_token(&backfill_tx, to_block, lease.token()).await,
            WalletBackfillFinishResult::Ready {
                committed_to: to_block
            }
        );
        tokio::time::timeout(Duration::from_secs(1), async {
            while handle.last_scanned() != to_block {
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .expect("recovery backfill applied");

        cancel.cancel();
        drop(db);
        fs::remove_dir_all(root_dir).expect("remove temp db dir");
    }

    fn wallet_config() -> WalletConfig {
        WalletConfig {
            chain: ChainKey {
                chain_id: 1,
                contract: Address::ZERO,
            },
            cache_key: "test".to_string(),
            start_block: Some(0),
            sync_to_block: None,
            quick_sync_endpoint: None,
            scan_keys: ViewingKeyData {
                viewing_private_key: [0u8; 32],
                viewing_public_key: [0u8; 32],
                nullifying_key: U256::ZERO,
                master_public_key: U256::ZERO,
            },
            spending_public_key: None,
            progress_tx: None,
            cache_store: None,
            poi_recovery_prover: None,
            poi_rpc_url: Url::parse("http://127.0.0.1:1").expect("poi rpc url"),
            poi_read_source: PoiReadSource::PoiProxy,
            local_poi_caches: None,
            manage_local_poi_cache: false,
            use_indexed_wallet_catch_up: true,
        }
    }

    fn source(block_number: u64, byte: u8) -> UtxoSource {
        UtxoSource {
            tx_hash: FixedBytes::from([byte; 32]),
            block_number,
            block_timestamp: 1_700_000_000 + block_number,
        }
    }

    fn test_wallet_utxo(block_number: u64, position: u64) -> WalletUtxo {
        WalletUtxo::new(Utxo::new(
            Note {
                token_hash: U256::from(1),
                value: U256::from(10),
                random: [0u8; 16],
                npk: U256::from(2),
            },
            2,
            position,
            source(block_number, block_number as u8),
            UtxoCommitmentKind::Transact,
        ))
    }

    fn pending_output_context_for_wallet_utxo(
        cfg: &WalletConfig,
        wallet_utxo: &WalletUtxo,
    ) -> PendingOutputPoiContextRecord {
        PendingOutputPoiContextRecord {
            chain_id: cfg.chain.chain_id,
            wallet_id: cfg.cache_key.clone(),
            txid_version: DEFAULT_TXID_VERSION.to_string(),
            output_commitment: wallet_utxo.utxo.poi.commitment,
            output_npk: wallet_utxo.utxo.poi.npk,
            utxo_tree_in: u64::from(wallet_utxo.utxo.tree),
            railgun_txid: U256::from(7),
            txid_merkleroot_index: None,
            pre_transaction_pois_per_txid_leaf_per_list: BTreeMap::new(),
            required_poi_list_keys: Vec::new(),
            output_role: PendingOutputPoiRole::Recipient,
            created_at: 123,
            source_operation_id: None,
            observation: None,
            submitted_poi_list_keys: Vec::new(),
            terminal_error: None,
        }
    }

    fn temp_db_root(name: &str) -> std::path::PathBuf {
        let unique = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("system clock")
            .as_nanos();
        let dir = std::env::temp_dir().join(format!("sync-service-{name}-{unique}"));
        fs::create_dir_all(&dir).expect("create temp db dir");
        dir
    }
}
