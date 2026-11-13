#[allow(clippy::wildcard_imports)]
use super::*;

pub(super) fn wallet_poi_refresh_interval() -> tokio::time::Interval {
    wallet_poi_refresh_interval_with_period(WALLET_POI_REFRESH_INTERVAL)
}

pub(super) fn wallet_poi_refresh_interval_with_period(period: Duration) -> tokio::time::Interval {
    let mut interval = tokio::time::interval_at(tokio::time::Instant::now() + period, period);
    interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    interval
}

const POI_MAINTENANCE_WATCHDOG: Duration = Duration::from_mins(5);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum PoiMaintenanceAbortReason {
    Timeout,
    Panic,
}

impl PoiMaintenanceAbortReason {
    pub(super) const fn category(self) -> &'static str {
        match self {
            Self::Timeout => "timeout",
            Self::Panic => "panic",
        }
    }
}

pub(super) async fn run_poi_maintenance_with_watchdog<F, T>(
    future: F,
    timeout: Duration,
) -> Result<T, PoiMaintenanceAbortReason>
where
    F: std::future::Future<Output = T>,
{
    match tokio::time::timeout(timeout, AssertUnwindSafe(future).catch_unwind()).await {
        Ok(Ok(value)) => Ok(value),
        Ok(Err(_)) => Err(PoiMaintenanceAbortReason::Panic),
        Err(_) => Err(PoiMaintenanceAbortReason::Timeout),
    }
}

pub(super) async fn next_poi_corpus_revision(
    receiver: &mut Option<watch::Receiver<PoiCorpusRevision>>,
) -> Option<PoiCorpusRevision> {
    let Some(receiver) = receiver.as_mut() else {
        return futures::future::pending().await;
    };
    if receiver.changed().await.is_err() {
        return None;
    }
    Some(*receiver.borrow_and_update())
}

fn publish_poi_refreshing(
    sender: &watch::Sender<bool>,
    value: bool,
    worker_handle: &WalletHandle,
    reset_generation: u64,
    cancel: &CancellationToken,
) {
    if let Err(reason) = worker_handle.with_active_apply(cancel, reset_generation, |_token| {
        sender.send_if_modified(|current| {
            if *current == value {
                false
            } else {
                *current = value;
                true
            }
        });
    }) {
        debug!(?reason, cache_key = %worker_handle.cache_key, "wallet POI refresh state publication skipped");
    }
}

/// `poi_refreshing` is derived from the maintenance controller phase.
pub(super) fn sync_poi_refreshing_from_controller(
    controller: &PoiMaintenanceController,
    sender: &watch::Sender<bool>,
    handle: &WalletHandle,
    cancel: &CancellationToken,
) {
    publish_poi_refreshing(
        sender,
        controller.is_running(),
        handle,
        handle.authority_reset_generation(),
        cancel,
    );
}

fn poi_maintenance_can_start(handle: &WalletHandle) -> bool {
    handle.lifecycle().allows_durable_commits()
        && handle.is_current_actor()
        && handle.current_snapshot().is_some()
}

fn poi_maintenance_credential(handle: &WalletHandle) -> Option<WalletActorCredential> {
    if poi_maintenance_can_start(handle) {
        Some(WalletActorCredential::current_for(handle))
    } else {
        None
    }
}

/// Actor entry: coalesce force intent and spawn at most one maintenance job.
pub(super) fn request_poi_maintenance(
    controller: &mut PoiMaintenanceController,
    remote_done_tx: &mpsc::Sender<WalletRemoteDone>,
    private_apply: &WalletPrivateApplyClient,
    poi_jobs: &WalletPoiJobTracker,
    poi_refreshing_tx: &watch::Sender<bool>,
    handle: &WalletHandle,
    cancel: &CancellationToken,
    db: &Arc<DbStore>,
    cache_store: &Arc<dyn WalletCacheStore>,
    cfg: &WalletConfig,
    public_data_plane: &ChainPublicDataPlane,
    http_client: Option<&reqwest::Client>,
    indexed_artifact_source: Option<&IndexedArtifactSourceConfig>,
    poi_runtime: &WalletPoiRuntime,
    poi_submitter: &ChainPoiSubmitterHandle,
    forest: &Arc<RwLock<MerkleForest>>,
    utxos: &Arc<RwLock<Vec<WalletUtxo>>>,
    active_poi_list_keys: &[FixedBytes<32>],
    force_output_poi_recovery: bool,
) -> bool {
    let can_start = poi_maintenance_can_start(handle);
    let credential = poi_maintenance_credential(handle);
    let Some(spec) = controller.request(force_output_poi_recovery, can_start, credential) else {
        if force_output_poi_recovery && controller.force_pending() && controller.is_running() {
            debug!(
                cache_key = %handle.cache_key,
                "poi force maintenance deferred until in-flight job completes"
            );
        } else if controller.is_running() {
            debug!(
                cache_key = %handle.cache_key,
                "poi maintenance already running; follow-up latched"
            );
        }
        sync_poi_refreshing_from_controller(controller, poi_refreshing_tx, handle, cancel);
        return false;
    };

    let client = poi_runtime.public_client().clone();
    PoiMaintenanceJob {
        handle: handle.clone(),
        cancel: cancel.clone(),
        credential: spec.credential,
        key: spec.key,
        done_tx: remote_done_tx.clone(),
        apply_client: private_apply.clone(),
        db: Arc::clone(db),
        cache_store: Arc::clone(cache_store),
        cfg: cfg.clone(),
        public_data_plane: public_data_plane.clone(),
        http_client: http_client.cloned(),
        indexed_artifact_source: indexed_artifact_source.cloned(),
        poi_client: client,
        poi_is_indexed: poi_runtime.is_indexed_artifacts(),
        poi_wallet_read_fallback: poi_runtime.wallet_read_fallback_enabled(),
        poi_submitter: poi_submitter.clone(),
        forest: Arc::clone(forest),
        utxos: Arc::clone(utxos),
        active_poi_list_keys: active_poi_list_keys.to_vec(),
        force_output_poi_recovery: spec.force_output_poi_recovery,
        unshield_attempts: controller.unshield_attempts(),
        forced_deferrals: controller.forced_deferrals(),
    }
    .spawn(poi_jobs);
    debug!(
        cache_key = %handle.cache_key,
        force = spec.force_output_poi_recovery,
        ?spec.key,
        "poi maintenance job started"
    );
    sync_poi_refreshing_from_controller(controller, poi_refreshing_tx, handle, cancel);
    true
}

/// Refine a current candidate report against the unrefined base derived from durable records.
///
/// Returns `None` when the base cannot be derived; callers then treat the report as not current.
pub(super) fn current_ppoi_workflow_status_for_candidate_report(
    cache_store: &dyn WalletCacheStore,
    cfg: &WalletConfig,
    active_list_keys: &[FixedBytes<32>],
    published: crate::WalletPpoiWorkflowStatus,
    report: &SenderCandidateRecoveryReport,
) -> Option<crate::WalletPpoiWorkflowStatus> {
    let base = wallet_ppoi_workflow_status_after_mutations(
        cache_store,
        cfg,
        active_list_keys,
        published.validation_revision,
        &[],
        &[],
        &[],
        &[],
        &[],
        &[],
    )
    .ok()?
    .status;
    Some(ppoi_workflow_status_with_candidate_report(base, report))
}

/// Refine a PPOI workflow status with a current sender candidate recovery report.
///
/// `status` must be an unrefined base derived from durable records: the refinement moves
/// units between buckets, so applying it to an already refined status compounds the move.
pub(super) fn ppoi_workflow_status_with_candidate_report(
    mut status: crate::WalletPpoiWorkflowStatus,
    report: &SenderCandidateRecoveryReport,
) -> crate::WalletPpoiWorkflowStatus {
    // Submitted unshields wait on validation, not recovery.
    let moved = report
        .unshield_awaiting_validation
        .min(status.awaiting_recovery);
    status.awaiting_recovery -= moved;
    status.awaiting_validation = status.awaiting_validation.saturating_add(moved);
    status.awaiting_public_txid_data = report
        .awaiting_public_txid_data
        .min(status.awaiting_recovery);
    status.awaiting_poi_data = report.awaiting_poi_data.min(status.awaiting_recovery);
    status.retrying_recovery = report.retrying.min(status.awaiting_recovery);
    status.recovery_needs_attention = report.needs_attention.min(status.awaiting_recovery);
    status
}

/// Re-enter after remote job completion: clear phase, maybe start forced follow-up.
pub(super) fn on_poi_maintenance_done(
    controller: &mut PoiMaintenanceController,
    remote_done_tx: &mpsc::Sender<WalletRemoteDone>,
    private_apply: &WalletPrivateApplyClient,
    poi_jobs: &WalletPoiJobTracker,
    poi_refreshing_tx: &watch::Sender<bool>,
    handle: &WalletHandle,
    cancel: &CancellationToken,
    db: &Arc<DbStore>,
    cache_store: &Arc<dyn WalletCacheStore>,
    cfg: &WalletConfig,
    public_data_plane: &ChainPublicDataPlane,
    http_client: Option<&reqwest::Client>,
    indexed_artifact_source: Option<&IndexedArtifactSourceConfig>,
    poi_runtime: &WalletPoiRuntime,
    poi_submitter: &ChainPoiSubmitterHandle,
    forest: &Arc<RwLock<MerkleForest>>,
    utxos: &Arc<RwLock<Vec<WalletUtxo>>>,
    active_poi_list_keys: &[FixedBytes<32>],
    key: PoiRemoteJobKey,
) {
    let force_follow_up = controller.on_job_done(key);
    sync_poi_refreshing_from_controller(controller, poi_refreshing_tx, handle, cancel);
    if force_follow_up {
        debug!(
            cache_key = %handle.cache_key,
            "starting deferred force poi maintenance after prior job"
        );
        let _ = request_poi_maintenance(
            controller,
            remote_done_tx,
            private_apply,
            poi_jobs,
            poi_refreshing_tx,
            handle,
            cancel,
            db,
            cache_store,
            cfg,
            public_data_plane,
            http_client,
            indexed_artifact_source,
            poi_runtime,
            poi_submitter,
            forest,
            utxos,
            active_poi_list_keys,
            false, // force already latched in controller
        );
    }
}

/// Inputs for a background POI maintenance job (remote I/O off the actor select loop).
struct PoiMaintenanceJob {
    handle: WalletHandle,
    cancel: CancellationToken,
    credential: WalletActorCredential,
    key: PoiRemoteJobKey,
    done_tx: mpsc::Sender<WalletRemoteDone>,
    /// Private commits re-enter the actor; jobs never write UTXO mirrors.
    apply_client: WalletPrivateApplyClient,
    db: Arc<DbStore>,
    cache_store: Arc<dyn WalletCacheStore>,
    cfg: WalletConfig,
    public_data_plane: ChainPublicDataPlane,
    http_client: Option<reqwest::Client>,
    indexed_artifact_source: Option<IndexedArtifactSourceConfig>,
    /// Shared POI runtime (client + policy); not held across actor turns as a permit.
    poi_client: PoiRpcClient,
    poi_is_indexed: bool,
    poi_wallet_read_fallback: bool,
    /// Receives the job's single-commitment PPOI handoffs.
    poi_submitter: ChainPoiSubmitterHandle,
    forest: Arc<RwLock<MerkleForest>>,
    utxos: Arc<RwLock<Vec<WalletUtxo>>>,
    active_poi_list_keys: Vec<FixedBytes<32>>,
    force_output_poi_recovery: bool,
    /// Actor-lifetime unshield attempt pacing, shared with the controller.
    unshield_attempts: SenderUnshieldAttempts,
    /// Forced submissions deferred by spacing in this job's reset generation,
    /// shared with the controller until it resets.
    forced_deferrals: DeferredForcedSubmissions,
}

struct PoiMaintenanceOutcome {
    recovered: usize,
    candidate_report: SenderCandidateRecoveryReport,
    recovery_error: Option<PoiMaintenanceError>,
    forced_pending_attempts: usize,
    submitted: usize,
    verified_completed: usize,
    verified_pending: usize,
    verified_errors: usize,
}

impl PoiMaintenanceJob {
    fn spawn(self, poi_jobs: &WalletPoiJobTracker) {
        poi_jobs.spawn(async move {
            let done_tx = self.done_tx.clone();
            let credential = self.credential;
            let key = self.key;
            let maintenance = Box::pin(self.run());
            let result =
                run_poi_maintenance_with_watchdog(maintenance, POI_MAINTENANCE_WATCHDOG).await;
            let done = match result {
                Ok(outcome) => WalletRemoteDone::PoiMaintenance {
                    credential,
                    key,
                    recovered: outcome.recovered,
                    candidate_report: Box::new(outcome.candidate_report),
                    recovery_error: outcome.recovery_error,
                    forced_pending_attempts: outcome.forced_pending_attempts,
                    submitted: outcome.submitted,
                    verified_completed: outcome.verified_completed,
                    verified_pending: outcome.verified_pending,
                    verified_errors: outcome.verified_errors,
                },
                Err(reason) => {
                    warn!(
                        category = reason.category(),
                        "poi maintenance watchdog aborted job"
                    );
                    WalletRemoteDone::PoiMaintenanceAborted {
                        credential,
                        key,
                        reason: reason.category(),
                    }
                }
            };
            if done_tx.send(done).await.is_err() {
                debug!("poi maintenance completion delivery skipped; actor stopped");
            }
        });
    }

    async fn run(self) -> PoiMaintenanceOutcome {
        let authority = WalletPrivateMutationAuthority::new(
            &self.handle,
            self.credential.reset_generation,
            &self.cancel,
        )
        .with_apply_client(&self.apply_client);
        let private_poi = WalletPrivatePoiClients::new(
            authority.remote_authority(),
            self.poi_client.clone(),
            Arc::new(self.poi_submitter.clone()),
        )
        .with_submission_routing(
            self.poi_submitter.submission_routing().cloned(),
            self.forced_deferrals,
        );
        // Reconstruct runtime view for authorized helpers.
        let poi_runtime = if self.poi_is_indexed {
            WalletPoiRuntime::IndexedArtifacts {
                client: self.poi_client,
                wallet_read_fallback: if self.poi_wallet_read_fallback {
                    PoiProxyFallback::OnCorpusUnavailable
                } else {
                    PoiProxyFallback::Disabled
                },
            }
        } else {
            WalletPoiRuntime::PoiProxy {
                client: self.poi_client,
            }
        };
        let client = poi_runtime.public_client();

        // Local-only mark-valid under short permits (no remote).
        mark_valid_output_poi_recoveries_authorized(
            &authority,
            self.db.as_ref(),
            self.cache_store.as_ref(),
            &self.cfg,
            &self.utxos,
            &self.active_poi_list_keys,
        )
        .await;

        let local_status_ready = if poi_runtime.is_indexed_artifacts() {
            self.public_data_plane
                .poi_corpus_ready_for_lists(
                    PublicPoiCorpusKey::wallet_default(self.cfg.chain.chain_id),
                    &self.active_poi_list_keys,
                )
                .await
        } else {
            false
        };
        if !poi_runtime.is_indexed_artifacts()
            || (poi_runtime.wallet_read_fallback_enabled() && !local_status_ready)
        {
            let _ = refresh_wallet_poi_statuses_remote_authorized(
                &authority,
                &private_poi,
                self.db.as_ref(),
                self.cache_store.as_ref(),
                &self.cfg,
                &self.active_poi_list_keys,
                WalletPoiRefreshSelection::RequiredOrRecoverable,
            )
            .await;
        }

        debug!(
            chain_id = self.cfg.chain.chain_id,
            "poi maintenance pending verification started"
        );
        let pending_verification = verify_submitted_pending_output_pois_with_config_authorized(
            &authority,
            &self.public_data_plane,
            &poi_runtime,
            &private_poi,
            &self.cfg,
            self.db.as_ref(),
            self.cache_store.as_ref(),
            &self.active_poi_list_keys,
        )
        .await;
        debug!(
            chain_id = self.cfg.chain.chain_id,
            completed = pending_verification.completed,
            pending = pending_verification.pending,
            errors = pending_verification.errors,
            "poi maintenance pending verification complete"
        );

        let forced_pending_attempts = if self.force_output_poi_recovery {
            force_resubmit_matching_pending_output_pois_authorized(
                &authority,
                &self.public_data_plane,
                self.db.as_ref(),
                self.cache_store.as_ref(),
                &self.cfg,
                &self.utxos,
                &self.active_poi_list_keys,
                &private_poi,
            )
            .await
        } else {
            0
        };

        let recovery = (OutputPoiRecoveryRun {
            authority: &authority,
            db: self.db.as_ref(),
            cache_store: self.cache_store.as_ref(),
            cfg: &self.cfg,
            public_data_plane: &self.public_data_plane,
            http_client: self.http_client.as_ref(),
            indexed_artifact_source: self.indexed_artifact_source.as_ref(),
            poi_runtime: &poi_runtime,
            forest: &self.forest,
            utxos: &self.utxos,
            client,
            private_poi: &private_poi,
            active_list_keys: &self.active_poi_list_keys,
            force_retry: self.force_output_poi_recovery,
            unshield_attempts: &self.unshield_attempts,
        })
        .recover_missing()
        .await;

        let force_submission_retry = self.force_output_poi_recovery
            && recovery.error.is_none()
            && recovery.recovered == 0
            && forced_pending_attempts == 0;
        debug!(
            chain_id = self.cfg.chain.chain_id,
            force_submission_retry, "poi maintenance retry-submitted stage started"
        );
        let submitted = process_pending_output_poi_observations_authorized(
            &authority,
            &self.public_data_plane,
            self.db.as_ref(),
            self.cache_store.as_ref(),
            &self.cfg,
            &self.active_poi_list_keys,
            Some(&private_poi),
            force_submission_retry,
        )
        .await;
        debug!(
            chain_id = self.cfg.chain.chain_id,
            force_submission_retry, submitted, "poi maintenance retry-submitted stage complete"
        );
        PoiMaintenanceOutcome {
            recovered: recovery.recovered,
            candidate_report: recovery.candidate_report,
            recovery_error: recovery.error,
            forced_pending_attempts,
            submitted,
            verified_completed: pending_verification.completed,
            verified_pending: pending_verification.pending,
            verified_errors: pending_verification.errors,
        }
    }
}
