use super::{
    Arc, AtomicU64, BTreeMap, BackfillEvent, CancellationToken, ChainError, ChainPublicDataPlane,
    DbStore, Duration, FixedBytes, FuturesUnordered, HashSet, IndexedArtifactSourceConfig, Instant,
    Instrument, LocalPoiStatusReader, MerkleForest, Mutex, OutputPoiRecoveryRun,
    PendingOutputPoiContextIntent, PoiMaintenanceController, PoiProxyFallback, PoiRemoteJobKey,
    PoiRpcClient, PoiStatusReader, PublicPoiCorpusKey, QueryRpcPool, RwLock, SharedLogBatch,
    SyncProgressStage, SyncProgressUpdate, WALLET_POI_REFRESH_INTERVAL, WalletActorApplyToken,
    WalletActorCommitToken, WalletActorCredential, WalletActorLifecycleCell,
    WalletBackfillApplyResult, WalletBackfillFinishResult, WalletBackfillGrant,
    WalletBackfillOwnerDisposition, WalletBackfillOwnerSignal, WalletBackfillRejectReason,
    WalletBackfillResetResult, WalletBackfillStartResult, WalletCacheError, WalletCacheStore,
    WalletCheckpointMutation, WalletConfig, WalletCurrentSnapshot, WalletHandle,
    WalletIndexedCatchUpCommand, WalletIndexedCatchUpLease, WalletIndexedCatchUpStatus,
    WalletLiveMetadataFlush, WalletLocalPendingSpentUpdate, WalletLogDelta, WalletPendingOverlay,
    WalletPendingOverlayUpdate, WalletPendingResetRecord, WalletPendingSpent, WalletPersistState,
    WalletPoiRefreshSelection, WalletPoiRuntime, WalletPrivateApplyClient,
    WalletPrivateApplyRequest, WalletPrivateCommit, WalletPrivateMutationAuthority,
    WalletPrivateMutationPermit, WalletPrivatePoiClients, WalletPrivateRequest,
    WalletPrivateRequestError, WalletPrivateViewTicket, WalletProgressPersist,
    WalletProgressPrivateEffects, WalletReadiness, WalletReadinessError, WalletRemoteDone,
    WalletResetReplayPlan, WalletResetRewindStatus, WalletResetToken, WalletScanApply,
    WalletScanRowsPayload, WalletSyncActorStateCommit, WalletSyncActorStateRecord, WalletSyncToken,
    WalletUtxo, WalletUtxoMutation, WalletViewState, WalletWorkerServices,
    apply_owned_poi_private_delta_on_actor, apply_wallet_delta_to_vec_with_outcome, broadcast,
    chain_pending_overlay_matches, debug, default_active_poi_list_keys,
    force_resubmit_matching_pending_output_pois_authorized, info,
    mark_valid_output_poi_recoveries_authorized, mpsc, now_epoch_secs, oneshot,
    pending_output_poi_observation_updates, pending_overlay_from_delta,
    process_pending_output_poi_observations_authorized,
    refresh_wallet_poi_statuses_remote_authorized, refresh_wallet_poi_statuses_selected,
    rewind_wallet_utxos, verify_submitted_pending_output_pois_with_config_authorized,
    wallet_poi_status_refresh_needed, wallet_poi_status_refresh_needed_for_selection,
    wallet_utxo_stable_identity, warn, watch,
};
use crate::types::BackfillRequest;
use futures::StreamExt;

#[cfg(test)]
use super::WalletInactiveReason;

const fn wallet_private_request_error(
    reason: &WalletBackfillRejectReason,
) -> WalletPrivateRequestError {
    match reason {
        WalletBackfillRejectReason::Shutdown => WalletPrivateRequestError::Inactive,
        WalletBackfillRejectReason::PersistenceFailed => {
            WalletPrivateRequestError::PersistenceFailed
        }
        WalletBackfillRejectReason::StaleGeneration { .. }
        | WalletBackfillRejectReason::StaleResetIntent { .. }
        | WalletBackfillRejectReason::StaleDataPlaneEpoch { .. }
        | WalletBackfillRejectReason::NonContiguous { .. }
        | WalletBackfillRejectReason::ApplyFailed
        | WalletBackfillRejectReason::TargetNotReached { .. }
        | WalletBackfillRejectReason::TargetExceeded { .. } => WalletPrivateRequestError::StaleView,
    }
}

async fn apply_local_pending_spent_update(
    handle: &WalletHandle,
    cancel: &CancellationToken,
    reset_generation: u64,
    update: WalletLocalPendingSpentUpdate,
) -> Result<bool, WalletPrivateRequestError> {
    let authority = WalletPrivateMutationAuthority::new(handle, reset_generation, cancel);
    let permit = authority
        .acquire()
        .await
        .map_err(|reason| wallet_private_request_error(&reason))?;
    let confirmed = permit.handle_utxos().read().await;
    permit
        .revalidate()
        .map_err(|reason| wallet_private_request_error(&reason))?;
    let unspent_identities = confirmed
        .iter()
        .filter(|utxo| !utxo.is_spent())
        .map(|utxo| {
            (
                utxo.utxo.tree,
                utxo.utxo.position,
                wallet_utxo_stable_identity(utxo),
            )
        })
        .collect::<HashSet<_>>();
    let mut overlay = permit.pending_overlay().write().await;
    permit
        .with_active_apply(|token| {
            let changed = match update {
                WalletLocalPendingSpentUpdate::Mark { utxos, tx_hash } => {
                    let now = now_epoch_secs();
                    let chain_pending = overlay
                        .pending_spent
                        .iter()
                        .map(WalletPendingSpent::key)
                        .collect::<HashSet<_>>();
                    let mut existing = overlay
                        .local_pending_spent
                        .iter()
                        .map(WalletPendingSpent::key)
                        .collect::<HashSet<_>>();
                    let before = overlay.local_pending_spent.len();
                    let mut updated_existing = false;
                    for utxo in utxos {
                        let key = (utxo.tree, utxo.position);
                        let identity = wallet_utxo_stable_identity(&WalletUtxo::new(utxo.clone()));
                        if !unspent_identities.contains(&(utxo.tree, utxo.position, identity))
                            || chain_pending.contains(&key)
                        {
                            continue;
                        }
                        if existing.insert(key) {
                            overlay
                                .local_pending_spent
                                .push(WalletPendingSpent::submitted(&utxo, tx_hash, now));
                        } else if let Some(spent) = overlay
                            .local_pending_spent
                            .iter_mut()
                            .find(|spent| spent.key() == key)
                            && spent.tx_hash != tx_hash
                        {
                            spent.tx_hash = tx_hash;
                            spent.block_timestamp = Some(now);
                            updated_existing = true;
                        }
                    }
                    overlay
                        .local_pending_spent
                        .sort_by_key(WalletPendingSpent::key);
                    overlay.local_pending_spent.len() != before || updated_existing
                }
                WalletLocalPendingSpentUpdate::ClearAll => {
                    let changed = !overlay.local_pending_spent.is_empty();
                    overlay.local_pending_spent.clear();
                    changed
                }
            };
            if changed {
                permit.apply_notify_changed(&token, &confirmed, &overlay);
            }
            changed
        })
        .map_err(|reason| wallet_private_request_error(&reason))
}

async fn commit_pending_output_contexts(
    handle: &WalletHandle,
    cancel: &CancellationToken,
    db: &DbStore,
    cache_store: &dyn WalletCacheStore,
    cfg: &WalletConfig,
    reset_generation: u64,
    contexts: &[PendingOutputPoiContextIntent],
) -> Result<usize, WalletPrivateRequestError> {
    let authority = WalletPrivateMutationAuthority::new(handle, reset_generation, cancel);
    let permit = authority
        .acquire()
        .await
        .map_err(|reason| wallet_private_request_error(&reason))?;
    let created_at = now_epoch_secs();
    let mut seen_commitments = HashSet::with_capacity(contexts.len());
    let mut new_records = Vec::with_capacity(contexts.len());
    for context in contexts {
        if !seen_commitments.insert(context.output_commitment) {
            continue;
        }
        let record =
            context
                .clone()
                .into_record(cfg.chain.chain_id, cfg.cache_key.to_string(), created_at);
        match db.get_pending_output_poi_context(
            record.chain_id,
            &record.wallet_id,
            &record.output_commitment,
        ) {
            Ok(Some(_)) => {}
            Ok(None) => new_records.push(record),
            Err(_) => return Err(WalletPrivateRequestError::PersistenceFailed),
        }
    }
    if new_records.is_empty() {
        return Ok(0);
    }
    match permit.with_durable_apply(|token| {
        cache_store.commit_wallet_private_state(
            WalletPrivateCommit::new(
                &token,
                &permit,
                cfg.chain.chain_id,
                WalletUtxoMutation::Preserve,
                WalletCheckpointMutation::Preserve,
            )
            .with_pending_output_context_updates(&new_records),
        )
    }) {
        Ok(Ok(())) => Ok(new_records.len()),
        Ok(Err(_)) => Err(WalletPrivateRequestError::PersistenceFailed),
        Err(reason) => Err(wallet_private_request_error(&reason)),
    }
}

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

/// `poi_refreshing` is derived from the maintenance controller phase.
async fn sync_poi_refreshing_from_controller(
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
    )
    .await;
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
async fn request_poi_maintenance(
    controller: &mut PoiMaintenanceController,
    remote_done_tx: &mpsc::Sender<WalletRemoteDone>,
    private_apply: &WalletPrivateApplyClient,
    poi_refreshing_tx: &watch::Sender<bool>,
    handle: &WalletHandle,
    cancel: &CancellationToken,
    db: &Arc<DbStore>,
    cache_store: &Arc<dyn WalletCacheStore>,
    cfg: &WalletConfig,
    public_data_plane: &ChainPublicDataPlane,
    rpcs: &Arc<QueryRpcPool>,
    http_client: Option<&reqwest::Client>,
    indexed_artifact_source: Option<&IndexedArtifactSourceConfig>,
    poi_runtime: &WalletPoiRuntime,
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
        sync_poi_refreshing_from_controller(controller, poi_refreshing_tx, handle, cancel).await;
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
        rpcs: Arc::clone(rpcs),
        http_client: http_client.cloned(),
        indexed_artifact_source: indexed_artifact_source.cloned(),
        poi_client: client,
        poi_is_indexed: poi_runtime.is_indexed_artifacts(),
        poi_wallet_read_fallback: poi_runtime.wallet_read_fallback_enabled(),
        forest: Arc::clone(forest),
        utxos: Arc::clone(utxos),
        active_poi_list_keys: active_poi_list_keys.to_vec(),
        force_output_poi_recovery: spec.force_output_poi_recovery,
    }
    .spawn();
    debug!(
        cache_key = %handle.cache_key,
        force = spec.force_output_poi_recovery,
        ?spec.key,
        "poi maintenance job started"
    );
    sync_poi_refreshing_from_controller(controller, poi_refreshing_tx, handle, cancel).await;
    true
}

/// Re-enter after remote job completion: clear phase, maybe start forced follow-up.
async fn on_poi_maintenance_done(
    controller: &mut PoiMaintenanceController,
    remote_done_tx: &mpsc::Sender<WalletRemoteDone>,
    private_apply: &WalletPrivateApplyClient,
    poi_refreshing_tx: &watch::Sender<bool>,
    handle: &WalletHandle,
    cancel: &CancellationToken,
    db: &Arc<DbStore>,
    cache_store: &Arc<dyn WalletCacheStore>,
    cfg: &WalletConfig,
    public_data_plane: &ChainPublicDataPlane,
    rpcs: &Arc<QueryRpcPool>,
    http_client: Option<&reqwest::Client>,
    indexed_artifact_source: Option<&IndexedArtifactSourceConfig>,
    poi_runtime: &WalletPoiRuntime,
    forest: &Arc<RwLock<MerkleForest>>,
    utxos: &Arc<RwLock<Vec<WalletUtxo>>>,
    active_poi_list_keys: &[FixedBytes<32>],
    key: PoiRemoteJobKey,
) {
    let force_follow_up = controller.on_job_done(key);
    sync_poi_refreshing_from_controller(controller, poi_refreshing_tx, handle, cancel).await;
    if force_follow_up {
        debug!(
            cache_key = %handle.cache_key,
            "starting deferred force poi maintenance after prior job"
        );
        let _ = request_poi_maintenance(
            controller,
            remote_done_tx,
            private_apply,
            poi_refreshing_tx,
            handle,
            cancel,
            db,
            cache_store,
            cfg,
            public_data_plane,
            rpcs,
            http_client,
            indexed_artifact_source,
            poi_runtime,
            forest,
            utxos,
            active_poi_list_keys,
            false, // force already latched in controller
        )
        .await;
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
    rpcs: Arc<QueryRpcPool>,
    http_client: Option<reqwest::Client>,
    indexed_artifact_source: Option<IndexedArtifactSourceConfig>,
    /// Shared POI runtime (client + policy); not held across actor turns as a permit.
    poi_client: PoiRpcClient,
    poi_is_indexed: bool,
    poi_wallet_read_fallback: bool,
    forest: Arc<RwLock<MerkleForest>>,
    utxos: Arc<RwLock<Vec<WalletUtxo>>>,
    active_poi_list_keys: Vec<FixedBytes<32>>,
    force_output_poi_recovery: bool,
}

impl PoiMaintenanceJob {
    fn spawn(self) {
        tokio::spawn(async move {
            self.run().await;
        });
    }

    async fn run(self) {
        let authority = WalletPrivateMutationAuthority::new(
            &self.handle,
            self.credential.reset_generation,
            &self.cancel,
        )
        .with_apply_client(&self.apply_client);
        let private_poi = WalletPrivatePoiClients::from_rpc(
            authority.remote_authority(),
            self.poi_client.clone(),
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

        let forced_pending_attempts = if self.force_output_poi_recovery {
            force_resubmit_matching_pending_output_pois_authorized(
                &authority,
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

        let recovered = (OutputPoiRecoveryRun {
            authority: &authority,
            db: self.db.as_ref(),
            cache_store: self.cache_store.as_ref(),
            cfg: &self.cfg,
            public_data_plane: &self.public_data_plane,
            rpcs: self.rpcs.as_ref(),
            http_client: self.http_client.as_ref(),
            indexed_artifact_source: self.indexed_artifact_source.as_ref(),
            poi_runtime: &poi_runtime,
            forest: &self.forest,
            utxos: &self.utxos,
            client,
            private_poi: &private_poi,
            active_list_keys: &self.active_poi_list_keys,
            force_retry: self.force_output_poi_recovery,
        })
        .recover_missing()
        .await;

        let force_submission_retry =
            self.force_output_poi_recovery && recovered == 0 && forced_pending_attempts == 0;
        let submitted = process_pending_output_poi_observations_authorized(
            &authority,
            self.db.as_ref(),
            self.cache_store.as_ref(),
            &self.cfg,
            &self.active_poi_list_keys,
            Some(&private_poi),
            force_submission_retry,
        )
        .await;

        let _ = self
            .done_tx
            .send(WalletRemoteDone::PoiMaintenance {
                credential: self.credential,
                key: self.key,
                recovered,
                forced_pending_attempts,
                submitted,
                verified_completed: pending_verification.completed,
                verified_pending: pending_verification.pending,
                verified_errors: pending_verification.errors,
            })
            .await;
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

/// Outcome of `CommitResetRewind` only (pending reset already accepted).
/// Never means "reset rejected" — use [`WalletBackfillResetResult::Rejected`] only
/// before durable `AcceptReset`.
#[derive(Debug, Clone, PartialEq, Eq)]
enum WalletResetRewindOutcome {
    Committed {
        committed_to: u64,
    },
    Deferred {
        committed_to: u64,
        reason: WalletBackfillRejectReason,
    },
}

impl WalletResetRewindOutcome {
    const fn committed(&self) -> bool {
        matches!(self, Self::Committed { .. })
    }
}

impl From<WalletResetRewindOutcome> for WalletResetRewindStatus {
    fn from(outcome: WalletResetRewindOutcome) -> Self {
        match outcome {
            WalletResetRewindOutcome::Committed { committed_to } => {
                Self::Committed { committed_to }
            }
            WalletResetRewindOutcome::Deferred {
                committed_to,
                reason,
            } => Self::Pending {
                committed_to,
                last_attempt: Some(reason),
            },
        }
    }
}

struct WalletResetCommitOutcome {
    rewind: WalletResetRewindOutcome,
}

impl WalletResetCommitOutcome {
    fn into_accept_result(self, reset_generation: u64) -> WalletBackfillResetResult {
        WalletBackfillResetResult::Accepted {
            reset_generation,
            rewind: self.rewind.into(),
        }
    }
}

/// Fold a post-accept rewind attempt into a public reset result.
/// After `AcceptReset` succeeds, the public result is never Rejected.
fn reset_result_after_accept(
    reset_generation: u64,
    outcome: WalletResetCommitOutcome,
) -> WalletBackfillResetResult {
    outcome.into_accept_result(reset_generation)
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
        wallet_id: cfg.cache_key.to_string(),
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

fn signal_restored_reset_attempt(startup_replay_tx: &mut Option<oneshot::Sender<()>>) {
    if let Some(tx) = startup_replay_tx.take() {
        let _ = tx.send(());
    }
}

fn persist_wallet_reset_replay_admission_with_token(
    token: &WalletActorCommitToken<'_>,
    permit: &WalletPrivateMutationPermit<'_>,
    cache_store: &dyn WalletCacheStore,
    cfg: &WalletConfig,
    highest_accepted_reset_intent: u64,
) -> Result<(), WalletCacheError> {
    let state = wallet_sync_actor_state_record(cfg, highest_accepted_reset_intent, None);
    cache_store.put_wallet_sync_actor_state(WalletSyncActorStateCommit::new(token, permit, &state))
}

/// Durable reset acceptance under an existing active-apply token (no re-fence).
fn persist_wallet_reset_acceptance_with_token(
    token: &WalletActorCommitToken<'_>,
    permit: &WalletPrivateMutationPermit<'_>,
    cache_store: &dyn WalletCacheStore,
    cfg: &WalletConfig,
    highest_accepted_reset_intent: u64,
    pending_reset: PendingWalletReset,
) -> Result<(), WalletCacheError> {
    let state =
        wallet_sync_actor_state_record(cfg, highest_accepted_reset_intent, Some(pending_reset));
    cache_store.put_wallet_sync_actor_state(WalletSyncActorStateCommit::new(token, permit, &state))
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum WalletActorJobKind {
    Backfill,
    PendingOverlay,
    IndexedCatchUp,
}

#[derive(Debug, Clone)]
struct WalletActorJob {
    reset_generation: u64,
    kind: WalletActorJobKind,
    target_block: Option<u64>,
    indexed_status: Option<WalletIndexedCatchUpStatus>,
}

/// Readiness-affecting fact transitions. Call sites mutate only through these;
/// publication always goes through [`WalletActorState::reduce_and_publish_readiness`]
/// (or the token/active variants). Recovery of [`WalletReadinessError::PersistenceFailed`]
/// is encoded in [`WalletReadinessFact::DurablePrivateCommitOk`], not a free-standing clear.
#[derive(Debug, Clone, PartialEq, Eq)]
enum WalletReadinessFact {
    /// Successful durable private commit. Optionally advances the actor cursor.
    /// Clears recoverable faults (`PersistenceFailed`) only.
    DurablePrivateCommitOk { last_scanned: Option<u64> },
    /// Durable private persist failed.
    DurablePersistFailed,
    /// Sticky or operational fault (e.g. backfill unavailable).
    SetFault(WalletReadinessError),
    /// Clear every readiness fault (reset accept / successful reset commit).
    ClearAllFaults,
}

struct WalletActorState {
    chain_id: u64,
    actor_id: u64,
    reset_generation: u64,
    last_scanned: u64,
    /// Highest target that completed its final durable finish in this reset generation.
    completed_target_block: Option<u64>,
    /// Last published readiness (updated only by reduce paths).
    readiness: WalletReadiness,
    /// Readiness fault input to [`Self::derived_readiness`].
    /// `PersistenceFailed` is recoverable on durable commit success; other faults
    /// stick until [`WalletReadinessFact::ClearAllFaults`] (reset).
    readiness_fault: Option<WalletReadinessError>,
    shutdown: bool,
    highest_accepted_reset_intent: u64,
    pending_reset: Option<PendingWalletReset>,
    pending_reset_rewind_committed: bool,
    pending_reset_replay_admitted: Option<WalletSyncToken>,
    active_jobs: BTreeMap<u64, WalletActorJob>,
    highest_accepted_backfill_job_id: u64,
    latest_pending_overlay_job: Option<u64>,
}

async fn accepted_backfill_owner_dropped(
    token: WalletSyncToken,
    receiver: oneshot::Receiver<WalletBackfillOwnerSignal>,
) -> (WalletSyncToken, WalletBackfillOwnerSignal) {
    let signal = receiver.await.unwrap_or(WalletBackfillOwnerSignal {
        disposition: WalletBackfillOwnerDisposition::DriverLost,
        acknowledgement: None,
    });
    (token, signal)
}

async fn accepted_indexed_job_owner_dropped(
    token: WalletSyncToken,
    receiver: oneshot::Receiver<()>,
) -> WalletSyncToken {
    let _ = receiver.await;
    token
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
            completed_target_block: None,
            readiness: WalletReadiness::Syncing,
            readiness_fault: None,
            shutdown: false,
            highest_accepted_reset_intent,
            pending_reset,
            pending_reset_rewind_committed: false,
            pending_reset_replay_admitted: None,
            active_jobs: BTreeMap::new(),
            highest_accepted_backfill_job_id: 0,
            latest_pending_overlay_job: None,
        }
    }

    const fn update_cursor(&mut self, last_scanned: u64) {
        self.last_scanned = last_scanned;
    }

    const fn fault_is_recoverable(reason: &WalletReadinessError) -> bool {
        matches!(reason, WalletReadinessError::PersistenceFailed)
    }

    fn clear_recoverable_faults(&mut self) {
        if self
            .readiness_fault
            .as_ref()
            .is_some_and(Self::fault_is_recoverable)
        {
            self.readiness_fault = None;
        }
    }

    /// Apply a readiness-affecting fact. Does not publish — caller must reduce.
    fn apply_fact(&mut self, fact: WalletReadinessFact) {
        match fact {
            WalletReadinessFact::DurablePrivateCommitOk { last_scanned } => {
                if let Some(last_scanned) = last_scanned {
                    self.last_scanned = last_scanned;
                }
                self.clear_recoverable_faults();
            }
            WalletReadinessFact::DurablePersistFailed => {
                self.readiness_fault = Some(WalletReadinessError::PersistenceFailed);
            }
            WalletReadinessFact::SetFault(reason) => {
                self.readiness_fault = Some(reason);
            }
            WalletReadinessFact::ClearAllFaults => {
                self.readiness_fault = None;
            }
        }
    }

    fn apply_fact_and_publish_with_token(
        &mut self,
        fact: WalletReadinessFact,
        token: &WalletActorApplyToken<'_>,
        ready_tx: &watch::Sender<bool>,
        readiness_tx: &watch::Sender<WalletReadiness>,
    ) {
        self.apply_fact(fact);
        self.reduce_and_publish_readiness_with_token(token, ready_tx, readiness_tx);
    }

    fn apply_fact_and_publish_active(
        &mut self,
        fact: WalletReadinessFact,
        permit: &WalletPrivateMutationPermit<'_>,
        ready_tx: &watch::Sender<bool>,
        readiness_tx: &watch::Sender<WalletReadiness>,
    ) -> Result<(), WalletBackfillRejectReason> {
        self.apply_fact(fact);
        self.reduce_and_publish_readiness_active(permit, ready_tx, readiness_tx)
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

    fn validate_private_request(
        &self,
        handle: &WalletHandle,
        cancel: &CancellationToken,
        ticket: WalletPrivateViewTicket,
        last_scanned: u64,
        require_cursor: bool,
    ) -> Result<u64, WalletPrivateRequestError> {
        handle.with_active_private_request(cancel, || {
            let reset_generation = ticket.reset_generation();
            if self.pending_reset.is_some() {
                return Err(WalletPrivateRequestError::ResetPending);
            }
            let WalletPrivateViewTicket::Current {
                last_scanned: request_last_scanned,
                ..
            } = ticket
            else {
                return Err(WalletPrivateRequestError::StaleView);
            };
            if reset_generation != self.reset_generation
                || (require_cursor && request_last_scanned != last_scanned)
            {
                return Err(WalletPrivateRequestError::StaleView);
            }
            Ok(reset_generation)
        })
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
                target_block: None,
                indexed_status: None,
            },
        );
        if kind == WalletActorJobKind::PendingOverlay {
            self.latest_pending_overlay_job = Some(token.job_id());
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

    fn has_active_backfill_job(&self) -> bool {
        self.active_jobs
            .values()
            .any(|job| job.kind == WalletActorJobKind::Backfill)
    }

    fn active_backfill_target(&self) -> Option<u64> {
        self.active_jobs
            .values()
            .filter(|job| job.kind == WalletActorJobKind::Backfill)
            .filter_map(|job| job.target_block)
            .max()
    }

    fn retire_job(&mut self, token: WalletSyncToken) -> bool {
        if !self.has_active_job(token) {
            return false;
        }
        let retired = self.active_jobs.remove(&token.job_id()).is_some();
        if retired && self.pending_reset_replay_admitted == Some(token) {
            self.pending_reset_replay_admitted = None;
        }
        retired
    }

    fn fail_job(&mut self, token: WalletSyncToken, reason: WalletReadinessError) -> bool {
        let retired = self.retire_job(token);
        if retired {
            self.apply_fact(WalletReadinessFact::SetFault(reason));
        }
        retired
    }

    fn apply_backfill_owner_disposition(
        &mut self,
        token: WalletSyncToken,
        disposition: WalletBackfillOwnerDisposition,
    ) -> bool {
        match disposition {
            WalletBackfillOwnerDisposition::BenignRetirement => self.retire_job(token),
            WalletBackfillOwnerDisposition::DriverLost => {
                self.fail_job(token, WalletReadinessError::BackfillUnavailable)
            }
        }
    }

    fn retire_all_jobs_for_reset(&mut self) -> bool {
        let indexed_catch_up_was_active = self
            .active_jobs
            .values()
            .any(|job| job.kind == WalletActorJobKind::IndexedCatchUp);
        self.active_jobs.clear();
        self.latest_pending_overlay_job = None;
        self.completed_target_block = None;
        indexed_catch_up_was_active
    }

    fn accept_indexed_catch_up(&mut self, token: WalletSyncToken) -> bool {
        if self
            .active_jobs
            .values()
            .any(|job| job.kind == WalletActorJobKind::IndexedCatchUp)
        {
            return false;
        }
        self.accept_job(token, WalletActorJobKind::IndexedCatchUp)
    }

    fn is_active_indexed_catch_up(&self, token: WalletSyncToken) -> bool {
        self.is_active_job(token, WalletActorJobKind::IndexedCatchUp)
    }

    fn publish_indexed_catch_up(
        &mut self,
        token: WalletSyncToken,
        status: WalletIndexedCatchUpStatus,
    ) -> bool {
        if !self.is_active_indexed_catch_up(token) {
            return false;
        }
        self.active_jobs
            .get_mut(&token.job_id())
            .expect("validated indexed catch-up job exists")
            .indexed_status = Some(status);
        true
    }

    fn accept_reset(&mut self, pending: PendingWalletReset) -> bool {
        self.highest_accepted_reset_intent = pending.intent_id;
        self.pending_reset = Some(pending);
        self.reset_generation = pending.reset_generation;
        self.pending_reset_rewind_committed = false;
        self.pending_reset_replay_admitted = None;
        self.apply_fact(WalletReadinessFact::ClearAllFaults);
        self.retire_all_jobs_for_reset()
    }

    const fn clear_pending_reset(&mut self) {
        self.pending_reset = None;
        self.pending_reset_rewind_committed = false;
        self.pending_reset_replay_admitted = None;
    }

    fn mark_shutdown(&mut self) {
        self.shutdown = true;
        self.active_jobs.clear();
        self.latest_pending_overlay_job = None;
        self.pending_reset_replay_admitted = None;
    }

    fn accept_target(&mut self, token: WalletSyncToken, target_block: u64) -> bool {
        if self.has_active_job(token) {
            return false;
        }
        if !self.accept_job(token, WalletActorJobKind::Backfill) {
            return false;
        }
        self.active_jobs
            .get_mut(&token.job_id())
            .expect("accepted backfill job exists")
            .target_block = Some(target_block);
        true
    }

    fn update_target(&mut self, token: WalletSyncToken, target_block: u64) -> Option<u64> {
        if !self.is_active_job(token, WalletActorJobKind::Backfill) {
            return None;
        }
        let job = self
            .active_jobs
            .get_mut(&token.job_id())
            .expect("validated backfill job exists");
        let target_block = job
            .target_block
            .map_or(target_block, |current| current.max(target_block));
        job.target_block = Some(target_block);
        Some(target_block)
    }

    fn complete_backfill_job(&mut self, token: WalletSyncToken) -> bool {
        let Some(target_block) = self
            .active_jobs
            .get(&token.job_id())
            .filter(|job| job.kind == WalletActorJobKind::Backfill)
            .and_then(|job| job.target_block)
        else {
            return false;
        };
        self.completed_target_block = Some(
            self.completed_target_block
                .map_or(target_block, |completed| completed.max(target_block)),
        );
        self.retire_job(token)
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
        if let Some(reason) = self.readiness_fault.clone() {
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
        match self.completed_target_block {
            Some(target_block) if target_block > 0 && self.last_scanned >= target_block => {
                WalletReadiness::Ready
            }
            _ => WalletReadiness::Syncing,
        }
    }

    /// Sole readiness publication path (no token). Caller must hold the lifecycle fence
    /// (`with_active_apply` token or terminal shutdown fence).
    fn reduce_and_publish_readiness(
        &mut self,
        ready_tx: &watch::Sender<bool>,
        readiness_tx: &watch::Sender<WalletReadiness>,
    ) {
        let readiness = self.derived_readiness();
        if let Err(err) = readiness_tx.send(readiness.clone()) {
            debug!(?err, "failed to send wallet readiness state");
        }
        if let Err(err) = ready_tx.send(readiness.is_ready()) {
            debug!(?err, "failed to send ready state");
        }
        self.readiness = readiness;
    }

    fn reduce_and_publish_readiness_active(
        &mut self,
        permit: &WalletPrivateMutationPermit<'_>,
        ready_tx: &watch::Sender<bool>,
        readiness_tx: &watch::Sender<WalletReadiness>,
    ) -> Result<(), WalletBackfillRejectReason> {
        permit.with_active_apply(|token| {
            self.reduce_and_publish_readiness_with_token(&token, ready_tx, readiness_tx);
        })
    }

    /// Sole readiness publication path under an Active apply token.
    fn reduce_and_publish_readiness_with_token(
        &mut self,
        token: &WalletActorApplyToken<'_>,
        ready_tx: &watch::Sender<bool>,
        readiness_tx: &watch::Sender<WalletReadiness>,
    ) {
        let readiness = self.derived_readiness();
        WalletPrivateMutationPermit::apply_publish_readiness(
            token,
            ready_tx,
            readiness_tx,
            &readiness,
        );
        self.readiness = readiness;
    }
}

#[cfg(test)]
pub(super) enum WalletPoiStatusReaderSource<'a> {
    Local(LocalPoiStatusReader),
    Remote(&'a PoiRpcClient),
}

#[cfg(test)]
impl WalletPoiStatusReaderSource<'_> {
    pub(super) fn as_reader(&self) -> &dyn PoiStatusReader {
        match self {
            Self::Local(reader) => reader,
            Self::Remote(reader) => *reader,
        }
    }
}

impl WalletPoiRuntime {
    /// Actor-safe: only a local corpus reader. Never returns remote proxy (no remote RTT).
    pub(super) async fn local_status_reader(
        &self,
        public_data_plane: &ChainPublicDataPlane,
        cfg: &WalletConfig,
        active_list_keys: &[FixedBytes<32>],
    ) -> Option<LocalPoiStatusReader> {
        match self {
            Self::IndexedArtifacts { .. } => {
                let key = PublicPoiCorpusKey::wallet_default(cfg.chain.chain_id);
                if !public_data_plane
                    .poi_corpus_ready_for_lists(key.clone(), active_list_keys)
                    .await
                {
                    return None;
                }
                let corpus = public_data_plane.ensure_poi_corpus(key).await.ok()?;
                Some(corpus.status_reader())
            }
            // PoiProxy has no local corpus for actor-side refresh.
            Self::PoiProxy { .. } => None,
        }
    }

    /// Job-only: may return remote proxy / fallback reader.
    #[cfg(test)]
    pub(super) async fn status_reader_for_job<'a>(
        &'a self,
        public_data_plane: &ChainPublicDataPlane,
        cfg: &WalletConfig,
        active_list_keys: &[FixedBytes<32>],
    ) -> Option<WalletPoiStatusReaderSource<'a>> {
        match self {
            Self::IndexedArtifacts { .. } => {
                let key = PublicPoiCorpusKey::wallet_default(cfg.chain.chain_id);
                if !public_data_plane
                    .poi_corpus_ready_for_lists(key.clone(), active_list_keys)
                    .await
                {
                    return self
                        .wallet_read_fallback_enabled()
                        .then(|| WalletPoiStatusReaderSource::Remote(self.public_client()));
                }
                let corpus = public_data_plane.ensure_poi_corpus(key).await.ok()?;
                Some(WalletPoiStatusReaderSource::Local(corpus.status_reader()))
            }
            Self::PoiProxy { .. } => {
                Some(WalletPoiStatusReaderSource::Remote(self.public_client()))
            }
        }
    }
}

impl WalletResetCommitRequest<'_> {
    async fn commit(self) -> WalletResetCommitOutcome {
        let request = self;
        let committed_to_before = *request.last_scanned;
        if request.cancel.is_cancelled() || !request.worker_handle.is_current_actor() {
            return WalletResetCommitOutcome {
                rewind: WalletResetRewindOutcome::Deferred {
                    committed_to: committed_to_before,
                    reason: WalletBackfillRejectReason::Shutdown,
                },
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
                    rewind: WalletResetRewindOutcome::Deferred {
                        committed_to: committed_to_before,
                        reason,
                    },
                };
            }
        };
        if request.cancel.is_cancelled() {
            return WalletResetCommitOutcome {
                rewind: WalletResetRewindOutcome::Deferred {
                    committed_to: committed_to_before,
                    reason: WalletBackfillRejectReason::Shutdown,
                },
            };
        }

        let persist_started = Instant::now();
        let sync_actor_state = wallet_sync_actor_state_record(
            request.cfg,
            request.highest_accepted_reset_intent,
            Some(request.pending),
        );
        let mut utxos_locked = request.utxos.write().await;
        let mut overlay_locked = permit.pending_overlay().write().await;
        let apply_result = permit.with_active_apply(|token| {
            request.cache_store.commit_wallet_private_state(
                WalletPrivateCommit::new(
                    &token,
                    &permit,
                    request.cfg.chain.chain_id,
                    WalletUtxoMutation::Replace(&candidate),
                    WalletCheckpointMutation::Set {
                        last_scanned_block: candidate_last_scanned,
                        last_scanned_block_hash: None,
                    },
                )
                .with_pending_output_context_deletes(&rewind.removed_output_commitments)
                .with_sync_actor_state(&sync_actor_state),
            )?;
            *utxos_locked = candidate;
            permit.apply_set_last_scanned(
                &token,
                candidate_last_scanned,
                &utxos_locked,
                &WalletPendingOverlay::default(),
            );
            let next_overlay = WalletPendingOverlay::default();
            let overlay_changed = !chain_pending_overlay_matches(&overlay_locked, &next_overlay)
                || !overlay_locked.local_pending_spent.is_empty()
                || !overlay_locked.new_utxos.is_empty();
            *overlay_locked = next_overlay;
            if rewind.changed || overlay_changed {
                permit.apply_notify_changed(&token, &utxos_locked, &overlay_locked);
            }
            // Exit ResetPending: public view is now rewound current.
            permit.apply_publish_view_current(&token, &utxos_locked, &overlay_locked);
            Ok::<(), WalletCacheError>(())
        });
        drop(overlay_locked);
        drop(utxos_locked);
        match apply_result {
            Ok(Ok(())) => {}
            Ok(Err(err)) => {
                warn!(
                    ?err,
                    cache_key = %request.cfg.cache_key,
                    intent_id = request.pending.intent_id,
                    from_block = request.pending.from_block,
                    reset_generation = request.pending.reset_generation,
                    "failed to persist wallet reset candidate"
                );
                return WalletResetCommitOutcome {
                    rewind: WalletResetRewindOutcome::Deferred {
                        committed_to: committed_to_before,
                        reason: WalletBackfillRejectReason::PersistenceFailed,
                    },
                };
            }
            Err(reason) => {
                return WalletResetCommitOutcome {
                    rewind: WalletResetRewindOutcome::Deferred {
                        committed_to: committed_to_before,
                        reason,
                    },
                };
            }
        }
        *request.last_scanned = candidate_last_scanned;
        request.persist_state.needs_full_persist = false;
        request.persist_state.pending_cache_reset = None;
        request
            .live_metadata_flush
            .mark_persisted(candidate_last_scanned, Instant::now());
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
            rewind: WalletResetRewindOutcome::Committed {
                committed_to: candidate_last_scanned,
            },
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
        let mut utxos_locked = request.utxos.write().await;
        let apply_result = permit.with_active_apply(|token| {
            request.persist_state.commit_progress_with_token(
                request.cache_store,
                &permit,
                &token,
                WalletProgressPersist {
                    cache_key: &request.cfg.cache_key,
                    snapshot: &candidate,
                    last_scanned: request.last_scanned,
                    checkpoint: WalletCheckpointMutation::Preserve,
                    changed: true,
                },
                WalletProgressPrivateEffects::default(),
            )?;
            *utxos_locked = candidate;
            request.actor_state.apply_fact_and_publish_with_token(
                WalletReadinessFact::DurablePrivateCommitOk { last_scanned: None },
                &token,
                request.ready_tx,
                request.readiness_tx,
            );
            let overlay = request
                .worker_handle
                .pending_overlay
                .try_read()
                .map(|guard| guard.clone())
                .unwrap_or_default();
            permit.apply_notify_changed(&token, &utxos_locked, &overlay);
            Ok::<(), WalletCacheError>(())
        });
        drop(utxos_locked);
        match apply_result {
            Ok(Ok(())) => {}
            Ok(Err(err)) => {
                warn!(?err, cache_key = %request.cfg.cache_key, selection = selection_label, "failed to persist wallet POI status refresh candidate");
                let _ = request.actor_state.apply_fact_and_publish_active(
                    WalletReadinessFact::DurablePersistFailed,
                    &permit,
                    request.ready_tx,
                    request.readiness_tx,
                );
                return Err(WalletBackfillRejectReason::PersistenceFailed);
            }
            Err(reason) => return Err(reason),
        }
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
        let changed = outcome.changed;
        // POI status refresh is never done inside scan commit (may be remote).
        // Actor schedules PoiMaintenanceJob after successful commits instead.

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
                let _ = request.actor_state.apply_fact_and_publish_active(
                    WalletReadinessFact::DurablePersistFailed,
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
                    | crate::chain::PublicDataPlaneError::PublicCacheReset { .. }
                    | crate::chain::PublicDataPlaneError::PoiCorpusUnavailable { .. }
                    | crate::chain::PublicDataPlaneError::PoiCorpusRefresh { .. } => {
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

        let target_block = request
            .actor_state
            .active_backfill_target()
            .unwrap_or(to_block)
            .max(to_block);
        let mut utxos_locked = request.utxos.write().await;
        let apply_result = permit.with_active_apply(|token| {
            let persisted_full_snapshot = request.persist_state.commit_progress_with_token(
                request.cache_store,
                &permit,
                &token,
                WalletProgressPersist {
                    cache_key: &request.cfg.cache_key,
                    snapshot: &candidate,
                    last_scanned: to_block,
                    checkpoint: WalletCheckpointMutation::Set {
                        last_scanned_block: to_block,
                        last_scanned_block_hash,
                    },
                    changed,
                },
                WalletProgressPrivateEffects {
                    pending_output_context_chain_id: request.cfg.chain.chain_id,
                    pending_output_context_updates: &pending_output_context_updates,
                    pending_output_context_deletes: &outcome.spent_output_commitments,
                    output_poi_recovery_updates: &[],
                },
            )?;
            *utxos_locked = candidate;
            let overlay = request
                .worker_handle
                .pending_overlay
                .try_read()
                .map(|guard| guard.clone())
                .unwrap_or_default();
            permit.apply_set_last_scanned(&token, to_block, &utxos_locked, &overlay);
            WalletPrivateMutationPermit::apply_publish_progress(
                &token,
                request.cfg.progress_tx.as_ref(),
                SyncProgressUpdate::new(
                    SyncProgressStage::IndexingUtxos,
                    from_block,
                    to_block,
                    target_block,
                ),
            );
            if changed {
                permit.apply_notify_changed(&token, &utxos_locked, &overlay);
            }
            // Durable success recovers PersistenceFailed inside the fact; publish when
            // callers need mid-backfill readiness updates (never publish pre-recovery).
            let fact = WalletReadinessFact::DurablePrivateCommitOk {
                last_scanned: Some(to_block),
            };
            if request.mark_syncing_on_commit {
                request.actor_state.apply_fact_and_publish_with_token(
                    fact,
                    &token,
                    request.ready_tx,
                    request.readiness_tx,
                );
            } else {
                request.actor_state.apply_fact(fact);
            }
            Ok::<bool, WalletCacheError>(persisted_full_snapshot)
        });
        drop(utxos_locked);
        let persisted_full_snapshot = match apply_result {
            Ok(Ok(persisted_full_snapshot)) => persisted_full_snapshot,
            Ok(Err(err)) => {
                warn!(?err, cache_key = %request.cfg.cache_key, from_block, to_block, "failed to persist wallet scan candidate");
                let _ = request.actor_state.apply_fact_and_publish_active(
                    WalletReadinessFact::DurablePersistFailed,
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
        *request.last_scanned = to_block;
        request
            .live_metadata_flush
            .mark_persisted(to_block, Instant::now());
        drop(public_scan_permit);
        drop(permit);

        // Pending-output submit is scheduled by the actor loop after scan commit
        // (never await remote submit here).

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

pub(crate) struct PreparedWalletWorker {
    handle: Option<WalletHandle>,
    cancel: CancellationToken,
    activation_tx: Option<oneshot::Sender<()>>,
}

impl PreparedWalletWorker {
    pub(crate) const fn handle(&self) -> &WalletHandle {
        self.handle
            .as_ref()
            .expect("prepared wallet worker must own its handle")
    }

    pub(crate) fn activate(mut self) -> Result<WalletHandle, ChainError> {
        if !self.handle().activate_actor() {
            return Err(ChainError::WalletResetFailed);
        }
        if self
            .activation_tx
            .take()
            .expect("prepared wallet worker must own its activation sender")
            .send(())
            .is_err()
        {
            return Err(ChainError::WalletResetFailed);
        }
        Ok(self
            .handle
            .take()
            .expect("prepared wallet worker must own its handle"))
    }
}

impl Drop for PreparedWalletWorker {
    fn drop(&mut self) {
        if let Some(handle) = self.handle.take() {
            handle.retire_actor();
            self.cancel.cancel();
        }
    }
}

pub(crate) async fn prepare_wallet_worker(
    services: WalletWorkerServices,
    cfg: WalletConfig,
    actor_id: u64,
    mut live_rx: broadcast::Receiver<SharedLogBatch>,
    mut backfill_rx: mpsc::Receiver<BackfillEvent>,
    cancel: CancellationToken,
    initial_utxos: Vec<WalletUtxo>,
    initial_last_scanned: u64,
) -> Result<PreparedWalletWorker, ChainError> {
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
        poi_runtime,
        forest,
        backfill_tx,
        backfill_sender,
        public_data_plane,
    } = services;
    if poi_runtime.is_indexed_artifacts() {
        public_data_plane
            .ensure_poi_corpus(PublicPoiCorpusKey::wallet_default(cfg.chain.chain_id))
            .await
            .map_err(ChainError::from)?;
    }
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
    let (reset_generation_tx, reset_generation_rx) = watch::channel(initial_reset_generation);
    let initial_view = if let Some(pending) = &restored_pending_reset {
        WalletViewState::ResetPending {
            intent_id: pending.intent_id,
            from_block: pending.from_block,
            reset_generation: pending.reset_generation,
        }
    } else {
        let initial_utxos = utxos
            .try_read()
            .map(|guard| guard.clone())
            .unwrap_or_default();
        WalletViewState::Current(WalletCurrentSnapshot::new(
            initial_last_scanned,
            0,
            initial_reset_generation,
            Arc::<[WalletUtxo]>::from(initial_utxos),
            Arc::new(WalletPendingOverlay::default()),
        ))
    };
    let (view_tx, view_rx) = watch::channel(initial_view);
    let (poi_refresh_tx, mut poi_refresh_rx) = mpsc::channel(1);
    let (pending_overlay_tx, mut pending_overlay_rx) = mpsc::channel(8);
    let (private_request_tx, mut private_request_rx) = mpsc::channel(8);
    let (indexed_catch_up_status_tx, mut indexed_catch_up_status_rx) = mpsc::unbounded_channel();
    let (poi_refreshing_tx, poi_refreshing_rx) = watch::channel(false);
    let (indexed_catch_up_tx, indexed_catch_up_rx) = watch::channel(None);
    let handle = WalletHandle {
        cache_key: cfg.cache_key.clone(),
        chain_id: cfg.chain.chain_id,
        actor_id,
        active_actor_id,
        lifecycle: Arc::new(WalletActorLifecycleCell::new_prepared()),
        authority_lock,
        utxos: utxos.clone(),
        pending_overlay,
        last_scanned: last_scanned_state,
        reset_generation: reset_generation_state,
        reset_generation_rx,
        next_sync_job_id,
        ready_rx,
        readiness_rx,
        rev_rx,
        view_rx,
        poi_refreshing_rx,
        indexed_catch_up_rx,
        pending_overlay_tx,
        private_request_tx,
        poi_refresh_tx,
        indexed_catch_up_status_tx,
        rev_tx,
        reset_generation_tx,
        view_tx,
        indexed_catch_up_tx,
    };
    let (startup_replay_tx, startup_replay_rx) = if restored_pending_reset.is_some() {
        let (tx, rx) = oneshot::channel();
        (Some(tx), Some(rx))
    } else {
        (None, None)
    };
    let (activation_tx, activation_rx) = oneshot::channel();

    let chain_id = cfg.chain.chain_id;
    let worker_handle = handle.clone();
    let prepared_cancel = cancel.clone();
    tokio::spawn(async move {
        let mut startup_replay_tx = startup_replay_tx;
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
        let poi_status_client = Some(poi_runtime.public_client());
        let active_poi_list_keys = default_active_poi_list_keys();
        let mut pending_reset_retry = tokio::time::interval_at(
            tokio::time::Instant::now() + WALLET_RESET_RETRY_INTERVAL,
            WALLET_RESET_RETRY_INTERVAL,
        );
        pending_reset_retry.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        if poi_status_client.is_some() {
            let locked = utxos.read().await;
            debug!(
                cache_key = %cfg.cache_key,
                poi_refresh_needed = wallet_poi_status_refresh_needed(&locked, &active_poi_list_keys),
                "startup wallet POI status refresh will run after backfill if needed"
            );
        }

        let mut readiness_started = worker_started;
        let (remote_done_tx, mut remote_done_rx) = mpsc::channel::<WalletRemoteDone>(8);
        // Jobs re-enter here for private POI commits; actor is sole UTXO mirror writer.
        let (private_apply_tx, mut private_apply_rx) =
            mpsc::channel::<WalletPrivateApplyRequest>(32);
        let private_apply = WalletPrivateApplyClient::new(private_apply_tx);
        let mut poi_maintenance = PoiMaintenanceController::new();
        let mut actor_state = WalletActorState::new(
            chain_id,
            worker_handle.actor_id,
            initial_reset_generation,
            last_scanned,
            restored_highest_reset_intent,
            restored_pending_reset,
        );
        let mut accepted_backfill_liveness = FuturesUnordered::new();
        let mut accepted_indexed_job_liveness = FuturesUnordered::new();
        macro_rules! publish_readiness {
            () => {{
                if let Err(reason) = worker_handle.with_active_apply(
                    &cancel,
                    actor_state.reset_generation,
                    |_token| {
                        actor_state.reduce_and_publish_readiness(&ready_tx, &readiness_tx);
                    },
                ) {
                    debug!(
                        ?reason,
                        cache_key = %cfg.cache_key,
                        "wallet readiness publication skipped"
                    );
                }
            }};
        }
        macro_rules! try_drive_pending_reset {
            () => {{
                if let Some(pending) = actor_state.pending_reset {
                    let outcome = if actor_state.pending_reset_rewind_committed {
                        WalletResetCommitOutcome {
                            rewind: WalletResetRewindOutcome::Committed {
                                committed_to: last_scanned,
                            },
                        }
                    } else {
                        WalletResetCommitRequest {
                            cache_store: cache_store.as_ref(),
                            cfg: &cfg,
                            utxos: &utxos,
                            worker_handle: &worker_handle,
                            pending,
                            highest_accepted_reset_intent: actor_state
                                .highest_accepted_reset_intent,
                            cancel: &cancel,
                            last_scanned: &mut last_scanned,
                            persist_state: &mut persist_state,
                            live_metadata_flush: &mut live_metadata_flush,
                        }
                        .commit()
                        .await
                    };
                    if outcome.rewind.committed() {
                        if !actor_state.pending_reset_rewind_committed {
                            actor_state.pending_reset_rewind_committed = true;
                            // A committed rewind starts a fresh readiness epoch.
                            actor_state.apply_fact(WalletReadinessFact::ClearAllFaults);
                            actor_state.update_cursor(last_scanned);
                            readiness_started = Instant::now();
                            backfill_complete_block = None;
                            live_rx = live_rx.resubscribe();
                        }

                        if actor_state.pending_reset_replay_admitted.is_none() {
                            let replay_from = reset_replay_from_block(
                                last_scanned,
                                pending.replay_plan.start_block,
                            );
                            let token =
                                worker_handle.mint_sync_token(actor_state.reset_generation);
                            let admitted = if !actor_state.accept_target(
                                token,
                                pending.replay_plan.target_block,
                            ) {
                                actor_state.apply_fact(WalletReadinessFact::SetFault(
                                    WalletReadinessError::BackfillUnavailable,
                                ));
                                false
                            } else if pending.replay_plan.target_block > 0
                                && replay_from > pending.replay_plan.target_block
                            {
                                actor_state.complete_backfill_job(token);
                                backfill_complete_block = actor_state.completed_target_block;
                                true
                            } else {
                                let (liveness, receiver) = oneshot::channel();
                                accepted_backfill_liveness
                                    .push(accepted_backfill_owner_dropped(token, receiver));
                                let driver = WalletBackfillGrant::for_actor_accepted_job(
                                    token,
                                    backfill_sender.clone(),
                                    liveness,
                                )
                                .activate();
                                let request = BackfillRequest::add(
                                    cfg.cache_key.clone(),
                                    replay_from,
                                    pending.replay_plan.target_block,
                                    pending.replay_plan.follow_safe_head,
                                    replay_from,
                                    driver,
                                );
                                match backfill_tx.try_send(request) {
                                    Ok(()) => true,
                                    Err(err) => {
                                        warn!(?err, cache_key = %cfg.cache_key, replay_from, target_block = pending.replay_plan.target_block, "wallet reset replay enqueue failed");
                                        actor_state.fail_job(
                                            token,
                                            WalletReadinessError::BackfillUnavailable,
                                        );
                                        false
                                    }
                                }
                            };
                            actor_state.pending_reset_replay_admitted = admitted.then_some(token);
                        }

                        if actor_state.pending_reset_replay_admitted.is_some() {
                            let authority = WalletPrivateMutationAuthority::new(
                                &worker_handle,
                                actor_state.reset_generation,
                                &cancel,
                            );
                            match authority.acquire().await {
                                Ok(permit) => {
                                    let persist_result = permit.with_active_apply(|token| {
                                        persist_wallet_reset_replay_admission_with_token(
                                            &token,
                                            &permit,
                                            cache_store.as_ref(),
                                            &cfg,
                                            actor_state.highest_accepted_reset_intent,
                                        )
                                    });
                                    match persist_result {
                                        Ok(Ok(())) => {
                                            actor_state.clear_pending_reset();
                                            actor_state.apply_fact(
                                                WalletReadinessFact::ClearAllFaults,
                                            );
                                        }
                                        Ok(Err(err)) => {
                                            warn!(?err, cache_key = %cfg.cache_key, intent_id = pending.intent_id, "failed to retire durable wallet reset replay plan");
                                            actor_state.apply_fact(
                                                WalletReadinessFact::DurablePersistFailed,
                                            );
                                        }
                                        Err(reason) => {
                                            debug!(?reason, cache_key = %cfg.cache_key, intent_id = pending.intent_id, "wallet reset replay-plan retirement rejected");
                                        }
                                    }
                                }
                                Err(reason) => {
                                    debug!(?reason, cache_key = %cfg.cache_key, intent_id = pending.intent_id, "wallet reset replay-plan retirement skipped");
                                }
                            }
                        }
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
                                    checkpoint: WalletCheckpointMutation::Preserve,
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
                actor_state.apply_fact(WalletReadinessFact::DurablePrivateCommitOk {
                    last_scanned: None,
                });
                let mut pre_ready_poi_status_changed = false;
                let mut pre_ready_poi_status_rejection = None;
                let mut pre_ready_poi_status_refresh_elapsed_ms = 0_u128;
                let mut pre_ready_local_cache_available = false;
                if poi_status_client.is_some() {
                    let refresh_needed = {
                        let locked = utxos.read().await;
                        wallet_poi_status_refresh_needed_for_selection(
                            &locked,
                            &active_poi_list_keys,
                            WalletPoiRefreshSelection::RequiredOrRecoverable,
                        )
                    };
                    if refresh_needed {
                        // Actor-safe: only local corpus (never remote proxy/fallback).
                        if let Some(status_reader) = poi_runtime
                            .local_status_reader(&public_data_plane, &cfg, &active_poi_list_keys)
                            .await
                        {
                            pre_ready_local_cache_available = true;
                            let status_refresh_started = Instant::now();
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
                                status_reader: &status_reader,
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

                if poi_status_client.is_some() {
                    let refresh_needed = {
                        let locked = utxos.read().await;
                        wallet_poi_status_refresh_needed_for_selection(
                            &locked,
                            &active_poi_list_keys,
                            WalletPoiRefreshSelection::RequiredOrRecoverable,
                        )
                    };
                    if refresh_needed
                        && let Some(status_reader) = poi_runtime
                            .local_status_reader(&public_data_plane, &cfg, &active_poi_list_keys)
                            .await
                    {
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
                                status_reader: &status_reader,
                                active_poi_list_keys: &active_poi_list_keys,
                                selection: WalletPoiRefreshSelection::RequiredOrRecoverable,
                                cancel: &cancel,
                            })
                            .commit()
                            .await
                            {
                                Ok(changed) => {
                                    debug!(
                                        cache_key = %cfg.cache_key,
                                        changed,
                                        "post-ready local wallet POI status refresh committed"
                                    );
                                }
                                Err(reason) => {
                                    warn!(?reason, cache_key = %cfg.cache_key, "post-ready wallet POI status refresh rejected");
                                }
                            }
                    }
                    let _ = request_poi_maintenance(
                        &mut poi_maintenance,
                        &remote_done_tx,
                        &private_apply,
                        &poi_refreshing_tx,
                        &worker_handle,
                        &cancel,
                        &db,
                        &cache_store,
                        &cfg,
                        &public_data_plane,
                        &rpcs,
                        http_client.as_ref(),
                        indexed_artifact_source.as_ref(),
                        &poi_runtime,
                        &forest,
                        &utxos,
                        &active_poi_list_keys,
                        false,
                    )
                    .await;
                }
                WalletBackfillDoneOutcome::Finished
                }
                }
            }};
        }
        if actor_state.pending_reset.is_some() && try_drive_pending_reset!().is_some() {
            signal_restored_reset_attempt(&mut startup_replay_tx);
        }

        // Prepared-worker cancellation drops the sender, so this cannot hang. Once activation is
        // accepted, let the active loop observe cancellation and publish terminal readiness.
        let activated = activation_rx.await.is_ok();
        if !activated {
            return;
        }
        loop {
            tokio::select! {
                () = cancel.cancelled() => break,
                Some((token, signal)) = accepted_backfill_liveness.next(), if !accepted_backfill_liveness.is_empty() => {
                    let WalletBackfillOwnerSignal {
                        disposition,
                        acknowledgement,
                    } = signal;
                    let changed = actor_state.apply_backfill_owner_disposition(token, disposition);
                    if changed {
                        if disposition == WalletBackfillOwnerDisposition::BenignRetirement
                            && !actor_state.has_active_backfill_job()
                        {
                            backfill_complete_block = actor_state.completed_target_block;
                        } else if disposition == WalletBackfillOwnerDisposition::DriverLost {
                            backfill_complete_block = None;
                        }
                        publish_readiness!();
                    }
                    if let Some(acknowledgement) = acknowledgement {
                        let _ = acknowledgement.send(());
                    }
                }
                Some(token) = accepted_indexed_job_liveness.next(), if !accepted_indexed_job_liveness.is_empty() => {
                    if actor_state.retire_job(token) {
                        let authority = WalletPrivateMutationAuthority::new(
                            &worker_handle,
                            actor_state.reset_generation,
                            &cancel,
                        );
                        if let Ok(permit) = authority.acquire().await
                            && let Err(reason) = permit.publish_indexed_catch_up(None)
                        {
                            debug!(?reason, cache_key = %cfg.cache_key, "indexed wallet catch-up abandonment status clear rejected");
                        }
                        publish_readiness!();
                    }
                }
                Some(apply_req) = private_apply_rx.recv() => {
                    let WalletPrivateApplyRequest {
                        reset_generation,
                        delta,
                        reply,
                    } = apply_req;
                    let result = apply_owned_poi_private_delta_on_actor(
                        &worker_handle,
                        &cancel,
                        reset_generation,
                        db.as_ref(),
                        cache_store.as_ref(),
                        &cfg,
                        delta,
                    )
                    .await;
                    let _ = reply.send(result);
                }
                Some(done) = remote_done_rx.recv() => {
                    match done {
                        WalletRemoteDone::PoiMaintenance {
                            credential,
                            key,
                            recovered,
                            forced_pending_attempts,
                            submitted,
                            verified_completed,
                            verified_pending,
                            verified_errors,
                        } => {
                            // Always complete phase first (may start deferred force follow-up).
                            on_poi_maintenance_done(
                                &mut poi_maintenance,
                                &remote_done_tx,
                                &private_apply,
                                &poi_refreshing_tx,
                                &worker_handle,
                                &cancel,
                                &db,
                                &cache_store,
                                &cfg,
                                &public_data_plane,
                                &rpcs,
                                http_client.as_ref(),
                                indexed_artifact_source.as_ref(),
                                &poi_runtime,
                                &forest,
                                &utxos,
                                &active_poi_list_keys,
                                key,
                            )
                            .await;
                            if !credential.is_current(&worker_handle) {
                                debug!(
                                    cache_key = %cfg.cache_key,
                                    ?key,
                                    "stale poi maintenance result dropped"
                                );
                                continue;
                            }
                            if recovered > 0 {
                                let authority = WalletPrivateMutationAuthority::new(
                                    &worker_handle,
                                    actor_state.reset_generation,
                                    &cancel,
                                );
                                authority
                                    .notify_changed_if(true, "poi_maintenance_remote_done")
                                    .await;
                            }
                            debug!(
                                cache_key = %cfg.cache_key,
                                recovered,
                                forced_pending_attempts,
                                submitted,
                                verified_completed,
                                verified_pending,
                                verified_errors,
                                "wallet POI remote maintenance complete"
                            );
                        }
                    }
                }
                _ = pending_reset_retry.tick(), if actor_state.pending_reset.is_some() => {
                    if let Some(outcome) = try_drive_pending_reset!() {
                        debug!(?outcome.rewind, cache_key = %cfg.cache_key, "wallet pending reset retry completed");
                        signal_restored_reset_attempt(&mut startup_replay_tx);
                    }
                }
                Some(refresh_request) = poi_refresh_rx.recv() => {
                    let Some(_client) = poi_status_client.as_ref() else {
                        continue;
                    };
                    if actor_state.pending_reset.is_some() {
                        let _ = poi_maintenance.request(
                            refresh_request.force_output_poi_recovery,
                            false,
                            None,
                        );
                        debug!(
                            cache_key = %cfg.cache_key,
                            "wallet POI refresh latched while reset commit is pending"
                        );
                        continue;
                    }
                    if backfill_complete_block.is_none() {
                        let _ = poi_maintenance.request(
                            refresh_request.force_output_poi_recovery,
                            false,
                            None,
                        );
                        debug!(
                            cache_key = %cfg.cache_key,
                            "wallet POI refresh latched until backfill complete"
                        );
                        continue;
                    }
                    let current_reset_generation = actor_state.reset_generation;
                    // Local-only status refresh on actor; remote readers must not block the loop.
                    if let Some(status_reader) = poi_runtime
                        .local_status_reader(&public_data_plane, &cfg, &active_poi_list_keys)
                        .await
                    {
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
                            status_reader: &status_reader,
                            active_poi_list_keys: &active_poi_list_keys,
                            selection: WalletPoiRefreshSelection::Recoverable,
                            cancel: &cancel,
                        })
                        .commit()
                        .await
                        {
                            Ok(changed) => {
                                debug!(
                                    cache_key = %cfg.cache_key,
                                    changed,
                                    "manual local wallet POI status refresh committed"
                                );
                            }
                            Err(reason) => {
                                warn!(?reason, cache_key = %cfg.cache_key, "manual wallet POI status refresh rejected");
                            }
                        }
                    }
                    let _ = request_poi_maintenance(
                        &mut poi_maintenance,
                        &remote_done_tx,
                        &private_apply,
                        &poi_refreshing_tx,
                        &worker_handle,
                        &cancel,
                        &db,
                        &cache_store,
                        &cfg,
                        &public_data_plane,
                        &rpcs,
                                http_client.as_ref(),
                                indexed_artifact_source.as_ref(),
                        &poi_runtime,
                        &forest,
                        &utxos,
                        &active_poi_list_keys,
                        refresh_request.force_output_poi_recovery,
                    )
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
                                        let (liveness, receiver) = oneshot::channel();
                                        accepted_indexed_job_liveness
                                            .push(accepted_indexed_job_owner_dropped(token, receiver));
                                        let _ = actor_state.reduce_and_publish_readiness_active(
                                            &permit,
                                            &ready_tx,
                                            &readiness_tx,
                                        );
                                        Some(WalletIndexedCatchUpLease::for_actor_accepted_job(
                                            token,
                                            liveness,
                                        ))
                                    } else {
                                        None
                                    };
                                    if let Err(lease) = response.send(lease) {
                                        drop(lease);
                                        if actor_state.retire_job(token) {
                                            if let Err(reason) =
                                                permit.publish_indexed_catch_up(None)
                                            {
                                                debug!(?reason, cache_key = %cfg.cache_key, "indexed wallet catch-up dropped-claim status clear rejected");
                                            }
                                            let _ = actor_state.reduce_and_publish_readiness_active(
                                                &permit,
                                                &ready_tx,
                                                &readiness_tx,
                                            );
                                        }
                                        debug!(cache_key = %cfg.cache_key, ?token, "indexed wallet catch-up claim receiver dropped");
                                    }
                                }
                                WalletIndexedCatchUpCommand::Publish { token, status } => {
                                    if actor_state.publish_indexed_catch_up(token, status) {
                                        if let Err(reason) =
                                            permit.publish_indexed_catch_up(Some(status))
                                        {
                                            debug!(?reason, cache_key = %cfg.cache_key, "indexed wallet catch-up status publication rejected");
                                        }
                                    } else {
                                        debug!(cache_key = %cfg.cache_key, ?token, "stale indexed wallet catch-up status publication ignored");
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
                Some(request) = private_request_rx.recv() => {
                    match request {
                        WalletPrivateRequest::LocalPendingSpent {
                            ticket,
                            update,
                            reply,
                        } => {
                            let result = match actor_state.validate_private_request(
                                &worker_handle,
                                &cancel,
                                ticket,
                                last_scanned,
                                true,
                            ) {
                                Ok(reset_generation) => {
                                    apply_local_pending_spent_update(
                                        &worker_handle,
                                        &cancel,
                                        reset_generation,
                                        update,
                                    )
                                    .await
                                }
                                Err(err) => Err(err),
                            };
                            let _ = reply.send(result);
                        }
                        WalletPrivateRequest::CreatePendingOutputContexts {
                            ticket,
                            contexts,
                            reply,
                        } => {
                            let result = match actor_state.validate_private_request(
                                &worker_handle,
                                &cancel,
                                ticket,
                                last_scanned,
                                false,
                            ) {
                                Ok(reset_generation) => {
                                    commit_pending_output_contexts(
                                        &worker_handle,
                                        &cancel,
                                        db.as_ref(),
                                        cache_store.as_ref(),
                                        &cfg,
                                        reset_generation,
                                        &contexts,
                                    )
                                    .await
                                }
                                Err(err) => Err(err),
                            };
                            let _ = reply.send(result);
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
                    if let Err(reason) = permit.notify_if_changed(changed).await {
                        debug!(?reason, cache_key = %cfg.cache_key, "pending overlay revision publication rejected");
                    }
                    actor_state.retire_job(request.token);
                    drop(permit);
                }
                () = tokio::time::sleep(WALLET_POI_REFRESH_INTERVAL), if poi_status_client.is_some() && backfill_complete_block.is_some() && actor_state.pending_reset.is_none() => {
                    let Some(_client) = poi_status_client.as_ref() else {
                        continue;
                    };
                    let current_reset_generation = actor_state.reset_generation;
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
                    if refresh_needed
                        && let Some(status_reader) = poi_runtime
                            .local_status_reader(&public_data_plane, &cfg, &active_poi_list_keys)
                            .await
                    {
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
                                status_reader: &status_reader,
                                active_poi_list_keys: &active_poi_list_keys,
                                selection,
                                cancel: &cancel,
                            })
                            .commit()
                            .await
                            {
                                Ok(changed) => {
                                    debug!(
                                        cache_key = %cfg.cache_key,
                                        changed,
                                        "periodic local wallet POI status refresh committed"
                                    );
                                }
                                Err(reason) => {
                                    warn!(?reason, cache_key = %cfg.cache_key, "periodic wallet POI status refresh rejected");
                                }
                        }
                    }
                    let _ = request_poi_maintenance(
                        &mut poi_maintenance,
                        &remote_done_tx,
                        &private_apply,
                        &poi_refreshing_tx,
                        &worker_handle,
                        &cancel,
                        &db,
                        &cache_store,
                        &cfg,
                        &public_data_plane,
                        &rpcs,
                                    http_client.as_ref(),
                                    indexed_artifact_source.as_ref(),
                        &poi_runtime,
                        &forest,
                        &utxos,
                        &active_poi_list_keys,
                        false,
                    )
                    .await;
                }
                Some(event) = backfill_rx.recv() => {
                    match event {
                        BackfillEvent::Start { target_block, token, response } => {
                            if let Err(reason) = actor_state.validate_sync_token_current(
                                token,
                                &worker_handle,
                                &cancel,
                            ) {
                                let _ = response.send(WalletBackfillStartResult::Rejected {
                                    committed_to: last_scanned,
                                    reason,
                                });
                                continue;
                            }
                            if try_drive_pending_reset!().is_some()
                                && actor_state.pending_reset.is_some()
                            {
                                let reason = if actor_state.readiness_fault
                                    == Some(WalletReadinessError::PersistenceFailed)
                                {
                                    WalletBackfillRejectReason::PersistenceFailed
                                } else {
                                    WalletBackfillRejectReason::Shutdown
                                };
                                let _ = response.send(WalletBackfillStartResult::Rejected {
                                    committed_to: last_scanned,
                                    reason,
                                });
                                continue;
                            }
                            if !actor_state.accept_target(token, target_block) {
                                let _ = response.send(WalletBackfillStartResult::Rejected {
                                    committed_to: last_scanned,
                                    reason: WalletBackfillRejectReason::Shutdown,
                                });
                                continue;
                            }
                            let (liveness, receiver) = oneshot::channel();
                            accepted_backfill_liveness
                                .push(accepted_backfill_owner_dropped(token, receiver));
                            backfill_complete_block = None;
                            publish_readiness!();
                            let result = WalletBackfillStartResult::Accepted {
                                committed_to: last_scanned,
                                target_block,
                                grant: WalletBackfillGrant::for_actor_accepted_job(
                                    token,
                                    backfill_sender.clone(),
                                    liveness,
                                ),
                            };
                            if let Err(result) = response.send(result) {
                                drop(result);
                                if actor_state.retire_job(token) {
                                    publish_readiness!();
                                }
                                debug!(cache_key = %cfg.cache_key, ?token, "wallet backfill start receiver dropped");
                            }
                        }
                        BackfillEvent::Apply { apply, token, response } => {
                            if let Some(outcome) = try_drive_pending_reset!()
                                && actor_state.pending_reset.is_some()
                            {
                                actor_state.retire_job(token);
                                let reason = match outcome.rewind {
                                    WalletResetRewindOutcome::Deferred { reason, .. } => reason,
                                    WalletResetRewindOutcome::Committed { .. }
                                        if actor_state.readiness_fault
                                            == Some(WalletReadinessError::PersistenceFailed) =>
                                    {
                                        WalletBackfillRejectReason::PersistenceFailed
                                    }
                                    WalletResetRewindOutcome::Committed { .. } =>
                                        WalletBackfillRejectReason::Shutdown,
                                };
                                if reason == WalletBackfillRejectReason::PersistenceFailed {
                                    actor_state.apply_fact(WalletReadinessFact::DurablePersistFailed);
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
                                mark_syncing_on_commit: true,
                                public_data_plane: &public_data_plane,
                            }
                             .commit()
                             .await;
                             actor_state.update_cursor(last_scanned);
                             if outcome.changed && poi_status_client.is_some() {
                                 let _ = request_poi_maintenance(
                                     &mut poi_maintenance,
                                     &remote_done_tx,
                                     &private_apply,
                                     &poi_refreshing_tx,
                                     &worker_handle,
                                     &cancel,
                                     &db,
                                     &cache_store,
                                     &cfg,
                                     &public_data_plane,
                                     &rpcs,
                                     http_client.as_ref(),
                                     indexed_artifact_source.as_ref(),
                                     &poi_runtime,
                                     &forest,
                                     &utxos,
                                     &active_poi_list_keys,
                                     false,
                                 )
                                 .await;
                             }
                             if let Err(err) = response.send(outcome.result) {
                                 debug!(?err, cache_key = %cfg.cache_key, "failed to send wallet scan apply result");
                             }
                         }
                         BackfillEvent::Finish { target_block, token, response } => {
                            let current_reset_generation = actor_state.reset_generation;
                            if let Err(reason) = actor_state.validate_active_sync_token(
                                token,
                                &worker_handle,
                                WalletActorJobKind::Backfill,
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
                            if let Some(outcome) = try_drive_pending_reset!()
                                && actor_state.pending_reset.is_some()
                            {
                                let reason = match outcome.rewind {
                                    WalletResetRewindOutcome::Deferred { reason, .. } => reason,
                                    WalletResetRewindOutcome::Committed { .. }
                                        if actor_state.readiness_fault
                                            == Some(WalletReadinessError::PersistenceFailed) =>
                                    {
                                        WalletBackfillRejectReason::PersistenceFailed
                                    }
                                    WalletResetRewindOutcome::Committed { .. } =>
                                        WalletBackfillRejectReason::Shutdown,
                                };
                                if reason == WalletBackfillRejectReason::PersistenceFailed {
                                    actor_state.apply_fact(WalletReadinessFact::DurablePersistFailed);
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
                            let Some(required_target) = actor_state.update_target(token, target_block)
                            else {
                                let _ = response.send(WalletBackfillFinishResult::Rejected {
                                    committed_to: last_scanned,
                                    reason: WalletBackfillRejectReason::Shutdown,
                                });
                                continue;
                            };
                            if required_target == 0 || required_target > last_scanned {
                                debug!(
                                    cache_key = %cfg.cache_key,
                                    target_block = required_target,
                                    last_scanned,
                                    reset_generation = current_reset_generation,
                                    "wallet target recorded; cursor has not reached target"
                                );
                                backfill_complete_block = None;
                                publish_readiness!();
                                let result = WalletBackfillFinishResult::Rejected {
                                    committed_to: last_scanned,
                                    reason: WalletBackfillRejectReason::TargetNotReached {
                                        target_block: required_target,
                                    },
                                };
                                if let Err(err) = response.send(result) {
                                    debug!(?err, cache_key = %cfg.cache_key, "failed to send pending wallet target result");
                                }
                                continue;
                            }
                            let finish_outcome = apply_backfill_done!(required_target);
                            let result = match finish_outcome {
                                WalletBackfillDoneOutcome::Finished => {
                                    actor_state.complete_backfill_job(token);
                                    if actor_state.has_active_backfill_job() {
                                        backfill_complete_block = None;
                                    }
                                    publish_readiness!();
                                    WalletBackfillFinishResult::Ready { committed_to: last_scanned }
                                }
                                WalletBackfillDoneOutcome::Rejected(reason) => {
                                    if reason == WalletBackfillRejectReason::PersistenceFailed {
                                        actor_state.apply_fact(
                                            WalletReadinessFact::DurablePersistFailed,
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
                        BackfillEvent::JobFailed { token, reason, response } => {
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
                            let _ = response.send(());
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
                            // AcceptReset transition: durable accept + generation + actor_state +
                            // publications under one active-apply fence (no split after durable write).
                            let accept_result = acceptance_permit.with_active_apply(|token| {
                                persist_wallet_reset_acceptance_with_token(
                                    &token,
                                    &acceptance_permit,
                                    cache_store.as_ref(),
                                    &cfg,
                                    intent_id,
                                    accepted_pending_reset,
                                )?;
                                acceptance_permit
                                    .apply_set_reset_generation(&token, next_reset_generation);
                                let reset_intent_id = accepted_pending_reset.intent_id;
                                let reset_from = accepted_pending_reset.from_block;
                                let clear_indexed_catch_up =
                                    actor_state.accept_reset(accepted_pending_reset);
                                // Force intent is generation-scoped; do not carry across rewind.
                                poi_maintenance.clear_force_on_reset();
                                if clear_indexed_catch_up {
                                    acceptance_permit
                                        .apply_publish_indexed_catch_up(&token, None);
                                }
                                acceptance_permit.apply_publish_view_reset_pending(
                                    &token,
                                    reset_intent_id,
                                    reset_from,
                                    next_reset_generation,
                                );
                                actor_state.reduce_and_publish_readiness_with_token(
                                    &token,
                                    &ready_tx,
                                    &readiness_tx,
                                );
                                Ok::<(), WalletCacheError>(())
                            });
                            match accept_result {
                                Ok(Ok(())) => {
                                    accepted_backfill_liveness.clear();
                                    accepted_indexed_job_liveness.clear();
                                }
                                Ok(Err(err)) => {
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
                                Err(reason) => {
                                    let result = WalletBackfillResetResult::Rejected {
                                        committed_to: last_scanned,
                                        reason,
                                    };
                                    if let Err(err) = response.send(result) {
                                        debug!(?err, cache_key = %cfg.cache_key, "failed to send reset acceptance rejection");
                                    }
                                    continue;
                                }
                            }
                            drop(acceptance_permit);
                            let outcome = try_drive_pending_reset!()
                                .expect("pending reset was installed before commit");
                            // Accept already succeeded: public result is always Accepted.
                            let result =
                                reset_result_after_accept(next_reset_generation, outcome);
                            if let Err(err) = response.send(result) {
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
                                if !actor_state.accept_target(token, batch.to_block) {
                                    actor_state.apply_fact(WalletReadinessFact::SetFault(
                                        WalletReadinessError::BackfillUnavailable,
                                    ));
                                    publish_readiness!();
                                    continue;
                                }
                                let (liveness, receiver) = oneshot::channel();
                                accepted_backfill_liveness
                                    .push(accepted_backfill_owner_dropped(token, receiver));
                                let driver = WalletBackfillGrant::for_actor_accepted_job(
                                    token,
                                    backfill_sender.clone(),
                                    liveness,
                                )
                                .activate();
                                match backfill_tx.try_send(BackfillRequest::add(
                                    cfg.cache_key.clone(),
                                    expected_from_block,
                                    batch.to_block,
                                    true,
                                    expected_from_block,
                                    driver,
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
                            // POI status refresh is never inline on live scan (may be remote).
                            // request_poi_maintenance runs after successful commit.
                            let apply = match WalletScanApply::rows_from_log_batch(
                                expected_from_block,
                                batch.to_block,
                                &batch,
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
                            if !actor_state.accept_target(live_token, batch.to_block) {
                                actor_state.apply_fact(WalletReadinessFact::SetFault(
                                    WalletReadinessError::BackfillUnavailable,
                                ));
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
                                    if outcome.changed && poi_status_client.is_some() {
                                        let _ = request_poi_maintenance(
                                            &mut poi_maintenance,
                                        &remote_done_tx,
                                        &private_apply,
                                        &poi_refreshing_tx,
                                            &worker_handle,
                                            &cancel,
                                            &db,
                                            &cache_store,
                                            &cfg,
                                            &public_data_plane,
                                            &rpcs,
                                            http_client.as_ref(),
                                            indexed_artifact_source.as_ref(),
                                            &poi_runtime,
                                            &forest,
                                            &utxos,
                                            &active_poi_list_keys,
                                            false,
                                        )
                                        .await;
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
        // Cancel drives Active → Stopping. Unregister retires first (under lifecycle fence),
        // so terminal Shutdown is not published for retired actors.
        let _ = worker_handle.mark_stopping();
        let _ = worker_handle.publish_terminal_shutdown_if_allowed(|| {
            actor_state.mark_shutdown();
            if let Err(err) = worker_handle.indexed_catch_up_tx.send(None) {
                debug!(?err, cache_key = %cfg.cache_key, "failed to clear indexed wallet catch-up status on shutdown");
            }
            actor_state.reduce_and_publish_readiness(&ready_tx, &readiness_tx);
        });
    }.instrument(tracing::info_span!("wallet", chain_id)));

    let prepared = PreparedWalletWorker {
        handle: Some(handle),
        cancel: prepared_cancel,
        activation_tx: Some(activation_tx),
    };
    if let Some(startup_replay_rx) = startup_replay_rx {
        startup_replay_rx
            .await
            .map_err(|_| ChainError::WalletResetFailed)?;
    }
    Ok(prepared)
}

#[cfg(test)]
pub(crate) async fn spawn_wallet_worker(
    services: WalletWorkerServices,
    cfg: WalletConfig,
    actor_id: u64,
    live_rx: broadcast::Receiver<SharedLogBatch>,
    backfill_rx: mpsc::Receiver<BackfillEvent>,
    cancel: CancellationToken,
    initial_utxos: Vec<WalletUtxo>,
    initial_last_scanned: u64,
) -> Result<WalletHandle, ChainError> {
    prepare_wallet_worker(
        services,
        cfg,
        actor_id,
        live_rx,
        backfill_rx,
        cancel,
        initial_utxos,
        initial_last_scanned,
    )
    .await?
    .activate()
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
    use async_trait::async_trait;
    use broadcaster_core::crypto::railgun::ViewingKeyData;
    use broadcaster_core::notes::Note;
    use broadcaster_core::query_rpc_pool::QueryRpcPool;
    use broadcaster_core::transact::DEFAULT_TXID_VERSION;
    use local_db::{
        DbConfig, DbStore, PendingOutputPoiContextRecord, PendingOutputPoiRole, WalletCacheKey,
        WalletMeta,
    };
    use merkletree::tree::MerkleForest;
    use poi::error::PoiError;
    use poi::poi::BlindedCommitmentData;
    use tokio::sync::{RwLock, broadcast, mpsc, oneshot, watch};
    use url::Url;

    use railgun_wallet::scan::{SpentNullifier, WalletLogDelta};
    use railgun_wallet::{PoiStatus, Utxo, UtxoCommitmentKind, UtxoSource, WalletUtxo};

    use crate::chain::ChainPublicDataPlane;
    use crate::types::{
        BackfillRequest, ChainKey, GlobalPoiPolicy, LogBatch, PublicDataPlaneEpoch,
        PublicScanReadScope, WalletBackfillDriver, WalletConfig, WalletIndexedCatchUpSource,
        WalletIndexedCatchUpStatus, WalletPendingSpent, WalletScanRows,
    };
    use crate::wallet::WalletActorLifecycle;
    use crate::wallet::handle::WalletPendingOverlayRequest;

    fn test_public_data_plane(db: &Arc<DbStore>) -> ChainPublicDataPlane {
        ChainPublicDataPlane::new(
            Arc::clone(db),
            Arc::new(std::sync::atomic::AtomicU64::new(0)),
        )
    }

    fn test_wallet_poi_runtime() -> WalletPoiRuntime {
        WalletPoiRuntime::from_policy(
            &GlobalPoiPolicy::PoiProxy {
                rpc_url: Url::parse("http://127.0.0.1:1").expect("POI RPC URL"),
            },
            None,
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
        fail_next_reset_replay_retirement: bool,
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

        fn fail_next_reset_replay_retirement(&self) {
            self.state
                .lock()
                .expect("cache state")
                .fail_next_reset_replay_retirement = true;
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
            if matches!(commit.utxo_mutation(), WalletUtxoMutation::Replace(_)) {
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
            let actor_state = commit.sync_actor_state().cloned();
            <DbStore as WalletCacheStore>::commit_wallet_private_state(self.db.as_ref(), commit)?;
            if let Some(state) = actor_state {
                *self.actor_state.lock().expect("actor state") = Some(state);
            }
            Ok(())
        }

        fn load_wallet_utxos(
            &self,
            _wallet_id: &WalletCacheKey,
        ) -> Result<Vec<WalletUtxo>, WalletCacheError> {
            Ok(Vec::new())
        }

        fn get_wallet_meta(
            &self,
            _wallet_id: &WalletCacheKey,
        ) -> Result<Option<WalletMeta>, WalletCacheError> {
            Ok(None)
        }

        fn get_wallet_sync_actor_state(
            &self,
            _chain_id: u64,
            _wallet_id: &WalletCacheKey,
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
            if commit.state().pending_reset.is_none()
                && store_state.fail_next_reset_replay_retirement
            {
                store_state.fail_next_reset_replay_retirement = false;
                return Err(WalletCacheError::Crypto);
            }
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
        match send_start_token(sender, apply.to_block, token).await {
            WalletBackfillStartResult::Accepted { grant, .. } => {
                let driver = grant.activate();
                let result = driver.apply("test", apply).await;
                driver.retire("test").await;
                result
            }
            WalletBackfillStartResult::Rejected {
                committed_to,
                reason,
            } => WalletBackfillApplyResult::Rejected {
                committed_to,
                reason,
            },
        }
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
        match send_start_token(sender, target_block, token).await {
            WalletBackfillStartResult::Accepted { grant, .. } => {
                let driver = grant.activate();
                let result = driver.finish("test", target_block).await;
                if !matches!(result, WalletBackfillFinishResult::Ready { .. }) {
                    driver.retire("test").await;
                }
                result
            }
            WalletBackfillStartResult::Rejected {
                committed_to,
                reason,
            } => WalletBackfillFinishResult::Rejected {
                committed_to,
                reason,
            },
        }
    }

    async fn send_start_token(
        sender: &mpsc::Sender<BackfillEvent>,
        target_block: u64,
        token: WalletSyncToken,
    ) -> WalletBackfillStartResult {
        let (response, result_rx) = oneshot::channel();
        sender
            .send(BackfillEvent::Start {
                target_block,
                token,
                response,
            })
            .await
            .expect("send target");
        result_rx.await.expect("target response")
    }

    fn assert_start_accepted(
        result: WalletBackfillStartResult,
        token: WalletSyncToken,
        committed_to: u64,
        target_block: u64,
    ) -> WalletBackfillDriver {
        match result {
            WalletBackfillStartResult::Accepted {
                committed_to: actual_committed_to,
                target_block: actual_target_block,
                grant,
            } => {
                assert_eq!(actual_committed_to, committed_to);
                assert_eq!(actual_target_block, target_block);
                assert_eq!(grant.token(), token);
                grant.activate()
            }
            other @ WalletBackfillStartResult::Rejected { .. } => {
                panic!("expected accepted target, got {other:?}")
            }
        }
    }

    fn accepted_test_backfill_owner(
        state: &mut WalletActorState,
        token: WalletSyncToken,
        target_block: u64,
    ) -> (
        WalletBackfillGrant,
        oneshot::Receiver<WalletBackfillOwnerSignal>,
    ) {
        assert!(state.accept_target(token, target_block));
        let (sender, _receiver) = mpsc::channel(1);
        let (liveness, receiver) = oneshot::channel();
        (
            WalletBackfillGrant::for_actor_accepted_job(token, sender, liveness),
            receiver,
        )
    }

    async fn unacknowledged_test_backfill_disposition(
        token: WalletSyncToken,
        liveness: oneshot::Receiver<WalletBackfillOwnerSignal>,
    ) -> WalletBackfillOwnerDisposition {
        let (actual_token, signal) = accepted_backfill_owner_dropped(token, liveness).await;
        assert_eq!(actual_token, token);
        assert!(signal.acknowledgement.is_none());
        signal.disposition
    }

    #[tokio::test]
    async fn dropped_start_response_receiver_retires_accepted_owner() {
        let mut state = WalletActorState::new(1, 1, 0, 100, 0, None);
        let token = WalletSyncToken::for_test(1, 1, 0, 1);
        let (grant, liveness) = accepted_test_backfill_owner(&mut state, token, 200);
        let (response, result_rx) = oneshot::channel();
        drop(result_rx);

        let result = WalletBackfillStartResult::Accepted {
            committed_to: 100,
            target_block: 200,
            grant,
        };
        drop(
            response
                .send(result)
                .expect_err("start receiver was dropped"),
        );

        assert_eq!(
            unacknowledged_test_backfill_disposition(token, liveness).await,
            WalletBackfillOwnerDisposition::BenignRetirement
        );
        assert!(state.apply_backfill_owner_disposition(
            token,
            WalletBackfillOwnerDisposition::BenignRetirement,
        ));
        assert!(state.active_jobs.is_empty());
    }

    #[tokio::test]
    async fn dropped_delivered_start_result_retires_accepted_owner() {
        let mut state = WalletActorState::new(1, 1, 0, 100, 0, None);
        let token = WalletSyncToken::for_test(1, 1, 0, 1);
        let (grant, liveness) = accepted_test_backfill_owner(&mut state, token, 200);
        let (response, result_rx) = oneshot::channel();
        response
            .send(WalletBackfillStartResult::Accepted {
                committed_to: 100,
                target_block: 200,
                grant,
            })
            .expect("deliver accepted start result");

        drop(result_rx.await.expect("receive accepted start result"));

        assert_eq!(
            unacknowledged_test_backfill_disposition(token, liveness).await,
            WalletBackfillOwnerDisposition::BenignRetirement
        );
        assert!(state.apply_backfill_owner_disposition(
            token,
            WalletBackfillOwnerDisposition::BenignRetirement,
        ));
        assert!(state.active_jobs.is_empty());
    }

    #[tokio::test]
    async fn dropping_unactivated_backfill_grant_restores_completed_readiness_without_fault() {
        let mut state = WalletActorState::new(1, 1, 0, 100, 0, None);
        let completed = WalletSyncToken::for_test(1, 1, 0, 1);
        assert!(state.accept_target(completed, 100));
        assert!(state.complete_backfill_job(completed));
        assert_eq!(state.derived_readiness(), WalletReadiness::Ready);

        let newer = WalletSyncToken::for_test(1, 1, 0, 2);
        let (grant, liveness) = accepted_test_backfill_owner(&mut state, newer, 200);
        assert_eq!(state.derived_readiness(), WalletReadiness::Syncing);
        drop(grant);

        assert_eq!(
            unacknowledged_test_backfill_disposition(newer, liveness).await,
            WalletBackfillOwnerDisposition::BenignRetirement
        );
        assert!(state.apply_backfill_owner_disposition(
            newer,
            WalletBackfillOwnerDisposition::BenignRetirement,
        ));
        assert_eq!(state.completed_target_block, Some(100));
        assert_eq!(state.readiness_fault, None);
        assert_eq!(state.derived_readiness(), WalletReadiness::Ready);
    }

    #[test]
    fn multiple_backfill_targets_recompute_from_job_records() {
        let mut state = WalletActorState::new(1, 1, 0, 200, 0, None);
        let first = WalletSyncToken::for_test(1, 1, 0, 1);
        let second = WalletSyncToken::for_test(1, 1, 0, 2);
        assert!(state.accept_target(first, 150));
        assert!(state.accept_target(second, 200));

        assert!(state.complete_backfill_job(first));
        assert_eq!(state.completed_target_block, Some(150));
        assert_eq!(state.derived_readiness(), WalletReadiness::Syncing);
        assert!(state.retire_job(second));
        assert_eq!(state.derived_readiness(), WalletReadiness::Ready);
    }

    #[tokio::test]
    async fn dropped_backfill_request_reports_active_driver_loss() {
        let mut state = WalletActorState::new(1, 1, 0, 100, 0, None);
        let completed = WalletSyncToken::for_test(1, 1, 0, 1);
        assert!(state.accept_target(completed, 100));
        assert!(state.complete_backfill_job(completed));
        assert_eq!(state.derived_readiness(), WalletReadiness::Ready);

        let token = WalletSyncToken::for_test(1, 1, 0, 2);
        let (grant, liveness) = accepted_test_backfill_owner(&mut state, token, 200);
        assert_eq!(state.derived_readiness(), WalletReadiness::Syncing);
        drop(BackfillRequest::add(
            "test",
            101,
            200,
            false,
            101,
            grant.activate(),
        ));

        assert_eq!(
            unacknowledged_test_backfill_disposition(token, liveness).await,
            WalletBackfillOwnerDisposition::DriverLost
        );
        assert!(
            state.apply_backfill_owner_disposition(
                token,
                WalletBackfillOwnerDisposition::DriverLost,
            )
        );
        assert!(state.active_jobs.is_empty());
        assert_eq!(
            state.derived_readiness(),
            WalletReadiness::Failed(WalletReadinessError::BackfillUnavailable)
        );
    }

    #[tokio::test]
    async fn persistence_retry_completion_ignores_subsequent_driver_drop() {
        let mut state = WalletActorState::new(1, 1, 0, 100, 0, None);
        let token = WalletSyncToken::for_test(1, 1, 0, 1);
        let (grant, liveness) = accepted_test_backfill_owner(&mut state, token, 100);
        let driver = grant.activate();

        state.apply_fact(WalletReadinessFact::DurablePersistFailed);

        assert!(state.is_active_job(token, WalletActorJobKind::Backfill));
        assert_eq!(state.active_jobs[&token.job_id()].target_block, Some(100));
        state.apply_fact(WalletReadinessFact::DurablePrivateCommitOk { last_scanned: None });
        assert!(state.complete_backfill_job(token));
        assert_eq!(state.derived_readiness(), WalletReadiness::Ready);
        drop(driver);
        assert_eq!(
            unacknowledged_test_backfill_disposition(token, liveness).await,
            WalletBackfillOwnerDisposition::DriverLost
        );
        assert!(
            !state.apply_backfill_owner_disposition(
                token,
                WalletBackfillOwnerDisposition::DriverLost,
            )
        );
        assert_eq!(state.derived_readiness(), WalletReadiness::Ready);
    }

    #[tokio::test]
    async fn dropped_indexed_owner_clears_exact_job_status_and_readiness() {
        let mut state = WalletActorState::new(1, 1, 0, 100, 0, None);
        let completed = WalletSyncToken::for_test(1, 1, 0, 1);
        assert!(state.accept_target(completed, 100));
        assert!(state.complete_backfill_job(completed));
        let token = WalletSyncToken::for_test(1, 1, 0, 2);
        assert!(state.accept_indexed_catch_up(token));
        let status = WalletIndexedCatchUpStatus {
            source: WalletIndexedCatchUpSource::IndexedArtifacts,
            from_block: 101,
            target_block: 200,
        };
        assert!(state.publish_indexed_catch_up(token, status));
        assert_eq!(
            state.active_jobs[&token.job_id()].indexed_status.as_ref(),
            Some(&status)
        );
        let (liveness, receiver) = oneshot::channel();
        let lease = WalletIndexedCatchUpLease::for_actor_accepted_job(token, liveness);
        drop(lease);

        assert_eq!(
            accepted_indexed_job_owner_dropped(token, receiver).await,
            token
        );
        assert!(state.retire_job(token));
        assert_eq!(state.derived_readiness(), WalletReadiness::Ready);
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
            &logs_payload(from_block, to_block),
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
                poi_runtime: test_wallet_poi_runtime(),
                forest: Arc::new(RwLock::new(MerkleForest::new())),
                backfill_tx: backfill_request_tx,
                backfill_sender: backfill_tx.clone(),
                public_data_plane: public_data_plane.clone(),
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
        assert_eq!(handle.last_scanned(), Some(100));

        let initial_token = handle.mint_sync_token(0);
        assert_eq!(
            send_target_token(&backfill_tx, 100, initial_token).await,
            WalletBackfillFinishResult::Ready { committed_to: 100 }
        );
        tokio::time::timeout(Duration::from_secs(1), async {
            while handle.last_scanned() != Some(101) {
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
                poi_runtime: test_wallet_poi_runtime(),
                forest: Arc::new(RwLock::new(MerkleForest::new())),
                backfill_tx: backfill_request_tx,
                backfill_sender: backfill_tx.clone(),
                public_data_plane: public_data_plane.clone(),
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

        assert_eq!(handle.last_scanned(), Some(100));
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
                poi_runtime: test_wallet_poi_runtime(),
                forest: Arc::new(RwLock::new(MerkleForest::new())),
                backfill_tx: backfill_request_tx,
                backfill_sender: backfill_tx.clone(),
                public_data_plane: public_data_plane.clone(),
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
        let tail_token = handle.mint_sync_token(0);
        let tail_lease = assert_start_accepted(
            send_start_token(&backfill_tx, 1000, tail_token).await,
            tail_token,
            900,
            1000,
        );
        assert_eq!(
            tail_lease
                .apply("test", indexed_delta_batch(901, 950, empty_delta()))
                .await,
            WalletBackfillApplyResult::Committed { committed_to: 950 }
        );

        tokio::time::timeout(Duration::from_secs(1), async {
            while handle.last_scanned() != Some(950) {
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .expect("partial indexed tail applied");
        assert_eq!(handle.readiness(), WalletReadiness::Syncing);
        assert!(!*handle.ready_rx.borrow());
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
                poi_runtime: test_wallet_poi_runtime(),
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
            while handle.last_scanned() != Some(120) {
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
                poi_runtime: test_wallet_poi_runtime(),
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

        assert_eq!(handle.last_scanned(), Some(100));
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
                poi_runtime: test_wallet_poi_runtime(),
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

        assert_eq!(handle.last_scanned(), Some(100));
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
                poi_runtime: test_wallet_poi_runtime(),
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

        assert_eq!(handle.last_scanned(), Some(110));
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
                poi_runtime: test_wallet_poi_runtime(),
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
                let overlay = handle.pending_overlay().expect("current view");
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
                poi_runtime: test_wallet_poi_runtime(),
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
                let overlay = handle.pending_overlay().expect("current view");
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
            handle
                .pending_overlay()
                .expect("current view")
                .pending_spent,
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
                poi_runtime: test_wallet_poi_runtime(),
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

        let lease = assert_start_accepted(
            send_start_token(&backfill_tx, 150, token).await,
            token,
            100,
            150,
        );
        lease.retire("test").await;

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
                poi_runtime: test_wallet_poi_runtime(),
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
        assert_eq!(handle.authority_reset_generation(), 0);
        assert_eq!(handle.last_scanned(), Some(100));

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
                poi_runtime: test_wallet_poi_runtime(),
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
        let lease = assert_start_accepted(
            send_start_token(&backfill_tx, 200, token).await,
            token,
            100,
            200,
        );
        lease.retire("test").await;
        tokio::time::sleep(Duration::from_millis(25)).await;
        let (response, result_rx) = oneshot::channel();
        backfill_tx
            .send(BackfillEvent::JobFailed {
                token,
                reason: WalletReadinessError::BackfillUnavailable,
                response,
            })
            .await
            .expect("late job failure");
        result_rx.await.expect("job failure response");
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
                poi_runtime: test_wallet_poi_runtime(),
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
        assert_eq!(handle.last_scanned(), Some(100));

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
                poi_runtime: test_wallet_poi_runtime(),
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

        let _lease = assert_start_accepted(
            send_start_token(&backfill_tx, 150, token).await,
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
            assert!(actor_state.accept_target(token, 0));
            assert!(actor_state.retire_job(token));
        }

        assert!(actor_state.active_jobs.is_empty());
        assert_eq!(actor_state.highest_accepted_backfill_job_id, 10_000);
        assert!(!actor_state.accept_job(
            WalletSyncToken::for_test(1, 1, 0, 10_000),
            WalletActorJobKind::Backfill,
        ));
        assert!(actor_state.accept_target(WalletSyncToken::for_test(1, 1, 0, 10_001), 0));
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
                poi_runtime: test_wallet_poi_runtime(),
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

        let lease = assert_start_accepted(
            send_start_token(&backfill_tx, 150, token).await,
            token,
            100,
            150,
        );
        lease.retire("test").await;

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
                poi_runtime: test_wallet_poi_runtime(),
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
        assert_eq!(handle.authority_reset_generation(), 0);

        let token = handle.mint_sync_token(handle.authority_reset_generation());
        let lease = assert_start_accepted(
            send_start_token(&backfill_tx, 110, token).await,
            token,
            100,
            110,
        );
        assert_eq!(
            lease
                .apply("test", indexed_delta_batch(101, 110, empty_delta()))
                .await,
            WalletBackfillApplyResult::Committed { committed_to: 110 }
        );
        assert_eq!(
            lease.finish("test", 110).await,
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
            driver,
            ..
        } = request
        else {
            panic!("expected live-gap add request");
        };
        assert_eq!(from_block, 111);
        assert_eq!(to_block, 120);
        assert_eq!(driver.token().reset_generation(), 0);

        cancel.cancel();
        drop(db);
        fs::remove_dir_all(root_dir).expect("remove temp db dir");
    }

    #[tokio::test]
    async fn wallet_reset_replay_is_admitted_when_response_receiver_is_dropped() {
        let root_dir = temp_db_root("wallet-reset-dropped-response");
        let db = Arc::new(
            DbStore::open(DbConfig {
                root_dir: root_dir.clone(),
            })
            .expect("open db"),
        );
        let cfg = wallet_config();
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
                poi_runtime: test_wallet_poi_runtime(),
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

        let (response, result_rx) = oneshot::channel();
        drop(result_rx);
        backfill_tx
            .send(BackfillEvent::Reset {
                token: test_reset_token(1),
                from_block: 100,
                replay_plan: WalletResetReplayPlan::new(0, 150, false),
                response,
            })
            .await
            .expect("send reset with dropped response receiver");

        let request = tokio::time::timeout(Duration::from_secs(1), backfill_request_rx.recv())
            .await
            .expect("actor-owned reset replay admitted")
            .expect("backfill request channel open");
        let BackfillRequest::Add {
            from_block,
            to_block,
            follow_safe_head,
            driver,
            ..
        } = request
        else {
            panic!("expected reset replay add request");
        };
        assert_eq!(from_block, 100);
        assert_eq!(to_block, 150);
        assert!(!follow_safe_head);
        assert_eq!(driver.token().reset_generation(), 1);

        tokio::time::timeout(Duration::from_secs(1), async {
            loop {
                let state = db
                    .get_wallet_sync_actor_state(cfg.chain.chain_id, &cfg.cache_key)
                    .expect("load wallet sync actor state")
                    .expect("wallet sync actor state");
                if state.pending_reset.is_none() {
                    break;
                }
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("durable reset plan retired after actor-owned admission");
        assert!(backfill_request_rx.try_recv().is_err());

        cancel.cancel();
        drop(handle);
        drop(db);
        fs::remove_dir_all(root_dir).expect("remove temp db dir");
    }

    #[tokio::test]
    async fn wallet_reset_replay_is_readmitted_after_durable_retirement_failure() {
        let root_dir = temp_db_root("wallet-reset-replay-readmission");
        let db = Arc::new(
            DbStore::open(DbConfig {
                root_dir: root_dir.clone(),
            })
            .expect("open db"),
        );
        let cache_store = Arc::new(FailingCacheStore::new(Arc::clone(&db)));
        cache_store.fail_next_reset_replay_retirement();
        let mut cfg = wallet_config();
        cfg.cache_store = Some(cache_store);
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
                poi_runtime: test_wallet_poi_runtime(),
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

        let (response, result_rx) = oneshot::channel();
        backfill_tx
            .send(BackfillEvent::Reset {
                token: test_reset_token(1),
                from_block: 100,
                replay_plan: WalletResetReplayPlan::new(0, 150, false),
                response,
            })
            .await
            .expect("send reset");
        assert_eq!(
            result_rx.await.expect("reset response"),
            WalletBackfillResetResult::accepted_committed(1, 99)
        );
        let first_lease =
            match tokio::time::timeout(Duration::from_secs(1), backfill_request_rx.recv())
                .await
                .expect("first reset replay admitted")
                .expect("first reset replay request")
            {
                BackfillRequest::Add { driver, .. } => driver,
                BackfillRequest::Remove { .. } => panic!("expected reset replay add request"),
            };
        let first_token = first_lease.token();

        first_lease.retire("test").await;
        let (response, result_rx) = oneshot::channel();
        backfill_tx
            .send(BackfillEvent::Apply {
                apply: indexed_delta_batch(100, 100, empty_delta()),
                token: first_token,
                response,
            })
            .await
            .expect("send event after reset replay retirement");
        assert_eq!(
            result_rx.await.expect("retired replay response"),
            WalletBackfillApplyResult::Rejected {
                committed_to: 99,
                reason: WalletBackfillRejectReason::Shutdown,
            }
        );

        let second_lease =
            match tokio::time::timeout(Duration::from_secs(1), backfill_request_rx.recv())
                .await
                .expect("reset replay readmitted")
                .expect("readmitted reset replay request")
            {
                BackfillRequest::Add { driver, .. } => driver,
                BackfillRequest::Remove { .. } => panic!("expected reset replay add request"),
            };
        let second_token = second_lease.token();
        assert_ne!(second_token, first_token);

        cancel.cancel();
        drop(handle);
        drop(db);
        fs::remove_dir_all(root_dir).expect("remove temp db dir");
    }

    #[tokio::test]
    async fn wallet_dropped_overlapping_backfill_response_preserves_covering_job() {
        let root_dir = temp_db_root("wallet-dropped-backfill-response");
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
                poi_runtime: test_wallet_poi_runtime(),
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

        let covering_token = handle.mint_sync_token(0);
        let covering_lease = assert_start_accepted(
            send_start_token(&backfill_tx, 200, covering_token).await,
            covering_token,
            100,
            200,
        );
        let dropped_token = handle.mint_sync_token(0);
        let (response, result_rx) = oneshot::channel();
        drop(result_rx);
        backfill_tx
            .send(BackfillEvent::Start {
                target_block: 150,
                token: dropped_token,
                response,
            })
            .await
            .expect("send target with dropped response receiver");

        let (response, result_rx) = oneshot::channel();
        backfill_tx
            .send(BackfillEvent::Apply {
                apply: indexed_delta_batch(101, 110, empty_delta()),
                token: dropped_token,
                response,
            })
            .await
            .expect("send late apply for dropped handoff");
        assert_eq!(
            result_rx.await.expect("late apply response"),
            WalletBackfillApplyResult::Rejected {
                committed_to: 100,
                reason: WalletBackfillRejectReason::Shutdown,
            }
        );
        assert_eq!(handle.readiness(), WalletReadiness::Syncing);

        assert_eq!(
            covering_lease
                .apply("test", indexed_delta_batch(101, 200, empty_delta()))
                .await,
            WalletBackfillApplyResult::Committed { committed_to: 200 }
        );
        assert_eq!(
            covering_lease.finish("test", 200).await,
            WalletBackfillFinishResult::Ready { committed_to: 200 }
        );

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
                poi_runtime: test_wallet_poi_runtime(),
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
            WalletBackfillResetResult::accepted_pending(
                1,
                120,
                Some(WalletBackfillRejectReason::PersistenceFailed),
            )
        );
        let token = handle.mint_sync_token(1);
        cache_store.fail_next_store();
        assert!(matches!(
            send_start_token(&backfill_tx, 130, token).await,
            WalletBackfillStartResult::Rejected {
                reason: WalletBackfillRejectReason::PersistenceFailed
                    | WalletBackfillRejectReason::Shutdown,
                ..
            }
        ));

        tokio::time::timeout(Duration::from_secs(2), async {
            loop {
                let state = db
                    .get_wallet_sync_actor_state(1, handle.cache_key.as_str())
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

        let replay_lease = match backfill_request_rx
            .recv()
            .await
            .expect("actor-owned reset replay request")
        {
            BackfillRequest::Add { driver, .. } => driver,
            BackfillRequest::Remove { .. } => panic!("expected reset replay add request"),
        };
        assert_eq!(
            replay_lease
                .apply("test", indexed_delta_batch(100, 130, empty_delta()))
                .await,
            WalletBackfillApplyResult::Committed { committed_to: 130 }
        );
        assert_eq!(
            replay_lease.finish("test", 130).await,
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
                poi_runtime: test_wallet_poi_runtime(),
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
            WalletBackfillResetResult::accepted_committed(1, 50)
        );
        assert_eq!(handle.last_scanned(), Some(50));
        assert_eq!(
            db.get_wallet_meta(&handle.cache_key)
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
    async fn wallet_reset_covered_positive_replay_target_completes_without_queued_job() {
        let root_dir = temp_db_root("wallet-reset-covered-replay-target");
        let db = Arc::new(
            DbStore::open(DbConfig {
                root_dir: root_dir.clone(),
            })
            .expect("open db"),
        );
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
                poi_runtime: test_wallet_poi_runtime(),
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
            120,
        )
        .await
        .expect("spawn wallet worker");

        let (response, result_rx) = oneshot::channel();
        backfill_tx
            .send(BackfillEvent::Reset {
                token: test_reset_token(1),
                from_block: 121,
                replay_plan: WalletResetReplayPlan::new(0, 100, false),
                response,
            })
            .await
            .expect("send covered-target reset");
        assert_eq!(
            result_rx.await.expect("reset response"),
            WalletBackfillResetResult::accepted_committed(1, 120)
        );
        tokio::time::timeout(Duration::from_secs(1), async {
            while handle.readiness() != WalletReadiness::Ready {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("covered replay target becomes ready");

        assert_eq!(handle.last_scanned(), Some(120));
        assert!(backfill_request_rx.try_recv().is_err());

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
                poi_runtime: test_wallet_poi_runtime(),
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
            WalletBackfillResetResult::accepted_pending(
                1,
                120,
                Some(WalletBackfillRejectReason::PersistenceFailed),
            )
        );
        // Accept held, rewind failed: public view is fenced.
        assert_eq!(handle.last_scanned(), None);
        assert_eq!(handle.last_scanned_raw(), 120);
        assert_eq!(
            send_reset(&backfill_tx, 2, 80).await,
            WalletBackfillResetResult::accepted_committed(2, 79)
        );
        assert_eq!(handle.last_scanned(), Some(79));
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
                poi_runtime: test_wallet_poi_runtime(),
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
            while handle.pending_overlay().map(|o| o.pending_spent.clone())
                != Some(vec![pending_spent.clone()])
            {
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .expect("pending overlay applied");

        assert_eq!(
            send_reset(&backfill_tx, 1, 100).await,
            WalletBackfillResetResult::accepted_committed(1, 99)
        );
        let overlay = handle.pending_overlay().expect("current after rewind");
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
                poi_runtime: test_wallet_poi_runtime(),
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
                poi_runtime: test_wallet_poi_runtime(),
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
        let _gap_lease = assert_start_accepted(
            send_start_token(&backfill_tx, 150, gap_token).await,
            gap_token,
            100,
            150,
        );
        let covered_token = handle.mint_sync_token(0);
        let covered_lease = assert_start_accepted(
            send_start_token(&backfill_tx, 100, covered_token).await,
            covered_token,
            100,
            100,
        );
        assert_eq!(
            covered_lease.finish("test", 100).await,
            WalletBackfillFinishResult::Ready { committed_to: 100 }
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
                poi_runtime: test_wallet_poi_runtime(),
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
            WalletBackfillResetResult::accepted_pending(
                1,
                120,
                Some(WalletBackfillRejectReason::PersistenceFailed),
            )
        );

        assert_eq!(handle.authority_reset_generation(), 1);
        // Accept succeeded, rewind failed: public view is fenced (not pre-reset current).
        assert!(matches!(
            handle.view_state(),
            WalletViewState::ResetPending {
                intent_id: 1,
                from_block: 100,
                reset_generation: 1,
            }
        ));
        assert_eq!(handle.last_scanned(), None);
        assert!(handle.utxos_snapshot().is_none());
        assert!(handle.pending_overlay().is_none());
        assert!(handle.current_snapshot().is_none());
        assert_eq!(handle.last_scanned_raw(), 120);
        assert_eq!(handle.readiness(), WalletReadiness::Syncing);
        assert!(!*handle.ready_rx.borrow());
        assert_eq!(*handle.rev_rx.borrow(), rev_before_reset);
        assert_eq!(
            cache_store.state().store_calls,
            store_calls_before_reset + 1
        );
        let state = db
            .get_wallet_sync_actor_state(1, handle.cache_key.as_str())
            .expect("load wallet sync actor state")
            .expect("wallet sync actor state persisted");
        assert_eq!(state.highest_accepted_reset_intent, 1);
        assert_eq!(state.pending_reset.expect("pending reset").from_block, 100);

        tokio::time::timeout(Duration::from_secs(2), async {
            loop {
                if handle.last_scanned() == Some(99) {
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
            .get_wallet_sync_actor_state(1, handle.cache_key.as_str())
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
                poi_runtime: test_wallet_poi_runtime(),
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
            WalletBackfillResetResult::accepted_committed(1, 99)
        );

        assert_eq!(handle.last_scanned(), Some(99));
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
            wallet_id: cfg.cache_key.to_string(),
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
                poi_runtime: test_wallet_poi_runtime(),
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

        assert_eq!(handle.authority_reset_generation(), 1);
        assert_eq!(handle.last_scanned(), Some(99));
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
    async fn wallet_worker_restored_pending_reset_waits_for_first_actor_replay_attempt() {
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
            wallet_id: cfg.cache_key.to_string(),
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
            Duration::from_secs(1),
            spawn_wallet_worker(
                WalletWorkerServices {
                    db: Arc::clone(&db),
                    rpcs: Arc::new(QueryRpcPool::new(
                        vec![Url::parse("http://127.0.0.1:1").expect("rpc url")],
                        Duration::from_secs(1),
                    )),
                    http_client: None,
                    indexed_artifact_source: None,
                    poi_runtime: test_wallet_poi_runtime(),
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
        .expect("restored pending reset first attempt should complete")
        .expect("spawn wallet worker");

        assert_eq!(
            cache_store.state().store_calls,
            1,
            "worker must not expose the handle before the first rewind attempt"
        );
        assert_eq!(handle.authority_reset_generation(), 1);
        // Public view is fenced: pre-reset cursor/UTXOs are not current.
        assert!(matches!(
            handle.view_state(),
            WalletViewState::ResetPending {
                intent_id: 7,
                from_block: 100,
                reset_generation: 1,
            }
        ));
        assert_eq!(handle.last_scanned(), None);
        assert!(handle.utxos_snapshot().is_none());
        assert!(handle.pending_overlay().is_none());
        assert!(handle.current_snapshot().is_none());
        assert_eq!(handle.last_scanned_raw(), 120);
        assert_eq!(handle.readiness(), WalletReadiness::Syncing);
        assert!(
            cache_store
                .actor_state()
                .expect("restored actor state")
                .pending_reset
                .is_some()
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
        let public_data_plane = test_public_data_plane(&db);

        let result = spawn_wallet_worker(
            WalletWorkerServices {
                db: Arc::clone(&db),
                rpcs: Arc::new(QueryRpcPool::new(
                    vec![Url::parse("http://127.0.0.1:1").expect("rpc url")],
                    Duration::from_secs(1),
                )),
                http_client: None,
                indexed_artifact_source: None,
                poi_runtime: test_wallet_poi_runtime(),
                forest: Arc::new(RwLock::new(MerkleForest::new())),
                backfill_tx: backfill_request_tx,
                backfill_sender: backfill_tx,
                public_data_plane: public_data_plane.clone(),
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

        assert!(matches!(
            result,
            Err(ChainError::WalletCache(WalletCacheError::Crypto))
        ));
        cancel.cancel();
        drop(db);
        fs::remove_dir_all(root_dir).expect("remove temp db dir");
    }

    #[tokio::test]
    async fn dropping_prepared_wallet_worker_retires_unregistered_actor() {
        let root_dir = temp_db_root("wallet-prepared-registration-cancelled");
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
        let prepared = prepare_wallet_worker(
            WalletWorkerServices {
                db: Arc::clone(&db),
                rpcs: Arc::new(QueryRpcPool::new(
                    vec![Url::parse("http://127.0.0.1:1").expect("rpc url")],
                    Duration::from_secs(1),
                )),
                http_client: None,
                indexed_artifact_source: None,
                poi_runtime: test_wallet_poi_runtime(),
                forest: Arc::new(RwLock::new(MerkleForest::new())),
                backfill_tx: backfill_request_tx,
                backfill_sender: backfill_tx,
                public_data_plane: test_public_data_plane(&db),
            },
            wallet_config(),
            1,
            live_rx,
            backfill_rx,
            cancel.clone(),
            Vec::new(),
            0,
        )
        .await
        .expect("prepare wallet worker");
        let handle = prepared.handle().clone();
        assert_eq!(handle.lifecycle(), WalletActorLifecycle::Prepared);

        drop(prepared);

        assert_eq!(handle.lifecycle(), WalletActorLifecycle::Retired);
        assert!(!handle.is_current_actor());
        assert!(cancel.is_cancelled());

        drop(db);
        fs::remove_dir_all(root_dir).expect("remove temp db dir");
    }

    #[tokio::test]
    async fn wallet_worker_publishes_shutdown_readiness_on_cancel() {
        let root_dir = temp_db_root("wallet-shutdown-readiness");
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
        let handle = spawn_wallet_worker(
            WalletWorkerServices {
                db: Arc::clone(&db),
                rpcs: Arc::new(QueryRpcPool::new(
                    vec![Url::parse("http://127.0.0.1:1").expect("rpc url")],
                    Duration::from_secs(1),
                )),
                http_client: None,
                indexed_artifact_source: None,
                poi_runtime: test_wallet_poi_runtime(),
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
            Vec::new(),
            0,
        )
        .await
        .expect("spawn wallet worker");
        let mut readiness_rx = handle.readiness_rx.clone();

        cancel.cancel();

        tokio::time::timeout(Duration::from_secs(1), async {
            while *readiness_rx.borrow() != WalletReadiness::Shutdown {
                readiness_rx
                    .changed()
                    .await
                    .expect("shutdown readiness should be published before channel closes");
            }
        })
        .await
        .expect("shutdown readiness published");
        assert_eq!(handle.readiness(), WalletReadiness::Shutdown);

        drop(db);
        fs::remove_dir_all(root_dir).expect("remove temp db dir");
    }

    #[tokio::test]
    async fn wallet_retire_actor_does_not_wait_on_authority_lock() {
        let root_dir = temp_db_root("wallet-retire-without-authority-lock");
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
                poi_runtime: test_wallet_poi_runtime(),
                forest: Arc::new(RwLock::new(MerkleForest::new())),
                backfill_tx: backfill_request_tx,
                backfill_sender: backfill_tx,
                public_data_plane: test_public_data_plane(&db),
            },
            wallet_config(),
            1,
            live_rx,
            backfill_rx,
            cancel.clone(),
            Vec::new(),
            0,
        )
        .await
        .expect("spawn wallet worker");

        // Simulate an R3-style long hold of authority_lock across remote I/O.
        let lock = Arc::clone(&handle.authority_lock);
        let held = lock.lock_owned().await;
        let retire_handle = handle.clone();
        let retired = tokio::task::spawn_blocking(move || {
            retire_handle.retire_actor();
            retire_handle.lifecycle()
        })
        .await
        .expect("retire task");
        assert_eq!(retired, WalletActorLifecycle::Retired);
        assert!(!handle.is_current_actor());
        drop(held);

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
                poi_runtime: test_wallet_poi_runtime(),
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
        handle.retire_actor();
        assert_eq!(handle.lifecycle(), WalletActorLifecycle::Retired);

        assert_eq!(
            send_reset(&backfill_tx, 1, 100).await,
            WalletBackfillResetResult::Rejected {
                committed_to: 120,
                reason: WalletBackfillRejectReason::Shutdown,
            }
        );

        assert_eq!(handle.authority_reset_generation(), 0);
        assert_eq!(handle.last_scanned(), None);
        assert_eq!(handle.last_scanned_raw(), 120);
        assert_eq!(
            handle.view_state().inactive_reason(),
            Some(WalletInactiveReason::Retired)
        );
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
        let mut cfg = wallet_config();
        cfg.cache_store = Some(cache_store.clone());
        let checkpoint = WalletMeta {
            last_scanned_block: 100,
            updated_at: 88,
            last_scanned_block_hash: Some([0xb6; 32]),
        };
        db.put_wallet_meta(&cfg.cache_key, &checkpoint)
            .expect("seed POI refresh checkpoint");
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
                poi_runtime: test_wallet_poi_runtime(),
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
            vec![test_wallet_utxo(105, 7)],
            100,
        )
        .await
        .expect("spawn wallet worker");
        let (ready_tx, ready_rx) = watch::channel(true);
        let (readiness_tx, readiness_rx) = watch::channel(WalletReadiness::Syncing);
        let mut persist_state = WalletPersistState::default();
        let mut actor_state = WalletActorState::new(1, 1, 0, 100, 0, None);
        let active_poi_list_keys = default_active_poi_list_keys();
        let poi_runtime = test_wallet_poi_runtime();
        // Unit test of commit request: job-style reader is fine (not actor path).
        let status_source = poi_runtime
            .status_reader_for_job(&public_data_plane, &cfg, &active_poi_list_keys)
            .await
            .expect("POI status reader");

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
            status_reader: status_source.as_reader(),
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
        drop(snapshot);

        assert_eq!(
            WalletPoiStatusRefreshCommitRequest {
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
                status_reader: status_source.as_reader(),
                active_poi_list_keys: &active_poi_list_keys,
                selection: WalletPoiRefreshSelection::RequiredOrRecoverable,
                cancel: &cancel,
            }
            .commit()
            .await,
            Ok(true)
        );
        let retained_checkpoint = db
            .get_wallet_meta(&cfg.cache_key)
            .expect("read retained POI refresh checkpoint")
            .expect("POI refresh checkpoint present");
        assert_eq!(retained_checkpoint.last_scanned_block, 100);
        assert_eq!(retained_checkpoint.updated_at, 88);
        assert_eq!(
            retained_checkpoint.last_scanned_block_hash,
            Some([0xb6; 32])
        );
        let snapshot = handle.utxos.read().await;
        assert!(!snapshot[0].utxo.poi.statuses.is_empty());

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
                poi_runtime: test_wallet_poi_runtime(),
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
    async fn wallet_scan_commit_does_not_perform_inline_poi_status_refresh() {
        // Architectural invariant: scan commit never awaits POI status I/O.
        // Remote/local status refresh is scheduled via PoiMaintenanceJob instead.
        let root_dir = temp_db_root("wallet-scan-commit-no-inline-poi");
        let db = Arc::new(
            DbStore::open(DbConfig {
                root_dir: root_dir.clone(),
            })
            .expect("open db"),
        );
        let cache_store = Arc::new(FailingCacheStore::new(Arc::clone(&db)));
        let mut cfg = wallet_config();
        cfg.cache_store = Some(cache_store.clone());
        let wallet_utxo = test_wallet_utxo(105, 7);
        let (started_tx, _started_rx) = oneshot::channel();
        let (_release, release_rx) = oneshot::channel();
        // If scan commit still awaited status refresh, this would hang forever.
        let _blocking_reader = Arc::new(BlockingPoiStatusReader::new(started_tx, release_rx));
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
                poi_runtime: test_wallet_poi_runtime(),
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
        let (readiness_tx, _readiness_rx) = watch::channel(WalletReadiness::Syncing);
        let mut last_scanned = 100;
        let mut persist_state = WalletPersistState::default();
        let mut live_metadata_flush = WalletLiveMetadataFlush::new(100, Instant::now());
        let mut actor_state = WalletActorState::new(1, 1, 0, 100, 0, None);
        let public_data_plane = test_public_data_plane(&db);
        let outcome = tokio::time::timeout(
            Duration::from_secs(2),
            WalletScanCommitRequest {
                db: db.as_ref(),
                cache_store: cache_store.as_ref(),
                cfg: &cfg,
                utxos: &handle.utxos,
                worker_handle: &handle,
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
                cancel: &cancel,
                last_scanned: &mut last_scanned,
                persist_state: &mut persist_state,
                live_metadata_flush: &mut live_metadata_flush,
                ready_tx: &ready_tx,
                readiness_tx: &readiness_tx,
                mark_syncing_on_commit: true,
                public_data_plane: &public_data_plane,
            }
            .commit(),
        )
        .await
        .expect("scan commit must not block on POI status I/O");

        assert!(matches!(
            outcome.result,
            WalletBackfillApplyResult::Committed { .. }
        ));
        assert!(outcome.changed);
        assert_eq!(handle.last_scanned(), Some(110));

        cancel.cancel();
        drop(db);
        fs::remove_dir_all(root_dir).expect("remove temp db dir");
    }

    #[test]
    fn readiness_facts_recover_persistence_failed_but_not_sticky_faults() {
        let mut state = WalletActorState::new(1, 1, 0, 10, 0, None);

        state.apply_fact(WalletReadinessFact::DurablePersistFailed);
        assert_eq!(
            state.derived_readiness(),
            WalletReadiness::Failed(WalletReadinessError::PersistenceFailed)
        );

        state.apply_fact(WalletReadinessFact::DurablePrivateCommitOk {
            last_scanned: Some(50),
        });
        assert_eq!(state.last_scanned, 50);
        assert_eq!(state.derived_readiness(), WalletReadiness::Syncing);

        state.apply_fact(WalletReadinessFact::SetFault(
            WalletReadinessError::BackfillUnavailable,
        ));
        state.apply_fact(WalletReadinessFact::DurablePrivateCommitOk {
            last_scanned: Some(60),
        });
        assert_eq!(state.last_scanned, 60);
        assert_eq!(
            state.derived_readiness(),
            WalletReadiness::Failed(WalletReadinessError::BackfillUnavailable)
        );

        state.apply_fact(WalletReadinessFact::ClearAllFaults);
        assert_eq!(state.derived_readiness(), WalletReadiness::Syncing);
    }

    #[tokio::test]
    async fn wallet_scan_commit_success_clears_published_persistence_failed() {
        // R1: durable scan success must not re-publish Failed(PersistenceFailed).
        // Recovery is encoded in DurablePrivateCommitOk before reduce/publish.
        let root_dir = temp_db_root("wallet-scan-commit-clears-persistence-failed");
        let db = Arc::new(
            DbStore::open(DbConfig {
                root_dir: root_dir.clone(),
            })
            .expect("open db"),
        );
        let cache_store = Arc::new(FailingCacheStore::new(Arc::clone(&db)));
        let mut cfg = wallet_config();
        cfg.cache_store = Some(cache_store.clone());
        let wallet_utxo = test_wallet_utxo(105, 7);
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
                poi_runtime: test_wallet_poi_runtime(),
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
        let (ready_tx, ready_rx) = watch::channel(false);
        let (readiness_tx, readiness_rx) = watch::channel(WalletReadiness::Failed(
            WalletReadinessError::PersistenceFailed,
        ));
        let mut last_scanned = 100;
        let mut persist_state = WalletPersistState::default();
        let mut live_metadata_flush = WalletLiveMetadataFlush::new(100, Instant::now());
        let mut actor_state = WalletActorState::new(1, 1, 0, 100, 0, None);
        actor_state.apply_fact(WalletReadinessFact::DurablePersistFailed);
        assert_eq!(
            actor_state.derived_readiness(),
            WalletReadiness::Failed(WalletReadinessError::PersistenceFailed)
        );
        let public_data_plane = test_public_data_plane(&db);
        let outcome = WalletScanCommitRequest {
            db: db.as_ref(),
            cache_store: cache_store.as_ref(),
            cfg: &cfg,
            utxos: &handle.utxos,
            worker_handle: &handle,
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
            cancel: &cancel,
            last_scanned: &mut last_scanned,
            persist_state: &mut persist_state,
            live_metadata_flush: &mut live_metadata_flush,
            ready_tx: &ready_tx,
            readiness_tx: &readiness_tx,
            mark_syncing_on_commit: true,
            public_data_plane: &public_data_plane,
        }
        .commit()
        .await;

        assert!(matches!(
            outcome.result,
            WalletBackfillApplyResult::Committed { .. }
        ));
        assert_eq!(last_scanned, 110);
        assert_eq!(actor_state.last_scanned, 110);
        assert_eq!(
            *readiness_rx.borrow(),
            WalletReadiness::Syncing,
            "successful scan must publish recovered readiness, not leave PersistenceFailed"
        );
        assert!(!*ready_rx.borrow());
        assert!(!matches!(
            actor_state.derived_readiness(),
            WalletReadiness::Failed(WalletReadinessError::PersistenceFailed)
        ));

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
                poi_runtime: test_wallet_poi_runtime(),
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
        let lease = assert_start_accepted(
            send_start_token(&backfill_tx, 200, token).await,
            token,
            100,
            200,
        );
        assert_eq!(
            lease
                .apply("test", indexed_delta_batch(101, 200, empty_delta()))
                .await,
            WalletBackfillApplyResult::Committed { committed_to: 200 }
        );
        assert_eq!(
            lease.finish("test", 200).await,
            WalletBackfillFinishResult::Ready { committed_to: 200 }
        );

        tokio::time::timeout(Duration::from_secs(1), async {
            while handle.last_scanned() != Some(200) || !*handle.ready_rx.borrow() {
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
                poi_runtime: test_wallet_poi_runtime(),
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
        assert_eq!(handle.last_scanned(), Some(100));

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
                poi_runtime: test_wallet_poi_runtime(),
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
                    &logs_payload(100, 199),
                    crate::types::PublicScanSource::Rpc,
                )
                .expect("normalize shared log payload"),
                0,
            )
            .await,
            WalletBackfillApplyResult::Committed { committed_to: 130 }
        );
        assert_eq!(handle.last_scanned(), Some(130));
        assert_eq!(
            send_apply(
                &handle,
                &backfill_tx,
                WalletScanApply::rows_from_log_batch(
                    131,
                    199,
                    &logs_payload(100, 199),
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
        assert_eq!(handle.last_scanned(), Some(130));

        cancel.cancel();
        drop(db);
        fs::remove_dir_all(root_dir).expect("remove temp db dir");
    }

    #[tokio::test]
    async fn wallet_dropped_indexed_claim_response_retires_exact_accepted_job() {
        let root_dir = temp_db_root("wallet-dropped-indexed-claim-response");
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
                poi_runtime: test_wallet_poi_runtime(),
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

        let (response, result_rx) = oneshot::channel();
        drop(result_rx);
        handle
            .indexed_catch_up_status_tx
            .send(WalletIndexedCatchUpCommand::Claim { response })
            .expect("send indexed claim with dropped response receiver");

        let lease =
            tokio::time::timeout(Duration::from_secs(1), handle.try_claim_indexed_catch_up())
                .await
                .expect("second indexed claim completed")
                .expect("dropped first claim must be retired");
        drop(lease);
        tokio::time::timeout(Duration::from_secs(1), async {
            while handle.readiness() != WalletReadiness::Ready {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("indexed claim retirement republished readiness");

        let shutdown_lease = handle
            .try_claim_indexed_catch_up()
            .await
            .expect("indexed claim before shutdown");
        handle.set_indexed_catch_up(
            &shutdown_lease,
            WalletIndexedCatchUpStatus {
                source: WalletIndexedCatchUpSource::Squid,
                from_block: 101,
                target_block: 200,
            },
        );
        tokio::time::timeout(Duration::from_secs(1), async {
            while handle.indexed_catch_up_rx.borrow().is_none() {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("indexed status published before shutdown");
        cancel.cancel();
        tokio::time::timeout(Duration::from_secs(1), async {
            while handle.readiness() != WalletReadiness::Shutdown
                || handle.indexed_catch_up_rx.borrow().is_some()
            {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("shutdown cleared indexed status and active job");
        drop(shutdown_lease);
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
                poi_runtime: test_wallet_poi_runtime(),
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
        handle.set_indexed_catch_up(&first_lease, first_status);
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
        drop(first_lease);
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
        handle.set_indexed_catch_up(&second_lease, second_status);
        tokio::time::timeout(Duration::from_secs(1), async {
            while handle.indexed_catch_up_rx.borrow().as_ref() != Some(&second_status) {
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .expect("second indexed catch-up status published");

        assert!(send_reset(&backfill_tx, 1, 50).await.committed());
        tokio::time::timeout(Duration::from_secs(1), async {
            while handle.indexed_catch_up_rx.borrow().is_some() {
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .expect("reset cleared indexed catch-up status");
        drop(second_lease);

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
                poi_runtime: test_wallet_poi_runtime(),
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
        let done_token = handle.mint_sync_token(0);
        let _done_lease = assert_start_accepted(
            send_start_token(&backfill_tx, 200, done_token).await,
            done_token,
            150,
            200,
        );
        assert_eq!(handle.last_scanned(), Some(150));
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
            while handle.last_scanned() == Some(150) {
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .expect("marker delta processed");
        assert_eq!(handle.last_scanned(), Some(151));

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
                poi_runtime: test_wallet_poi_runtime(),
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
            WalletBackfillResetResult::accepted_committed(1, 79)
        );
        tokio::time::timeout(Duration::from_secs(1), async {
            while handle.authority_reset_generation() != 1 || handle.last_scanned() != Some(79) {
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
        assert_eq!(handle.last_scanned(), Some(79));

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
        let current_target_lease = assert_start_accepted(
            send_start_token(&backfill_tx, 150, current_target_token).await,
            current_target_token,
            79,
            150,
        );
        current_target_lease.retire("test").await;
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
            while handle.last_scanned() != Some(90) {
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
                poi_runtime: test_wallet_poi_runtime(),
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
        assert_eq!(handle.last_scanned(), Some(100));

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
            driver,
            ..
        } = request
        else {
            panic!("expected add backfill request");
        };
        assert_eq!(cache_key, handle.cache_key.to_string());
        assert_eq!(from_block, 101);
        assert!(to_block > from_block);
        assert!(follow_safe_head);
        assert_eq!(driver.token().reset_generation(), 0);
        assert_eq!(handle.last_scanned(), Some(100));

        assert_eq!(
            driver.apply("test", logs_apply(from_block, to_block)).await,
            WalletBackfillApplyResult::Committed {
                committed_to: to_block
            }
        );
        assert_eq!(
            driver.finish("test", to_block).await,
            WalletBackfillFinishResult::Ready {
                committed_to: to_block
            }
        );
        tokio::time::timeout(Duration::from_secs(1), async {
            while handle.last_scanned() != Some(to_block) {
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .expect("recovery backfill applied");

        cancel.cancel();
        drop(db);
        fs::remove_dir_all(root_dir).expect("remove temp db dir");
    }

    #[tokio::test]
    async fn wallet_private_mailbox_publishes_coherent_local_pending_spends() {
        let wallet_utxo = test_wallet_utxo(105, 7);
        let (root_dir, db, _cache_store, handle, cancel, _backfill_tx, _live_tx) =
            spawn_consumer_api_wallet("wallet-private-local-pending", vec![wallet_utxo.clone()])
                .await;
        let initial_revision = handle
            .current_snapshot()
            .expect("current wallet view")
            .revision;
        let tx_hash = FixedBytes::from([0x71; 32]);

        assert_eq!(
            handle
                .mark_pending_spent_utxos(std::slice::from_ref(&wallet_utxo.utxo), Some(tx_hash))
                .await,
            Ok(true)
        );
        let marked = handle.current_snapshot().expect("marked wallet view");
        assert_eq!(marked.utxos.len(), 1);
        assert!(marked.revision > initial_revision);
        assert_eq!(marked.pending_overlay.local_pending_spent.len(), 1);
        assert_eq!(
            marked.pending_overlay.local_pending_spent[0].tx_hash,
            Some(tx_hash)
        );

        let missing = test_wallet_utxo(106, 99);
        assert_eq!(
            handle
                .mark_pending_spent_utxos(std::slice::from_ref(&missing.utxo), None)
                .await,
            Ok(false),
            "the actor must not mark an input outside its current unspent projection"
        );
        let mut stale_replacement = wallet_utxo.utxo.clone();
        stale_replacement.note.value = U256::from(999);
        assert_eq!(
            handle
                .mark_pending_spent_utxos(std::slice::from_ref(&stale_replacement), None)
                .await,
            Ok(false),
            "a stale input must not mark a different current output at the same position"
        );
        assert_eq!(handle.clear_all_local_pending_spent().await, Ok(true));
        assert!(
            handle
                .current_snapshot()
                .expect("cleared wallet view")
                .pending_overlay
                .local_pending_spent
                .is_empty()
        );

        handle.retire_actor();
        assert_eq!(
            handle
                .mark_pending_spent_utxos(std::slice::from_ref(&wallet_utxo.utxo), None)
                .await,
            Err(WalletPrivateRequestError::Inactive)
        );

        cancel.cancel();
        drop(db);
        fs::remove_dir_all(root_dir).expect("remove temp db dir");
    }

    #[tokio::test]
    async fn wallet_private_mailbox_orders_mark_before_clear_across_command_kinds() {
        let wallet_utxo = test_wallet_utxo(105, 7);
        let (root_dir, db, _cache_store, handle, cancel, _backfill_tx, _live_tx) =
            spawn_consumer_api_wallet("wallet-private-command-order", vec![wallet_utxo.clone()])
                .await;
        let snapshot = handle.current_snapshot().expect("current wallet view");
        let ticket = WalletPrivateViewTicket::Current {
            reset_generation: snapshot.reset_generation,
            last_scanned: snapshot.last_scanned,
        };
        let revision = snapshot.revision;
        let held = Arc::clone(&handle.authority_lock).lock_owned().await;
        let (mark_reply, mark_result) = oneshot::channel();
        handle
            .private_request_tx
            .send(WalletPrivateRequest::LocalPendingSpent {
                ticket,
                update: WalletLocalPendingSpentUpdate::Mark {
                    utxos: vec![wallet_utxo.utxo],
                    tx_hash: None,
                },
                reply: mark_reply,
            })
            .await
            .expect("queue mark request");
        let (clear_reply, clear_result) = oneshot::channel();
        handle
            .private_request_tx
            .send(WalletPrivateRequest::LocalPendingSpent {
                ticket,
                update: WalletLocalPendingSpentUpdate::ClearAll,
                reply: clear_reply,
            })
            .await
            .expect("queue clear request");
        wait_for_sender_capacity(&handle.private_request_tx, 7, "ordered private commands").await;

        drop(held);
        assert_eq!(mark_result.await.expect("mark result"), Ok(true));
        assert_eq!(clear_result.await.expect("clear result"), Ok(true));
        let final_snapshot = handle.current_snapshot().expect("final wallet view");
        assert!(
            final_snapshot
                .pending_overlay
                .local_pending_spent
                .is_empty()
        );
        assert_eq!(final_snapshot.revision, revision.wrapping_add(2));

        cancel.cancel();
        drop(db);
        fs::remove_dir_all(root_dir).expect("remove temp db dir");
    }

    #[tokio::test]
    async fn pending_output_context_mailbox_stamps_deduplicates_and_fences_persistence() {
        let wallet_utxo = test_wallet_utxo(105, 7);
        let (root_dir, db, cache_store, handle, cancel, _backfill_tx, _live_tx) =
            spawn_consumer_api_wallet("wallet-private-pending-context", vec![wallet_utxo.clone()])
                .await;
        let cfg = wallet_config();
        let context = pending_output_context_intent_for_wallet_utxo(&wallet_utxo);
        let checkpoint = WalletMeta {
            last_scanned_block: 100,
            updated_at: 77,
            last_scanned_block_hash: Some([0xa5; 32]),
        };
        db.put_wallet_meta(&cfg.cache_key, &checkpoint)
            .expect("seed checkpoint metadata");
        let revision_before = handle
            .current_snapshot()
            .expect("current wallet view")
            .revision;

        assert_eq!(
            handle
                .create_pending_output_poi_contexts(vec![context.clone()])
                .await,
            Ok(1)
        );
        let persisted = db
            .get_pending_output_poi_context(
                cfg.chain.chain_id,
                &cfg.cache_key,
                &context.output_commitment,
            )
            .expect("read pending context")
            .expect("persisted pending context");
        assert_eq!(persisted.chain_id, cfg.chain.chain_id);
        assert_eq!(persisted.wallet_id, cfg.cache_key.as_str());
        assert!(persisted.created_at > 0);
        assert!(persisted.txid_merkleroot_index.is_none());
        assert!(persisted.source_operation_id.is_none());
        assert!(persisted.observation.is_none());
        assert!(persisted.submitted_poi_list_keys.is_empty());
        assert!(persisted.terminal_error.is_none());
        let retained_checkpoint = db
            .get_wallet_meta(&cfg.cache_key)
            .expect("read retained checkpoint")
            .expect("checkpoint present");
        assert_eq!(retained_checkpoint.last_scanned_block, 100);
        assert_eq!(retained_checkpoint.updated_at, 77);
        assert_eq!(
            retained_checkpoint.last_scanned_block_hash,
            Some([0xa5; 32])
        );
        assert_eq!(
            handle
                .current_snapshot()
                .expect("wallet view after context persistence")
                .revision,
            revision_before,
            "context persistence must not publish an unrelated wallet-view revision"
        );

        let mut advanced = persisted;
        advanced.observation = Some(local_db::PendingOutputPoiObservation {
            output_tree: 3,
            output_position: 4,
            tx_hash: FixedBytes::from([0x79; 32]),
            block_number: 120,
            block_timestamp: 1_700_000_120,
        });
        advanced.submitted_poi_list_keys = vec![FixedBytes::from([0x7a; 32])];
        db.put_pending_output_poi_context(&advanced)
            .expect("advance pending context state");
        assert_eq!(
            handle
                .create_pending_output_poi_contexts(vec![context.clone()])
                .await,
            Ok(0),
            "duplicate creation must not overwrite actor-owned workflow state"
        );
        let retained = db
            .get_pending_output_poi_context(
                cfg.chain.chain_id,
                &cfg.cache_key,
                &context.output_commitment,
            )
            .expect("read retained pending context")
            .expect("retained pending context");
        assert_eq!(retained.observation, advanced.observation);
        assert_eq!(
            retained.submitted_poi_list_keys,
            advanced.submitted_poi_list_keys
        );

        let mut first = context.clone();
        first.output_commitment = FixedBytes::from([0x81; 32]);
        first.output_npk = FixedBytes::from([0x91; 32]);
        let mut duplicate = first.clone();
        duplicate.output_npk = FixedBytes::from([0x92; 32]);
        assert_eq!(
            handle
                .create_pending_output_poi_contexts(vec![first.clone(), duplicate])
                .await,
            Ok(1),
            "the first matching commitment in one request must win"
        );
        let deduplicated = db
            .get_pending_output_poi_context(
                cfg.chain.chain_id,
                &cfg.cache_key,
                &first.output_commitment,
            )
            .expect("read deduplicated pending context")
            .expect("deduplicated pending context");
        assert_eq!(deduplicated.output_npk, first.output_npk);
        assert!(deduplicated.observation.is_none());
        assert!(deduplicated.submitted_poi_list_keys.is_empty());
        assert!(deduplicated.terminal_error.is_none());

        cache_store.fail_next_meta();
        let mut failed = context;
        failed.output_commitment = FixedBytes::from([0x82; 32]);
        assert_eq!(
            handle
                .create_pending_output_poi_contexts(vec![failed.clone()])
                .await,
            Err(WalletPrivateRequestError::PersistenceFailed)
        );
        assert!(
            db.get_pending_output_poi_context(
                cfg.chain.chain_id,
                &cfg.cache_key,
                &failed.output_commitment,
            )
            .expect("read failed pending context")
            .is_none()
        );
        assert_eq!(
            handle
                .current_snapshot()
                .expect("wallet view after failed persistence")
                .revision,
            revision_before
        );

        cancel.cancel();
        drop(db);
        fs::remove_dir_all(root_dir).expect("remove temp db dir");
    }

    #[tokio::test]
    async fn reset_pending_private_commands_prefer_active_then_retired_session_state() {
        let wallet_utxo = test_wallet_utxo(105, 7);
        let (root_dir, db, cache_store, handle, cancel, backfill_tx, _live_tx) =
            spawn_consumer_api_wallet(
                "wallet-private-reset-pending-retired",
                vec![wallet_utxo.clone()],
            )
            .await;
        let cfg = wallet_config();
        let context = pending_output_context_intent_for_wallet_utxo(&wallet_utxo);
        assert_eq!(
            handle
                .mark_pending_spent_utxos(std::slice::from_ref(&wallet_utxo.utxo), None)
                .await,
            Ok(true)
        );
        let revision = *handle.rev_rx.borrow();

        cache_store.fail_next_store();
        assert_eq!(
            send_reset(&backfill_tx, 1, 80).await,
            WalletBackfillResetResult::accepted_pending(
                1,
                100,
                Some(WalletBackfillRejectReason::PersistenceFailed),
            )
        );
        assert!(matches!(
            handle.view_state(),
            WalletViewState::ResetPending { .. }
        ));
        assert_private_command_error(
            &handle,
            &wallet_utxo,
            context.clone(),
            WalletPrivateRequestError::ResetPending,
        )
        .await;
        assert_private_command_state_unchanged(&handle, revision).await;
        assert!(
            db.get_pending_output_poi_context(
                cfg.chain.chain_id,
                &cfg.cache_key,
                &context.output_commitment,
            )
            .expect("read reset-pending context")
            .is_none()
        );

        handle.retire_actor();
        cancel.cancel();
        assert_eq!(
            handle.view_state().inactive_reason(),
            Some(WalletInactiveReason::Retired)
        );
        assert_private_command_error(
            &handle,
            &wallet_utxo,
            context.clone(),
            WalletPrivateRequestError::Inactive,
        )
        .await;
        assert_private_command_state_unchanged(&handle, revision).await;
        assert!(
            db.get_pending_output_poi_context(
                cfg.chain.chain_id,
                &cfg.cache_key,
                &context.output_commitment,
            )
            .expect("read retired context")
            .is_none()
        );

        drop(db);
        fs::remove_dir_all(root_dir).expect("remove temp db dir");
    }

    #[tokio::test]
    async fn reset_pending_private_commands_prefer_worker_shutdown_state() {
        let wallet_utxo = test_wallet_utxo(105, 7);
        let (root_dir, db, cache_store, handle, cancel, backfill_tx, _live_tx) =
            spawn_consumer_api_wallet(
                "wallet-private-reset-pending-shutdown",
                vec![wallet_utxo.clone()],
            )
            .await;
        let cfg = wallet_config();
        let context = pending_output_context_intent_for_wallet_utxo(&wallet_utxo);
        assert_eq!(
            handle
                .mark_pending_spent_utxos(std::slice::from_ref(&wallet_utxo.utxo), None)
                .await,
            Ok(true)
        );
        let revision = *handle.rev_rx.borrow();

        cache_store.fail_next_store();
        assert!(matches!(
            send_reset(&backfill_tx, 1, 80).await,
            WalletBackfillResetResult::Accepted {
                rewind: WalletResetRewindStatus::Pending { .. },
                ..
            }
        ));
        cancel.cancel();
        tokio::time::timeout(Duration::from_secs(1), async {
            while handle.view_state().inactive_reason() != Some(WalletInactiveReason::Shutdown) {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("worker publishes terminal shutdown view");

        assert_private_command_error(
            &handle,
            &wallet_utxo,
            context.clone(),
            WalletPrivateRequestError::Inactive,
        )
        .await;
        assert_private_command_state_unchanged(&handle, revision).await;
        assert!(
            db.get_pending_output_poi_context(
                cfg.chain.chain_id,
                &cfg.cache_key,
                &context.output_commitment,
            )
            .expect("read shutdown context")
            .is_none()
        );

        drop(db);
        fs::remove_dir_all(root_dir).expect("remove temp db dir");
    }

    #[tokio::test]
    async fn wallet_private_mailbox_rejects_queued_stale_stamps() {
        let wallet_utxo = test_wallet_utxo(105, 7);
        let (root_dir, db, _cache_store, handle, cancel, _backfill_tx, _live_tx) =
            spawn_consumer_api_wallet("wallet-private-stale-queue", vec![wallet_utxo.clone()])
                .await;
        let (pending_reply, pending_result) = oneshot::channel();
        handle
            .private_request_tx
            .send(WalletPrivateRequest::LocalPendingSpent {
                ticket: WalletPrivateViewTicket::Current {
                    reset_generation: 0,
                    last_scanned: 99,
                },
                update: WalletLocalPendingSpentUpdate::Mark {
                    utxos: vec![wallet_utxo.utxo.clone()],
                    tx_hash: None,
                },
                reply: pending_reply,
            })
            .await
            .expect("queue stale pending-spend request");
        assert_eq!(
            pending_result.await.expect("stale pending-spend response"),
            Err(WalletPrivateRequestError::StaleView)
        );
        assert!(
            handle
                .current_snapshot()
                .expect("current wallet view")
                .pending_overlay
                .local_pending_spent
                .is_empty()
        );

        let cfg = wallet_config();
        let context = pending_output_context_intent_for_wallet_utxo(&wallet_utxo);
        let (context_reply, context_result) = oneshot::channel();
        handle
            .private_request_tx
            .send(WalletPrivateRequest::CreatePendingOutputContexts {
                ticket: WalletPrivateViewTicket::Current {
                    reset_generation: 1,
                    last_scanned: 100,
                },
                contexts: vec![context.clone()],
                reply: context_reply,
            })
            .await
            .expect("queue stale pending-context request");
        assert_eq!(
            context_result
                .await
                .expect("stale pending-context response"),
            Err(WalletPrivateRequestError::StaleView)
        );
        assert!(
            db.get_pending_output_poi_context(
                cfg.chain.chain_id,
                &cfg.cache_key,
                &context.output_commitment,
            )
            .expect("read stale pending context")
            .is_none()
        );

        cancel.cancel();
        drop(db);
        fs::remove_dir_all(root_dir).expect("remove temp db dir");
    }

    #[tokio::test]
    async fn dequeued_clear_all_rejects_shutdown_without_mutation() {
        let wallet_utxo = test_wallet_utxo(105, 7);
        let (root_dir, db, _cache_store, handle, cancel, _backfill_tx, _live_tx) =
            spawn_consumer_api_wallet("wallet-private-clear-shutdown", vec![wallet_utxo.clone()])
                .await;
        assert_eq!(
            handle
                .mark_pending_spent_utxos(std::slice::from_ref(&wallet_utxo.utxo), None)
                .await,
            Ok(true)
        );
        let revision_before = handle
            .current_snapshot()
            .expect("marked wallet view")
            .revision;
        let held = Arc::clone(&handle.authority_lock).lock_owned().await;
        let snapshot = handle.current_snapshot().expect("current clear-all view");
        let (clear_reply, clear_result) = oneshot::channel();
        handle
            .private_request_tx
            .send(WalletPrivateRequest::LocalPendingSpent {
                ticket: WalletPrivateViewTicket::Current {
                    reset_generation: snapshot.reset_generation,
                    last_scanned: snapshot.last_scanned,
                },
                update: WalletLocalPendingSpentUpdate::ClearAll,
                reply: clear_reply,
            })
            .await
            .expect("queue clear-all request");
        wait_for_sender_capacity(&handle.private_request_tx, 8, "dequeued clear-all").await;

        cancel.cancel();
        drop(held);
        assert_eq!(
            clear_result.await.expect("clear-all result"),
            Err(WalletPrivateRequestError::Inactive)
        );
        assert_eq!(
            handle.view_state().inactive_reason(),
            Some(WalletInactiveReason::Shutdown)
        );
        assert_eq!(*handle.rev_rx.borrow(), revision_before);
        assert_eq!(
            handle
                .pending_overlay
                .read()
                .await
                .local_pending_spent
                .len(),
            1
        );

        drop(db);
        fs::remove_dir_all(root_dir).expect("remove temp db dir");
    }

    #[tokio::test]
    async fn dequeued_pending_context_rejects_retirement_without_persistence() {
        let wallet_utxo = test_wallet_utxo(105, 7);
        let (root_dir, db, _cache_store, handle, cancel, _backfill_tx, _live_tx) =
            spawn_consumer_api_wallet(
                "wallet-private-context-retirement",
                vec![wallet_utxo.clone()],
            )
            .await;
        let cfg = wallet_config();
        let context = pending_output_context_intent_for_wallet_utxo(&wallet_utxo);
        let held = Arc::clone(&handle.authority_lock).lock_owned().await;
        let snapshot = handle
            .current_snapshot()
            .expect("current pending-context view");
        let (context_reply, context_result) = oneshot::channel();
        handle
            .private_request_tx
            .send(WalletPrivateRequest::CreatePendingOutputContexts {
                ticket: WalletPrivateViewTicket::Current {
                    reset_generation: snapshot.reset_generation,
                    last_scanned: snapshot.last_scanned,
                },
                contexts: vec![context],
                reply: context_reply,
            })
            .await
            .expect("queue pending-context request");
        wait_for_sender_capacity(&handle.private_request_tx, 8, "dequeued retirement context")
            .await;

        handle.retire_actor();
        drop(held);
        assert_eq!(
            context_result.await.expect("pending-context result"),
            Err(WalletPrivateRequestError::Inactive)
        );
        assert!(
            db.list_pending_output_poi_contexts(cfg.chain.chain_id, &cfg.cache_key)
                .expect("list pending contexts")
                .is_empty()
        );

        cancel.cancel();
        drop(db);
        fs::remove_dir_all(root_dir).expect("remove temp db dir");
    }

    #[tokio::test]
    async fn current_mailbox_requests_queued_behind_reset_are_rejected() {
        let wallet_utxo = test_wallet_utxo(105, 7);
        let (root_dir, db, _cache_store, handle, cancel, backfill_tx, _live_tx) =
            spawn_consumer_api_wallet("wallet-private-queued-reset", vec![wallet_utxo.clone()])
                .await;
        let cfg = wallet_config();
        let context = pending_output_context_intent_for_wallet_utxo(&wallet_utxo);
        let context_commitment = context.output_commitment;
        let held = Arc::clone(&handle.authority_lock).lock_owned().await;
        let (reset_response, reset_result) = oneshot::channel();
        backfill_tx
            .send(BackfillEvent::Reset {
                token: test_reset_token(1),
                from_block: 80,
                replay_plan: WalletResetReplayPlan::new(0, 0, true),
                response: reset_response,
            })
            .await
            .expect("queue reset");
        wait_for_sender_capacity(&backfill_tx, 8, "dequeued reset").await;

        let mark_handle = handle.clone();
        let mark_utxo = wallet_utxo.utxo.clone();
        let mark = tokio::spawn(async move {
            mark_handle
                .mark_pending_spent_utxos(std::slice::from_ref(&mark_utxo), None)
                .await
        });
        let context_handle = handle.clone();
        let create = tokio::spawn(async move {
            context_handle
                .create_pending_output_poi_contexts(vec![context])
                .await
        });
        wait_for_sender_capacity(&handle.private_request_tx, 6, "queued reset commands").await;

        drop(held);
        assert_eq!(
            reset_result
                .await
                .expect("reset response")
                .reset_generation(),
            Some(1)
        );
        assert!(matches!(
            mark.await.expect("pending-spend task"),
            Err(WalletPrivateRequestError::ResetPending | WalletPrivateRequestError::StaleView)
        ));
        assert!(matches!(
            create.await.expect("pending-context task"),
            Err(WalletPrivateRequestError::ResetPending | WalletPrivateRequestError::StaleView)
        ));
        assert!(
            db.get_pending_output_poi_context(
                cfg.chain.chain_id,
                &cfg.cache_key,
                &context_commitment,
            )
            .expect("read reset-fenced pending context")
            .is_none()
        );

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
            cache_key: WalletCacheKey::from_opaque_bytes(b"test")
                .expect("non-empty test wallet cache key"),
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
            wallet_id: cfg.cache_key.to_string(),
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

    fn pending_output_context_intent_for_wallet_utxo(
        wallet_utxo: &WalletUtxo,
    ) -> PendingOutputPoiContextIntent {
        PendingOutputPoiContextIntent {
            txid_version: DEFAULT_TXID_VERSION.to_string(),
            output_commitment: wallet_utxo.utxo.poi.commitment,
            output_npk: wallet_utxo.utxo.poi.npk,
            utxo_tree_in: u64::from(wallet_utxo.utxo.tree),
            railgun_txid: U256::from(7),
            pre_transaction_pois_per_txid_leaf_per_list: BTreeMap::new(),
            required_poi_list_keys: Vec::new(),
            output_role: PendingOutputPoiRole::Recipient,
        }
    }

    async fn assert_private_command_error(
        handle: &WalletHandle,
        wallet_utxo: &WalletUtxo,
        context: PendingOutputPoiContextIntent,
        expected: WalletPrivateRequestError,
    ) {
        assert_eq!(
            handle
                .mark_pending_spent_utxos(std::slice::from_ref(&wallet_utxo.utxo), None)
                .await,
            Err(expected)
        );
        assert_eq!(handle.clear_all_local_pending_spent().await, Err(expected));
        assert_eq!(
            handle
                .create_pending_output_poi_contexts(vec![context])
                .await,
            Err(expected)
        );
    }

    async fn assert_private_command_state_unchanged(handle: &WalletHandle, revision: u64) {
        assert_eq!(*handle.rev_rx.borrow(), revision);
        assert_eq!(
            handle
                .pending_overlay
                .read()
                .await
                .local_pending_spent
                .len(),
            1
        );
    }

    async fn spawn_consumer_api_wallet(
        name: &str,
        initial_utxos: Vec<WalletUtxo>,
    ) -> (
        std::path::PathBuf,
        Arc<DbStore>,
        Arc<FailingCacheStore>,
        WalletHandle,
        CancellationToken,
        mpsc::Sender<BackfillEvent>,
        broadcast::Sender<SharedLogBatch>,
    ) {
        let root_dir = temp_db_root(name);
        let db = Arc::new(
            DbStore::open(DbConfig {
                root_dir: root_dir.clone(),
            })
            .expect("open db"),
        );
        let cache_store = Arc::new(FailingCacheStore::new(Arc::clone(&db)));
        let mut cfg = wallet_config();
        cfg.cache_store = Some(cache_store.clone());
        cfg.sync_to_block = Some(100);
        cfg.use_indexed_wallet_catch_up = false;
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
                poi_runtime: test_wallet_poi_runtime(),
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
            initial_utxos,
            100,
        )
        .await
        .expect("spawn wallet worker");
        (
            root_dir,
            db,
            cache_store,
            handle,
            cancel,
            backfill_tx,
            live_tx,
        )
    }

    async fn wait_for_sender_capacity<T>(sender: &mpsc::Sender<T>, expected: usize, label: &str) {
        let reached = tokio::time::timeout(Duration::from_secs(1), async {
            while sender.capacity() != expected {
                tokio::task::yield_now().await;
            }
        })
        .await;
        assert!(
            reached.is_ok(),
            "{label}: expected sender capacity {expected}, got {}",
            sender.capacity()
        );
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
