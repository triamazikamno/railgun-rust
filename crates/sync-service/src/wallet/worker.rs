use super::*;

fn set_poi_refreshing(sender: &watch::Sender<bool>, value: bool, cache_key: &str) {
    if let Err(err) = sender.send(value) {
        debug!(?err, cache_key, "failed to send wallet POI refresh state");
    }
}

fn set_wallet_readiness(
    ready_tx: &watch::Sender<bool>,
    readiness_tx: &watch::Sender<WalletReadiness>,
    readiness: WalletReadiness,
    cache_key: &str,
) {
    if let Err(err) = readiness_tx.send(readiness.clone()) {
        debug!(?err, cache_key, "failed to send wallet readiness state");
    }
    if let Err(err) = ready_tx.send(readiness.is_ready()) {
        debug!(?err, cache_key, "failed to send ready state");
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
    public_data_epoch: &'a AtomicU64,
}

struct WalletScanCommitOutcome {
    result: WalletBackfillApplyResult,
    changed: bool,
}

struct WalletPoiStatusRefreshCommitRequest<'a> {
    db: &'a DbStore,
    cache_store: &'a dyn WalletCacheStore,
    cfg: &'a WalletConfig,
    utxos: &'a Arc<RwLock<Vec<WalletUtxo>>>,
    worker_handle: &'a WalletHandle,
    last_scanned: u64,
    reset_generation: u64,
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
}

struct WalletResetCommitRequest<'a> {
    db: &'a DbStore,
    cache_store: &'a dyn WalletCacheStore,
    cfg: &'a WalletConfig,
    utxos: &'a Arc<RwLock<Vec<WalletUtxo>>>,
    worker_handle: &'a WalletHandle,
    pending: PendingWalletReset,
    cancel: &'a CancellationToken,
    last_scanned: &'a mut u64,
    persist_state: &'a mut WalletPersistState,
    live_metadata_flush: &'a mut WalletLiveMetadataFlush,
    ready_tx: &'a watch::Sender<bool>,
    readiness_tx: &'a watch::Sender<WalletReadiness>,
}

struct WalletResetCommitOutcome {
    result: WalletBackfillResetResult,
    committed: bool,
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
        let authority = WalletPrivateMutationAuthority {
            handle: request.worker_handle,
            reset_generation: request.pending.reset_generation,
            cancel: request.cancel,
        };
        let authority_guard = match authority.acquire().await {
            Ok(guard) => guard,
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
        if let Err(err) = request.cache_store.commit_wallet_private_state(
            request.db,
            WalletPrivateCommit::new(
                &authority,
                request.cfg.chain.chain_id,
                &candidate,
                true,
                candidate_last_scanned,
                None,
                &[],
                &rewind.removed_output_commitments,
                &[],
            ),
        ) {
            warn!(
                ?err,
                cache_key = %request.cfg.cache_key,
                intent_id = request.pending.intent_id,
                from_block = request.pending.from_block,
                reset_generation = request.pending.reset_generation,
                "failed to persist wallet reset candidate"
            );
            set_wallet_readiness(
                request.ready_tx,
                request.readiness_tx,
                WalletReadiness::Failed(WalletReadinessError::PersistenceFailed),
                &request.cfg.cache_key,
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
            *locked = candidate;
        }
        *request.last_scanned = candidate_last_scanned;
        request
            .worker_handle
            .set_last_scanned(candidate_last_scanned);
        request.persist_state.needs_full_persist = false;
        request.persist_state.pending_cache_reset = None;
        request
            .live_metadata_flush
            .mark_persisted(candidate_last_scanned, Instant::now());
        request.worker_handle.notify_if_changed(rewind.changed);
        drop(authority_guard);
        set_wallet_readiness(
            request.ready_tx,
            request.readiness_tx,
            WalletReadiness::Syncing,
            &request.cfg.cache_key,
        );

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

        let authority = WalletPrivateMutationAuthority {
            handle: request.worker_handle,
            reset_generation: request.reset_generation,
            cancel: request.cancel,
        };
        let authority_guard = authority.acquire().await?;
        if request.cancel.is_cancelled() {
            return Err(WalletBackfillRejectReason::Shutdown);
        }

        let persist_started = Instant::now();
        if let Err(err) = request.persist_state.persist_progress(
            request.db,
            request.cache_store,
            &authority,
            WalletProgressPersist {
                cache_key: &request.cfg.cache_key,
                snapshot: &candidate,
                last_scanned: request.last_scanned,
                last_scanned_block_hash: None,
                changed: true,
            },
        ) {
            warn!(?err, cache_key = %request.cfg.cache_key, selection = selection_label, "failed to persist wallet POI status refresh candidate");
            set_wallet_readiness(
                request.ready_tx,
                request.readiness_tx,
                WalletReadiness::Failed(WalletReadinessError::PersistenceFailed),
                &request.cfg.cache_key,
            );
            return Err(WalletBackfillRejectReason::PersistenceFailed);
        }

        {
            let mut locked = request.utxos.write().await;
            *locked = candidate;
        }
        request.worker_handle.notify_changed();
        drop(authority_guard);
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
        if !request.apply.payload.covers(from_block, to_block) {
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
        let current_data_epoch = request.public_data_epoch.load(Ordering::Acquire);
        if request.apply.data_epoch.value != current_data_epoch {
            return WalletScanCommitOutcome {
                result: WalletBackfillApplyResult::Rejected {
                    committed_to: *request.last_scanned,
                    reason: WalletBackfillRejectReason::StaleDataPlaneEpoch {
                        expected: current_data_epoch,
                        actual: request.apply.data_epoch.value,
                    },
                },
                changed: false,
            };
        }

        let (delta, last_scanned_block_hash, log_count, source_label) = match request.apply.payload
        {
            WalletScanPayload::Logs(batch) => {
                let filtered_logs: Vec<_> = batch
                    .logs
                    .iter()
                    .filter(|log| {
                        log.block_number
                            .is_some_and(|block| block >= from_block && block <= to_block)
                    })
                    .cloned()
                    .collect();
                let delta = if filtered_logs.is_empty() {
                    WalletLogDelta {
                        utxos: Vec::new(),
                        nullifiers: Vec::new(),
                        commitment_observations: Vec::new(),
                    }
                } else {
                    match parse_wallet_delta_from_logs(
                        &filtered_logs,
                        &batch.block_timestamps,
                        &request.cfg.scan_keys,
                    ) {
                        Ok(delta) => delta,
                        Err(err) => {
                            warn!(?err, cache_key = %request.cfg.cache_key, from_block, to_block, "failed to parse wallet scan logs");
                            return WalletScanCommitOutcome {
                                result: WalletBackfillApplyResult::Rejected {
                                    committed_to: *request.last_scanned,
                                    reason: WalletBackfillRejectReason::ApplyFailed,
                                },
                                changed: false,
                            };
                        }
                    }
                };
                let last_scanned_block_hash = if batch.to_block == to_block {
                    batch.to_block_hash
                } else {
                    None
                };
                (delta, last_scanned_block_hash, filtered_logs.len(), "logs")
            }
            WalletScanPayload::IndexedRows { rows, source, .. } => {
                let delta = parse_indexed_wallet_delta(
                    &rows.transact_commitments,
                    &rows.shield_commitments,
                    &rows.legacy_encrypted_commitments,
                    &rows.legacy_generated_commitments,
                    &rows.nullifiers,
                    &request.cfg.scan_keys,
                );
                let log_count = rows.transact_commitments.len()
                    + rows.shield_commitments.len()
                    + rows.legacy_encrypted_commitments.len()
                    + rows.legacy_generated_commitments.len()
                    + rows.nullifiers.len();
                (delta, None, log_count, source.as_str())
            }
            #[cfg(test)]
            WalletScanPayload::IndexedDeltaForTest { delta, source, .. } => {
                (*delta, None, 0, source.as_str())
            }
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

        let authority = WalletPrivateMutationAuthority {
            handle: request.worker_handle,
            reset_generation: request.event_reset_generation,
            cancel: request.cancel,
        };
        let authority_guard = match authority.acquire().await {
            Ok(guard) => guard,
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
                set_wallet_readiness(
                    request.ready_tx,
                    request.readiness_tx,
                    WalletReadiness::Failed(WalletReadinessError::PersistenceFailed),
                    &request.cfg.cache_key,
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
        let persisted_full_snapshot = match request
            .persist_state
            .persist_progress_with_private_effects(
                request.db,
                request.cache_store,
                &authority,
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
                set_wallet_readiness(
                    request.ready_tx,
                    request.readiness_tx,
                    WalletReadiness::Failed(WalletReadinessError::PersistenceFailed),
                    &request.cfg.cache_key,
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

        {
            let mut locked = request.utxos.write().await;
            *locked = candidate;
        }
        *request.last_scanned = to_block;
        request.worker_handle.set_last_scanned(to_block);
        request
            .live_metadata_flush
            .mark_persisted(to_block, Instant::now());
        request.worker_handle.notify_if_changed(changed);
        drop(authority_guard);
        if request.mark_syncing_on_commit {
            set_wallet_readiness(
                request.ready_tx,
                request.readiness_tx,
                WalletReadiness::Syncing,
                &request.cfg.cache_key,
            );
        }

        if commitment_observation_count > 0 {
            let authority = WalletPrivateMutationAuthority {
                handle: request.worker_handle,
                reset_generation: request.event_reset_generation,
                cancel: request.cancel,
            };
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

pub(crate) fn spawn_wallet_worker(
    services: WalletWorkerServices,
    cfg: WalletConfig,
    actor_id: u64,
    mut live_rx: broadcast::Receiver<SharedLogBatch>,
    mut backfill_rx: mpsc::Receiver<BackfillEvent>,
    cancel: CancellationToken,
    initial_utxos: Vec<WalletUtxo>,
    initial_last_scanned: u64,
) -> WalletHandle {
    let utxos = Arc::new(RwLock::new(initial_utxos));
    let pending_overlay = Arc::new(RwLock::new(WalletPendingOverlay::default()));
    let last_scanned_state = Arc::new(AtomicU64::new(initial_last_scanned));
    let reset_generation_state = Arc::new(AtomicU64::new(0));
    let active_actor_id = Arc::new(AtomicU64::new(actor_id));
    let authority_lock = Arc::new(Mutex::new(()));
    let indexed_catch_up_active = Arc::new(AtomicBool::new(false));
    let WalletWorkerServices {
        db,
        rpcs,
        http_client,
        indexed_artifact_source,
        forest,
        backfill_tx,
        backfill_sender,
        public_data_epoch,
    } = services;
    let cache_store = wallet_cache_store(&db, &cfg);
    let (ready_tx, ready_rx) = watch::channel(false);
    let (readiness_tx, readiness_rx) = watch::channel(WalletReadiness::Syncing);
    let (rev_tx, rev_rx) = watch::channel(0_u64);
    let (poi_refresh_tx, mut poi_refresh_rx) = mpsc::channel(1);
    let (pending_overlay_tx, mut pending_overlay_rx) = mpsc::channel(8);
    let (poi_refreshing_tx, poi_refreshing_rx) = watch::channel(false);
    let (indexed_catch_up_tx, indexed_catch_up_rx) = watch::channel(None);
    let handle = WalletHandle {
        cache_key: cfg.cache_key.clone(),
        actor_id,
        active_actor_id,
        authority_lock,
        utxos: utxos.clone(),
        pending_overlay,
        last_scanned: last_scanned_state,
        reset_generation: reset_generation_state,
        ready_rx,
        readiness_rx,
        rev_rx,
        poi_refreshing_rx,
        indexed_catch_up_rx,
        indexed_catch_up_active,
        poi_read_source: cfg.poi_read_source.clone(),
        local_poi_caches: cfg.local_poi_caches.clone(),
        pending_overlay_tx,
        poi_refresh_tx,
        rev_tx,
        indexed_catch_up_tx,
    };

    let chain_id = cfg.chain.chain_id;
    let worker_handle = handle.clone();
    tokio::spawn(async move {
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
        let mut reset_generation = 0_u64;
        let mut highest_accepted_reset_intent = 0_u64;
        let mut pending_reset: Option<PendingWalletReset> = None;
        macro_rules! try_commit_pending_reset {
            () => {{
                if let Some(pending) = pending_reset {
                    let outcome = WalletResetCommitRequest {
                        db: db.as_ref(),
                        cache_store: cache_store.as_ref(),
                        cfg: &cfg,
                        utxos: &utxos,
                        worker_handle: &worker_handle,
                        pending,
                        cancel: &cancel,
                        last_scanned: &mut last_scanned,
                        persist_state: &mut persist_state,
                        live_metadata_flush: &mut live_metadata_flush,
                        ready_tx: &ready_tx,
                        readiness_tx: &readiness_tx,
                    }
                    .commit()
                    .await;
                    if outcome.committed {
                        pending_reset = None;
                        readiness_started = Instant::now();
                        backfill_complete_block = None;
                        live_rx = live_rx.resubscribe();
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
                let should_persist = persist_state.needs_full_persist
                    || persist_state.pending_cache_reset.is_some();
                let authority = WalletPrivateMutationAuthority {
                    handle: &worker_handle,
                    reset_generation,
                    cancel: &cancel,
                };
                let snapshot = utxos.read().await;
                let persist_ok = if should_persist {
                    match authority.acquire().await {
                        Ok(authority_guard) => {
                            let persisted = match persist_state.persist_progress(
                                db.as_ref(),
                                cache_store.as_ref(),
                                &authority,
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
                                    true
                                }
                                Err(err) => {
                                    warn!(?err, cache_key = %cfg.cache_key, "failed to update wallet cache metadata");
                                    set_wallet_readiness(
                                        &ready_tx,
                                        &readiness_tx,
                                        WalletReadiness::Failed(WalletReadinessError::PersistenceFailed),
                                        &cfg.cache_key,
                                    );
                                    false
                                }
                            };
                            drop(authority_guard);
                            persisted
                        }
                        Err(reason) => {
                            warn!(?reason, cache_key = %cfg.cache_key, "wallet target metadata persist rejected");
                            set_wallet_readiness(
                                &ready_tx,
                                &readiness_tx,
                                WalletReadiness::Failed(WalletReadinessError::PersistenceFailed),
                                &cfg.cache_key,
                            );
                            false
                        }
                    }
                } else {
                    true
                };
                drop(snapshot);
                if !persist_ok {
                    false
                } else {
                let mut pre_ready_poi_status_changed = false;
                let mut pre_ready_poi_status_persist_failed = false;
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
                                db: db.as_ref(),
                                cache_store: cache_store.as_ref(),
                                cfg: &cfg,
                                utxos: &utxos,
                                worker_handle: &worker_handle,
                                last_scanned,
                                reset_generation,
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
                                    pre_ready_poi_status_persist_failed = true;
                                    warn!(?reason, cache_key = %cfg.cache_key, "pre-ready wallet POI status refresh rejected");
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
                if pre_ready_poi_status_persist_failed {
                    false
                } else {
                let snapshot = utxos.read().await;
                let (unspent, spent) = wallet_utxo_counts(&snapshot);
                backfill_complete_block = Some(last_block);
                set_wallet_readiness(&ready_tx, &readiness_tx, WalletReadiness::Ready, &cfg.cache_key);
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
                    let authority = WalletPrivateMutationAuthority {
                        handle: &worker_handle,
                        reset_generation,
                        cancel: &cancel,
                    };
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
                        set_poi_refreshing(&poi_refreshing_tx, true, &cfg.cache_key);
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
                            set_poi_refreshing(&poi_refreshing_tx, false, &cfg.cache_key);
                        } else {
                            let status_refresh_started = Instant::now();
                            let status_reader = wallet_poi_status_reader_source(client, &cfg);
                            let changed = match (WalletPoiStatusRefreshCommitRequest {
                                db: db.as_ref(),
                                cache_store: cache_store.as_ref(),
                                cfg: &cfg,
                                utxos: &utxos,
                                worker_handle: &worker_handle,
                                last_scanned,
                                reset_generation,
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
                            set_poi_refreshing(&poi_refreshing_tx, false, &cfg.cache_key);
                            let output_recovery_started = Instant::now();
                            let recovered = recover_missing_output_pois_from_wallet(OutputPoiRecoveryRun {
                                worker_handle: &worker_handle,
                                reset_generation,
                                cancel: &cancel,
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
                            let output_recovery_elapsed_ms =
                                output_recovery_started.elapsed().as_millis();
                            worker_handle.notify_if_changed(recovered > 0);
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
                true
                }
                }
            }};
        }
        loop {
            tokio::select! {
                _ = cancel.cancelled() => break,
                Some(refresh_request) = poi_refresh_rx.recv() => {
                    let Some(client) = poi_status_client.as_ref() else {
                        continue;
                    };
                    if pending_reset.is_some() {
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
                    set_poi_refreshing(&poi_refreshing_tx, true, &cfg.cache_key);
                    if !local_poi_caches_ready_for_refresh(
                        &mut startup_artifact_warmup,
                        &cfg,
                        &active_poi_list_keys,
                        "manual_poi_refresh",
                    ).await {
                        log_local_poi_cache_unavailable(&cfg, "manual_poi_refresh");
                        set_poi_refreshing(&poi_refreshing_tx, false, &cfg.cache_key);
                        continue;
                    }
                    let status_reader = wallet_poi_status_reader_source(client, &cfg);
                    let changed = match (WalletPoiStatusRefreshCommitRequest {
                        db: db.as_ref(),
                        cache_store: cache_store.as_ref(),
                        cfg: &cfg,
                        utxos: &utxos,
                        worker_handle: &worker_handle,
                        last_scanned,
                        reset_generation,
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
                            set_poi_refreshing(&poi_refreshing_tx, false, &cfg.cache_key);
                            continue;
                        }
                    };
                    let authority = WalletPrivateMutationAuthority {
                        handle: &worker_handle,
                        reset_generation,
                        cancel: &cancel,
                    };
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
                    set_poi_refreshing(&poi_refreshing_tx, false, &cfg.cache_key);
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
                        worker_handle: &worker_handle,
                        reset_generation,
                        cancel: &cancel,
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
                    worker_handle.notify_if_changed(recovered > 0);
                }
                Some(request) = pending_overlay_rx.recv() => {
                    if pending_reset.is_some()
                        || request.reset_generation != reset_generation
                        || request.last_scanned != last_scanned
                    {
                        debug!(
                            cache_key = %cfg.cache_key,
                            request_reset_generation = request.reset_generation,
                            current_reset_generation = reset_generation,
                            request_last_scanned = request.last_scanned,
                            current_last_scanned = last_scanned,
                            pending_reset = pending_reset.is_some(),
                            "ignoring stale pending overlay update"
                        );
                        continue;
                    }
                    let authority_guard = match worker_handle.actor_authority(reset_generation).await {
                        Ok(guard) => guard,
                        Err(reason) => {
                            debug!(?reason, cache_key = %cfg.cache_key, "pending overlay update rejected");
                            continue;
                        }
                    };
                    if cancel.is_cancelled() {
                        continue;
                    }
                    worker_handle.set_chain_pending_overlay(request.overlay).await;
                    drop(authority_guard);
                }
                _ = tokio::time::sleep(WALLET_POI_REFRESH_INTERVAL), if poi_status_client.is_some() && backfill_complete_block.is_some() && pending_reset.is_none() => {
                    let Some(client) = poi_status_client.as_ref() else {
                        continue;
                    };
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
                        let authority = WalletPrivateMutationAuthority {
                            handle: &worker_handle,
                            reset_generation,
                            cancel: &cancel,
                        };
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
                    set_poi_refreshing(&poi_refreshing_tx, true, &cfg.cache_key);
                    if !local_poi_caches_ready_for_refresh(
                        &mut startup_artifact_warmup,
                        &cfg,
                        &active_poi_list_keys,
                        "periodic_poi_refresh",
                    ).await {
                        log_local_poi_cache_unavailable(&cfg, "periodic_poi_refresh");
                        set_poi_refreshing(&poi_refreshing_tx, false, &cfg.cache_key);
                        continue;
                    }
                    let status_reader = wallet_poi_status_reader_source(client, &cfg);
                    let changed = match (WalletPoiStatusRefreshCommitRequest {
                        db: db.as_ref(),
                        cache_store: cache_store.as_ref(),
                        cfg: &cfg,
                        utxos: &utxos,
                        worker_handle: &worker_handle,
                        last_scanned,
                        reset_generation,
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
                            set_poi_refreshing(&poi_refreshing_tx, false, &cfg.cache_key);
                            continue;
                        }
                    };
                    let authority = WalletPrivateMutationAuthority {
                        handle: &worker_handle,
                        reset_generation,
                        cancel: &cancel,
                    };
                    let pending_verification = verify_submitted_pending_output_pois_with_config_authorized(
                        &authority,
                        client,
                        &cfg,
                        db.as_ref(),
                        cache_store.as_ref(),
                        &active_poi_list_keys,
                    ).await;
                    set_poi_refreshing(&poi_refreshing_tx, false, &cfg.cache_key);
                    recover_missing_output_pois_from_wallet(OutputPoiRecoveryRun {
                        worker_handle: &worker_handle,
                        reset_generation,
                        cancel: &cancel,
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
                        BackfillEvent::Apply { apply, reset_generation: event_reset_generation, response } => {
                            if let Some(outcome) = try_commit_pending_reset!()
                                && !outcome.committed
                            {
                                let reason = match outcome.result {
                                    WalletBackfillResetResult::Rejected { reason, .. } => reason,
                                    WalletBackfillResetResult::Accepted { .. } => WalletBackfillRejectReason::PersistenceFailed,
                                };
                                let result = WalletBackfillApplyResult::Rejected {
                                    committed_to: last_scanned,
                                    reason,
                                };
                                if let Err(err) = response.send(result) {
                                    debug!(?err, cache_key = %cfg.cache_key, "failed to send pending-reset wallet scan apply result");
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
                                current_reset_generation: reset_generation,
                                event_reset_generation,
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
                                public_data_epoch: public_data_epoch.as_ref(),
                            }
                            .commit()
                            .await;
                            if let Err(err) = response.send(outcome.result) {
                                debug!(?err, cache_key = %cfg.cache_key, "failed to send wallet scan apply result");
                            }
                        }
                        BackfillEvent::Target { target_block, reset_generation: event_reset_generation, response } => {
                            if let Some(outcome) = try_commit_pending_reset!()
                                && !outcome.committed
                            {
                                let reason = match outcome.result {
                                    WalletBackfillResetResult::Rejected { reason, .. } => reason,
                                    WalletBackfillResetResult::Accepted { .. } => WalletBackfillRejectReason::PersistenceFailed,
                                };
                                let result = WalletBackfillFinishResult::Rejected {
                                    committed_to: last_scanned,
                                    reason,
                                };
                                if let Err(err) = response.send(result) {
                                    debug!(?err, cache_key = %cfg.cache_key, "failed to send pending-reset wallet target result");
                                }
                                continue;
                            }
                            if event_reset_generation != reset_generation {
                                let result = WalletBackfillFinishResult::Rejected {
                                    committed_to: last_scanned,
                                    reason: WalletBackfillRejectReason::StaleGeneration {
                                        expected: reset_generation,
                                        actual: event_reset_generation,
                                    },
                                };
                                if let Err(err) = response.send(result) {
                                    debug!(?err, cache_key = %cfg.cache_key, "failed to send stale wallet target result");
                                }
                                continue;
                            }
                            if target_block > last_scanned {
                                debug!(
                                    cache_key = %cfg.cache_key,
                                    target_block,
                                    last_scanned,
                                    reset_generation,
                                    "wallet target recorded; cursor has not reached target"
                                );
                                backfill_complete_block = None;
                                set_wallet_readiness(&ready_tx, &readiness_tx, WalletReadiness::Syncing, &cfg.cache_key);
                                let result = WalletBackfillFinishResult::Rejected {
                                    committed_to: last_scanned,
                                    reason: WalletBackfillRejectReason::TargetNotReached { target_block },
                                };
                                if let Err(err) = response.send(result) {
                                    debug!(?err, cache_key = %cfg.cache_key, "failed to send pending wallet target result");
                                }
                                continue;
                            }
                            let finish_ready = apply_backfill_done!(target_block);
                            let result = if finish_ready && matches!(*readiness_tx.borrow(), WalletReadiness::Ready) {
                                WalletBackfillFinishResult::Ready { committed_to: last_scanned }
                            } else {
                                WalletBackfillFinishResult::Rejected {
                                    committed_to: last_scanned,
                                    reason: WalletBackfillRejectReason::PersistenceFailed,
                                }
                            };
                            if let Err(err) = response.send(result) {
                                debug!(?err, cache_key = %cfg.cache_key, "failed to send wallet target result");
                            }
                        }
                        BackfillEvent::Reset { intent_id, from_block, response } => {
                            if cancel.is_cancelled() || !worker_handle.is_current_actor() {
                                let result = WalletBackfillResetResult::Rejected {
                                    committed_to: last_scanned,
                                    reason: WalletBackfillRejectReason::Shutdown,
                                };
                                if let Err(err) = response.send(result) {
                                    debug!(?err, cache_key = %cfg.cache_key, "failed to send shutdown wallet reset result");
                                }
                                continue;
                            }

                            if intent_id <= highest_accepted_reset_intent {
                                let result = WalletBackfillResetResult::Rejected {
                                    committed_to: last_scanned,
                                    reason: WalletBackfillRejectReason::StaleResetIntent {
                                        accepted: highest_accepted_reset_intent,
                                        actual: intent_id,
                                    },
                                };
                                if let Err(err) = response.send(result) {
                                    debug!(?err, cache_key = %cfg.cache_key, "failed to send stale wallet reset result");
                                }
                                continue;
                            }
                            highest_accepted_reset_intent = intent_id;

                            let reset_from_block = pending_reset
                                .map_or(from_block, |pending| pending.from_block.min(from_block));
                            reset_generation = reset_generation.wrapping_add(1);
                            worker_handle.set_reset_generation(reset_generation);
                            pending_reset = Some(PendingWalletReset {
                                intent_id,
                                from_block: reset_from_block,
                                reset_generation,
                            });
                            let outcome = try_commit_pending_reset!()
                                .expect("pending reset was installed before commit");
                            if let Err(err) = response.send(outcome.result) {
                                debug!(?err, cache_key = %cfg.cache_key, "failed to send wallet reset result");
                            }
                        }
                    }
                }
                result = live_rx.recv(), if backfill_complete_block.is_some() && pending_reset.is_none() => {
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
                                match backfill_tx
                                    .send(crate::types::BackfillRequest::Add {
                                        cache_key: cfg.cache_key.clone(),
                                        from_block: expected_from_block,
                                        to_block: batch.to_block,
                                        follow_safe_head: true,
                                        progress_start_block: expected_from_block,
                                        reset_generation,
                                        progress_tx: cfg.progress_tx.clone(),
                                        sender: backfill_sender.clone(),
                                    })
                                    .await
                                {
                                    Ok(()) => {
                                        backfill_complete_block = None;
                                        live_rx = live_rx.resubscribe();
                                        set_wallet_readiness(&ready_tx, &readiness_tx, WalletReadiness::Syncing, &cfg.cache_key);
                                    }
                                    Err(err) => {
                                        warn!(?err, cache_key = %cfg.cache_key, "failed to request wallet live gap backfill");
                                    }
                                }
                                live_receiver_lagged = false;
                                continue;
                            }
                            live_receiver_lagged = false;
                            let poi_submitter = poi_status_client
                                .as_ref()
                                .map(|client| client as &dyn PendingOutputPoiSubmitter);
                            let poi_status_reader = poi_status_client
                                .as_ref()
                                .map(|client| wallet_poi_status_reader_source(client, &cfg));
                            let outcome = WalletScanCommitRequest {
                                db: db.as_ref(),
                                cache_store: cache_store.as_ref(),
                                cfg: &cfg,
                                utxos: &utxos,
                                worker_handle: &worker_handle,
                                apply: WalletScanApply::logs(
                                    expected_from_block,
                                    batch.to_block,
                                    batch,
                                    PublicDataPlaneEpoch::new(public_data_epoch.load(Ordering::Acquire)),
                                ),
                                current_reset_generation: reset_generation,
                                event_reset_generation: reset_generation,
                                cancel: &cancel,
                                last_scanned: &mut last_scanned,
                                persist_state: &mut persist_state,
                                live_metadata_flush: &mut live_metadata_flush,
                                ready_tx: &ready_tx,
                                readiness_tx: &readiness_tx,
                                poi_submitter,
                                poi_status_reader: poi_status_reader.as_ref().map(WalletPoiStatusReaderSource::as_reader),
                                active_poi_list_keys: &active_poi_list_keys,
                                refresh_poi_statuses: true,
                                mark_syncing_on_commit: false,
                                public_data_epoch: public_data_epoch.as_ref(),
                            }
                            .commit()
                            .await;
                            match outcome.result {
                                WalletBackfillApplyResult::Committed { .. }
                                | WalletBackfillApplyResult::AlreadyCovered { .. } => {
                                    if outcome.changed && let Some(client) = poi_status_client.as_ref() {
                                        let authority = WalletPrivateMutationAuthority {
                                            handle: &worker_handle,
                                            reset_generation,
                                            cancel: &cancel,
                                        };
                                        verify_submitted_pending_output_pois_with_config_authorized(
                                            &authority,
                                            client,
                                            &cfg,
                                            db.as_ref(),
                                            cache_store.as_ref(),
                                            &active_poi_list_keys,
                                        ).await;
                                        recover_missing_output_pois_from_wallet(OutputPoiRecoveryRun {
                                            worker_handle: &worker_handle,
                                            reset_generation,
                                            cancel: &cancel,
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
        set_wallet_readiness(&ready_tx, &readiness_tx, WalletReadiness::Shutdown, &cfg.cache_key);
    }.instrument(tracing::info_span!("wallet", chain_id)));

    handle
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

    use crate::types::{
        BackfillRequest, ChainKey, LogBatch, PoiArtifactManifestSource, PoiArtifactSourceConfig,
        PoiReadSource, WalletConfig, WalletIndexedCatchUpSource, WalletIndexedCatchUpStatus,
    };

    #[derive(Debug, Clone, Copy, Default)]
    struct FailingCacheStoreState {
        store_calls: usize,
        meta_calls: usize,
        fail_next_store: bool,
        fail_next_meta: bool,
    }

    #[derive(Default)]
    struct FailingCacheStore {
        state: Mutex<FailingCacheStoreState>,
    }

    impl FailingCacheStore {
        fn fail_next_store(&self) {
            self.state.lock().expect("cache state").fail_next_store = true;
        }

        fn fail_next_meta(&self) {
            self.state.lock().expect("cache state").fail_next_meta = true;
        }

        fn state(&self) -> FailingCacheStoreState {
            *self.state.lock().expect("cache state")
        }
    }

    impl WalletCacheStore for FailingCacheStore {
        fn commit_wallet_private_state(
            &self,
            db: &DbStore,
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
                db.put_pending_output_poi_context(record)?;
            }
            for output_commitment in commit.pending_output_context_deletes() {
                db.delete_pending_output_poi_context(
                    commit.pending_output_context_chain_id(),
                    commit.wallet_id(),
                    output_commitment,
                )?;
            }
            for record in commit.output_poi_recovery_updates() {
                db.put_output_poi_recovery(record)?;
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
        sender: &mpsc::Sender<BackfillEvent>,
        apply: WalletScanApply,
        reset_generation: u64,
    ) -> WalletBackfillApplyResult {
        let (response, result_rx) = oneshot::channel();
        sender
            .send(BackfillEvent::Apply {
                apply,
                reset_generation,
                response,
            })
            .await
            .expect("send apply");
        result_rx.await.expect("apply response")
    }

    async fn send_target(
        sender: &mpsc::Sender<BackfillEvent>,
        target_block: u64,
        reset_generation: u64,
    ) -> WalletBackfillFinishResult {
        let (response, result_rx) = oneshot::channel();
        sender
            .send(BackfillEvent::Target {
                target_block,
                reset_generation,
                response,
            })
            .await
            .expect("send target");
        result_rx.await.expect("target response")
    }

    async fn send_reset(
        sender: &mpsc::Sender<BackfillEvent>,
        intent_id: u64,
        from_block: u64,
    ) -> WalletBackfillResetResult {
        let (response, result_rx) = oneshot::channel();
        sender
            .send(BackfillEvent::Reset {
                intent_id,
                from_block,
                response,
            })
            .await
            .expect("send reset");
        result_rx.await.expect("reset response")
    }

    fn logs_apply(from_block: u64, to_block: u64) -> WalletScanApply {
        WalletScanApply::logs(
            from_block,
            to_block,
            logs_payload(from_block, to_block),
            PublicDataPlaneEpoch::new(0),
        )
    }

    fn logs_payload(from_block: u64, to_block: u64) -> Arc<LogBatch> {
        Arc::new(LogBatch {
            from_block,
            to_block,
            logs: Vec::new(),
            block_timestamps: HashMap::new(),
            to_block_hash: None,
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
            PublicDataPlaneEpoch::new(0),
            WalletIndexedCatchUpSource::IndexedArtifacts,
        )
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
                public_data_epoch: Arc::new(AtomicU64::new(0)),
            },
            wallet_config(),
            1,
            live_rx,
            backfill_rx,
            cancel.clone(),
            Vec::new(),
            100,
        );
        live_tx
            .send(Arc::new(LogBatch {
                from_block: 101,
                to_block: 101,
                logs: Vec::new(),
                block_timestamps: HashMap::new(),
                to_block_hash: None,
            }))
            .expect("live receiver");
        tokio::task::yield_now().await;
        assert_eq!(handle.last_scanned(), 100);

        assert_eq!(
            send_target(&backfill_tx, 100, 0).await,
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
        let cache_store = Arc::new(FailingCacheStore::default());
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
                public_data_epoch: Arc::new(AtomicU64::new(0)),
            },
            cfg,
            1,
            live_rx,
            backfill_rx,
            cancel.clone(),
            Vec::new(),
            100,
        );

        assert_eq!(
            send_target(&backfill_tx, 100, 0).await,
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
                public_data_epoch: Arc::new(AtomicU64::new(0)),
            },
            wallet_config(),
            1,
            live_rx,
            backfill_rx,
            cancel.clone(),
            Vec::new(),
            900,
        );

        assert_eq!(
            send_target(&backfill_tx, 900, 0).await,
            WalletBackfillFinishResult::Ready { committed_to: 900 }
        );
        assert_eq!(handle.readiness(), WalletReadiness::Ready);
        assert_eq!(
            send_apply(
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
        assert_eq!(
            send_target(&backfill_tx, 1000, 0).await,
            WalletBackfillFinishResult::Rejected {
                committed_to: 950,
                reason: WalletBackfillRejectReason::TargetNotReached { target_block: 1000 },
            }
        );
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
                public_data_epoch: Arc::new(AtomicU64::new(0)),
            },
            wallet_config(),
            1,
            live_rx,
            backfill_rx,
            cancel.clone(),
            Vec::new(),
            100,
        );
        let wallet_utxo = test_wallet_utxo(105, 7);
        let nullifier = wallet_utxo.utxo.nullifier(U256::ZERO);

        assert_eq!(
            send_apply(
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
        let cache_store = Arc::new(FailingCacheStore::default());
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
                public_data_epoch: Arc::new(AtomicU64::new(0)),
            },
            cfg,
            1,
            live_rx,
            backfill_rx,
            cancel.clone(),
            Vec::new(),
            100,
        );

        assert_eq!(
            send_apply(
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
        let cache_store = Arc::new(FailingCacheStore::default());
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
                public_data_epoch: Arc::new(AtomicU64::new(0)),
            },
            cfg.clone(),
            1,
            live_rx,
            backfill_rx,
            cancel.clone(),
            vec![wallet_utxo.clone()],
            100,
        );

        assert_eq!(
            send_apply(
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
                public_data_epoch: Arc::new(AtomicU64::new(0)),
            },
            cfg.clone(),
            1,
            live_rx,
            backfill_rx,
            cancel.clone(),
            vec![wallet_utxo.clone()],
            100,
        );

        assert_eq!(
            send_apply(
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
                backfill_sender: backfill_tx,
                public_data_epoch: Arc::new(AtomicU64::new(0)),
            },
            wallet_config(),
            1,
            live_rx,
            backfill_rx,
            cancel.clone(),
            vec![wallet_utxo.clone()],
            100,
        );
        let pending_spent = WalletPendingSpent {
            tree: wallet_utxo.utxo.tree,
            position: wallet_utxo.utxo.position,
            tx_hash: Some(FixedBytes::from([0xaa; 32])),
            block_number: Some(101),
            block_timestamp: Some(1_700_000_101),
        };

        assert!(
            handle
                .request_pending_overlay_update(
                    WalletPendingOverlay {
                        pending_spent: vec![pending_spent.clone()],
                        ..WalletPendingOverlay::default()
                    },
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
    async fn wallet_reset_rejects_persistence_failure_without_publishing_rewind() {
        let root_dir = temp_db_root("wallet-reset-persist-failure");
        let db = Arc::new(
            DbStore::open(DbConfig {
                root_dir: root_dir.clone(),
            })
            .expect("open db"),
        );
        let cache_store = Arc::new(FailingCacheStore::default());
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
                public_data_epoch: Arc::new(AtomicU64::new(0)),
            },
            cfg,
            1,
            live_rx,
            backfill_rx,
            cancel.clone(),
            vec![initial_utxo],
            120,
        );

        assert_eq!(
            send_target(&backfill_tx, 120, 0).await,
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
        assert_eq!(
            handle.readiness(),
            WalletReadiness::Failed(WalletReadinessError::PersistenceFailed)
        );
        assert!(!*handle.ready_rx.borrow());
        assert_eq!(*handle.rev_rx.borrow(), rev_before_reset);
        let snapshot = handle.utxos.read().await;
        assert_eq!(snapshot.len(), 1);
        assert_eq!(snapshot[0].utxo.source.block_number, 105);
        assert_eq!(
            cache_store.state().store_calls,
            store_calls_before_reset + 1
        );

        cancel.cancel();
        drop(snapshot);
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
        let cache_store = Arc::new(FailingCacheStore::default());
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
                public_data_epoch: Arc::new(AtomicU64::new(0)),
            },
            cfg.clone(),
            1,
            live_rx,
            backfill_rx,
            cancel.clone(),
            vec![initial_utxo],
            120,
        );

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
    async fn wallet_reset_rejects_retired_actor_without_side_effects() {
        let root_dir = temp_db_root("wallet-reset-retired-actor");
        let db = Arc::new(
            DbStore::open(DbConfig {
                root_dir: root_dir.clone(),
            })
            .expect("open db"),
        );
        let cache_store = Arc::new(FailingCacheStore::default());
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
                public_data_epoch: Arc::new(AtomicU64::new(0)),
            },
            cfg,
            1,
            live_rx,
            backfill_rx,
            cancel.clone(),
            vec![initial_utxo],
            120,
        );

        assert_eq!(
            send_target(&backfill_tx, 120, 0).await,
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
        let cache_store = Arc::new(FailingCacheStore::default());
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
                public_data_epoch: Arc::new(AtomicU64::new(0)),
            },
            cfg.clone(),
            1,
            live_rx,
            backfill_rx,
            cancel.clone(),
            vec![test_wallet_utxo(105, 7)],
            100,
        );
        let (ready_tx, ready_rx) = watch::channel(true);
        let (readiness_tx, readiness_rx) = watch::channel(WalletReadiness::Syncing);
        let remote_client = PoiRpcClient::new(cfg.poi_rpc_url.clone());
        let status_reader = wallet_poi_status_reader_source(&remote_client, &cfg);
        let mut persist_state = WalletPersistState::default();
        let active_poi_list_keys = default_active_poi_list_keys();

        let result = WalletPoiStatusRefreshCommitRequest {
            db: db.as_ref(),
            cache_store: cache_store.as_ref(),
            cfg: &cfg,
            utxos: &handle.utxos,
            worker_handle: &handle,
            last_scanned: 100,
            reset_generation: 0,
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
        let cache_store = Arc::new(FailingCacheStore::default());
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
                public_data_epoch: Arc::new(AtomicU64::new(0)),
            },
            cfg.clone(),
            1,
            live_rx,
            backfill_rx,
            cancel.clone(),
            vec![initial_utxo],
            100,
        );
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
            let mut persist_state = WalletPersistState::default();
            WalletPoiStatusRefreshCommitRequest {
                db: commit_db.as_ref(),
                cache_store: commit_cache_store.as_ref(),
                cfg: &commit_cfg,
                utxos: &commit_handle.utxos,
                worker_handle: &commit_handle,
                last_scanned: 100,
                reset_generation: 0,
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
        let cache_store = Arc::new(FailingCacheStore::default());
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
                public_data_epoch: Arc::new(AtomicU64::new(0)),
            },
            cfg.clone(),
            1,
            live_rx,
            backfill_rx,
            cancel.clone(),
            Vec::new(),
            100,
        );
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
            let mut last_scanned = 100;
            let mut persist_state = WalletPersistState::default();
            let mut live_metadata_flush = WalletLiveMetadataFlush::new(100, Instant::now());
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
                public_data_epoch: commit_handle.reset_generation.as_ref(),
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
                public_data_epoch: Arc::new(AtomicU64::new(0)),
            },
            wallet_config(),
            1,
            live_rx,
            backfill_rx,
            cancel.clone(),
            Vec::new(),
            100,
        );

        assert_eq!(
            send_apply(
                &backfill_tx,
                indexed_delta_batch(101, 200, empty_delta()),
                0
            )
            .await,
            WalletBackfillApplyResult::Committed { committed_to: 200 }
        );
        assert_eq!(
            send_target(&backfill_tx, 200, 0).await,
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
                public_data_epoch: Arc::new(AtomicU64::new(0)),
            },
            wallet_config(),
            1,
            live_rx,
            backfill_rx,
            cancel.clone(),
            Vec::new(),
            100,
        );

        assert_eq!(
            send_apply(&backfill_tx, logs_apply(105, 110), 0).await,
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
                public_data_epoch: Arc::new(AtomicU64::new(0)),
            },
            cfg,
            1,
            live_rx,
            backfill_rx,
            cancel.clone(),
            Vec::new(),
            119,
        );

        assert_eq!(
            send_apply(
                &backfill_tx,
                WalletScanApply::logs(
                    120,
                    130,
                    logs_payload(100, 199),
                    PublicDataPlaneEpoch::new(0),
                ),
                0,
            )
            .await,
            WalletBackfillApplyResult::Committed { committed_to: 130 }
        );
        assert_eq!(handle.last_scanned(), 130);
        assert_eq!(
            send_apply(
                &backfill_tx,
                WalletScanApply::logs(
                    131,
                    199,
                    logs_payload(100, 199),
                    PublicDataPlaneEpoch::new(0),
                ),
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
                backfill_sender: backfill_tx,
                public_data_epoch: Arc::new(AtomicU64::new(0)),
            },
            wallet_config(),
            1,
            live_rx,
            backfill_rx,
            cancel.clone(),
            Vec::new(),
            100,
        );

        assert!(handle.try_claim_indexed_catch_up());
        assert!(!handle.try_claim_indexed_catch_up());
        handle.set_indexed_catch_up(WalletIndexedCatchUpStatus {
            source: WalletIndexedCatchUpSource::IndexedArtifacts,
            from_block: 101,
            target_block: 200,
        });
        assert!(handle.indexed_catch_up_rx.borrow().is_some());
        handle.clear_indexed_catch_up();
        assert!(handle.indexed_catch_up_rx.borrow().is_none());
        assert!(handle.try_claim_indexed_catch_up());
        handle.clear_indexed_catch_up();

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
                public_data_epoch: Arc::new(AtomicU64::new(0)),
            },
            wallet_config(),
            1,
            live_rx,
            backfill_rx,
            cancel.clone(),
            Vec::new(),
            150,
        );

        assert_eq!(
            send_apply(
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
        assert_eq!(
            send_target(&backfill_tx, 200, 0).await,
            WalletBackfillFinishResult::Rejected {
                committed_to: 150,
                reason: WalletBackfillRejectReason::TargetNotReached { target_block: 200 },
            }
        );
        assert_eq!(handle.last_scanned(), 150);
        assert_eq!(
            send_apply(
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
                public_data_epoch: Arc::new(AtomicU64::new(0)),
            },
            wallet_config(),
            1,
            live_rx,
            backfill_rx,
            cancel.clone(),
            Vec::new(),
            100,
        );

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
            send_target(&backfill_tx, 150, 0).await,
            WalletBackfillFinishResult::Rejected {
                reason: WalletBackfillRejectReason::StaleGeneration { .. },
                ..
            }
        ));
        assert!(matches!(
            send_apply(&backfill_tx, logs_apply(101, 150), 0).await,
            WalletBackfillApplyResult::Rejected {
                reason: WalletBackfillRejectReason::StaleGeneration { .. },
                ..
            }
        ));
        assert_eq!(handle.last_scanned(), 79);

        assert!(matches!(
            send_apply(
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
        assert!(matches!(
            send_target(&backfill_tx, 150, 1).await,
            WalletBackfillFinishResult::Rejected {
                reason: WalletBackfillRejectReason::TargetNotReached { .. },
                ..
            }
        ));
        assert_eq!(
            send_apply(&backfill_tx, indexed_delta_batch(80, 90, empty_delta()), 1).await,
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
                public_data_epoch: Arc::new(AtomicU64::new(0)),
            },
            wallet_config(),
            1,
            live_rx,
            backfill_rx,
            cancel.clone(),
            Vec::new(),
            100,
        );
        for block in 101..=120 {
            live_tx
                .send(Arc::new(LogBatch {
                    from_block: block,
                    to_block: block,
                    logs: Vec::new(),
                    block_timestamps: HashMap::new(),
                    to_block_hash: None,
                }))
                .expect("live receiver");
        }
        tokio::task::yield_now().await;
        assert_eq!(handle.last_scanned(), 100);

        assert_eq!(
            send_target(&backfill_tx, 100, 0).await,
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
            reset_generation,
            ..
        } = request
        else {
            panic!("expected add backfill request");
        };
        assert_eq!(cache_key, "test");
        assert_eq!(from_block, 101);
        assert!(to_block > from_block);
        assert!(follow_safe_head);
        assert_eq!(reset_generation, 0);
        assert_eq!(handle.last_scanned(), 100);

        assert_eq!(
            send_apply(
                &backfill_tx,
                logs_apply(from_block, to_block),
                reset_generation
            )
            .await,
            WalletBackfillApplyResult::Committed {
                committed_to: to_block
            }
        );
        assert_eq!(
            send_target(&backfill_tx, to_block, reset_generation).await,
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
