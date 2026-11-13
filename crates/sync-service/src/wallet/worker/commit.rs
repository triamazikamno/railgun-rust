#[allow(clippy::wildcard_imports)]
use super::*;

pub(super) struct WalletScanCommitRequest<'a> {
    pub(super) cache_store: &'a dyn WalletCacheStore,
    pub(super) cfg: &'a WalletConfig,
    pub(super) utxos: &'a Arc<RwLock<Vec<WalletUtxo>>>,
    pub(super) worker_handle: &'a WalletHandle,
    pub(super) apply: WalletScanApply,
    pub(super) job_token: WalletSyncToken,
    pub(super) current_reset_generation: u64,
    pub(super) event_reset_generation: u64,
    pub(super) actor_state: &'a mut WalletActorState,
    pub(super) cancel: &'a CancellationToken,
    pub(super) last_scanned: &'a mut u64,
    pub(super) persist_state: &'a mut WalletPersistState,
    pub(super) live_metadata_flush: &'a mut WalletLiveMetadataFlush,
    pub(super) public_data_plane: &'a ChainPublicDataPlane,
}

pub(super) struct WalletScanCommitOutcome {
    pub(super) result: WalletBackfillApplyResult,
    pub(super) changed: bool,
}

pub(super) fn wallet_scan_progress_update(
    configured_start_block: Option<u64>,
    page_from_block: u64,
    current_block: u64,
    target_block: u64,
    source: PublicScanSource,
) -> SyncProgressUpdate {
    SyncProgressUpdate::new(
        SyncProgressStage::IndexingUtxos,
        configured_start_block.unwrap_or(page_from_block),
        current_block,
        target_block,
    )
    .with_source(source)
}

pub(super) struct WalletPoiStatusRefreshCommitRequest<'a> {
    pub(super) cache_store: &'a dyn WalletCacheStore,
    pub(super) cfg: &'a WalletConfig,
    pub(super) utxos: &'a Arc<RwLock<Vec<WalletUtxo>>>,
    pub(super) worker_handle: &'a WalletHandle,
    pub(super) last_scanned: u64,
    pub(super) reset_generation: u64,
    pub(super) actor_state: &'a mut WalletActorState,
    pub(super) persist_state: &'a mut WalletPersistState,
    pub(super) status_reader: &'a dyn PoiStatusReader,
    pub(super) active_poi_list_keys: &'a [FixedBytes<32>],
    pub(super) selection: WalletPoiRefreshSelection,
    pub(super) cancel: &'a CancellationToken,
}

pub(super) struct WalletResetCommitRequest<'a> {
    pub(super) cache_store: &'a dyn WalletCacheStore,
    pub(super) cfg: &'a WalletConfig,
    pub(super) utxos: &'a Arc<RwLock<Vec<WalletUtxo>>>,
    pub(super) worker_handle: &'a WalletHandle,
    pub(super) pending: PendingWalletReset,
    pub(super) highest_accepted_reset_intent: u64,
    pub(super) actor_state: &'a mut WalletActorState,
    pub(super) cancel: &'a CancellationToken,
    pub(super) last_scanned: &'a mut u64,
    pub(super) persist_state: &'a mut WalletPersistState,
    pub(super) live_metadata_flush: &'a mut WalletLiveMetadataFlush,
}

/// Outcome of `CommitResetRewind` only (pending reset already accepted).
/// Never means "reset rejected" — use [`WalletBackfillResetResult::Rejected`] only
/// before durable `AcceptReset`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) enum WalletResetRewindOutcome {
    Committed {
        committed_to: u64,
    },
    Deferred {
        committed_to: u64,
        reason: WalletBackfillRejectReason,
    },
}

impl WalletResetRewindOutcome {
    pub(super) const fn committed(&self) -> bool {
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

pub(super) struct WalletResetCommitOutcome {
    pub(super) rewind: WalletResetRewindOutcome,
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
pub(super) fn reset_result_after_accept(
    reset_generation: u64,
    outcome: WalletResetCommitOutcome,
) -> WalletBackfillResetResult {
    outcome.into_accept_result(reset_generation)
}

pub(super) enum WalletBackfillDoneOutcome {
    Finished {
        poi_corpus_revision: Option<PoiCorpusRevision>,
    },
    Rejected(WalletBackfillRejectReason),
}

pub(super) const WALLET_RESET_RETRY_INTERVAL: Duration = Duration::from_secs(1);

fn wallet_sync_actor_state_record(
    cfg: &WalletConfig,
    highest_accepted_reset_intent: u64,
    pending_reset: Option<PendingWalletReset>,
) -> WalletSyncActorStateRecord {
    WalletSyncActorStateRecord {
        chain_id: cfg.chain.chain_id,
        wallet_id: cfg.cache_key.to_string(),
        highest_accepted_reset_intent,
        pending_reset: pending_reset.map(|pending| {
            let replay_plan = pending.replay_plan();
            WalletPendingResetRecord {
                intent_id: pending.intent_id(),
                from_block: pending.rewind_from_block(),
                replay_start_block: replay_plan.start_block,
                replay_target_block: replay_plan.target_block,
                follow_safe_head: replay_plan.follow_safe_head,
            }
        }),
        updated_at: now_epoch_secs(),
    }
}

pub(super) fn reset_replay_from_block(last_scanned: u64, start_block: u64) -> u64 {
    last_scanned.saturating_add(1).max(start_block)
}

pub(super) fn validate_restored_pending_reset(
    cfg: &WalletConfig,
    initial_last_scanned: u64,
    pending: PendingWalletReset,
) -> Result<(), ChainError> {
    let post_rewind_cursor =
        initial_last_scanned.min(pending.rewind_from_block().saturating_sub(1));
    let configured_start_block = cfg.start_block.unwrap_or_default();
    let replay_plan = pending.replay_plan();
    let required_replay_start_block = post_rewind_cursor.saturating_add(1);
    let required_replay_target_block = configured_start_block.saturating_sub(1);
    let starts_after_cursor = replay_plan.start_block > required_replay_start_block;
    let bounded_target_misses_start_boundary = !replay_plan.follow_safe_head
        && replay_plan.start_block < configured_start_block
        && replay_plan.target_block < required_replay_target_block;
    if starts_after_cursor || bounded_target_misses_start_boundary {
        return Err(ChainError::IncompatiblePendingWalletResetReplay {
            post_rewind_cursor,
            configured_start_block,
            replay_start_block: replay_plan.start_block,
            replay_target_block: replay_plan.target_block,
            follow_safe_head: replay_plan.follow_safe_head,
            required_replay_start_block,
            required_replay_target_block,
        });
    }
    Ok(())
}

pub(super) fn signal_restored_reset_attempt(startup_replay_tx: &mut Option<oneshot::Sender<()>>) {
    if let Some(tx) = startup_replay_tx.take() {
        let _ = tx.send(());
    }
}

pub(super) fn persist_wallet_reset_replay_admission_with_token(
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
pub(super) fn persist_wallet_reset_acceptance_with_token(
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

pub(super) async fn accepted_backfill_owner_dropped(
    token: WalletSyncToken,
    receiver: oneshot::Receiver<WalletBackfillOwnerSignal>,
) -> (WalletSyncToken, WalletBackfillOwnerSignal) {
    let signal = receiver.await.unwrap_or(WalletBackfillOwnerSignal {
        disposition: WalletBackfillOwnerDisposition::DriverLost,
        acknowledgement: None,
    });
    (token, signal)
}

pub(super) async fn accepted_indexed_job_owner_dropped(
    token: WalletSyncToken,
    receiver: oneshot::Receiver<()>,
) -> WalletSyncToken {
    let _ = receiver.await;
    token
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
}

impl WalletResetCommitRequest<'_> {
    pub(super) async fn commit(self) -> WalletResetCommitOutcome {
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
            committed_to_before.min(request.pending.rewind_from_block().saturating_sub(1));
        let wallet_utxos_before_rewind = request.utxos.read().await.clone();
        let mut candidate = wallet_utxos_before_rewind.clone();
        let rewind = rewind_wallet_utxos(&mut candidate, request.pending.rewind_from_block());
        let pending_output_rewind = match pending_output_poi_rewind_state_updates(
            request.cache_store,
            request.cfg.chain.chain_id,
            &request.cfg.cache_key,
            request.pending.rewind_from_block(),
            &wallet_utxos_before_rewind,
        ) {
            Ok(updates) => updates,
            Err(err) => {
                warn!(
                    ?err,
                    cache_key = %request.cfg.cache_key,
                    intent_id = request.pending.intent_id(),
                    from_block = request.pending.rewind_from_block(),
                    "failed to prepare pending output POI reset cleanup"
                );
                return WalletResetCommitOutcome {
                    rewind: WalletResetRewindOutcome::Deferred {
                        committed_to: committed_to_before,
                        reason: WalletBackfillRejectReason::PersistenceFailed,
                    },
                };
            }
        };
        let sender_candidate_deletes = match request
            .cache_store
            .list_sender_transaction_candidates(request.cfg.chain.chain_id, &request.cfg.cache_key)
            .and_then(|candidates| {
                sender_transaction_candidate_rewind_ids(
                    &candidates,
                    request.pending.rewind_from_block(),
                )
                .map_err(|_| WalletCacheError::Crypto)
            }) {
            Ok(deletes) => deletes,
            Err(err) => {
                warn!(
                    ?err,
                    cache_key = %request.cfg.cache_key,
                    intent_id = request.pending.intent_id(),
                    from_block = request.pending.rewind_from_block(),
                    "failed to prepare sender candidate reset cleanup"
                );
                return WalletResetCommitOutcome {
                    rewind: WalletResetRewindOutcome::Deferred {
                        committed_to: committed_to_before,
                        reason: WalletBackfillRejectReason::PersistenceFailed,
                    },
                };
            }
        };
        let mut pending_context_deletes = rewind.removed_output_commitments.clone();
        pending_context_deletes.extend_from_slice(&pending_output_rewind.context_deletes);
        pending_context_deletes.sort_unstable();
        pending_context_deletes.dedup();
        let mut output_recovery_deletes = rewind.removed_output_commitments.clone();
        output_recovery_deletes.extend_from_slice(&pending_output_rewind.recovery_deletes);
        output_recovery_deletes.sort_unstable();
        output_recovery_deletes.dedup();
        let authority = WalletPrivateMutationAuthority::new(
            request.worker_handle,
            request.pending.reset_generation(),
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
        let active_list_keys = default_active_poi_list_keys();
        let workflow_status = match wallet_ppoi_workflow_status_after_mutations(
            request.cache_store,
            request.cfg,
            &active_list_keys,
            permit.ppoi_workflow_status().validation_revision,
            &pending_output_rewind.context_updates,
            &pending_context_deletes,
            &[],
            &output_recovery_deletes,
            &[],
            &sender_candidate_deletes,
        ) {
            Ok(status) => status,
            Err(err) => {
                warn!(
                    ?err,
                    cache_key = %request.cfg.cache_key,
                    intent_id = request.pending.intent_id(),
                    from_block = request.pending.rewind_from_block(),
                    "failed to derive pending output PPOI workflow reset candidate"
                );
                return WalletResetCommitOutcome {
                    rewind: WalletResetRewindOutcome::Deferred {
                        committed_to: committed_to_before,
                        reason: WalletBackfillRejectReason::PersistenceFailed,
                    },
                };
            }
        };

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
                    WalletUtxoMutation::Replace(&candidate),
                    WalletCheckpointMutation::Set {
                        last_scanned_block: candidate_last_scanned,
                        last_scanned_block_hash: None,
                    },
                )
                .with_pending_output_context_updates(&pending_output_rewind.context_updates)
                .with_pending_output_context_deletes(&pending_context_deletes)
                .with_output_poi_recovery_deletes(&output_recovery_deletes)
                .with_sender_transaction_candidate_deletes(&sender_candidate_deletes)
                .with_sync_actor_state(&sync_actor_state),
            )?;
            *request.last_scanned = candidate_last_scanned;
            request.persist_state.needs_full_persist = false;
            request.persist_state.pending_cache_reset = None;
            request
                .live_metadata_flush
                .mark_persisted(candidate_last_scanned, Instant::now());
            *utxos_locked = candidate;
            let now = now_epoch_secs();
            let local_pending_spent = overlay_locked
                .local_pending_spent
                .iter()
                .filter(|spent| {
                    let submitted_at = spent.block_timestamp.unwrap_or(now);
                    now.saturating_sub(submitted_at) < LOCAL_PENDING_SPENT_TTL.as_secs()
                })
                .cloned()
                .collect();
            let next_overlay = WalletPendingOverlay {
                local_pending_spent,
                ..WalletPendingOverlay::default()
            };
            let overlay_changed = !chain_pending_overlay_matches(&overlay_locked, &next_overlay)
                || overlay_locked.local_pending_spent != next_overlay.local_pending_spent
                || !overlay_locked.new_utxos.is_empty();
            *overlay_locked = next_overlay;
            permit.apply_set_last_scanned_mirror(&token, candidate_last_scanned);
            if rewind.changed || overlay_changed {
                permit.apply_increment_revision(&token);
            }
            let view = permit.apply_current_view(&token, &utxos_locked, &overlay_locked);
            request
                .actor_state
                .transition_with_view_and_ppoi_workflow_projection(
                    &token,
                    view,
                    workflow_status,
                    |mut state| {
                        state.mark_pending_reset_rewind_committed(candidate_last_scanned);
                    },
                );
            debug_assert!(request.actor_state.pending_reset_rewind_committed());
            debug_assert_eq!(
                request.worker_handle.last_scanned_raw(),
                *request.last_scanned
            );
            debug_assert!(matches!(
                request.worker_handle.view_state(),
                WalletViewState::Current(current)
                    if current.last_scanned == *request.last_scanned
            ));
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
                    intent_id = request.pending.intent_id(),
                    from_block = request.pending.rewind_from_block(),
                    reset_generation = request.pending.reset_generation(),
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
        drop(permit);

        let snapshot = request.utxos.read().await;
        let (unspent, spent) = wallet_utxo_counts(&snapshot);
        info!(
            cache_key = %request.cfg.cache_key,
            intent_id = request.pending.intent_id(),
            from_block = request.pending.rewind_from_block(),
            last_scanned = candidate_last_scanned,
            total = snapshot.len(),
            unspent,
            spent,
            changed = rewind.changed,
            pending_context_deletes = pending_context_deletes.len(),
            pending_context_rewinds = pending_output_rewind.context_updates.len(),
            output_recovery_deletes = output_recovery_deletes.len(),
            sender_candidate_deletes = sender_candidate_deletes.len(),
            reset_generation = request.pending.reset_generation(),
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
    pub(super) async fn commit(self) -> Result<bool, WalletBackfillRejectReason> {
        let request = self;
        if request.cancel.is_cancelled() || !request.worker_handle.is_current_actor() {
            return Err(WalletBackfillRejectReason::Shutdown);
        }
        let started = Instant::now();
        let selection_label = request.selection.as_str();
        let mut candidate = request.utxos.read().await.clone();
        if !wallet_poi_status_refresh_needed_for_selection(
            &candidate,
            request.active_poi_list_keys,
            request.selection,
        ) {
            request.actor_state.transition_active(
                request.worker_handle,
                request.cancel,
                |mut state| {
                    state.durable_poi_status_commit_ok(request.reset_generation, request.selection);
                },
            )?;
            debug!(
                cache_key = %request.cfg.cache_key,
                selection = selection_label,
                elapsed_ms = started.elapsed().as_millis(),
                "wallet POI status refresh selection no longer applies"
            );
            return Ok(false);
        }
        let refresh = refresh_wallet_poi_statuses_selected(
            request.status_reader,
            request.cfg.chain.chain_id,
            request.active_poi_list_keys,
            &mut candidate,
            request.selection,
        )
        .await;
        if !refresh.changed {
            if refresh.complete {
                request.actor_state.transition_active(
                    request.worker_handle,
                    request.cancel,
                    |mut state| {
                        state.durable_poi_status_commit_ok(
                            request.reset_generation,
                            request.selection,
                        );
                    },
                )?;
            }
            debug!(
                cache_key = %request.cfg.cache_key,
                selection = selection_label,
                complete = refresh.complete,
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
            permit.apply_increment_revision(&token);
            let overlay = request
                .worker_handle
                .pending_overlay
                .try_read()
                .map(|guard| guard.clone())
                .unwrap_or_default();
            let view = permit.apply_current_view(&token, &utxos_locked, &overlay);
            request
                .actor_state
                .transition_with_view(&token, view, |mut state| {
                    state.durable_poi_status_commit_ok(request.reset_generation, request.selection);
                });
            Ok::<(), WalletCacheError>(())
        });
        drop(utxos_locked);
        match apply_result {
            Ok(Ok(())) => {}
            Ok(Err(err)) => {
                warn!(?err, cache_key = %request.cfg.cache_key, selection = selection_label, "failed to persist wallet POI status refresh candidate");
                let _ = permit.with_active_apply(|token| {
                    request.actor_state.transition(&token, |mut state| {
                        state
                            .poi_status_persist_failed(request.reset_generation, request.selection);
                    });
                });
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
    pub(super) async fn commit(self) -> WalletScanCommitOutcome {
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

        let progress_source = request.apply.rows.source;
        let source_label = progress_source.as_str();
        let progress_start_block = request
            .actor_state
            .progress_start_block(request.job_token)
            .or(request.cfg.start_block);
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
                    sender_scan_outputs: Vec::new(),
                };
                (delta, request.apply.rows.to_block_hash, 0)
            }
            #[cfg(test)]
            WalletScanRowsPayload::IndexedDeltaForTest { delta } => (*delta, None, 0),
        };

        let WalletLogDelta {
            utxos,
            nullifiers,
            commitment_observations,
            sender_scan_outputs,
        } = delta;
        let commitment_observation_count = commitment_observations.len();
        let delta = WalletLogDelta {
            utxos,
            nullifiers,
            commitment_observations: Vec::new(),
            sender_scan_outputs,
        };

        let mut candidate = request.utxos.read().await.clone();
        let rows_before = candidate.len();
        let apply_started = Instant::now();
        let outcome = apply_wallet_delta_to_vec_with_outcome(request.cfg, &mut candidate, delta);
        let changed = outcome.changed;
        let Ok(sender_transaction_candidates) = outcome
            .sender_scan_candidates
            .into_iter()
            .map(|candidate| {
                candidate.into_record(request.cfg.chain.chain_id, request.cfg.cache_key.clone())
            })
            .collect::<Result<Vec<_>, _>>()
        else {
            warn!(
                chain_id = request.cfg.chain.chain_id,
                from_block, to_block, "failed to prepare sender transaction candidates"
            );
            return WalletScanCommitOutcome {
                result: WalletBackfillApplyResult::Rejected {
                    committed_to: *request.last_scanned,
                    reason: WalletBackfillRejectReason::ApplyFailed,
                },
                changed: false,
            };
        };
        let sender_scan_candidate_count = sender_transaction_candidates.len();
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

        let Ok(pending_output_observation_updates) = pending_output_poi_observation_state_updates(
            request.cache_store,
            request.cfg.chain.chain_id,
            &request.cfg.cache_key,
            &commitment_observations,
        ) else {
            warn!(
                chain_id = request.cfg.chain.chain_id,
                from_block,
                to_block,
                "failed to prepare wallet scan pending output POI observations"
            );
            let _ = permit.with_active_apply(|token| {
                request.actor_state.transition(&token, |mut state| {
                    state.sync_progress_persist_failed(request.job_token, from_block, to_block);
                });
            });
            return WalletScanCommitOutcome {
                result: WalletBackfillApplyResult::Rejected {
                    committed_to: *request.last_scanned,
                    reason: WalletBackfillRejectReason::PersistenceFailed,
                },
                changed: false,
            };
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
                    | crate::chain::PublicDataPlaneError::InvalidCompletedAcquisition { .. }
                    | crate::chain::PublicDataPlaneError::CompletedAcquisitionRowPageLimit {
                        ..
                    }
                    | crate::chain::PublicDataPlaneError::UnprovenRpcCoverage { .. }
                    | crate::chain::PublicDataPlaneError::PublicCacheReset { .. }
                    | crate::chain::PublicDataPlaneError::PoiCorpusUnavailable { .. }
                    | crate::chain::PublicDataPlaneError::PoiCorpusRefresh { .. }
                    | crate::chain::PublicDataPlaneError::PoiArtifactPersistence { .. } => {
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
        let active_list_keys = default_active_poi_list_keys();
        let workflow_status = match wallet_ppoi_workflow_status_after_mutations(
            request.cache_store,
            request.cfg,
            &active_list_keys,
            permit.ppoi_workflow_status().validation_revision,
            &pending_output_observation_updates.context_updates,
            &outcome.spent_output_commitments,
            &[],
            &pending_output_observation_updates.recovery_deletes,
            &sender_transaction_candidates,
            &[],
        ) {
            Ok(status) => status,
            Err(err) => {
                warn!(
                    ?err,
                    cache_key = %request.cfg.cache_key,
                    from_block,
                    to_block,
                    "failed to derive pending output PPOI workflow scan candidate"
                );
                let _ = permit.with_active_apply(|token| {
                    request.actor_state.transition(&token, |mut state| {
                        state.sync_progress_persist_failed(request.job_token, from_block, to_block);
                    });
                });
                return WalletScanCommitOutcome {
                    result: WalletBackfillApplyResult::Rejected {
                        committed_to: *request.last_scanned,
                        reason: WalletBackfillRejectReason::PersistenceFailed,
                    },
                    changed: false,
                };
            }
        };

        let target_block = request
            .actor_state
            .active_backfill_target()
            .unwrap_or(to_block)
            .max(to_block);
        let mut utxos_locked = request.utxos.write().await;
        let mut overlay_locked = request.worker_handle.pending_overlay.write().await;
        let mut projection_changed = changed;
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
                    pending_output_context_updates: &pending_output_observation_updates
                        .context_updates,
                    pending_output_context_deletes: &outcome.spent_output_commitments,
                    output_poi_recovery_updates: &[],
                    output_poi_recovery_deletes: &pending_output_observation_updates
                        .recovery_deletes,
                    sender_transaction_candidate_updates: &sender_transaction_candidates,
                    sender_transaction_candidate_deletes: &[],
                },
            )?;
            permit.apply_publish_ppoi_workflow_projection(&token, workflow_status);
            *utxos_locked = candidate;
            projection_changed |=
                prune_local_pending_spent(&mut overlay_locked, &utxos_locked, now_epoch_secs());
            *request.last_scanned = to_block;
            request
                .live_metadata_flush
                .mark_persisted(to_block, Instant::now());
            permit.apply_set_last_scanned_mirror(&token, to_block);
            if projection_changed {
                permit.apply_increment_revision(&token);
            }
            let view = permit.apply_current_view(&token, &utxos_locked, &overlay_locked);
            request
                .actor_state
                .transition_with_view(&token, view, |mut state| {
                    state.durable_sync_progress_commit_ok(request.job_token, from_block, to_block);
                });
            WalletPrivateMutationPermit::apply_publish_progress(
                &token,
                request.cfg.progress_tx.as_ref(),
                wallet_scan_progress_update(
                    progress_start_block,
                    from_block,
                    to_block,
                    target_block,
                    progress_source,
                ),
            );
            Ok::<bool, WalletCacheError>(persisted_full_snapshot)
        });
        drop(overlay_locked);
        drop(utxos_locked);
        let persisted_full_snapshot = match apply_result {
            Ok(Ok(persisted_full_snapshot)) => persisted_full_snapshot,
            Ok(Err(err)) => {
                warn!(?err, cache_key = %request.cfg.cache_key, from_block, to_block, "failed to persist wallet scan candidate");
                let _ = permit.with_active_apply(|token| {
                    request.actor_state.transition(&token, |mut state| {
                        state.sync_progress_persist_failed(request.job_token, from_block, to_block);
                    });
                });
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
            changed = projection_changed,
            commitment_observations = commitment_observation_count,
            sender_scan_candidates = sender_scan_candidate_count,
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
            changed: projection_changed,
        }
    }
}
