#[allow(clippy::wildcard_imports)]
use super::*;
use crate::types::WalletResetToken;

/// A wallet reset request from the backfill loop.
struct WalletResetRequest {
    token: WalletResetToken,
    from_block: u64,
    replay_plan: WalletResetReplayPlan,
    response: oneshot::Sender<WalletBackfillResetResult>,
}

impl WalletActorLoop<'_> {
    /// Handles one event from the backfill loop.
    pub(super) async fn handle_backfill_event(&mut self, event: BackfillEvent) {
        match event {
            #[cfg(test)]
            BackfillEvent::PanicForTest => {
                panic!("test wallet actor panic");
            }
            #[cfg(test)]
            BackfillEvent::HoldTrackedPoiJobForTest { sentinel, started } => {
                let held_data_plane = self.public_data_plane.clone();
                self.poi_jobs.spawn(async move {
                    let _held = (held_data_plane, sentinel);
                    let _ = started.send(());
                    std::future::pending::<()>().await;
                });
            }
            BackfillEvent::ReserveTarget {
                target_block,
                token,
                response,
            } => {
                self.reserve_sync_target(target_block, token, response)
                    .await;
            }
            BackfillEvent::Start {
                target_block,
                token,
                response,
            } => self.start_backfill(target_block, token, response).await,
            BackfillEvent::Apply {
                apply,
                token,
                response,
            } => self.apply_backfill(apply, token, response).await,
            BackfillEvent::Finish {
                target_block,
                token,
                response,
            } => self.finish_backfill(target_block, token, response).await,
            BackfillEvent::JobFailed {
                token,
                reason,
                response,
            } => self.fail_backfill_job(token, &reason, response),
            BackfillEvent::Reset {
                token,
                from_block,
                replay_plan,
                response,
            } => {
                self.reset_wallet(WalletResetRequest {
                    token,
                    from_block,
                    replay_plan,
                    response,
                })
                .await;
            }
        }
    }

    /// Applies an accepted backfill job owner's final signal: a benign retirement of the
    /// last job completes the backfill and catches up POI statuses; a lost driver reopens it.
    pub(super) async fn handle_backfill_owner_signal(
        &mut self,
        token: WalletSyncToken,
        signal: WalletBackfillOwnerSignal,
    ) {
        let WalletBackfillOwnerSignal {
            disposition,
            acknowledgement,
        } = signal;
        let changed = self
            .actor_state
            .transition_active(&self.worker_handle, &self.cancel, |mut state| {
                state.apply_backfill_owner_disposition(token, disposition)
            })
            .unwrap_or(false);
        if changed {
            if disposition == WalletBackfillOwnerDisposition::BenignRetirement
                && !self.actor_state.has_active_backfill_job()
            {
                self.backfill_complete_block = self.actor_state.completed_target_block();
                self.refresh_poi_statuses_after_backfill_retirement().await;
            } else if disposition == WalletBackfillOwnerDisposition::DriverLost {
                self.backfill_complete_block = None;
            }
        }
        if let Some(acknowledgement) = acknowledgement {
            let _ = acknowledgement.send(());
        }
    }

    /// Why a new backfill job for `token` is rejected, if it is: a stale token, or a
    /// reset still pending after driving it (a persistence failure when persistence
    /// failed, otherwise shutdown).
    async fn new_job_rejection(
        &mut self,
        token: WalletSyncToken,
    ) -> Option<WalletBackfillRejectReason> {
        if let Err(reason) =
            self.actor_state
                .validate_sync_token_current(token, &self.worker_handle, &self.cancel)
        {
            return Some(reason);
        }
        if self.try_drive_pending_reset(true).await.is_some()
            && self.actor_state.pending_reset().is_some()
        {
            return Some(self.pending_reset_rejection());
        }
        None
    }

    /// Drives a pending reset before a step of an accepted job. While one is still
    /// pending, the step is rejected with the deferred rewind's reason, or as in
    /// [`Self::new_job_rejection`] once the rewind committed.
    async fn reset_blocks_job_step(&mut self) -> Option<WalletBackfillRejectReason> {
        if let Some(outcome) = self.try_drive_pending_reset(true).await
            && self.actor_state.pending_reset().is_some()
        {
            Some(match outcome.rewind {
                WalletResetRewindOutcome::Deferred { reason, .. } => reason,
                WalletResetRewindOutcome::Committed { .. } => self.pending_reset_rejection(),
            })
        } else {
            None
        }
    }

    /// Sends a backfill-loop reply, logging when the requester already went away.
    fn send_logged<T: std::fmt::Debug>(
        &self,
        response: oneshot::Sender<T>,
        result: T,
        send_failure: &'static str,
    ) {
        if let Err(err) = response.send(result) {
            debug!(?err, cache_key = %self.cfg.cache_key, "{send_failure}");
        }
    }

    const fn pending_reset_rejection(&self) -> WalletBackfillRejectReason {
        if self.actor_state.has_persistence_failure() {
            WalletBackfillRejectReason::PersistenceFailed
        } else {
            WalletBackfillRejectReason::Shutdown
        }
    }

    async fn reserve_sync_target(
        &mut self,
        target_block: u64,
        token: WalletSyncToken,
        response: oneshot::Sender<Result<WalletSyncTargetLease, WalletBackfillRejectReason>>,
    ) {
        if let Some(reason) = self.new_job_rejection(token).await {
            let _ = response.send(Err(reason));
            return;
        }
        let accepted = self
            .actor_state
            .transition_active(&self.worker_handle, &self.cancel, |mut state| {
                state.accept_sync_target(token, target_block)
            })
            .unwrap_or(false);
        if !accepted {
            let _ = response.send(Err(WalletBackfillRejectReason::Shutdown));
            return;
        }
        let (liveness, receiver) = oneshot::channel();
        self.accepted_backfill_liveness
            .push(accepted_backfill_owner_dropped(token, receiver));
        let lease = WalletSyncTargetLease::for_actor_accepted_job(
            token,
            self.backfill_sender.clone(),
            liveness,
        );
        if let Err(lease) = response.send(Ok(lease)) {
            drop(lease);
            let _ = self.actor_state.transition_active(
                &self.worker_handle,
                &self.cancel,
                |mut state| state.retire_job(token),
            );
        }
    }

    async fn start_backfill(
        &mut self,
        target_block: u64,
        token: WalletSyncToken,
        response: oneshot::Sender<WalletBackfillStartResult>,
    ) {
        if let Some(reason) = self.new_job_rejection(token).await {
            let _ = response.send(WalletBackfillStartResult::Rejected {
                committed_to: self.last_scanned,
                reason,
            });
            return;
        }
        let accepted = self
            .actor_state
            .transition_active(&self.worker_handle, &self.cancel, |mut state| {
                state.accept_target(token, target_block)
            })
            .unwrap_or(false);
        if !accepted {
            let _ = response.send(WalletBackfillStartResult::Rejected {
                committed_to: self.last_scanned,
                reason: WalletBackfillRejectReason::Shutdown,
            });
            return;
        }
        let (liveness, receiver) = oneshot::channel();
        self.accepted_backfill_liveness
            .push(accepted_backfill_owner_dropped(token, receiver));
        self.backfill_complete_block = None;
        let result = WalletBackfillStartResult::Accepted {
            committed_to: self.last_scanned,
            target_block,
            grant: WalletBackfillGrant::for_actor_accepted_job_with_cancel(
                token,
                self.backfill_sender.clone(),
                liveness,
                self.cancel.clone(),
            ),
        };
        match response.send(result) {
            Ok(()) => {
                let _ = self.actor_state.transition_active(
                    &self.worker_handle,
                    &self.cancel,
                    |mut state| state.backfill_dispatch_admitted(token),
                );
            }
            Err(result) => {
                drop(result);
                let _ = self.actor_state.transition_active(
                    &self.worker_handle,
                    &self.cancel,
                    |mut state| state.retire_job(token),
                );
                debug!(cache_key = %self.cfg.cache_key, ?token, "wallet backfill start receiver dropped");
            }
        }
    }

    async fn apply_backfill(
        &mut self,
        apply: WalletScanApply,
        token: WalletSyncToken,
        response: oneshot::Sender<WalletBackfillApplyResult>,
    ) {
        if let Some(reason) = self.reset_blocks_job_step().await {
            let _ = self.actor_state.transition_active(
                &self.worker_handle,
                &self.cancel,
                |mut state| {
                    state.retire_job(token);
                },
            );
            self.send_logged(
                response,
                WalletBackfillApplyResult::Rejected {
                    committed_to: self.last_scanned,
                    reason,
                },
                "failed to send pending-reset wallet scan apply result",
            );
            return;
        }
        let current_reset_generation = self.actor_state.reset_generation();
        if let Err(reason) = self.actor_state.validate_active_backfill_token(
            token,
            &self.worker_handle,
            &self.cancel,
        ) {
            self.send_logged(
                response,
                WalletBackfillApplyResult::Rejected {
                    committed_to: self.last_scanned,
                    reason,
                },
                "failed to send inactive wallet scan apply result",
            );
            return;
        }
        let outcome = WalletScanCommitRequest {
            cache_store: self.cache_store.as_ref(),
            cfg: &self.cfg,
            utxos: &self.utxos,
            worker_handle: &self.worker_handle,
            apply,
            job_token: token,
            current_reset_generation,
            event_reset_generation: token.reset_generation(),
            actor_state: &mut self.actor_state,
            cancel: &self.cancel,
            last_scanned: &mut self.last_scanned,
            persist_state: &mut self.persist_state,
            live_metadata_flush: &mut self.live_metadata_flush,
            public_data_plane: &self.public_data_plane,
        }
        .commit()
        .await;
        if outcome.changed && self.poi_status_client.is_some() {
            let _ = self.request_poi_maintenance(false);
        }
        self.send_logged(
            response,
            outcome.result,
            "failed to send wallet scan apply result",
        );
    }

    async fn finish_backfill(
        &mut self,
        target_block: u64,
        token: WalletSyncToken,
        response: oneshot::Sender<WalletBackfillFinishResult>,
    ) {
        let current_reset_generation = self.actor_state.reset_generation();
        if let Err(reason) = self.actor_state.validate_active_backfill_token(
            token,
            &self.worker_handle,
            &self.cancel,
        ) {
            self.send_logged(
                response,
                WalletBackfillFinishResult::Rejected {
                    committed_to: self.last_scanned,
                    reason,
                },
                "failed to send stale wallet target result",
            );
            return;
        }
        if let Some(reason) = self.reset_blocks_job_step().await {
            self.send_logged(
                response,
                WalletBackfillFinishResult::Rejected {
                    committed_to: self.last_scanned,
                    reason,
                },
                "failed to send pending-reset wallet target result",
            );
            return;
        }
        let Some(required_target) = self
            .actor_state
            .transition_active(&self.worker_handle, &self.cancel, |mut state| {
                state.update_target(token, target_block)
            })
            .ok()
            .flatten()
        else {
            let _ = response.send(WalletBackfillFinishResult::Rejected {
                committed_to: self.last_scanned,
                reason: WalletBackfillRejectReason::Shutdown,
            });
            return;
        };
        if required_target == 0 || required_target > self.last_scanned {
            self.reject_unreached_target(required_target, current_reset_generation, response);
            return;
        }
        let result = self
            .complete_backfill_to_target(required_target, token)
            .await;
        self.send_logged(response, result, "failed to send wallet target result");
    }

    /// Rejects a finish whose target the cursor has not reached yet.
    fn reject_unreached_target(
        &mut self,
        required_target: u64,
        current_reset_generation: u64,
        response: oneshot::Sender<WalletBackfillFinishResult>,
    ) {
        debug!(
            cache_key = %self.cfg.cache_key,
            target_block = required_target,
            last_scanned = self.last_scanned,
            reset_generation = current_reset_generation,
            "wallet target recorded; cursor has not reached target"
        );
        self.backfill_complete_block = None;
        self.send_logged(
            response,
            WalletBackfillFinishResult::Rejected {
                committed_to: self.last_scanned,
                reason: WalletBackfillRejectReason::TargetNotReached {
                    target_block: required_target,
                },
            },
            "failed to send pending wallet target result",
        );
    }

    /// Completes the backfill job once the cursor reached `required_target`.
    async fn complete_backfill_to_target(
        &mut self,
        required_target: u64,
        token: WalletSyncToken,
    ) -> WalletBackfillFinishResult {
        match self.apply_backfill_done(required_target, token).await {
            WalletBackfillDoneOutcome::Finished {
                poi_corpus_revision,
            } => {
                self.finish_completed_backfill(token, poi_corpus_revision)
                    .await
            }
            WalletBackfillDoneOutcome::Rejected(reason) => {
                let _ = self.actor_state.transition_active(
                    &self.worker_handle,
                    &self.cancel,
                    |mut state| {
                        if reason == WalletBackfillRejectReason::PersistenceFailed {
                            state.backfill_completion_persist_failed(token);
                        } else {
                            state.retire_job(token);
                        }
                    },
                );
                WalletBackfillFinishResult::Rejected {
                    committed_to: self.last_scanned,
                    reason,
                }
            }
        }
    }

    /// Retires the completed job, unless the PPOI corpus moved past the revision the
    /// completion applied. Holds the corpus revision fence while checking.
    async fn finish_completed_backfill(
        &mut self,
        token: WalletSyncToken,
        poi_corpus_revision: Option<PoiCorpusRevision>,
    ) -> WalletBackfillFinishResult {
        let _revision_fence = match self.poi_corpus_handle.as_ref() {
            Some(corpus) => Some(corpus.revision_read_fence().await),
            None => None,
        };
        if poi_corpus_revision.is_some_and(|applied_revision| {
            self.poi_corpus_revision_rx
                .as_mut()
                .is_some_and(|revision_rx| *revision_rx.borrow_and_update() != applied_revision)
        }) {
            WalletBackfillFinishResult::Rejected {
                committed_to: self.last_scanned,
                reason: WalletBackfillRejectReason::ApplyFailed,
            }
        } else {
            let completed = self
                .actor_state
                .transition_active(&self.worker_handle, &self.cancel, |mut state| {
                    state.complete_backfill_job(token)
                })
                .unwrap_or(false);
            if completed {
                if self.actor_state.has_active_backfill_job() {
                    self.backfill_complete_block = None;
                }
                WalletBackfillFinishResult::Ready {
                    committed_to: self.last_scanned,
                }
            } else {
                WalletBackfillFinishResult::Rejected {
                    committed_to: self.last_scanned,
                    reason: WalletBackfillRejectReason::Shutdown,
                }
            }
        }
    }

    fn fail_backfill_job(
        &mut self,
        token: WalletSyncToken,
        reason: &WalletReadinessError,
        response: oneshot::Sender<()>,
    ) {
        if self
            .actor_state
            .validate_active_backfill_token(token, &self.worker_handle, &self.cancel)
            .is_ok()
        {
            let _ = self.actor_state.transition_active(
                &self.worker_handle,
                &self.cancel,
                |mut state| match *reason {
                    WalletReadinessError::BackfillUnavailable => {
                        state.fail_job_backfill_unavailable(token)
                    }
                    WalletReadinessError::TargetNotReached { target_block } => {
                        state.fail_job_target_not_reached(token, target_block)
                    }
                    WalletReadinessError::ApplyFailed => state.fail_job_apply_failed(token),
                    WalletReadinessError::PersistenceFailed => false,
                },
            );
        }
        let _ = response.send(());
    }

    async fn reset_wallet(&mut self, request: WalletResetRequest) {
        let WalletResetRequest {
            token,
            from_block,
            replay_plan,
            response,
        } = request;
        if let Err(reason) =
            self.actor_state
                .validate_reset_token_current(token, &self.worker_handle, &self.cancel)
        {
            self.send_logged(
                response,
                WalletBackfillResetResult::Rejected {
                    committed_to: self.last_scanned,
                    reason,
                },
                "failed to send shutdown wallet reset result",
            );
            return;
        }
        let intent_id = token.intent_id();

        if intent_id <= self.actor_state.highest_accepted_reset_intent() {
            self.send_logged(
                response,
                WalletBackfillResetResult::Rejected {
                    committed_to: self.last_scanned,
                    reason: WalletBackfillRejectReason::StaleResetIntent {
                        accepted: self.actor_state.highest_accepted_reset_intent(),
                        actual: intent_id,
                    },
                },
                "failed to send stale wallet reset result",
            );
            return;
        }
        let next_reset_generation = match self
            .accept_wallet_reset(intent_id, from_block, replay_plan)
            .await
        {
            Ok(next_reset_generation) => next_reset_generation,
            Err((reason, send_failure)) => {
                self.send_logged(
                    response,
                    WalletBackfillResetResult::Rejected {
                        committed_to: self.last_scanned,
                        reason,
                    },
                    send_failure,
                );
                return;
            }
        };
        let outcome = self
            .try_drive_pending_reset(true)
            .await
            .expect("pending reset was installed before commit");
        // Accept already succeeded: public result is always Accepted.
        let result = reset_result_after_accept(next_reset_generation, outcome);
        self.send_logged(response, result, "failed to send wallet reset result");
    }

    /// Accepts the reset durably. Returns the new reset generation, or the rejection
    /// together with the message to log if it cannot be delivered.
    async fn accept_wallet_reset(
        &mut self,
        intent_id: u64,
        from_block: u64,
        replay_plan: WalletResetReplayPlan,
    ) -> Result<u64, (WalletBackfillRejectReason, &'static str)> {
        let current_reset_generation = self.actor_state.reset_generation();
        let acceptance_authority = WalletPrivateMutationAuthority::new(
            &self.worker_handle,
            current_reset_generation,
            &self.cancel,
        );
        let acceptance_permit = acceptance_authority
            .acquire()
            .await
            .map_err(|reason| (reason, "failed to send reset authority rejection"))?;
        let accepted_pending_reset =
            self.pending_reset_to_accept(intent_id, from_block, replay_plan);
        let next_reset_generation = accepted_pending_reset.reset_generation();
        // AcceptReset transition: durable accept + generation + actor_state +
        // publications under one active-apply fence (no split after durable write).
        let accept_result = acceptance_permit.with_active_apply(|token| {
            persist_wallet_reset_acceptance_with_token(
                &token,
                &acceptance_permit,
                self.cache_store.as_ref(),
                &self.cfg,
                intent_id,
                accepted_pending_reset,
            )?;
            acceptance_permit.apply_set_reset_generation(&token, next_reset_generation);
            let reset_intent_id = accepted_pending_reset.intent_id();
            let reset_from = accepted_pending_reset.rewind_from_block();
            let reset_view = WalletViewState::ResetPending {
                intent_id: reset_intent_id,
                from_block: reset_from,
                reset_generation: next_reset_generation,
            };
            let clear_indexed_catch_up =
                self.actor_state
                    .transition_with_view(&token, reset_view, |mut state| {
                        state.accept_reset(accepted_pending_reset)
                    });
            // Force intent is generation-scoped; do not carry across rewind.
            self.poi_maintenance.clear_force_on_reset();
            if clear_indexed_catch_up {
                acceptance_permit.apply_publish_indexed_catch_up(&token, None);
            }
            Ok::<(), WalletCacheError>(())
        });
        match accept_result {
            Ok(Ok(())) => {
                self.accepted_backfill_liveness.clear();
                self.accepted_indexed_job_liveness.clear();
                self.pending_output_poi_tentative_attempts.clear();
            }
            Ok(Err(err)) => {
                warn!(?err, cache_key = %self.cfg.cache_key, intent_id, from_block, "failed to persist wallet reset acceptance");
                return Err((
                    WalletBackfillRejectReason::PersistenceFailed,
                    "failed to send wallet reset persistence failure",
                ));
            }
            Err(reason) => return Err((reason, "failed to send reset acceptance rejection")),
        }
        drop(acceptance_permit);
        Ok(next_reset_generation)
    }

    /// The pending reset to accept: merged with any reset already pending, one reset
    /// generation ahead of the current one.
    fn pending_reset_to_accept(
        &self,
        intent_id: u64,
        from_block: u64,
        replay_plan: WalletResetReplayPlan,
    ) -> PendingWalletReset {
        let reset_from_block = self
            .actor_state
            .pending_reset()
            .map_or(from_block, |pending| {
                pending.rewind_from_block().min(from_block)
            });
        let replay_plan =
            PendingWalletReset::merge_replay_plan(self.actor_state.pending_reset(), replay_plan);
        PendingWalletReset::new(
            intent_id,
            reset_from_block,
            self.actor_state.reset_generation().wrapping_add(1),
            replay_plan,
        )
    }
}
