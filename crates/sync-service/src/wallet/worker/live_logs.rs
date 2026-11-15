use super::commit::WalletScanCommitOutcome;
#[allow(clippy::wildcard_imports)]
use super::*;
use std::ops::{ControlFlow, RangeInclusive};

impl WalletActorLoop<'_> {
    /// Handles one live log receive. Breaks when the live channel closed.
    pub(super) async fn handle_live_logs(
        &mut self,
        result: Result<SharedLogBatch, broadcast::error::RecvError>,
    ) -> ControlFlow<()> {
        match result {
            Ok(batch) => self.apply_live_batch(&batch).await,
            Err(broadcast::error::RecvError::Closed) => return ControlFlow::Break(()),
            Err(broadcast::error::RecvError::Lagged(skipped)) => {
                self.live_receiver_lagged = true;
                warn!(cache_key = %self.cfg.cache_key, skipped, "wallet live log receiver lagged");
            }
        }
        ControlFlow::Continue(())
    }

    /// Commits a live batch that continues the cursor, or requests a backfill for a gap.
    async fn apply_live_batch(&mut self, batch: &SharedLogBatch) {
        if self.cfg.sync_to_block.is_some() {
            return;
        }
        if self.backfill_complete_block.is_none() || batch.to_block <= self.last_scanned {
            self.live_receiver_lagged = false;
            return;
        }
        let expected_from_block = self.last_scanned.saturating_add(1);
        if batch.from_block > expected_from_block {
            self.request_live_gap_backfill(batch, expected_from_block);
            return;
        }
        self.live_receiver_lagged = false;
        // POI status refresh is never inline on live scan (may be remote).
        // request_poi_maintenance runs after successful commit.
        let apply = match WalletScanApply::rows_from_log_batch(
            expected_from_block,
            batch.to_block,
            batch,
            PublicScanSource::Rpc,
        ) {
            Ok(apply) => apply,
            Err(err) => {
                warn!(?err, cache_key = %self.cfg.cache_key, from_block = expected_from_block, to_block = batch.to_block, "failed to normalize wallet live logs");
                return;
            }
        };
        let current_reset_generation = self.actor_state.reset_generation();
        let live_token = self.worker_handle.mint_sync_token(current_reset_generation);
        let accepted = self
            .actor_state
            .transition_active(&self.worker_handle, &self.cancel, |mut state| {
                state.accept_target(live_token, batch.to_block)
            })
            .unwrap_or(false);
        if !accepted {
            return;
        }
        let outcome = WalletScanCommitRequest {
            cache_store: self.cache_store.as_ref(),
            cfg: &self.cfg,
            utxos: &self.utxos,
            worker_handle: &self.worker_handle,
            apply,
            job_token: live_token,
            current_reset_generation,
            event_reset_generation: live_token.reset_generation(),
            actor_state: &mut self.actor_state,
            cancel: &self.cancel,
            last_scanned: &mut self.last_scanned,
            persist_state: &mut self.persist_state,
            live_metadata_flush: &mut self.live_metadata_flush,
            public_data_plane: &self.public_data_plane,
        }
        .commit()
        .await;
        self.settle_live_commit(live_token, outcome, expected_from_block..=batch.to_block);
    }

    /// Requests a backfill for the blocks missing before `batch` as a new accepted job.
    fn request_live_gap_backfill(&mut self, batch: &SharedLogBatch, expected_from_block: u64) {
        warn!(
            cache_key = %self.cfg.cache_key,
            expected_from_block,
            batch_from_block = batch.from_block,
            batch_to_block = batch.to_block,
            live_receiver_lagged = self.live_receiver_lagged,
            "wallet live log gap detected; requesting backfill"
        );
        let current_reset_generation = self.actor_state.reset_generation();
        let token = self.worker_handle.mint_sync_token(current_reset_generation);
        let accepted = self
            .actor_state
            .transition_active(&self.worker_handle, &self.cancel, |mut state| {
                state.accept_target(token, batch.to_block)
            })
            .unwrap_or(false);
        if !accepted {
            return;
        }
        if let Err(err) =
            self.dispatch_live_backfill(token, expected_from_block..=batch.to_block, true)
        {
            warn!(?err, cache_key = %self.cfg.cache_key, "failed to request wallet live gap backfill");
            let _ = self.actor_state.transition_active(
                &self.worker_handle,
                &self.cancel,
                |mut state| {
                    state.fail_job_backfill_unavailable(token);
                },
            );
        }
        self.live_receiver_lagged = false;
    }

    /// Settles the live job after its commit: retires it, hands a persistence failure to
    /// the backfill loop for retry, or logs a rejection.
    fn settle_live_commit(
        &mut self,
        live_token: WalletSyncToken,
        outcome: WalletScanCommitOutcome,
        range: RangeInclusive<u64>,
    ) {
        match outcome.result {
            WalletBackfillApplyResult::Committed { .. }
            | WalletBackfillApplyResult::AlreadyCovered { .. } => {
                let _ = self.actor_state.transition_active(
                    &self.worker_handle,
                    &self.cancel,
                    |mut state| state.retire_job(live_token),
                );
                if outcome.changed && self.poi_status_client.is_some() {
                    let _ = self.request_poi_maintenance(false);
                }
            }
            WalletBackfillApplyResult::Rejected {
                reason: WalletBackfillRejectReason::PersistenceFailed,
                ..
            } => {
                // Keep the accepted live job as the owner of its exact failed
                // range and let the normal backfill loop apply persistence backoff.
                let (from_block, to_block) = (*range.start(), *range.end());
                if let Err(err) = self.dispatch_live_backfill(live_token, range, false) {
                    warn!(?err, cache_key = %self.cfg.cache_key, from_block, to_block, "failed to enqueue wallet live persistence retry");
                    let _ = self.actor_state.transition_active(
                        &self.worker_handle,
                        &self.cancel,
                        |mut state| {
                            state.fail_job_backfill_unavailable(live_token);
                        },
                    );
                }
            }
            WalletBackfillApplyResult::Rejected { reason, .. } => {
                let _ = self.actor_state.transition_active(
                    &self.worker_handle,
                    &self.cancel,
                    |mut state| state.retire_job(live_token),
                );
                warn!(?reason, cache_key = %self.cfg.cache_key, "wallet live scan batch rejected");
            }
        }
    }

    /// Hands `range` to the backfill loop as the accepted job `token`. Once the backfill
    /// loop takes it, live scanning waits for that backfill and the live subscription
    /// restarts.
    fn dispatch_live_backfill(
        &mut self,
        token: WalletSyncToken,
        range: RangeInclusive<u64>,
        follow_safe_head: bool,
    ) -> Result<(), Box<mpsc::error::TrySendError<BackfillRequest>>> {
        let (liveness, receiver) = oneshot::channel();
        self.accepted_backfill_liveness
            .push(accepted_backfill_owner_dropped(token, receiver));
        let driver = WalletBackfillGrant::for_actor_accepted_job_with_cancel(
            token,
            self.backfill_sender.clone(),
            liveness,
            self.cancel.clone(),
        )
        .activate();
        let (from_block, to_block) = range.into_inner();
        self.backfill_tx.try_send(BackfillRequest::add(
            self.cfg.cache_key.clone(),
            from_block,
            to_block,
            follow_safe_head,
            from_block,
            driver,
        ))?;
        let _ =
            self.actor_state
                .transition_active(&self.worker_handle, &self.cancel, |mut state| {
                    state.backfill_dispatch_admitted(token)
                });
        self.backfill_complete_block = None;
        self.live_rx = self.live_rx.resubscribe();
        Ok(())
    }
}
