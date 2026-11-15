#[allow(clippy::wildcard_imports)]
use super::*;
use crate::wallet::handle::WalletPendingOverlayRequest;
use railgun_wallet::scan::CommitmentObservation;

impl WalletActorLoop<'_> {
    /// Publishes a chain pending overlay update, then schedules tentative PPOI
    /// submissions for the commitments it observed.
    pub(super) async fn handle_pending_overlay(&mut self, request: WalletPendingOverlayRequest) {
        let current_reset_generation = self.actor_state.reset_generation();
        if !self.accept_pending_overlay(&request, current_reset_generation) {
            return;
        }
        self.pending_output_poi_tentative_attempts
            .clear_generation(current_reset_generation);
        let Some(tentative_observations) = self
            .publish_pending_overlay(request, current_reset_generation)
            .await
        else {
            return;
        };
        if !tentative_observations.is_empty() {
            self.schedule_tentative_pending_output_pois(&tentative_observations);
        }
    }

    /// Accepts an overlay update only when it matches the actor's current view.
    fn accept_pending_overlay(
        &mut self,
        request: &WalletPendingOverlayRequest,
        current_reset_generation: u64,
    ) -> bool {
        let request_is_current = self.actor_state.pending_reset().is_none()
            && request.reset_generation == current_reset_generation
            && request.last_scanned == self.last_scanned;
        let accepted = request_is_current
            && self
                .actor_state
                .transition_active(&self.worker_handle, &self.cancel, |mut state| {
                    state.accept_pending_overlay(request.token, request.last_scanned)
                })
                .unwrap_or(false);
        if !accepted {
            debug!(
                cache_key = %self.cfg.cache_key,
                token = ?request.token,
                request_reset_generation = request.reset_generation,
                current_reset_generation,
                request_last_scanned = request.last_scanned,
                current_last_scanned = self.last_scanned,
                pending_reset = self.actor_state.pending_reset().is_some(),
                "ignoring stale pending overlay update"
            );
        }
        accepted
    }

    /// Builds and publishes the overlay under a mutation permit, retiring the request's
    /// job either way. Returns the commitment observations to schedule tentative
    /// submissions for, or `None` when the update was dropped.
    async fn publish_pending_overlay(
        &mut self,
        request: WalletPendingOverlayRequest,
        current_reset_generation: u64,
    ) -> Option<Vec<CommitmentObservation>> {
        let authority = WalletPrivateMutationAuthority::new(
            &self.worker_handle,
            current_reset_generation,
            &self.cancel,
        );
        let permit = match authority.acquire().await {
            Ok(guard) => guard,
            Err(reason) => {
                debug!(?reason, cache_key = %self.cfg.cache_key, "pending overlay update rejected");
                let _ = self.actor_state.transition_active(
                    &self.worker_handle,
                    &self.cancel,
                    |mut state| state.retire_job(request.token),
                );
                return None;
            }
        };
        let job = OverlayJob {
            permit: &permit,
            token: request.token,
            last_scanned: request.last_scanned,
        };
        if !job.still_current(&mut self.actor_state) {
            return None;
        }
        let mut tentative_observations = Vec::new();
        let mut overlay = match request.update {
            WalletPendingOverlayUpdate::Clear => {
                self.pending_output_poi_tentative_attempts.clear();
                WalletPendingOverlay::default()
            }
            WalletPendingOverlayUpdate::PublicRows(rows) => {
                let mut delta = log_delta_for_rows(rows.payload, &self.cfg);
                tentative_observations = std::mem::take(&mut delta.commitment_observations);
                let reset_generation = self.actor_state.reset_generation();
                self.pending_output_poi_tentative_attempts
                    .prune_for_observations(reset_generation, &tentative_observations);
                let confirmed = self.utxos.read().await;
                if !job.still_current(&mut self.actor_state) {
                    return None;
                }
                pending_overlay_from_delta(&self.cfg, &confirmed, delta)
            }
        };
        self.pending_output_poi_tentative_attempts.apply_to_overlay(
            self.actor_state.reset_generation(),
            &mut overlay,
            now_epoch_secs(),
        );
        let changed = match permit.replace_chain_pending_overlay(overlay).await {
            Ok(changed) => changed,
            Err(reason) => {
                debug!(?reason, cache_key = %self.cfg.cache_key, "pending overlay update rejected before publication");
                job.retire(&mut self.actor_state);
                return None;
            }
        };
        if let Err(reason) = permit.notify_if_changed(changed).await {
            debug!(?reason, cache_key = %self.cfg.cache_key, "pending overlay revision publication rejected");
        }
        job.retire(&mut self.actor_state);
        Some(tentative_observations)
    }

    /// Reserves tentative PPOI candidates for newly observed commitments and starts a
    /// submission job for the reserved ones.
    fn schedule_tentative_pending_output_pois(
        &mut self,
        tentative_observations: &[CommitmentObservation],
    ) {
        let observation_count = tentative_observations.len();
        let mut candidate_count = 0;
        let mut reserved_count = 0;
        let tentative_candidates = match prepare_pending_output_poi_tentative_candidates(
            self.cache_store.as_ref(),
            &self.cfg,
            &self.active_poi_list_keys,
            tentative_observations,
        ) {
            Ok(candidates) => {
                candidate_count = candidates.len();
                let reserved = candidates
                    .into_iter()
                    .filter(|candidate| {
                        self.pending_output_poi_tentative_attempts
                            .reserve(self.actor_state.reset_generation(), candidate.clone())
                    })
                    .collect::<Vec<_>>();
                reserved_count = reserved.len();
                reserved
            }
            Err(_err) => Vec::new(),
        };
        if reserved_count > 0 {
            info!(
                observations = observation_count,
                candidates = candidate_count,
                reserved = reserved_count,
                "tentative pending output POI candidates scheduled"
            );
        }
        if !tentative_candidates.is_empty() {
            spawn_pending_output_poi_tentative_job(
                &self.poi_jobs,
                &self.worker_handle,
                &self.cancel,
                &self.remote_done_tx,
                &self.cache_store,
                &self.cfg,
                self.poi_runtime,
                &self.poi_submitter,
                &self.active_poi_list_keys,
                tentative_candidates,
            );
        }
    }
}

/// An accepted overlay request's job, checked and retired under one mutation permit.
struct OverlayJob<'p, 'a> {
    permit: &'p WalletPrivateMutationPermit<'a>,
    token: WalletSyncToken,
    last_scanned: u64,
}

impl OverlayJob<'_, '_> {
    /// Whether the job is still current under the permit; retires it when not.
    fn still_current(&self, actor_state: &mut WalletActorState) -> bool {
        let current = actor_state.pending_overlay_is_current(self.token, self.last_scanned)
            && self.permit.revalidate().is_ok();
        if !current {
            self.retire(actor_state);
        }
        current
    }

    /// Retires the job under the permit's active-apply fence.
    fn retire(&self, actor_state: &mut WalletActorState) {
        let _ = self.permit.with_active_apply(|token| {
            actor_state.transition(&token, |mut state| {
                state.retire_job(self.token);
            });
        });
    }
}

fn log_delta_for_rows(payload: WalletScanRowsPayload, cfg: &WalletConfig) -> WalletLogDelta {
    match payload {
        WalletScanRowsPayload::Rows(rows) => WalletLogDelta::from_rows(&rows, &cfg.scan_keys),
        WalletScanRowsPayload::EmptyCoverage => WalletLogDelta {
            utxos: Vec::new(),
            nullifiers: Vec::new(),
            commitment_observations: Vec::new(),
            sender_scan_outputs: Vec::new(),
        },
        #[cfg(test)]
        WalletScanRowsPayload::IndexedDeltaForTest { delta } => *delta,
    }
}
