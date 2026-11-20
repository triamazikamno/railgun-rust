#[allow(clippy::wildcard_imports)]
use super::*;

impl WalletActorMutation<'_> {
    fn accept_job(&mut self, token: WalletSyncToken, kind: WalletActorJobKind) -> bool {
        if token.chain_id() != self.state.chain_id
            || token.actor_id() != self.state.actor_id
            || token.reset_generation() != self.state.reset_generation
        {
            return false;
        }
        if let Some(job) = self.state.active_jobs.get(&token.job_id()) {
            return job.kind == kind && job.reset_generation == token.reset_generation();
        }
        if kind == WalletActorJobKind::Backfill {
            if token.job_id() <= self.state.highest_accepted_backfill_job_id {
                return false;
            }
            self.state.highest_accepted_backfill_job_id = token.job_id();
        }
        self.state.active_jobs.insert(
            token.job_id(),
            WalletActorJob {
                reset_generation: token.reset_generation(),
                kind,
                target_block: None,
                indexed_status: None,
            },
        );
        if kind == WalletActorJobKind::PendingOverlay {
            self.state.latest_pending_overlay_job = Some(token.job_id());
        }
        true
    }

    pub(in crate::wallet) fn durable_poi_status_commit_ok(
        &mut self,
        reset_generation: u64,
        selection: WalletPoiRefreshSelection,
    ) {
        self.state
            .poi_persistence_requirements
            .remove(reset_generation, selection);
    }

    pub(in crate::wallet) fn poi_status_persist_failed(
        &mut self,
        reset_generation: u64,
        selection: WalletPoiRefreshSelection,
    ) {
        if reset_generation == self.state.reset_generation {
            self.state
                .poi_persistence_requirements
                .insert(reset_generation, selection);
        }
    }

    pub(in crate::wallet) fn durable_reset_replay_commit_ok(&mut self, intent_id: u64) {
        if self.state.reset_replay_persistence_requirement == Some(intent_id) {
            self.state.reset_replay_persistence_requirement = None;
        }
    }

    pub(in crate::wallet) const fn reset_replay_persist_failed(&mut self, intent_id: u64) {
        self.state.reset_replay_persistence_requirement = Some(intent_id);
    }

    pub(in crate::wallet) fn sync_progress_persist_failed(
        &mut self,
        token: WalletSyncToken,
        from_block: u64,
        to_block: u64,
    ) -> bool {
        if from_block > to_block
            || from_block != self.state.last_scanned.saturating_add(1)
            || !self
                .state
                .is_active_job(token, WalletActorJobKind::Backfill)
        {
            return false;
        }
        let incoming = WalletRequiredPersistRange {
            from_block,
            to_block,
        };
        self.state.progress_persistence_requirement = Some(
            self.state
                .progress_persistence_requirement
                .filter(|required| required.reset_generation == token.reset_generation())
                .map_or_else(
                    || WalletProgressPersistenceRequirement {
                        reset_generation: token.reset_generation(),
                        range: incoming,
                    },
                    |required| WalletProgressPersistenceRequirement {
                        reset_generation: required.reset_generation,
                        range: WalletRequiredPersistRange {
                            from_block: required.range.from_block.min(incoming.from_block),
                            to_block: required.range.to_block.max(incoming.to_block),
                        },
                    },
                ),
        );
        true
    }

    pub(in crate::wallet) fn durable_sync_progress_commit_ok(
        &mut self,
        token: WalletSyncToken,
        from_block: u64,
        to_block: u64,
    ) -> bool {
        if from_block > to_block
            || from_block != self.state.last_scanned.saturating_add(1)
            || !self
                .state
                .is_active_job(token, WalletActorJobKind::Backfill)
        {
            return false;
        }
        self.state.last_scanned = to_block;
        if let Some(mut required) = self.state.progress_persistence_requirement
            && required.reset_generation == token.reset_generation()
        {
            if required.range.to_block <= to_block {
                self.state.progress_persistence_requirement = None;
            } else {
                required.range.from_block =
                    required.range.from_block.max(to_block.saturating_add(1));
                self.state.progress_persistence_requirement = Some(required);
            }
        }
        true
    }

    pub(in crate::wallet) fn backfill_completion_persist_failed(
        &mut self,
        token: WalletSyncToken,
    ) -> bool {
        if !self
            .state
            .is_active_job(token, WalletActorJobKind::Backfill)
        {
            return false;
        }
        let Some(target_block) = self
            .state
            .active_jobs
            .get(&token.job_id())
            .and_then(|job| job.target_block)
        else {
            return false;
        };
        let incoming = WalletCompletionPersistenceRequirement {
            reset_generation: token.reset_generation(),
            token,
            target_block,
        };
        self.state.completion_persistence_requirement = Some(
            self.state
                .completion_persistence_requirement
                .filter(|required| required.reset_generation == token.reset_generation())
                .map_or(incoming, |required| {
                    if incoming.target_block > required.target_block
                        || (incoming.target_block == required.target_block
                            && incoming.token.job_id() < required.token.job_id())
                    {
                        incoming
                    } else {
                        required
                    }
                }),
        );
        true
    }

    pub(in crate::wallet) fn durable_backfill_completion_commit_ok(
        &mut self,
        token: WalletSyncToken,
    ) -> bool {
        if !self
            .state
            .is_active_job(token, WalletActorJobKind::Backfill)
        {
            return false;
        }
        let Some(target_block) = self
            .state
            .active_jobs
            .get(&token.job_id())
            .and_then(|job| job.target_block)
        else {
            return false;
        };
        if !self
            .state
            .completion_persistence_requirement
            .is_some_and(|required| {
                required.reset_generation == token.reset_generation()
                    && required.target_block <= target_block
            })
        {
            return false;
        }
        self.state.completion_persistence_requirement = None;
        true
    }

    pub(in crate::wallet) const fn set_poi_corpus_refresh_pending(&mut self, pending: bool) {
        self.state.poi_corpus_refresh_pending = pending;
    }

    pub(in crate::wallet) const fn observe_poi_corpus_revision(&mut self, changed: bool) {
        self.state.poi_corpus_refresh_pending |= changed;
    }

    pub(in crate::wallet) const fn mark_pending_reset_rewind_committed(
        &mut self,
        last_scanned: u64,
    ) {
        self.state.pending_reset_rewind_committed = true;
        self.state.last_scanned = last_scanned;
    }

    pub(in crate::wallet) const fn set_pending_reset_replay_admitted(
        &mut self,
        replay: Option<(WalletSyncToken, u64)>,
    ) {
        self.state.pending_reset_replay_admitted = match replay {
            Some((token, _)) => Some(token),
            None => None,
        };
        self.state.pending_reset_progress_start_block = match replay {
            Some((_, progress_start_block)) => Some(progress_start_block),
            None => None,
        };
    }

    pub(in crate::wallet) const fn clear_pending_reset(&mut self) {
        self.state.pending_reset = None;
        self.state.pending_reset_rewind_committed = false;
    }

    pub(in crate::wallet) fn accept_target(
        &mut self,
        token: WalletSyncToken,
        target_block: u64,
    ) -> bool {
        if self.state.has_active_job(token) || !self.accept_job(token, WalletActorJobKind::Backfill)
        {
            return false;
        }
        self.state
            .active_jobs
            .get_mut(&token.job_id())
            .expect("accepted backfill job exists")
            .target_block = Some(target_block);
        true
    }

    pub(in crate::wallet) fn accept_sync_target(
        &mut self,
        token: WalletSyncToken,
        target_block: u64,
    ) -> bool {
        if self.state.has_active_job(token)
            || !self.accept_job(token, WalletActorJobKind::SyncTarget)
        {
            return false;
        }
        self.state
            .active_jobs
            .get_mut(&token.job_id())
            .expect("accepted sync target job exists")
            .target_block = Some(target_block);
        true
    }

    pub(in crate::wallet) fn update_target(
        &mut self,
        token: WalletSyncToken,
        target_block: u64,
    ) -> Option<u64> {
        if !self
            .state
            .is_active_job(token, WalletActorJobKind::Backfill)
        {
            return None;
        }
        let job = self
            .state
            .active_jobs
            .get_mut(&token.job_id())
            .expect("validated backfill job exists");
        let target_block = job
            .target_block
            .map_or(target_block, |current| current.max(target_block));
        job.target_block = Some(target_block);
        Some(target_block)
    }

    pub(in crate::wallet) fn complete_backfill_job(&mut self, token: WalletSyncToken) -> bool {
        if !self
            .state
            .is_active_job(token, WalletActorJobKind::Backfill)
        {
            return false;
        }
        let Some(target_block) = self
            .state
            .active_jobs
            .get(&token.job_id())
            .filter(|job| job.kind == WalletActorJobKind::Backfill)
            .and_then(|job| job.target_block)
        else {
            return false;
        };
        self.state.completed_target_block = Some(
            self.state
                .completed_target_block
                .map_or(target_block, |completed| completed.max(target_block)),
        );
        self.retire_job(token)
    }

    pub(in crate::wallet) fn retire_job(&mut self, token: WalletSyncToken) -> bool {
        if !self.state.has_active_job(token) {
            return false;
        }
        self.remove_job(token)
    }

    fn remove_job(&mut self, token: WalletSyncToken) -> bool {
        let retired = self.state.active_jobs.remove(&token.job_id()).is_some();
        if retired && self.state.pending_reset_replay_admitted == Some(token) {
            self.state.pending_reset_replay_admitted = None;
            self.state.pending_reset_progress_start_block = None;
        }
        retired
    }

    fn fail_job(&mut self, token: WalletSyncToken, reason: WalletJobFailureReason) -> bool {
        if !self.state.has_active_job(token) {
            return false;
        }
        let target_block = self
            .state
            .active_jobs
            .get(&token.job_id())
            .and_then(|job| job.target_block)
            .unwrap_or(self.state.last_scanned);
        let retired = self.remove_job(token);
        if retired {
            self.state
                .job_failures
                .entry(token.job_id())
                .or_insert(WalletJobFailure {
                    token,
                    target_block,
                    reason,
                });
        }
        retired
    }

    pub(in crate::wallet) fn fail_job_backfill_unavailable(
        &mut self,
        token: WalletSyncToken,
    ) -> bool {
        self.fail_job(token, WalletJobFailureReason::BackfillUnavailable)
    }

    pub(in crate::wallet) fn fail_job_target_not_reached(
        &mut self,
        token: WalletSyncToken,
        target_block: u64,
    ) -> bool {
        self.fail_job(
            token,
            WalletJobFailureReason::TargetNotReached { target_block },
        )
    }

    pub(in crate::wallet) fn fail_job_apply_failed(&mut self, token: WalletSyncToken) -> bool {
        self.fail_job(token, WalletJobFailureReason::ApplyFailed)
    }

    pub(in crate::wallet) fn backfill_dispatch_admitted(&mut self, token: WalletSyncToken) -> bool {
        if !self
            .state
            .is_active_job(token, WalletActorJobKind::Backfill)
        {
            return false;
        }
        let Some(target_block) = self
            .state
            .active_jobs
            .get(&token.job_id())
            .and_then(|job| job.target_block)
        else {
            return false;
        };
        let before = self.state.job_failures.len();
        self.state.job_failures.retain(|_, failure| {
            failure.token.reset_generation() != token.reset_generation()
                || failure.target_block > target_block
        });
        self.state.job_failures.len() != before
    }

    pub(in crate::wallet) fn apply_backfill_owner_disposition(
        &mut self,
        token: WalletSyncToken,
        disposition: WalletBackfillOwnerDisposition,
    ) -> bool {
        match disposition {
            WalletBackfillOwnerDisposition::BenignRetirement => self.retire_job(token),
            WalletBackfillOwnerDisposition::DriverLost => self.fail_job_backfill_unavailable(token),
        }
    }

    pub(in crate::wallet) fn accept_indexed_catch_up(&mut self, token: WalletSyncToken) -> bool {
        if self
            .state
            .active_jobs
            .values()
            .any(|job| job.kind == WalletActorJobKind::IndexedCatchUp)
        {
            return false;
        }
        self.accept_job(token, WalletActorJobKind::IndexedCatchUp)
    }

    pub(in crate::wallet) fn publish_indexed_catch_up(
        &mut self,
        token: WalletSyncToken,
        status: WalletIndexedCatchUpStatus,
    ) -> bool {
        if !self
            .state
            .is_active_job(token, WalletActorJobKind::IndexedCatchUp)
        {
            return false;
        }
        self.state
            .active_jobs
            .get_mut(&token.job_id())
            .expect("validated indexed catch-up job exists")
            .indexed_status = Some(status);
        true
    }

    pub(in crate::wallet) fn accept_pending_overlay(
        &mut self,
        token: WalletSyncToken,
        last_scanned: u64,
    ) -> bool {
        token.reset_generation() == self.state.reset_generation
            && last_scanned == self.state.last_scanned
            && self
                .state
                .latest_pending_overlay_job
                .is_none_or(|latest| token.job_id() > latest)
            && self.accept_job(token, WalletActorJobKind::PendingOverlay)
    }

    pub(in crate::wallet) fn accept_reset(&mut self, pending: PendingWalletReset) -> bool {
        self.state
            .poi_persistence_requirements
            .rebase(pending.reset_generation);
        self.state.reset_replay_persistence_requirement = None;
        self.state.progress_persistence_requirement = None;
        self.state.completion_persistence_requirement = None;
        self.state.job_failures.clear();
        self.state.highest_accepted_reset_intent = pending.intent_id;
        self.state.pending_reset = Some(pending);
        self.state.reset_generation = pending.reset_generation;
        self.state.pending_reset_rewind_committed = false;
        self.state.pending_reset_replay_admitted = None;
        self.state.pending_reset_progress_start_block = None;
        let indexed_catch_up_was_active = self
            .state
            .active_jobs
            .values()
            .any(|job| job.kind == WalletActorJobKind::IndexedCatchUp);
        self.state.active_jobs.clear();
        self.state.latest_pending_overlay_job = None;
        self.state.completed_target_block = None;
        indexed_catch_up_was_active
    }
}

#[cfg(test)]
impl WalletActorMutation<'_> {
    pub(in crate::wallet) const fn update_cursor(&mut self, last_scanned: u64) {
        self.state.last_scanned = last_scanned;
    }

    pub(in crate::wallet) fn test_accept_backfill_job_id(
        &mut self,
        token: WalletSyncToken,
    ) -> bool {
        self.accept_job(token, WalletActorJobKind::Backfill)
    }
}
