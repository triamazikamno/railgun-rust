#[allow(clippy::wildcard_imports)]
use super::*;

impl WalletActorState {
    pub(in crate::wallet) fn new(
        chain_id: u64,
        actor_id: u64,
        reset_generation: u64,
        last_scanned: u64,
        highest_accepted_reset_intent: u64,
        pending_reset: Option<PendingWalletReset>,
        poi_corpus_refresh_pending: bool,
        initial_view: WalletViewState,
    ) -> (Self, watch::Receiver<WalletObservation>) {
        let (observation, observation_rx) = WalletObservationPublisher::new(initial_view);
        (
            Self {
                chain_id,
                actor_id,
                reset_generation,
                last_scanned,
                completed_target_block: None,
                poi_persistence_requirements: WalletPoiPersistenceRequirements::default(),
                reset_replay_persistence_requirement: None,
                progress_persistence_requirement: None,
                completion_persistence_requirement: None,
                job_failures: BTreeMap::new(),
                poi_corpus_refresh_pending,
                shutdown: false,
                highest_accepted_reset_intent,
                pending_reset,
                pending_reset_rewind_committed: false,
                pending_reset_replay_admitted: None,
                pending_reset_progress_start_block: None,
                active_jobs: BTreeMap::new(),
                highest_accepted_backfill_job_id: 0,
                latest_pending_overlay_job: None,
                observation,
            },
            observation_rx,
        )
    }

    pub(in crate::wallet) fn observation_publisher(&self) -> Arc<WalletObservationPublisher> {
        Arc::clone(&self.observation)
    }

    /// Lifecycle-authorized synchronous transition. The mutation facade cannot escape this
    /// call, and typed readiness is derived and published before it returns.
    pub(in crate::wallet) fn transition<R>(
        &mut self,
        _token: &WalletActorApplyToken<'_>,
        transition: impl for<'a> FnOnce(WalletActorMutation<'a>) -> R,
    ) -> R {
        let result = transition(WalletActorMutation { state: self });
        self.publish_derived_readiness();
        result
    }

    pub(in crate::wallet) fn transition_with_view<R>(
        &mut self,
        _token: &WalletActorApplyToken<'_>,
        view: WalletViewState,
        transition: impl for<'a> FnOnce(WalletActorMutation<'a>) -> R,
    ) -> R {
        let result = transition(WalletActorMutation { state: self });
        self.observation.publish(view, self.derived_readiness());
        result
    }

    pub(in crate::wallet) fn transition_with_view_and_ppoi_workflow_projection<R>(
        &mut self,
        _token: &WalletActorApplyToken<'_>,
        view: WalletViewState,
        projection: WalletPpoiWorkflowProjection,
        transition: impl for<'a> FnOnce(WalletActorMutation<'a>) -> R,
    ) -> R {
        let result = transition(WalletActorMutation { state: self });
        self.observation.publish_with_ppoi_workflow_projection(
            view,
            self.derived_readiness(),
            projection,
        );
        result
    }

    pub(in crate::wallet) fn transition_active<R>(
        &mut self,
        handle: &crate::wallet::WalletHandle,
        cancel: &CancellationToken,
        transition: impl for<'a> FnOnce(WalletActorMutation<'a>) -> R,
    ) -> Result<R, WalletBackfillRejectReason> {
        let reset_generation = self.reset_generation;
        handle.with_active_apply(cancel, reset_generation, |token| {
            self.transition(&token, transition)
        })
    }

    /// Dedicated terminal transition. The caller must hold the terminal lifecycle fence.
    pub(in crate::wallet) fn transition_terminal_shutdown(
        &mut self,
        _token: &WalletActorTerminalToken<'_>,
        reason: WalletInactiveReason,
        reset_generation: u64,
    ) {
        self.shutdown = true;
        self.active_jobs.clear();
        self.latest_pending_overlay_job = None;
        self.pending_reset_replay_admitted = None;
        self.pending_reset_progress_start_block = None;
        self.poi_persistence_requirements = WalletPoiPersistenceRequirements::default();
        self.reset_replay_persistence_requirement = None;
        self.progress_persistence_requirement = None;
        self.completion_persistence_requirement = None;
        self.job_failures.clear();
        self.observation.publish_terminal(reason, reset_generation);
    }

    fn publish_derived_readiness(&self) {
        self.observation.publish_readiness(self.derived_readiness());
    }

    fn derived_readiness(&self) -> WalletReadiness {
        if self.shutdown {
            return WalletReadiness::Shutdown;
        }
        if self.has_persistence_failure() {
            return WalletReadiness::Failed(WalletReadinessError::PersistenceFailed);
        }
        if let Some(failure) = self.job_failures.values().next() {
            return WalletReadiness::Failed(failure.reason.readiness_error());
        }
        if self.pending_reset.is_some() || self.poi_corpus_refresh_pending {
            return WalletReadiness::Syncing;
        }
        if self.active_jobs.values().any(|job| {
            matches!(
                job.kind,
                WalletActorJobKind::SyncTarget
                    | WalletActorJobKind::Backfill
                    | WalletActorJobKind::IndexedCatchUp
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

    pub(in crate::wallet) const fn reset_generation(&self) -> u64 {
        self.reset_generation
    }

    pub(in crate::wallet) const fn completed_target_block(&self) -> Option<u64> {
        self.completed_target_block
    }

    pub(in crate::wallet) const fn highest_accepted_reset_intent(&self) -> u64 {
        self.highest_accepted_reset_intent
    }

    pub(in crate::wallet) const fn pending_reset(&self) -> Option<PendingWalletReset> {
        self.pending_reset
    }

    pub(in crate::wallet) const fn pending_reset_rewind_committed(&self) -> bool {
        self.pending_reset_rewind_committed
    }

    pub(in crate::wallet) const fn pending_reset_replay_admitted(&self) -> Option<WalletSyncToken> {
        self.pending_reset_replay_admitted
    }

    pub(in crate::wallet) fn progress_start_block(&self, token: WalletSyncToken) -> Option<u64> {
        if self.pending_reset_replay_admitted == Some(token) {
            self.pending_reset_progress_start_block
        } else {
            None
        }
    }

    pub(in crate::wallet) const fn poi_corpus_refresh_pending(&self) -> bool {
        self.poi_corpus_refresh_pending
    }

    pub(in crate::wallet) const fn has_persistence_failure(&self) -> bool {
        !self.poi_persistence_requirements.is_empty()
            || self.reset_replay_persistence_requirement.is_some()
            || self.progress_persistence_requirement.is_some()
            || self.completion_persistence_requirement.is_some()
    }

    pub(in crate::wallet) fn failed_poi_status_refresh_selection(
        &self,
        reset_generation: u64,
    ) -> Option<WalletPoiRefreshSelection> {
        self.poi_persistence_requirements.next(reset_generation)
    }

    pub(in crate::wallet) fn has_failed_poi_status_refresh(
        &self,
        reset_generation: u64,
        selection: WalletPoiRefreshSelection,
    ) -> bool {
        self.poi_persistence_requirements
            .contains(reset_generation, selection)
    }

    pub(in crate::wallet) fn has_active_backfill_job(&self) -> bool {
        self.active_jobs
            .values()
            .any(|job| job.kind == WalletActorJobKind::Backfill)
    }

    pub(in crate::wallet) fn active_backfill_target(&self) -> Option<u64> {
        self.active_jobs
            .values()
            .filter(|job| job.kind == WalletActorJobKind::Backfill)
            .filter_map(|job| job.target_block)
            .max()
    }

    pub(in crate::wallet) fn pending_overlay_is_current(
        &self,
        token: WalletSyncToken,
        last_scanned: u64,
    ) -> bool {
        self.has_active_job(token)
            && self.latest_pending_overlay_job == Some(token.job_id())
            && last_scanned == self.last_scanned
            && self
                .active_jobs
                .get(&token.job_id())
                .is_some_and(|job| job.kind == WalletActorJobKind::PendingOverlay)
    }

    pub(in crate::wallet) fn validate_sync_token_current(
        &self,
        token: WalletSyncToken,
        handle: &crate::wallet::WalletHandle,
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

    pub(in crate::wallet) fn validate_active_backfill_token(
        &self,
        token: WalletSyncToken,
        handle: &crate::wallet::WalletHandle,
        cancel: &CancellationToken,
    ) -> Result<(), WalletBackfillRejectReason> {
        self.validate_sync_token_current(token, handle, cancel)?;
        if !self.is_active_job(token, WalletActorJobKind::Backfill) {
            return Err(WalletBackfillRejectReason::Shutdown);
        }
        Ok(())
    }

    pub(in crate::wallet) fn validate_reset_token_current(
        &self,
        token: WalletResetToken,
        handle: &crate::wallet::WalletHandle,
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

    pub(in crate::wallet) fn validate_private_request(
        &self,
        handle: &crate::wallet::WalletHandle,
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

    pub(in crate::wallet) fn validate_pending_overlay_request(
        &self,
        handle: &crate::wallet::WalletHandle,
        cancel: &CancellationToken,
    ) -> Result<u64, WalletPrivateRequestError> {
        handle.with_active_private_request(cancel, || Ok(self.reset_generation))
    }

    pub(super) fn is_active_job(&self, token: WalletSyncToken, kind: WalletActorJobKind) -> bool {
        token.chain_id() == self.chain_id
            && token.actor_id() == self.actor_id
            && token.reset_generation() == self.reset_generation
            && self.active_jobs.get(&token.job_id()).is_some_and(|job| {
                job.reset_generation == token.reset_generation() && job.kind == kind
            })
    }

    pub(super) fn has_active_job(&self, token: WalletSyncToken) -> bool {
        token.chain_id() == self.chain_id
            && token.actor_id() == self.actor_id
            && token.reset_generation() == self.reset_generation
            && self
                .active_jobs
                .get(&token.job_id())
                .is_some_and(|job| job.reset_generation == token.reset_generation())
    }
}

#[cfg(test)]
impl WalletActorState {
    pub(in crate::wallet) fn set_observation_publisher_for_test(
        &mut self,
        observation: Arc<WalletObservationPublisher>,
    ) {
        self.observation = observation;
    }

    pub(in crate::wallet) const fn last_scanned(&self) -> u64 {
        self.last_scanned
    }

    pub(in crate::wallet) fn test_readiness(&self) -> WalletReadiness {
        self.derived_readiness()
    }

    pub(in crate::wallet) fn test_active_job_count(&self) -> usize {
        self.active_jobs.len()
    }

    pub(in crate::wallet) fn test_job_failure_count(&self) -> usize {
        self.job_failures.len()
    }

    pub(in crate::wallet) const fn test_highest_accepted_backfill_job_id(&self) -> u64 {
        self.highest_accepted_backfill_job_id
    }

    pub(in crate::wallet) fn test_active_backfill_target_for(
        &self,
        token: WalletSyncToken,
    ) -> Option<u64> {
        self.active_jobs
            .get(&token.job_id())
            .filter(|job| job.kind == WalletActorJobKind::Backfill)
            .and_then(|job| job.target_block)
    }

    pub(in crate::wallet) fn test_persistence_range_for(
        &self,
        token: WalletSyncToken,
    ) -> Option<(u64, u64)> {
        self.progress_persistence_requirement
            .filter(|required| required.reset_generation == token.reset_generation())
            .map(|required| (required.range.from_block, required.range.to_block))
    }

    pub(in crate::wallet) fn test_completion_requirement(&self) -> Option<(WalletSyncToken, u64)> {
        self.completion_persistence_requirement
            .map(|required| (required.token, required.target_block))
    }

    pub(in crate::wallet) const fn test_reset_replay_requirement(&self) -> Option<u64> {
        self.reset_replay_persistence_requirement
    }

    pub(in crate::wallet) fn test_has_job_failure(&self, token: WalletSyncToken) -> bool {
        self.job_failures
            .get(&token.job_id())
            .is_some_and(|failure| failure.token == token)
    }

    pub(in crate::wallet) fn test_poi_requirement_count(&self) -> usize {
        usize::from(self.poi_persistence_requirements.required)
            + usize::from(self.poi_persistence_requirements.required_or_recoverable)
            + usize::from(
                self.poi_persistence_requirements
                    .recoverable_stale
                    .is_some(),
            )
            + usize::from(self.poi_persistence_requirements.recoverable)
            + usize::from(self.poi_persistence_requirements.corpus_revision.is_some())
    }

    pub(in crate::wallet) fn test_indexed_status(
        &self,
        token: WalletSyncToken,
    ) -> Option<&WalletIndexedCatchUpStatus> {
        self.active_jobs
            .get(&token.job_id())
            .and_then(|job| job.indexed_status.as_ref())
    }

    pub(in crate::wallet) fn test_transition<R>(
        &mut self,
        transition: impl for<'a> FnOnce(WalletActorMutation<'a>) -> R,
    ) -> R {
        let token = WalletActorApplyToken {
            _fence: PhantomData,
        };
        self.transition(&token, transition)
    }
}
