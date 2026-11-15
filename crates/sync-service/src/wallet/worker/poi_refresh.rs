#[allow(clippy::wildcard_imports)]
use super::*;
use crate::wallet::handle::WalletPoiRefreshRequest;

impl WalletActorLoop<'_> {
    /// Refreshes POI statuses from the local corpus when `selection` needs it.
    /// Returns `None` when no refresh was attempted.
    async fn commit_local_poi_status_refresh(
        &mut self,
        selection: WalletPoiRefreshSelection,
    ) -> Option<Result<bool, WalletBackfillRejectReason>> {
        let reset_generation = self.actor_state.reset_generation();
        let refresh_needed = self
            .poi_status_refresh_needed(reset_generation, selection)
            .await;
        if refresh_needed {
            if let Some(status_reader) = self.local_poi_status_reader().await {
                Some(
                    self.commit_poi_status_refresh(&status_reader, reset_generation, selection)
                        .await,
                )
            } else {
                None
            }
        } else {
            None
        }
    }

    /// Whether `selection` has POI statuses to refresh, or a failed refresh to retry.
    pub(super) async fn poi_status_refresh_needed(
        &self,
        reset_generation: u64,
        selection: WalletPoiRefreshSelection,
    ) -> bool {
        let locked = self.utxos.read().await;
        self.actor_state
            .has_failed_poi_status_refresh(reset_generation, selection)
            || wallet_poi_status_refresh_needed_for_selection(
                &locked,
                &self.active_poi_list_keys,
                selection,
            )
    }

    /// Actor-safe: only a local corpus reader, never the remote proxy or fallback.
    pub(super) async fn local_poi_status_reader(&self) -> Option<LocalPoiStatusReader> {
        self.poi_runtime
            .local_status_reader(
                &self.public_data_plane,
                &self.cfg,
                &self.active_poi_list_keys,
            )
            .await
    }

    pub(super) async fn commit_poi_status_refresh(
        &mut self,
        status_reader: &LocalPoiStatusReader,
        reset_generation: u64,
        selection: WalletPoiRefreshSelection,
    ) -> Result<bool, WalletBackfillRejectReason> {
        WalletPoiStatusRefreshCommitRequest {
            cache_store: self.cache_store.as_ref(),
            cfg: &self.cfg,
            utxos: &self.utxos,
            worker_handle: &self.worker_handle,
            last_scanned: self.last_scanned,
            reset_generation,
            actor_state: &mut self.actor_state,
            persist_state: &mut self.persist_state,
            status_reader,
            active_poi_list_keys: &self.active_poi_list_keys,
            selection,
            cancel: &self.cancel,
        }
        .commit()
        .await
    }

    /// Reads the latest committed PPOI corpus revision and records what changed.
    /// Returns `None` when the wallet has no corpus revision feed.
    pub(super) fn observe_poi_corpus_revision(&mut self) -> Option<PoiCorpusRevision> {
        let revision = *self.poi_corpus_revision_rx.as_mut()?.borrow_and_update();
        let _ =
            self.actor_state
                .transition_active(&self.worker_handle, &self.cancel, |mut state| {
                    state.observe_poi_corpus_revision(revision != self.last_poi_corpus_revision);
                });
        self.blocked_shield_refresh_pending |= revision.blocked_shields_revision
            != self.last_poi_corpus_revision.blocked_shields_revision;
        self.last_poi_corpus_revision = revision;
        Some(revision)
    }

    /// Whether the backfill completed and no reset is pending.
    const fn is_caught_up(&self) -> bool {
        self.backfill_complete_block.is_some() && self.actor_state.pending_reset().is_none()
    }

    /// A refresh for POI statuses the PPOI corpus changed, including blocked-shield
    /// changes still pending.
    const fn corpus_revision_selection(&self) -> WalletPoiRefreshSelection {
        WalletPoiRefreshSelection::CorpusRevision {
            blocked_shields_changed: self.blocked_shield_refresh_pending,
        }
    }

    /// Whether the wallet still holds POI statuses that `selection` would refresh.
    async fn selection_needs_poi_refresh(&self, selection: WalletPoiRefreshSelection) -> bool {
        let locked = self.utxos.read().await;
        wallet_poi_status_refresh_needed_for_selection(
            &locked,
            &self.active_poi_list_keys,
            selection,
        )
    }

    fn mark_corpus_refresh_done(&mut self) {
        self.blocked_shield_refresh_pending = false;
        let _ =
            self.actor_state
                .transition_active(&self.worker_handle, &self.cancel, |mut state| {
                    state.set_poi_corpus_refresh_pending(false);
                });
    }

    fn mark_corpus_refresh_pending(&mut self) {
        let _ =
            self.actor_state
                .transition_active(&self.worker_handle, &self.cancel, |mut state| {
                    state.set_poi_corpus_refresh_pending(true);
                });
    }

    /// Clears a pending corpus refresh once nothing is left for `selection` to refresh.
    async fn clear_corpus_refresh_if_done(&mut self, selection: WalletPoiRefreshSelection) {
        if self.actor_state.poi_corpus_refresh_pending()
            && !self.selection_needs_poi_refresh(selection).await
        {
            self.mark_corpus_refresh_done();
        }
    }

    /// Handles a wallet handle's request for a POI refresh: refreshes local statuses and
    /// requests POI maintenance, or latches the request until the wallet is ready.
    pub(super) async fn handle_poi_refresh_request(&mut self, request: WalletPoiRefreshRequest) {
        let Some(_client) = self.poi_status_client.as_ref() else {
            return;
        };
        if self.actor_state.pending_reset().is_some() {
            let _ = self
                .poi_maintenance
                .request(request.force_output_poi_recovery, false, None);
            debug!(
                cache_key = %self.cfg.cache_key,
                "wallet POI refresh latched while reset commit is pending"
            );
            return;
        }
        if self.backfill_complete_block.is_none() {
            let _ = self
                .poi_maintenance
                .request(request.force_output_poi_recovery, false, None);
            debug!(
                cache_key = %self.cfg.cache_key,
                "wallet POI refresh latched until backfill complete"
            );
            return;
        }
        let current_reset_generation = self.actor_state.reset_generation();
        // Local-only status refresh on actor; remote readers must not block the loop.
        if let Some(status_reader) = self.local_poi_status_reader().await {
            match self
                .commit_poi_status_refresh(
                    &status_reader,
                    current_reset_generation,
                    WalletPoiRefreshSelection::Recoverable,
                )
                .await
            {
                Ok(changed) => {
                    debug!(
                        cache_key = %self.cfg.cache_key,
                        changed,
                        "manual local wallet POI status refresh committed"
                    );
                }
                Err(reason) => {
                    warn!(?reason, cache_key = %self.cfg.cache_key, "manual wallet POI status refresh rejected");
                }
            }
        }
        let _ = self.request_poi_maintenance(request.force_output_poi_recovery);
    }

    /// Catches up with a newly committed PPOI corpus revision: refreshes tentative pending
    /// output statuses and the wallet's POI statuses the revision affects. `None` means
    /// the revision feed closed.
    pub(super) async fn handle_poi_corpus_revision(&mut self, revision: Option<PoiCorpusRevision>) {
        let Some(mut revision) = revision else {
            self.poi_corpus_revision_rx = None;
            return;
        };
        let _ =
            self.actor_state
                .transition_active(&self.worker_handle, &self.cancel, |mut state| {
                    state.observe_poi_corpus_revision(revision != self.last_poi_corpus_revision);
                });
        let _revision_fence = match self.poi_corpus_handle.as_ref() {
            Some(corpus) => Some(corpus.revision_read_fence().await),
            None => None,
        };
        if let Some(revision_rx) = self.poi_corpus_revision_rx.as_mut() {
            revision = *revision_rx.borrow_and_update();
        }
        refresh_tentative_pending_output_poi_statuses(
            &self.worker_handle,
            &self.cancel,
            self.poi_corpus_handle.as_ref(),
            &self.cfg,
            &self.active_poi_list_keys,
            self.actor_state.reset_generation(),
            &mut self.pending_output_poi_tentative_attempts,
        )
        .await;
        let _ =
            self.actor_state
                .transition_active(&self.worker_handle, &self.cancel, |mut state| {
                    state.observe_poi_corpus_revision(revision != self.last_poi_corpus_revision);
                });
        debug!(
            cache_key = %self.cfg.cache_key,
            revision = revision.revision,
            blocked_shields_revision = revision.blocked_shields_revision,
            backfill_complete = self.backfill_complete_block.is_some(),
            reset_pending = self.actor_state.pending_reset().is_some(),
            "committed PPOI corpus revision observed"
        );
        let blocked_shields_changed = revision.blocked_shields_revision
            != self.last_poi_corpus_revision.blocked_shields_revision;
        self.last_poi_corpus_revision = revision;
        self.blocked_shield_refresh_pending |= blocked_shields_changed;
        self.refresh_poi_statuses_for_corpus_revision(revision)
            .await;
    }

    /// Refreshes POI statuses for `revision` once the wallet is ready.
    async fn refresh_poi_statuses_for_corpus_revision(&mut self, revision: PoiCorpusRevision) {
        if self.is_caught_up()
            && let Some(result) = self
                .commit_local_poi_status_refresh(self.corpus_revision_selection())
                .await
        {
            match result {
                Ok(changed) => {
                    self.mark_corpus_refresh_done();
                    debug!(
                        cache_key = %self.cfg.cache_key,
                        revision = revision.revision,
                        changed,
                        "corpus revision local wallet POI status refresh committed"
                    );
                }
                Err(reason) => warn!(
                    ?reason,
                    cache_key = %self.cfg.cache_key,
                    revision = revision.revision,
                    "corpus revision wallet POI status refresh rejected"
                ),
            }
        }
        self.clear_corpus_refresh_if_done(self.corpus_revision_selection())
            .await;
    }

    /// Periodic local POI status refresh, followed by a POI maintenance request.
    pub(super) async fn handle_poi_status_tick(&mut self) {
        let Some(_client) = self.poi_status_client.as_ref() else {
            return;
        };
        self.observe_poi_corpus_revision();
        let _revision_fence = match self.poi_corpus_handle.as_ref() {
            Some(corpus) => Some(corpus.revision_read_fence().await),
            None => None,
        };
        let selection = self.periodic_poi_refresh_selection(now_epoch_secs());
        if let Some(result) = self.commit_local_poi_status_refresh(selection).await {
            match result {
                Ok(changed) => {
                    self.mark_corpus_refresh_done();
                    debug!(
                        cache_key = %self.cfg.cache_key,
                        changed,
                        "periodic local wallet POI status refresh committed"
                    );
                }
                Err(reason) => {
                    warn!(?reason, cache_key = %self.cfg.cache_key, "periodic wallet POI status refresh rejected");
                }
            }
        }
        self.clear_corpus_refresh_if_done(selection).await;
        let _ = self.request_poi_maintenance(false);
    }

    /// Pending corpus changes first, then a failed refresh to retry, otherwise statuses
    /// that went stale by `now`.
    fn periodic_poi_refresh_selection(&self, now: u64) -> WalletPoiRefreshSelection {
        if self.actor_state.poi_corpus_refresh_pending() || self.blocked_shield_refresh_pending {
            self.corpus_revision_selection()
        } else if let Some(failed_selection) = self
            .actor_state
            .failed_poi_status_refresh_selection(self.actor_state.reset_generation())
        {
            failed_selection
        } else {
            WalletPoiRefreshSelection::RecoverableStale { now }
        }
    }

    /// After the last backfill job retired, catches up with the committed PPOI corpus and
    /// refreshes the POI statuses a corpus change left pending.
    pub(super) async fn refresh_poi_statuses_after_backfill_retirement(&mut self) {
        if self
            .poi_corpus_revision_rx
            .as_ref()
            .is_some_and(|revision_rx| *revision_rx.borrow() != self.last_poi_corpus_revision)
        {
            let _ = self.actor_state.transition_active(
                &self.worker_handle,
                &self.cancel,
                |mut state| state.observe_poi_corpus_revision(true),
            );
        }
        let _revision_fence = match self.poi_corpus_handle.as_ref() {
            Some(corpus) => Some(corpus.revision_read_fence().await),
            None => None,
        };
        if self.observe_poi_corpus_revision().is_none()
            || !self.actor_state.poi_corpus_refresh_pending()
        {
            return;
        }
        let selection = self.corpus_revision_selection();
        let result = self.commit_local_poi_status_refresh(selection).await;
        let refresh_still_needed =
            result.is_none() && self.selection_needs_poi_refresh(selection).await;
        match result {
            None if refresh_still_needed => self.mark_corpus_refresh_pending(),
            Some(Ok(_)) | None => self.mark_corpus_refresh_done(),
            Some(Err(reason)) => {
                warn!(?reason, cache_key = %self.cfg.cache_key, "target retirement POI status refresh rejected");
                self.mark_corpus_refresh_pending();
            }
        }
    }
}
