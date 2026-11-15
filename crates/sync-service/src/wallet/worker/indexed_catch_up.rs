#[allow(clippy::wildcard_imports)]
use super::*;
use crate::types::WalletIndexedCatchUpStatus;

impl WalletActorLoop<'_> {
    /// Handles an indexed catch-up job's claim or status publication.
    pub(super) async fn handle_indexed_catch_up_command(
        &mut self,
        command: WalletIndexedCatchUpCommand,
    ) {
        match command {
            WalletIndexedCatchUpCommand::Claim { response } => {
                self.claim_indexed_catch_up(response).await;
            }
            WalletIndexedCatchUpCommand::Publish { token, status } => {
                self.publish_indexed_catch_up_status(token, status).await;
            }
        }
    }

    /// Accepts a new indexed catch-up job and hands its lease to the claimant, or `None`
    /// when the actor cannot accept one.
    async fn claim_indexed_catch_up(
        &mut self,
        response: oneshot::Sender<Option<WalletIndexedCatchUpLease>>,
    ) {
        let authority = WalletPrivateMutationAuthority::new(
            &self.worker_handle,
            self.actor_state.reset_generation(),
            &self.cancel,
        );
        let permit = match authority.acquire().await {
            Ok(permit) => permit,
            Err(reason) => {
                let _ = response.send(None);
                debug!(?reason, cache_key = %self.cfg.cache_key, "indexed wallet catch-up status publication skipped");
                return;
            }
        };
        let token = self
            .worker_handle
            .mint_sync_token(self.actor_state.reset_generation());
        let accepted = permit
            .with_active_apply(|apply_token| {
                self.actor_state.transition(&apply_token, |mut state| {
                    state.accept_indexed_catch_up(token)
                })
            })
            .unwrap_or(false);
        let lease = if accepted {
            let (liveness, receiver) = oneshot::channel();
            self.accepted_indexed_job_liveness
                .push(accepted_indexed_job_owner_dropped(token, receiver));
            Some(WalletIndexedCatchUpLease::for_actor_accepted_job(
                token, liveness,
            ))
        } else {
            None
        };
        if let Err(lease) = response.send(lease) {
            drop(lease);
            let retired = permit
                .with_active_apply(|apply_token| {
                    self.actor_state
                        .transition(&apply_token, |mut state| state.retire_job(token))
                })
                .unwrap_or(false);
            if retired && let Err(reason) = permit.publish_indexed_catch_up(None) {
                debug!(?reason, cache_key = %self.cfg.cache_key, "indexed wallet catch-up dropped-claim status clear rejected");
            }
            debug!(cache_key = %self.cfg.cache_key, ?token, "indexed wallet catch-up claim receiver dropped");
        }
    }

    /// Publishes an indexed catch-up job's status while the job is still current.
    async fn publish_indexed_catch_up_status(
        &mut self,
        token: WalletSyncToken,
        status: WalletIndexedCatchUpStatus,
    ) {
        let authority = WalletPrivateMutationAuthority::new(
            &self.worker_handle,
            self.actor_state.reset_generation(),
            &self.cancel,
        );
        let permit = match authority.acquire().await {
            Ok(permit) => permit,
            Err(reason) => {
                debug!(?reason, cache_key = %self.cfg.cache_key, "indexed wallet catch-up status publication skipped");
                return;
            }
        };
        let published = permit
            .with_active_apply(|apply_token| {
                self.actor_state.transition(&apply_token, |mut state| {
                    state.publish_indexed_catch_up(token, status)
                })
            })
            .unwrap_or(false);
        if published {
            if let Err(reason) = permit.publish_indexed_catch_up(Some(status)) {
                debug!(?reason, cache_key = %self.cfg.cache_key, "indexed wallet catch-up status publication rejected");
            }
        } else {
            debug!(cache_key = %self.cfg.cache_key, ?token, "stale indexed wallet catch-up status publication ignored");
        }
    }

    /// Retires an indexed catch-up job whose owner went away and clears its published status.
    pub(super) async fn handle_indexed_job_owner_dropped(&mut self, token: WalletSyncToken) {
        let retired = self
            .actor_state
            .transition_active(&self.worker_handle, &self.cancel, |mut state| {
                state.retire_job(token)
            })
            .unwrap_or(false);
        if retired {
            let authority = WalletPrivateMutationAuthority::new(
                &self.worker_handle,
                self.actor_state.reset_generation(),
                &self.cancel,
            );
            if let Ok(permit) = authority.acquire().await
                && let Err(reason) = permit.publish_indexed_catch_up(None)
            {
                debug!(?reason, cache_key = %self.cfg.cache_key, "indexed wallet catch-up abandonment status clear rejected");
            }
        }
    }
}
