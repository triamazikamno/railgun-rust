use railgun_wallet::Utxo;

use crate::wallet::handle::WalletPrivateViewTicket;

use super::{
    Arc, CancellationToken, ChainPoiSubmitterHandle, ChainPublicDataPlane, DbStore, FixedBytes,
    PendingOutputPoiContextIntent, RwLock, WalletActorState, WalletBackfillRejectReason,
    WalletCacheStore, WalletConfig, WalletHandle, WalletPendingSpentMarkOutcome,
    WalletPersistState, WalletPoiRefreshSelection, WalletPoiRuntime,
    WalletPoiStatusRefreshCommitRequest, WalletPrivateApplyRequest, WalletPrivateRequest,
    WalletPrivateRequestError, WalletUtxo,
    apply_owned_poi_private_delta_on_actor_with_active_lists, clear_local_pending_spent,
    commit_pending_output_contexts, mark_local_pending_spent, oneshot,
    wallet_poi_status_refresh_needed_for_selection,
};

/// State and services the wallet actor task works with across loop iterations.
pub(super) struct WalletActorLoop<'a> {
    pub(super) cfg: WalletConfig,
    pub(super) cache_store: Arc<dyn WalletCacheStore>,
    pub(super) utxos: Arc<RwLock<Vec<WalletUtxo>>>,
    pub(super) worker_handle: WalletHandle,
    pub(super) cancel: CancellationToken,
    /// Borrowed because the task's public POI client borrows it for the whole loop.
    pub(super) poi_runtime: &'a WalletPoiRuntime,
    pub(super) public_data_plane: ChainPublicDataPlane,
    pub(super) active_poi_list_keys: Vec<FixedBytes<32>>,
    pub(super) actor_state: WalletActorState,
    pub(super) persist_state: WalletPersistState,
    pub(super) last_scanned: u64,
    pub(super) db: Arc<DbStore>,
    pub(super) poi_submitter: ChainPoiSubmitterHandle,
}

impl WalletActorLoop<'_> {
    /// Refreshes POI statuses from the local corpus when `selection` needs it.
    /// Returns `None` when no refresh was attempted.
    pub(super) async fn commit_local_poi_status_refresh(
        &mut self,
        selection: WalletPoiRefreshSelection,
    ) -> Option<Result<bool, WalletBackfillRejectReason>> {
        let reset_generation = self.actor_state.reset_generation();
        let refresh_needed = {
            let locked = self.utxos.read().await;
            self.actor_state
                .has_failed_poi_status_refresh(reset_generation, selection)
                || wallet_poi_status_refresh_needed_for_selection(
                    &locked,
                    &self.active_poi_list_keys,
                    selection,
                )
        };
        if refresh_needed {
            if let Some(status_reader) = self
                .poi_runtime
                .local_status_reader(
                    &self.public_data_plane,
                    &self.cfg,
                    &self.active_poi_list_keys,
                )
                .await
            {
                Some(
                    (WalletPoiStatusRefreshCommitRequest {
                        cache_store: self.cache_store.as_ref(),
                        cfg: &self.cfg,
                        utxos: &self.utxos,
                        worker_handle: &self.worker_handle,
                        last_scanned: self.last_scanned,
                        reset_generation,
                        actor_state: &mut self.actor_state,
                        persist_state: &mut self.persist_state,
                        status_reader: &status_reader,
                        active_poi_list_keys: &self.active_poi_list_keys,
                        selection,
                        cancel: &self.cancel,
                    })
                    .commit()
                    .await,
                )
            } else {
                None
            }
        } else {
            None
        }
    }

    /// Commits a private POI delta that a remote job sent back to the actor.
    pub(super) async fn handle_private_apply(&self, apply_req: WalletPrivateApplyRequest) {
        let WalletPrivateApplyRequest {
            reset_generation,
            delta,
            reply,
        } = apply_req;
        let result = apply_owned_poi_private_delta_on_actor_with_active_lists(
            &self.worker_handle,
            &self.cancel,
            reset_generation,
            self.db.as_ref(),
            self.cache_store.as_ref(),
            &self.cfg,
            &self.active_poi_list_keys,
            delta,
        )
        .await;
        let _ = reply.send(result);
    }

    /// Answers a private-state request from a wallet handle.
    pub(super) async fn handle_private_request(&self, request: WalletPrivateRequest) {
        match request {
            WalletPrivateRequest::MarkLocalPendingSpent {
                utxos,
                tx_hash,
                reply,
            } => {
                self.handle_mark_local_pending_spent(utxos, tx_hash, reply)
                    .await;
            }
            WalletPrivateRequest::ClearLocalPendingSpent { reply } => {
                self.handle_clear_local_pending_spent(reply).await;
            }
            WalletPrivateRequest::CreatePendingOutputContexts {
                ticket,
                contexts,
                reply,
            } => {
                self.handle_create_pending_output_contexts(ticket, contexts, reply)
                    .await;
            }
        }
    }

    async fn handle_mark_local_pending_spent(
        &self,
        utxos: Vec<Utxo>,
        tx_hash: Option<FixedBytes<32>>,
        reply: oneshot::Sender<Result<WalletPendingSpentMarkOutcome, WalletPrivateRequestError>>,
    ) {
        let result = match self
            .actor_state
            .validate_pending_overlay_request(&self.worker_handle, &self.cancel)
        {
            Ok(reset_generation) => {
                mark_local_pending_spent(
                    &self.worker_handle,
                    &self.cancel,
                    reset_generation,
                    utxos,
                    tx_hash,
                )
                .await
            }
            Err(err) => Err(err),
        };
        let _ = reply.send(result);
    }

    async fn handle_clear_local_pending_spent(
        &self,
        reply: oneshot::Sender<Result<bool, WalletPrivateRequestError>>,
    ) {
        let result = match self
            .actor_state
            .validate_pending_overlay_request(&self.worker_handle, &self.cancel)
        {
            Ok(reset_generation) => {
                clear_local_pending_spent(&self.worker_handle, &self.cancel, reset_generation).await
            }
            Err(err) => Err(err),
        };
        let _ = reply.send(result);
    }

    async fn handle_create_pending_output_contexts(
        &self,
        ticket: WalletPrivateViewTicket,
        contexts: Vec<PendingOutputPoiContextIntent>,
        reply: oneshot::Sender<Result<usize, WalletPrivateRequestError>>,
    ) {
        let result = match self.actor_state.validate_private_request(
            &self.worker_handle,
            &self.cancel,
            ticket,
            self.last_scanned,
            false,
        ) {
            Ok(reset_generation) => {
                commit_pending_output_contexts(
                    &self.worker_handle,
                    &self.cancel,
                    self.db.as_ref(),
                    self.cache_store.as_ref(),
                    &self.cfg,
                    reset_generation,
                    &self.active_poi_list_keys,
                    &self.poi_submitter,
                    &contexts,
                )
                .await
            }
            Err(err) => Err(err),
        };
        let _ = reply.send(result);
    }
}
