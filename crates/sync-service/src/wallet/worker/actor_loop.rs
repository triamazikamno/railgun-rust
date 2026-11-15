use super::{
    Arc, CancellationToken, ChainPublicDataPlane, FixedBytes, RwLock, WalletActorState,
    WalletBackfillRejectReason, WalletCacheStore, WalletConfig, WalletHandle, WalletPersistState,
    WalletPoiRefreshSelection, WalletPoiRuntime, WalletPoiStatusRefreshCommitRequest, WalletUtxo,
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
}
