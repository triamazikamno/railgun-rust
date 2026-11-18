//! Capabilities for mutating a wallet's private state: the actor-checked authority, its remote
//! counterpart and the permit held while a mutation applies.

#[allow(clippy::wildcard_imports)]
use super::*;
pub(crate) struct WalletPrivateMutationAuthority<'a> {
    handle: &'a WalletHandle,
    reset_generation: u64,
    cancel: &'a CancellationToken,
    /// When set, private POI commits re-enter the actor (job mode). Never write mirrors off-loop.
    apply_client: Option<&'a WalletPrivateApplyClient>,
}

/// Owned capability for wallet-private remote effects.
///
/// This authority cannot acquire a mutation permit or write durable state. It only
/// authorizes generation-scoped network effects and is invalidated by reset/shutdown.
#[derive(Clone)]
pub(crate) struct WalletPrivateRemoteAuthority {
    handle: WalletHandle,
    reset_generation: u64,
    cancel: CancellationToken,
}

pub(crate) struct WalletPrivateMutationPermit<'a> {
    handle: &'a WalletHandle,
    reset_generation: AtomicU64,
    cancel: &'a CancellationToken,
    _guard: OwnedMutexGuard<()>,
}

impl<'a> WalletPrivateMutationAuthority<'a> {
    pub(in crate::wallet) const fn new(
        handle: &'a WalletHandle,
        reset_generation: u64,
        cancel: &'a CancellationToken,
    ) -> Self {
        Self {
            handle,
            reset_generation,
            cancel,
            apply_client: None,
        }
    }

    /// Job mode: durable POI private commits are applied only on the actor turn.
    pub(in crate::wallet) const fn with_apply_client(
        mut self,
        apply_client: &'a WalletPrivateApplyClient,
    ) -> Self {
        self.apply_client = Some(apply_client);
        self
    }

    pub(in crate::wallet) const fn apply_client(&self) -> Option<&'a WalletPrivateApplyClient> {
        self.apply_client
    }

    pub(in crate::wallet) const fn reset_generation(&self) -> u64 {
        self.reset_generation
    }

    pub(in crate::wallet) const fn chain_id(&self) -> u64 {
        self.handle.chain.chain_id
    }

    pub(in crate::wallet) const fn wallet_id(&self) -> &WalletCacheKey {
        &self.handle.cache_key
    }

    #[must_use]
    pub(in crate::wallet) fn remote_authority(&self) -> WalletPrivateRemoteAuthority {
        WalletPrivateRemoteAuthority {
            handle: self.handle.clone(),
            reset_generation: self.reset_generation,
            cancel: self.cancel.clone(),
        }
    }

    pub(in crate::wallet) async fn acquire(
        &self,
    ) -> Result<WalletPrivateMutationPermit<'a>, WalletBackfillRejectReason> {
        self.handle
            .revalidate_durable_commit(self.cancel, self.reset_generation)?;
        let guard = self
            .handle
            .actor_authority(self.cancel, self.reset_generation)
            .await?;
        self.revalidate()?;
        Ok(WalletPrivateMutationPermit {
            handle: self.handle,
            reset_generation: AtomicU64::new(self.reset_generation),
            cancel: self.cancel,
            _guard: guard,
        })
    }

    pub(in crate::wallet) fn revalidate(&self) -> Result<(), WalletBackfillRejectReason> {
        self.handle
            .revalidate_durable_commit(self.cancel, self.reset_generation)
    }

    pub(in crate::wallet) async fn wallet_utxos(
        &self,
    ) -> Result<Vec<WalletUtxo>, WalletBackfillRejectReason> {
        self.revalidate()?;
        let snapshot = self.handle.utxos.read().await.clone();
        self.revalidate()?;
        Ok(snapshot)
    }

    pub(in crate::wallet) async fn notify_changed_if(&self, changed: bool, label: &'static str) {
        if !changed {
            return;
        }
        match self.acquire().await {
            Ok(permit) => {
                if let Err(reason) = permit.notify_changed().await {
                    debug!(target: LOG_TARGET, ?reason, cache_key = %self.handle.cache_key, label, "wallet revision publication rejected");
                }
            }
            Err(reason) => {
                debug!(target: LOG_TARGET, ?reason, cache_key = %self.handle.cache_key, label, "wallet revision publication skipped");
            }
        }
    }
}

impl WalletPrivateRemoteAuthority {
    pub(in crate::wallet) fn revalidate(&self) -> Result<(), WalletBackfillRejectReason> {
        self.handle
            .revalidate_durable_commit(&self.cancel, self.reset_generation)
    }

    /// Completes when this remote capability is invalidated by reset or shutdown.
    pub(in crate::wallet) async fn invalidated(&self) {
        let mut generation_rx = self.handle.reset_generation_rx.clone();
        loop {
            if self.revalidate().is_err() {
                return;
            }
            tokio::select! {
                biased;
                () = self.cancel.cancelled() => return,
                changed = generation_rx.changed() => {
                    if changed.is_err()
                        || *generation_rx.borrow_and_update() != self.reset_generation
                    {
                        return;
                    }
                }
            }
        }
    }
}

impl WalletPrivateMutationPermit<'_> {
    pub(crate) const fn chain_id(&self) -> u64 {
        self.handle.chain.chain_id
    }

    pub(crate) const fn wallet_id(&self) -> &WalletCacheKey {
        &self.handle.cache_key
    }

    pub(in crate::wallet) fn revalidate(&self) -> Result<(), WalletBackfillRejectReason> {
        self.handle
            .revalidate_durable_commit(self.cancel, self.reset_generation.load(Ordering::Acquire))
    }

    /// Synchronous private apply under the lifecycle fence (mirrors, publishes, durable commits).
    pub(in crate::wallet) fn with_active_apply<R>(
        &self,
        apply: impl for<'a> FnOnce(WalletActorApplyToken<'a>) -> R,
    ) -> Result<R, WalletBackfillRejectReason> {
        self.handle.with_active_apply(
            self.cancel,
            self.reset_generation.load(Ordering::Acquire),
            apply,
        )
    }

    /// Alias for durable commit call sites.
    pub(in crate::wallet) fn with_durable_apply<R>(
        &self,
        apply: impl for<'a> FnOnce(WalletActorCommitToken<'a>) -> R,
    ) -> Result<R, WalletBackfillRejectReason> {
        self.with_active_apply(apply)
    }

    pub(in crate::wallet) fn apply_set_last_scanned_mirror(
        &self,
        _token: &WalletActorApplyToken<'_>,
        block: u64,
    ) {
        self.handle.last_scanned.store(block, Ordering::Relaxed);
    }

    pub(in crate::wallet) fn apply_increment_revision(&self, _token: &WalletActorApplyToken<'_>) {
        self.handle.increment_revision();
    }

    pub(in crate::wallet) fn apply_current_view(
        &self,
        _token: &WalletActorApplyToken<'_>,
        utxos: &[WalletUtxo],
        overlay: &WalletPendingOverlay,
    ) -> WalletViewState {
        self.handle.current_view_projection(utxos, overlay)
    }

    pub(in crate::wallet) fn apply_notify_changed(
        &self,
        _token: &WalletActorApplyToken<'_>,
        utxos: &[WalletUtxo],
        overlay: &WalletPendingOverlay,
    ) {
        self.handle.notify_changed_with_projection(utxos, overlay);
    }

    pub(in crate::wallet) fn apply_publish_ppoi_workflow_projection(
        &self,
        _token: &WalletActorApplyToken<'_>,
        projection: WalletPpoiWorkflowProjection,
    ) {
        if let Some(observation) = self.handle.observation.upgrade() {
            observation.publish_ppoi_workflow_projection(projection.status, projection.submissions);
        }
    }

    pub(in crate::wallet) fn ppoi_workflow_status(&self) -> WalletPpoiWorkflowStatus {
        self.handle
            .observation
            .upgrade()
            .map_or_else(WalletPpoiWorkflowStatus::default, |observation| {
                observation.ppoi_workflow_status()
            })
    }

    pub(in crate::wallet) fn apply_publish_progress(
        _token: &WalletActorApplyToken<'_>,
        progress_tx: Option<&SyncProgressSender>,
        update: SyncProgressUpdate,
    ) {
        if let Some(progress_tx) = progress_tx {
            let _ = progress_tx.send(Some(update));
        }
    }

    pub(in crate::wallet) fn apply_publish_indexed_catch_up(
        &self,
        _token: &WalletActorApplyToken<'_>,
        status: Option<WalletIndexedCatchUpStatus>,
    ) {
        if let Err(err) = self.handle.indexed_catch_up_tx.send(status) {
            debug!(target: LOG_TARGET, ?err, cache_key = %self.handle.cache_key, "failed to send indexed wallet catch-up status");
        }
    }

    pub(in crate::wallet) fn apply_set_reset_generation(
        &self,
        _token: &WalletActorApplyToken<'_>,
        generation: u64,
    ) {
        self.handle
            .reset_generation
            .store(generation, Ordering::Relaxed);
        self.reset_generation.store(generation, Ordering::Release);
        self.handle.reset_generation_tx.send_replace(generation);
    }

    pub(in crate::wallet) const fn pending_overlay(&self) -> &Arc<RwLock<WalletPendingOverlay>> {
        &self.handle.pending_overlay
    }

    pub(in crate::wallet) const fn handle_utxos(&self) -> &Arc<RwLock<Vec<WalletUtxo>>> {
        &self.handle.utxos
    }

    pub(in crate::wallet) async fn wallet_utxos(
        &self,
    ) -> Result<Vec<WalletUtxo>, WalletBackfillRejectReason> {
        self.revalidate()?;
        let snapshot = self.handle.utxos.read().await.clone();
        self.revalidate()?;
        Ok(snapshot)
    }

    pub(in crate::wallet) async fn notify_changed(&self) -> Result<(), WalletBackfillRejectReason> {
        let utxos = self.handle.utxos.read().await.clone();
        let overlay = self.handle.pending_overlay.read().await.clone();
        self.with_active_apply(|token| {
            self.apply_notify_changed(&token, &utxos, &overlay);
        })
    }

    pub(in crate::wallet) async fn notify_if_changed(
        &self,
        changed: bool,
    ) -> Result<(), WalletBackfillRejectReason> {
        if !changed {
            return Ok(());
        }
        self.notify_changed().await
    }

    pub(in crate::wallet) fn publish_indexed_catch_up(
        &self,
        status: Option<WalletIndexedCatchUpStatus>,
    ) -> Result<(), WalletBackfillRejectReason> {
        self.with_active_apply(|token| {
            self.apply_publish_indexed_catch_up(&token, status);
        })
    }

    pub(in crate::wallet) async fn replace_chain_pending_overlay(
        &self,
        next: WalletPendingOverlay,
    ) -> Result<bool, WalletBackfillRejectReason> {
        self.handle
            .replace_chain_pending_overlay_authorized(next, self)
            .await
    }
}
