pub const WALLET_POI_STATUS_BATCH_SIZE: usize = 1000;
pub const WALLET_POI_RECOVERABLE_REFRESH_AFTER: Duration = Duration::from_secs(60);
pub(super) const WALLET_POI_REFRESH_INTERVAL: Duration = Duration::from_secs(15);
#[cfg(test)]
pub(super) const WALLET_METADATA_LIVE_FLUSH_INTERVAL: Duration = Duration::from_secs(60);
#[cfg(test)]
pub(super) const WALLET_METADATA_LIVE_FLUSH_BLOCKS: u64 = 25;
pub(super) const LOCAL_PENDING_SPENT_TTL: Duration = Duration::from_secs(10 * 60);
pub(super) const OUTPUT_POI_RECOVERY_TRANSIENT_RETRY_AFTER: Duration = Duration::from_secs(10 * 60);
pub(super) const OUTPUT_POI_RECOVERY_PROOF_FAILURE_RETRY_AFTER: Duration =
    Duration::from_secs(24 * 60 * 60);
pub(super) const OUTPUT_POI_RECOVERY_SUBMITTED_RETRY_AFTER: Duration =
    Duration::from_secs(24 * 60 * 60);
pub(super) const PENDING_OUTPUT_POI_SUBMITTED_RETRY_AFTER: Duration = Duration::from_secs(5 * 60);
pub(super) const OUTPUT_POI_RECOVERY_ROOT_SEARCH_LEAVES: u64 = 128;
pub(super) const OUTPUT_POI_RECOVERY_VERIFY_PROOF: bool = true;
pub(super) const OUTPUT_POI_RECOVERY_SLOW_STEP_AFTER: Duration = Duration::from_secs(5);
pub(super) const EVM_CHAIN_TYPE: u8 = 0;
pub(super) const RETIRED_WALLET_ACTOR_ID: u64 = 0;

#[derive(Debug, Clone, Copy)]
pub(super) enum WalletPoiRefreshSelection {
    Required,
    RequiredOrRecoverable,
    RecoverableStale { now: u64 },
    Recoverable,
}

impl WalletPoiRefreshSelection {
    pub(super) const fn as_str(&self) -> &'static str {
        match self {
            Self::Required => "required",
            Self::RequiredOrRecoverable => "required_or_recoverable",
            Self::RecoverableStale { .. } => "recoverable_stale",
            Self::Recoverable => "recoverable",
        }
    }

    pub(super) fn matches_wallet_utxo(
        self,
        wallet_utxo: &WalletUtxo,
        active_list_keys: &[FixedBytes<32>],
    ) -> bool {
        match self {
            Self::Required => {
                wallet_utxo.utxo.poi.refreshed_at.is_none()
                    || active_list_keys
                        .iter()
                        .any(|list_key| !wallet_utxo.utxo.poi.statuses.contains_key(list_key))
            }
            Self::RequiredOrRecoverable => {
                Self::Required.matches_wallet_utxo(wallet_utxo, active_list_keys)
                    || wallet_utxo
                        .utxo
                        .poi
                        .has_recoverable_status_for_lists(active_list_keys)
            }
            Self::Recoverable => wallet_utxo
                .utxo
                .poi
                .has_recoverable_status_for_lists(active_list_keys),
            Self::RecoverableStale { now } => {
                wallet_utxo
                    .utxo
                    .poi
                    .has_recoverable_status_for_lists(active_list_keys)
                    && wallet_utxo
                        .utxo
                        .poi
                        .refreshed_at
                        .is_none_or(|refreshed_at| {
                            now.saturating_sub(refreshed_at)
                                >= WALLET_POI_RECOVERABLE_REFRESH_AFTER.as_secs()
                        })
            }
        }
    }
}

use super::*;

use crate::types::SyncProgressSender;

#[derive(Debug, Clone)]
pub struct WalletHandle {
    pub cache_key: String,
    pub(super) chain_id: u64,
    pub(super) actor_id: u64,
    pub(super) active_actor_id: Arc<AtomicU64>,
    pub(super) lifecycle: Arc<WalletActorLifecycleCell>,
    pub(super) authority_lock: Arc<Mutex<()>>,
    pub(super) utxos: Arc<RwLock<Vec<WalletUtxo>>>,
    pub(super) pending_overlay: Arc<RwLock<WalletPendingOverlay>>,
    pub(super) last_scanned: Arc<AtomicU64>,
    pub(super) reset_generation: Arc<AtomicU64>,
    /// Private remote-job invalidation. Updated synchronously with reset generation.
    pub(super) reset_generation_rx: watch::Receiver<u64>,
    pub(super) next_sync_job_id: Arc<AtomicU64>,
    pub ready_rx: watch::Receiver<bool>,
    pub readiness_rx: watch::Receiver<WalletReadiness>,
    pub rev_rx: watch::Receiver<u64>,
    /// Single-source public private-view (Current vs ResetPending).
    pub view_rx: watch::Receiver<WalletViewState>,
    pub poi_refreshing_rx: watch::Receiver<bool>,
    pub indexed_catch_up_rx: watch::Receiver<Option<WalletIndexedCatchUpStatus>>,
    pub(super) pending_overlay_tx: mpsc::Sender<WalletPendingOverlayRequest>,
    pub(super) poi_refresh_tx: mpsc::Sender<WalletPoiRefreshRequest>,
    pub(super) indexed_catch_up_status_tx: mpsc::UnboundedSender<WalletIndexedCatchUpCommand>,
    pub(super) rev_tx: watch::Sender<u64>,
    pub(super) reset_generation_tx: watch::Sender<u64>,
    pub(super) view_tx: watch::Sender<WalletViewState>,
    pub(super) indexed_catch_up_tx: watch::Sender<Option<WalletIndexedCatchUpStatus>>,
}

#[derive(Debug, Clone, Copy)]
pub(crate) struct WalletActorTokenAuthority<'a> {
    handle: &'a WalletHandle,
}

impl WalletActorTokenAuthority<'_> {
    #[must_use]
    pub(crate) const fn chain_id(&self) -> u64 {
        self.handle.chain_id
    }

    #[must_use]
    pub(crate) const fn actor_id(&self) -> u64 {
        self.handle.actor_id
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub(crate) struct WalletIndexedCatchUpLease {
    token: WalletSyncToken,
}

impl WalletIndexedCatchUpLease {
    #[must_use]
    pub(super) const fn for_actor_accepted_job(token: WalletSyncToken) -> Self {
        Self { token }
    }

    #[must_use]
    pub(crate) const fn token(self) -> WalletSyncToken {
        self.token
    }
}

#[derive(Debug)]
pub(super) struct WalletPendingOverlayRequest {
    pub(super) update: WalletPendingOverlayUpdate,
    pub(super) token: WalletSyncToken,
    pub(super) reset_generation: u64,
    pub(super) last_scanned: u64,
}

#[derive(Debug)]
pub(super) enum WalletPendingOverlayUpdate {
    PublicRows(WalletScanRows),
    Clear,
}

#[derive(Debug)]
pub(super) enum WalletIndexedCatchUpCommand {
    Claim {
        response: oneshot::Sender<Option<WalletIndexedCatchUpLease>>,
    },
    Publish {
        lease: WalletIndexedCatchUpLease,
        status: WalletIndexedCatchUpStatus,
    },
    Clear {
        lease: WalletIndexedCatchUpLease,
    },
}

/// Owned pure POI private delta for actor re-entry (jobs never write mirrors).
///
/// Protocol B: payloads are **intents**. Actor apply folds them against the current
/// private UTXO snapshot (and matching context rules) — never blind-writes stale rows.
#[derive(Debug, Clone)]
pub(crate) enum OwnedPoiPrivateDelta {
    /// Proposed pending-context / recovery rows; apply keeps only those still matching
    /// an unspent wallet UTXO under the permit snapshot.
    Metadata {
        pending_updates: Vec<PendingOutputPoiContextRecord>,
        recovery_updates: Vec<OutputPoiRecoveryRecord>,
    },
    /// Mark list keys Valid on the matching unspent UTXO (skipped if gone/spent).
    VerifiedValid {
        record: PendingOutputPoiContextRecord,
        valid_list_keys: Vec<FixedBytes<32>>,
        now: u64,
    },
    /// Apply remotely-read statuses only to currently matching unspent UTXOs.
    PoiStatusRefresh {
        active_list_keys: Vec<FixedBytes<32>>,
        expected_poi_by_blinded_commitment: BTreeMap<FixedBytes<32>, UtxoPoiMetadata>,
        statuses_by_blinded_commitment:
            BTreeMap<FixedBytes<32>, BTreeMap<FixedBytes<32>, PoiStatus>>,
        refreshed_at: u64,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum PoiPrivateApplyOutcome {
    Applied { utxo_changed: bool },
    Skipped,
}

/// Job → actor private apply request. Actor is the sole UTXO/durable private writer.
pub(crate) struct WalletPrivateApplyRequest {
    pub reset_generation: u64,
    pub delta: OwnedPoiPrivateDelta,
    pub reply: oneshot::Sender<Result<PoiPrivateApplyOutcome, WalletCacheError>>,
}

/// Client used by remote jobs to re-enter the actor for private POI commits.
#[derive(Clone)]
pub(crate) struct WalletPrivateApplyClient {
    tx: mpsc::Sender<WalletPrivateApplyRequest>,
}

impl WalletPrivateApplyClient {
    pub(crate) fn new(tx: mpsc::Sender<WalletPrivateApplyRequest>) -> Self {
        Self { tx }
    }

    pub(crate) async fn apply(
        &self,
        reset_generation: u64,
        delta: OwnedPoiPrivateDelta,
    ) -> Result<PoiPrivateApplyOutcome, WalletCacheError> {
        let (reply_tx, reply_rx) = oneshot::channel();
        self.tx
            .send(WalletPrivateApplyRequest {
                reset_generation,
                delta,
                reply: reply_tx,
            })
            .await
            .map_err(|_| WalletCacheError::Crypto)?;
        reply_rx.await.map_err(|_| WalletCacheError::Crypto)?
    }
}

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
    pub(super) const fn new(
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
    pub(super) const fn with_apply_client(
        mut self,
        apply_client: &'a WalletPrivateApplyClient,
    ) -> Self {
        self.apply_client = Some(apply_client);
        self
    }

    pub(super) const fn apply_client(&self) -> Option<&'a WalletPrivateApplyClient> {
        self.apply_client
    }

    pub(super) const fn reset_generation(&self) -> u64 {
        self.reset_generation
    }

    #[must_use]
    pub(super) fn remote_authority(&self) -> WalletPrivateRemoteAuthority {
        WalletPrivateRemoteAuthority {
            handle: self.handle.clone(),
            reset_generation: self.reset_generation,
            cancel: self.cancel.clone(),
        }
    }

    pub(super) async fn acquire(
        &self,
    ) -> Result<WalletPrivateMutationPermit<'a>, WalletBackfillRejectReason> {
        self.handle
            .revalidate_durable_commit(self.cancel, self.reset_generation)?;
        let guard = self.handle.actor_authority(self.reset_generation).await?;
        self.revalidate()?;
        Ok(WalletPrivateMutationPermit {
            handle: self.handle,
            reset_generation: AtomicU64::new(self.reset_generation),
            cancel: self.cancel,
            _guard: guard,
        })
    }

    pub(super) fn revalidate(&self) -> Result<(), WalletBackfillRejectReason> {
        self.handle
            .revalidate_durable_commit(self.cancel, self.reset_generation)
    }

    pub(super) async fn wallet_utxos(&self) -> Result<Vec<WalletUtxo>, WalletBackfillRejectReason> {
        self.revalidate()?;
        let snapshot = self.handle.utxos.read().await.clone();
        self.revalidate()?;
        Ok(snapshot)
    }

    pub(super) async fn notify_changed_if(&self, changed: bool, label: &'static str) {
        if !changed {
            return;
        }
        match self.acquire().await {
            Ok(permit) => {
                if let Err(reason) = permit.notify_changed().await {
                    debug!(?reason, cache_key = %self.handle.cache_key, label, "wallet revision publication rejected");
                }
            }
            Err(reason) => {
                debug!(?reason, cache_key = %self.handle.cache_key, label, "wallet revision publication skipped");
            }
        }
    }
}

impl WalletPrivateRemoteAuthority {
    pub(super) fn revalidate(&self) -> Result<(), WalletBackfillRejectReason> {
        self.handle
            .revalidate_durable_commit(&self.cancel, self.reset_generation)
    }

    /// Completes when this remote capability is invalidated by reset or shutdown.
    pub(super) async fn invalidated(&self) {
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
    pub(crate) fn wallet_id(&self) -> &str {
        &self.handle.cache_key
    }

    pub(super) fn revalidate(&self) -> Result<(), WalletBackfillRejectReason> {
        self.handle
            .revalidate_durable_commit(self.cancel, self.reset_generation.load(Ordering::Acquire))
    }

    /// Synchronous private apply under the lifecycle fence (mirrors, publishes, durable commits).
    pub(super) fn with_active_apply<R>(
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
    pub(super) fn with_durable_apply<R>(
        &self,
        apply: impl for<'a> FnOnce(WalletActorCommitToken<'a>) -> R,
    ) -> Result<R, WalletBackfillRejectReason> {
        self.with_active_apply(apply)
    }

    /// Token-gated helpers — only call inside `with_active_apply` (no re-fence).
    ///
    /// Publishes a full private projection. Pass the mirrors already held/updated under apply.
    pub(super) fn apply_set_last_scanned(
        &self,
        _token: &WalletActorApplyToken<'_>,
        block: u64,
        utxos: &[WalletUtxo],
        overlay: &WalletPendingOverlay,
    ) {
        self.handle.last_scanned.store(block, Ordering::Relaxed);
        self.handle.publish_view_current_projection(utxos, overlay);
    }

    pub(super) fn apply_publish_view_reset_pending(
        &self,
        _token: &WalletActorApplyToken<'_>,
        intent_id: u64,
        from_block: u64,
        reset_generation: u64,
    ) {
        self.handle
            .publish_view_reset_pending(intent_id, from_block, reset_generation);
    }

    pub(super) fn apply_publish_view_current(
        &self,
        _token: &WalletActorApplyToken<'_>,
        utxos: &[WalletUtxo],
        overlay: &WalletPendingOverlay,
    ) {
        self.handle.publish_view_current_projection(utxos, overlay);
    }

    pub(super) fn apply_notify_changed(
        &self,
        _token: &WalletActorApplyToken<'_>,
        utxos: &[WalletUtxo],
        overlay: &WalletPendingOverlay,
    ) {
        self.handle.notify_changed_with_projection(utxos, overlay);
    }

    pub(super) fn apply_publish_progress(
        &self,
        _token: &WalletActorApplyToken<'_>,
        progress_tx: Option<&SyncProgressSender>,
        update: SyncProgressUpdate,
    ) {
        if let Some(progress_tx) = progress_tx {
            let _ = progress_tx.send(Some(update));
        }
    }

    pub(super) fn apply_publish_readiness(
        &self,
        _token: &WalletActorApplyToken<'_>,
        ready_tx: &watch::Sender<bool>,
        readiness_tx: &watch::Sender<WalletReadiness>,
        readiness: WalletReadiness,
    ) {
        if let Err(err) = readiness_tx.send(readiness.clone()) {
            debug!(?err, "failed to send wallet readiness state");
        }
        if let Err(err) = ready_tx.send(readiness.is_ready()) {
            debug!(?err, "failed to send ready state");
        }
    }

    pub(super) fn apply_publish_indexed_catch_up(
        &self,
        _token: &WalletActorApplyToken<'_>,
        status: Option<WalletIndexedCatchUpStatus>,
    ) {
        if let Err(err) = self.handle.indexed_catch_up_tx.send(status) {
            debug!(?err, cache_key = %self.handle.cache_key, "failed to send indexed wallet catch-up status");
        }
    }

    pub(super) fn apply_publish_poi_refreshing(
        &self,
        _token: &WalletActorApplyToken<'_>,
        sender: &watch::Sender<bool>,
        value: bool,
    ) {
        if let Err(err) = sender.send(value) {
            debug!(?err, cache_key = %self.handle.cache_key, "failed to send wallet POI refresh state");
        }
    }

    pub(super) fn apply_set_reset_generation(
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

    pub(super) fn pending_overlay(&self) -> &Arc<RwLock<WalletPendingOverlay>> {
        &self.handle.pending_overlay
    }

    pub(super) fn handle_utxos(&self) -> &Arc<RwLock<Vec<WalletUtxo>>> {
        &self.handle.utxos
    }

    pub(super) fn last_scanned(&self) -> Result<u64, WalletBackfillRejectReason> {
        self.revalidate()?;
        Ok(self.handle.last_scanned_raw())
    }

    pub(super) async fn wallet_utxos(&self) -> Result<Vec<WalletUtxo>, WalletBackfillRejectReason> {
        self.revalidate()?;
        let snapshot = self.handle.utxos.read().await.clone();
        self.revalidate()?;
        Ok(snapshot)
    }

    pub(super) async fn replace_wallet_utxos(
        &self,
        next: Vec<WalletUtxo>,
    ) -> Result<(), WalletBackfillRejectReason> {
        let mut locked = self.handle.utxos.write().await;
        self.with_active_apply(|_token| {
            *locked = next;
        })
    }

    pub(super) async fn set_last_scanned(
        &self,
        block: u64,
    ) -> Result<(), WalletBackfillRejectReason> {
        let utxos = self.handle.utxos.read().await.clone();
        let overlay = self.handle.pending_overlay.read().await.clone();
        self.with_active_apply(|token| {
            self.apply_set_last_scanned(&token, block, &utxos, &overlay);
        })
    }

    pub(super) fn set_reset_generation(
        &self,
        generation: u64,
    ) -> Result<(), WalletBackfillRejectReason> {
        self.with_active_apply(|token| {
            self.apply_set_reset_generation(&token, generation);
        })
    }

    pub(super) fn publish_progress(
        &self,
        progress_tx: Option<&SyncProgressSender>,
        update: SyncProgressUpdate,
    ) -> Result<(), WalletBackfillRejectReason> {
        self.with_active_apply(|token| {
            self.apply_publish_progress(&token, progress_tx, update);
        })
    }

    pub(super) async fn notify_changed(&self) -> Result<(), WalletBackfillRejectReason> {
        let utxos = self.handle.utxos.read().await.clone();
        let overlay = self.handle.pending_overlay.read().await.clone();
        self.with_active_apply(|token| {
            self.apply_notify_changed(&token, &utxos, &overlay);
        })
    }

    pub(super) async fn notify_if_changed(
        &self,
        changed: bool,
    ) -> Result<(), WalletBackfillRejectReason> {
        if !changed {
            return Ok(());
        }
        self.notify_changed().await
    }

    pub(super) fn publish_indexed_catch_up(
        &self,
        status: Option<WalletIndexedCatchUpStatus>,
    ) -> Result<(), WalletBackfillRejectReason> {
        self.with_active_apply(|token| {
            self.apply_publish_indexed_catch_up(&token, status);
        })
    }

    pub(super) fn publish_poi_refreshing(
        &self,
        sender: &watch::Sender<bool>,
        value: bool,
    ) -> Result<(), WalletBackfillRejectReason> {
        self.with_active_apply(|token| {
            self.apply_publish_poi_refreshing(&token, sender, value);
        })
    }

    /// Publish readiness/ready under the lifecycle fence (Active only).
    pub(super) fn publish_readiness(
        &self,
        ready_tx: &watch::Sender<bool>,
        readiness_tx: &watch::Sender<WalletReadiness>,
        readiness: WalletReadiness,
    ) -> Result<(), WalletBackfillRejectReason> {
        self.with_active_apply(|token| {
            self.apply_publish_readiness(&token, ready_tx, readiness_tx, readiness);
        })
    }

    pub(super) async fn replace_chain_pending_overlay(
        &self,
        next: WalletPendingOverlay,
    ) -> Result<bool, WalletBackfillRejectReason> {
        self.handle
            .replace_chain_pending_overlay_authorized(next, self)
            .await
    }
}

pub use crate::types::{WalletPendingOverlay, WalletPendingSpent};

impl WalletHandle {
    #[must_use]
    pub(crate) const fn actor_id(&self) -> u64 {
        self.actor_id
    }

    #[must_use]
    pub(crate) fn is_current_actor(&self) -> bool {
        self.actor_id != RETIRED_WALLET_ACTOR_ID
            && self.active_actor_id.load(Ordering::Acquire) == self.actor_id
    }

    #[must_use]
    pub(crate) fn lifecycle(&self) -> WalletActorLifecycle {
        self.lifecycle.get()
    }

    /// Active → Stopping. Used when cancel is observed for a still-current actor.
    pub(crate) fn mark_stopping(&self) -> bool {
        self.lifecycle.mark_stopping()
    }

    /// Exactly one terminal Shutdown publish while Stopping and still current.
    /// Runs `publish` under the lifecycle fence so retire cannot interleave.
    pub(crate) fn publish_terminal_shutdown_if_allowed(&self, publish: impl FnOnce()) -> bool {
        self.lifecycle
            .publish_terminal_shutdown_if_allowed(self.is_current_actor(), publish)
    }

    pub(super) fn revalidate_durable_commit(
        &self,
        cancel: &CancellationToken,
        expected_reset_generation: u64,
    ) -> Result<(), WalletBackfillRejectReason> {
        if cancel.is_cancelled()
            || !self.lifecycle().allows_durable_commits()
            || !self.is_current_actor()
        {
            return Err(WalletBackfillRejectReason::Shutdown);
        }
        let current_reset_generation = self.authority_reset_generation();
        if current_reset_generation != expected_reset_generation {
            return Err(WalletBackfillRejectReason::StaleGeneration {
                expected: current_reset_generation,
                actual: expected_reset_generation,
            });
        }
        Ok(())
    }

    async fn actor_authority(
        &self,
        expected_reset_generation: u64,
    ) -> Result<OwnedMutexGuard<()>, WalletBackfillRejectReason> {
        let guard = Arc::clone(&self.authority_lock).lock_owned().await;
        if !self.lifecycle().allows_durable_commits() || !self.is_current_actor() {
            return Err(WalletBackfillRejectReason::Shutdown);
        }
        let current_reset_generation = self.authority_reset_generation();
        if current_reset_generation != expected_reset_generation {
            return Err(WalletBackfillRejectReason::StaleGeneration {
                expected: current_reset_generation,
                actual: expected_reset_generation,
            });
        }
        Ok(guard)
    }

    /// Thin identity fence: does not wait on `authority_lock` (which may be held across remote I/O).
    pub(crate) fn retire_actor(&self) {
        self.lifecycle.mark_retired(|| {
            self.active_actor_id
                .store(RETIRED_WALLET_ACTOR_ID, Ordering::Release);
        });
    }

    /// Final validation + synchronous private apply under the lifecycle fence.
    /// Rejects if not Active/current, cancelled, or reset generation is stale.
    pub(crate) fn with_active_apply<R>(
        &self,
        cancel: &CancellationToken,
        expected_reset_generation: u64,
        apply: impl for<'a> FnOnce(WalletActorApplyToken<'a>) -> R,
    ) -> Result<R, WalletBackfillRejectReason> {
        match self
            .lifecycle
            .with_active_apply(self.is_current_actor(), |token| {
                if cancel.is_cancelled() {
                    return Err(WalletBackfillRejectReason::Shutdown);
                }
                let current_reset_generation = self.authority_reset_generation();
                if current_reset_generation != expected_reset_generation {
                    return Err(WalletBackfillRejectReason::StaleGeneration {
                        expected: current_reset_generation,
                        actual: expected_reset_generation,
                    });
                }
                Ok(apply(token))
            }) {
            Ok(Ok(value)) => Ok(value),
            Ok(Err(reason)) => Err(reason),
            Err(()) => Err(WalletBackfillRejectReason::Shutdown),
        }
    }

    pub(crate) fn mint_sync_token(&self, reset_generation: u64) -> WalletSyncToken {
        WalletSyncToken::mint(
            WalletActorTokenAuthority { handle: self },
            reset_generation,
            self.next_sync_job_id.fetch_add(1, Ordering::AcqRel),
        )
    }

    /// Start generation-scoped backfill from a public progress ticket.
    ///
    /// Revalidates `progress` against the current view before minting a lease. Rejects if
    /// the view is reset-pending or the generation advanced (stale ticket).
    pub(crate) async fn start_backfill(
        &self,
        cache_key: &str,
        sender: &mpsc::Sender<BackfillEvent>,
        progress: crate::types::WalletSchedulableProgress,
        target_block: u64,
    ) -> WalletBackfillFinishResult {
        let Some(progress) = self.revalidate_schedulable_progress(progress) else {
            let current = self.schedulable_progress();
            return WalletBackfillFinishResult::Rejected {
                committed_to: self.last_scanned_raw(),
                reason: WalletBackfillRejectReason::StaleGeneration {
                    expected: current
                        .map(|p| p.reset_generation)
                        .unwrap_or(progress.reset_generation),
                    actual: progress.reset_generation,
                },
            };
        };
        let lease = WalletBackfillLease::from_token(
            self.mint_sync_token(progress.reset_generation),
            sender.clone(),
        );
        lease.finish(cache_key, target_block).await
    }

    /// Revalidate a stored progress ticket against the current public view.
    ///
    /// Returns refreshed progress (same generation, possibly advanced cursor) or `None` if
    /// the view is reset-pending or the generation changed.
    #[must_use]
    pub(crate) fn revalidate_schedulable_progress(
        &self,
        progress: crate::types::WalletSchedulableProgress,
    ) -> Option<crate::types::WalletSchedulableProgress> {
        progress.revalidate(self.schedulable_progress())
    }

    pub(crate) fn mint_reset_token(&self, intent_id: u64) -> WalletResetToken {
        WalletResetToken::mint(WalletActorTokenAuthority { handle: self }, intent_id)
    }

    /// Current cursor only when view is [`WalletViewState::Current`].
    /// Returns `None` while reset is pending (do not treat pre-reset cursor as current).
    #[must_use]
    pub fn last_scanned(&self) -> Option<u64> {
        self.view_state().last_scanned_current()
    }

    /// Raw durable cursor for actor-internal use (may be pre-reset while public view is pending).
    ///
    /// Never use for catch-up / hedge / lag scheduling — use [`Self::last_scanned`],
    /// [`Self::schedulable_progress`], or [`Self::wait_schedulable_progress`].
    #[must_use]
    pub(crate) fn last_scanned_raw(&self) -> u64 {
        self.last_scanned.load(Ordering::Relaxed)
    }

    /// Generation-scoped public progress ticket from one view observation.
    ///
    /// Returns `None` while reset-pending. This is the only public scheduling capability;
    /// pass it through to [`Self::start_backfill`] / catch-up APIs (revalidated at start).
    #[must_use]
    pub fn schedulable_progress(&self) -> Option<crate::types::WalletSchedulableProgress> {
        self.view_state().schedulable_progress()
    }

    /// Wait until the public view is [`WalletViewState::Current`], then return
    /// view-stamped `(last_scanned, reset_generation)` for scheduling.
    ///
    /// Generation comes from the view snapshot only — never from authority generation —
    /// so AcceptReset cannot pair an old cursor with a newly advanced atomic generation.
    pub(crate) async fn wait_schedulable_progress(
        &self,
        cancel: &CancellationToken,
    ) -> Option<crate::types::WalletSchedulableProgress> {
        let mut view_rx = self.view_rx.clone();
        loop {
            if cancel.is_cancelled() {
                return None;
            }
            let view = view_rx.borrow_and_update().clone();
            if let Some(progress) = view.schedulable_progress() {
                return Some(progress);
            }
            tokio::select! {
                _ = cancel.cancelled() => return None,
                changed = view_rx.changed() => {
                    if changed.is_err() {
                        return None;
                    }
                }
            }
        }
    }

    #[must_use]
    pub fn view_state(&self) -> WalletViewState {
        self.view_rx.borrow().clone()
    }

    #[must_use]
    pub fn readiness(&self) -> WalletReadiness {
        self.readiness_rx.borrow().clone()
    }

    /// Authority reset generation for token revalidation and actor minting.
    ///
    /// Not for public scheduling: may advance before [`WalletViewState`] is republished.
    /// Use [`Self::schedulable_progress`] / [`Self::wait_schedulable_progress`] instead.
    #[must_use]
    pub(crate) fn authority_reset_generation(&self) -> u64 {
        self.reset_generation.load(Ordering::Relaxed)
    }

    #[cfg(test)]
    pub(crate) async fn advance_reset_generation(&self) -> Option<u64> {
        let _guard = self.authority_lock.lock().await;
        if !self.is_current_actor() {
            return None;
        }
        let generation = self
            .reset_generation
            .fetch_add(1, Ordering::AcqRel)
            .wrapping_add(1);
        self.reset_generation_tx.send_replace(generation);
        Some(generation)
    }

    pub(crate) fn set_indexed_catch_up(
        &self,
        lease: WalletIndexedCatchUpLease,
        status: WalletIndexedCatchUpStatus,
    ) {
        if let Err(err) = self
            .indexed_catch_up_status_tx
            .send(WalletIndexedCatchUpCommand::Publish { lease, status })
        {
            debug!(?err, cache_key = %self.cache_key, "failed to request indexed wallet catch-up status publication");
        }
    }

    pub(crate) async fn try_claim_indexed_catch_up(&self) -> Option<WalletIndexedCatchUpLease> {
        let (response, result) = oneshot::channel();
        if self
            .indexed_catch_up_status_tx
            .send(WalletIndexedCatchUpCommand::Claim { response })
            .is_err()
        {
            return None;
        }
        result.await.unwrap_or(None)
    }

    pub(crate) fn clear_indexed_catch_up(&self, lease: WalletIndexedCatchUpLease) {
        if let Err(err) = self
            .indexed_catch_up_status_tx
            .send(WalletIndexedCatchUpCommand::Clear { lease })
        {
            debug!(?err, cache_key = %self.cache_key, "failed to request indexed wallet catch-up status clear");
        }
    }

    fn notify_changed_with_projection(&self, utxos: &[WalletUtxo], overlay: &WalletPendingOverlay) {
        let rev = self.rev_rx.borrow().wrapping_add(1);
        if let Err(err) = self.rev_tx.send(rev) {
            debug!(?err, cache_key = %self.cache_key, "failed to send wallet revision");
        }
        if self.view_rx.borrow().is_current() {
            self.publish_view_current_projection(utxos, overlay);
        }
    }

    /// Publish full private projection as [`WalletViewState::Current`].
    /// Call only with mirrors that match actor-owned state at this apply.
    fn publish_view_current_projection(
        &self,
        utxos: &[WalletUtxo],
        overlay: &WalletPendingOverlay,
    ) {
        let last_scanned = self.last_scanned.load(Ordering::Relaxed);
        let revision = *self.rev_rx.borrow();
        let reset_generation = self.authority_reset_generation();
        let snapshot = WalletCurrentSnapshot::new(
            last_scanned,
            revision,
            reset_generation,
            Arc::<[WalletUtxo]>::from(utxos.to_vec()),
            Arc::new(overlay.clone()),
        );
        if let Err(err) = self.view_tx.send(WalletViewState::Current(snapshot)) {
            debug!(?err, cache_key = %self.cache_key, "failed to send wallet view state");
        }
    }

    fn publish_view_reset_pending(&self, intent_id: u64, from_block: u64, reset_generation: u64) {
        if let Err(err) = self.view_tx.send(WalletViewState::ResetPending {
            intent_id,
            from_block,
            reset_generation,
        }) {
            debug!(?err, cache_key = %self.cache_key, "failed to send wallet reset-pending view");
        }
    }

    #[cfg(test)]
    pub(crate) async fn notify_changed(&self) {
        let utxos = self.utxos.read().await.clone();
        let overlay = self.pending_overlay.read().await.clone();
        self.notify_changed_with_projection(&utxos, &overlay);
    }

    /// Pending tip overlay only when view is [`WalletViewState::Current`].
    /// Sole public source is the published projection (not the live lock).
    pub fn pending_overlay(&self) -> Option<Arc<WalletPendingOverlay>> {
        self.current_snapshot()
            .map(|snapshot| Arc::clone(&snapshot.pending_overlay))
    }

    async fn request_pending_overlay_update(
        &self,
        update: WalletPendingOverlayUpdate,
        reset_generation: u64,
        last_scanned: u64,
    ) -> bool {
        let token = self.mint_sync_token(reset_generation);
        self.pending_overlay_tx
            .send(WalletPendingOverlayRequest {
                update,
                token,
                reset_generation,
                last_scanned,
            })
            .await
            .is_ok()
    }

    pub(crate) async fn request_pending_overlay_rows(
        &self,
        rows: WalletScanRows,
        reset_generation: u64,
        last_scanned: u64,
    ) -> bool {
        self.request_pending_overlay_update(
            WalletPendingOverlayUpdate::PublicRows(rows),
            reset_generation,
            last_scanned,
        )
        .await
    }

    pub(crate) async fn request_pending_overlay_clear(
        &self,
        reset_generation: u64,
        last_scanned: u64,
    ) -> bool {
        self.request_pending_overlay_update(
            WalletPendingOverlayUpdate::Clear,
            reset_generation,
            last_scanned,
        )
        .await
    }

    /// UTXO snapshot only when view is [`WalletViewState::Current`].
    /// Returns `None` while reset is pending.
    pub fn utxos_snapshot(&self) -> Option<Arc<[WalletUtxo]>> {
        self.current_snapshot()
            .map(|snapshot| Arc::clone(&snapshot.utxos))
    }

    /// Coherent current private snapshot from the published view, or `None` while reset-pending.
    ///
    /// This is the sole public private-projection choke point (UTXOs + pending overlay + stamps).
    pub fn current_snapshot(&self) -> Option<Arc<WalletCurrentSnapshot>> {
        self.view_state().current_snapshot()
    }

    #[cfg(test)]
    pub(crate) async fn clear_local_pending_spent(&self) -> bool {
        let changed = {
            let mut overlay = self.pending_overlay.write().await;
            let changed = !overlay.local_pending_spent.is_empty();
            overlay.local_pending_spent.clear();
            changed
        };
        if changed {
            self.notify_changed().await;
        }
        changed
    }

    #[cfg(test)]
    pub(crate) async fn mark_pending_spent_utxos(
        &self,
        utxos: &[Utxo],
        tx_hash: Option<FixedBytes<32>>,
    ) {
        if utxos.is_empty() {
            return;
        }
        let now = now_epoch_secs();
        let changed = {
            let mut overlay = self.pending_overlay.write().await;
            let chain_pending: HashSet<_> = overlay
                .pending_spent
                .iter()
                .map(WalletPendingSpent::key)
                .collect();
            let mut existing: HashSet<_> = overlay
                .local_pending_spent
                .iter()
                .map(WalletPendingSpent::key)
                .collect();
            let before = overlay.local_pending_spent.len();
            let mut updated_existing = false;
            for utxo in utxos {
                let key = (utxo.tree, utxo.position);
                if chain_pending.contains(&key) {
                    continue;
                }
                if existing.insert(key) {
                    overlay
                        .local_pending_spent
                        .push(WalletPendingSpent::submitted(utxo, tx_hash, now));
                } else if let Some(spent) = overlay
                    .local_pending_spent
                    .iter_mut()
                    .find(|spent| spent.key() == key)
                    && spent.tx_hash != tx_hash
                {
                    spent.tx_hash = tx_hash;
                    spent.block_timestamp = Some(now);
                    updated_existing = true;
                }
            }
            overlay
                .local_pending_spent
                .sort_by_key(WalletPendingSpent::key);
            overlay.local_pending_spent.len() != before || updated_existing
        };
        if changed {
            self.notify_changed().await;
        }
    }

    #[cfg(test)]
    pub(super) async fn set_chain_pending_overlay(&self, next: WalletPendingOverlay) {
        let _ = self
            .replace_chain_pending_overlay_unchecked(next)
            .await
            .expect("test overlay replacement should not require authority");
        // Always republish: tests may seed local_pending_spent on the live lock first.
        self.notify_changed().await;
    }

    async fn replace_chain_pending_overlay_authorized(
        &self,
        next: WalletPendingOverlay,
        permit: &WalletPrivateMutationPermit<'_>,
    ) -> Result<bool, WalletBackfillRejectReason> {
        permit.revalidate()?;
        let now = now_epoch_secs();
        let confirmed_spent: HashSet<_> = {
            let utxos = self.utxos.read().await;
            permit.revalidate()?;
            utxos
                .iter()
                .filter(|utxo| utxo.is_spent())
                .map(|utxo| (utxo.utxo.tree, utxo.utxo.position))
                .collect()
        };
        let chain_pending_spent: HashSet<_> = next
            .pending_spent
            .iter()
            .map(WalletPendingSpent::key)
            .collect();
        let mut overlay = self.pending_overlay.write().await;
        permit.with_active_apply(|_token| {
            let chain_changed = !chain_pending_overlay_matches(&overlay, &next);
            let before_local = overlay.local_pending_spent.len();
            overlay.local_pending_spent.retain(|spent| {
                let key = spent.key();
                if confirmed_spent.contains(&key) || chain_pending_spent.contains(&key) {
                    return false;
                }
                let submitted_at = spent.block_timestamp.unwrap_or(now);
                now.saturating_sub(submitted_at) < LOCAL_PENDING_SPENT_TTL.as_secs()
            });
            let local_changed = overlay.local_pending_spent.len() != before_local;
            overlay.new_utxos = next.new_utxos;
            overlay.pending_spent = next.pending_spent;
            chain_changed || local_changed
        })
    }

    #[cfg(test)]
    async fn replace_chain_pending_overlay_unchecked(
        &self,
        next: WalletPendingOverlay,
    ) -> Result<bool, WalletBackfillRejectReason> {
        let now = now_epoch_secs();
        let confirmed_spent: HashSet<_> = {
            let utxos = self.utxos.read().await;
            utxos
                .iter()
                .filter(|utxo| utxo.is_spent())
                .map(|utxo| (utxo.utxo.tree, utxo.utxo.position))
                .collect()
        };
        let chain_pending_spent: HashSet<_> = next
            .pending_spent
            .iter()
            .map(WalletPendingSpent::key)
            .collect();
        let changed = {
            let mut overlay = self.pending_overlay.write().await;
            let chain_changed = !chain_pending_overlay_matches(&overlay, &next);
            let before_local = overlay.local_pending_spent.len();
            overlay.local_pending_spent.retain(|spent| {
                let key = spent.key();
                if confirmed_spent.contains(&key) || chain_pending_spent.contains(&key) {
                    return false;
                }
                let submitted_at = spent.block_timestamp.unwrap_or(now);
                now.saturating_sub(submitted_at) < LOCAL_PENDING_SPENT_TTL.as_secs()
            });
            let local_changed = overlay.local_pending_spent.len() != before_local;
            overlay.new_utxos = next.new_utxos;
            overlay.pending_spent = next.pending_spent;
            chain_changed || local_changed
        };
        Ok(changed)
    }

    pub async fn refresh_poi_statuses(&self) -> bool {
        self.poi_refresh_tx
            .send(WalletPoiRefreshRequest {
                force_output_poi_recovery: true,
            })
            .await
            .is_ok()
    }
}

#[derive(Debug, Clone, Copy)]
pub(super) struct WalletPoiRefreshRequest {
    pub(super) force_output_poi_recovery: bool,
}
