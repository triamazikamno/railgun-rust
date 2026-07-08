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
    pub(super) authority_lock: Arc<Mutex<()>>,
    pub(super) utxos: Arc<RwLock<Vec<WalletUtxo>>>,
    pub(super) pending_overlay: Arc<RwLock<WalletPendingOverlay>>,
    pub(super) last_scanned: Arc<AtomicU64>,
    pub(super) reset_generation: Arc<AtomicU64>,
    pub(super) next_sync_job_id: Arc<AtomicU64>,
    pub ready_rx: watch::Receiver<bool>,
    pub readiness_rx: watch::Receiver<WalletReadiness>,
    pub rev_rx: watch::Receiver<u64>,
    pub poi_refreshing_rx: watch::Receiver<bool>,
    pub indexed_catch_up_rx: watch::Receiver<Option<WalletIndexedCatchUpStatus>>,
    pub(super) pending_overlay_tx: mpsc::Sender<WalletPendingOverlayRequest>,
    pub(super) poi_refresh_tx: mpsc::Sender<WalletPoiRefreshRequest>,
    pub(super) indexed_catch_up_status_tx: mpsc::Sender<WalletIndexedCatchUpCommand>,
    pub(super) rev_tx: watch::Sender<u64>,
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

pub(crate) struct WalletPrivateMutationAuthority<'a> {
    handle: &'a WalletHandle,
    reset_generation: u64,
    cancel: &'a CancellationToken,
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
        }
    }

    pub(super) async fn acquire(
        &self,
    ) -> Result<WalletPrivateMutationPermit<'a>, WalletBackfillRejectReason> {
        if self.cancel.is_cancelled() {
            return Err(WalletBackfillRejectReason::Shutdown);
        }
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
        if self.cancel.is_cancelled() || !self.handle.is_current_actor() {
            return Err(WalletBackfillRejectReason::Shutdown);
        }
        let current_reset_generation = self.handle.reset_generation();
        if current_reset_generation != self.reset_generation {
            return Err(WalletBackfillRejectReason::StaleGeneration {
                expected: current_reset_generation,
                actual: self.reset_generation,
            });
        }
        Ok(())
    }

    pub(super) async fn cancelled(&self) {
        self.cancel.cancelled().await;
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
                if let Err(reason) = permit.notify_changed() {
                    debug!(?reason, cache_key = %self.handle.cache_key, label, "wallet revision publication rejected");
                }
            }
            Err(reason) => {
                debug!(?reason, cache_key = %self.handle.cache_key, label, "wallet revision publication skipped");
            }
        }
    }
}

impl WalletPrivateMutationPermit<'_> {
    pub(crate) fn wallet_id(&self) -> &str {
        &self.handle.cache_key
    }

    pub(super) fn revalidate(&self) -> Result<(), WalletBackfillRejectReason> {
        if self.cancel.is_cancelled() || !self.handle.is_current_actor() {
            return Err(WalletBackfillRejectReason::Shutdown);
        }
        let current_reset_generation = self.handle.reset_generation();
        let expected_reset_generation = self.reset_generation.load(Ordering::Acquire);
        if current_reset_generation != expected_reset_generation {
            return Err(WalletBackfillRejectReason::StaleGeneration {
                expected: current_reset_generation,
                actual: expected_reset_generation,
            });
        }
        Ok(())
    }

    pub(super) fn last_scanned(&self) -> Result<u64, WalletBackfillRejectReason> {
        self.revalidate()?;
        Ok(self.handle.last_scanned())
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
        self.revalidate()?;
        let mut locked = self.handle.utxos.write().await;
        self.revalidate()?;
        *locked = next;
        Ok(())
    }

    pub(super) fn set_last_scanned(&self, block: u64) -> Result<(), WalletBackfillRejectReason> {
        self.revalidate()?;
        self.handle.last_scanned.store(block, Ordering::Relaxed);
        Ok(())
    }

    pub(super) fn set_reset_generation(
        &self,
        generation: u64,
    ) -> Result<(), WalletBackfillRejectReason> {
        self.revalidate()?;
        self.handle
            .reset_generation
            .store(generation, Ordering::Relaxed);
        self.reset_generation.store(generation, Ordering::Release);
        Ok(())
    }

    pub(super) fn publish_readiness(
        &self,
        ready_tx: &watch::Sender<bool>,
        readiness_tx: &watch::Sender<WalletReadiness>,
        readiness: WalletReadiness,
    ) -> Result<(), WalletBackfillRejectReason> {
        self.revalidate()?;
        if let Err(err) = readiness_tx.send(readiness.clone()) {
            debug!(?err, cache_key = %self.handle.cache_key, "failed to send wallet readiness state");
        }
        if let Err(err) = ready_tx.send(readiness.is_ready()) {
            debug!(?err, cache_key = %self.handle.cache_key, "failed to send ready state");
        }
        Ok(())
    }

    pub(super) fn publish_progress(
        &self,
        progress_tx: Option<&SyncProgressSender>,
        update: SyncProgressUpdate,
    ) -> Result<(), WalletBackfillRejectReason> {
        self.revalidate()?;
        if let Some(progress_tx) = progress_tx {
            let _ = progress_tx.send(Some(update));
        }
        Ok(())
    }

    pub(super) fn notify_changed(&self) -> Result<(), WalletBackfillRejectReason> {
        self.revalidate()?;
        self.handle.notify_changed_inner();
        Ok(())
    }

    pub(super) fn notify_if_changed(
        &self,
        changed: bool,
    ) -> Result<(), WalletBackfillRejectReason> {
        self.revalidate()?;
        if changed {
            self.handle.notify_changed_inner();
        }
        Ok(())
    }

    pub(super) fn publish_indexed_catch_up(
        &self,
        status: Option<WalletIndexedCatchUpStatus>,
    ) -> Result<(), WalletBackfillRejectReason> {
        self.revalidate()?;
        if let Err(err) = self.handle.indexed_catch_up_tx.send(status) {
            debug!(?err, cache_key = %self.handle.cache_key, "failed to send indexed wallet catch-up status");
        }
        Ok(())
    }

    pub(super) fn publish_poi_refreshing(
        &self,
        sender: &watch::Sender<bool>,
        value: bool,
    ) -> Result<(), WalletBackfillRejectReason> {
        self.revalidate()?;
        if let Err(err) = sender.send(value) {
            debug!(?err, cache_key = %self.handle.cache_key, "failed to send wallet POI refresh state");
        }
        Ok(())
    }

    pub(super) async fn replace_chain_pending_overlay(
        &self,
        next: WalletPendingOverlay,
    ) -> Result<bool, WalletBackfillRejectReason> {
        self.revalidate()?;
        self.handle
            .replace_chain_pending_overlay_authorized(next, self)
            .await
    }
}

#[derive(Debug, Clone, Default)]
pub struct WalletPendingOverlay {
    pub new_utxos: Vec<WalletUtxo>,
    pub pending_spent: Vec<WalletPendingSpent>,
    pub local_pending_spent: Vec<WalletPendingSpent>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WalletPendingSpent {
    pub tree: u32,
    pub position: u64,
    pub tx_hash: Option<FixedBytes<32>>,
    pub block_number: Option<u64>,
    pub block_timestamp: Option<u64>,
}

impl WalletPendingSpent {
    #[must_use]
    pub const fn key(&self) -> (u32, u64) {
        (self.tree, self.position)
    }

    pub(super) fn from_source(utxo: &Utxo, source: UtxoSource) -> Self {
        Self {
            tree: utxo.tree,
            position: utxo.position,
            tx_hash: Some(source.tx_hash),
            block_number: Some(source.block_number),
            block_timestamp: Some(source.block_timestamp),
        }
    }

    #[cfg(test)]
    pub(super) fn submitted(utxo: &Utxo, tx_hash: Option<FixedBytes<32>>, now: u64) -> Self {
        Self {
            tree: utxo.tree,
            position: utxo.position,
            tx_hash,
            block_number: None,
            block_timestamp: Some(now),
        }
    }
}

impl WalletHandle {
    #[cfg(test)]
    #[must_use]
    pub(crate) const fn actor_id(&self) -> u64 {
        self.actor_id
    }

    #[must_use]
    pub(super) fn is_current_actor(&self) -> bool {
        self.actor_id != RETIRED_WALLET_ACTOR_ID
            && self.active_actor_id.load(Ordering::Acquire) == self.actor_id
    }

    async fn actor_authority(
        &self,
        expected_reset_generation: u64,
    ) -> Result<OwnedMutexGuard<()>, WalletBackfillRejectReason> {
        let guard = Arc::clone(&self.authority_lock).lock_owned().await;
        if !self.is_current_actor() {
            return Err(WalletBackfillRejectReason::Shutdown);
        }
        let current_reset_generation = self.reset_generation();
        if current_reset_generation != expected_reset_generation {
            return Err(WalletBackfillRejectReason::StaleGeneration {
                expected: current_reset_generation,
                actual: expected_reset_generation,
            });
        }
        Ok(guard)
    }

    pub(crate) async fn retire_actor(&self) {
        let _guard = self.authority_lock.lock().await;
        self.active_actor_id
            .store(RETIRED_WALLET_ACTOR_ID, Ordering::Release);
    }

    pub(crate) fn mint_sync_token(&self, reset_generation: u64) -> WalletSyncToken {
        WalletSyncToken::mint(
            WalletActorTokenAuthority { handle: self },
            reset_generation,
            self.next_sync_job_id.fetch_add(1, Ordering::AcqRel),
        )
    }

    pub(crate) async fn start_backfill(
        &self,
        cache_key: &str,
        sender: &mpsc::Sender<BackfillEvent>,
        reset_generation: u64,
        target_block: u64,
    ) -> WalletBackfillFinishResult {
        let lease =
            WalletBackfillLease::from_token(self.mint_sync_token(reset_generation), sender.clone());
        lease.finish(cache_key, target_block).await
    }

    pub(crate) fn mint_reset_token(&self, intent_id: u64) -> WalletResetToken {
        WalletResetToken::mint(WalletActorTokenAuthority { handle: self }, intent_id)
    }

    #[must_use]
    pub fn last_scanned(&self) -> u64 {
        self.last_scanned.load(Ordering::Relaxed)
    }

    #[must_use]
    pub fn readiness(&self) -> WalletReadiness {
        self.readiness_rx.borrow().clone()
    }

    #[must_use]
    pub(crate) fn reset_generation(&self) -> u64 {
        self.reset_generation.load(Ordering::Relaxed)
    }

    #[cfg(test)]
    pub(crate) async fn advance_reset_generation(&self) -> Option<u64> {
        let _guard = self.authority_lock.lock().await;
        if !self.is_current_actor() {
            return None;
        }
        Some(
            self.reset_generation
                .fetch_add(1, Ordering::AcqRel)
                .wrapping_add(1),
        )
    }

    pub(crate) fn set_indexed_catch_up(
        &self,
        lease: WalletIndexedCatchUpLease,
        status: WalletIndexedCatchUpStatus,
    ) {
        if let Err(err) = self
            .indexed_catch_up_status_tx
            .try_send(WalletIndexedCatchUpCommand::Publish { lease, status })
        {
            debug!(?err, cache_key = %self.cache_key, "failed to request indexed wallet catch-up status publication");
        }
    }

    pub(crate) async fn try_claim_indexed_catch_up(&self) -> Option<WalletIndexedCatchUpLease> {
        let (response, result) = oneshot::channel();
        if self
            .indexed_catch_up_status_tx
            .send(WalletIndexedCatchUpCommand::Claim { response })
            .await
            .is_err()
        {
            return None;
        }
        result.await.unwrap_or(None)
    }

    pub(crate) fn clear_indexed_catch_up(&self, lease: WalletIndexedCatchUpLease) {
        if let Err(err) = self
            .indexed_catch_up_status_tx
            .try_send(WalletIndexedCatchUpCommand::Clear { lease })
        {
            debug!(?err, cache_key = %self.cache_key, "failed to request indexed wallet catch-up status clear");
        }
    }

    fn notify_changed_inner(&self) {
        let rev = self.rev_rx.borrow().wrapping_add(1);
        if let Err(err) = self.rev_tx.send(rev) {
            debug!(?err, cache_key = %self.cache_key, "failed to send wallet revision");
        }
    }

    #[cfg(test)]
    pub(crate) fn notify_changed(&self) {
        self.notify_changed_inner();
    }

    pub async fn pending_overlay(&self) -> WalletPendingOverlay {
        self.pending_overlay.read().await.clone()
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

    pub async fn utxos_snapshot(&self) -> Vec<WalletUtxo> {
        self.utxos.read().await.clone()
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
            self.notify_changed_inner();
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
            self.notify_changed_inner();
        }
    }

    #[cfg(test)]
    pub(super) async fn set_chain_pending_overlay(&self, next: WalletPendingOverlay) {
        let changed = self
            .replace_chain_pending_overlay_unchecked(next)
            .await
            .expect("test overlay replacement should not require authority");
        if changed {
            self.notify_changed_inner();
        }
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
        let changed = {
            let mut overlay = self.pending_overlay.write().await;
            permit.revalidate()?;
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
