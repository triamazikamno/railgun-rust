#[allow(clippy::wildcard_imports)]
use super::*;

pub(in crate::wallet) const WALLET_METADATA_LIVE_FLUSH_INTERVAL: super::Duration =
    super::Duration::from_mins(1);
pub(in crate::wallet) const WALLET_METADATA_LIVE_FLUSH_BLOCKS: u64 = 25;

pub(super) use crate::types::WalletPendingSpent;

#[cfg(test)]
impl WalletHandle {
    /// Thin identity fence: does not wait on `authority_lock` (which may be held across remote I/O).
    pub(crate) fn retire_actor(&self) {
        let observation = self.observation.upgrade();
        self.retire_actor_with_observation(observation.as_deref(), WalletInactiveReason::Retired);
    }

    pub(crate) async fn hold_actor_authority_for_test(&self) -> OwnedMutexGuard<()> {
        Arc::clone(&self.authority_lock).lock_owned().await
    }

    pub(crate) fn publish_readiness_for_test(&self, readiness: &WalletReadiness) {
        self.observation
            .upgrade()
            .expect("test observation publisher remains owned")
            .publish_readiness(readiness.clone());
    }

    pub(crate) fn publish_view_for_test(&self, view: WalletViewState) {
        self.observation
            .upgrade()
            .expect("test observation publisher remains owned")
            .publish_view(view);
    }

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

    pub(crate) async fn notify_changed(&self) {
        let utxos = self.utxos.read().await.clone();
        let overlay = self.pending_overlay.read().await.clone();
        self.notify_changed_with_projection(&utxos, &overlay);
    }

    pub(crate) async fn clear_local_pending_spent_for_test(&self) -> bool {
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

    pub(crate) async fn mark_pending_spent_utxos_for_test(
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
            let before = overlay.local_pending_spent.len();
            let mut updated_existing = false;
            for utxo in utxos {
                let submitted = test_support::WalletPendingSpent::submitted(utxo, tx_hash, now);
                if let Some(existing) = overlay.local_pending_spent.iter_mut().find(|spent| {
                    spent.key() == submitted.key()
                        && spent.stable_identity == submitted.stable_identity
                }) {
                    if existing != &submitted {
                        *existing = submitted;
                        updated_existing = true;
                    }
                } else {
                    overlay.local_pending_spent.push(submitted);
                }
            }
            overlay
                .local_pending_spent
                .sort_by_key(test_support::WalletPendingSpent::key);
            overlay.local_pending_spent.len() != before || updated_existing
        };
        if changed {
            self.notify_changed().await;
        }
    }

    pub(in crate::wallet) async fn set_chain_pending_overlay(&self, next: WalletPendingOverlay) {
        let _ = self
            .replace_chain_pending_overlay_unchecked(next)
            .await
            .expect("test overlay replacement should not require authority");
        // Always republish: tests may seed local_pending_spent on the live lock first.
        self.notify_changed().await;
    }

    async fn replace_chain_pending_overlay_unchecked(
        &self,
        next: WalletPendingOverlay,
    ) -> Result<bool, WalletBackfillRejectReason> {
        let now = now_epoch_secs();
        let confirmed_spent: Vec<_> = {
            let utxos = self.utxos.read().await;
            utxos
                .iter()
                .filter(|utxo| utxo.is_spent())
                .cloned()
                .collect()
        };
        let changed = {
            let mut overlay = self.pending_overlay.write().await;
            let chain_changed = !chain_pending_overlay_matches(&overlay, &next);
            let before_local = overlay.local_pending_spent.len();
            overlay.local_pending_spent.retain(|spent| {
                if confirmed_spent
                    .iter()
                    .any(|utxo| spent.matches_local_utxo(utxo))
                {
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
}
