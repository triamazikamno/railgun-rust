#[allow(clippy::wildcard_imports)]
use super::*;

pub(super) async fn mark_local_pending_spent(
    handle: &WalletHandle,
    cancel: &CancellationToken,
    reset_generation: u64,
    utxos: Vec<railgun_wallet::Utxo>,
    tx_hash: Option<FixedBytes<32>>,
) -> Result<WalletPendingSpentMarkOutcome, WalletPrivateRequestError> {
    let authority = WalletPrivateMutationAuthority::new(handle, reset_generation, cancel);
    let permit = authority
        .acquire()
        .await
        .map_err(|reason| wallet_private_request_error(&reason))?;
    let confirmed = permit.handle_utxos().read().await;
    permit
        .revalidate()
        .map_err(|reason| wallet_private_request_error(&reason))?;
    let current_identities = confirmed
        .iter()
        .map(|utxo| {
            (
                utxo.utxo.tree,
                utxo.utxo.position,
                wallet_utxo_stable_identity(utxo),
                utxo.is_spent(),
            )
        })
        .collect::<HashSet<_>>();
    let mut overlay = permit.pending_overlay().write().await;
    permit
        .with_active_apply(|token| {
            let now = now_epoch_secs();
            let mut marked = prune_local_pending_spent(&mut overlay, &confirmed, now);
            for utxo in utxos {
                let key = (utxo.tree, utxo.position);
                let submitted = WalletPendingSpent::submitted(&utxo, tx_hash, now);
                let identity = submitted
                    .stable_identity
                    .as_ref()
                    .expect("submitted lock has stable identity");
                if current_identities.contains(&(utxo.tree, utxo.position, identity.clone(), true))
                {
                    let previous_len = overlay.local_pending_spent.len();
                    overlay.local_pending_spent.retain(|spent| {
                        spent.key() != key || spent.stable_identity.as_ref() != Some(identity)
                    });
                    marked |= overlay.local_pending_spent.len() != previous_len;
                    continue;
                }
                if let Some(existing) = overlay.local_pending_spent.iter_mut().find(|spent| {
                    spent.key() == key && spent.stable_identity.as_ref() == Some(identity)
                }) {
                    if existing.tx_hash != tx_hash {
                        existing.tx_hash = tx_hash;
                        existing.block_timestamp = Some(now);
                        marked = true;
                    } else if tx_hash.is_some() && existing.block_timestamp != Some(now) {
                        existing.block_timestamp = Some(now);
                        marked = true;
                    }
                    continue;
                }
                overlay.local_pending_spent.push(submitted);
                marked = true;
            }
            overlay
                .local_pending_spent
                .sort_by_key(WalletPendingSpent::key);
            if marked {
                permit.apply_notify_changed(&token, &confirmed, &overlay);
            }
            if marked {
                WalletPendingSpentMarkOutcome::Marked
            } else {
                WalletPendingSpentMarkOutcome::AlreadyProtected
            }
        })
        .map_err(|reason| wallet_private_request_error(&reason))
}

pub(super) fn prune_local_pending_spent(
    overlay: &mut WalletPendingOverlay,
    confirmed: &[WalletUtxo],
    now: u64,
) -> bool {
    let before = overlay.local_pending_spent.len();
    overlay.local_pending_spent.retain(|spent| {
        let submitted_at = spent.block_timestamp.unwrap_or(now);
        now.saturating_sub(submitted_at) < LOCAL_PENDING_SPENT_TTL.as_secs()
            && !confirmed
                .iter()
                .any(|utxo| utxo.is_spent() && spent.matches_local_utxo(utxo))
    });
    overlay.local_pending_spent.len() != before
}

pub(super) async fn wait_for_local_pending_spent_expiry(handle: &WalletHandle) -> u64 {
    let now = now_epoch_secs();
    let next_expiry = handle
        .pending_overlay
        .read()
        .await
        .local_pending_spent
        .iter()
        .map(|spent| {
            spent
                .block_timestamp
                .unwrap_or(now)
                .saturating_add(LOCAL_PENDING_SPENT_TTL.as_secs())
        })
        .min();
    let Some(next_expiry) = next_expiry else {
        return futures::future::pending().await;
    };
    tokio::time::sleep(Duration::from_secs(next_expiry.saturating_sub(now))).await;
    next_expiry
}

pub(super) async fn expire_local_pending_spent(
    handle: &WalletHandle,
    cancel: &CancellationToken,
    reset_generation: u64,
    expiry: u64,
) -> Result<bool, WalletPrivateRequestError> {
    let authority = WalletPrivateMutationAuthority::new(handle, reset_generation, cancel);
    let permit = authority
        .acquire()
        .await
        .map_err(|reason| wallet_private_request_error(&reason))?;
    let confirmed = permit.handle_utxos().read().await;
    permit
        .revalidate()
        .map_err(|reason| wallet_private_request_error(&reason))?;
    let mut overlay = permit.pending_overlay().write().await;
    permit
        .with_active_apply(|token| {
            let changed = prune_local_pending_spent(&mut overlay, &confirmed, expiry);
            if changed {
                permit.apply_notify_changed(&token, &confirmed, &overlay);
            }
            changed
        })
        .map_err(|reason| wallet_private_request_error(&reason))
}

pub(super) async fn clear_local_pending_spent(
    handle: &WalletHandle,
    cancel: &CancellationToken,
    reset_generation: u64,
) -> Result<bool, WalletPrivateRequestError> {
    let authority = WalletPrivateMutationAuthority::new(handle, reset_generation, cancel);
    let permit = authority
        .acquire()
        .await
        .map_err(|reason| wallet_private_request_error(&reason))?;
    let confirmed = permit.handle_utxos().read().await;
    permit
        .revalidate()
        .map_err(|reason| wallet_private_request_error(&reason))?;
    let mut overlay = permit.pending_overlay().write().await;
    permit
        .with_active_apply(|token| {
            let changed = !overlay.local_pending_spent.is_empty();
            overlay.local_pending_spent.clear();
            if changed {
                permit.apply_notify_changed(&token, &confirmed, &overlay);
            }
            changed
        })
        .map_err(|reason| wallet_private_request_error(&reason))
}
