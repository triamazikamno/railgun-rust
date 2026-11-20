#[allow(clippy::wildcard_imports)]
use super::*;

/// Route private POI durable writes: jobs re-enter the actor; tests/inline use short permit.
///
/// Invariant: only the wallet actor turn mutates private UTXO mirrors. Jobs must attach
/// [`WalletPrivateApplyClient`] via [`WalletPrivateMutationAuthority::with_apply_client`].
pub(in crate::wallet) async fn apply_poi_private_delta(
    authority: &WalletPrivateMutationAuthority<'_>,
    db: &DbStore,
    cache_store: &dyn WalletCacheStore,
    cfg: &WalletConfig,
    delta: OwnedPoiPrivateDelta,
) -> Result<PoiPrivateApplyOutcome, WalletCacheError> {
    if let Some(client) = authority.apply_client() {
        return client.apply(authority.reset_generation(), delta).await;
    }
    let active_list_keys = default_active_poi_list_keys();
    apply_poi_private_delta_inline(authority, db, cache_store, cfg, &active_list_keys, delta).await
}

/// Actor-turn apply of an owned POI delta (sole private writer path).
#[cfg(test)]
pub(in crate::wallet) async fn apply_owned_poi_private_delta_on_actor(
    handle: &WalletHandle,
    cancel: &CancellationToken,
    reset_generation: u64,
    db: &DbStore,
    cache_store: &dyn WalletCacheStore,
    cfg: &WalletConfig,
    delta: OwnedPoiPrivateDelta,
) -> Result<PoiPrivateApplyOutcome, WalletCacheError> {
    apply_owned_poi_private_delta_on_actor_with_active_lists(
        handle,
        cancel,
        reset_generation,
        db,
        cache_store,
        cfg,
        &default_active_poi_list_keys(),
        delta,
    )
    .await
}

/// Actor-turn apply using the actor's current active-list configuration.
pub(in crate::wallet) async fn apply_owned_poi_private_delta_on_actor_with_active_lists(
    handle: &WalletHandle,
    cancel: &CancellationToken,
    reset_generation: u64,
    db: &DbStore,
    cache_store: &dyn WalletCacheStore,
    cfg: &WalletConfig,
    active_list_keys: &[FixedBytes<32>],
    delta: OwnedPoiPrivateDelta,
) -> Result<PoiPrivateApplyOutcome, WalletCacheError> {
    let authority = WalletPrivateMutationAuthority::new(handle, reset_generation, cancel);
    apply_poi_private_delta_inline(&authority, db, cache_store, cfg, active_list_keys, delta).await
}

/// Holds the chain POI corpus read fence for a commit that consumes a local proof.
///
/// Call after the mutation permit and any public-data commit guard, and keep the returned guard
/// through the durable commit. Returns the stale outcome, with the fence released, when the
/// corpus revision changed after the proof source was read. A commit without an expected
/// revision takes no corpus fence.
pub(super) async fn hold_expected_poi_corpus_revision(
    expected: Option<&ExpectedPoiCorpusRevision>,
) -> Result<Option<tokio::sync::OwnedRwLockReadGuard<()>>, PoiPrivateApplyOutcome> {
    let Some(expected) = expected else {
        return Ok(None);
    };
    let revision_fence = expected.corpus.revision_read_fence().await;
    if *expected.corpus.committed_revision_rx().borrow() != expected.revision {
        return Err(PoiPrivateApplyOutcome::SkippedStaleCorpusRevision);
    }
    Ok(Some(revision_fence))
}
