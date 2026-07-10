use super::{
    BTreeMap, BlindedCommitmentData, DbStore, EVM_CHAIN_TYPE, Error, FixedBytes, Instant,
    OwnedPoiPrivateDelta, POI_MERKLETREE_LEAVES_PAGE_SIZE, PoiCache, PoiCacheError,
    PoiPrivateApplyOutcome, PoiRpcClient, PoiRpcError, PoiStatusReader, SnapshotEvent, U256,
    WALLET_POI_STATUS_BATCH_SIZE, WalletBackfillRejectReason, WalletCacheStore, WalletConfig,
    WalletPoiRefreshSelection, WalletPrivateMutationAuthority, WalletPrivatePoiClients,
    WalletPrivateRemoteError, WalletPrivateRemoteStale, WalletUtxo, apply_poi_private_delta,
    blinded_commitment_type, debug, now_epoch_secs, warn,
};
use broadcaster_core::transact::DEFAULT_TXID_VERSION;
use broadcaster_core::transact::MERKLE_ZERO_VALUE;

pub(super) async fn refresh_wallet_poi_statuses_selected(
    client: &dyn PoiStatusReader,
    chain_id: u64,
    active_list_keys: &[FixedBytes<32>],
    wallet_utxos: &mut [WalletUtxo],
    selection: WalletPoiRefreshSelection,
) -> bool {
    if active_list_keys.is_empty() {
        return false;
    }

    let started = Instant::now();
    let selection_label = selection.as_str();
    let unspent: Vec<_> = wallet_utxos
        .iter()
        .enumerate()
        .filter(|(_, wallet_utxo)| {
            !wallet_utxo.is_spent() && selection.matches_wallet_utxo(wallet_utxo, active_list_keys)
        })
        .map(|(index, wallet_utxo)| {
            (
                index,
                BlindedCommitmentData::new(
                    wallet_utxo.utxo.poi.blinded_commitment,
                    blinded_commitment_type(wallet_utxo.utxo.poi.commitment_kind),
                ),
            )
        })
        .collect();

    debug!(
        chain_id,
        selection = selection_label,
        list_keys = active_list_keys.len(),
        commitments = unspent.len(),
        batch_size = WALLET_POI_STATUS_BATCH_SIZE,
        "wallet POI status refresh started"
    );
    let mut status_changes = 0usize;
    for (chunk_index, chunk) in unspent.chunks(WALLET_POI_STATUS_BATCH_SIZE).enumerate() {
        let request_data: Vec<_> = chunk.iter().map(|(_, data)| *data).collect();
        let chunk_started = Instant::now();
        match client
            .pois_per_list(
                DEFAULT_TXID_VERSION,
                EVM_CHAIN_TYPE,
                chain_id,
                active_list_keys,
                &request_data,
            )
            .await
        {
            Ok(statuses_by_blinded_commitment) => {
                let chunk_elapsed_ms = chunk_started.elapsed().as_millis();
                let refreshed_at = now_epoch_secs();
                for (index, data) in chunk {
                    let Some(wallet_utxo) = wallet_utxos.get_mut(*index) else {
                        continue;
                    };
                    status_changes += wallet_utxo.utxo.poi.apply_status_refresh(
                        active_list_keys,
                        statuses_by_blinded_commitment.get(&data.blinded_commitment),
                        refreshed_at,
                    );
                }
                debug!(
                    chain_id,
                    selection = selection_label,
                    chunk_index,
                    commitments = chunk.len(),
                    returned_commitments = statuses_by_blinded_commitment.len(),
                    elapsed_ms = chunk_elapsed_ms,
                    "wallet POI status chunk complete"
                );
            }
            Err(error) => {
                let chunk_elapsed_ms = chunk_started.elapsed().as_millis();
                warn!(
                    ?error,
                    chain_id,
                    commitments = chunk.len(),
                    chunk_index,
                    elapsed_ms = chunk_elapsed_ms,
                    "wallet POI status chunk failed; leaving statuses unknown"
                );
                for (index, _) in chunk {
                    let Some(wallet_utxo) = wallet_utxos.get_mut(*index) else {
                        continue;
                    };
                    status_changes += wallet_utxo
                        .utxo
                        .poi
                        .mark_statuses_unknown_for_lists(active_list_keys);
                }
            }
        }
    }
    let changed = status_changes > 0;
    debug!(
        chain_id,
        selection = selection_label,
        commitments = unspent.len(),
        status_changes,
        changed,
        elapsed_ms = started.elapsed().as_millis(),
        "wallet POI status refresh complete"
    );
    changed
}

/// Remote general-status refresh for `PoiProxy` / artifact fallback jobs.
///
/// Every batch is a separately authorized private disclosure. Results re-enter the
/// actor as a pure intent and are folded against the current UTXO set before commit.
pub(super) async fn refresh_wallet_poi_statuses_remote_authorized(
    authority: &WalletPrivateMutationAuthority<'_>,
    private_poi: &WalletPrivatePoiClients,
    db: &DbStore,
    cache_store: &dyn WalletCacheStore,
    cfg: &WalletConfig,
    active_list_keys: &[FixedBytes<32>],
    selection: WalletPoiRefreshSelection,
) -> bool {
    if active_list_keys.is_empty() {
        return false;
    }
    let snapshot = match authority.wallet_utxos().await {
        Ok(snapshot) => snapshot,
        Err(reason) => {
            debug!(?reason, cache_key = %cfg.cache_key, "remote wallet POI status refresh skipped");
            return false;
        }
    };
    let candidate_utxos = snapshot
        .iter()
        .filter(|wallet_utxo| {
            !wallet_utxo.is_spent() && selection.matches_wallet_utxo(wallet_utxo, active_list_keys)
        })
        .collect::<Vec<_>>();
    let candidates = candidate_utxos
        .iter()
        .map(|wallet_utxo| {
            BlindedCommitmentData::new(
                wallet_utxo.utxo.poi.blinded_commitment,
                blinded_commitment_type(wallet_utxo.utxo.poi.commitment_kind),
            )
        })
        .collect::<Vec<_>>();
    if candidates.is_empty() {
        return false;
    }
    let expected_poi_by_blinded_commitment = candidate_utxos
        .iter()
        .map(|wallet_utxo| {
            (
                wallet_utxo.utxo.poi.blinded_commitment,
                wallet_utxo.utxo.poi.clone(),
            )
        })
        .collect::<BTreeMap<_, _>>();

    let mut statuses_by_blinded_commitment = BTreeMap::new();
    for chunk in candidates.chunks(WALLET_POI_STATUS_BATCH_SIZE) {
        let request_data = chunk.to_vec();
        let request_commitments = request_data
            .iter()
            .map(|data| data.blinded_commitment)
            .collect::<Vec<_>>();
        let response = private_poi
            .pois_per_list(
                || async {
                    let current = authority.wallet_utxos().await?;
                    Ok::<bool, WalletBackfillRejectReason>(request_commitments.iter().all(
                        |commitment| {
                            current.iter().any(|utxo| {
                                !utxo.is_spent() && utxo.utxo.poi.blinded_commitment == *commitment
                            })
                        },
                    ))
                },
                DEFAULT_TXID_VERSION,
                EVM_CHAIN_TYPE,
                cfg.chain.chain_id,
                active_list_keys,
                &request_data,
            )
            .await;
        match response {
            Ok(statuses) => statuses_by_blinded_commitment.extend(statuses),
            Err(WalletPrivateRemoteError::Stale(WalletPrivateRemoteStale::Subject)) => {}
            Err(WalletPrivateRemoteError::Stale(WalletPrivateRemoteStale::Authority)) => break,
            Err(WalletPrivateRemoteError::Check(reason)) => {
                debug!(?reason, cache_key = %cfg.cache_key, "remote wallet POI status check rejected");
                break;
            }
            Err(WalletPrivateRemoteError::Remote(error)) => {
                warn!(?error, cache_key = %cfg.cache_key, "remote wallet POI status batch failed");
            }
        }
    }
    if statuses_by_blinded_commitment.is_empty() {
        return false;
    }

    matches!(
        apply_poi_private_delta(
            authority,
            db,
            cache_store,
            cfg,
            OwnedPoiPrivateDelta::PoiStatusRefresh {
                active_list_keys: active_list_keys.to_vec(),
                expected_poi_by_blinded_commitment,
                statuses_by_blinded_commitment,
                refreshed_at: now_epoch_secs(),
            },
        )
        .await,
        Ok(PoiPrivateApplyOutcome::Applied { utxo_changed: true })
    )
}

#[derive(Debug, Default)]
pub(crate) struct LivePoiTailOutcome {
    pub(crate) events: usize,
    pub(crate) pages: usize,
    pub(crate) start_index: u64,
    pub(crate) next_event_index: u64,
}

#[derive(Debug, Error)]
pub(crate) enum LivePoiTailError {
    #[error("live POI tail request failed")]
    Rpc(#[from] PoiRpcError),
    #[error("live POI cache update failed")]
    Cache(#[from] PoiCacheError),
    #[error("live POI event range overflow")]
    RangeOverflow,
    #[error("live POI roots were rejected by the POI RPC")]
    RootRejected,
}

pub(crate) async fn sync_live_poi_event_tail(
    client: &PoiRpcClient,
    cache: &mut PoiCache,
) -> Result<LivePoiTailOutcome, LivePoiTailError> {
    let identity = cache.identity().clone();
    let mut outcome = LivePoiTailOutcome {
        start_index: cache.progress().next_event_index,
        next_event_index: cache.progress().next_event_index,
        ..LivePoiTailOutcome::default()
    };
    if outcome.next_event_index == 0 {
        return Ok(outcome);
    }

    loop {
        let start_index = outcome.next_event_index;
        let end_index = start_index
            .checked_add(POI_MERKLETREE_LEAVES_PAGE_SIZE)
            .ok_or(LivePoiTailError::RangeOverflow)?;
        let leaves = client
            .poi_merkletree_leaves(
                &identity.txid_version,
                identity.chain_type,
                identity.chain_id,
                &identity.list_key,
                start_index,
                end_index,
            )
            .await?;
        let leaves = trim_zero_padding(&leaves);
        if leaves.is_empty() {
            break;
        }
        let returned = leaves.len();
        apply_live_poi_leaves(cache, start_index, leaves)?;
        outcome.events += returned;
        outcome.pages += 1;
        outcome.next_event_index = cache.progress().next_event_index;
        if returned < POI_MERKLETREE_LEAVES_PAGE_SIZE as usize {
            break;
        }
    }

    if outcome.events > 0 && !cache.validate_roots(client).await? {
        return Err(LivePoiTailError::RootRejected);
    }

    Ok(outcome)
}

pub(crate) async fn live_tail_candidate_cache(
    client: &PoiRpcClient,
    cache: &PoiCache,
) -> Result<(PoiCache, LivePoiTailOutcome), LivePoiTailError> {
    let mut tailed_cache = cache.clone();
    let outcome = sync_live_poi_event_tail(client, &mut tailed_cache).await?;
    Ok((tailed_cache, outcome))
}

pub(super) fn apply_live_poi_leaves(
    cache: &mut PoiCache,
    start_index: u64,
    leaves: &[U256],
) -> Result<(), LivePoiTailError> {
    let mut snapshot_events = Vec::with_capacity(leaves.len());
    for (offset, leaf) in leaves.iter().enumerate() {
        let event_index = start_index
            .checked_add(offset as u64)
            .ok_or(LivePoiTailError::RangeOverflow)?;
        snapshot_events.push(SnapshotEvent {
            event_index,
            blinded_commitment: leaf.to_be_bytes::<32>(),
            signature: [0; 64],
            event_type: poi::poi::PoiEventType::Shield,
        });
    }
    cache.apply_verified_artifact_events(&snapshot_events)?;
    Ok(())
}

pub(super) fn trim_zero_padding(leaves: &[U256]) -> &[U256] {
    let zero_leaf = MERKLE_ZERO_VALUE;
    for (index, leaf) in leaves.iter().enumerate() {
        if *leaf == zero_leaf {
            return &leaves[..index];
        }
    }
    leaves
}
