//! Restored state and fresh channels for a wallet worker that is being prepared.

#[allow(clippy::wildcard_imports)]
use super::*;
use crate::types::WalletObservation;
use crate::wallet::handle::{WalletPendingOverlayRequest, WalletPoiRefreshRequest};

/// The wallet's POI corpus subscription, present only when POI reads come from indexed
/// artifacts.
pub(super) struct WalletPoiCorpusStart {
    pub(super) handle: Option<PublicPoiCorpusHandle>,
    pub(super) revision_rx: Option<watch::Receiver<PoiCorpusRevision>>,
    pub(super) last_revision: PoiCorpusRevision,
    /// A committed corpus revision means blocked shields need a refresh at startup.
    pub(super) blocked_shield_refresh_pending: bool,
}

pub(super) async fn open_wallet_poi_corpus(
    poi_runtime: &WalletPoiRuntime,
    public_data_plane: &ChainPublicDataPlane,
    chain_id: u64,
) -> Result<WalletPoiCorpusStart, ChainError> {
    if !poi_runtime.is_indexed_artifacts() {
        return Ok(WalletPoiCorpusStart {
            handle: None,
            revision_rx: None,
            last_revision: PoiCorpusRevision::default(),
            blocked_shield_refresh_pending: false,
        });
    }
    let corpus = public_data_plane
        .ensure_poi_corpus(PublicPoiCorpusKey::wallet_default(chain_id))
        .await
        .map_err(ChainError::from)?;
    let mut revision_rx = corpus.committed_revision_rx();
    let last_revision = *revision_rx.borrow_and_update();
    Ok(WalletPoiCorpusStart {
        handle: Some(corpus),
        revision_rx: Some(revision_rx),
        last_revision,
        blocked_shield_refresh_pending: last_revision.revision > 0,
    })
}

/// The persisted pending reset, validated against the cache cursor, and the highest reset
/// intent the actor accepted before.
pub(super) fn restore_wallet_sync_state(
    cache_store: &dyn WalletCacheStore,
    cfg: &WalletConfig,
    initial_last_scanned: u64,
) -> Result<(Option<PendingWalletReset>, u64), ChainError> {
    let restored_sync_state =
        cache_store.get_wallet_sync_actor_state(cfg.chain.chain_id, &cfg.cache_key)?;
    let restored_pending_reset = restored_sync_state
        .as_ref()
        .and_then(|state| state.pending_reset.as_ref())
        .map(|pending| {
            PendingWalletReset::new(
                pending.intent_id,
                pending.from_block,
                1,
                WalletResetReplayPlan::new(
                    pending.replay_start_block,
                    pending.replay_target_block,
                    pending.follow_safe_head,
                ),
            )
        });
    if let Some(pending) = restored_pending_reset {
        validate_restored_pending_reset(cfg, initial_last_scanned, pending)?;
    }
    let restored_highest_reset_intent = restored_sync_state
        .as_ref()
        .map_or(0, |state| state.highest_accepted_reset_intent);
    Ok((restored_pending_reset, restored_highest_reset_intent))
}

/// The view the actor starts with: reset-pending when a reset was restored, otherwise the
/// cached UTXOs.
pub(super) fn initial_wallet_view(
    pending_reset: Option<&PendingWalletReset>,
    utxos: &RwLock<Vec<WalletUtxo>>,
    last_scanned: u64,
    reset_generation: u64,
) -> WalletViewState {
    if let Some(pending) = pending_reset {
        WalletViewState::ResetPending {
            intent_id: pending.intent_id(),
            from_block: pending.rewind_from_block(),
            reset_generation: pending.reset_generation(),
        }
    } else {
        let initial_utxos = utxos
            .try_read()
            .map(|guard| guard.clone())
            .unwrap_or_default();
        WalletViewState::Current(WalletCurrentSnapshot::new(
            last_scanned,
            0,
            reset_generation,
            Arc::<[WalletUtxo]>::from(initial_utxos),
            Arc::new(WalletPendingOverlay::default()),
        ))
    }
}

/// The actor-side receivers of the prepared handle's request channels.
pub(super) struct WalletActorInbox {
    pub(super) poi_refresh_rx: mpsc::Receiver<WalletPoiRefreshRequest>,
    pub(super) pending_overlay_rx: mpsc::Receiver<WalletPendingOverlayRequest>,
    pub(super) private_request_rx: mpsc::Receiver<WalletPrivateRequest>,
    pub(super) indexed_catch_up_status_rx: mpsc::UnboundedReceiver<WalletIndexedCatchUpCommand>,
}

/// A prepared actor's handle on fresh channels, with the receivers and the POI-refreshing
/// sender the actor keeps.
pub(super) fn new_prepared_wallet_handle(
    cfg: &WalletConfig,
    actor_id: u64,
    utxos: &Arc<RwLock<Vec<WalletUtxo>>>,
    observation: &Arc<WalletObservationPublisher>,
    observation_rx: watch::Receiver<WalletObservation>,
    last_scanned: u64,
    reset_generation: u64,
) -> (WalletHandle, WalletActorInbox, watch::Sender<bool>) {
    let (rev_tx, rev_rx) = watch::channel(0_u64);
    let (reset_generation_tx, reset_generation_rx) = watch::channel(reset_generation);
    let (poi_refresh_tx, poi_refresh_rx) = mpsc::channel(1);
    let (pending_overlay_tx, pending_overlay_rx) = mpsc::channel(8);
    let (private_request_tx, private_request_rx) = mpsc::channel(8);
    let (indexed_catch_up_status_tx, indexed_catch_up_status_rx) = mpsc::unbounded_channel();
    let (poi_refreshing_tx, poi_refreshing_rx) = watch::channel(false);
    let (indexed_catch_up_tx, indexed_catch_up_rx) = watch::channel(None);
    let handle = WalletHandle {
        cache_key: cfg.cache_key.clone(),
        chain: cfg.chain,
        actor_id,
        active_actor_id: Arc::new(AtomicU64::new(actor_id)),
        lifecycle: Arc::new(WalletActorLifecycleCell::new_prepared()),
        authority_lock: Arc::new(Mutex::new(())),
        utxos: Arc::clone(utxos),
        pending_overlay: Arc::new(RwLock::new(WalletPendingOverlay::default())),
        last_scanned: Arc::new(AtomicU64::new(last_scanned)),
        reset_generation: Arc::new(AtomicU64::new(reset_generation)),
        reset_generation_rx,
        next_sync_job_id: Arc::new(AtomicU64::new(1)),
        observation: Arc::downgrade(observation),
        observation_rx,
        rev_rx,
        poi_refreshing_rx,
        indexed_catch_up_rx,
        pending_overlay_tx,
        private_request_tx,
        poi_refresh_tx,
        indexed_catch_up_status_tx,
        rev_tx,
        reset_generation_tx,
        indexed_catch_up_tx,
    };
    let inbox = WalletActorInbox {
        poi_refresh_rx,
        pending_overlay_rx,
        private_request_rx,
        indexed_catch_up_status_rx,
    };
    (handle, inbox, poi_refreshing_tx)
}
