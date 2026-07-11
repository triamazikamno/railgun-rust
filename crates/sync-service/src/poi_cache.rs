use std::collections::{BTreeMap, HashMap, hash_map::Entry};
use std::sync::Arc;
use std::sync::atomic::AtomicU64;
use std::time::{Duration, Instant, SystemTime};

use alloy::hex;
use alloy::primitives::FixedBytes;
use broadcaster_core::transact::DEFAULT_TXID_VERSION;
use local_db::DbStore;
use poi::cache::{PoiCache, PoiCacheIdentity};
use poi::poi::{DEFAULT_WALLET_POI_RPC_URL, PoiRpcClient, default_active_poi_list_keys};
use tokio::sync::{RwLock, watch};
use tokio_util::sync::CancellationToken;
use tracing::{Instrument, debug, info, warn};
use url::Url;

use crate::poi_artifacts::{
    PersistedPoiArtifactCache, PoiArtifactIngestor, PoiArtifactProgressEvent,
    clear_poi_artifact_cache_for_reset, load_persisted_cache, poi_artifact_cache_generation_cell,
    with_poi_artifact_cache_generation,
};
use crate::types::{
    LocalPoiCaches, PoiArtifactCacheListProgress, PoiArtifactCachePhase, PoiArtifactCacheProgress,
    PoiArtifactSourceConfig,
};
use crate::wallet::{
    live_tail_candidate_cache, sync_live_poi_event_tail, wallet_poi_status_client,
};

const EVM_CHAIN_TYPE: u8 = 0;
const POI_ARTIFACT_CACHE_SYNC_INTERVAL: Duration = Duration::from_mins(5);
const POI_ARTIFACT_CACHE_LIVE_TAIL_INTERVAL: Duration = Duration::from_mins(1);

struct ChainPoiCacheLoop {
    db: Arc<DbStore>,
    http_client: Option<reqwest::Client>,
    poi_rpc_url: Url,
    artifact_config: PoiArtifactSourceConfig,
    chain_id: u64,
    local_caches: LocalPoiCaches,
    active_list_keys: Vec<FixedBytes<32>>,
    preloaded_caches: BTreeMap<FixedBytes<32>, PersistedPoiArtifactCache>,
    progress_tx: watch::Sender<BTreeMap<u64, PoiArtifactCacheProgress>>,
    cancel: CancellationToken,
}

pub(crate) struct PoiCacheService {
    db: Arc<DbStore>,
    artifact_config: PoiArtifactSourceConfig,
    http_client: Option<reqwest::Client>,
    poi_rpc_url: Url,
    chains: RwLock<HashMap<u64, LocalPoiCaches>>,
    progress_tx: watch::Sender<BTreeMap<u64, PoiArtifactCacheProgress>>,
    cancel: CancellationToken,
    cache_generation: Arc<AtomicU64>,
}

impl PoiCacheService {
    pub(crate) fn new(
        db: Arc<DbStore>,
        artifact_config: PoiArtifactSourceConfig,
        http_client: Option<reqwest::Client>,
    ) -> Result<Self, local_db::DbError> {
        let (progress_tx, _) = watch::channel(BTreeMap::new());
        let cache_generation = poi_artifact_cache_generation_cell(&db)?;
        Ok(Self {
            db,
            artifact_config,
            http_client,
            poi_rpc_url: default_poi_rpc_url(),
            chains: RwLock::new(HashMap::new()),
            progress_tx,
            cancel: CancellationToken::new(),
            cache_generation,
        })
    }

    #[must_use]
    pub(crate) fn with_poi_rpc_url(mut self, poi_rpc_url: Url) -> Self {
        self.poi_rpc_url = poi_rpc_url;
        self
    }

    #[cfg(test)]
    #[must_use]
    pub(crate) fn progress_rx(&self) -> watch::Receiver<BTreeMap<u64, PoiArtifactCacheProgress>> {
        self.progress_tx.subscribe()
    }

    pub(crate) async fn start_chain(&self, chain_id: u64) -> LocalPoiCaches {
        if let Some(existing) = self.local_caches(chain_id).await {
            return existing;
        }

        let local_caches = LocalPoiCaches::new(Arc::clone(&self.cache_generation));
        let concurrent_existing = {
            let mut chains = self.chains.write().await;
            match chains.entry(chain_id) {
                Entry::Occupied(entry) => Some(entry.get().clone()),
                Entry::Vacant(entry) => {
                    entry.insert(local_caches.clone());
                    None
                }
            }
        };
        if let Some(existing) = concurrent_existing {
            return existing;
        }

        let active_list_keys = default_active_poi_list_keys();
        send_poi_artifact_cache_progress(
            &self.progress_tx,
            new_poi_artifact_cache_progress(
                chain_id,
                PoiArtifactCachePhase::LoadingPersisted,
                0,
                active_list_keys.len(),
                None,
                None,
                None,
                poi_cache_list_progress_for_keys(&active_list_keys),
                false,
                None,
            ),
        );
        let mut preloaded_caches = install_persisted_chain_poi_caches(
            self.db.as_ref(),
            chain_id,
            &local_caches,
            &active_list_keys,
        )
        .await;
        synchronize_chain_cache_generation(chain_id, &local_caches, Some(&mut preloaded_caches))
            .await;
        emit_chain_poi_cache_ready_progress(
            &self.progress_tx,
            chain_id,
            &local_caches,
            &active_list_keys,
        )
        .await;
        spawn_chain_poi_cache_loop(ChainPoiCacheLoop {
            db: Arc::clone(&self.db),
            http_client: self.http_client.clone(),
            poi_rpc_url: self.poi_rpc_url.clone(),
            artifact_config: self.artifact_config.clone(),
            chain_id,
            local_caches: local_caches.clone(),
            active_list_keys,
            preloaded_caches,
            progress_tx: self.progress_tx.clone(),
            cancel: self.cancel.child_token(),
        });
        local_caches
    }

    pub(crate) async fn local_caches(&self, chain_id: u64) -> Option<LocalPoiCaches> {
        let local_caches = self.chains.read().await.get(&chain_id).cloned()?;
        if synchronize_chain_cache_generation(chain_id, &local_caches, None).await {
            send_stale_chain_poi_cache_progress(&self.progress_tx, chain_id);
            spawn_chain_poi_cache_resync(
                Arc::clone(&self.db),
                self.http_client.clone(),
                self.poi_rpc_url.clone(),
                self.artifact_config.clone(),
                chain_id,
                local_caches.clone(),
                self.progress_tx.clone(),
            );
        }
        Some(local_caches)
    }

    pub(crate) async fn reset_poi_artifact_cache(&self) -> Result<u64, local_db::DbError> {
        let reset = clear_poi_artifact_cache_for_reset(&self.db)?;
        debug!(
            generation = reset.generation,
            "POI artifact cache generation published after durable reset"
        );
        let chains: Vec<_> = self
            .chains
            .read()
            .await
            .iter()
            .map(|(chain_id, local_caches)| (*chain_id, local_caches.clone()))
            .collect();
        let chain_count = chains.len();

        for (chain_id, local_caches) in &chains {
            let active_list_keys = default_active_poi_list_keys();
            send_poi_artifact_cache_progress(
                &self.progress_tx,
                new_poi_artifact_cache_progress(
                    *chain_id,
                    PoiArtifactCachePhase::Resetting,
                    0,
                    active_list_keys.len(),
                    None,
                    None,
                    None,
                    poi_cache_list_progress_for_keys(&active_list_keys),
                    false,
                    None,
                ),
            );
            local_caches.synchronize_generation().await;
            let installed_generation = local_caches.installed_generation();
            info!(
                chain_id,
                installed_generation, "fenced in-memory artifact POI cache"
            );
        }

        for (chain_id, local_caches) in chains {
            spawn_chain_poi_cache_resync(
                Arc::clone(&self.db),
                self.http_client.clone(),
                self.poi_rpc_url.clone(),
                self.artifact_config.clone(),
                chain_id,
                local_caches,
                self.progress_tx.clone(),
            );
        }

        info!(
            persisted_records = reset.removed,
            generation = reset.generation,
            chain_count,
            "reset local artifact POI cache"
        );
        Ok(reset.removed)
    }

    pub(crate) fn shutdown(&self) {
        self.cancel.cancel();
    }
}

fn default_poi_rpc_url() -> Url {
    Url::parse(DEFAULT_WALLET_POI_RPC_URL).expect("default POI RPC URL is valid")
}

#[allow(clippy::too_many_arguments)]
const fn new_poi_artifact_cache_progress(
    chain_id: u64,
    phase: PoiArtifactCachePhase,
    completed_lists: usize,
    total_lists: usize,
    current_list_key: Option<FixedBytes<32>>,
    current_event_index: Option<u64>,
    target_event_index: Option<u64>,
    list_progress: Vec<PoiArtifactCacheListProgress>,
    ready_for_wallet_checks: bool,
    last_error: Option<String>,
) -> PoiArtifactCacheProgress {
    PoiArtifactCacheProgress {
        chain_id,
        phase,
        completed_lists,
        total_lists,
        current_list_key,
        current_event_index,
        target_event_index,
        list_progress,
        ready_for_wallet_checks,
        last_error,
    }
}

fn send_poi_artifact_cache_progress(
    progress_tx: &watch::Sender<BTreeMap<u64, PoiArtifactCacheProgress>>,
    progress: PoiArtifactCacheProgress,
) {
    progress_tx.send_modify(|chains| {
        chains.insert(progress.chain_id, progress);
    });
}

fn send_stale_chain_poi_cache_progress(
    progress_tx: &watch::Sender<BTreeMap<u64, PoiArtifactCacheProgress>>,
    chain_id: u64,
) {
    let active_list_keys = default_active_poi_list_keys();
    send_poi_artifact_cache_progress(
        progress_tx,
        new_poi_artifact_cache_progress(
            chain_id,
            PoiArtifactCachePhase::LoadingPersisted,
            0,
            active_list_keys.len(),
            None,
            None,
            None,
            poi_cache_list_progress_for_keys(&active_list_keys),
            false,
            None,
        ),
    );
}

fn poi_cache_list_progress_for_keys(
    active_list_keys: &[FixedBytes<32>],
) -> Vec<PoiArtifactCacheListProgress> {
    active_list_keys
        .iter()
        .map(|list_key| PoiArtifactCacheListProgress {
            list_key: *list_key,
            current_event_index: None,
            target_event_index: None,
            ready_for_wallet_checks: false,
        })
        .collect()
}

fn single_list_event_index(
    list_progress: &[PoiArtifactCacheListProgress],
) -> (Option<u64>, Option<u64>) {
    if let [progress] = list_progress {
        (progress.current_event_index, progress.target_event_index)
    } else {
        (None, None)
    }
}

fn list_progress_with_active_event(
    active_list_keys: &[FixedBytes<32>],
    baseline: &[PoiArtifactCacheListProgress],
    active_list_key: FixedBytes<32>,
    current_event_index: Option<u64>,
    target_event_index: Option<u64>,
) -> Vec<PoiArtifactCacheListProgress> {
    active_list_keys
        .iter()
        .map(|list_key| {
            let mut progress = baseline
                .iter()
                .find(|progress| progress.list_key == *list_key)
                .cloned()
                .unwrap_or(PoiArtifactCacheListProgress {
                    list_key: *list_key,
                    current_event_index: None,
                    target_event_index: None,
                    ready_for_wallet_checks: false,
                });
            if *list_key == active_list_key {
                progress.current_event_index = current_event_index;
                progress.target_event_index = target_event_index;
            }
            progress
        })
        .collect()
}

fn emit_poi_artifact_ingestor_progress(
    progress_tx: &watch::Sender<BTreeMap<u64, PoiArtifactCacheProgress>>,
    chain_id: u64,
    total_lists: usize,
    list_index: usize,
    list_key: FixedBytes<32>,
    active_list_keys: &[FixedBytes<32>],
    baseline_list_progress: &[PoiArtifactCacheListProgress],
    ready_for_wallet_checks: bool,
    event: PoiArtifactProgressEvent,
) {
    let list_progress = list_progress_with_active_event(
        active_list_keys,
        baseline_list_progress,
        list_key,
        event.current_event_index,
        event.target_event_index,
    );
    send_poi_artifact_cache_progress(
        progress_tx,
        new_poi_artifact_cache_progress(
            chain_id,
            event.phase,
            list_index,
            total_lists,
            Some(list_key),
            event.current_event_index,
            event.target_event_index,
            list_progress,
            ready_for_wallet_checks,
            None,
        ),
    );
}

async fn emit_chain_poi_cache_ready_progress(
    progress_tx: &watch::Sender<BTreeMap<u64, PoiArtifactCacheProgress>>,
    chain_id: u64,
    local_caches: &LocalPoiCaches,
    active_list_keys: &[FixedBytes<32>],
) {
    let ready =
        chain_poi_caches_available_for_lists(chain_id, local_caches, active_list_keys).await;
    let completed = installed_chain_poi_cache_count(chain_id, local_caches, active_list_keys).await;
    let list_progress =
        chain_poi_cache_list_progress(chain_id, local_caches, active_list_keys).await;
    let (current_event_index, target_event_index) = single_list_event_index(&list_progress);
    send_poi_artifact_cache_progress(
        progress_tx,
        new_poi_artifact_cache_progress(
            chain_id,
            PoiArtifactCachePhase::Ready,
            completed,
            active_list_keys.len(),
            None,
            current_event_index,
            target_event_index,
            list_progress,
            ready,
            None,
        ),
    );
}

impl Drop for PoiCacheService {
    fn drop(&mut self) {
        self.cancel.cancel();
    }
}

fn spawn_chain_poi_cache_loop(task: ChainPoiCacheLoop) {
    let chain_id = task.chain_id;
    tokio::spawn(
        async move {
            run_chain_poi_cache_loop(task).await;
        }
        .instrument(tracing::info_span!("poi_artifact_cache", chain_id)),
    );
}

fn spawn_chain_poi_cache_resync(
    db: Arc<DbStore>,
    http_client: Option<reqwest::Client>,
    poi_rpc_url: Url,
    artifact_config: PoiArtifactSourceConfig,
    chain_id: u64,
    local_caches: LocalPoiCaches,
    progress_tx: watch::Sender<BTreeMap<u64, PoiArtifactCacheProgress>>,
) {
    tokio::spawn(
        async move {
            let active_list_keys = default_active_poi_list_keys();
            sync_chain_poi_artifact_caches(
                db.as_ref(),
                http_client.as_ref(),
                &poi_rpc_url,
                &artifact_config,
                chain_id,
                &local_caches,
                &active_list_keys,
                BTreeMap::new(),
                &progress_tx,
            )
            .await;
        }
        .instrument(tracing::info_span!("poi_artifact_cache_resync", chain_id)),
    );
}

async fn run_chain_poi_cache_loop(mut task: ChainPoiCacheLoop) {
    let chain_id = task.chain_id;
    info!(
        chain_id,
        list_count = task.active_list_keys.len(),
        "starting chain-scoped artifact POI cache service"
    );
    let live_tail_client = wallet_poi_status_client(&task.poi_rpc_url, task.http_client.as_ref());
    let mut last_artifact_sync = Instant::now()
        .checked_sub(POI_ARTIFACT_CACHE_SYNC_INTERVAL)
        .unwrap_or_else(Instant::now);
    loop {
        let caches_available = chain_poi_caches_available_for_lists(
            chain_id,
            &task.local_caches,
            &task.active_list_keys,
        )
        .await;
        if !caches_available || last_artifact_sync.elapsed() >= POI_ARTIFACT_CACHE_SYNC_INTERVAL {
            sync_chain_poi_artifact_caches(
                task.db.as_ref(),
                task.http_client.as_ref(),
                &task.poi_rpc_url,
                &task.artifact_config,
                chain_id,
                &task.local_caches,
                &task.active_list_keys,
                std::mem::take(&mut task.preloaded_caches),
                &task.progress_tx,
            )
            .await;
            last_artifact_sync = Instant::now();
        } else {
            sync_chain_poi_live_tails(
                &live_tail_client,
                chain_id,
                &task.local_caches,
                &task.active_list_keys,
                &task.progress_tx,
            )
            .await;
        }

        tokio::select! {
            () = task.cancel.cancelled() => break,
            () = tokio::time::sleep(POI_ARTIFACT_CACHE_LIVE_TAIL_INTERVAL) => {}
        }
    }
    info!(chain_id, "chain-scoped artifact POI cache service stopped");
}

#[allow(clippy::too_many_arguments)]
async fn sync_chain_poi_artifact_caches(
    db: &DbStore,
    http_client: Option<&reqwest::Client>,
    poi_rpc_url: &Url,
    artifact_config: &PoiArtifactSourceConfig,
    chain_id: u64,
    local_caches: &LocalPoiCaches,
    active_list_keys: &[FixedBytes<32>],
    mut preloaded_caches: BTreeMap<FixedBytes<32>, PersistedPoiArtifactCache>,
    progress_tx: &watch::Sender<BTreeMap<u64, PoiArtifactCacheProgress>>,
) {
    let total_lists = active_list_keys.len();
    if total_lists == 0 {
        send_poi_artifact_cache_progress(
            progress_tx,
            new_poi_artifact_cache_progress(
                chain_id,
                PoiArtifactCachePhase::Ready,
                0,
                0,
                None,
                None,
                None,
                Vec::new(),
                true,
                None,
            ),
        );
        return;
    }

    synchronize_chain_cache_generation(chain_id, local_caches, Some(&mut preloaded_caches)).await;
    let initially_ready =
        chain_poi_caches_available_for_lists(chain_id, local_caches, active_list_keys).await;
    let client = http_client.cloned().unwrap_or_else(reqwest::Client::new);
    let live_tail_client = wallet_poi_status_client(poi_rpc_url, http_client);
    let mut last_error = None;
    for (list_index, list_key) in active_list_keys.iter().enumerate() {
        let identity =
            PoiCacheIdentity::new(EVM_CHAIN_TYPE, chain_id, DEFAULT_TXID_VERSION, *list_key);
        let baseline_list_progress =
            chain_poi_cache_list_progress(chain_id, local_caches, active_list_keys).await;
        let active_list_keys_for_progress = active_list_keys.to_vec();
        let ingestor = PoiArtifactIngestor::new(artifact_config.clone(), client.clone())
            .with_progress_observer({
                let progress_tx = progress_tx.clone();
                let list_key = *list_key;
                let baseline_list_progress = baseline_list_progress.clone();
                move |event| {
                    emit_poi_artifact_ingestor_progress(
                        &progress_tx,
                        chain_id,
                        total_lists,
                        list_index,
                        list_key,
                        &active_list_keys_for_progress,
                        &baseline_list_progress,
                        initially_ready,
                        event,
                    );
                }
            });
        let sync_started = Instant::now();
        let artifact_refresh_started = Instant::now();
        let artifact_refresh = ingestor
            .refresh_persisted_cache_with_optional_preloaded_and_proxy(
                db,
                identity.clone(),
                preloaded_caches.remove(list_key),
                SystemTime::now(),
                Some(&live_tail_client),
            )
            .await;
        let artifact_refresh_elapsed_ms = artifact_refresh_started.elapsed().as_millis();
        match artifact_refresh {
            Ok(refresh) => {
                let manifest_sequence = refresh.manifest_sequence;
                let artifact_tip_index = refresh.entry.current_tip_index;
                let candidate_generation = refresh.cache_generation;
                let mut cache = refresh.cache;
                let live_tail_started = Instant::now();
                let local_tip_index = cache.progress().next_event_index.saturating_sub(1);
                let baseline_list_progress =
                    chain_poi_cache_list_progress(chain_id, local_caches, active_list_keys).await;
                let list_progress = list_progress_with_active_event(
                    active_list_keys,
                    &baseline_list_progress,
                    *list_key,
                    Some(local_tip_index),
                    None,
                );
                send_poi_artifact_cache_progress(
                    progress_tx,
                    new_poi_artifact_cache_progress(
                        chain_id,
                        PoiArtifactCachePhase::LiveTailing,
                        list_index,
                        total_lists,
                        Some(*list_key),
                        Some(local_tip_index),
                        None,
                        list_progress,
                        initially_ready,
                        None,
                    ),
                );
                let live_tail = match live_tail_candidate_cache(&live_tail_client, &cache).await {
                    Ok((tailed_cache, outcome)) => {
                        cache = tailed_cache;
                        let list_progress = list_progress_with_active_event(
                            active_list_keys,
                            &baseline_list_progress,
                            *list_key,
                            Some(outcome.next_event_index.saturating_sub(1)),
                            Some(outcome.next_event_index.saturating_sub(1)),
                        );
                        send_poi_artifact_cache_progress(
                            progress_tx,
                            new_poi_artifact_cache_progress(
                                chain_id,
                                PoiArtifactCachePhase::LiveTailing,
                                list_index,
                                total_lists,
                                Some(*list_key),
                                Some(outcome.next_event_index.saturating_sub(1)),
                                Some(outcome.next_event_index.saturating_sub(1)),
                                list_progress,
                                initially_ready,
                                None,
                            ),
                        );
                        Some(outcome)
                    }
                    Err(err) => {
                        warn!(
                            ?err,
                            chain_id,
                            list_key = %hex::encode(list_key),
                            "live POI event tail failed; using artifact checkpoint"
                        );
                        None
                    }
                };
                let live_tail_elapsed_ms = live_tail_started.elapsed().as_millis();
                let local_tip_index = cache.progress().next_event_index.saturating_sub(1);
                let install_started = Instant::now();
                let install_lock_started = Instant::now();
                let installed = install_generated_cache_if_current(
                    local_caches,
                    *list_key,
                    cache,
                    candidate_generation,
                )
                .await;
                if !installed && local_caches.current_generation() != candidate_generation {
                    debug!(
                        chain_id,
                        list_key = %hex::encode(list_key),
                        candidate_generation,
                        "artifact POI cache install skipped; cache generation advanced"
                    );
                }
                let install_lock_wait_elapsed_ms = install_lock_started.elapsed().as_millis();
                debug!(
                    chain_id,
                    list_key = %hex::encode(list_key),
                    manifest_sequence,
                    artifact_tip_index,
                    local_tip_index,
                    live_tail_events = live_tail.as_ref().map_or(0, |outcome| outcome.events),
                    live_tail_pages = live_tail.as_ref().map_or(0, |outcome| outcome.pages),
                    live_tail_start_index = live_tail.as_ref().map_or_else(
                        || local_tip_index.saturating_add(1),
                        |outcome| outcome.start_index,
                    ),
                    live_tail_next_event_index = live_tail.as_ref().map_or_else(
                        || local_tip_index.saturating_add(1),
                        |outcome| outcome.next_event_index,
                    ),
                    base_cid = %refresh.entry.base.cid,
                    delta_count = refresh.entry.deltas.len(),
                    blocked_shields_cid = %refresh.entry.blocked_shields.cid,
                    artifact_refresh_elapsed_ms,
                    live_tail_elapsed_ms,
                    installed,
                    install_lock_wait_elapsed_ms,
                    install_elapsed_ms = install_started.elapsed().as_millis(),
                    elapsed_ms = sync_started.elapsed().as_millis(),
                    "chain-scoped artifact POI cache sync complete"
                );
            }
            Err(err) => {
                last_error = Some(err.to_string());
                warn!(
                    ?err,
                    chain_id,
                    list_key = %hex::encode(list_key),
                    elapsed_ms = sync_started.elapsed().as_millis(),
                    "chain-scoped artifact POI cache sync failed; using last accepted local cache state if available"
                );
                match load_persisted_cache(db, &identity) {
                    Ok(Some(persisted)) => {
                        let candidate_generation = persisted.cache_generation;
                        let mut cache = persisted.cache;
                        match live_tail_candidate_cache(&live_tail_client, &cache).await {
                            Ok((tailed_cache, _outcome)) => {
                                cache = tailed_cache;
                            }
                            Err(err) => warn!(
                                ?err,
                                chain_id,
                                list_key = %hex::encode(list_key),
                                "live POI event tail failed after artifact refresh error"
                            ),
                        }
                        let installed = install_generated_cache_if_current(
                            local_caches,
                            *list_key,
                            cache,
                            candidate_generation,
                        )
                        .await;
                        if !installed {
                            debug!(
                                chain_id,
                                list_key = %hex::encode(list_key),
                                candidate_generation,
                                "persisted artifact POI cache install skipped; stale generation or current cache is newer"
                            );
                        }
                    }
                    Ok(None) => {}
                    Err(err) => warn!(
                        ?err,
                        chain_id,
                        list_key = %hex::encode(list_key),
                        "failed to load persisted artifact POI cache after refresh error"
                    ),
                }
                synchronize_chain_cache_generation(chain_id, local_caches, None).await;
                let ready =
                    chain_poi_caches_available_for_lists(chain_id, local_caches, active_list_keys)
                        .await;
                let completed =
                    installed_chain_poi_cache_count(chain_id, local_caches, active_list_keys).await;
                let list_progress =
                    chain_poi_cache_list_progress(chain_id, local_caches, active_list_keys).await;
                let (current_event_index, target_event_index) =
                    single_list_event_index(&list_progress);
                send_poi_artifact_cache_progress(
                    progress_tx,
                    new_poi_artifact_cache_progress(
                        chain_id,
                        PoiArtifactCachePhase::Error,
                        completed,
                        total_lists,
                        Some(*list_key),
                        current_event_index,
                        target_event_index,
                        list_progress,
                        ready,
                        last_error.clone(),
                    ),
                );
            }
        }
    }
    synchronize_chain_cache_generation(chain_id, local_caches, None).await;
    let ready =
        chain_poi_caches_available_for_lists(chain_id, local_caches, active_list_keys).await;
    let completed = installed_chain_poi_cache_count(chain_id, local_caches, active_list_keys).await;
    let list_progress =
        chain_poi_cache_list_progress(chain_id, local_caches, active_list_keys).await;
    let (current_event_index, target_event_index) = single_list_event_index(&list_progress);
    let phase = if last_error.is_some() {
        PoiArtifactCachePhase::Error
    } else {
        PoiArtifactCachePhase::Ready
    };
    send_poi_artifact_cache_progress(
        progress_tx,
        new_poi_artifact_cache_progress(
            chain_id,
            phase,
            completed,
            total_lists,
            None,
            current_event_index,
            target_event_index,
            list_progress,
            ready,
            last_error,
        ),
    );
}

fn install_cache_if_not_behind(
    caches: &mut BTreeMap<FixedBytes<32>, PoiCache>,
    list_key: FixedBytes<32>,
    cache: PoiCache,
) -> bool {
    if caches.get(&list_key).is_some_and(|current| {
        current.progress().next_event_index > cache.progress().next_event_index
    }) {
        return false;
    }
    caches.insert(list_key, cache);
    true
}

async fn synchronize_chain_cache_generation(
    chain_id: u64,
    local_caches: &LocalPoiCaches,
    preloaded_caches: Option<&mut BTreeMap<FixedBytes<32>, PersistedPoiArtifactCache>>,
) -> bool {
    let (installed_is_stale, preloaded_is_stale) = with_poi_artifact_cache_generation(
        local_caches.shared_generation(),
        |current_generation| {
            let installed_is_stale = local_caches.installed_generation() != current_generation;
            let preloaded_is_stale = preloaded_caches.as_ref().is_some_and(|preloaded| {
                preloaded
                    .values()
                    .any(|persisted| persisted.cache_generation != current_generation)
            });
            (installed_is_stale, preloaded_is_stale)
        },
    );
    if !installed_is_stale && !preloaded_is_stale {
        return false;
    }

    let generation_changed = local_caches.synchronize_generation().await;
    let mut preloaded_caches = preloaded_caches;
    let (removed_preloaded, current_generation) = with_poi_artifact_cache_generation(
        local_caches.shared_generation(),
        |current_generation| {
            let removed_preloaded = preloaded_caches.as_mut().map_or(0, |preloaded| {
                let previous_len = preloaded.len();
                preloaded.retain(|_, persisted| persisted.cache_generation == current_generation);
                previous_len.saturating_sub(preloaded.len())
            });
            (removed_preloaded, current_generation)
        },
    );
    if generation_changed || removed_preloaded > 0 {
        debug!(
            chain_id,
            current_generation,
            removed_preloaded,
            "synchronized chain-scoped POI caches to shared generation"
        );
    }
    generation_changed || removed_preloaded > 0
}

async fn install_generated_cache_if_current(
    local_caches: &LocalPoiCaches,
    list_key: FixedBytes<32>,
    cache: PoiCache,
    candidate_generation: u64,
) -> bool {
    let mut caches = local_caches.write().await;
    with_poi_artifact_cache_generation(local_caches.shared_generation(), |current_generation| {
        if current_generation != candidate_generation {
            return false;
        }
        if local_caches.installed_generation() != candidate_generation {
            caches.clear();
            local_caches.mark_installed_generation(candidate_generation);
        }
        install_cache_if_not_behind(&mut caches, list_key, cache)
    })
}

async fn install_persisted_chain_poi_caches(
    db: &DbStore,
    chain_id: u64,
    local_caches: &LocalPoiCaches,
    active_list_keys: &[FixedBytes<32>],
) -> BTreeMap<FixedBytes<32>, PersistedPoiArtifactCache> {
    let started = Instant::now();
    let mut loaded = BTreeMap::new();
    for list_key in active_list_keys {
        let identity =
            PoiCacheIdentity::new(EVM_CHAIN_TYPE, chain_id, DEFAULT_TXID_VERSION, *list_key);
        match load_persisted_cache(db, &identity) {
            Ok(Some(persisted)) => {
                loaded.insert(*list_key, persisted);
            }
            Ok(None) => {}
            Err(err) => warn!(
                ?err,
                chain_id,
                list_key = %hex::encode(list_key),
                "failed to load persisted artifact POI cache"
            ),
        }
    }

    install_loaded_persisted_chain_poi_caches(chain_id, local_caches, loaded, started).await
}

async fn install_loaded_persisted_chain_poi_caches(
    chain_id: u64,
    local_caches: &LocalPoiCaches,
    mut loaded: BTreeMap<FixedBytes<32>, PersistedPoiArtifactCache>,
    started: Instant,
) -> BTreeMap<FixedBytes<32>, PersistedPoiArtifactCache> {
    let loaded_count = loaded.len();
    if loaded_count > 0 {
        let lock_started = Instant::now();
        let mut caches = local_caches.write().await;
        let lock_wait_elapsed_ms = lock_started.elapsed().as_millis();
        with_poi_artifact_cache_generation(
            local_caches.shared_generation(),
            |current_generation| {
                if local_caches.installed_generation() != current_generation {
                    caches.clear();
                    local_caches.mark_installed_generation(current_generation);
                }
                loaded.retain(|list_key, persisted| {
                    if current_generation != persisted.cache_generation {
                        return false;
                    }
                    caches.insert(*list_key, persisted.cache.clone());
                    true
                });
            },
        );
        let installed_count = loaded.len();
        if installed_count != loaded_count {
            debug!(
                chain_id,
                loaded_count,
                installed_count,
                "discarded stale persisted chain-scoped artifact POI caches"
            );
        }
        info!(
            chain_id,
            loaded_count,
            installed_count,
            lock_wait_elapsed_ms,
            elapsed_ms = started.elapsed().as_millis(),
            "installed persisted chain-scoped artifact POI cache"
        );
    }

    loaded
}

async fn chain_poi_caches_available_for_lists(
    chain_id: u64,
    local_caches: &LocalPoiCaches,
    active_list_keys: &[FixedBytes<32>],
) -> bool {
    if active_list_keys.is_empty() {
        return true;
    }
    let caches = local_caches.read().await;
    with_poi_artifact_cache_generation(local_caches.shared_generation(), |current_generation| {
        local_caches.installed_generation() == current_generation
            && active_list_keys.iter().all(|list_key| {
                caches.get(list_key).is_some_and(|cache| {
                    cache.identity().chain_type == EVM_CHAIN_TYPE
                        && cache.identity().chain_id == chain_id
                        && cache.identity().txid_version == DEFAULT_TXID_VERSION
                        && cache.progress().next_event_index > 0
                })
            })
    })
}

async fn installed_chain_poi_cache_count(
    chain_id: u64,
    local_caches: &LocalPoiCaches,
    active_list_keys: &[FixedBytes<32>],
) -> usize {
    let caches = local_caches.read().await;
    active_list_keys
        .iter()
        .filter(|list_key| {
            caches.get(*list_key).is_some_and(|cache| {
                cache.identity().chain_type == EVM_CHAIN_TYPE
                    && cache.identity().chain_id == chain_id
                    && cache.identity().txid_version == DEFAULT_TXID_VERSION
                    && cache.progress().next_event_index > 0
            })
        })
        .count()
}

async fn chain_poi_cache_list_progress(
    chain_id: u64,
    local_caches: &LocalPoiCaches,
    active_list_keys: &[FixedBytes<32>],
) -> Vec<PoiArtifactCacheListProgress> {
    let caches = local_caches.read().await;
    active_list_keys
        .iter()
        .map(|list_key| {
            let event_index = caches.get(list_key).and_then(|cache| {
                if cache.identity().chain_type == EVM_CHAIN_TYPE
                    && cache.identity().chain_id == chain_id
                    && cache.identity().txid_version == DEFAULT_TXID_VERSION
                {
                    cache.progress().next_event_index.checked_sub(1)
                } else {
                    None
                }
            });
            PoiArtifactCacheListProgress {
                list_key: *list_key,
                current_event_index: event_index,
                target_event_index: event_index,
                ready_for_wallet_checks: event_index.is_some(),
            }
        })
        .collect()
}

async fn sync_chain_poi_live_tails(
    client: &PoiRpcClient,
    chain_id: u64,
    local_caches: &LocalPoiCaches,
    active_list_keys: &[FixedBytes<32>],
    progress_tx: &watch::Sender<BTreeMap<u64, PoiArtifactCacheProgress>>,
) {
    let total_lists = active_list_keys.len();
    synchronize_chain_cache_generation(chain_id, local_caches, None).await;
    let initially_ready =
        chain_poi_caches_available_for_lists(chain_id, local_caches, active_list_keys).await;
    let mut last_error = None;
    for (list_index, list_key) in active_list_keys.iter().enumerate() {
        let (mut cache, candidate_generation) = {
            let caches = local_caches.read().await;
            let Some(cache) = caches.get(list_key).cloned() else {
                continue;
            };
            (cache, local_caches.installed_generation())
        };
        let original_next_event_index = cache.progress().next_event_index;
        if original_next_event_index == 0 {
            continue;
        }
        let baseline_list_progress =
            chain_poi_cache_list_progress(chain_id, local_caches, active_list_keys).await;
        let list_progress = list_progress_with_active_event(
            active_list_keys,
            &baseline_list_progress,
            *list_key,
            Some(original_next_event_index.saturating_sub(1)),
            None,
        );
        send_poi_artifact_cache_progress(
            progress_tx,
            new_poi_artifact_cache_progress(
                chain_id,
                PoiArtifactCachePhase::LiveTailing,
                list_index,
                total_lists,
                Some(*list_key),
                Some(original_next_event_index.saturating_sub(1)),
                None,
                list_progress,
                initially_ready,
                None,
            ),
        );
        let started = Instant::now();
        match sync_live_poi_event_tail(client, &mut cache).await {
            Ok(outcome) => {
                if outcome.events > 0 {
                    if install_tailed_poi_cache_if_current(
                        local_caches,
                        *list_key,
                        cache,
                        original_next_event_index,
                        candidate_generation,
                    )
                    .await
                    {
                        info!(
                            chain_id,
                            list_key = %hex::encode(list_key),
                            events = outcome.events,
                            pages = outcome.pages,
                            start_index = outcome.start_index,
                            next_event_index = outcome.next_event_index,
                            elapsed_ms = started.elapsed().as_millis(),
                            "chain-scoped live POI event tail applied"
                        );
                    } else {
                        debug!(
                            chain_id,
                            list_key = %hex::encode(list_key),
                            start_index = outcome.start_index,
                            next_event_index = outcome.next_event_index,
                            "chain-scoped live POI event tail install skipped; cache already advanced"
                        );
                    }
                } else {
                    debug!(
                        chain_id,
                        list_key = %hex::encode(list_key),
                        start_index = outcome.start_index,
                        elapsed_ms = started.elapsed().as_millis(),
                        "chain-scoped live POI event tail already current"
                    );
                }
            }
            Err(err) => {
                last_error = Some(err.to_string());
                warn!(
                    ?err,
                    chain_id,
                    list_key = %hex::encode(list_key),
                    elapsed_ms = started.elapsed().as_millis(),
                    "chain-scoped live POI event tail failed"
                );
            }
        }
    }
    synchronize_chain_cache_generation(chain_id, local_caches, None).await;
    let ready =
        chain_poi_caches_available_for_lists(chain_id, local_caches, active_list_keys).await;
    let completed = installed_chain_poi_cache_count(chain_id, local_caches, active_list_keys).await;
    let list_progress =
        chain_poi_cache_list_progress(chain_id, local_caches, active_list_keys).await;
    let (current_event_index, target_event_index) = single_list_event_index(&list_progress);
    let phase = if last_error.is_some() {
        PoiArtifactCachePhase::Error
    } else {
        PoiArtifactCachePhase::Ready
    };
    send_poi_artifact_cache_progress(
        progress_tx,
        new_poi_artifact_cache_progress(
            chain_id,
            phase,
            completed,
            total_lists,
            None,
            current_event_index,
            target_event_index,
            list_progress,
            ready,
            last_error,
        ),
    );
}

async fn install_tailed_poi_cache_if_current(
    local_caches: &LocalPoiCaches,
    list_key: FixedBytes<32>,
    cache: PoiCache,
    expected_next_event_index: u64,
    candidate_generation: u64,
) -> bool {
    let mut caches = local_caches.write().await;
    with_poi_artifact_cache_generation(local_caches.shared_generation(), |current_generation| {
        if current_generation != candidate_generation
            || local_caches.installed_generation() != candidate_generation
        {
            return false;
        }
        let Some(current) = caches.get(&list_key) else {
            return false;
        };
        if current.progress().next_event_index != expected_next_event_index {
            return false;
        }
        caches.insert(list_key, cache);
        true
    })
}

#[cfg(test)]
mod tests {
    use super::{
        EVM_CHAIN_TYPE, PoiCacheService, chain_poi_cache_list_progress,
        chain_poi_caches_available_for_lists, emit_chain_poi_cache_ready_progress,
        install_cache_if_not_behind, install_generated_cache_if_current,
        install_loaded_persisted_chain_poi_caches, install_tailed_poi_cache_if_current,
        live_tail_candidate_cache, single_list_event_index,
    };
    use crate::poi_artifacts::{
        clear_poi_artifact_cache_for_reset, load_persisted_cache,
        poi_artifact_cache_generation_cell,
    };
    use crate::types::{
        LocalPoiCaches, PoiArtifactCachePhase, PoiArtifactCacheProgress, PoiArtifactManifestSource,
        PoiArtifactSourceConfig,
    };
    use crate::wallet::{
        LivePoiTailError, LocalPoiMerkleProofSource, LocalPoiStatusReader, PoiStatusReader,
    };
    use alloy::primitives::{FixedBytes, U256};
    use broadcaster_core::transact::DEFAULT_TXID_VERSION;
    use local_db::{DbConfig, DbStore, PoiArtifactCacheRecord, PoiArtifactDescriptorRecord};
    use poi::artifacts::SnapshotEvent;
    use poi::cache::{PoiCache, PoiCacheIdentity};
    use poi::poi::{
        BlindedCommitmentData, PoiEventType, PoiRpcClient, default_active_poi_list_key,
    };
    use railgun_wallet::PoiStatus;
    use railgun_wallet::tx::PoiMerkleProofSource;
    use std::collections::BTreeMap;
    use std::fs;
    use std::io::{Read, Write};
    use std::net::TcpListener;
    use std::path::PathBuf;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::sync::mpsc::{self, Receiver};
    use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
    use url::Url;

    static TEMP_DB_COUNTER: AtomicU64 = AtomicU64::new(0);

    struct MockPoiRpc {
        url: Url,
        requests: Receiver<serde_json::Value>,
    }

    fn temp_db_root() -> PathBuf {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(0, |duration| duration.as_nanos());
        let counter = TEMP_DB_COUNTER.fetch_add(1, Ordering::Relaxed);
        std::env::temp_dir().join(format!(
            "railgun-poi-cache-service-test-{}-{nanos}-{counter}",
            std::process::id()
        ))
    }

    fn artifact_config() -> PoiArtifactSourceConfig {
        PoiArtifactSourceConfig {
            trusted_publisher_pubkey: FixedBytes::from([0x22; 32]),
            manifest_source: PoiArtifactManifestSource::Url(
                Url::parse("http://127.0.0.1:1/manifest").expect("manifest URL"),
            ),
            gateway_urls: vec![Url::parse("http://127.0.0.1:1").expect("gateway URL")],
            max_manifest_age: None,
        }
    }

    fn snapshot_event(index: u64, blinded_commitment: FixedBytes<32>) -> SnapshotEvent {
        SnapshotEvent {
            event_index: index,
            blinded_commitment: *blinded_commitment,
            signature: [0_u8; 64],
            event_type: PoiEventType::Transact,
        }
    }

    fn cache_with_events(identity: PoiCacheIdentity, events: &[SnapshotEvent]) -> PoiCache {
        let mut cache = PoiCache::new(identity);
        cache
            .apply_verified_artifact_events(events)
            .expect("apply cache events");
        cache.accept_current_roots();
        cache
    }

    #[tokio::test]
    async fn chain_poi_cache_list_progress_reports_each_active_list() {
        let first_key = default_active_poi_list_key();
        let second_key = FixedBytes::from([7_u8; 32]);
        let first_identity =
            PoiCacheIdentity::new(EVM_CHAIN_TYPE, 1, DEFAULT_TXID_VERSION, first_key);
        let second_identity =
            PoiCacheIdentity::new(EVM_CHAIN_TYPE, 1, DEFAULT_TXID_VERSION, second_key);
        let first_cache = cache_with_events(
            first_identity,
            &[snapshot_event(0, FixedBytes::from([1_u8; 32]))],
        );
        let second_cache = cache_with_events(
            second_identity,
            &[
                snapshot_event(0, FixedBytes::from([2_u8; 32])),
                snapshot_event(1, FixedBytes::from([3_u8; 32])),
            ],
        );
        let local_caches = LocalPoiCaches::new_for_test(BTreeMap::from([
            (first_key, first_cache),
            (second_key, second_cache),
        ]));
        let active_list_keys = vec![first_key, second_key];

        let list_progress =
            chain_poi_cache_list_progress(1, &local_caches, &active_list_keys).await;

        assert_eq!(list_progress.len(), 2);
        assert_eq!(list_progress[0].list_key, first_key);
        assert_eq!(list_progress[0].current_event_index, Some(0));
        assert_eq!(list_progress[0].target_event_index, Some(0));
        assert!(list_progress[0].ready_for_wallet_checks);
        assert_eq!(list_progress[1].list_key, second_key);
        assert_eq!(list_progress[1].current_event_index, Some(1));
        assert_eq!(list_progress[1].target_event_index, Some(1));
        assert!(list_progress[1].ready_for_wallet_checks);
        assert_eq!(single_list_event_index(&list_progress), (None, None));
    }

    fn persist_cache(db: &DbStore, cache: &PoiCache) {
        let identity = cache.identity();
        let current_tip_index = cache.progress().next_event_index.saturating_sub(1);
        let current_tip_root = *cache
            .clone()
            .current_roots()
            .get(&0)
            .expect("cache has current tree root");
        db.put_poi_artifact_cache(&PoiArtifactCacheRecord {
            chain_type: identity.chain_type,
            chain_id: identity.chain_id,
            txid_version: identity.txid_version.clone(),
            list_key: identity.list_key,
            last_accepted_manifest_sequence: 1,
            base_descriptor: test_descriptor_record("base"),
            applied_delta_descriptors: Vec::new(),
            blocked_shields_descriptor: test_descriptor_record("blocked"),
            current_tip_index,
            current_tip_root,
            cache_payload: cache.to_bytes().expect("cache bytes"),
            updated_at: 0,
        })
        .expect("persist POI artifact cache");
    }

    fn test_descriptor_record(cid: &str) -> PoiArtifactDescriptorRecord {
        PoiArtifactDescriptorRecord {
            cid: cid.to_string(),
            sha256: "0x00".to_string(),
            byte_size: 0,
        }
    }

    async fn wait_for_progress(
        rx: &mut tokio::sync::watch::Receiver<BTreeMap<u64, PoiArtifactCacheProgress>>,
        chain_id: u64,
        predicate: impl Fn(&PoiArtifactCacheProgress) -> bool,
    ) -> PoiArtifactCacheProgress {
        for _ in 0..20 {
            if let Some(progress) = rx.borrow().get(&chain_id)
                && predicate(progress)
            {
                return progress.clone();
            }
            tokio::time::timeout(Duration::from_secs(2), rx.changed())
                .await
                .expect("progress update timeout")
                .expect("progress channel open");
        }
        panic!("expected progress update for chain {chain_id}");
    }

    fn spawn_poi_rpc_sequence(results: Vec<serde_json::Value>) -> MockPoiRpc {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind mock POI RPC");
        let url = Url::parse(&format!(
            "http://{}",
            listener.local_addr().expect("local addr")
        ))
        .expect("mock POI RPC URL");
        let (tx, requests) = mpsc::channel();
        std::thread::spawn(move || {
            for result in results {
                let (mut stream, _) = listener.accept().expect("accept request");
                let mut bytes = Vec::new();
                let mut buf = [0_u8; 1024];
                let (body_start, content_length) = loop {
                    let read = stream.read(&mut buf).expect("read request");
                    assert!(read > 0, "mock POI RPC closed before request body");
                    bytes.extend_from_slice(&buf[..read]);
                    if let Some(lengths) = http_body_bounds(&bytes) {
                        break lengths;
                    }
                };
                let body = &bytes[body_start..body_start + content_length];
                let request: serde_json::Value =
                    serde_json::from_slice(body).expect("request JSON");
                tx.send(request.clone()).expect("record request");
                let response = serde_json::json!({
                    "jsonrpc": "2.0",
                    "id": request["id"].clone(),
                    "result": result,
                })
                .to_string();
                let headers = format!(
                    "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n",
                    response.len()
                );
                stream.write_all(headers.as_bytes()).expect("write headers");
                stream.write_all(response.as_bytes()).expect("write body");
            }
        });
        MockPoiRpc { url, requests }
    }

    fn http_body_bounds(bytes: &[u8]) -> Option<(usize, usize)> {
        let body_start = bytes.windows(4).position(|window| window == b"\r\n\r\n")? + 4;
        let headers = std::str::from_utf8(&bytes[..body_start]).ok()?;
        let content_length = headers.lines().find_map(|line| {
            line.strip_prefix("content-length:")
                .or_else(|| line.strip_prefix("Content-Length:"))
                .and_then(|value| value.trim().parse::<usize>().ok())
        })?;
        (bytes.len() >= body_start + content_length).then_some((body_start, content_length))
    }

    #[tokio::test]
    async fn poi_cache_service_reuses_chain_cache_handle() {
        let root_dir = temp_db_root();
        fs::create_dir_all(&root_dir).expect("create temp db root");
        let db = Arc::new(
            DbStore::open(DbConfig {
                root_dir: root_dir.clone(),
            })
            .expect("open temp db"),
        );
        let service = PoiCacheService::new(db, artifact_config(), None)
            .expect("initialize POI cache generation");

        let first = service.start_chain(1).await;
        let second = service.start_chain(1).await;
        let other_chain = service.start_chain(137).await;

        assert!(first.ptr_eq(&second));
        assert!(!first.ptr_eq(&other_chain));
        service.shutdown();
        fs::remove_dir_all(root_dir).expect("remove temp db dir");
    }

    #[tokio::test]
    async fn start_chain_reports_persisted_cache_ready() {
        let root_dir = temp_db_root();
        fs::create_dir_all(&root_dir).expect("create temp db root");
        let db = Arc::new(
            DbStore::open(DbConfig {
                root_dir: root_dir.clone(),
            })
            .expect("open temp db"),
        );
        let list_key = default_active_poi_list_key();
        let identity = PoiCacheIdentity::new(EVM_CHAIN_TYPE, 1, DEFAULT_TXID_VERSION, list_key);
        let cache = cache_with_events(identity, &[snapshot_event(0, FixedBytes::from([9_u8; 32]))]);
        persist_cache(db.as_ref(), &cache);
        let service = PoiCacheService::new(Arc::clone(&db), artifact_config(), None)
            .expect("initialize POI cache generation");

        service.start_chain(1).await;

        let progress = service
            .progress_rx()
            .borrow()
            .get(&1)
            .cloned()
            .expect("progress");
        assert_eq!(progress.phase, PoiArtifactCachePhase::Ready);
        assert_eq!(progress.completed_lists, 1);
        assert_eq!(progress.total_lists, 1);
        assert_eq!(progress.current_event_index, Some(0));
        assert_eq!(progress.target_event_index, Some(0));
        assert_eq!(progress.list_progress.len(), 1);
        assert_eq!(progress.list_progress[0].list_key, list_key);
        assert_eq!(progress.list_progress[0].current_event_index, Some(0));
        assert!(progress.ready_for_wallet_checks);
        service.shutdown();
        fs::remove_dir_all(root_dir).expect("remove temp db dir");
    }

    #[tokio::test]
    async fn failed_rebuild_with_previous_cache_reports_nonblocking_error() {
        let root_dir = temp_db_root();
        fs::create_dir_all(&root_dir).expect("create temp db root");
        let db = Arc::new(
            DbStore::open(DbConfig {
                root_dir: root_dir.clone(),
            })
            .expect("open temp db"),
        );
        let list_key = default_active_poi_list_key();
        let identity = PoiCacheIdentity::new(EVM_CHAIN_TYPE, 1, DEFAULT_TXID_VERSION, list_key);
        let cache = cache_with_events(identity, &[snapshot_event(0, FixedBytes::from([9_u8; 32]))]);
        persist_cache(db.as_ref(), &cache);
        let service = Arc::new(
            PoiCacheService::new(db, artifact_config(), None)
                .expect("initialize POI cache generation")
                .with_poi_rpc_url(Url::parse("http://127.0.0.1:1").expect("test POI RPC URL")),
        );
        let mut progress_rx = service.progress_rx();
        let starter = Arc::clone(&service);
        let start = tokio::spawn(async move {
            starter.start_chain(1).await;
        });

        let progress =
            wait_for_progress(&mut progress_rx, 1, PoiArtifactCacheProgress::is_error).await;

        assert_eq!(progress.phase, PoiArtifactCachePhase::Error);
        assert!(progress.ready_for_wallet_checks);
        assert_eq!(progress.completed_lists, 1);
        assert_eq!(progress.current_event_index, Some(0));
        assert_eq!(progress.target_event_index, Some(0));
        assert_eq!(progress.list_progress.len(), 1);
        assert_eq!(progress.list_progress[0].list_key, list_key);
        assert_eq!(progress.list_progress[0].current_event_index, Some(0));
        assert!(progress.last_error.is_some());
        start.await.expect("start chain task");
        service.shutdown();
        fs::remove_dir_all(root_dir).expect("remove temp db dir");
    }

    #[tokio::test]
    async fn failed_rebuild_without_previous_cache_reports_blocking_error() {
        let root_dir = temp_db_root();
        fs::create_dir_all(&root_dir).expect("create temp db root");
        let db = Arc::new(
            DbStore::open(DbConfig {
                root_dir: root_dir.clone(),
            })
            .expect("open temp db"),
        );
        let service = Arc::new(
            PoiCacheService::new(db, artifact_config(), None)
                .expect("initialize POI cache generation")
                .with_poi_rpc_url(Url::parse("http://127.0.0.1:1").expect("test POI RPC URL")),
        );
        let mut progress_rx = service.progress_rx();
        let starter = Arc::clone(&service);
        let start = tokio::spawn(async move {
            starter.start_chain(1).await;
        });

        let progress =
            wait_for_progress(&mut progress_rx, 1, PoiArtifactCacheProgress::is_error).await;

        assert_eq!(progress.phase, PoiArtifactCachePhase::Error);
        assert!(!progress.ready_for_wallet_checks);
        assert_eq!(progress.completed_lists, 0);
        assert!(progress.last_error.is_some());
        start.await.expect("start chain task");
        service.shutdown();
        fs::remove_dir_all(root_dir).expect("remove temp db dir");
    }

    #[test]
    fn artifact_candidate_install_does_not_roll_back_advanced_cache() {
        let list_key = FixedBytes::from([0x11; 32]);
        let identity = PoiCacheIdentity::new(EVM_CHAIN_TYPE, 1, DEFAULT_TXID_VERSION, list_key);
        let artifact_commitment = FixedBytes::from([0x22; 32]);
        let live_tail_commitment = FixedBytes::from([0x33; 32]);
        let current_cache = cache_with_events(
            identity.clone(),
            &[
                snapshot_event(0, artifact_commitment),
                snapshot_event(1, live_tail_commitment),
            ],
        );
        let artifact_candidate =
            cache_with_events(identity, &[snapshot_event(0, artifact_commitment)]);
        let mut caches = BTreeMap::from([(list_key, current_cache)]);

        let installed = install_cache_if_not_behind(&mut caches, list_key, artifact_candidate);

        let current = caches.get(&list_key).expect("current cache");
        assert!(!installed);
        assert_eq!(current.progress().next_event_index, 2);
        assert!(current.position(&live_tail_commitment).is_some());
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn old_refresh_waiting_for_local_lock_is_rejected_after_generation_bump() {
        let root_dir = temp_db_root();
        fs::create_dir_all(&root_dir).expect("create temp db root");
        let db = Arc::new(
            DbStore::open(DbConfig {
                root_dir: root_dir.clone(),
            })
            .expect("open temp db"),
        );
        let list_key = default_active_poi_list_key();
        let identity = PoiCacheIdentity::new(EVM_CHAIN_TYPE, 1, DEFAULT_TXID_VERSION, list_key);
        let candidate = cache_with_events(
            identity,
            &[snapshot_event(0, FixedBytes::from([0x31_u8; 32]))],
        );
        let cache_generation =
            poi_artifact_cache_generation_cell(&db).expect("shared cache generation");
        let local_caches = LocalPoiCaches::new(Arc::clone(&cache_generation));
        let local_guard = local_caches.write().await;
        let install = tokio::spawn({
            let local_caches = local_caches.clone();
            async move {
                install_generated_cache_if_current(&local_caches, list_key, candidate, 0).await
            }
        });
        tokio::task::yield_now().await;
        assert!(
            !install.is_finished(),
            "old refresh must wait for cache lock"
        );

        let reset = clear_poi_artifact_cache_for_reset(&db).expect("bump cache generation");
        drop(local_guard);

        assert!(!install.await.expect("refresh install task"));
        assert!(local_caches.read().await.is_empty());
        let service = PoiCacheService::new(Arc::clone(&db), artifact_config(), None)
            .expect("initialize service from persistent generation");
        assert_eq!(
            service.cache_generation.load(Ordering::Acquire),
            reset.generation
        );
        service.shutdown();
        drop(service);
        drop(db);
        fs::remove_dir_all(root_dir).expect("remove temp db dir");
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn persisted_preload_waiting_for_local_lock_is_fenced_by_reset() {
        let root_dir = temp_db_root();
        fs::create_dir_all(&root_dir).expect("create temp db root");
        let db = Arc::new(
            DbStore::open(DbConfig {
                root_dir: root_dir.clone(),
            })
            .expect("open temp db"),
        );
        let list_key = default_active_poi_list_key();
        let identity = PoiCacheIdentity::new(EVM_CHAIN_TYPE, 1, DEFAULT_TXID_VERSION, list_key);
        let persisted = cache_with_events(
            identity.clone(),
            &[snapshot_event(0, FixedBytes::from([0x41_u8; 32]))],
        );
        persist_cache(&db, &persisted);
        let persisted = load_persisted_cache(&db, &identity)
            .expect("load persisted cache candidate")
            .expect("persisted cache candidate");
        let preloaded = BTreeMap::from([(list_key, persisted)]);
        let cache_generation =
            poi_artifact_cache_generation_cell(&db).expect("shared cache generation");
        let local_caches = LocalPoiCaches::new(Arc::clone(&cache_generation));
        let local_guard = local_caches.write().await;
        let preload = tokio::spawn({
            let local_caches = local_caches.clone();
            async move {
                install_loaded_persisted_chain_poi_caches(
                    1,
                    &local_caches,
                    preloaded,
                    Instant::now(),
                )
                .await
            }
        });
        tokio::task::yield_now().await;
        assert!(!preload.is_finished(), "preload must wait for cache lock");

        clear_poi_artifact_cache_for_reset(&db).expect("reset persisted cache");
        drop(local_guard);

        assert!(preload.await.expect("preload task").is_empty());
        assert!(local_caches.read().await.is_empty());
        drop(db);
        fs::remove_dir_all(root_dir).expect("remove temp db dir");
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn services_for_one_db_share_generation_and_resynchronize_stale_caches() {
        let root_dir = temp_db_root();
        fs::create_dir_all(&root_dir).expect("create temp db root");
        let db = Arc::new(
            DbStore::open(DbConfig {
                root_dir: root_dir.clone(),
            })
            .expect("open temp db"),
        );
        let list_key = default_active_poi_list_key();
        let identity = PoiCacheIdentity::new(EVM_CHAIN_TYPE, 1, DEFAULT_TXID_VERSION, list_key);
        let old_commitment = FixedBytes::from([0x51_u8; 32]);
        let old_cache = cache_with_events(identity.clone(), &[snapshot_event(0, old_commitment)]);
        persist_cache(&db, &old_cache);

        let reset_service = PoiCacheService::new(Arc::clone(&db), artifact_config(), None)
            .expect("initialize reset service");
        let serving_service = PoiCacheService::new(Arc::clone(&db), artifact_config(), None)
            .expect("initialize serving service");
        assert!(Arc::ptr_eq(
            &reset_service.cache_generation,
            &serving_service.cache_generation
        ));

        let local_caches = serving_service.start_chain(1).await;
        assert!(local_caches.read().await.contains_key(&list_key));
        let status_reader = LocalPoiStatusReader::new(local_caches.clone());
        let proof_source = LocalPoiMerkleProofSource::new(local_caches.clone());
        let old_statuses = status_reader
            .pois_per_list(
                DEFAULT_TXID_VERSION,
                EVM_CHAIN_TYPE,
                1,
                &[list_key],
                &[BlindedCommitmentData::transact(old_commitment)],
            )
            .await
            .expect("read old-generation status before reset");
        assert_eq!(
            old_statuses
                .get(&old_commitment)
                .and_then(|per_list| per_list.get(&list_key)),
            Some(&PoiStatus::Valid)
        );
        proof_source
            .poi_merkle_proofs(
                DEFAULT_TXID_VERSION,
                EVM_CHAIN_TYPE,
                1,
                &list_key,
                &[old_commitment],
            )
            .await
            .expect("read old-generation proof before reset");
        let old_generation = serving_service.cache_generation.load(Ordering::Acquire);
        let old_refresh = cache_with_events(
            identity.clone(),
            &[
                snapshot_event(0, FixedBytes::from([0x51_u8; 32])),
                snapshot_event(1, FixedBytes::from([0x52_u8; 32])),
            ],
        );

        reset_service
            .reset_poi_artifact_cache()
            .await
            .expect("reset shared POI cache");
        let current_generation = reset_service.cache_generation.load(Ordering::Acquire);
        assert_eq!(current_generation, old_generation + 1);
        assert_eq!(
            serving_service.cache_generation.load(Ordering::Acquire),
            current_generation
        );

        let stale_statuses = status_reader
            .pois_per_list(
                DEFAULT_TXID_VERSION,
                EVM_CHAIN_TYPE,
                1,
                &[list_key],
                &[BlindedCommitmentData::transact(old_commitment)],
            )
            .await
            .expect("old reader fences status after cross-service reset");
        assert_eq!(
            stale_statuses
                .get(&old_commitment)
                .and_then(|per_list| per_list.get(&list_key)),
            Some(&PoiStatus::Unknown)
        );
        proof_source
            .poi_merkle_proofs(
                DEFAULT_TXID_VERSION,
                EVM_CHAIN_TYPE,
                1,
                &list_key,
                &[old_commitment],
            )
            .await
            .expect_err("old reader must not return a stale proof after cross-service reset");
        assert!(
            local_caches.read().await.is_empty(),
            "direct readers must fence the old-generation corpus without service re-entry"
        );
        assert_eq!(local_caches.installed_generation(), current_generation);

        let exposed = serving_service.start_chain(1).await;
        assert!(local_caches.ptr_eq(&exposed));
        assert!(
            exposed.read().await.is_empty(),
            "the second service must clear its old-generation corpus before exposing it"
        );
        assert!(
            !install_generated_cache_if_current(
                &local_caches,
                list_key,
                old_refresh,
                old_generation,
            )
            .await,
            "an old-generation refresh must be rejected by the shared fence"
        );

        let preloaded_cache = cache_with_events(
            identity.clone(),
            &[snapshot_event(0, FixedBytes::from([0x61_u8; 32]))],
        );
        persist_cache(&db, &preloaded_cache);
        let persisted = load_persisted_cache(&db, &identity)
            .expect("load current-generation persisted cache")
            .expect("current-generation persisted cache");
        assert_eq!(persisted.cache_generation, current_generation);
        let active_list_keys = vec![list_key];
        let installed_preloads = install_loaded_persisted_chain_poi_caches(
            1,
            &local_caches,
            BTreeMap::from([(list_key, persisted)]),
            Instant::now(),
        )
        .await;
        assert_eq!(installed_preloads.len(), 1);
        let current_commitment = FixedBytes::from([0x61_u8; 32]);
        let current_statuses = status_reader
            .pois_per_list(
                DEFAULT_TXID_VERSION,
                EVM_CHAIN_TYPE,
                1,
                &[list_key],
                &[BlindedCommitmentData::transact(current_commitment)],
            )
            .await
            .expect("old reader sees current-generation status after install");
        assert_eq!(
            current_statuses
                .get(&current_commitment)
                .and_then(|per_list| per_list.get(&list_key)),
            Some(&PoiStatus::Valid)
        );
        proof_source
            .poi_merkle_proofs(
                DEFAULT_TXID_VERSION,
                EVM_CHAIN_TYPE,
                1,
                &list_key,
                &[current_commitment],
            )
            .await
            .expect("old reader sees current-generation proof after install");
        assert!(
            chain_poi_caches_available_for_lists(1, &local_caches, &active_list_keys).await,
            "a current-generation install must restore cache readiness"
        );

        let refreshed_cache = cache_with_events(
            identity.clone(),
            &[
                snapshot_event(0, FixedBytes::from([0x61_u8; 32])),
                snapshot_event(1, FixedBytes::from([0x62_u8; 32])),
            ],
        );
        assert!(
            install_generated_cache_if_current(
                &local_caches,
                list_key,
                refreshed_cache,
                current_generation,
            )
            .await
        );

        let live_tailed_cache = cache_with_events(
            identity,
            &[
                snapshot_event(0, FixedBytes::from([0x61_u8; 32])),
                snapshot_event(1, FixedBytes::from([0x62_u8; 32])),
                snapshot_event(2, FixedBytes::from([0x63_u8; 32])),
            ],
        );
        assert!(
            install_tailed_poi_cache_if_current(
                &local_caches,
                list_key,
                live_tailed_cache,
                2,
                current_generation,
            )
            .await
        );
        assert_eq!(
            local_caches
                .read()
                .await
                .get(&list_key)
                .expect("live-tailed cache")
                .progress()
                .next_event_index,
            3
        );
        assert!(chain_poi_caches_available_for_lists(1, &local_caches, &active_list_keys).await);
        let (progress_tx, progress_rx) = tokio::sync::watch::channel(BTreeMap::new());
        emit_chain_poi_cache_ready_progress(&progress_tx, 1, &local_caches, &active_list_keys)
            .await;
        assert!(
            progress_rx
                .borrow()
                .get(&1)
                .expect("serving progress")
                .ready_for_wallet_checks
        );

        serving_service.shutdown();
        reset_service.shutdown();
        drop(serving_service);
        drop(reset_service);
        drop(db);
        fs::remove_dir_all(root_dir).expect("remove temp db dir");
    }

    #[tokio::test]
    async fn failed_live_tail_candidate_does_not_mutate_artifact_cache() {
        let list_key = FixedBytes::from([7_u8; 32]);
        let identity = PoiCacheIdentity::new(EVM_CHAIN_TYPE, 1, DEFAULT_TXID_VERSION, list_key);
        let artifact_commitment = FixedBytes::from([0x22; 32]);
        let tailed_commitment = FixedBytes::from([0x33; 32]);
        let cache = cache_with_events(identity, &[snapshot_event(0, artifact_commitment)]);
        let original_next_event_index = cache.progress().next_event_index;
        let leaves = vec![U256::from_be_bytes(tailed_commitment.0)];
        let mock = spawn_poi_rpc_sequence(vec![
            serde_json::to_value(leaves).expect("leaves JSON"),
            serde_json::json!(false),
        ]);
        let client = PoiRpcClient::new(mock.url.clone());

        let err = live_tail_candidate_cache(&client, &cache)
            .await
            .expect_err("root validation rejection should reject candidate cache");

        assert!(matches!(err, LivePoiTailError::RootRejected));
        assert_eq!(cache.progress().next_event_index, original_next_event_index);
        assert!(cache.position(&tailed_commitment).is_none());
        let request = mock
            .requests
            .recv_timeout(Duration::from_secs(2))
            .expect("remote leaf request");
        assert_eq!(request["method"], "ppoi_poi_merkletree_leaves");
        let request = mock
            .requests
            .recv_timeout(Duration::from_secs(2))
            .expect("remote root validation request");
        assert_eq!(request["method"], "ppoi_validate_poi_merkleroots");
    }
}
