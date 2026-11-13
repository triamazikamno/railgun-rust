use super::commit::wallet_scan_progress_update;
use super::poi_maintenance::{
    PoiMaintenanceAbortReason, ppoi_workflow_status_with_candidate_report,
    run_poi_maintenance_with_watchdog, sync_poi_refreshing_from_controller,
    wallet_poi_refresh_interval_with_period,
};
use super::test_support::spawn_wallet_worker;
use super::*;
use crate::types::WalletResetToken;
use crate::wallet::actor::PoiRemoteJobKind;
use std::sync::atomic::Ordering;

use crate::{WalletPpoiSubmissionStatus, WalletPpoiWorkflowStatus, WalletReadiness};

use std::collections::{BTreeMap, HashMap};
use std::fs;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use alloy::primitives::{Address, FixedBytes, U256};
use async_trait::async_trait;
use broadcaster_core::contracts::railgun::CommitmentCiphertext;
use broadcaster_core::crypto::railgun::ViewingKeyData;
use broadcaster_core::notes::Note;
use broadcaster_core::transact::DEFAULT_TXID_VERSION;
use local_db::{
    DbConfig, DbStore, OpaqueWalletPrivateRow, OutputPoiRecoveryRecord, OutputPoiRecoveryStatus,
    PendingOutputPoiContextRecord, PendingOutputPoiObservation, PendingOutputPoiRole,
    WalletCacheKey, WalletMeta, WalletPrivateRecordKind,
};
use merkletree::tree::MerkleForest;
use poi::artifacts::SnapshotEvent;
use poi::cache::{PoiCache, PoiCacheIdentity};
use poi::error::PoiError;
use poi::poi::{BlindedCommitmentData, PoiEventType};
use tokio::sync::{RwLock, broadcast, mpsc, oneshot, watch};
use url::Url;

use railgun_wallet::scan::{
    CommitmentObservation, SenderScanOutput, SpentNullifier, WalletLogDelta,
};
use railgun_wallet::{NoteCiphertext, PoiStatus, Utxo, UtxoCommitmentKind, UtxoSource, WalletUtxo};

use crate::chain::ChainPublicDataPlane;
use crate::types::{
    BackfillRequest, ChainKey, GlobalPoiPolicy, LogBatch, PoiArtifactManifestSource,
    PoiArtifactSourceConfig, PoiProxyFallback, PublicDataPlaneEpoch, PublicScanReadScope,
    WalletBackfillDriver, WalletConfig, WalletIndexedCatchUpSource, WalletIndexedCatchUpStatus,
    WalletObservation, WalletPendingSpent, WalletScanRows,
};
use crate::wallet::handle::{
    PendingOutputPoiSubject, WalletPendingOverlayRequest, WalletPrivateViewTicket,
};
use crate::wallet::pending_output_poi::{
    PendingOutputPoiPreflight, PendingOutputPoiSubmissionPlan, current_pending_output_poi_subject,
    expected_recovery_state, pending_output_poi_submission_plan_current,
    pending_output_poi_submit_identity,
};
use crate::wallet::{EVM_CHAIN_TYPE, WalletActorLifecycle};

mod backfill;
mod jobs;
mod lifecycle;
mod mailbox;
mod poi_status;
mod reset;
mod scan;

fn test_public_data_plane(db: &Arc<DbStore>) -> ChainPublicDataPlane {
    ChainPublicDataPlane::new(Arc::clone(db), Arc::new(AtomicU64::new(0)))
}

async fn wait_for_readiness(
    readiness_rx: &mut watch::Receiver<WalletObservation>,
    expected: WalletReadiness,
) {
    tokio::time::timeout(Duration::from_secs(2), async {
        while readiness_rx.borrow().readiness() != &expected {
            readiness_rx
                .changed()
                .await
                .expect("wallet readiness sender remains active");
        }
    })
    .await
    .expect("wallet readiness transition");
}

fn test_wallet_poi_runtime() -> WalletPoiRuntime {
    WalletPoiRuntime::from_policy(
        &GlobalPoiPolicy::PoiProxy {
            rpc_url: Url::parse("http://127.0.0.1:1")
                .expect("POI RPC URL")
                .into(),
        },
        None,
    )
}

const fn test_public_scan_read_scope() -> PublicScanReadScope {
    PublicScanReadScope::new(PublicDataPlaneEpoch::new(0))
}

#[derive(Debug, Clone, Copy, Default)]
struct FailingCacheStoreState {
    store_calls: usize,
    meta_calls: usize,
    last_chain_id: Option<u64>,
    fail_next_store: bool,
    fail_next_meta: bool,
    fail_next_actor_state: bool,
    fail_next_actor_state_put: bool,
    fail_next_reset_replay_retirement: bool,
}

struct FailingCacheStore {
    db: Arc<DbStore>,
    state: Mutex<FailingCacheStoreState>,
    actor_state: Mutex<Option<WalletSyncActorStateRecord>>,
    recovery_reads: AtomicU64,
    replay_pending_replacement: Mutex<Option<PendingOutputPoiContextRecord>>,
}

impl FailingCacheStore {
    fn new(db: Arc<DbStore>) -> Self {
        Self {
            db,
            state: Mutex::default(),
            actor_state: Mutex::default(),
            recovery_reads: AtomicU64::new(0),
            replay_pending_replacement: Mutex::default(),
        }
    }

    fn fail_next_store(&self) {
        self.state.lock().expect("cache state").fail_next_store = true;
    }

    fn fail_next_meta(&self) {
        self.state.lock().expect("cache state").fail_next_meta = true;
    }

    fn fail_next_actor_state(&self) {
        self.state
            .lock()
            .expect("cache state")
            .fail_next_actor_state = true;
    }

    fn fail_next_actor_state_put(&self) {
        self.state
            .lock()
            .expect("cache state")
            .fail_next_actor_state_put = true;
    }

    fn fail_next_reset_replay_retirement(&self) {
        self.state
            .lock()
            .expect("cache state")
            .fail_next_reset_replay_retirement = true;
    }

    fn seed_actor_state(&self, state: WalletSyncActorStateRecord) {
        *self.actor_state.lock().expect("actor state") = Some(state);
    }

    fn actor_state(&self) -> Option<WalletSyncActorStateRecord> {
        self.actor_state.lock().expect("actor state").clone()
    }

    fn state(&self) -> FailingCacheStoreState {
        *self.state.lock().expect("cache state")
    }
}

impl WalletCacheStore for FailingCacheStore {
    fn commit_wallet_private_state(
        &self,
        commit: WalletPrivateCommit<'_>,
    ) -> Result<(), WalletCacheError> {
        self.state.lock().expect("cache state").last_chain_id = Some(commit.chain_id());
        if matches!(commit.utxo_mutation(), WalletUtxoMutation::Replace(_)) {
            let mut state = self.state.lock().expect("cache state");
            state.store_calls += 1;
            if state.fail_next_store {
                state.fail_next_store = false;
                return Err(WalletCacheError::Crypto);
            }
        } else {
            let mut state = self.state.lock().expect("cache state");
            state.meta_calls += 1;
            if state.fail_next_meta {
                state.fail_next_meta = false;
                return Err(WalletCacheError::Crypto);
            }
        }
        let actor_state = commit.sync_actor_state().cloned();
        <DbStore as WalletCacheStore>::commit_wallet_private_state(self.db.as_ref(), commit)?;
        if let Some(state) = actor_state {
            *self.actor_state.lock().expect("actor state") = Some(state);
        }
        Ok(())
    }

    fn load_wallet_utxos(
        &self,
        _wallet_id: &WalletCacheKey,
    ) -> Result<Vec<WalletUtxo>, WalletCacheError> {
        Ok(Vec::new())
    }

    fn get_wallet_meta(
        &self,
        _wallet_id: &WalletCacheKey,
    ) -> Result<Option<WalletMeta>, WalletCacheError> {
        Ok(None)
    }

    fn get_wallet_sync_actor_state(
        &self,
        _chain_id: u64,
        _wallet_id: &WalletCacheKey,
    ) -> Result<Option<WalletSyncActorStateRecord>, WalletCacheError> {
        let mut state = self.state.lock().expect("cache state");
        if state.fail_next_actor_state {
            state.fail_next_actor_state = false;
            return Err(WalletCacheError::Crypto);
        }
        Ok(self.actor_state.lock().expect("actor state").clone())
    }

    fn put_wallet_sync_actor_state(
        &self,
        commit: WalletSyncActorStateCommit<'_>,
    ) -> Result<(), WalletCacheError> {
        let mut store_state = self.state.lock().expect("cache state");
        if commit.state().pending_reset.is_none() && store_state.fail_next_reset_replay_retirement {
            store_state.fail_next_reset_replay_retirement = false;
            return Err(WalletCacheError::Crypto);
        }
        if store_state.fail_next_actor_state_put {
            store_state.fail_next_actor_state_put = false;
            return Err(WalletCacheError::Crypto);
        }
        drop(store_state);
        self.db.put_wallet_sync_actor_state(commit.state())?;
        *self.actor_state.lock().expect("actor state") = Some(commit.state().clone());
        Ok(())
    }

    fn get_pending_output_poi_context(
        &self,
        chain_id: u64,
        wallet_id: &WalletCacheKey,
        output_commitment: &FixedBytes<32>,
    ) -> Result<Option<PendingOutputPoiContextRecord>, WalletCacheError> {
        <DbStore as WalletCacheStore>::get_pending_output_poi_context(
            self.db.as_ref(),
            chain_id,
            wallet_id,
            output_commitment,
        )
    }

    fn list_pending_output_poi_contexts(
        &self,
        chain_id: u64,
        wallet_id: &WalletCacheKey,
    ) -> Result<Vec<PendingOutputPoiContextRecord>, WalletCacheError> {
        <DbStore as WalletCacheStore>::list_pending_output_poi_contexts(
            self.db.as_ref(),
            chain_id,
            wallet_id,
        )
    }

    fn get_output_poi_recovery(
        &self,
        chain_id: u64,
        wallet_id: &WalletCacheKey,
        output_commitment: &FixedBytes<32>,
    ) -> Result<Option<OutputPoiRecoveryRecord>, WalletCacheError> {
        // Replay selects the source from its first recovery read, then captures the
        // predecessor on its second. Replace the durable subject after that snapshot.
        if self.recovery_reads.fetch_add(1, Ordering::SeqCst) == 1
            && let Some(replacement) = self
                .replay_pending_replacement
                .lock()
                .expect("replay replacement")
                .take()
        {
            self.db.put_pending_output_poi_context(&replacement)?;
        }
        <DbStore as WalletCacheStore>::get_output_poi_recovery(
            self.db.as_ref(),
            chain_id,
            wallet_id,
            output_commitment,
        )
    }

    fn list_output_poi_recoveries(
        &self,
        chain_id: u64,
        wallet_id: &WalletCacheKey,
    ) -> Result<Vec<OutputPoiRecoveryRecord>, WalletCacheError> {
        <DbStore as WalletCacheStore>::list_output_poi_recoveries(
            self.db.as_ref(),
            chain_id,
            wallet_id,
        )
    }

    fn get_sender_transaction_candidate(
        &self,
        chain_id: u64,
        wallet_id: &WalletCacheKey,
        outer_transaction_hash: &FixedBytes<32>,
    ) -> Result<Option<crate::SenderTransactionCandidate>, WalletCacheError> {
        <DbStore as WalletCacheStore>::get_sender_transaction_candidate(
            self.db.as_ref(),
            chain_id,
            wallet_id,
            outer_transaction_hash,
        )
    }

    fn list_sender_transaction_candidates(
        &self,
        chain_id: u64,
        wallet_id: &WalletCacheKey,
    ) -> Result<Vec<crate::SenderTransactionCandidate>, WalletCacheError> {
        <DbStore as WalletCacheStore>::list_sender_transaction_candidates(
            self.db.as_ref(),
            chain_id,
            wallet_id,
        )
    }
}

struct BlockingPoiStatusReader {
    started: tokio::sync::Mutex<Option<oneshot::Sender<()>>>,
    release: tokio::sync::Mutex<Option<oneshot::Receiver<()>>>,
    status: PoiStatus,
}

impl BlockingPoiStatusReader {
    fn new(started: oneshot::Sender<()>, release: oneshot::Receiver<()>) -> Self {
        Self {
            started: tokio::sync::Mutex::new(Some(started)),
            release: tokio::sync::Mutex::new(Some(release)),
            status: PoiStatus::Valid,
        }
    }
}

#[async_trait]
impl PoiStatusReader for BlockingPoiStatusReader {
    async fn pois_per_list(
        &self,
        _txid_version: &str,
        _chain_type: u8,
        _chain_id: u64,
        list_keys: &[FixedBytes<32>],
        blinded_commitment_datas: &[BlindedCommitmentData],
    ) -> Result<BTreeMap<FixedBytes<32>, BTreeMap<FixedBytes<32>, PoiStatus>>, PoiError> {
        if let Some(started) = self.started.lock().await.take() {
            let _ = started.send(());
        }
        if let Some(release) = self.release.lock().await.take() {
            let _ = release.await;
        }
        Ok(blinded_commitment_datas
            .iter()
            .map(|data| {
                (
                    data.blinded_commitment,
                    list_keys
                        .iter()
                        .copied()
                        .map(|list_key| (list_key, self.status))
                        .collect(),
                )
            })
            .collect())
    }
}

async fn send_apply(
    handle: &WalletHandle,
    sender: &mpsc::Sender<BackfillEvent>,
    apply: WalletScanApply,
    reset_generation: u64,
) -> WalletBackfillApplyResult {
    send_apply_token(sender, apply, handle.mint_sync_token(reset_generation)).await
}

async fn send_apply_token(
    sender: &mpsc::Sender<BackfillEvent>,
    apply: WalletScanApply,
    token: WalletSyncToken,
) -> WalletBackfillApplyResult {
    match send_start_token(sender, apply.to_block, token).await {
        WalletBackfillStartResult::Accepted { grant, .. } => {
            let driver = grant.activate();
            let result = driver.apply("test", apply).await;
            driver.retire("test").await;
            result
        }
        WalletBackfillStartResult::Rejected {
            committed_to,
            reason,
        } => WalletBackfillApplyResult::Rejected {
            committed_to,
            reason,
        },
    }
}

async fn send_target(
    handle: &WalletHandle,
    sender: &mpsc::Sender<BackfillEvent>,
    target_block: u64,
    reset_generation: u64,
) -> WalletBackfillFinishResult {
    send_target_token(
        sender,
        target_block,
        handle.mint_sync_token(reset_generation),
    )
    .await
}

async fn send_target_token(
    sender: &mpsc::Sender<BackfillEvent>,
    target_block: u64,
    token: WalletSyncToken,
) -> WalletBackfillFinishResult {
    match send_start_token(sender, target_block, token).await {
        WalletBackfillStartResult::Accepted { grant, .. } => {
            let driver = grant.activate();
            let result = driver.finish("test", target_block).await;
            if !matches!(result, WalletBackfillFinishResult::Ready { .. }) {
                driver.retire("test").await;
            }
            result
        }
        WalletBackfillStartResult::Rejected {
            committed_to,
            reason,
        } => WalletBackfillFinishResult::Rejected {
            committed_to,
            reason,
        },
    }
}

async fn send_start_token(
    sender: &mpsc::Sender<BackfillEvent>,
    target_block: u64,
    token: WalletSyncToken,
) -> WalletBackfillStartResult {
    let (response, result_rx) = oneshot::channel();
    sender
        .send(BackfillEvent::Start {
            target_block,
            token,
            response,
        })
        .await
        .expect("send target");
    result_rx.await.expect("target response")
}

fn assert_start_accepted(
    result: WalletBackfillStartResult,
    token: WalletSyncToken,
    committed_to: u64,
    target_block: u64,
) -> WalletBackfillDriver {
    match result {
        WalletBackfillStartResult::Accepted {
            committed_to: actual_committed_to,
            target_block: actual_target_block,
            grant,
        } => {
            assert_eq!(actual_committed_to, committed_to);
            assert_eq!(actual_target_block, target_block);
            assert_eq!(grant.token(), token);
            grant.activate()
        }
        other @ WalletBackfillStartResult::Rejected { .. } => {
            panic!("expected accepted target, got {other:?}")
        }
    }
}

fn test_actor_state(last_scanned: u64) -> WalletActorState {
    test_actor_state_with_observation(last_scanned).0
}

fn test_actor_state_with_observation(
    last_scanned: u64,
) -> (WalletActorState, watch::Receiver<WalletObservation>) {
    WalletActorState::new(
        1,
        1,
        0,
        last_scanned,
        0,
        None,
        false,
        WalletViewState::Current(WalletCurrentSnapshot::new(
            last_scanned,
            0,
            0,
            Arc::<[WalletUtxo]>::from(Vec::new()),
            Arc::new(WalletPendingOverlay::default()),
        )),
    )
}

fn test_actor_state_for_handle(
    handle: &WalletHandle,
    last_scanned: u64,
) -> (WalletActorState, watch::Receiver<WalletObservation>) {
    let mut state = test_actor_state(last_scanned);
    state.set_observation_publisher_for_test(
        handle
            .observation
            .upgrade()
            .expect("test handle owns observation publisher"),
    );
    (state, handle.subscribe_observation())
}

const fn test_reset_token(intent_id: u64) -> WalletResetToken {
    WalletResetToken::for_test(1, 1, intent_id)
}

async fn send_reset(
    sender: &mpsc::Sender<BackfillEvent>,
    intent_id: u64,
    from_block: u64,
) -> WalletBackfillResetResult {
    let (response, result_rx) = oneshot::channel();
    sender
        .send(BackfillEvent::Reset {
            token: test_reset_token(intent_id),
            from_block,
            replay_plan: WalletResetReplayPlan::new(0, 0, true),
            response,
        })
        .await
        .expect("send reset");
    result_rx.await.expect("reset response")
}

fn logs_apply(from_block: u64, to_block: u64) -> WalletScanApply {
    WalletScanApply::rows_from_log_batch(
        from_block,
        to_block,
        &logs_payload(from_block, to_block),
        PublicScanSource::Rpc,
    )
    .expect("normalize empty log payload")
}

fn logs_payload(from_block: u64, to_block: u64) -> Arc<LogBatch> {
    Arc::new(LogBatch {
        from_block,
        to_block,
        logs: Vec::new(),
        block_timestamps: HashMap::new(),
        to_block_hash: None,
        read_scope: test_public_scan_read_scope(),
    })
}

fn indexed_delta_batch(from_block: u64, to_block: u64, delta: WalletLogDelta) -> WalletScanApply {
    WalletScanApply::indexed_delta_for_test(
        from_block,
        to_block,
        delta,
        test_public_scan_read_scope(),
        WalletIndexedCatchUpSource::IndexedArtifacts,
    )
}

fn pending_overlay_rows_from_delta(
    from_block: u64,
    to_block: u64,
    delta: WalletLogDelta,
) -> WalletScanRows {
    indexed_delta_batch(from_block, to_block, delta).rows
}

fn empty_delta() -> WalletLogDelta {
    WalletLogDelta {
        utxos: Vec::new(),
        nullifiers: Vec::new(),
        commitment_observations: Vec::new(),
        sender_scan_outputs: Vec::new(),
    }
}

fn wallet_config() -> WalletConfig {
    WalletConfig {
        chain: ChainKey {
            chain_id: 1,
            contract: Address::ZERO,
        },
        cache_key: WalletCacheKey::from_opaque_bytes(b"test")
            .expect("non-empty test wallet cache key"),
        start_block: Some(0),
        sync_to_block: None,
        quick_sync_endpoint: None,
        scan_keys: ViewingKeyData {
            viewing_private_key: [0u8; 32],
            viewing_public_key: [0u8; 32],
            nullifying_key: U256::ZERO,
            master_public_key: U256::ZERO,
        },
        spending_public_key: None,
        progress_tx: None,
        cache_store: None,
        poi_recovery_prover: None,
        use_indexed_wallet_catch_up: true,
    }
}

fn source(block_number: u64, byte: u8) -> UtxoSource {
    UtxoSource {
        tx_hash: FixedBytes::from([byte; 32]),
        block_number,
        block_timestamp: 1_700_000_000 + block_number,
    }
}

fn test_wallet_utxo(block_number: u64, position: u64) -> WalletUtxo {
    test_wallet_utxo_with_random(block_number, position, [0; 16])
}

fn test_wallet_utxo_with_random(block_number: u64, position: u64, random: [u8; 16]) -> WalletUtxo {
    WalletUtxo::new(Utxo::new(
        Note {
            token_hash: U256::from(1),
            value: U256::from(10),
            random,
            npk: U256::from(u64::from(random[0]) + 2),
        },
        2,
        position,
        source(block_number, block_number as u8),
        UtxoCommitmentKind::Transact,
    ))
}

fn pending_output_context_for_wallet_utxo(
    cfg: &WalletConfig,
    wallet_utxo: &WalletUtxo,
) -> PendingOutputPoiContextRecord {
    PendingOutputPoiContextRecord {
        chain_id: cfg.chain.chain_id,
        wallet_id: cfg.cache_key.to_string(),
        txid_version: DEFAULT_TXID_VERSION.to_string(),
        output_commitment: wallet_utxo.utxo.poi.commitment,
        output_npk: wallet_utxo.utxo.poi.npk,
        utxo_tree_in: u64::from(wallet_utxo.utxo.tree),
        railgun_txid: U256::from(7),
        txid_merkleroot_index: None,
        pre_transaction_pois_per_txid_leaf_per_list: BTreeMap::new(),
        required_poi_list_keys: Vec::new(),
        output_role: PendingOutputPoiRole::Recipient,
        created_at: 123,
        source_operation_id: None,
        observation: None,
        submitted_poi_list_keys: Vec::new(),
        terminal_error: None,
    }
}

fn current_pending_proof_map(list_key: FixedBytes<32>) -> crate::wallet::PreTransactionPoiMap {
    let fixture: serde_json::Value = serde_json::from_slice(include_bytes!(
        "../../../../core/tests/fixtures/ppoi_3x3.json"
    ))
    .expect("current proof fixture");
    let proof = serde_json::from_value(fixture["pre_tx_poi"].clone()).expect("current proof");
    let leaf = serde_json::from_value(fixture["public_context"]["txid_leaf_hash"].clone())
        .expect("current proof leaf");
    BTreeMap::from([(list_key, BTreeMap::from([(leaf, proof)]))])
}

fn observed_external_pending_output_context(
    cfg: &WalletConfig,
    output: &WalletUtxo,
    list_key: FixedBytes<32>,
    observed_source: &UtxoSource,
) -> PendingOutputPoiContextRecord {
    let mut context = pending_output_context_for_wallet_utxo(cfg, output);
    context.pre_transaction_pois_per_txid_leaf_per_list =
        BTreeMap::from([(list_key, BTreeMap::new())]);
    context.required_poi_list_keys = vec![list_key];
    context.observation = Some(PendingOutputPoiObservation {
        output_tree: u64::from(output.utxo.tree),
        output_position: output.utxo.position,
        tx_hash: observed_source.tx_hash,
        block_number: observed_source.block_number,
        block_timestamp: observed_source.block_timestamp,
    });
    context.submitted_poi_list_keys = vec![list_key];
    context.terminal_error = Some("stale observation terminal state".to_string());
    context
}

fn output_poi_recovery_for_pending_context(
    context: &PendingOutputPoiContextRecord,
    status: OutputPoiRecoveryStatus,
) -> OutputPoiRecoveryRecord {
    OutputPoiRecoveryRecord {
        chain_id: context.chain_id,
        wallet_id: context.wallet_id.clone(),
        output_commitment: context.output_commitment,
        source_tx_hash: context
            .observation
            .as_ref()
            .expect("observed pending context")
            .tx_hash,
        tx_input: None,
        status,
        created_at: 123,
        updated_at: 124,
        last_detection_at: None,
        last_submission_at: Some(124),
        next_retry_at: Some(125),
        attempt_count: 1,
        last_error: None,
    }
}

fn temp_db_root(name: &str) -> std::path::PathBuf {
    let unique = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("system clock")
        .as_nanos();
    let dir = std::env::temp_dir().join(format!("sync-service-{name}-{unique}"));
    fs::create_dir_all(&dir).expect("create temp db dir");
    dir
}
