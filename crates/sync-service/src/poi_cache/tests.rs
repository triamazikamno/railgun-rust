use super::{
    ActivePoiCacheAttempt, ChainPoiCacheCommand, ChainPoiCacheCoordinator, EVM_CHAIN_TYPE,
    POI_CACHE_BLOCKED_ACTIVE_INTERVAL, POI_CACHE_BLOCKED_IDLE_INTERVAL,
    POI_CACHE_EVENT_ACTIVE_INTERVAL, POI_CACHE_EVENT_IDLE_INTERVAL,
    POI_CACHE_FAILURE_RETRY_INTERVAL, PersistedPoiArtifactCache, PoiCacheCandidateJob,
    PoiCacheDemand, PoiCacheMaintenanceSchedule, PoiCacheService, PoiCacheServiceError,
    PoiCacheServiceRuntime, PoiCacheSyncScope, PoiCorpusCompactionLane, PoiCorpusCompactionRequest,
    PoiListSourceOutcome, PoiRpcAttemptOutcome, PoiSourceHealth, PreparedPoiCacheBatch,
    PreparedPoiCacheCandidate, PreparedPoiCachePersistence, PreparedPublicRpcPersistence,
    StagedPoiCacheCandidate, apply_poi_cache_demand_update, apply_staged_poi_cache_batch,
    cancel_active_attempt, cancel_poi_corpus_compaction_lane, chain_poi_cache_list_progress,
    drop_completed_attempt, effective_poi_cache_scope, enqueue_poi_corpus_compactions,
    finish_chain_poi_cache_attempt, install_cache_if_not_behind, new_poi_artifact_cache_progress,
    poi_cache_demand, poi_cache_error_diagnostic, produce_chain_poi_cache_candidates,
    public_rpc_candidate_cache, publish_active_attempt_progress,
    publish_chain_poi_cache_ready_and_acknowledge_initialization, record_list_source_outcomes,
    replacement_poi_cache_scope, run_background_poi_corpus_compaction, single_list_event_index,
    source_health_for_lists, stage_poi_cache_candidate, start_next_poi_corpus_compaction,
    validate_artifact_manifest_sequences, wait_for_active_poi_corpus_compaction,
};
use crate::chain::PoiArtifactPersistenceHandle;
use crate::poi_artifacts::test_support::{load_persisted_cache, persist_public_rpc_cache};
use crate::poi_artifacts::{
    ExpectedPoiCorpusBase, clear_poi_artifact_cache_for_reset,
    load_persisted_cache_candidate_for_publisher, record_poi_rpc_success,
};
use crate::types::PoiCorpusRevision;
use crate::types::{
    LocalPoiCaches, PoiArtifactCacheAttemptId, PoiArtifactCacheFailureKind,
    PoiArtifactCacheGraphProgress, PoiArtifactCachePhase, PoiArtifactCacheProgress,
    PoiArtifactManifestSource, PoiArtifactSourceConfig, WalletCurrentSnapshot, WalletObservation,
    WalletPendingOverlay, WalletPpoiWorkflowStatus, WalletReadiness, WalletViewState,
};
use crate::wallet::test_support::{LivePoiTailError, live_tail_candidate_cache};
use alloy::primitives::{FixedBytes, U256};
use broadcaster_core::transact::DEFAULT_TXID_VERSION;
use ed25519_dalek::{Signer, SigningKey};
use local_db::{
    DbConfig, DbStore, POI_CORPUS_JOURNAL_SOFT_DELTA_COUNT, PoiArtifactCacheRecord,
    PoiArtifactDescriptorRecord, PoiCacheRecordSource, PoiCorpusJournalHeadRecord,
    PoiCorpusValidationRecord,
};
use poi::artifacts::SnapshotEvent;
use poi::artifacts::verify::canonical_poi_event_message;
use poi::cache::{PoiCache, PoiCacheError, PoiCacheIdentity, PoiCacheJournalDelta};
use poi::error::PoiRpcError;
use poi::poi::{
    BlockedShield, PoiEventType, PoiRpcClient, PoiSyncedListEvent, SignedPoiEvent,
    default_active_poi_list_key,
};
use railgun_wallet::{Note, PoiStatus, Utxo, UtxoCommitmentKind, UtxoSource, WalletUtxo};
use std::collections::BTreeMap;
use std::fs;
use std::io::{Read, Write};
use std::net::TcpListener;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::mpsc::{self, Receiver};
use std::sync::{Arc, Mutex as StdMutex};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use tokio::sync::watch;
use tokio::time::Instant as TokioInstant;
use tokio_util::sync::CancellationToken;
use url::Url;

static TEMP_DB_COUNTER: AtomicU64 = AtomicU64::new(0);

const fn attempt_id(value: u64) -> PoiArtifactCacheAttemptId {
    PoiArtifactCacheAttemptId::new(value)
}

fn test_persistence(db: &Arc<DbStore>) -> PoiArtifactPersistenceHandle {
    PoiArtifactPersistenceHandle::new(Arc::clone(db), Arc::new(tokio::sync::Mutex::new(())))
}

#[test]
fn v4_candidate_batch_requires_one_global_manifest_sequence() {
    validate_artifact_manifest_sequences([10, 10].into_iter())
        .expect("matching manifest sequences");
    assert!(matches!(
        validate_artifact_manifest_sequences([9, 10].into_iter()),
        Err(PoiCacheServiceError::Refresh { .. })
    ));
}

#[test]
fn maintenance_schedule_uses_demand_intervals_and_last_success() {
    let now = TokioInstant::now();
    let mut schedule = PoiCacheMaintenanceSchedule::new(now);
    assert_eq!(schedule.due_scope(now), Some(PoiCacheSyncScope::FULL));
    assert_eq!(
        PoiCacheSyncScope::EVENTS.union(PoiCacheSyncScope::BLOCKED_SHIELDS),
        PoiCacheSyncScope::FULL
    );

    schedule.record_success(PoiCacheSyncScope::FULL, now);
    schedule.update_demand(
        PoiCacheDemand {
            events: true,
            blocked_shields: true,
        },
        now + Duration::from_secs(1),
    );
    assert_eq!(
        schedule.due_scope(now + Duration::from_secs(1)),
        Some(PoiCacheSyncScope::FULL)
    );

    let active_success = now + Duration::from_secs(2);
    schedule.record_success(PoiCacheSyncScope::FULL, active_success);
    assert_eq!(
        schedule.event_deadline,
        active_success + POI_CACHE_EVENT_ACTIVE_INTERVAL
    );
    assert_eq!(
        schedule.blocked_shields_deadline,
        active_success + POI_CACHE_BLOCKED_ACTIVE_INTERVAL
    );

    schedule.update_demand(PoiCacheDemand::default(), now + Duration::from_secs(3));
    assert_eq!(
        schedule.event_deadline,
        active_success + POI_CACHE_EVENT_IDLE_INTERVAL
    );
    assert_eq!(
        schedule.blocked_shields_deadline,
        active_success + POI_CACHE_BLOCKED_IDLE_INTERVAL
    );

    let failed_at = active_success + Duration::from_secs(4);
    schedule.record_failure(PoiCacheSyncScope::BLOCKED_SHIELDS, failed_at);
    assert_eq!(
        schedule.blocked_shields_deadline,
        failed_at + POI_CACHE_FAILURE_RETRY_INTERVAL
    );
}

#[test]
fn demand_activation_is_immediate_and_identity_fenced() {
    let now = TokioInstant::now();
    let mut schedule = PoiCacheMaintenanceSchedule::new(now);
    schedule.record_success(PoiCacheSyncScope::FULL, now);
    assert!(apply_poi_cache_demand_update(
        &mut schedule,
        2,
        PoiCacheDemand {
            events: true,
            blocked_shields: false,
        },
        now + Duration::from_secs(1),
    ));
    assert_eq!(
        schedule.due_scope(now + Duration::from_secs(1)),
        Some(PoiCacheSyncScope::EVENTS)
    );
    assert!(!apply_poi_cache_demand_update(
        &mut schedule,
        1,
        PoiCacheDemand::default(),
        now + Duration::from_secs(2),
    ));
    assert!(schedule.demand.events);
}

#[test]
fn event_scope_requires_initialized_blocked_shield_snapshots() {
    let list_key = FixedBytes::from([0x12; 32]);
    let mut initialized = cache_with_events(
        PoiCacheIdentity::new(EVM_CHAIN_TYPE, 1, DEFAULT_TXID_VERSION, list_key),
        &[snapshot_event(0, FixedBytes::from([0x34; 32]))],
    );
    initialized
        .apply_blocked_shields(&[])
        .expect("mark blocked snapshot initialized");

    assert_eq!(
        effective_poi_cache_scope(
            PoiCacheSyncScope::EVENTS,
            &BTreeMap::from([(list_key, initialized)]),
            &[list_key],
        ),
        PoiCacheSyncScope::EVENTS
    );

    let missing = cache_with_events(
        PoiCacheIdentity::new(EVM_CHAIN_TYPE, 1, DEFAULT_TXID_VERSION, list_key),
        &[snapshot_event(0, FixedBytes::from([0x34; 32]))],
    );
    assert_eq!(
        effective_poi_cache_scope(
            PoiCacheSyncScope::EVENTS,
            &BTreeMap::from([(list_key, missing)]),
            &[list_key],
        ),
        PoiCacheSyncScope::FULL
    );
    assert_eq!(
        effective_poi_cache_scope(PoiCacheSyncScope::EVENTS, &BTreeMap::new(), &[list_key],),
        PoiCacheSyncScope::FULL
    );
    assert_eq!(
        effective_poi_cache_scope(
            PoiCacheSyncScope::BLOCKED_SHIELDS,
            &BTreeMap::new(),
            &[list_key],
        ),
        PoiCacheSyncScope::BLOCKED_SHIELDS
    );
}

#[test]
fn event_retry_replaces_active_full_scope_without_dropping_blocked_work() {
    let active = ActivePoiCacheAttempt {
        id: attempt_id(1),
        generation: 0,
        scope: PoiCacheSyncScope::FULL,
        cancel: CancellationToken::new(),
        job: Box::pin(std::future::pending()),
        retry_completion: None,
    };

    assert_eq!(
        replacement_poi_cache_scope(PoiCacheSyncScope::EVENTS, Some(&active)),
        PoiCacheSyncScope::FULL
    );
    assert_eq!(
        replacement_poi_cache_scope(PoiCacheSyncScope::EVENTS, None),
        PoiCacheSyncScope::EVENTS
    );
}

#[test]
fn demand_derivation_uses_unspent_current_and_pending_utxos() {
    let list_key = FixedBytes::from([0x11; 32]);
    let mut transact = demand_utxo(1, UtxoCommitmentKind::Transact);
    transact
        .utxo
        .poi
        .statuses
        .insert(list_key, PoiStatus::Missing);
    let mut shield = demand_utxo(2, UtxoCommitmentKind::Shield);
    shield
        .utxo
        .poi
        .statuses
        .insert(list_key, PoiStatus::Unknown);
    let mut spent = demand_utxo(3, UtxoCommitmentKind::Shield);
    spent.spent = Some(UtxoSource {
        tx_hash: FixedBytes::from([0x33; 32]),
        block_number: 3,
        block_timestamp: 3,
    });
    let pending = demand_utxo(4, UtxoCommitmentKind::Transact);

    let demand = poi_cache_demand(
        &demand_observation(
            vec![transact, shield, spent],
            WalletPendingOverlay {
                new_utxos: vec![pending],
                ..WalletPendingOverlay::default()
            },
            WalletPpoiWorkflowStatus::default(),
        ),
        &[list_key],
    );
    assert_eq!(
        demand,
        PoiCacheDemand {
            events: true,
            blocked_shields: true,
        }
    );

    let workflow = poi_cache_demand(
        &demand_observation(
            Vec::new(),
            WalletPendingOverlay::default(),
            WalletPpoiWorkflowStatus {
                awaiting_poi_data: 1,
                awaiting_validation: 1,
                ..WalletPpoiWorkflowStatus::default()
            },
        ),
        &[list_key],
    );
    assert_eq!(
        workflow,
        PoiCacheDemand {
            events: true,
            blocked_shields: false,
        }
    );

    let reset = WalletObservation::new(
        WalletViewState::ResetPending {
            intent_id: 1,
            from_block: 2,
            reset_generation: 3,
        },
        WalletReadiness::Syncing,
    );
    assert_eq!(
        poi_cache_demand(&reset, &[list_key]),
        PoiCacheDemand::default()
    );
}

#[test]
fn artifact_success_forces_rpc_probe_and_rpc_success_recovers_health() {
    let list_key = FixedBytes::from([0x91; 32]);
    let mut health = PoiSourceHealth::new(Some(Instant::now()));
    health.consecutive_rpc_failures = 3;
    assert!(health.artifact_eligible());
    assert!(health.attempt_plan(true).use_artifact);

    health.record(&PoiListSourceOutcome {
        list_key,
        rpc: None,
        artifact_succeeded: true,
    });

    let forced_probe = health.attempt_plan(true);
    assert!(!forced_probe.use_artifact);
    assert!(!forced_probe.artifact_after_rpc_failure);

    health.record(&PoiListSourceOutcome {
        list_key,
        rpc: Some(PoiRpcAttemptOutcome::Succeeded {
            backlog_large: false,
        }),
        artifact_succeeded: false,
    });

    assert_eq!(health.consecutive_rpc_failures, 0);
    assert!(health.rpc_stale_at.is_some());
    assert!(!health.force_rpc_probe);
    assert!(!health.attempt_plan(true).use_artifact);
}

#[test]
fn mixed_list_source_health_reaches_artifact_eligibility_independently() {
    let healthy_key = FixedBytes::from([0x92; 32]);
    let failing_key = FixedBytes::from([0x93; 32]);
    let mut health = BTreeMap::from([
        (healthy_key, PoiSourceHealth::new(None)),
        (failing_key, PoiSourceHealth::new(None)),
    ]);

    record_list_source_outcomes(
        &mut health,
        &[
            PoiListSourceOutcome {
                list_key: healthy_key,
                rpc: Some(PoiRpcAttemptOutcome::Succeeded {
                    backlog_large: true,
                }),
                artifact_succeeded: false,
            },
            PoiListSourceOutcome {
                list_key: failing_key,
                rpc: Some(PoiRpcAttemptOutcome::Failed),
                artifact_succeeded: false,
            },
        ],
    );
    assert!(health[&healthy_key].artifact_acceleration_needed);
    assert!(!health[&failing_key].artifact_acceleration_needed);
    assert_eq!(health[&failing_key].consecutive_rpc_failures, 1);

    for _ in 0..2 {
        record_list_source_outcomes(
            &mut health,
            &[
                PoiListSourceOutcome {
                    list_key: healthy_key,
                    rpc: Some(PoiRpcAttemptOutcome::Succeeded {
                        backlog_large: false,
                    }),
                    artifact_succeeded: false,
                },
                PoiListSourceOutcome {
                    list_key: failing_key,
                    rpc: Some(PoiRpcAttemptOutcome::Failed),
                    artifact_succeeded: false,
                },
            ],
        );
    }

    assert_eq!(health[&healthy_key].consecutive_rpc_failures, 0);
    assert!(health[&healthy_key].rpc_stale_at.is_some());
    assert!(!health[&healthy_key].attempt_plan(true).use_artifact);
    assert_eq!(health[&failing_key].consecutive_rpc_failures, 3);
    assert!(health[&failing_key].rpc_stale_at.is_none());
    assert!(health[&failing_key].attempt_plan(true).use_artifact);
}

#[tokio::test]
async fn empty_rpc_source_success_persists_health_without_creating_corpus() {
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
    let mock = spawn_poi_rpc_sequence(vec![serde_json::json!([]), serde_json::json!([])]);
    let result = public_rpc_candidate_cache(
        &PoiRpcClient::new(mock.url.clone()),
        PoiCache::new(identity.clone()),
        PoiCacheSyncScope::FULL,
    )
    .await
    .expect("empty public RPC synchronization succeeds");
    assert!(result.candidate.is_none());
    assert!(!result.outcome.changed);
    let event_request = mock
        .requests
        .recv_timeout(Duration::from_secs(2))
        .expect("empty event request");
    let blocked_request = mock
        .requests
        .recv_timeout(Duration::from_secs(2))
        .expect("empty blocked-shields request");
    assert_eq!(event_request["method"], "ppoi_poi_events");
    assert_eq!(blocked_request["method"], "ppoi_blocked_shields");
    assert!(mock.requests.try_recv().is_err());

    let generation = db
        .poi_artifact_cache_generation()
        .expect("cache generation");
    let local_caches = LocalPoiCaches::new();
    let (_command_tx, command_rx) = tokio::sync::mpsc::channel(1);
    let (job_tx, job_rx) = tokio::sync::mpsc::unbounded_channel();
    let (progress_tx, _) = tokio::sync::watch::channel(BTreeMap::new());
    let coordinator = ChainPoiCacheCoordinator {
        db: Arc::clone(&db),
        http_client: None,
        poi_rpc_url: mock.url.into(),
        artifact_config: artifact_config(),
        cache_generation: generation,
        chain_id: 1,
        local_caches: local_caches.clone(),
        active_list_keys: vec![list_key],
        preloaded_caches: BTreeMap::new(),
        installed_head_anchors: StdMutex::new(BTreeMap::new()),
        command_rx,
        job_tx,
        job_rx,
        progress_tx,
        cancel: tokio_util::sync::CancellationToken::new(),
        runtime: Arc::new(PoiCacheServiceRuntime::new()),
        poi_artifact_persistence: test_persistence(&db),
    };
    finish_chain_poi_cache_attempt(
        &coordinator,
        attempt_id(1),
        generation,
        PreparedPoiCacheBatch {
            candidates: Vec::new(),
            source_outcomes: vec![PoiListSourceOutcome {
                list_key,
                rpc: Some(PoiRpcAttemptOutcome::Succeeded {
                    backlog_large: result.outcome.event_page_budget_exhausted,
                }),
                artifact_succeeded: false,
            }],
            actual_scope: PoiCacheSyncScope::FULL,
            result: Ok(()),
        },
    )
    .await
    .result
    .expect("persist empty RPC source health");

    assert!(local_caches.read().await.is_empty());
    assert!(
        db.get_poi_artifact_cache(
            identity.chain_type,
            identity.chain_id,
            &identity.txid_version,
            &identity.list_key,
        )
        .expect("load absent empty corpus")
        .is_none()
    );
    let health = db
        .get_poi_corpus_rpc_health(
            identity.chain_type,
            identity.chain_id,
            &identity.txid_version,
            &identity.list_key,
        )
        .expect("load empty RPC health")
        .expect("empty RPC health");
    assert_eq!(health.cache_generation, generation);
    assert!(health.last_successful_rpc_sync_at_ms.is_some());

    drop(coordinator);
    drop(db);
    fs::remove_dir_all(root_dir).expect("remove temp db dir");
}

#[tokio::test]
async fn public_rpc_candidate_reuses_validated_roots_but_revalidates_pending_roots() {
    let list_key = default_active_poi_list_key();
    let identity = PoiCacheIdentity::new(EVM_CHAIN_TYPE, 1, DEFAULT_TXID_VERSION, list_key);
    let unchanged = spawn_poi_rpc_sequence(vec![serde_json::json!([])]);
    let unchanged_result = public_rpc_candidate_cache(
        &PoiRpcClient::new(unchanged.url.clone()),
        cache_with_events(
            identity.clone(),
            &[snapshot_event(0, FixedBytes::from([0x55; 32]))],
        ),
        PoiCacheSyncScope::EVENTS,
    )
    .await
    .expect("unchanged validated roots");
    assert!(unchanged_result.candidate.is_none());
    assert_eq!(
        unchanged
            .requests
            .recv_timeout(Duration::from_secs(2))
            .expect("event request")["method"],
        "ppoi_poi_events"
    );
    assert!(unchanged.requests.try_recv().is_err());

    let mut pending =
        cache_with_events(identity, &[snapshot_event(0, FixedBytes::from([0x55; 32]))]);
    pending
        .apply_verified_artifact_events(&[snapshot_event(1, FixedBytes::from([0x66; 32]))])
        .expect("mutate event corpus");
    let retry = spawn_poi_rpc_sequence(vec![serde_json::json!([]), serde_json::json!(true)]);
    public_rpc_candidate_cache(
        &PoiRpcClient::new(retry.url.clone()),
        pending,
        PoiCacheSyncScope::EVENTS,
    )
    .await
    .expect("pending roots revalidated");
    let methods = [
        retry
            .requests
            .recv_timeout(Duration::from_secs(2))
            .expect("pending event request"),
        retry
            .requests
            .recv_timeout(Duration::from_secs(2))
            .expect("root validation request"),
    ];
    assert_eq!(methods[0]["method"], "ppoi_poi_events");
    assert_eq!(methods[1]["method"], "ppoi_validate_poi_merkleroots");
}

#[tokio::test]
async fn blocked_only_candidate_keeps_empty_event_delta_for_persistence() {
    let list_key = default_active_poi_list_key();
    let identity = PoiCacheIdentity::new(EVM_CHAIN_TYPE, 1, DEFAULT_TXID_VERSION, list_key);
    let mock = spawn_poi_rpc_sequence(vec![serde_json::json!([])]);
    let result = public_rpc_candidate_cache(
        &PoiRpcClient::new(mock.url.clone()),
        cache_with_events(identity, &[snapshot_event(0, FixedBytes::from([0x77; 32]))]),
        PoiCacheSyncScope::BLOCKED_SHIELDS,
    )
    .await
    .expect("blocked-only candidate");

    let candidate = result
        .candidate
        .expect("changed blocked snapshot candidate");
    assert!(candidate.delta.is_empty());
    assert_eq!(candidate.blocked_shields, Some(Vec::new()));
    assert_eq!(
        mock.requests
            .recv_timeout(Duration::from_secs(2))
            .expect("blocked-shields request")["method"],
        "ppoi_blocked_shields"
    );
}

#[tokio::test]
async fn durable_base_read_error_skips_network_candidate_work() {
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
    let generation = db
        .poi_artifact_cache_generation()
        .expect("cache generation");
    let persisted =
        persisted_public_rpc_journal_with_delta_count(db.as_ref(), &identity, generation, 0);
    let installed_cache = persisted.cache.clone();
    let installed_head = persisted.journal_head.expect("installed journal head");
    db.put_raw_poi_sidecar_state_for_test("poi_artifact_cache_generation", b"invalid-generation")
        .expect("corrupt generation setting");
    let rpc = spawn_stalled_http_server();
    let (event_tx, _event_rx) = tokio::sync::mpsc::unbounded_channel();

    let batch = produce_chain_poi_cache_candidates(PoiCacheCandidateJob {
        db: Arc::clone(&db),
        http_client: None,
        poi_rpc_url: rpc.url.clone().into(),
        artifact_config: artifact_config(),
        chain_id: 1,
        active_list_keys: vec![list_key],
        baseline: BTreeMap::from([(list_key, installed_cache.clone())]),
        installed_head_anchors: BTreeMap::from([(list_key, installed_head)]),
        preloaded_caches: BTreeMap::new(),
        attempt_id: attempt_id(1),
        generation,
        ready: true,
        source_plans: BTreeMap::from([(list_key, PoiSourceHealth::new(None).attempt_plan(true))]),
        scope: PoiCacheSyncScope::FULL,
        event_tx,
        cancel: CancellationToken::new(),
        poi_artifact_persistence: test_persistence(&db),
    })
    .await;

    assert!(batch.result.is_err());
    assert!(batch.candidates.is_empty());
    assert!(batch.source_outcomes.is_empty());
    assert!(rpc.accepted.try_recv().is_err());
    assert_eq!(installed_cache.progress().next_event_index, 1);

    drop(rpc);
    drop(db);
    fs::remove_dir_all(root_dir).expect("remove temp db dir");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn health_only_restart_probes_rpc_before_artifact() {
    let root_dir = temp_db_root();
    fs::create_dir_all(&root_dir).expect("create temp db root");
    let db = DbStore::open(DbConfig {
        root_dir: root_dir.clone(),
    })
    .expect("open temp db");
    let list_key = default_active_poi_list_key();
    let identity = PoiCacheIdentity::new(EVM_CHAIN_TYPE, 1, DEFAULT_TXID_VERSION, list_key);
    let generation = db
        .poi_artifact_cache_generation()
        .expect("cache generation");
    record_poi_rpc_success(&db, &identity, generation).expect("persist empty RPC health");
    assert!(
        db.get_poi_artifact_cache(
            identity.chain_type,
            identity.chain_id,
            &identity.txid_version,
            &identity.list_key,
        )
        .expect("load absent corpus")
        .is_none()
    );
    drop(db);

    let reopened = Arc::new(
        DbStore::open(DbConfig {
            root_dir: root_dir.clone(),
        })
        .expect("reopen temp db"),
    );
    let health = source_health_for_lists(
        reopened.as_ref(),
        1,
        generation,
        &[list_key],
        &BTreeMap::new(),
    );
    assert!(!health[&list_key].attempt_plan(false).use_artifact);

    let rpc = spawn_poi_rpc_sequence(vec![serde_json::json!([]), serde_json::json!([])]);
    let artifact = spawn_stalled_http_server();
    let service = PoiCacheService::new(
        Arc::clone(&reopened),
        artifact_config_with_url(artifact.url.clone()),
        None,
    )
    .expect("initialize POI cache service")
    .with_poi_rpc_url(rpc.url.clone())
    .with_active_list_keys(vec![list_key]);
    service.start_chain(1).await.expect("start chain");

    let event_request = rpc
        .requests
        .recv_timeout(Duration::from_secs(2))
        .expect("recently healthy public RPC receives the first request");
    assert_eq!(event_request["method"], "ppoi_poi_events");
    assert!(
        artifact.accepted.try_recv().is_err(),
        "artifact source must not be contacted before recently healthy RPC"
    );
    let blocked_request = rpc
        .requests
        .recv_timeout(Duration::from_secs(2))
        .expect("empty blocked-shields request");
    assert_eq!(blocked_request["method"], "ppoi_blocked_shields");

    service.shutdown().await;
    drop(service);
    drop(artifact);
    drop(reopened);
    fs::remove_dir_all(root_dir).expect("remove temp db dir");
}

#[tokio::test]
async fn empty_rpc_success_persists_health_without_rewriting_corpus() {
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
    let cache = cache_with_events(
        identity.clone(),
        &[snapshot_event(0, FixedBytes::from([0x94; 32]))],
    );
    let generation = db
        .poi_artifact_cache_generation()
        .expect("cache generation");
    persist_public_rpc_cache(
        &db,
        &cache,
        generation,
        0,
        ExpectedPoiCorpusBase::NoValidCorpus,
    )
    .expect("persist initial public corpus");
    let mut stale_record = db
        .get_poi_artifact_cache(
            identity.chain_type,
            identity.chain_id,
            &identity.txid_version,
            &identity.list_key,
        )
        .expect("load initial corpus")
        .expect("initial corpus");
    stale_record.legacy_last_successful_rpc_sync_at_ms = Some(1);
    db.put_poi_artifact_cache(&stale_record)
        .expect("store stale embedded health");
    let corpus_before = db
        .get_poi_artifact_cache(
            identity.chain_type,
            identity.chain_id,
            &identity.txid_version,
            &identity.list_key,
        )
        .expect("load corpus before health update")
        .expect("corpus before health update");

    let local_caches = LocalPoiCaches::new_for_test(BTreeMap::from([(list_key, cache)]));
    let (_command_tx, command_rx) = tokio::sync::mpsc::channel(1);
    let (job_tx, job_rx) = tokio::sync::mpsc::unbounded_channel();
    let (progress_tx, _) = tokio::sync::watch::channel(BTreeMap::new());
    let coordinator = ChainPoiCacheCoordinator {
        db: Arc::clone(&db),
        http_client: None,
        poi_rpc_url: Url::parse("http://127.0.0.1:1")
            .expect("POI RPC URL")
            .into(),
        artifact_config: artifact_config(),
        cache_generation: generation,
        chain_id: 1,
        local_caches,
        active_list_keys: vec![list_key],
        preloaded_caches: BTreeMap::new(),
        installed_head_anchors: StdMutex::new(BTreeMap::new()),
        command_rx,
        job_tx,
        job_rx,
        progress_tx,
        cancel: tokio_util::sync::CancellationToken::new(),
        runtime: Arc::new(PoiCacheServiceRuntime::new()),
        poi_artifact_persistence: test_persistence(&db),
    };
    finish_chain_poi_cache_attempt(
        &coordinator,
        attempt_id(1),
        generation,
        PreparedPoiCacheBatch {
            candidates: Vec::new(),
            source_outcomes: vec![PoiListSourceOutcome {
                list_key,
                rpc: Some(PoiRpcAttemptOutcome::Succeeded {
                    backlog_large: false,
                }),
                artifact_succeeded: false,
            }],
            actual_scope: PoiCacheSyncScope::FULL,
            result: Ok(()),
        },
    )
    .await
    .result
    .expect("commit empty RPC health update");
    let corpus_after = db
        .get_poi_artifact_cache(
            identity.chain_type,
            identity.chain_id,
            &identity.txid_version,
            &identity.list_key,
        )
        .expect("load corpus after health update")
        .expect("corpus after health update");
    assert_eq!(corpus_after, corpus_before);

    drop(coordinator);
    drop(db);
    let reopened = DbStore::open(DbConfig {
        root_dir: root_dir.clone(),
    })
    .expect("reopen db");
    let persisted = load_persisted_cache(&reopened, &identity)
        .expect("load corpus after restart")
        .expect("persisted corpus after restart");
    let health = source_health_for_lists(
        &reopened,
        1,
        generation,
        &[list_key],
        &BTreeMap::from([(list_key, persisted)]),
    );
    assert!(health[&list_key].rpc_stale_at.is_some());
    assert!(!health[&list_key].attempt_plan(true).use_artifact);

    drop(reopened);
    fs::remove_dir_all(root_dir).expect("remove temp db dir");
}

struct MockPoiRpc {
    url: Url,
    requests: Receiver<serde_json::Value>,
}

struct StalledHttpServer {
    url: Url,
    accepted: Receiver<()>,
    release: Arc<AtomicBool>,
}

impl Drop for StalledHttpServer {
    fn drop(&mut self) {
        self.release.store(true, Ordering::Release);
    }
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
            Url::parse("http://127.0.0.1:1/manifest")
                .expect("manifest URL")
                .into(),
        ),
        gateway_urls: vec![
            Url::parse("http://127.0.0.1:1")
                .expect("gateway URL")
                .into(),
        ],
        gateway_pool: None,
        max_manifest_age: None,
    }
}

fn artifact_config_with_url(url: Url) -> PoiArtifactSourceConfig {
    PoiArtifactSourceConfig {
        trusted_publisher_pubkey: FixedBytes::from([0x22; 32]),
        manifest_source: PoiArtifactManifestSource::Url(url.clone().into()),
        gateway_urls: vec![url.into()],
        gateway_pool: None,
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

fn demand_utxo(position: u64, kind: UtxoCommitmentKind) -> WalletUtxo {
    WalletUtxo::new(Utxo::new(
        Note {
            token_hash: U256::from(1),
            value: U256::from(10),
            random: [0; 16],
            npk: U256::from(2),
        },
        0,
        position,
        UtxoSource {
            tx_hash: FixedBytes::from([position as u8; 32]),
            block_number: position,
            block_timestamp: position,
        },
        kind,
    ))
}

fn demand_observation(
    utxos: Vec<WalletUtxo>,
    overlay: WalletPendingOverlay,
    workflow: WalletPpoiWorkflowStatus,
) -> WalletObservation {
    WalletObservation::with_ppoi_workflow_status(
        WalletViewState::Current(WalletCurrentSnapshot::new(0, 0, 0, utxos, overlay)),
        WalletReadiness::Ready,
        workflow,
    )
}

fn persisted_public_rpc_journal_with_delta_count(
    db: &DbStore,
    identity: &PoiCacheIdentity,
    generation: u64,
    delta_count: u32,
) -> PersistedPoiArtifactCache {
    let mut cache = PoiCache::new(identity.clone());
    for event_index in 0..=u64::from(delta_count) {
        let mut commitment = [0_u8; 32];
        commitment[24..].copy_from_slice(&event_index.to_be_bytes());
        cache
            .apply_verified_artifact_events(&[snapshot_event(
                event_index,
                FixedBytes::from(commitment),
            )])
            .expect("append test journal event");
        cache.accept_current_roots();
        let expected_base = if event_index == 0 {
            ExpectedPoiCorpusBase::NoValidCorpus
        } else {
            load_persisted_cache(db, identity)
                .expect("load prior test journal state")
                .expect("prior test journal state")
                .expected_base()
        };
        persist_public_rpc_cache(db, &cache, generation, event_index, expected_base)
            .expect("persist test journal revision");
    }
    load_persisted_cache(db, identity)
        .expect("load completed test journal")
        .expect("completed test journal")
}

fn compaction_test_coordinator(
    db: &Arc<DbStore>,
    local_caches: LocalPoiCaches,
    list_key: FixedBytes<32>,
    anchor: PoiCorpusJournalHeadRecord,
) -> (
    ChainPoiCacheCoordinator,
    watch::Receiver<BTreeMap<u64, PoiArtifactCacheProgress>>,
    Arc<tokio::sync::Mutex<()>>,
) {
    let (_command_tx, command_rx) = tokio::sync::mpsc::channel(1);
    let (job_tx, job_rx) = tokio::sync::mpsc::unbounded_channel();
    let (progress_tx, progress_rx) = tokio::sync::watch::channel(BTreeMap::new());
    let commit_fence = Arc::new(tokio::sync::Mutex::new(()));
    (
        ChainPoiCacheCoordinator {
            db: Arc::clone(db),
            http_client: None,
            poi_rpc_url: Url::parse("http://127.0.0.1:1")
                .expect("POI RPC URL")
                .into(),
            artifact_config: artifact_config(),
            cache_generation: db
                .poi_artifact_cache_generation()
                .expect("cache generation"),
            chain_id: 1,
            local_caches,
            active_list_keys: vec![list_key],
            preloaded_caches: BTreeMap::new(),
            installed_head_anchors: StdMutex::new(BTreeMap::from([(list_key, anchor)])),
            command_rx,
            job_tx,
            job_rx,
            progress_tx,
            cancel: CancellationToken::new(),
            runtime: Arc::new(PoiCacheServiceRuntime::new()),
            poi_artifact_persistence: PoiArtifactPersistenceHandle::new(
                Arc::clone(db),
                Arc::clone(&commit_fence),
            ),
        },
        progress_rx,
        commit_fence,
    )
}

fn public_rpc_candidate_for_test(
    list_key: FixedBytes<32>,
    cache: PoiCache,
    range_start_index: u64,
    expected_base: ExpectedPoiCorpusBase,
    starting_record: Option<PoiArtifactCacheRecord>,
    starting_head: Option<PoiCorpusJournalHeadRecord>,
) -> PreparedPoiCacheCandidate {
    let event_end_cursor = cache.progress().next_event_index;
    let mut events = Vec::new();
    let mut leaves = Vec::new();
    for event_index in range_start_index..event_end_cursor {
        let blinded_commitment = cache
            .commitment_at_global_index(event_index)
            .expect("test journal delta commitment");
        events.push(poi::cache::PoiCacheJournalEvent {
            event_index,
            blinded_commitment,
        });
        leaves.push(blinded_commitment);
    }
    let delta = PoiCacheJournalDelta {
        version: poi::cache::POI_CACHE_JOURNAL_DELTA_VERSION,
        identity: cache.identity().clone(),
        event_start_cursor: range_start_index,
        event_end_cursor,
        leaf_start_cursor: range_start_index,
        leaf_end_cursor: cache.progress().next_leaf_index,
        events,
        leaves,
    };
    PreparedPoiCacheCandidate {
        list_key,
        cache: Some(cache),
        persistence: PreparedPoiCachePersistence::PublicRpc {
            prepared: Box::new(PreparedPublicRpcPersistence {
                range_start_index,
                expected_base,
                starting_record,
                starting_head,
                delta,
                blocked_shields: None,
            }),
        },
    }
}

#[tokio::test]
async fn chain_poi_cache_list_progress_reports_each_active_list() {
    let first_key = default_active_poi_list_key();
    let second_key = FixedBytes::from([7_u8; 32]);
    let first_identity = PoiCacheIdentity::new(EVM_CHAIN_TYPE, 1, DEFAULT_TXID_VERSION, first_key);
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

    let list_progress = chain_poi_cache_list_progress(1, &local_caches, &active_list_keys).await;

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
    let cache_generation = db
        .poi_artifact_cache_generation()
        .expect("load cache generation");
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
        cache_generation,
        source: PoiCacheRecordSource::IndexedArtifacts,
        validation: PoiCorpusValidationRecord::PublisherAttested {
            publisher_pubkey: FixedBytes::from([0x22; 32]),
            manifest_sequence: 1,
            manifest_root: current_tip_root,
            artifact_tip_index: current_tip_index,
        },
        legacy_observed_manifest_sequence: 1,
        base_descriptor: test_descriptor_record("base"),
        applied_delta_descriptors: Vec::new(),
        blocked_shields_descriptor: test_descriptor_record("blocked"),
        artifact_tip_index: Some(current_tip_index),
        artifact_tip_root: Some(current_tip_root),
        current_tip_index,
        current_tip_root,
        cache_payload: cache.to_bytes().expect("cache bytes"),
        legacy_last_successful_rpc_sync_at_ms: None,
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
        tokio::time::timeout(Duration::from_secs(15), rx.changed())
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
            let request: serde_json::Value = serde_json::from_slice(body).expect("request JSON");
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

fn spawn_stalled_http_server() -> StalledHttpServer {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind stalled HTTP server");
    listener
        .set_nonblocking(true)
        .expect("set stalled HTTP listener nonblocking");
    let url = Url::parse(&format!(
        "http://{}",
        listener.local_addr().expect("stalled HTTP local addr")
    ))
    .expect("stalled HTTP URL");
    let (accepted_tx, accepted) = mpsc::channel();
    let release = Arc::new(AtomicBool::new(false));
    let thread_release = Arc::clone(&release);
    std::thread::spawn(move || {
        let mut streams = Vec::new();
        while !thread_release.load(Ordering::Acquire) {
            match listener.accept() {
                Ok((stream, _)) => {
                    streams.push(stream);
                    let _ = accepted_tx.send(());
                }
                Err(err) if err.kind() == std::io::ErrorKind::WouldBlock => {
                    std::thread::sleep(Duration::from_millis(5));
                }
                Err(_) => break,
            }
        }
    });
    StalledHttpServer {
        url,
        accepted,
        release,
    }
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
async fn concurrent_start_reuses_local_cache_and_coordinator() {
    let root_dir = temp_db_root();
    fs::create_dir_all(&root_dir).expect("create temp db root");
    let db = Arc::new(
        DbStore::open(DbConfig {
            root_dir: root_dir.clone(),
        })
        .expect("open temp db"),
    );
    let service = Arc::new(
        PoiCacheService::new(db, artifact_config(), None).expect("initialize POI cache generation"),
    );

    let (first, second) = tokio::join!(service.start_chain(1), service.start_chain(1));
    let first = first.expect("first chain start");
    let second = second.expect("concurrent chain start");
    assert!(first.ptr_eq(&second));
    assert!(first.ptr_eq(&service.local_caches));
    assert!(service.coordinator.lock().await.is_some());
    assert_eq!(service.progress_rx().borrow().len(), 1);
    service.shutdown().await;
    fs::remove_dir_all(root_dir).expect("remove temp db dir");
}

#[tokio::test]
async fn started_chain_reuses_local_cache_during_public_cache_reset() {
    let root_dir = temp_db_root();
    fs::create_dir_all(&root_dir).expect("create temp db root");
    let db = Arc::new(
        DbStore::open(DbConfig {
            root_dir: root_dir.clone(),
        })
        .expect("open temp db"),
    );
    let service =
        PoiCacheService::new(db, artifact_config(), None).expect("initialize POI cache service");
    let first = service.start_chain(1).await.expect("start chain");
    let first_command = service
        .coordinator
        .lock()
        .await
        .as_ref()
        .expect("started coordinator")
        .command_tx
        .clone();
    let reset = service.quiesce_for_public_cache_reset().await;

    let reused = tokio::time::timeout(Duration::from_millis(100), service.start_chain(1))
        .await
        .expect("started chain reuse must not wait for public cache reset")
        .expect("reuse started chain");

    assert!(first.ptr_eq(&reused));
    let current_command = service
        .coordinator
        .lock()
        .await
        .as_ref()
        .expect("reused coordinator")
        .command_tx
        .clone();
    assert!(first_command.same_channel(&current_command));

    drop(reset);
    service.shutdown().await;
    drop(service);
    fs::remove_dir_all(root_dir).expect("remove temp db dir");
}

#[tokio::test]
async fn initialization_waiters_release_coordinator_slot_mutex() {
    let root_dir = temp_db_root();
    fs::create_dir_all(&root_dir).expect("create temp db root");
    let db = Arc::new(
        DbStore::open(DbConfig {
            root_dir: root_dir.clone(),
        })
        .expect("open temp db"),
    );
    let service = Arc::new(
        PoiCacheService::new(db, artifact_config(), None).expect("initialize POI cache service"),
    );

    let (command_tx, _command_rx) = tokio::sync::mpsc::channel(1);
    let (initialized_tx, initialized_rx) = tokio::sync::watch::channel(false);
    let (_stopped_tx, stopped_rx) = tokio::sync::watch::channel(false);
    *service.coordinator.lock().await = Some(super::ChainPoiCacheHandle {
        command_tx,
        initialized_rx,
        stopped_rx,
    });
    let caches = tokio::spawn({
        let service = Arc::clone(&service);
        async move { service.local_caches(1).await }
    });
    tokio::time::timeout(Duration::from_secs(1), async {
        while initialized_tx.receiver_count() < 2 {
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("local cache waiter subscribed to initialization");
    let slot = tokio::time::timeout(Duration::from_millis(100), service.coordinator.lock())
        .await
        .expect("local cache waiter releases coordinator mutex");
    drop(slot);
    initialized_tx.send(true).expect("complete initialization");
    assert!(
        caches
            .await
            .expect("local cache task")
            .expect("local cache lookup")
            .is_some()
    );
    service.coordinator.lock().await.take();

    let (command_tx, _command_rx) = tokio::sync::mpsc::channel(1);
    let (initialized_tx, initialized_rx) = tokio::sync::watch::channel(false);
    let (_stopped_tx, stopped_rx) = tokio::sync::watch::channel(false);
    *service.coordinator.lock().await = Some(super::ChainPoiCacheHandle {
        command_tx,
        initialized_rx,
        stopped_rx,
    });
    let start = tokio::spawn({
        let service = Arc::clone(&service);
        async move { service.start_chain(1).await }
    });
    tokio::time::timeout(Duration::from_secs(1), async {
        while initialized_tx.receiver_count() < 2 {
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("chain start waiter subscribed to initialization");
    let slot = tokio::time::timeout(Duration::from_millis(100), service.coordinator.lock())
        .await
        .expect("chain start waiter releases coordinator mutex");
    drop(slot);
    initialized_tx.send(true).expect("complete chain start");
    start
        .await
        .expect("chain start task")
        .expect("shared chain start");
    service.coordinator.lock().await.take();

    service.shutdown().await;
    drop(service);
    fs::remove_dir_all(root_dir).expect("remove temp db dir");
}

#[tokio::test]
async fn poi_cache_service_rejects_mismatched_chain() {
    let root_dir = temp_db_root();
    fs::create_dir_all(&root_dir).expect("create temp db root");
    let db = Arc::new(
        DbStore::open(DbConfig {
            root_dir: root_dir.clone(),
        })
        .expect("open temp db"),
    );
    let service =
        PoiCacheService::new(db, artifact_config(), None).expect("initialize POI cache service");

    assert!(matches!(
        service.start_chain(137).await,
        Err(PoiCacheServiceError::ChainMismatch {
            expected: 1,
            actual: 137,
        })
    ));
    assert!(service.coordinator.lock().await.is_none());

    service.shutdown().await;
    fs::remove_dir_all(root_dir).expect("remove temp db dir");
}

#[tokio::test]
async fn queued_public_cache_resets_quiesce_without_deadlock() {
    let root_dir = temp_db_root();
    fs::create_dir_all(&root_dir).expect("create temp db root");
    let db = Arc::new(
        DbStore::open(DbConfig {
            root_dir: root_dir.clone(),
        })
        .expect("open temp db"),
    );
    let service = Arc::new(
        PoiCacheService::new(db, artifact_config(), None).expect("initialize POI cache service"),
    );
    service.start_chain(1).await.expect("start fixed chain");
    let first_attempt = service
        .progress_tx
        .borrow()
        .get(&1)
        .expect("initial cache attempt")
        .attempt_id;

    let first = service.quiesce_for_public_cache_reset().await;
    let queued_service = Arc::clone(&service);
    let queued_polled = Arc::new(AtomicBool::new(false));
    let queued = tokio::spawn({
        let queued_polled = Arc::clone(&queued_polled);
        async move {
            queued_polled.store(true, Ordering::Release);
            queued_service.quiesce_for_public_cache_reset().await
        }
    });
    tokio::time::timeout(Duration::from_secs(1), async {
        while !queued_polled.load(Ordering::Acquire) {
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("queued reset reaches admission");
    assert!(!queued.is_finished());
    drop(first);

    let second = tokio::time::timeout(Duration::from_secs(1), queued)
        .await
        .expect("queued reset quiesces")
        .expect("queued reset task completes");
    drop(second);
    tokio::time::timeout(Duration::from_secs(1), async {
        loop {
            if service
                .progress_tx
                .borrow()
                .get(&1)
                .is_some_and(|progress| progress.attempt_id != first_attempt)
            {
                break;
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("reset release starts a new attempt");
    service.shutdown().await;
    fs::remove_dir_all(root_dir).expect("remove temp db dir");
}

#[tokio::test]
async fn closed_initialization_removes_dead_chain_handle() {
    let root_dir = temp_db_root();
    fs::create_dir_all(&root_dir).expect("create temp db root");
    let db = Arc::new(
        DbStore::open(DbConfig {
            root_dir: root_dir.clone(),
        })
        .expect("open temp db"),
    );
    let service = PoiCacheService::new(Arc::clone(&db), artifact_config(), None)
        .expect("initialize POI cache service");
    let (command_tx, command_rx) = tokio::sync::mpsc::channel(1);
    drop(command_rx);
    let (initialized_tx, initialized_rx) = tokio::sync::watch::channel(false);
    drop(initialized_tx);
    let (stopped_tx, stopped_rx) = tokio::sync::watch::channel(false);
    drop(stopped_tx);
    *service.coordinator.lock().await = Some(super::ChainPoiCacheHandle {
        command_tx,
        initialized_rx,
        stopped_rx,
    });

    assert!(matches!(
        service.local_caches(1).await,
        Err(PoiCacheServiceError::CoordinatorStopped)
    ));
    assert!(service.coordinator.lock().await.is_none());
    let restarted = service
        .start_chain(1)
        .await
        .expect("restart after dead initialization");
    assert!(restarted.ptr_eq(&service.local_caches));

    service.shutdown().await;
    drop(service);
    drop(db);
    fs::remove_dir_all(root_dir).expect("remove temp db dir");
}

#[tokio::test]
async fn shutdown_fenced_ready_failure_cannot_acknowledge_initialization() {
    let local_caches = LocalPoiCaches::new_for_test(BTreeMap::new());
    let runtime = PoiCacheServiceRuntime::new();
    runtime
        .publication_fence
        .lock()
        .expect("publication fence")
        .shutdown = true;
    let cancel = tokio_util::sync::CancellationToken::new();
    let (progress_tx, progress_rx) = tokio::sync::watch::channel(BTreeMap::new());
    let (initialized_tx, mut initialized_rx) = tokio::sync::watch::channel(false);

    let result = publish_chain_poi_cache_ready_and_acknowledge_initialization(
        &progress_tx,
        1,
        &local_caches,
        &[],
        attempt_id(1),
        0,
        &runtime,
        &cancel,
        initialized_tx,
    )
    .await;

    assert!(matches!(result, Err(PoiCacheServiceError::Shutdown { .. })));
    assert!(!*initialized_rx.borrow());
    assert!(initialized_rx.changed().await.is_err());
    assert!(progress_rx.borrow().is_empty());
}

#[tokio::test]
async fn retry_response_closure_removes_dead_chain_handle() {
    let root_dir = temp_db_root();
    fs::create_dir_all(&root_dir).expect("create temp db root");
    let db = Arc::new(
        DbStore::open(DbConfig {
            root_dir: root_dir.clone(),
        })
        .expect("open temp db"),
    );
    let service = PoiCacheService::new(Arc::clone(&db), artifact_config(), None)
        .expect("initialize POI cache service");
    let (command_tx, mut command_rx) = tokio::sync::mpsc::channel(1);
    let (initialized_tx, initialized_rx) = tokio::sync::watch::channel(true);
    let (stopped_tx, stopped_rx) = tokio::sync::watch::channel(false);
    let coordinator = tokio::spawn(async move {
        let Some(ChainPoiCacheCommand::Retry { scope, admission }) = command_rx.recv().await else {
            panic!("expected retry command");
        };
        assert_eq!(scope, PoiCacheSyncScope::FULL);
        drop(admission);
        drop(initialized_tx);
        drop(stopped_tx);
    });
    *service.coordinator.lock().await = Some(super::ChainPoiCacheHandle {
        command_tx,
        initialized_rx,
        stopped_rx,
    });

    assert!(matches!(
        service.retry_chain(1).await,
        Err(PoiCacheServiceError::CoordinatorStopped)
    ));
    assert!(service.coordinator.lock().await.is_none());
    coordinator.await.expect("coordinator task");

    service.shutdown().await;
    drop(service);
    drop(db);
    fs::remove_dir_all(root_dir).expect("remove temp db dir");
}

#[tokio::test]
async fn retry_scope_wrappers_route_full_and_event_commands() {
    let root_dir = temp_db_root();
    fs::create_dir_all(&root_dir).expect("create temp db root");
    let db = Arc::new(
        DbStore::open(DbConfig {
            root_dir: root_dir.clone(),
        })
        .expect("open temp db"),
    );
    let service = PoiCacheService::new(Arc::clone(&db), artifact_config(), None)
        .expect("initialize POI cache service");
    let (command_tx, mut command_rx) = tokio::sync::mpsc::channel(2);
    let (initialized_tx, initialized_rx) = tokio::sync::watch::channel(true);
    let (stopped_tx, stopped_rx) = tokio::sync::watch::channel(false);
    let coordinator = tokio::spawn(async move {
        for expected_scope in [PoiCacheSyncScope::FULL, PoiCacheSyncScope::EVENTS] {
            let Some(ChainPoiCacheCommand::Retry { scope, admission }) = command_rx.recv().await
            else {
                panic!("expected retry command");
            };
            assert_eq!(scope, expected_scope);
            assert!(
                admission
                    .send(Err(PoiCacheServiceError::Refresh {
                        reason: "test scope routing".to_string(),
                    }))
                    .is_ok()
            );
        }
        drop(initialized_tx);
        drop(stopped_tx);
    });
    *service.coordinator.lock().await = Some(super::ChainPoiCacheHandle {
        command_tx,
        initialized_rx,
        stopped_rx,
    });

    assert!(matches!(
        service.retry_chain(1).await,
        Err(PoiCacheServiceError::Refresh { .. })
    ));
    assert!(matches!(
        service.retry_chain_events(1).await,
        Err(PoiCacheServiceError::Refresh { .. })
    ));
    coordinator.await.expect("coordinator task");

    service.shutdown().await;
    drop(service);
    drop(db);
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

    service.start_chain(1).await.expect("start chain");

    let progress = service
        .progress_rx()
        .borrow()
        .get(&1)
        .cloned()
        .expect("progress");
    assert_eq!(progress.total_lists, 1);
    assert_eq!(progress.current_event_index, Some(0));
    assert_eq!(progress.list_progress.len(), 1);
    assert_eq!(progress.list_progress[0].list_key, list_key);
    assert_eq!(progress.list_progress[0].current_event_index, Some(0));
    assert!(progress.ready_for_wallet_checks);
    service.shutdown().await;
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
        starter.start_chain(1).await.expect("start chain");
    });

    let progress = wait_for_progress(&mut progress_rx, 1, PoiArtifactCacheProgress::is_error).await;

    assert_eq!(progress.phase, PoiArtifactCachePhase::Failed);
    assert!(progress.ready_for_wallet_checks);
    assert_eq!(
        progress.failure_kind(),
        Some(PoiArtifactCacheFailureKind::RefreshDegraded)
    );
    assert_eq!(progress.completed_lists, 1);
    assert_eq!(progress.current_event_index, Some(0));
    assert_eq!(progress.target_event_index, Some(0));
    assert_eq!(progress.list_progress.len(), 1);
    assert_eq!(progress.list_progress[0].list_key, list_key);
    assert_eq!(progress.list_progress[0].current_event_index, Some(0));
    assert!(progress.last_error.is_some());
    start.await.expect("start chain task");
    service.shutdown().await;
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
        starter.start_chain(1).await.expect("start chain");
    });

    let progress = wait_for_progress(&mut progress_rx, 1, PoiArtifactCacheProgress::is_error).await;

    assert_eq!(progress.phase, PoiArtifactCachePhase::Failed);
    assert!(!progress.ready_for_wallet_checks);
    assert_eq!(
        progress.failure_kind(),
        Some(PoiArtifactCacheFailureKind::ServingCorpusUnavailable)
    );
    assert_eq!(progress.completed_lists, 0);
    assert!(progress.last_error.is_some());
    start.await.expect("start chain task");
    service.shutdown().await;
    fs::remove_dir_all(root_dir).expect("remove temp db dir");
}

#[test]
fn v4_warm_refresh_and_cold_startup_keep_readiness_independent_from_phase() {
    let warm_attempt_id = attempt_id(41);
    let warm = new_poi_artifact_cache_progress(
        warm_attempt_id,
        9,
        1,
        PoiArtifactCachePhase::ResolvingManifest,
        1,
        1,
        None,
        Some(7),
        Some(7),
        Vec::new(),
        PoiArtifactCacheGraphProgress::default(),
        true,
        None,
    );
    let cold = new_poi_artifact_cache_progress(
        attempt_id(42),
        10,
        1,
        PoiArtifactCachePhase::DownloadingChunks,
        0,
        1,
        None,
        None,
        Some(7),
        Vec::new(),
        PoiArtifactCacheGraphProgress {
            total_chunks: 2,
            total_authenticated_encoded_bytes: Some(1024),
            replay_start_event_index: Some(0),
            replay_end_event_index: Some(7),
            total_replay_event_count: 8,
            ..PoiArtifactCacheGraphProgress::default()
        },
        false,
        None,
    );

    assert!(warm.is_active());
    assert!(warm.ready_for_wallet_checks);
    assert_eq!(warm.attempt_id, warm_attempt_id);
    assert_eq!(warm.generation, 9);
    assert!(cold.is_active());
    assert!(!cold.ready_for_wallet_checks);
    assert!(!cold.is_ready());
}

#[test]
fn shared_failure_diagnostic_redacts_rpc_message_and_response_data() {
    let error = PoiCacheError::Rpc(PoiRpcError::JsonRpc {
        code: -32_000,
        message: "raw-response-message-sentinel".to_string(),
        data: Some(serde_json::json!({
            "url": "https://user-sentinel:password-sentinel@host.invalid/path?token=sentinel"
        })),
    });

    let diagnostic = poi_cache_error_diagnostic(&error);

    assert_eq!(diagnostic, "POI cache RPC JSON-RPC error -32000");
    for sentinel in [
        "raw-response-message-sentinel",
        "user-sentinel",
        "password-sentinel",
        "token=sentinel",
    ] {
        assert!(!diagnostic.contains(sentinel), "leaked {sentinel}");
    }
}

#[test]
fn persisted_rpc_health_older_than_freshness_window_is_immediately_stale() {
    let root_dir = temp_db_root();
    fs::create_dir_all(&root_dir).expect("create temp db root");
    let db = DbStore::open(DbConfig {
        root_dir: root_dir.clone(),
    })
    .expect("open temp db");
    let list_key = default_active_poi_list_key();
    let identity = PoiCacheIdentity::new(EVM_CHAIN_TYPE, 1, DEFAULT_TXID_VERSION, list_key);
    let cache = cache_with_events(
        identity.clone(),
        &[snapshot_event(0, FixedBytes::from([0x95; 32]))],
    );
    let generation = db
        .poi_artifact_cache_generation()
        .expect("cache generation");
    persist_public_rpc_cache(
        &db,
        &cache,
        generation,
        0,
        ExpectedPoiCorpusBase::NoValidCorpus,
    )
    .expect("persist public corpus");
    db.put_poi_corpus_rpc_health(&local_db::PoiCorpusRpcHealthRecord {
        chain_type: identity.chain_type,
        chain_id: identity.chain_id,
        txid_version: identity.txid_version.clone(),
        list_key,
        cache_generation: generation,
        last_successful_rpc_sync_at_ms: Some(0),
        updated_at: 0,
    })
    .expect("persist stale RPC health");

    let persisted = load_persisted_cache(&db, &identity)
        .expect("load corpus")
        .expect("persisted corpus");
    let health = source_health_for_lists(
        &db,
        1,
        generation,
        &[list_key],
        &BTreeMap::from([(list_key, persisted)]),
    );
    assert!(health[&list_key].attempt_plan(true).use_artifact);

    drop(db);
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
    let artifact_candidate = cache_with_events(identity, &[snapshot_event(0, artifact_commitment)]);
    let mut caches = BTreeMap::from([(list_key, current_cache)]);

    let installed = install_cache_if_not_behind(&mut caches, list_key, artifact_candidate);

    let current = caches.get(&list_key).expect("current cache");
    assert!(!installed);
    assert_eq!(current.progress().next_event_index, 2);
    assert!(current.position(&live_tail_commitment).is_some());
}

#[tokio::test]
async fn blocked_only_staged_install_preserves_events_and_publishes_blocked_revision() {
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
    let event_commitment = FixedBytes::from([0x2a; 32]);
    let current = cache_with_events(identity, &[snapshot_event(0, event_commitment)]);
    let mut replacement = current.clone();
    replacement
        .replace_blocked_shields(&[BlockedShield {
            commitment_hash: alloy::hex::encode_prefixed([0x2b; 32]),
            blinded_commitment: alloy::hex::encode_prefixed([0x2c; 32]),
            block_reason: Some("replacement".to_string()),
            signature: alloy::hex::encode_prefixed([0x2d; 64]),
        }])
        .expect("replace blocked shields");
    let local_caches = LocalPoiCaches::new_for_test(BTreeMap::from([(list_key, current)]));
    let mut revision_rx = local_caches.committed_revision_rx();
    assert_eq!(
        *revision_rx.borrow(),
        PoiCorpusRevision {
            revision: 1,
            blocked_shields_revision: 1,
        }
    );
    let (_command_tx, command_rx) = tokio::sync::mpsc::channel(1);
    let (job_tx, job_rx) = tokio::sync::mpsc::unbounded_channel();
    let (progress_tx, _) = tokio::sync::watch::channel(BTreeMap::new());
    let coordinator = ChainPoiCacheCoordinator {
        db: Arc::clone(&db),
        http_client: None,
        poi_rpc_url: Url::parse("http://127.0.0.1:1")
            .expect("POI RPC URL")
            .into(),
        artifact_config: artifact_config(),
        cache_generation: db
            .poi_artifact_cache_generation()
            .expect("cache generation"),
        chain_id: 1,
        local_caches: local_caches.clone(),
        active_list_keys: vec![list_key],
        preloaded_caches: BTreeMap::new(),
        installed_head_anchors: StdMutex::new(BTreeMap::new()),
        command_rx,
        job_tx,
        job_rx,
        progress_tx,
        cancel: CancellationToken::new(),
        runtime: Arc::new(PoiCacheServiceRuntime::new()),
        poi_artifact_persistence: test_persistence(&db),
    };

    let compactions = apply_staged_poi_cache_batch(
        &coordinator,
        attempt_id(61),
        db.poi_artifact_cache_generation()
            .expect("cache generation"),
        vec![StagedPoiCacheCandidate {
            list_key,
            cache: replacement,
            journal_head: None,
            compaction: None,
        }],
        &Ok(()),
    )
    .await
    .expect("publish blocked-only replacement");
    assert!(compactions.is_empty());

    revision_rx.changed().await.expect("blocked revision");
    assert_eq!(
        *revision_rx.borrow_and_update(),
        PoiCorpusRevision {
            revision: 2,
            blocked_shields_revision: 2,
        }
    );
    let installed = local_caches.read().await[&list_key].clone();
    assert_eq!(installed.progress().next_event_index, 1);
    assert_eq!(
        installed.commitment_at_global_index(0),
        Some(event_commitment)
    );
    assert_eq!(
        installed.status(&FixedBytes::from([0x2c; 32])),
        PoiStatus::ShieldBlocked
    );

    drop(coordinator);
    drop(db);
    fs::remove_dir_all(root_dir).expect("remove temp db dir");
}

#[tokio::test]
async fn artifact_failure_recovers_corpus_through_public_ranges_without_wallet_commitments() {
    let root_dir = temp_db_root();
    fs::create_dir_all(&root_dir).expect("create temp db root");
    let db = Arc::new(
        DbStore::open(DbConfig {
            root_dir: root_dir.clone(),
        })
        .expect("open temp db"),
    );
    let signing_key = SigningKey::from_bytes(&[0x45; 32]);
    let list_key = FixedBytes::from(signing_key.verifying_key().to_bytes());
    let commitment = FixedBytes::from([0x35_u8; 32]);
    let mut signed_poi_event = SignedPoiEvent {
        index: 0,
        blinded_commitment: commitment,
        signature: String::new(),
        event_type: PoiEventType::Transact,
    };
    signed_poi_event.signature = alloy::hex::encode(
        signing_key
            .sign(&canonical_poi_event_message(&signed_poi_event))
            .to_bytes(),
    );
    let event = PoiSyncedListEvent {
        signed_poi_event,
        validated_merkleroot: "0x00".to_string(),
    };
    let mock = spawn_poi_rpc_sequence(vec![
        serde_json::to_value(vec![event]).expect("events JSON"),
        serde_json::to_value(vec![U256::from_be_bytes(commitment.0)]).expect("leaves JSON"),
        serde_json::json!([]),
        serde_json::json!(true),
    ]);
    let service = PoiCacheService::new(Arc::clone(&db), artifact_config(), None)
        .expect("initialize POI cache service")
        .with_poi_rpc_url(mock.url.clone())
        .with_active_list_keys(vec![list_key]);
    let mut progress_rx = service.progress_rx();
    let local_caches = service.start_chain(1).await.expect("start chain");
    wait_for_progress(&mut progress_rx, 1, PoiArtifactCacheProgress::is_ready).await;

    let cache = local_caches
        .read()
        .await
        .get(&list_key)
        .cloned()
        .expect("public range corpus installed");
    assert_eq!(cache.status(&commitment), PoiStatus::Valid);
    assert!(cache.position(&commitment).is_some());
    let persisted = load_persisted_cache(db.as_ref(), cache.identity())
        .expect("load persisted range corpus")
        .expect("persisted range corpus");
    assert_eq!(persisted.record.source, PoiCacheRecordSource::PublicRpc);
    assert!(
        progress_rx
            .borrow()
            .get(&1)
            .is_some_and(PoiArtifactCacheProgress::is_ready)
    );
    let methods = (0..4)
        .map(|_| {
            let request = mock
                .requests
                .recv_timeout(Duration::from_secs(2))
                .expect("public corpus request");
            assert!(!request.to_string().contains("blindedCommitments"));
            request["method"]
                .as_str()
                .expect("request method")
                .to_string()
        })
        .collect::<Vec<_>>();
    assert_eq!(
        methods,
        vec![
            "ppoi_poi_events",
            "ppoi_poi_merkletree_leaves",
            "ppoi_blocked_shields",
            "ppoi_validate_poi_merkleroots",
        ]
    );

    service.shutdown().await;
    drop(service);
    drop(db);
    fs::remove_dir_all(root_dir).expect("remove temp db dir");
}

#[tokio::test]
async fn soft_compaction_updates_only_durable_head_anchor() {
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
    let generation = db
        .poi_artifact_cache_generation()
        .expect("cache generation");
    let persisted = persisted_public_rpc_journal_with_delta_count(
        db.as_ref(),
        &identity,
        generation,
        POI_CORPUS_JOURNAL_SOFT_DELTA_COUNT,
    );
    assert!(persisted.compaction_recommended);
    let old_head = persisted
        .journal_head
        .clone()
        .expect("journal head before soft compaction");
    let expected_base = persisted.expected_base();
    let runtime_before = persisted.cache.clone();
    let runtime_bytes = runtime_before.to_bytes().expect("encode runtime cache");
    let local_caches = LocalPoiCaches::new();
    local_caches.write().await.insert(list_key, runtime_before);
    let revision_rx = local_caches.committed_revision_rx();
    let (coordinator, progress_rx, _commit_fence) =
        compaction_test_coordinator(&db, local_caches.clone(), list_key, old_head.clone());

    assert!(
        run_background_poi_corpus_compaction(
            &coordinator,
            generation,
            PoiCorpusCompactionRequest {
                identity: identity.clone(),
                expected_base,
            },
        )
        .await
    );

    let durable = load_persisted_cache(&db, &identity)
        .expect("load compacted corpus")
        .expect("compacted corpus");
    let compacted_head = durable
        .journal_head
        .clone()
        .expect("compacted journal head");
    assert!(compacted_head.revision > old_head.revision);
    assert_eq!(compacted_head.base_revision, compacted_head.revision);
    assert_eq!(compacted_head.delta_count, 0);
    assert_eq!(
        coordinator
            .installed_head_anchors
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .get(&list_key),
        Some(&compacted_head)
    );
    assert_eq!(
        local_caches
            .read()
            .await
            .get(&list_key)
            .expect("runtime cache after compaction")
            .to_bytes()
            .expect("encode runtime cache after compaction"),
        runtime_bytes
    );
    assert!(!revision_rx.has_changed().expect("revision stream"));
    assert!(!progress_rx.has_changed().expect("progress stream"));

    let mut corrupt_base = db
        .get_poi_artifact_cache(
            identity.chain_type,
            identity.chain_id,
            &identity.txid_version,
            &identity.list_key,
        )
        .expect("load compacted base")
        .expect("compacted base");
    corrupt_base.cache_payload = vec![0xc1];
    db.put_poi_artifact_cache(&corrupt_base)
        .expect("corrupt compacted historical base");
    assert!(load_persisted_cache(&db, &identity).is_err());
    let installed_cache = local_caches
        .read()
        .await
        .get(&list_key)
        .cloned()
        .expect("installed cache for anchored selection");
    let (selected, selected_base) = load_persisted_cache_candidate_for_publisher(
        &db,
        &identity,
        coordinator.artifact_config.trusted_publisher_pubkey,
        Some(installed_cache),
        Some(&compacted_head),
    )
    .expect("select exact compacted installed anchor");
    assert!(selected.is_some());
    assert_eq!(
        selected_base,
        ExpectedPoiCorpusBase::from_journal_head(&compacted_head)
    );

    drop(coordinator);
    drop(db);
    fs::remove_dir_all(root_dir).expect("remove temp db dir");
}

#[tokio::test]
async fn stalled_compaction_lane_does_not_block_quiesce_command() {
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
    let generation = db
        .poi_artifact_cache_generation()
        .expect("cache generation");
    let persisted =
        persisted_public_rpc_journal_with_delta_count(db.as_ref(), &identity, generation, 1);
    let expected_base = persisted.expected_base();
    let anchor = persisted.journal_head.expect("journal head");
    let local_caches = LocalPoiCaches::new();
    local_caches.write().await.insert(list_key, persisted.cache);
    let (coordinator, _progress_rx, commit_fence) =
        compaction_test_coordinator(&db, local_caches, list_key, anchor);
    let commit_guard = commit_fence.lock_owned().await;
    let mut lane = PoiCorpusCompactionLane::default();
    enqueue_poi_corpus_compactions(
        &mut lane,
        vec![PoiCorpusCompactionRequest {
            identity,
            expected_base,
        }],
    );
    start_next_poi_corpus_compaction(&coordinator, &mut lane, generation);
    assert!(lane.active.is_some());

    let (command_tx, mut command_rx) = tokio::sync::mpsc::channel(1);
    let (response, quiesced) = tokio::sync::oneshot::channel();
    command_tx
        .send(ChainPoiCacheCommand::QuiesceForPublicCacheReset {
            lease: CancellationToken::new(),
            response,
        })
        .await
        .expect("queue quiesce command");
    let command = tokio::time::timeout(Duration::from_millis(100), async {
        tokio::select! {
            biased;
            command = command_rx.recv() => command,
            _ = wait_for_active_poi_corpus_compaction(&mut lane) => {
                panic!("held commit fence unexpectedly completed compaction")
            }
        }
    })
    .await
    .expect("quiesce remains responsive during compaction")
    .expect("queued quiesce command");
    let ChainPoiCacheCommand::QuiesceForPublicCacheReset { response, .. } = command else {
        panic!("unexpected retry command");
    };
    cancel_poi_corpus_compaction_lane(&mut lane);
    response.send(()).expect("acknowledge quiescence");
    quiesced.await.expect("receive quiescence acknowledgement");
    assert!(lane.active.is_none());
    assert!(lane.pending.is_empty());

    drop(commit_guard);
    coordinator.cancel.cancel();
    drop(coordinator);
    drop(db);
    fs::remove_dir_all(root_dir).expect("remove temp db dir");
}

#[tokio::test]
async fn background_compaction_stale_cancel_and_generation_mismatch_preserve_anchor() {
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
    let generation = db
        .poi_artifact_cache_generation()
        .expect("cache generation");
    let persisted =
        persisted_public_rpc_journal_with_delta_count(db.as_ref(), &identity, generation, 1);
    let original_head = persisted
        .journal_head
        .clone()
        .expect("journal head before rejected compactions");
    let expected_base = persisted.expected_base();
    let local_caches = LocalPoiCaches::new();
    local_caches.write().await.insert(list_key, persisted.cache);
    let revision_rx = local_caches.committed_revision_rx();
    let (coordinator, progress_rx, _commit_fence) =
        compaction_test_coordinator(&db, local_caches, list_key, original_head.clone());

    assert!(
        run_background_poi_corpus_compaction(
            &coordinator,
            generation,
            PoiCorpusCompactionRequest {
                identity: identity.clone(),
                expected_base: ExpectedPoiCorpusBase::NoValidCorpus,
            },
        )
        .await
    );
    assert!(
        run_background_poi_corpus_compaction(
            &coordinator,
            generation.saturating_add(1),
            PoiCorpusCompactionRequest {
                identity: identity.clone(),
                expected_base,
            },
        )
        .await
    );
    coordinator.cancel.cancel();
    assert!(
        !run_background_poi_corpus_compaction(
            &coordinator,
            generation,
            PoiCorpusCompactionRequest {
                identity: identity.clone(),
                expected_base,
            },
        )
        .await
    );

    assert_eq!(
        coordinator
            .installed_head_anchors
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .get(&list_key),
        Some(&original_head)
    );
    assert_eq!(
        load_persisted_cache(&db, &identity)
            .expect("load unchanged durable corpus")
            .expect("unchanged durable corpus")
            .journal_head
            .as_ref(),
        Some(&original_head)
    );
    assert!(!revision_rx.has_changed().expect("revision stream"));
    assert!(!progress_rx.has_changed().expect("progress stream"));

    drop(coordinator);
    drop(db);
    fs::remove_dir_all(root_dir).expect("remove temp db dir");
}

#[tokio::test]
async fn reset_before_durable_stage_rejects_old_generation_candidate() {
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
    let candidate_cache = cache_with_events(
        identity.clone(),
        &[snapshot_event(0, FixedBytes::from([0x73; 32]))],
    );
    let generation = db
        .poi_artifact_cache_generation()
        .expect("cache generation");
    let local_caches = LocalPoiCaches::new();
    let revision_rx = local_caches.committed_revision_rx();
    let (_command_tx, command_rx) = tokio::sync::mpsc::channel(1);
    let (job_tx, job_rx) = tokio::sync::mpsc::unbounded_channel();
    let (progress_tx, _) = tokio::sync::watch::channel(BTreeMap::new());
    let coordinator = ChainPoiCacheCoordinator {
        db: Arc::clone(&db),
        http_client: None,
        poi_rpc_url: Url::parse("http://127.0.0.1:1")
            .expect("POI RPC URL")
            .into(),
        artifact_config: artifact_config(),
        cache_generation: generation,
        chain_id: 1,
        local_caches: local_caches.clone(),
        active_list_keys: vec![list_key],
        preloaded_caches: BTreeMap::new(),
        installed_head_anchors: StdMutex::new(BTreeMap::new()),
        command_rx,
        job_tx,
        job_rx,
        progress_tx,
        cancel: tokio_util::sync::CancellationToken::new(),
        runtime: Arc::new(PoiCacheServiceRuntime::new()),
        poi_artifact_persistence: test_persistence(&db),
    };
    let reset = clear_poi_artifact_cache_for_reset(&db).expect("reset before durable stage");
    assert!(reset.generation > generation);
    let result = stage_poi_cache_candidate(
        &coordinator,
        attempt_id(9),
        generation,
        public_rpc_candidate_for_test(
            list_key,
            candidate_cache,
            0,
            ExpectedPoiCorpusBase::NoValidCorpus,
            None,
            None,
        ),
    )
    .await;

    assert!(matches!(result, Err(PoiCacheServiceError::Refresh { .. })));
    assert!(local_caches.read().await.is_empty());
    assert!(!revision_rx.has_changed().expect("revision stream"));
    assert!(coordinator.progress_tx.borrow().is_empty());
    assert!(
        db.get_poi_artifact_cache(
            identity.chain_type,
            identity.chain_id,
            &identity.txid_version,
            &identity.list_key,
        )
        .expect("read reset corpus")
        .is_none()
    );

    drop(coordinator);
    drop(db);
    fs::remove_dir_all(root_dir).expect("remove temp db dir");
}

#[tokio::test]
async fn final_public_rpc_candidate_cancelled_at_commit_fence_returns_shutdown() {
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
    let generation = db
        .poi_artifact_cache_generation()
        .expect("cache generation");
    let local_caches = LocalPoiCaches::new();
    let revision_rx = local_caches.committed_revision_rx();
    let attempt_id = attempt_id(13);
    let initial_progress = new_poi_artifact_cache_progress(
        attempt_id,
        generation,
        1,
        PoiArtifactCachePhase::Validating,
        0,
        1,
        Some(list_key),
        None,
        Some(0),
        Vec::new(),
        PoiArtifactCacheGraphProgress::default(),
        false,
        None,
    );
    let (_command_tx, command_rx) = tokio::sync::mpsc::channel(1);
    let (job_tx, job_rx) = tokio::sync::mpsc::unbounded_channel();
    let (progress_tx, progress_rx) =
        tokio::sync::watch::channel(BTreeMap::from([(1, initial_progress)]));
    let commit_fence = Arc::new(tokio::sync::Mutex::new(()));
    let commit_guard = Arc::clone(&commit_fence).lock_owned().await;
    let coordinator = ChainPoiCacheCoordinator {
        db: Arc::clone(&db),
        http_client: None,
        poi_rpc_url: Url::parse("http://127.0.0.1:1")
            .expect("POI RPC URL")
            .into(),
        artifact_config: artifact_config(),
        cache_generation: generation,
        chain_id: 1,
        local_caches: local_caches.clone(),
        active_list_keys: vec![list_key],
        preloaded_caches: BTreeMap::new(),
        installed_head_anchors: StdMutex::new(BTreeMap::new()),
        command_rx,
        job_tx,
        job_rx,
        progress_tx,
        cancel: CancellationToken::new(),
        runtime: Arc::new(PoiCacheServiceRuntime::new()),
        poi_artifact_persistence: PoiArtifactPersistenceHandle::new(Arc::clone(&db), commit_fence),
    };
    let mut finish = Box::pin(finish_chain_poi_cache_attempt(
        &coordinator,
        attempt_id,
        generation,
        PreparedPoiCacheBatch {
            candidates: vec![public_rpc_candidate_for_test(
                list_key,
                cache_with_events(
                    identity.clone(),
                    &[snapshot_event(0, FixedBytes::from([0x77; 32]))],
                ),
                0,
                ExpectedPoiCorpusBase::NoValidCorpus,
                None,
                None,
            )],
            source_outcomes: Vec::new(),
            actual_scope: PoiCacheSyncScope::FULL,
            result: Ok(()),
        },
    ));
    assert!(
        futures::poll!(&mut finish).is_pending(),
        "public RPC candidate must wait for the held commit fence"
    );
    assert_eq!(
        progress_rx.borrow().get(&1).map(|progress| progress.phase),
        Some(PoiArtifactCachePhase::Persisting)
    );

    coordinator.cancel.cancel();
    let finished = tokio::time::timeout(Duration::from_secs(2), finish.as_mut())
        .await
        .expect("cancelled final candidate returned promptly");

    assert!(matches!(
        finished.result,
        Err(PoiCacheServiceError::Shutdown { attempt_id: id }) if id == attempt_id
    ));
    assert!(local_caches.read().await.is_empty());
    assert!(!revision_rx.has_changed().expect("revision stream"));
    assert_eq!(
        progress_rx.borrow().get(&1).map(|progress| progress.phase),
        Some(PoiArtifactCachePhase::Persisting)
    );
    assert!(
        db.get_poi_artifact_cache(
            identity.chain_type,
            identity.chain_id,
            &identity.txid_version,
            &identity.list_key,
        )
        .expect("read corpus after pre-admission cancellation")
        .is_none()
    );

    drop(finish);
    drop(commit_guard);
    drop(coordinator);
    drop(db);
    fs::remove_dir_all(root_dir).expect("remove temp db dir");
}

#[tokio::test]
async fn partial_batch_install_publishes_committed_revision() {
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
    let generation = db
        .poi_artifact_cache_generation()
        .expect("cache generation");
    let local_caches = LocalPoiCaches::new();
    let mut revision_rx = local_caches.committed_revision_rx();
    let (_command_tx, command_rx) = tokio::sync::mpsc::channel(1);
    let (job_tx, job_rx) = tokio::sync::mpsc::unbounded_channel();
    let (progress_tx, _) = tokio::sync::watch::channel(BTreeMap::new());
    let coordinator = ChainPoiCacheCoordinator {
        db: Arc::clone(&db),
        http_client: None,
        poi_rpc_url: Url::parse("http://127.0.0.1:1")
            .expect("POI RPC URL")
            .into(),
        artifact_config: artifact_config(),
        cache_generation: generation,
        chain_id: 1,
        local_caches: local_caches.clone(),
        active_list_keys: vec![list_key, FixedBytes::from([0x91; 32])],
        preloaded_caches: BTreeMap::new(),
        installed_head_anchors: StdMutex::new(BTreeMap::new()),
        command_rx,
        job_tx,
        job_rx,
        progress_tx,
        cancel: tokio_util::sync::CancellationToken::new(),
        runtime: Arc::new(PoiCacheServiceRuntime::new()),
        poi_artifact_persistence: test_persistence(&db),
    };

    let result = finish_chain_poi_cache_attempt(
        &coordinator,
        attempt_id(1),
        generation,
        PreparedPoiCacheBatch {
            candidates: vec![public_rpc_candidate_for_test(
                list_key,
                cache_with_events(
                    identity.clone(),
                    &[snapshot_event(0, FixedBytes::from([0x92; 32]))],
                ),
                0,
                ExpectedPoiCorpusBase::NoValidCorpus,
                None,
                None,
            )],
            source_outcomes: Vec::new(),
            actual_scope: PoiCacheSyncScope::FULL,
            result: Err("second list failed".to_string()),
        },
    )
    .await;

    assert!(matches!(
        result.result,
        Err(PoiCacheServiceError::Refresh { .. })
    ));
    revision_rx
        .changed()
        .await
        .expect("partial batch committed revision");
    assert_eq!(
        *revision_rx.borrow_and_update(),
        PoiCorpusRevision {
            revision: 1,
            blocked_shields_revision: 1,
        }
    );
    assert!(local_caches.read().await.contains_key(&list_key));
    assert!(
        db.get_poi_artifact_cache(
            identity.chain_type,
            identity.chain_id,
            &identity.txid_version,
            &identity.list_key,
        )
        .expect("read partial batch corpus")
        .is_some()
    );

    drop(coordinator);
    drop(db);
    fs::remove_dir_all(root_dir).expect("remove temp db dir");
}

#[tokio::test]
async fn cancelled_apply_after_durable_stage_keeps_corpus_without_runtime_publication() {
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
    let candidate_cache = cache_with_events(
        identity.clone(),
        &[snapshot_event(0, FixedBytes::from([0x74; 32]))],
    );
    let second_list_key = FixedBytes::from([0x75; 32]);
    let second_identity =
        PoiCacheIdentity::new(EVM_CHAIN_TYPE, 1, DEFAULT_TXID_VERSION, second_list_key);
    let generation = db
        .poi_artifact_cache_generation()
        .expect("cache generation");
    let local_caches = LocalPoiCaches::new();
    let revision_rx = local_caches.committed_revision_rx();
    let (_command_tx, command_rx) = tokio::sync::mpsc::channel(1);
    let (job_tx, job_rx) = tokio::sync::mpsc::unbounded_channel();
    let (progress_tx, progress_rx) = tokio::sync::watch::channel(BTreeMap::new());
    let coordinator = ChainPoiCacheCoordinator {
        db: Arc::clone(&db),
        http_client: None,
        poi_rpc_url: Url::parse("http://127.0.0.1:1")
            .expect("POI RPC URL")
            .into(),
        artifact_config: artifact_config(),
        cache_generation: generation,
        chain_id: 1,
        local_caches: local_caches.clone(),
        active_list_keys: vec![list_key, second_list_key],
        preloaded_caches: BTreeMap::new(),
        installed_head_anchors: StdMutex::new(BTreeMap::new()),
        command_rx,
        job_tx,
        job_rx,
        progress_tx,
        cancel: tokio_util::sync::CancellationToken::new(),
        runtime: Arc::new(PoiCacheServiceRuntime::new()),
        poi_artifact_persistence: test_persistence(&db),
    };
    let candidates = vec![
        public_rpc_candidate_for_test(
            list_key,
            candidate_cache,
            0,
            ExpectedPoiCorpusBase::NoValidCorpus,
            None,
            None,
        ),
        public_rpc_candidate_for_test(
            second_list_key,
            cache_with_events(
                second_identity.clone(),
                &[snapshot_event(0, FixedBytes::from([0x76; 32]))],
            ),
            0,
            ExpectedPoiCorpusBase::NoValidCorpus,
            None,
            None,
        ),
    ];
    assert!(!coordinator.cancel.is_cancelled());
    let mut staged = Vec::new();
    for candidate in candidates {
        if let Some(candidate) =
            stage_poi_cache_candidate(&coordinator, attempt_id(12), generation, candidate)
                .await
                .expect("stage durable POI cache candidate")
        {
            staged.push(candidate);
        }
    }
    assert_eq!(staged.len(), 2);
    assert!(
        db.get_poi_artifact_cache(
            identity.chain_type,
            identity.chain_id,
            &identity.txid_version,
            &identity.list_key,
        )
        .expect("read first corpus after durable stage")
        .is_some()
    );
    assert!(
        db.get_poi_artifact_cache(
            second_identity.chain_type,
            second_identity.chain_id,
            &second_identity.txid_version,
            &second_identity.list_key,
        )
        .expect("read second corpus after durable stage")
        .is_some()
    );

    coordinator.cancel.cancel();
    let result =
        apply_staged_poi_cache_batch(&coordinator, attempt_id(12), generation, staged, &Ok(()))
            .await;

    assert!(matches!(
        result,
        Err(PoiCacheServiceError::Shutdown { attempt_id: id }) if id == attempt_id(12)
    ));
    assert!(local_caches.read().await.is_empty());
    assert!(!revision_rx.has_changed().expect("revision stream"));
    assert!(progress_rx.borrow().is_empty());
    assert!(
        db.get_poi_artifact_cache(
            identity.chain_type,
            identity.chain_id,
            &identity.txid_version,
            &identity.list_key,
        )
        .expect("read first corpus after shutdown")
        .is_some()
    );
    assert!(
        db.get_poi_artifact_cache(
            second_identity.chain_type,
            second_identity.chain_id,
            &second_identity.txid_version,
            &second_identity.list_key,
        )
        .expect("read second corpus after shutdown")
        .is_some()
    );

    drop(coordinator);
    drop(db);
    fs::remove_dir_all(root_dir).expect("remove temp db dir");
}

#[test]
fn cancelling_active_attempt_drops_candidate_future_before_returning() {
    struct PendingCandidate {
        dropped: Arc<AtomicBool>,
    }

    impl std::future::Future for PendingCandidate {
        type Output = PreparedPoiCacheBatch;

        fn poll(
            self: std::pin::Pin<&mut Self>,
            _context: &mut std::task::Context<'_>,
        ) -> std::task::Poll<Self::Output> {
            std::task::Poll::Pending
        }
    }

    impl Drop for PendingCandidate {
        fn drop(&mut self) {
            self.dropped.store(true, Ordering::Release);
        }
    }

    let dropped = Arc::new(AtomicBool::new(false));
    let mut active = Some(ActivePoiCacheAttempt {
        id: attempt_id(44),
        generation: 0,
        scope: PoiCacheSyncScope::FULL,
        cancel: CancellationToken::new(),
        job: Box::pin(PendingCandidate {
            dropped: Arc::clone(&dropped),
        }),
        retry_completion: None,
    });

    cancel_active_attempt(&mut active, |attempt_id| PoiCacheServiceError::Shutdown {
        attempt_id,
    });

    assert!(dropped.load(Ordering::Acquire));
    assert!(active.is_none());
}

#[tokio::test]
async fn stale_attempt_progress_cannot_overwrite_replacement() {
    let root_dir = temp_db_root();
    fs::create_dir_all(&root_dir).expect("create temp db root");
    let db = Arc::new(
        DbStore::open(DbConfig {
            root_dir: root_dir.clone(),
        })
        .expect("open temp db"),
    );
    let local_caches = LocalPoiCaches::new();
    let (_command_tx, command_rx) = tokio::sync::mpsc::channel(1);
    let (job_tx, job_rx) = tokio::sync::mpsc::unbounded_channel();
    let replacement_id = attempt_id(2);
    let replacement_progress = new_poi_artifact_cache_progress(
        replacement_id,
        0,
        1,
        PoiArtifactCachePhase::LiveTailing,
        0,
        1,
        None,
        None,
        None,
        Vec::new(),
        PoiArtifactCacheGraphProgress::default(),
        false,
        None,
    );
    let (progress_tx, progress_rx) =
        tokio::sync::watch::channel(BTreeMap::from([(1, replacement_progress)]));
    let coordinator = ChainPoiCacheCoordinator {
        db: Arc::clone(&db),
        http_client: None,
        poi_rpc_url: Url::parse("http://127.0.0.1:1")
            .expect("POI RPC URL")
            .into(),
        artifact_config: artifact_config(),
        cache_generation: 0,
        chain_id: 1,
        local_caches,
        active_list_keys: vec![default_active_poi_list_key()],
        preloaded_caches: BTreeMap::new(),
        installed_head_anchors: StdMutex::new(BTreeMap::new()),
        command_rx,
        job_tx,
        job_rx,
        progress_tx,
        cancel: tokio_util::sync::CancellationToken::new(),
        runtime: Arc::new(PoiCacheServiceRuntime::new()),
        poi_artifact_persistence: test_persistence(&db),
    };
    let active = ActivePoiCacheAttempt {
        id: replacement_id,
        generation: 0,
        scope: PoiCacheSyncScope::FULL,
        cancel: CancellationToken::new(),
        job: Box::pin(std::future::pending()),
        retry_completion: None,
    };
    publish_active_attempt_progress(
        &coordinator,
        Some(&active),
        super::ChainPoiCacheJobEvent {
            progress: new_poi_artifact_cache_progress(
                attempt_id(1),
                0,
                1,
                PoiArtifactCachePhase::Failed,
                0,
                1,
                None,
                None,
                None,
                Vec::new(),
                PoiArtifactCacheGraphProgress::default(),
                false,
                Some("stale".to_string()),
            ),
        },
    );

    assert_eq!(progress_rx.borrow()[&1].attempt_id, replacement_id);
    assert_eq!(progress_rx.borrow()[&1].generation, 0);
    assert_eq!(
        progress_rx.borrow()[&1].phase,
        PoiArtifactCachePhase::LiveTailing
    );
    drop(active);
    drop(coordinator);
    drop(db);
    fs::remove_dir_all(root_dir).expect("remove temp db dir");
}

#[tokio::test]
async fn stale_completion_drops_candidate_before_retry_response() {
    struct ReadyCandidate {
        dropped: Arc<AtomicBool>,
    }

    impl std::future::Future for ReadyCandidate {
        type Output = PreparedPoiCacheBatch;

        fn poll(
            self: std::pin::Pin<&mut Self>,
            _context: &mut std::task::Context<'_>,
        ) -> std::task::Poll<Self::Output> {
            std::task::Poll::Ready(PreparedPoiCacheBatch {
                candidates: Vec::new(),
                source_outcomes: Vec::new(),
                actual_scope: PoiCacheSyncScope::FULL,
                result: Ok(()),
            })
        }
    }

    impl Drop for ReadyCandidate {
        fn drop(&mut self) {
            self.dropped.store(true, Ordering::Release);
        }
    }

    let dropped = Arc::new(AtomicBool::new(false));
    let (response, result) = tokio::sync::oneshot::channel();
    let response = drop_completed_attempt(ActivePoiCacheAttempt {
        id: attempt_id(45),
        generation: 0,
        scope: PoiCacheSyncScope::FULL,
        cancel: CancellationToken::new(),
        job: Box::pin(ReadyCandidate {
            dropped: Arc::clone(&dropped),
        }),
        retry_completion: Some(response),
    })
    .expect("retry response");

    assert!(dropped.load(Ordering::Acquire));
    let _ = response.send(Err(PoiCacheServiceError::StaleAttempt {
        attempt_id: attempt_id(45),
    }));
    assert!(matches!(
        result.await.expect("stale response"),
        Err(PoiCacheServiceError::StaleAttempt { attempt_id: id }) if id == attempt_id(45)
    ));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn stalled_attempt_is_cancelled_on_shutdown() {
    let root_dir = temp_db_root();
    fs::create_dir_all(&root_dir).expect("create temp db root");
    let db = Arc::new(
        DbStore::open(DbConfig {
            root_dir: root_dir.clone(),
        })
        .expect("open temp db"),
    );
    let stalled = spawn_stalled_http_server();
    let service = Arc::new(
        PoiCacheService::new(
            Arc::clone(&db),
            artifact_config_with_url(stalled.url.clone()),
            None,
        )
        .expect("initialize POI cache service")
        .with_poi_rpc_url(stalled.url.clone()),
    );
    service.start_chain(1).await.expect("start chain");
    stalled
        .accepted
        .recv_timeout(Duration::from_secs(2))
        .expect("background attempt reached network");
    let retry = service.retry_chain(1).await.expect("admit retry");
    let retry = tokio::spawn(retry.wait());
    stalled
        .accepted
        .recv_timeout(Duration::from_secs(2))
        .expect("retry attempt reached network");

    service.shutdown().await;
    let retry_result = tokio::time::timeout(Duration::from_secs(1), retry)
        .await
        .expect("shutdown cancelled retry promptly")
        .expect("retry task");
    assert!(matches!(
        retry_result,
        Err(PoiCacheServiceError::Shutdown { .. })
    ));

    drop(service);
    drop(stalled);
    drop(db);
    fs::remove_dir_all(root_dir).expect("remove temp db dir");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn admitted_retries_have_distinct_correlated_attempt_ids() {
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
    let mut initialized =
        cache_with_events(identity, &[snapshot_event(0, FixedBytes::from([0x45; 32]))]);
    initialized
        .apply_blocked_shields(&[])
        .expect("mark blocked snapshot initialized");
    persist_cache(&db, &initialized);
    let stalled = spawn_stalled_http_server();
    let service = Arc::new(
        PoiCacheService::new(
            Arc::clone(&db),
            artifact_config_with_url(stalled.url.clone()),
            None,
        )
        .expect("initialize POI cache service")
        .with_poi_rpc_url(stalled.url.clone()),
    );
    service.start_chain(1).await.expect("start chain");
    stalled
        .accepted
        .recv_timeout(Duration::from_secs(10))
        .expect("startup attempt reached network");

    let first = service.retry_chain(1).await.expect("admit first retry");
    let first_id = first.attempt_id();
    assert_eq!(service.progress_rx().borrow()[&1].attempt_id, first_id);
    let first_wait = tokio::spawn(first.wait());
    stalled
        .accepted
        .recv_timeout(Duration::from_secs(10))
        .expect("first retry reached network");

    let second = service
        .retry_chain_events(1)
        .await
        .expect("admit event-only retry");
    let second_id = second.attempt_id();
    assert!(second_id > first_id);
    assert_eq!(service.progress_rx().borrow()[&1].attempt_id, second_id);
    assert!(matches!(
        first_wait.await.expect("first retry wait"),
        Err(PoiCacheServiceError::AttemptSuperseded { attempt_id })
            if attempt_id == first_id
    ));

    service.shutdown().await;
    assert!(matches!(
        second.wait().await,
        Err(PoiCacheServiceError::Shutdown { attempt_id }) if attempt_id == second_id
    ));
    drop(service);
    drop(stalled);
    drop(db);
    fs::remove_dir_all(root_dir).expect("remove temp db dir");
}

#[tokio::test]
async fn admitted_retry_id_matches_terminal_progress() {
    let root_dir = temp_db_root();
    fs::create_dir_all(&root_dir).expect("create temp db root");
    let db = Arc::new(
        DbStore::open(DbConfig {
            root_dir: root_dir.clone(),
        })
        .expect("open temp db"),
    );
    let service = PoiCacheService::new(Arc::clone(&db), artifact_config(), None)
        .expect("initialize POI cache service")
        .with_poi_rpc_url(Url::parse("http://127.0.0.1:1").expect("POI RPC URL"));
    service.start_chain(1).await.expect("start chain");
    let mut progress_rx = service.progress_rx();

    let retry = service.retry_chain(1).await.expect("admit retry");
    let retry_id = retry.attempt_id();
    assert_eq!(progress_rx.borrow()[&1].attempt_id, retry_id);
    assert!(matches!(
        retry.wait().await,
        Err(PoiCacheServiceError::Refresh { .. })
    ));
    let terminal = wait_for_progress(&mut progress_rx, 1, |progress| {
        progress.attempt_id == retry_id && progress.is_error()
    })
    .await;
    assert_eq!(terminal.attempt_id, retry_id);

    service.shutdown().await;
    drop(service);
    drop(db);
    fs::remove_dir_all(root_dir).expect("remove temp db dir");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn coordinator_replacement_does_not_reuse_service_attempt_ids() {
    let root_dir = temp_db_root();
    fs::create_dir_all(&root_dir).expect("create temp db root");
    let db = Arc::new(
        DbStore::open(DbConfig {
            root_dir: root_dir.clone(),
        })
        .expect("open temp db"),
    );
    let service = PoiCacheService::new(Arc::clone(&db), artifact_config(), None)
        .expect("initialize POI cache service")
        .with_poi_rpc_url(Url::parse("http://127.0.0.1:1").expect("POI RPC URL"));
    service
        .start_chain(1)
        .await
        .expect("start first coordinator");
    let first_id = service.progress_rx().borrow()[&1].attempt_id;
    let mut stopped = service
        .coordinator
        .lock()
        .await
        .take()
        .expect("first coordinator")
        .stopped_rx;
    while !*stopped.borrow() {
        stopped.changed().await.expect("first coordinator stops");
    }

    service
        .start_chain(1)
        .await
        .expect("start replacement coordinator");
    let second_id = service.progress_rx().borrow()[&1].attempt_id;
    assert!(second_id > first_id);

    service.shutdown().await;
    drop(service);
    drop(db);
    fs::remove_dir_all(root_dir).expect("remove temp db dir");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn ready_progress_is_preserved_until_retry_attempt_starts() {
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
    persist_cache(
        &db,
        &cache_with_events(identity, &[snapshot_event(0, FixedBytes::from([0x45; 32]))]),
    );
    let stalled = spawn_stalled_http_server();
    let service = Arc::new(
        PoiCacheService::new(
            Arc::clone(&db),
            artifact_config_with_url(stalled.url.clone()),
            None,
        )
        .expect("initialize POI cache service")
        .with_poi_rpc_url(stalled.url.clone()),
    );
    let local_caches = service.start_chain(1).await.expect("start chain");
    stalled
        .accepted
        .recv_timeout(Duration::from_secs(2))
        .expect("background public RPC attempt reached network");
    let cache_guard = local_caches.write().await;
    let retry_service = Arc::clone(&service);
    let retry = tokio::spawn(async move { retry_service.retry_chain(1).await });
    tokio::time::sleep(Duration::from_millis(50)).await;

    let progress = service
        .progress_rx()
        .borrow()
        .get(&1)
        .cloned()
        .expect("chain progress");
    assert!(
        progress.ready_for_wallet_checks,
        "a queued retry must not clear readiness while the old corpus remains usable"
    );

    drop(cache_guard);
    service.shutdown().await;
    let _ = tokio::time::timeout(Duration::from_secs(1), retry)
        .await
        .expect("retry released after shutdown");
    drop(service);
    drop(stalled);
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
