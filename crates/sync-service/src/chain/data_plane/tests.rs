use super::poi_persistence::commit_public_rpc_after_admission;
use super::scan_state::PublicScanCoverageRecord;
use super::wallet_scan_artifacts::{
    wallet_scan_artifact_chunk_blob_id, wallet_scan_artifact_transient_slot_id,
};
use super::*;

use std::fs;
use std::io::ErrorKind;
use std::net::TcpListener;
use std::path::PathBuf;
use std::sync::atomic::AtomicBool;
use std::sync::mpsc as std_mpsc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use crate::indexed_artifacts::{
    ChainScope, ChainType, CompressionAlgorithm, DatasetDescriptorMetadata,
    INDEXED_ARTIFACT_CHUNK_FORMAT_VERSION, IndexedArtifactDescriptor, IndexedArtifactRange,
    IndexedArtifactRangeKind, IndexedDatasetKind, VerifiedIndexedArtifactChunk,
};
use crate::poi_artifacts::{
    ExpectedPoiCorpusBase, PersistedPoiArtifactCache, PoiArtifactError, PoiCorpusStore,
    PublicRpcPersistResult,
};
use crate::poi_cache::PoiCacheServiceError;
use crate::public_cache::WALLET_SCAN_ARTIFACT_CHUNK_BLOB_KIND;
use crate::types::{PoiArtifactManifestSource, PoiArtifactSourceConfig};
use alloy::primitives::{Address, U256};
use broadcaster_core::utxo::UtxoSource;
use ed25519_dalek::SigningKey;
use local_db::{
    BlobMeta, DbConfig, POI_CORPUS_JOURNAL_MAX_DELTA_COUNT, PoiArtifactCacheRecord,
    PoiArtifactDescriptorRecord, PoiCacheRecordSource, PoiCorpusValidationRecord,
};
use poi::artifacts::SnapshotEvent;
use poi::artifacts::v4::Manifest;
use poi::cache::{
    POI_CACHE_JOURNAL_DELTA_VERSION, PoiCache, PoiCacheIdentity, PoiCacheJournalDelta,
    PoiCacheJournalEvent,
};
use poi::poi::PoiEventType;
use railgun_wallet::scan::IndexedNullifierInput;
use sha2::{Digest, Sha256};
use url::Url;

#[tokio::test]
async fn poi_artifact_persistence_handle_observes_manifest_watermark() {
    let (db, data_plane, root_dir) = test_data_plane_with_db("poi-v4-persistence-handle");
    let persistence = data_plane.poi_artifact_persistence();
    let signing_key = SigningKey::from_bytes(&[0x42; 32]);
    let publisher = FixedBytes::from(signing_key.verifying_key().to_bytes());
    let mut manifest = Manifest::new(1_700_000_000_000, 7, publisher, Vec::new());
    manifest
        .sign_manifest(&signing_key)
        .expect("sign POI manifest");

    let observed = persistence
        .observe_manifest(publisher, manifest, None)
        .await
        .expect("observe POI manifest through data plane");

    assert_eq!(observed.manifest().sequence, 7);
    assert_eq!(
        db.get_poi_publisher_manifest_watermark(&publisher)
            .expect("load publisher watermark")
            .expect("publisher watermark present")
            .accepted_sequence,
        7
    );

    drop(persistence);
    drop(db);
    fs::remove_dir_all(root_dir).expect("remove temp db dir");
}

#[tokio::test]
async fn blocking_commit_returns_success_after_post_admission_cancellation() {
    let (db, data_plane, root_dir) = test_data_plane_with_db("blocking-commit-success-cancel");
    let persistence = data_plane.poi_artifact_persistence();
    let cancel = CancellationToken::new();
    let operation_cancel = cancel.clone();

    let result = persistence
        .run_blocking_commit(Some(&cancel), "test success", move |_| {
            operation_cancel.cancel();
            Ok(17_u64)
        })
        .await
        .expect("started blocking commit succeeds");

    assert_eq!(result, Some(17));
    drop(persistence);
    drop(data_plane);
    drop(db);
    fs::remove_dir_all(root_dir).expect("remove temp db dir");
}

#[tokio::test]
async fn blocking_commit_propagates_error_after_post_admission_cancellation() {
    let (db, data_plane, root_dir) = test_data_plane_with_db("blocking-commit-error-cancel");
    let persistence = data_plane.poi_artifact_persistence();
    let cancel = CancellationToken::new();
    let operation_cancel = cancel.clone();

    let error = persistence
        .run_blocking_commit(Some(&cancel), "test error", move |_| {
            operation_cancel.cancel();
            Err::<(), _>(PoiArtifactError::Persistence {
                reason: "operation-error-sentinel".to_string(),
            })
        })
        .await
        .expect_err("started blocking commit error is propagated");

    assert!(matches!(
        error,
        PublicDataPlaneError::PoiArtifactPersistence { reason }
            if reason.contains("operation-error-sentinel")
    ));
    drop(persistence);
    drop(data_plane);
    drop(db);
    fs::remove_dir_all(root_dir).expect("remove temp db dir");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn data_plane_shutdown_waits_for_detached_blocking_commit() {
    let (db, data_plane, root_dir) = test_data_plane_with_db("shutdown-drains-blocking-commit");
    let persistence = data_plane.poi_artifact_persistence();
    let (started_tx, started_rx) = tokio::sync::oneshot::channel();
    let (release_tx, release_rx) = std_mpsc::channel();
    let commit = tokio::spawn(async move {
        persistence
            .run_blocking_commit(None, "test shutdown drain", move |_| {
                let _ = started_tx.send(());
                release_rx.recv().expect("release detached commit");
                Ok(())
            })
            .await
    });
    started_rx.await.expect("blocking commit started");
    commit.abort();
    assert!(
        commit
            .await
            .expect_err("commit waiter aborted")
            .is_cancelled()
    );

    let shutdown = tokio::spawn({
        let data_plane = data_plane.clone();
        async move { data_plane.shutdown().await }
    });
    tokio::task::yield_now().await;
    assert!(!shutdown.is_finished());
    release_tx.send(()).expect("release blocking commit");
    tokio::time::timeout(Duration::from_secs(1), shutdown)
        .await
        .expect("data-plane shutdown completes")
        .expect("shutdown task");

    drop(data_plane);
    drop(db);
    fs::remove_dir_all(root_dir).expect("remove temp db dir");
}

#[test]
fn public_rpc_hard_limit_compacts_and_retries_append_once() {
    let (db, root_dir) = test_db("public-rpc-hard-limit-retry");
    let publisher = FixedBytes::from([0x43; 32]);
    let persisted = fill_public_rpc_journal_to_hard_limit(db.as_ref(), publisher);
    let before = persisted
        .journal_head
        .clone()
        .expect("explicit journal head at hard limit");
    assert_eq!(before.delta_count, POI_CORPUS_JOURNAL_MAX_DELTA_COUNT);
    let range_start_index = persisted.cache.progress().next_event_index;
    let expected_base = persisted.expected_base();
    let starting_record = Some(persisted.metadata_only());
    let (candidate, delta) = append_public_rpc_test_event(persisted.cache);

    let committed = commit_public_rpc_after_admission(
        db.as_ref(),
        candidate,
        before.corpus.cache_generation,
        publisher,
        range_start_index,
        expected_base,
        starting_record.as_ref(),
        Some(&before),
        &delta,
        None,
        || false,
    )
    .expect("compact and retry public RPC append")
    .expect("retried append published");
    let after = committed
        .journal_head
        .as_ref()
        .expect("explicit journal head after retry");
    assert_eq!(after.delta_count, 1);
    assert_eq!(after.base_revision + 1, after.revision);
    assert!(after.revision > before.revision);
    assert_eq!(
        committed.cache.progress().next_event_index,
        range_start_index + 1
    );

    drop(db);
    fs::remove_dir_all(root_dir).expect("remove temp db dir");
}

#[test]
fn public_rpc_post_compaction_cancellation_does_not_publish_candidate() {
    let (db, root_dir) = test_db("public-rpc-hard-limit-cancel");
    let publisher = FixedBytes::from([0x44; 32]);
    let persisted = fill_public_rpc_journal_to_hard_limit(db.as_ref(), publisher);
    let before = persisted
        .journal_head
        .clone()
        .expect("explicit journal head at hard limit");
    let range_start_index = persisted.cache.progress().next_event_index;
    let expected_base = persisted.expected_base();
    let starting_record = Some(persisted.metadata_only());
    let identity = persisted.cache.identity().clone();
    let (candidate, delta) = append_public_rpc_test_event(persisted.cache);
    let cancellation_checked = AtomicBool::new(false);

    let committed = commit_public_rpc_after_admission(
        db.as_ref(),
        candidate,
        before.corpus.cache_generation,
        publisher,
        range_start_index,
        expected_base,
        starting_record.as_ref(),
        Some(&before),
        &delta,
        None,
        || {
            cancellation_checked.store(true, Ordering::Release);
            true
        },
    )
    .expect("cancel after compaction");
    assert!(cancellation_checked.load(Ordering::Acquire));
    assert!(committed.is_none());
    let retained = PoiCorpusStore::new(db.as_ref(), before.corpus.cache_generation, publisher)
        .load(&identity)
        .expect("load compacted corpus")
        .expect("compacted corpus remains");
    let retained_head = retained
        .journal_head
        .expect("explicit compacted journal head");
    assert_eq!(retained_head.delta_count, 0);
    assert_eq!(retained_head.base_revision, retained_head.revision);
    assert_eq!(
        retained.cache.progress().next_event_index,
        range_start_index,
        "cancelled candidate must not be appended"
    );

    drop(db);
    fs::remove_dir_all(root_dir).expect("remove temp db dir");
}

#[test]
fn public_rpc_reset_between_compaction_and_retry_cannot_stage_candidate() {
    let (db, root_dir) = test_db("public-rpc-hard-limit-reset-race");
    let publisher = FixedBytes::from([0x45; 32]);
    let persisted = fill_public_rpc_journal_to_hard_limit(db.as_ref(), publisher);
    let generation = persisted.cache_generation;
    let range_start_index = persisted.cache.progress().next_event_index;
    let expected_base = persisted.expected_base();
    let starting_record = Some(persisted.metadata_only());
    let starting_head = persisted.journal_head.clone();
    let (candidate, delta) = append_public_rpc_test_event(persisted.cache);

    let Err(error) = commit_public_rpc_after_admission(
        db.as_ref(),
        candidate,
        generation,
        publisher,
        range_start_index,
        expected_base,
        starting_record.as_ref(),
        starting_head.as_ref(),
        &delta,
        None,
        || {
            db.clear_poi_artifact_cache()
                .expect("reset corpus after compaction");
            false
        },
    ) else {
        panic!("stale retry must reject the reset generation");
    };
    assert!(matches!(
        error,
        PoiArtifactError::StalePublicCacheGeneration { .. }
    ));
    assert!(matches!(
        db.inspect_poi_corpus_journal_head(
            EVM_CHAIN_TYPE,
            1,
            DEFAULT_TXID_VERSION,
            &FixedBytes::from([0x46; 32]),
        )
        .expect("inspect reset corpus"),
        local_db::StoredRecord::Missing
    ));

    drop(db);
    fs::remove_dir_all(root_dir).expect("remove temp db dir");
}

#[test]
fn public_rpc_stale_commit_does_not_stage_valid_winner() {
    let (db, root_dir) = test_db("public-rpc-stale-valid-winner");
    let publisher = FixedBytes::from([0x48; 32]);
    let persisted = persist_public_rpc_test_base(db.as_ref(), publisher);
    let generation = persisted.cache_generation;
    let range_start_index = persisted.cache.progress().next_event_index;
    let expected_base = persisted.expected_base();
    let starting_record = persisted.metadata_only();
    let starting_head = persisted
        .journal_head
        .clone()
        .expect("public RPC starting head");
    let (stale_candidate, stale_delta) = append_public_rpc_test_event(persisted.cache.clone());
    let (winner_candidate, winner_delta) = append_public_rpc_test_event(persisted.cache);
    let store = PoiCorpusStore::new(db.as_ref(), generation, publisher);
    let winner = match store
        .commit_public_rpc(
            winner_candidate,
            range_start_index,
            expected_base,
            Some(&starting_record),
            Some(&starting_head),
            &winner_delta,
            None,
        )
        .expect("commit valid public RPC winner")
    {
        PublicRpcPersistResult::Applied(persisted) => *persisted,
        PublicRpcPersistResult::Stale => panic!("valid winner was stale"),
        PublicRpcPersistResult::CompactionRequired(_) => {
            panic!("valid winner unexpectedly required compaction")
        }
    };

    let stale = commit_public_rpc_after_admission(
        db.as_ref(),
        stale_candidate,
        generation,
        publisher,
        range_start_index,
        expected_base,
        Some(&starting_record),
        Some(&starting_head),
        &stale_delta,
        None,
        || false,
    )
    .expect("reject stale public RPC candidate");
    assert!(
        stale.is_none(),
        "stale candidate must not stage another writer's winner"
    );
    let durable = store
        .load(&winner.cache.identity().clone())
        .expect("load durable winner")
        .expect("durable winner remains present");
    assert_eq!(durable.journal_head, winner.journal_head);
    assert_eq!(
        durable.cache.to_bytes().expect("encode durable cache"),
        winner.cache.to_bytes().expect("encode winner cache")
    );

    drop(db);
    fs::remove_dir_all(root_dir).expect("remove temp db dir");
}

#[tokio::test]
async fn blocking_commit_cancels_waiter_before_admission_while_first_commit_holds_fence() {
    let (db, data_plane, root_dir) = test_data_plane_with_db("blocking-commit-wait-cancel");
    let persistence = data_plane.poi_artifact_persistence();
    let first_persistence = persistence.clone();
    let (first_started_tx, first_started_rx) = std_mpsc::channel();
    let (release_first_tx, release_first_rx) = std_mpsc::channel();
    let first = tokio::spawn(async move {
        first_persistence
            .run_blocking_commit(None, "test fence holder", move |_| {
                first_started_tx.send(()).expect("signal first commit");
                release_first_rx.recv().expect("release first commit");
                Ok(11_u64)
            })
            .await
    });
    tokio::time::timeout(Duration::from_secs(2), async {
        loop {
            match first_started_rx.try_recv() {
                Ok(()) => break,
                Err(std_mpsc::TryRecvError::Empty) => tokio::task::yield_now().await,
                Err(std_mpsc::TryRecvError::Disconnected) => {
                    panic!("first commit stopped before acquiring fence")
                }
            }
        }
    })
    .await
    .expect("first commit acquired fence");

    let cancel = CancellationToken::new();
    let second_executed = Arc::new(AtomicBool::new(false));
    let operation_executed = Arc::clone(&second_executed);
    let mut second = Box::pin(persistence.run_blocking_commit(
        Some(&cancel),
        "test cancelled waiter",
        move |_| {
            operation_executed.store(true, Ordering::SeqCst);
            Ok(22_u64)
        },
    ));
    assert!(
        futures::poll!(&mut second).is_pending(),
        "second commit must wait for the held fence"
    );

    cancel.cancel();
    let second_result = tokio::time::timeout(Duration::from_secs(2), &mut second)
        .await
        .expect("cancelled waiter returned promptly")
        .expect("cancelled waiter does not fail");
    assert_eq!(second_result, None);
    assert!(!second_executed.load(Ordering::SeqCst));

    release_first_tx.send(()).expect("release first commit");
    let first_result = first
        .await
        .expect("join first commit")
        .expect("first commit succeeds");
    assert_eq!(first_result, Some(11));
    drop(second);
    drop(persistence);
    drop(data_plane);
    drop(db);
    fs::remove_dir_all(root_dir).expect("remove temp db dir");
}

#[tokio::test]
async fn poi_corpus_registry_reuses_fixed_chain_handle_and_rejects_mismatch() {
    let (data_plane, root_dir) = test_data_plane_with_poi_service("poi-corpus-reuse");
    let key = PublicPoiCorpusKey::new(EVM_CHAIN_TYPE, 1, DEFAULT_TXID_VERSION);
    let first = data_plane
        .ensure_poi_corpus(key.clone())
        .await
        .expect("first POI corpus");

    let second = data_plane
        .ensure_poi_corpus(key.clone())
        .await
        .expect("second POI corpus");
    assert!(first.local_caches().ptr_eq(&second.local_caches()));
    let Err(error) = data_plane
        .ensure_poi_corpus(PublicPoiCorpusKey::new(
            EVM_CHAIN_TYPE,
            137,
            DEFAULT_TXID_VERSION,
        ))
        .await
    else {
        panic!("mismatched chain must be rejected");
    };
    assert!(matches!(
        error,
        PublicDataPlaneError::PoiCorpusRefresh { chain_id: 137, reason }
            if reason.contains("owns chain 1")
    ));
    assert_eq!(data_plane.state.lock().await.poi_corpora.len(), 1);
    let list_key = FixedBytes::from([0x11; 32]);
    let mut cache = PoiCache::new(PoiCacheIdentity::new(
        key.chain_type,
        key.chain_id,
        &key.txid_version,
        list_key,
    ));
    cache
        .apply_verified_artifact_events(&[poi::artifacts::SnapshotEvent {
            event_index: 0,
            blinded_commitment: [0x22; 32],
            signature: [0_u8; 64],
            event_type: PoiEventType::Transact,
        }])
        .expect("apply POI event");
    first.local_caches().write().await.insert(list_key, cache);
    assert!(
        data_plane
            .poi_corpus_ready_for_lists(key.clone(), &[list_key])
            .await
    );
    data_plane
        .reset_public_cache()
        .await
        .expect("reset public cache");
    assert!(
        data_plane
            .poi_corpus_ready_for_lists(key, &[list_key])
            .await
    );
    data_plane.shutdown().await;
    drop(data_plane);
    fs::remove_dir_all(root_dir).expect("remove temp db dir");
}

#[tokio::test]
async fn poi_corpus_requires_chain_owned_service() {
    let (data_plane, root_dir) = test_data_plane("poi-corpus-no-service");
    let key = PublicPoiCorpusKey::new(EVM_CHAIN_TYPE, 1, DEFAULT_TXID_VERSION);

    let Err(error) = data_plane.ensure_poi_corpus(key).await else {
        panic!("POI corpus should require a chain-owned service");
    };

    assert_eq!(
        error,
        PublicDataPlaneError::PoiCorpusUnavailable {
            chain_id: 1,
            txid_version: DEFAULT_TXID_VERSION.to_string(),
        }
    );
    drop(data_plane);
    fs::remove_dir_all(root_dir).expect("remove temp db dir");
}

#[tokio::test]
async fn txid_latest_marker_read_is_data_plane_operation() {
    let (data_plane, root_dir) = test_data_plane("txid-latest-empty");
    let key = PublicTxidCacheKey::new(test_wallet_scan_scope(), DEFAULT_TXID_VERSION);

    assert_eq!(
        data_plane
            .cached_txid_latest_validated(&key)
            .expect("read empty TXID public cache"),
        None
    );

    drop(data_plane);
    fs::remove_dir_all(root_dir).expect("remove temp db dir");
}

#[tokio::test]
async fn public_scan_coverage_rejects_stale_epoch_write() {
    let (data_plane, root_dir) = test_data_plane("stale-coverage-write");
    data_plane.invalidate_public_scan_coverage_from(100).await;

    let error = data_plane
        .record_public_scan_coverage(PublicScanCoverageWrite {
            range: PublicScanRange::new(100, 110),
            source: PublicScanSource::Rpc,
            row_count: 0,
            read_scope: PublicScanReadScope::new(PublicDataPlaneEpoch::new(0)),
        })
        .await
        .expect_err("stale coverage must be rejected");

    assert_eq!(
        error,
        PublicDataPlaneError::StaleEpoch {
            expected: 1,
            actual: 0,
        }
    );
    assert!(matches!(
        data_plane
            .cached_public_scan_coverage(PublicScanRange::new(100, 110))
            .await,
        PublicCoverageAnswer::Missing { .. }
    ));
    drop(data_plane);
    fs::remove_dir_all(root_dir).expect("remove temp db dir");
}

#[tokio::test]
async fn public_scan_apply_rejects_stale_rows_without_buffering() {
    let (data_plane, root_dir) = test_data_plane("stale-row-apply");
    let apply = WalletScanApply::rows(
        100,
        110,
        WalletScanInputRows::default(),
        data_plane.begin_public_scan_read(),
        PublicScanSource::Rpc,
        None,
    );
    data_plane.invalidate_public_scan_coverage_from(100).await;

    let error = data_plane
        .record_public_scan_apply(&apply)
        .await
        .expect_err("stale public rows must be rejected");

    assert_eq!(
        error,
        PublicDataPlaneError::StaleEpoch {
            expected: 1,
            actual: 0,
        }
    );
    assert!(data_plane.state.lock().await.recent_scan_rows.is_empty());
    assert!(
        data_plane
            .cached_wallet_scan_apply(100, 110)
            .await
            .is_none()
    );
    let diagnostics = data_plane.diagnostics().await;
    assert!(diagnostics.events.iter().any(|event| {
        event.kind == PublicDataPlaneDiagnosticKind::CoverageRejected
            && event.source == Some(PublicScanSource::Rpc)
            && event.range == Some(PublicScanRange::new(100, 110))
            && event.reason == "stale coverage epoch"
            && event.epoch == PublicDataPlaneEpoch::new(1)
    }));
    drop(data_plane);
    fs::remove_dir_all(root_dir).expect("remove temp db dir");
}

#[tokio::test]
async fn public_scan_apply_rejects_hashless_rpc_coverage() {
    let (data_plane, root_dir) = test_data_plane("hashless-rpc-coverage");
    let read_scope = data_plane.begin_public_scan_read();
    let applies = [
        WalletScanApply::rows(
            100,
            110,
            WalletScanInputRows::default(),
            read_scope,
            PublicScanSource::Rpc,
            None,
        ),
        WalletScanApply::empty_coverage(100, 110, read_scope, PublicScanSource::ArchiveRpc, None),
    ];

    for apply in applies {
        let error = data_plane
            .record_public_scan_apply(&apply)
            .await
            .expect_err("hashless RPC coverage must be rejected");
        assert_eq!(
            error,
            PublicDataPlaneError::UnprovenRpcCoverage {
                from_block: 100,
                to_block: 110,
                scan_source: apply.rows.source,
            }
        );
    }
    assert!(matches!(
        data_plane
            .cached_public_scan_coverage(PublicScanRange::new(100, 110))
            .await,
        PublicCoverageAnswer::Missing { .. }
    ));

    drop(data_plane);
    fs::remove_dir_all(root_dir).expect("remove temp db dir");
}

#[tokio::test]
async fn completed_acquisition_rejects_hashless_rpc_coverage() {
    let (data_plane, root_dir) = test_data_plane("hashless-rpc-acquisition");
    let apply = WalletScanApply::empty_coverage(
        100,
        110,
        data_plane.begin_public_scan_read(),
        PublicScanSource::Rpc,
        None,
    );

    let error = data_plane
        .commit_completed_wallet_scan_acquisition(PublicScanRange::new(100, 110), &[apply])
        .await
        .expect_err("hashless RPC acquisition must be rejected");
    assert_eq!(
        error,
        PublicDataPlaneError::UnprovenRpcCoverage {
            from_block: 100,
            to_block: 110,
            scan_source: PublicScanSource::Rpc,
        }
    );

    drop(data_plane);
    fs::remove_dir_all(root_dir).expect("remove temp db dir");
}

#[tokio::test]
async fn completed_acquisition_compacts_five_row_pages_for_full_replay() {
    let (data_plane, root_dir) = test_data_plane("completed-acquisition-compaction");
    let read_scope = data_plane.begin_public_scan_read();
    let applies = (100..105)
        .map(|block_number| {
            WalletScanApply::rows(
                block_number,
                block_number,
                WalletScanInputRows {
                    nullifiers: vec![IndexedNullifierInput {
                        tree_number: 1,
                        nullifier: U256::from(block_number),
                        source: UtxoSource {
                            tx_hash: FixedBytes::from(
                                [u8::try_from(block_number).expect("test block"); 32],
                            ),
                            block_number,
                            block_timestamp: block_number.saturating_add(1_700_000_000),
                        },
                    }],
                    ..WalletScanInputRows::default()
                },
                read_scope,
                PublicScanSource::Squid,
                Some([u8::try_from(block_number).expect("test block"); 32]),
            )
        })
        .collect::<Vec<_>>();
    data_plane
        .commit_completed_wallet_scan_acquisition(PublicScanRange::new(100, 104), &applies)
        .await
        .expect("commit compacted acquisition");

    assert_eq!(data_plane.state.lock().await.recent_scan_rows.len(), 1);
    let replay = data_plane
        .cached_wallet_scan_suffix(100, 104)
        .await
        .expect("completed acquisition is replayable");
    assert_eq!(replay.len(), 1);
    assert_eq!((replay[0].from_block, replay[0].to_block), (100, 104));
    assert_eq!(replay[0].rows.to_block_hash, Some([104; 32]));
    let WalletScanRowsPayload::Rows(rows) = &replay[0].rows.payload else {
        panic!("compacted replay rows expected");
    };
    assert_eq!(rows.nullifiers.len(), 5);
    assert_eq!(rows.nullifiers[0].source.block_number, 100);
    assert_eq!(rows.nullifiers[0].nullifier, U256::from(100));

    drop(data_plane);
    fs::remove_dir_all(root_dir).expect("remove temp db dir");
}

#[tokio::test]
async fn completed_acquisition_preserves_final_empty_rpc_endpoint_hash() {
    let (data_plane, root_dir) = test_data_plane("completed-acquisition-empty-rpc-hash");
    let read_scope = data_plane.begin_public_scan_read();
    let applies = vec![
        WalletScanApply::rows(
            100,
            100,
            WalletScanInputRows {
                nullifiers: vec![IndexedNullifierInput {
                    tree_number: 1,
                    nullifier: U256::from(100),
                    source: UtxoSource {
                        tx_hash: FixedBytes::from([0x11; 32]),
                        block_number: 100,
                        block_timestamp: 1_700_000_100,
                    },
                }],
                ..WalletScanInputRows::default()
            },
            read_scope,
            PublicScanSource::Squid,
            None,
        ),
        WalletScanApply::rows(
            101,
            102,
            WalletScanInputRows::default(),
            read_scope,
            PublicScanSource::Rpc,
            Some([0x22; 32]),
        ),
    ];

    data_plane
        .commit_completed_wallet_scan_acquisition(PublicScanRange::new(100, 102), &applies)
        .await
        .expect("commit mixed acquisition");

    let replay = data_plane
        .cached_wallet_scan_suffix(100, 102)
        .await
        .expect("mixed acquisition is replayable");
    assert_eq!(replay.len(), 2);
    assert!(matches!(
        replay[0].rows.payload,
        WalletScanRowsPayload::Rows(_)
    ));
    assert!(matches!(
        replay[1].rows.payload,
        WalletScanRowsPayload::EmptyCoverage
    ));
    assert_eq!((replay[1].from_block, replay[1].to_block), (101, 102));
    assert_eq!(replay[1].rows.to_block_hash, Some([0x22; 32]));

    drop(data_plane);
    fs::remove_dir_all(root_dir).expect("remove temp db dir");
}

#[tokio::test]
async fn completed_acquisition_rejects_mixed_stale_scopes_atomically() {
    let (data_plane, root_dir) = test_data_plane("completed-acquisition-stale-scopes");
    let stale_scope = data_plane.begin_public_scan_read();
    data_plane.invalidate_public_scan_coverage_from(100).await;
    let current_scope = data_plane.begin_public_scan_read();
    data_plane
        .record_public_scan_coverage(PublicScanCoverageWrite {
            range: PublicScanRange::new(50, 60),
            source: PublicScanSource::Rpc,
            row_count: 0,
            read_scope: current_scope,
        })
        .await
        .expect("seed unrelated coverage");
    let applies = vec![
        WalletScanApply::rows(
            100,
            100,
            WalletScanInputRows::default(),
            stale_scope,
            PublicScanSource::Squid,
            None,
        ),
        WalletScanApply::rows(
            101,
            101,
            WalletScanInputRows::default(),
            current_scope,
            PublicScanSource::Squid,
            None,
        ),
    ];

    let error = data_plane
        .commit_completed_wallet_scan_acquisition(PublicScanRange::new(100, 101), &applies)
        .await
        .expect_err("mixed stale scopes must be rejected");

    assert_eq!(
        error,
        PublicDataPlaneError::StaleEpoch {
            expected: 1,
            actual: 0,
        }
    );
    let state = data_plane.state.lock().await;
    assert!(state.recent_scan_rows.is_empty());
    assert_eq!(state.coverage.records().len(), 1);
    assert_eq!(
        state.coverage.records()[0].range,
        PublicScanRange::new(50, 60)
    );
    drop(state);
    let diagnostics = data_plane.diagnostics().await;
    assert!(diagnostics.events.iter().any(|event| {
        event.kind == PublicDataPlaneDiagnosticKind::CoverageRejected
            && event.source == Some(PublicScanSource::Squid)
            && event.range == Some(PublicScanRange::new(100, 100))
            && event.reason == "stale coverage epoch"
            && event.epoch == PublicDataPlaneEpoch::new(1)
    }));
    assert!(
        data_plane
            .cached_wallet_scan_suffix(100, 101)
            .await
            .is_none()
    );

    drop(data_plane);
    fs::remove_dir_all(root_dir).expect("remove temp db dir");
}

#[tokio::test]
async fn completed_acquisition_rejects_too_many_source_runs_atomically() {
    let (data_plane, root_dir) = test_data_plane("completed-acquisition-source-runs");
    let read_scope = data_plane.begin_public_scan_read();
    let applies = (100..105)
        .map(|block_number| {
            let source = if block_number % 2 == 0 {
                PublicScanSource::Squid
            } else {
                PublicScanSource::Rpc
            };
            WalletScanApply::rows(
                block_number,
                block_number,
                WalletScanInputRows {
                    nullifiers: vec![IndexedNullifierInput {
                        tree_number: 1,
                        nullifier: U256::from(block_number),
                        source: UtxoSource {
                            tx_hash: FixedBytes::from([0x11; 32]),
                            block_number,
                            block_timestamp: block_number.saturating_add(1_700_000_000),
                        },
                    }],
                    ..WalletScanInputRows::default()
                },
                read_scope,
                source,
                matches!(source, PublicScanSource::Rpc).then_some([0x22; 32]),
            )
        })
        .collect::<Vec<_>>();

    {
        let state = data_plane.state.lock().await;
        assert_eq!(
            state.coverage.records(),
            [] as [PublicScanCoverageRecord; 0]
        );
        assert!(state.recent_scan_rows.is_empty());
    }

    let error = data_plane
        .commit_completed_wallet_scan_acquisition(PublicScanRange::new(100, 104), &applies)
        .await
        .expect_err("five source runs exceed bounded row retention");

    assert_eq!(
        error,
        PublicDataPlaneError::CompletedAcquisitionRowPageLimit {
            row_pages: 5,
            limit: RECENT_PUBLIC_SCAN_ROW_PAGE_LIMIT,
        }
    );
    let state = data_plane.state.lock().await;
    assert_eq!(
        state.coverage.records(),
        [] as [PublicScanCoverageRecord; 0]
    );
    assert!(state.recent_scan_rows.is_empty());
    drop(state);
    assert!(
        data_plane
            .cached_wallet_scan_suffix(100, 104)
            .await
            .is_none()
    );

    drop(data_plane);
    fs::remove_dir_all(root_dir).expect("remove temp db dir");
}

#[tokio::test]
async fn cached_wallet_scan_apply_reuses_only_empty_cached_coverage_without_rows() {
    let (data_plane, root_dir) = test_data_plane("cached-empty-coverage");
    data_plane
        .record_public_scan_coverage(PublicScanCoverageWrite {
            range: PublicScanRange::new(100, 110),
            source: PublicScanSource::IndexedArtifacts,
            row_count: 0,
            read_scope: data_plane.begin_public_scan_read(),
        })
        .await
        .expect("record empty coverage");
    data_plane
        .record_public_scan_coverage(PublicScanCoverageWrite {
            range: PublicScanRange::new(111, 120),
            source: PublicScanSource::Squid,
            row_count: 1,
            read_scope: data_plane.begin_public_scan_read(),
        })
        .await
        .expect("record non-empty coverage");

    let apply = data_plane
        .cached_wallet_scan_apply(100, 120)
        .await
        .expect("empty prefix coverage is reusable");
    assert_eq!(apply.from_block, 100);
    assert_eq!(apply.to_block, 110);
    assert_eq!(apply.rows.source, PublicScanSource::CachedCoverage);
    assert!(
        data_plane
            .cached_wallet_scan_apply(111, 120)
            .await
            .is_none(),
        "coverage with rows cannot be replayed without row data"
    );
    drop(data_plane);
    fs::remove_dir_all(root_dir).expect("remove temp db dir");
}

#[tokio::test]
async fn cached_wallet_scan_apply_reuses_and_filters_recent_rows() {
    let (data_plane, root_dir) = test_data_plane("cached-recent-rows");
    let source = |block_number| UtxoSource {
        tx_hash: FixedBytes::from([u8::try_from(block_number).expect("test block"); 32]),
        block_number,
        block_timestamp: block_number.saturating_add(1_700_000_000),
    };
    let rows = WalletScanInputRows {
        nullifiers: vec![
            IndexedNullifierInput {
                tree_number: 1,
                nullifier: U256::from(105),
                source: source(105),
            },
            IndexedNullifierInput {
                tree_number: 1,
                nullifier: U256::from(109),
                source: source(109),
            },
        ],
        ..WalletScanInputRows::default()
    };
    data_plane
        .record_recent_public_scan_rows(PublicScanRows {
            range: PublicScanRange::new(100, 110),
            source: PublicScanSource::Rpc,
            to_block_hash: Some([0x11; 32]),
            rows,
            epoch: data_plane.current_epoch(),
        })
        .await
        .expect("record recent rows");

    let apply = data_plane
        .cached_wallet_scan_apply(106, 110)
        .await
        .expect("recent rows cover requested subrange");

    assert_eq!((apply.from_block, apply.to_block), (106, 110));
    assert_eq!(apply.rows.source, PublicScanSource::CachedCoverage);
    assert_eq!(apply.rows.to_block_hash, Some([0x11; 32]));
    let WalletScanRowsPayload::Rows(rows) = apply.rows.payload else {
        panic!("recent row replay should contain normalized rows");
    };
    assert_eq!(rows.nullifiers.len(), 1);
    assert_eq!(rows.nullifiers[0].source.block_number, 109);
    drop(data_plane);
    fs::remove_dir_all(root_dir).expect("remove temp db dir");
}

#[tokio::test]
async fn cached_wallet_scan_suffix_combines_rows_and_empty_coverage() {
    let (data_plane, root_dir) = test_data_plane("cached-row-suffix");
    data_plane
        .record_public_scan_coverage(PublicScanCoverageWrite {
            range: PublicScanRange::new(100, 109),
            source: PublicScanSource::Rpc,
            row_count: 1,
            read_scope: data_plane.begin_public_scan_read(),
        })
        .await
        .expect("record unavailable row coverage");
    data_plane
        .record_recent_public_scan_rows(PublicScanRows {
            range: PublicScanRange::new(110, 120),
            source: PublicScanSource::Rpc,
            to_block_hash: Some([0x11; 32]),
            rows: WalletScanInputRows {
                nullifiers: vec![IndexedNullifierInput {
                    tree_number: 1,
                    nullifier: U256::from(115),
                    source: UtxoSource {
                        tx_hash: FixedBytes::from([0x11; 32]),
                        block_number: 115,
                        block_timestamp: 1_700_000_115,
                    },
                }],
                ..WalletScanInputRows::default()
            },
            epoch: data_plane.current_epoch(),
        })
        .await
        .expect("record row-bearing suffix");
    data_plane
        .record_public_scan_coverage(PublicScanCoverageWrite {
            range: PublicScanRange::new(121, 130),
            source: PublicScanSource::Rpc,
            row_count: 0,
            read_scope: data_plane.begin_public_scan_read(),
        })
        .await
        .expect("record empty suffix");

    let suffix = data_plane
        .cached_wallet_scan_suffix(100, 130)
        .await
        .expect("contiguous suffix is reusable");

    assert_eq!(suffix.len(), 2);
    assert_eq!((suffix[0].from_block, suffix[0].to_block), (110, 120));
    assert_eq!((suffix[1].from_block, suffix[1].to_block), (121, 130));
    assert!(matches!(
        suffix[0].rows.payload,
        WalletScanRowsPayload::Rows(_)
    ));
    assert!(matches!(
        suffix[1].rows.payload,
        WalletScanRowsPayload::EmptyCoverage
    ));
    drop(data_plane);
    fs::remove_dir_all(root_dir).expect("remove temp db dir");
}

#[tokio::test]
async fn recent_scan_rows_are_bounded_and_cleared_by_invalidation() {
    let (data_plane, root_dir) = test_data_plane("bounded-recent-rows");
    for from_block in 0..u64::try_from(RECENT_PUBLIC_SCAN_ROW_PAGE_LIMIT + 2).expect("limit") {
        data_plane
            .record_recent_public_scan_rows(PublicScanRows {
                range: PublicScanRange::new(from_block, from_block),
                source: PublicScanSource::Rpc,
                to_block_hash: Some([0x11; 32]),
                rows: WalletScanInputRows {
                    nullifiers: vec![IndexedNullifierInput {
                        tree_number: 1,
                        nullifier: U256::from(from_block),
                        source: UtxoSource {
                            tx_hash: FixedBytes::from([0x11; 32]),
                            block_number: from_block,
                            block_timestamp: from_block.saturating_add(1_700_000_000),
                        },
                    }],
                    ..WalletScanInputRows::default()
                },
                epoch: data_plane.current_epoch(),
            })
            .await
            .expect("record recent page");
    }
    assert_eq!(
        data_plane.state.lock().await.recent_scan_rows.len(),
        RECENT_PUBLIC_SCAN_ROW_PAGE_LIMIT
    );

    data_plane.invalidate_public_scan_coverage_from(3).await;

    assert!(data_plane.state.lock().await.recent_scan_rows.is_empty());
    drop(data_plane);
    fs::remove_dir_all(root_dir).expect("remove temp db dir");
}

#[tokio::test]
async fn historical_row_pages_do_not_evict_newer_tip_rows() {
    let (data_plane, root_dir) = test_data_plane("recent-rows-preserve-tip");
    let record_page = |block_number| PublicScanRows {
        range: PublicScanRange::new(block_number, block_number),
        source: PublicScanSource::Rpc,
        to_block_hash: Some([0x11; 32]),
        rows: WalletScanInputRows {
            nullifiers: vec![IndexedNullifierInput {
                tree_number: 1,
                nullifier: U256::from(block_number),
                source: UtxoSource {
                    tx_hash: FixedBytes::from([0x11; 32]),
                    block_number,
                    block_timestamp: block_number.saturating_add(1_700_000_000),
                },
            }],
            ..WalletScanInputRows::default()
        },
        epoch: data_plane.current_epoch(),
    };
    data_plane
        .record_recent_public_scan_rows(record_page(100))
        .await
        .expect("record tip page");
    for block_number in 0..u64::try_from(RECENT_PUBLIC_SCAN_ROW_PAGE_LIMIT).expect("limit") {
        data_plane
            .record_recent_public_scan_rows(record_page(block_number))
            .await
            .expect("record historical page");
    }

    let retained_blocks = data_plane
        .state
        .lock()
        .await
        .recent_scan_rows
        .iter()
        .map(|rows| rows.range.to_block)
        .collect::<Vec<_>>();
    assert_eq!(retained_blocks, vec![100, 1, 2, 3]);
    assert!(
        data_plane
            .cached_wallet_scan_apply(100, 100)
            .await
            .is_some(),
        "newer tip page must remain replayable"
    );
    drop(data_plane);
    fs::remove_dir_all(root_dir).expect("remove temp db dir");
}

#[tokio::test]
async fn completed_acquisition_reserves_rows_during_deterministic_eviction() {
    let (data_plane, root_dir) = test_data_plane("completed-acquisition-reservation");
    let rows_for_block = |block_number| WalletScanInputRows {
        nullifiers: vec![IndexedNullifierInput {
            tree_number: 1,
            nullifier: U256::from(block_number),
            source: UtxoSource {
                tx_hash: FixedBytes::from([0x11; 32]),
                block_number,
                block_timestamp: block_number.saturating_add(1_700_000_000),
            },
        }],
        ..WalletScanInputRows::default()
    };
    for block_number in 200..204 {
        data_plane
            .record_recent_public_scan_rows(PublicScanRows {
                range: PublicScanRange::new(block_number, block_number),
                source: PublicScanSource::Rpc,
                to_block_hash: Some([0x22; 32]),
                rows: rows_for_block(block_number),
                epoch: data_plane.current_epoch(),
            })
            .await
            .expect("record newer row page");
    }
    let epoch = data_plane.current_epoch();
    let apply = WalletScanApply::rows(
        100,
        100,
        rows_for_block(100),
        PublicScanReadScope::new(epoch),
        PublicScanSource::Rpc,
        Some([0x33; 32]),
    );
    data_plane
        .commit_completed_wallet_scan_acquisition(PublicScanRange::new(100, 100), &[apply])
        .await
        .expect("commit exact acquisition");

    let retained_blocks = data_plane
        .state
        .lock()
        .await
        .recent_scan_rows
        .iter()
        .map(|rows| rows.range.from_block)
        .collect::<Vec<_>>();
    assert_eq!(retained_blocks, vec![201, 202, 203, 100]);
    assert!(
        data_plane
            .cached_wallet_scan_exact(100, 100)
            .await
            .is_some()
    );
    drop(data_plane);
    fs::remove_dir_all(root_dir).expect("remove temp db dir");
}

#[tokio::test]
async fn atomic_apply_keeps_wider_fetch_and_completed_subrange_replayable() {
    let (data_plane, root_dir) = test_data_plane("atomic-wider-fetch-acquisition");
    let rows_for_block = |block_number| WalletScanInputRows {
        nullifiers: vec![IndexedNullifierInput {
            tree_number: 1,
            nullifier: U256::from(block_number),
            source: UtxoSource {
                tx_hash: FixedBytes::from([0x44; 32]),
                block_number,
                block_timestamp: block_number.saturating_add(1_700_000_000),
            },
        }],
        ..WalletScanInputRows::default()
    };
    for block_number in 200..204 {
        data_plane
            .record_recent_public_scan_rows(PublicScanRows {
                range: PublicScanRange::new(block_number, block_number),
                source: PublicScanSource::Rpc,
                to_block_hash: Some([0x55; 32]),
                rows: rows_for_block(block_number),
                epoch: data_plane.current_epoch(),
            })
            .await
            .expect("record newer row page");
    }
    let epoch = data_plane.current_epoch();
    let full_apply = WalletScanApply::rows(
        100,
        110,
        rows_for_block(100),
        PublicScanReadScope::new(epoch),
        PublicScanSource::Rpc,
        Some([0x66; 32]),
    );
    let candidate_apply = WalletScanApply::rows(
        105,
        108,
        rows_for_block(101),
        PublicScanReadScope::new(epoch),
        PublicScanSource::Rpc,
        None,
    );
    let candidate = WalletScanAcquisitionCandidate {
        range: PublicScanRange::new(105, 108),
        applies: vec![candidate_apply],
    };
    let (_, outcome) = data_plane
        .record_public_scan_apply_with_acquisition(&full_apply, Some(&candidate))
        .await
        .expect("publish wider apply and acquisition");
    assert!(matches!(
        outcome,
        Some(WalletScanAcquisitionOutcome::Retained)
    ));
    assert!(
        data_plane
            .cached_wallet_scan_exact(100, 110)
            .await
            .is_some()
    );
    assert!(
        data_plane
            .cached_wallet_scan_exact(105, 108)
            .await
            .is_some()
    );
    let retained = data_plane
        .state
        .lock()
        .await
        .recent_scan_rows
        .iter()
        .map(|rows| rows.range.from_block)
        .collect::<Vec<_>>();
    assert_eq!(retained, vec![201, 202, 203, 100]);
    drop(data_plane);
    fs::remove_dir_all(root_dir).expect("remove temp db dir");
}

#[tokio::test]
async fn acquisition_compaction_reduces_five_row_pages_before_page_limit() {
    let (data_plane, root_dir) = test_data_plane("acquisition-five-page-compaction");
    let rows_for_block = |block_number| WalletScanInputRows {
        nullifiers: vec![IndexedNullifierInput {
            tree_number: 1,
            nullifier: U256::from(block_number),
            source: UtxoSource {
                tx_hash: FixedBytes::from([0x77; 32]),
                block_number,
                block_timestamp: block_number.saturating_add(1_700_000_000),
            },
        }],
        ..WalletScanInputRows::default()
    };
    for block_number in 100..104 {
        data_plane
            .record_recent_public_scan_rows(PublicScanRows {
                range: PublicScanRange::new(block_number, block_number),
                source: PublicScanSource::Rpc,
                to_block_hash: Some([0x88; 32]),
                rows: rows_for_block(block_number),
                epoch: data_plane.current_epoch(),
            })
            .await
            .expect("record cached row page");
    }

    let epoch = data_plane.current_epoch();
    let fresh_apply = WalletScanApply::rows(
        104,
        104,
        rows_for_block(104),
        PublicScanReadScope::new(epoch),
        PublicScanSource::Rpc,
        Some([0x88; 32]),
    );
    let candidate_applies = (100..=104)
        .map(|block_number| {
            WalletScanApply::rows(
                block_number,
                block_number,
                rows_for_block(block_number),
                PublicScanReadScope::new(epoch),
                PublicScanSource::Rpc,
                Some([0x88; 32]),
            )
        })
        .collect::<Vec<_>>();
    let candidate = WalletScanAcquisitionCandidate {
        range: PublicScanRange::new(100, 104),
        applies: candidate_applies,
    };
    let (_, outcome) = data_plane
        .record_public_scan_apply_with_acquisition(&fresh_apply, Some(&candidate))
        .await
        .expect("publish fresh page and compact acquisition");

    assert!(matches!(
        outcome,
        Some(WalletScanAcquisitionOutcome::Retained)
    ));
    let replay = data_plane
        .cached_wallet_scan_exact(100, 104)
        .await
        .expect("five-block acquisition remains exactly replayable");
    assert_eq!(replay.len(), 1);
    let WalletScanRowsPayload::Rows(rows) = &replay[0].rows.payload else {
        panic!("compacted row payload expected");
    };
    assert_eq!(rows.nullifiers.len(), 5);
    assert_eq!(
        rows.nullifiers
            .iter()
            .map(|nullifier| nullifier.source.block_number)
            .collect::<Vec<_>>(),
        (100..=104).collect::<Vec<_>>()
    );
    let state = data_plane.state.lock().await;
    assert!(state.recent_scan_rows.len() <= RECENT_PUBLIC_SCAN_ROW_PAGE_LIMIT);
    assert_eq!(state.recent_scan_rows.len(), 1);
    assert_eq!(
        state.recent_scan_rows[0].range,
        PublicScanRange::new(100, 104)
    );
    assert_eq!(state.recent_scan_rows[0].row_count(), 5);
    drop(state);
    drop(data_plane);
    fs::remove_dir_all(root_dir).expect("remove temp db dir");
}

#[tokio::test]
async fn empty_scan_pages_do_not_evict_buffered_rows() {
    let (data_plane, root_dir) = test_data_plane("empty-pages-preserve-rows");
    data_plane
        .record_recent_public_scan_rows(PublicScanRows {
            range: PublicScanRange::new(100, 110),
            source: PublicScanSource::Rpc,
            to_block_hash: Some([0x11; 32]),
            rows: WalletScanInputRows {
                nullifiers: vec![IndexedNullifierInput {
                    tree_number: 1,
                    nullifier: U256::from(105),
                    source: UtxoSource {
                        tx_hash: FixedBytes::from([0x11; 32]),
                        block_number: 105,
                        block_timestamp: 1_700_000_105,
                    },
                }],
                ..WalletScanInputRows::default()
            },
            epoch: data_plane.current_epoch(),
        })
        .await
        .expect("record row-bearing page");
    for block in 200..205 {
        data_plane
            .record_recent_public_scan_rows(PublicScanRows {
                range: PublicScanRange::new(block, block),
                source: PublicScanSource::Rpc,
                to_block_hash: Some([0x11; 32]),
                rows: WalletScanInputRows::default(),
                epoch: data_plane.current_epoch(),
            })
            .await
            .expect("record empty page");
    }

    let apply = data_plane
        .cached_wallet_scan_apply(100, 110)
        .await
        .expect("row-bearing page remains buffered");
    let WalletScanRowsPayload::Rows(rows) = apply.rows.payload else {
        panic!("buffered rows expected");
    };
    assert_eq!(rows.nullifiers.len(), 1);
    assert_eq!(data_plane.state.lock().await.recent_scan_rows.len(), 1);
    drop(data_plane);
    fs::remove_dir_all(root_dir).expect("remove temp db dir");
}

#[tokio::test]
async fn empty_overlap_fragments_do_not_consume_row_page_budget() {
    let (data_plane, root_dir) = test_data_plane("empty-overlap-fragments");
    let rows_for_block = |block_number| WalletScanInputRows {
        nullifiers: vec![IndexedNullifierInput {
            tree_number: 1,
            nullifier: U256::from(block_number),
            source: UtxoSource {
                tx_hash: FixedBytes::from([u8::try_from(block_number).expect("test block"); 32]),
                block_number,
                block_timestamp: block_number.saturating_add(1_700_000_000),
            },
        }],
        ..WalletScanInputRows::default()
    };
    for block in 1..=3 {
        data_plane
            .record_recent_public_scan_rows(PublicScanRows {
                range: PublicScanRange::new(block, block),
                source: PublicScanSource::Rpc,
                to_block_hash: Some([0x11; 32]),
                rows: rows_for_block(block),
                epoch: data_plane.current_epoch(),
            })
            .await
            .expect("record unrelated row page");
    }
    data_plane
        .record_recent_public_scan_rows(PublicScanRows {
            range: PublicScanRange::new(100, 200),
            source: PublicScanSource::Rpc,
            to_block_hash: Some([0x22; 32]),
            rows: rows_for_block(160),
            epoch: data_plane.current_epoch(),
        })
        .await
        .expect("record overlapping row page");
    data_plane
        .record_recent_public_scan_rows(PublicScanRows {
            range: PublicScanRange::new(150, 175),
            source: PublicScanSource::Rpc,
            to_block_hash: Some([0x33; 32]),
            rows: WalletScanInputRows::default(),
            epoch: data_plane.current_epoch(),
        })
        .await
        .expect("record empty overlap");

    assert_eq!(data_plane.state.lock().await.recent_scan_rows.len(), 3);
    for block in 1..=3 {
        let apply = data_plane
            .cached_wallet_scan_apply(block, block)
            .await
            .expect("unrelated row page remains buffered");
        assert!(matches!(apply.rows.payload, WalletScanRowsPayload::Rows(_)));
    }
    let empty = data_plane
        .cached_wallet_scan_apply(100, 200)
        .await
        .expect("empty fragments remain replayable as coverage");
    assert!(matches!(
        empty.rows.payload,
        WalletScanRowsPayload::EmptyCoverage
    ));
    drop(data_plane);
    fs::remove_dir_all(root_dir).expect("remove temp db dir");
}

#[tokio::test]
async fn overlapping_scan_page_preserves_unaffected_row_ranges() {
    let (data_plane, root_dir) = test_data_plane("overlapping-pages-preserve-rows");
    let source = |block_number| UtxoSource {
        tx_hash: FixedBytes::from([u8::try_from(block_number).expect("test block"); 32]),
        block_number,
        block_timestamp: block_number.saturating_add(1_700_000_000),
    };
    let nullifier = |block_number| IndexedNullifierInput {
        tree_number: 1,
        nullifier: U256::from(block_number),
        source: source(block_number),
    };
    data_plane
        .record_recent_public_scan_rows(PublicScanRows {
            range: PublicScanRange::new(100, 200),
            source: PublicScanSource::Rpc,
            to_block_hash: Some([0x11; 32]),
            rows: WalletScanInputRows {
                nullifiers: vec![nullifier(110), nullifier(160), nullifier(190)],
                ..WalletScanInputRows::default()
            },
            epoch: data_plane.current_epoch(),
        })
        .await
        .expect("record original page");
    data_plane
        .record_recent_public_scan_rows(PublicScanRows {
            range: PublicScanRange::new(150, 175),
            source: PublicScanSource::Rpc,
            to_block_hash: Some([0x22; 32]),
            rows: WalletScanInputRows {
                nullifiers: vec![nullifier(170)],
                ..WalletScanInputRows::default()
            },
            epoch: data_plane.current_epoch(),
        })
        .await
        .expect("record overlapping page");

    let prefix = data_plane
        .cached_wallet_scan_apply(100, 149)
        .await
        .expect("unaffected prefix remains buffered");
    assert_eq!(prefix.rows.to_block_hash, None);
    let WalletScanRowsPayload::Rows(prefix_rows) = prefix.rows.payload else {
        panic!("prefix rows expected");
    };
    assert_eq!(prefix_rows.nullifiers[0].source.block_number, 110);

    let suffix = data_plane
        .cached_wallet_scan_apply(176, 200)
        .await
        .expect("unaffected suffix remains buffered");
    assert_eq!(suffix.rows.to_block_hash, Some([0x11; 32]));
    let WalletScanRowsPayload::Rows(suffix_rows) = suffix.rows.payload else {
        panic!("suffix rows expected");
    };
    assert_eq!(suffix_rows.nullifiers[0].source.block_number, 190);
    drop(data_plane);
    fs::remove_dir_all(root_dir).expect("remove temp db dir");
}

#[tokio::test]
async fn duplicate_public_coverage_writes_replace_canonical_coverage() {
    let (data_plane, root_dir) = test_data_plane("duplicate-coverage-row-count");
    let range = PublicScanRange::new(100, 110);
    for _ in 0..2 {
        data_plane
            .record_public_scan_coverage(PublicScanCoverageWrite {
                range,
                source: PublicScanSource::Rpc,
                row_count: 3,
                read_scope: data_plane.begin_public_scan_read(),
            })
            .await
            .expect("record duplicate coverage");
    }

    let answer = data_plane.cached_public_scan_coverage(range).await;

    assert!(matches!(
        answer,
        PublicCoverageAnswer::CoveredWithRows {
            range: PublicScanRange {
                from_block: 100,
                to_block: 110
            },
            ..
        }
    ));
    assert_eq!(data_plane.state.lock().await.coverage.len(), 1);
    drop(data_plane);
    fs::remove_dir_all(root_dir).expect("remove temp db dir");
}

#[tokio::test]
async fn overlapping_public_coverage_writes_preserve_replayable_remainders() {
    let (data_plane, root_dir) = test_data_plane("overlapping-coverage-remainders");
    data_plane
        .record_public_scan_coverage(PublicScanCoverageWrite {
            range: PublicScanRange::new(100, 200),
            source: PublicScanSource::Rpc,
            row_count: 0,
            read_scope: data_plane.begin_public_scan_read(),
        })
        .await
        .expect("record wide coverage");
    data_plane
        .record_public_scan_coverage(PublicScanCoverageWrite {
            range: PublicScanRange::new(150, 200),
            source: PublicScanSource::Rpc,
            row_count: 0,
            read_scope: data_plane.begin_public_scan_read(),
        })
        .await
        .expect("record overlapping suffix coverage");

    assert_eq!(data_plane.state.lock().await.coverage.len(), 2);
    assert_eq!(
        data_plane
            .cached_public_scan_coverage(PublicScanRange::new(100, 149))
            .await,
        PublicCoverageAnswer::ReplayableEmpty {
            range: PublicScanRange::new(100, 149),
            source: PublicScanSource::Rpc,
            epoch: PublicDataPlaneEpoch::new(0),
        }
    );
    let apply = data_plane
        .cached_wallet_scan_apply(100, 200)
        .await
        .expect("overlapping empty coverage remains replayable");
    assert_eq!(apply.from_block, 100);
    assert_eq!(apply.to_block, 200);
    assert_eq!(apply.rows.source, PublicScanSource::CachedCoverage);

    drop(data_plane);
    fs::remove_dir_all(root_dir).expect("remove temp db dir");
}

#[tokio::test]
async fn empty_coverage_preserves_hash_only_for_its_exact_endpoint() {
    let (data_plane, root_dir) = test_data_plane("empty-coverage-exact-endpoint-hash");
    data_plane
        .record_recent_public_scan_rows(PublicScanRows {
            range: PublicScanRange::new(100, 200),
            source: PublicScanSource::Rpc,
            to_block_hash: Some([0x11; 32]),
            rows: WalletScanInputRows::default(),
            epoch: data_plane.current_epoch(),
        })
        .await
        .expect("record wide empty coverage");
    data_plane
        .record_recent_public_scan_rows(PublicScanRows {
            range: PublicScanRange::new(150, 175),
            source: PublicScanSource::Rpc,
            to_block_hash: Some([0x22; 32]),
            rows: WalletScanInputRows::default(),
            epoch: data_plane.current_epoch(),
        })
        .await
        .expect("record overlapping empty coverage");

    let prefix = data_plane
        .cached_wallet_scan_apply(100, 149)
        .await
        .expect("prefix remains replayable");
    let overlap = data_plane
        .cached_wallet_scan_apply(150, 175)
        .await
        .expect("overlap remains replayable");
    let suffix = data_plane
        .cached_wallet_scan_apply(176, 200)
        .await
        .expect("suffix remains replayable");
    let partial_suffix = data_plane
        .cached_wallet_scan_apply(176, 199)
        .await
        .expect("partial suffix remains replayable");
    let full = data_plane
        .cached_wallet_scan_apply(100, 200)
        .await
        .expect("canonicalized coverage remains replayable");

    assert_eq!(prefix.rows.to_block_hash, None);
    assert_eq!(overlap.rows.to_block_hash, Some([0x22; 32]));
    assert_eq!(suffix.rows.to_block_hash, Some([0x11; 32]));
    assert_eq!(partial_suffix.rows.to_block_hash, None);
    assert_eq!(full.rows.to_block_hash, Some([0x11; 32]));

    drop(data_plane);
    fs::remove_dir_all(root_dir).expect("remove temp db dir");
}

#[tokio::test]
async fn row_bearing_cached_coverage_is_not_replayable_empty() {
    let (data_plane, root_dir) = test_data_plane("partial-coverage-no-row-count");
    data_plane
        .record_public_scan_coverage(PublicScanCoverageWrite {
            range: PublicScanRange::new(100, 120),
            source: PublicScanSource::Rpc,
            row_count: 7,
            read_scope: data_plane.begin_public_scan_read(),
        })
        .await
        .expect("record aggregate coverage");

    let answer = data_plane
        .cached_public_scan_coverage(PublicScanRange::new(100, 110))
        .await;

    assert_eq!(
        answer,
        PublicCoverageAnswer::CoveredWithRows {
            range: PublicScanRange::new(100, 110),
            source: PublicScanSource::Rpc,
            epoch: PublicDataPlaneEpoch::new(0),
        }
    );
    assert_eq!(
        data_plane.state.lock().await.coverage.records()[0].row_count,
        7
    );
    assert!(
        data_plane
            .cached_wallet_scan_apply(100, 110)
            .await
            .is_none(),
        "row-bearing coverage must not be replayed as empty coverage"
    );
    drop(data_plane);
    fs::remove_dir_all(root_dir).expect("remove temp db dir");
}

#[tokio::test]
async fn invalidation_removes_or_restamps_stale_coverage_records() {
    let (data_plane, root_dir) = test_data_plane("coverage-invalidation-stale-cleanup");
    data_plane
        .record_public_scan_coverage(PublicScanCoverageWrite {
            range: PublicScanRange::new(1, 9),
            source: PublicScanSource::Rpc,
            row_count: 0,
            read_scope: data_plane.begin_public_scan_read(),
        })
        .await
        .expect("record retained coverage");
    data_plane
        .record_public_scan_coverage(PublicScanCoverageWrite {
            range: PublicScanRange::new(10, 20),
            source: PublicScanSource::Rpc,
            row_count: 0,
            read_scope: data_plane.begin_public_scan_read(),
        })
        .await
        .expect("record invalidated coverage");

    let new_epoch = data_plane.invalidate_public_scan_coverage_from(10).await;

    let state = data_plane.state.lock().await;
    assert_eq!(state.coverage.len(), 1);
    assert_eq!(
        state.coverage.records()[0].range,
        PublicScanRange::new(1, 9)
    );
    assert_eq!(state.coverage.records()[0].epoch, new_epoch);
    drop(state);
    assert!(matches!(
        data_plane
            .cached_public_scan_coverage(PublicScanRange::new(1, 9))
            .await,
        PublicCoverageAnswer::ReplayableEmpty { .. }
    ));
    assert!(matches!(
        data_plane
            .cached_public_scan_coverage(PublicScanRange::new(10, 20))
            .await,
        PublicCoverageAnswer::Missing { .. }
    ));
    drop(data_plane);
    fs::remove_dir_all(root_dir).expect("remove temp db dir");
}

#[tokio::test]
async fn invalidation_trims_spanning_coverage_record() {
    let (data_plane, root_dir) = test_data_plane("coverage-invalidation-trim");
    data_plane
        .record_public_scan_coverage(PublicScanCoverageWrite {
            range: PublicScanRange::new(1, 20),
            source: PublicScanSource::Rpc,
            row_count: 0,
            read_scope: data_plane.begin_public_scan_read(),
        })
        .await
        .expect("record spanning coverage");

    let new_epoch = data_plane.invalidate_public_scan_coverage_from(10).await;

    let state = data_plane.state.lock().await;
    assert_eq!(state.coverage.len(), 1);
    assert_eq!(
        state.coverage.records()[0].range,
        PublicScanRange::new(1, 9)
    );
    assert_eq!(state.coverage.records()[0].epoch, new_epoch);
    drop(state);
    assert!(matches!(
        data_plane
            .cached_public_scan_coverage(PublicScanRange::new(1, 9))
            .await,
        PublicCoverageAnswer::ReplayableEmpty { .. }
    ));
    assert!(matches!(
        data_plane
            .cached_public_scan_coverage(PublicScanRange::new(10, 20))
            .await,
        PublicCoverageAnswer::Missing { .. }
    ));
    drop(data_plane);
    fs::remove_dir_all(root_dir).expect("remove temp db dir");
}

#[tokio::test]
async fn public_cache_reset_clears_coverage_and_advances_epoch() {
    let (data_plane, root_dir) = test_data_plane("public-cache-reset-coverage");
    data_plane
        .record_public_scan_coverage(PublicScanCoverageWrite {
            range: PublicScanRange::new(1, 2),
            source: PublicScanSource::Rpc,
            row_count: 0,
            read_scope: data_plane.begin_public_scan_read(),
        })
        .await
        .expect("record coverage");
    data_plane
        .record_source_decision(
            PublicDataPlaneDiagnosticKind::SourceSelected,
            PublicScanSource::Rpc,
            PublicScanRange::new(1, 2),
            data_plane.begin_public_scan_read(),
            "test",
        )
        .await;

    let reset = data_plane
        .reset_public_cache()
        .await
        .expect("reset public cache");
    assert_eq!(reset.previous_epoch, PublicDataPlaneEpoch::new(0));
    assert_eq!(reset.new_epoch, PublicDataPlaneEpoch::new(1));
    assert_eq!(reset.coverage_entries_removed, 1);
    assert!(reset.diagnostics_removed >= 1);
    assert!(data_plane.cached_wallet_scan_apply(1, 2).await.is_none());
    drop(data_plane);
    fs::remove_dir_all(root_dir).expect("remove temp db dir");
}

#[tokio::test]
async fn public_cache_reset_clears_raw_public_artifacts_but_preserves_poi_corpus() {
    let (db, data_plane, root_dir) = test_data_plane_with_db("public-cache-reset-durable");
    let txid_kind = "txid_public_cache";
    let txid_name = "stale.msgpack";
    let txid_id = "stale-entry";
    let txid_path = db.blob_path(txid_kind, txid_name);
    db.ensure_blob_dir(txid_kind).expect("ensure txid blob dir");
    fs::write(&txid_path, b"stale txid cache").expect("write stale txid blob");
    db.put_blob_meta(
        txid_kind,
        txid_id,
        &BlobMeta {
            format_version: 1,
            relative_path: DbStore::relative_blob_path(txid_kind, txid_name),
            content_hash: Sha256::digest(b"stale txid cache").into(),
            source_hash: None,
            source_sequence: None,
            created_at: 1,
            updated_at: 1,
            last_accessed_at: 1,
            last_block: None,
        },
    )
    .expect("put txid blob meta");
    let descriptor = PoiArtifactDescriptorRecord {
        cid: "cid".to_string(),
        sha256: "sha256".to_string(),
        byte_size: 1,
    };
    let list_key = FixedBytes::from([7_u8; 32]);
    db.put_poi_artifact_cache(&PoiArtifactCacheRecord {
        chain_type: 0,
        chain_id: 1,
        txid_version: "v2".to_string(),
        list_key,
        cache_generation: 0,
        source: PoiCacheRecordSource::IndexedArtifacts,
        validation: PoiCorpusValidationRecord::Legacy,
        legacy_observed_manifest_sequence: 1,
        base_descriptor: descriptor.clone(),
        applied_delta_descriptors: Vec::new(),
        blocked_shields_descriptor: descriptor,
        artifact_tip_index: Some(0),
        artifact_tip_root: Some(FixedBytes::from([9_u8; 32])),
        current_tip_index: 0,
        current_tip_root: FixedBytes::from([9_u8; 32]),
        cache_payload: vec![1, 2, 3],
        legacy_last_successful_rpc_sync_at_ms: None,
        updated_at: 1,
    })
    .expect("put poi artifact cache");
    let poi_raw_kind = crate::poi_artifacts::POI_V4_RAW_CHUNK_BLOB_KIND;
    let poi_raw_name = "poi-v4.bin";
    db.ensure_blob_dir(poi_raw_kind)
        .expect("ensure POI raw blob dir");
    fs::write(db.blob_path(poi_raw_kind, poi_raw_name), b"raw POI v4").expect("write POI raw blob");
    db.put_blob_meta(
        poi_raw_kind,
        "poi-v4",
        &BlobMeta {
            format_version: 1,
            relative_path: DbStore::relative_blob_path(poi_raw_kind, poi_raw_name),
            content_hash: Sha256::digest(b"raw POI v4").into(),
            source_hash: None,
            source_sequence: None,
            created_at: 1,
            updated_at: 1,
            last_accessed_at: 1,
            last_block: None,
        },
    )
    .expect("put POI raw metadata");
    let wallet_scan_chunk = test_wallet_scan_chunk(1, 2, &[1, 2, 3], |metadata| {
        metadata.chunk_sealed = true;
    });
    assert_eq!(
        data_plane
            .retain_wallet_scan_artifact_chunks(
                std::slice::from_ref(&wallet_scan_chunk),
                data_plane.begin_public_scan_read(),
            )
            .await,
        1
    );
    let transient_wallet_scan_chunk = test_wallet_scan_chunk(3, 4, &[4, 5, 6], |_| {});
    assert!(
        data_plane
            .retain_wallet_scan_transient_artifact_chunk_for_generation(
                &transient_wallet_scan_chunk,
                data_plane.begin_public_scan_read(),
                data_plane.wallet_scan_artifact_cache_generation(),
                1,
            )
            .await
    );

    assert!(
        db.get_blob_meta(txid_kind, txid_id)
            .expect("get txid blob meta")
            .is_some()
    );
    assert!(
        db.get_poi_artifact_cache(0, 1, "v2", &list_key)
            .expect("get poi cache")
            .is_some()
    );

    let reset = data_plane
        .reset_public_cache()
        .await
        .expect("reset public cache");

    assert_eq!(reset.txid_blob_entries_removed, 1);
    assert_eq!(reset.wallet_scan_artifact_chunk_entries_removed, 2);
    assert_eq!(reset.poi_artifact_checkpoint_chunk_entries_removed, 1);
    assert_eq!(
        db.poi_artifact_cache_generation()
            .expect("load POI cache generation after reset"),
        0
    );
    assert!(
        db.get_blob_meta(txid_kind, txid_id)
            .expect("get txid blob meta after reset")
            .is_none()
    );
    assert!(!txid_path.exists());
    assert!(
        data_plane
            .cached_wallet_scan_transient_artifact_chunk(&transient_wallet_scan_chunk.descriptor)
            .is_none()
    );
    assert!(
        db.get_poi_artifact_cache(0, 1, "v2", &list_key)
            .expect("get poi cache after reset")
            .is_some()
    );
    assert!(
        data_plane
            .cached_wallet_scan_artifact_chunk(&wallet_scan_chunk.descriptor)
            .is_none()
    );

    data_plane.shutdown().await;
    let destructive = crate::reset_offline_poi_corpus(db.as_ref())
        .await
        .expect("destructively reset offline POI corpus");
    assert_eq!(destructive.corpus_entries_removed, 1);
    assert_eq!(destructive.generation, 1);
    assert!(
        db.get_poi_artifact_cache(0, 1, "v2", &list_key)
            .expect("get destructively reset POI corpus")
            .is_none()
    );

    drop(data_plane);
    drop(db);
    fs::remove_dir_all(root_dir).expect("remove temp db dir");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn public_cache_reset_cancels_active_poi_attempt_before_raw_reset_and_restarts() {
    let (db, data_plane, stalled, root_dir) =
        test_data_plane_with_stalled_poi_service("public-cache-reset-poi-attempt");
    let key = PublicPoiCorpusKey::wallet_default(1);
    let list_key = poi::poi::default_active_poi_list_key();
    let corpus = data_plane
        .ensure_poi_corpus(key.clone())
        .await
        .expect("start POI coordinator");
    let local_caches = corpus.local_caches();
    stalled
        .accepted
        .recv_timeout(Duration::from_secs(2))
        .expect("startup attempt reached network");

    let mut serving_cache = PoiCache::new(PoiCacheIdentity::new(
        key.chain_type,
        key.chain_id,
        key.txid_version.clone(),
        list_key,
    ));
    serving_cache
        .apply_verified_artifact_events(&[poi::artifacts::SnapshotEvent {
            event_index: 0,
            blinded_commitment: [0x71; 32],
            signature: [0; 64],
            event_type: PoiEventType::Transact,
        }])
        .expect("build serving corpus");
    serving_cache.accept_current_roots();
    let serving_bytes = serving_cache.to_bytes().expect("encode serving corpus");
    local_caches.write().await.insert(list_key, serving_cache);

    let service = Arc::clone(
        data_plane
            .poi_cache_service
            .as_ref()
            .expect("POI cache service"),
    );
    let old_attempt = service.retry_chain(1).await.expect("admit old attempt");
    let old_attempt_id = old_attempt.attempt_id();
    stalled
        .accepted
        .recv_timeout(Duration::from_secs(2))
        .expect("old attempt reached network");
    assert!(service.progress_rx().borrow()[&1].ready_for_wallet_checks);

    let raw_kind = crate::poi_artifacts::POI_V4_RAW_CHUNK_BLOB_KIND;
    db.ensure_blob_dir(raw_kind)
        .expect("ensure raw POI cache directory");
    fs::write(db.blob_path(raw_kind, "stale.bin"), b"stale").expect("write stale raw chunk");
    db.put_blob_meta(
        raw_kind,
        "stale",
        &BlobMeta {
            format_version: 1,
            relative_path: DbStore::relative_blob_path(raw_kind, "stale.bin"),
            content_hash: Sha256::digest(b"stale").into(),
            source_hash: None,
            source_sequence: None,
            created_at: 1,
            updated_at: 1,
            last_accessed_at: 1,
            last_block: None,
        },
    )
    .expect("persist stale raw chunk metadata");

    data_plane
        .reset_public_cache()
        .await
        .expect("reset public cache");
    assert!(matches!(
        old_attempt.wait().await,
        Err(PoiCacheServiceError::StaleAttempt { attempt_id })
            if attempt_id == old_attempt_id
    ));
    stalled
        .accepted
        .recv_timeout(Duration::from_secs(2))
        .expect("replacement attempt reached network");

    let replacement = service.progress_rx().borrow()[&1].clone();
    assert!(replacement.attempt_id > old_attempt_id);
    assert!(replacement.ready_for_wallet_checks);
    assert!(
        db.get_blob_meta(raw_kind, "stale")
            .expect("read reset raw metadata")
            .is_none()
    );
    let retained = local_caches
        .read()
        .await
        .get(&list_key)
        .cloned()
        .expect("serving corpus retained");
    assert_eq!(
        retained.to_bytes().expect("encode retained corpus"),
        serving_bytes,
    );
    assert!(
        db.get_poi_artifact_cache(key.chain_type, key.chain_id, &key.txid_version, &list_key,)
            .expect("read absent stale candidate")
            .is_none()
    );
    tokio::task::yield_now().await;
    assert_eq!(
        service.progress_rx().borrow()[&1].attempt_id,
        replacement.attempt_id,
    );

    data_plane.shutdown().await;
    drop(data_plane);
    drop(service);
    drop(stalled);
    drop(db);
    fs::remove_dir_all(root_dir).expect("remove temp db dir");
}

#[cfg(unix)]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn failed_public_cache_reset_releases_poi_attempt_lease() {
    use std::os::unix::fs::PermissionsExt;

    let (db, data_plane, stalled, root_dir) =
        test_data_plane_with_stalled_poi_service("failed-public-cache-reset-poi-attempt");
    data_plane
        .ensure_poi_corpus(PublicPoiCorpusKey::wallet_default(1))
        .await
        .expect("start POI coordinator");
    stalled
        .accepted
        .recv_timeout(Duration::from_secs(2))
        .expect("old attempt reached network");
    let service = Arc::clone(
        data_plane
            .poi_cache_service
            .as_ref()
            .expect("POI cache service"),
    );
    let old_attempt_id = service.progress_rx().borrow()[&1].attempt_id;

    let txid_cache_dir = db.blob_dir().join(crate::txid_cache::TXID_CACHE_BLOB_KIND);
    match fs::remove_dir_all(&txid_cache_dir) {
        Ok(()) => {}
        Err(error) if error.kind() == ErrorKind::NotFound => {}
        Err(error) => panic!("remove TXID cache directory: {error}"),
    }
    fs::create_dir_all(&txid_cache_dir).expect("create TXID cache directory");
    fs::write(txid_cache_dir.join("blocked"), b"blocked").expect("seed TXID cache file");
    fs::set_permissions(&txid_cache_dir, fs::Permissions::from_mode(0o500))
        .expect("make TXID cache directory non-writable");

    let reset = data_plane.reset_public_cache().await;
    fs::set_permissions(&txid_cache_dir, fs::Permissions::from_mode(0o700))
        .expect("restore TXID cache directory permissions");
    assert!(matches!(
        reset,
        Err(PublicDataPlaneError::PublicCacheReset { .. })
    ));
    stalled
        .accepted
        .recv_timeout(Duration::from_secs(2))
        .expect("failed reset admitted replacement attempt");
    assert!(service.progress_rx().borrow()[&1].attempt_id > old_attempt_id);

    fs::remove_dir_all(txid_cache_dir).expect("remove failing TXID cache path");
    data_plane.shutdown().await;
    drop(data_plane);
    drop(service);
    drop(stalled);
    drop(db);
    fs::remove_dir_all(root_dir).expect("remove temp db dir");
}

#[tokio::test]
async fn wallet_scan_retention_admitted_before_db_reset_is_suppressed() {
    let (db, writer, root_dir) = test_data_plane_with_db("wallet-scan-reset-generation");
    let resetter = ChainPublicDataPlane::new(Arc::clone(&db), Arc::new(AtomicU64::new(0)));
    let chunk = test_wallet_scan_chunk(1, 2, &[1, 2, 3], |metadata| {
        metadata.chunk_sealed = true;
    });
    let transient_chunk = test_wallet_scan_chunk(3, 4, &[4, 5, 6], |_| {});
    let read_scope = writer.begin_public_scan_read();
    let admitted_generation = writer.wallet_scan_artifact_cache_generation();

    resetter
        .reset_public_cache()
        .await
        .expect("reset shared persisted cache");
    let retained = writer
        .retain_wallet_scan_artifact_chunks_for_generation(
            std::slice::from_ref(&chunk),
            read_scope,
            admitted_generation,
        )
        .await;

    assert_eq!(retained, 0);
    assert!(
        !writer
            .retain_wallet_scan_transient_artifact_chunk_for_generation(
                &transient_chunk,
                read_scope,
                admitted_generation,
                1,
            )
            .await
    );
    assert_eq!(writer.current_epoch(), PublicDataPlaneEpoch::new(0));
    assert!(
        writer
            .cached_wallet_scan_artifact_chunk(&chunk.descriptor)
            .is_none()
    );
    assert!(
        writer
            .cached_wallet_scan_transient_artifact_chunk(&transient_chunk.descriptor)
            .is_none()
    );
    drop(writer);
    drop(resetter);
    drop(db);
    fs::remove_dir_all(root_dir).expect("remove temp db dir");
}

#[tokio::test]
async fn public_cache_reset_does_not_depend_on_stopped_poi_service() {
    let (data_plane, root_dir) = test_data_plane_with_poi_service("reset-poi-sync-failure");
    data_plane
        .record_public_scan_coverage(PublicScanCoverageWrite {
            range: PublicScanRange::new(1, 2),
            source: PublicScanSource::Rpc,
            row_count: 0,
            read_scope: data_plane.begin_public_scan_read(),
        })
        .await
        .expect("record public coverage");
    data_plane
        .ensure_poi_corpus(PublicPoiCorpusKey::wallet_default(1))
        .await
        .expect("start POI cache coordinator");
    let service = Arc::clone(
        data_plane
            .poi_cache_service
            .as_ref()
            .expect("POI cache service"),
    );
    service.shutdown().await;
    let permit = data_plane.acquire_public_cache_reset_permit().await;

    let result = permit.apply().await;

    assert!(result.is_ok());
    assert_eq!(data_plane.current_epoch(), PublicDataPlaneEpoch::new(1));
    assert!(matches!(
        data_plane
            .cached_public_scan_coverage(PublicScanRange::new(1, 2))
            .await,
        PublicCoverageAnswer::Missing { .. }
    ));
    drop(data_plane);
    drop(service);
    fs::remove_dir_all(root_dir).expect("remove temp db dir");
}

#[tokio::test]
async fn wallet_scan_artifact_chunk_cache_reuses_exact_content_identity() {
    let (db, data_plane, root_dir) = test_data_plane_with_db("wallet-scan-chunk-cache");
    let stable_chunk = test_wallet_scan_chunk(1, 10, &[1, 2, 3], |_| {});
    let transient_tail = test_wallet_scan_chunk(11, 20, &[4, 5, 6], |_| {});
    let retained = data_plane
        .retain_wallet_scan_artifact_chunks(
            std::slice::from_ref(&stable_chunk),
            data_plane.begin_public_scan_read(),
        )
        .await;

    assert_eq!(retained, 1);
    assert_eq!(
        data_plane
            .cached_wallet_scan_artifact_chunk(&stable_chunk.descriptor)
            .expect("stable chunk cached")
            .bytes,
        stable_chunk.bytes
    );
    assert!(
        data_plane
            .cached_wallet_scan_artifact_chunk(&transient_tail.descriptor)
            .is_none(),
        "chunks not selected for retention stay uncached"
    );
    assert!(
        data_plane
            .retain_wallet_scan_transient_artifact_chunk_for_generation(
                &transient_tail,
                data_plane.begin_public_scan_read(),
                data_plane.wallet_scan_artifact_cache_generation(),
                1,
            )
            .await
    );
    assert_eq!(
        data_plane
            .cached_wallet_scan_transient_artifact_chunk(&transient_tail.descriptor)
            .expect("transient tail cached")
            .bytes,
        transient_tail.bytes
    );
    let replacement_tail = test_wallet_scan_chunk(11, 22, &[10, 11, 12], |_| {});
    assert_eq!(
        wallet_scan_artifact_transient_slot_id(&transient_tail.descriptor),
        wallet_scan_artifact_transient_slot_id(&replacement_tail.descriptor)
    );
    assert!(
        data_plane
            .retain_wallet_scan_transient_artifact_chunk_for_generation(
                &replacement_tail,
                data_plane.begin_public_scan_read(),
                data_plane.wallet_scan_artifact_cache_generation(),
                2,
            )
            .await
    );
    assert!(
        data_plane
            .cached_wallet_scan_transient_artifact_chunk(&transient_tail.descriptor)
            .is_none(),
        "replaced transient descriptor must not reuse newer slot bytes"
    );
    assert_eq!(
        data_plane
            .cached_wallet_scan_transient_artifact_chunk(&replacement_tail.descriptor)
            .expect("replacement transient tail cached")
            .bytes,
        replacement_tail.bytes
    );
    assert!(
        !data_plane
            .retain_wallet_scan_transient_artifact_chunk_for_generation(
                &transient_tail,
                data_plane.begin_public_scan_read(),
                data_plane.wallet_scan_artifact_cache_generation(),
                1,
            )
            .await,
        "older manifest sequence must not replace a newer transient tail"
    );
    assert!(
        data_plane
            .cached_wallet_scan_transient_artifact_chunk(&replacement_tail.descriptor)
            .is_some()
    );

    let mut mismatched_descriptor = stable_chunk.descriptor.clone();
    mismatched_descriptor.metadata.chunk_sealed = true;
    assert!(
        data_plane
            .cached_wallet_scan_artifact_chunk(&mismatched_descriptor)
            .is_some(),
        "speculative sealing metadata must not prevent exact-content reuse"
    );
    mismatched_descriptor.sha256 = FixedBytes::from([0xff; 32]);
    assert!(
        data_plane
            .cached_wallet_scan_artifact_chunk(&mismatched_descriptor)
            .is_none(),
        "content identity must match before cached bytes are reused"
    );

    let sealed_tail = test_wallet_scan_chunk(21, 30, &[7, 8, 9], |metadata| {
        metadata.chunk_sealed = true;
    });
    assert_eq!(
        data_plane
            .retain_wallet_scan_artifact_chunks(
                std::slice::from_ref(&sealed_tail),
                data_plane.begin_public_scan_read(),
            )
            .await,
        1
    );
    assert!(
        data_plane
            .cached_wallet_scan_artifact_chunk(&sealed_tail.descriptor)
            .is_some(),
        "explicitly demanded verified chunks are retained"
    );

    let predecessor = test_wallet_scan_chunk(31, 40, &[13, 14, 15], |_| {});
    assert_eq!(
        data_plane
            .retain_wallet_scan_artifact_chunks(
                std::slice::from_ref(&predecessor),
                data_plane.begin_public_scan_read(),
            )
            .await,
        1,
        "demanded verified chunks may be retained"
    );
    let predecessor_id = wallet_scan_artifact_chunk_blob_id(&predecessor.descriptor);
    let mut predecessor_meta = db
        .get_blob_meta(WALLET_SCAN_ARTIFACT_CHUNK_BLOB_KIND, &predecessor_id)
        .expect("read predecessor meta")
        .expect("predecessor cached");
    predecessor_meta.last_accessed_at = 0;
    db.put_blob_meta(
        WALLET_SCAN_ARTIFACT_CHUNK_BLOB_KIND,
        &predecessor_id,
        &predecessor_meta,
    )
    .expect("reset access time");
    assert_eq!(
        data_plane
            .retain_wallet_scan_artifact_chunks(
                std::slice::from_ref(&predecessor),
                data_plane.begin_public_scan_read(),
            )
            .await,
        0,
        "overlapping maintenance must not rewrite a cached wallet chunk"
    );
    assert!(
        data_plane
            .cached_wallet_scan_artifact_chunk(&predecessor.descriptor)
            .is_some(),
        "verified cache hit should be reused"
    );
    let untouched_meta = db
        .get_blob_meta(WALLET_SCAN_ARTIFACT_CHUNK_BLOB_KIND, &predecessor_id)
        .expect("read predecessor meta after cache hit")
        .expect("predecessor meta retained");
    assert_eq!(
        untouched_meta.last_accessed_at, 0,
        "verified cache hits must remain read-only"
    );

    drop(data_plane);
    drop(db);
    fs::remove_dir_all(root_dir).expect("remove temp db dir");
}

#[tokio::test]
async fn public_data_plane_diagnostics_record_source_fallback() {
    let (data_plane, root_dir) = test_data_plane("data-plane-diagnostics");
    let stale_scope = data_plane.begin_public_scan_read();
    data_plane.invalidate_public_scan_coverage_from(10).await;
    data_plane
        .record_source_decision(
            PublicDataPlaneDiagnosticKind::SourceSelected,
            PublicScanSource::IndexedArtifacts,
            PublicScanRange::new(10, 20),
            stale_scope,
            "artifact source selected",
        )
        .await;
    data_plane
        .record_source_decision(
            PublicDataPlaneDiagnosticKind::SourceFallback,
            PublicScanSource::Squid,
            PublicScanRange::new(10, 20),
            data_plane.begin_public_scan_read(),
            "artifact failed before checkpoint",
        )
        .await;

    let diagnostics = data_plane.diagnostics().await;
    assert_eq!(diagnostics.events.len(), 3);
    assert_eq!(
        diagnostics.events[1].kind,
        PublicDataPlaneDiagnosticKind::SourceSelected
    );
    assert_eq!(
        diagnostics.events[1].source,
        Some(PublicScanSource::IndexedArtifacts)
    );
    assert_eq!(diagnostics.events[1].epoch, stale_scope.epoch());
    assert_eq!(
        diagnostics.events[2].kind,
        PublicDataPlaneDiagnosticKind::SourceFallback
    );
    assert_eq!(diagnostics.events[2].source, Some(PublicScanSource::Squid));
    drop(data_plane);
    fs::remove_dir_all(root_dir).expect("remove temp db dir");
}

#[tokio::test]
async fn public_scan_epoch_validation_rejects_stale_apply_epoch() {
    let (data_plane, root_dir) = test_data_plane("stale-apply-epoch");
    data_plane.invalidate_public_scan_coverage_from(10).await;

    let error = data_plane
        .validate_public_scan_read(
            PublicScanRange::new(10, 20),
            PublicScanSource::CachedCoverage,
            PublicScanReadScope::new(PublicDataPlaneEpoch::new(0)),
        )
        .await
        .expect_err("stale apply epoch must be rejected");

    assert_eq!(
        error,
        PublicDataPlaneError::StaleEpoch {
            expected: 1,
            actual: 0,
        }
    );
    drop(data_plane);
    fs::remove_dir_all(root_dir).expect("remove temp db dir");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn validated_public_scan_commit_blocks_epoch_invalidation_until_commit_finishes() {
    let (data_plane, root_dir) = test_data_plane("validated-commit-epoch-guard");
    let read_scope = data_plane.begin_public_scan_read();
    let range = PublicScanRange::new(10, 20);
    let (entered_tx, entered_rx) = tokio::sync::oneshot::channel();
    let (release_tx, release_rx) = std_mpsc::channel();
    let commit_plane = data_plane.clone();
    let commit_task = tokio::spawn(async move {
        let permit = commit_plane
            .public_scan_commit_permit(range, PublicScanSource::Rpc, read_scope)
            .await
            .expect("validated commit");
        let _ = entered_tx.send(());
        release_rx.recv().expect("release commit");
        drop(permit);
    });
    entered_rx.await.expect("commit closure entered");

    let invalidate_plane = data_plane.clone();
    let invalidate_task = tokio::spawn(async move {
        invalidate_plane
            .invalidate_public_scan_coverage_from(10)
            .await
    });
    tokio::time::sleep(Duration::from_millis(50)).await;
    assert!(
        !invalidate_task.is_finished(),
        "epoch invalidation must wait for the guarded commit section"
    );

    release_tx.send(()).expect("release commit");
    commit_task.await.expect("commit task");
    assert_eq!(
        invalidate_task.await.expect("invalidate task"),
        PublicDataPlaneEpoch::new(1)
    );
    drop(data_plane);
    fs::remove_dir_all(root_dir).expect("remove temp db dir");
}

fn test_data_plane(name: &str) -> (ChainPublicDataPlane, PathBuf) {
    let (db, root_dir) = test_db(name);
    let data_plane = ChainPublicDataPlane::new(db, Arc::new(AtomicU64::new(0)));
    (data_plane, root_dir)
}

fn test_data_plane_with_poi_service(name: &str) -> (ChainPublicDataPlane, PathBuf) {
    let (db, root_dir) = test_db(name);
    let data_plane = ChainPublicDataPlane::new(Arc::clone(&db), Arc::new(AtomicU64::new(0)));
    let poi_cache_service = PoiCacheService::new_with_persistence(
        Arc::clone(&db),
        1,
        PoiArtifactSourceConfig {
            trusted_publisher_pubkey: FixedBytes::from([0x42; 32]),
            manifest_source: PoiArtifactManifestSource::Url(
                Url::parse("http://127.0.0.1:1/poi-manifest.json")
                    .expect("POI manifest URL")
                    .into(),
            ),
            gateway_urls: Vec::new(),
            gateway_pool: None,
            max_manifest_age: None,
        },
        None,
        data_plane.poi_artifact_persistence(),
    )
    .expect("initialize POI cache generation")
    .with_poi_rpc_url(Url::parse("http://127.0.0.1:1").expect("POI RPC URL"));
    let data_plane = data_plane.with_poi_cache_service(Arc::new(poi_cache_service));
    (data_plane, root_dir)
}

struct StalledHttpServer {
    url: Url,
    accepted: std_mpsc::Receiver<()>,
    release: Arc<AtomicBool>,
}

impl Drop for StalledHttpServer {
    fn drop(&mut self) {
        self.release.store(true, Ordering::Release);
    }
}

fn test_data_plane_with_stalled_poi_service(
    name: &str,
) -> (
    Arc<DbStore>,
    ChainPublicDataPlane,
    StalledHttpServer,
    PathBuf,
) {
    let (db, root_dir) = test_db(name);
    let stalled = spawn_stalled_http_server();
    let data_plane = ChainPublicDataPlane::new(Arc::clone(&db), Arc::new(AtomicU64::new(0)));
    let poi_cache_service = PoiCacheService::new_with_persistence(
        Arc::clone(&db),
        1,
        PoiArtifactSourceConfig {
            trusted_publisher_pubkey: FixedBytes::from([0x42; 32]),
            manifest_source: PoiArtifactManifestSource::Url(stalled.url.clone().into()),
            gateway_urls: vec![stalled.url.clone().into()],
            gateway_pool: None,
            max_manifest_age: None,
        },
        None,
        data_plane.poi_artifact_persistence(),
    )
    .expect("initialize stalled POI cache service")
    .with_poi_rpc_url(stalled.url.clone());
    let data_plane = data_plane.with_poi_cache_service(Arc::new(poi_cache_service));
    (db, data_plane, stalled, root_dir)
}

fn spawn_stalled_http_server() -> StalledHttpServer {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind stalled HTTP server");
    listener
        .set_nonblocking(true)
        .expect("set stalled HTTP listener nonblocking");
    let url = Url::parse(&format!(
        "http://{}",
        listener.local_addr().expect("stalled HTTP local address")
    ))
    .expect("stalled HTTP URL");
    let (accepted_tx, accepted) = std_mpsc::channel();
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
                Err(error) if error.kind() == ErrorKind::WouldBlock => {
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

fn test_data_plane_with_db(name: &str) -> (Arc<DbStore>, ChainPublicDataPlane, PathBuf) {
    let (db, root_dir) = test_db(name);
    let data_plane = ChainPublicDataPlane::new(Arc::clone(&db), Arc::new(AtomicU64::new(0)));
    (db, data_plane, root_dir)
}

fn append_public_rpc_test_event(mut cache: PoiCache) -> (PoiCache, PoiCacheJournalDelta) {
    let event_index = cache.progress().next_event_index;
    assert_eq!(event_index, cache.progress().next_leaf_index);
    let mut commitment = [0_u8; 32];
    commitment[24..].copy_from_slice(&event_index.to_be_bytes());
    let event = SnapshotEvent {
        event_index,
        blinded_commitment: commitment,
        signature: [0_u8; 64],
        event_type: PoiEventType::Transact,
    };
    cache
        .apply_verified_artifact_events(&[event])
        .expect("append test event");
    cache.accept_current_roots();
    let blinded_commitment = FixedBytes::from(commitment);
    let delta = PoiCacheJournalDelta {
        version: POI_CACHE_JOURNAL_DELTA_VERSION,
        identity: cache.identity().clone(),
        event_start_cursor: event_index,
        event_end_cursor: event_index + 1,
        leaf_start_cursor: event_index,
        leaf_end_cursor: event_index + 1,
        events: vec![PoiCacheJournalEvent {
            event_index,
            blinded_commitment,
        }],
        leaves: vec![blinded_commitment],
    };
    (cache, delta)
}

fn persist_public_rpc_test_base(
    db: &DbStore,
    publisher: FixedBytes<32>,
) -> PersistedPoiArtifactCache {
    let identity = PoiCacheIdentity::new(
        EVM_CHAIN_TYPE,
        1,
        DEFAULT_TXID_VERSION,
        FixedBytes::from([0x46; 32]),
    );
    let generation = db
        .poi_artifact_cache_generation()
        .expect("load test corpus generation");
    let store = PoiCorpusStore::new(db, generation, publisher);
    let (base, base_delta) = append_public_rpc_test_event(PoiCache::new(identity));
    match store
        .commit_public_rpc(
            base,
            0,
            ExpectedPoiCorpusBase::NoValidCorpus,
            None,
            None,
            &base_delta,
            None,
        )
        .expect("persist test corpus base")
    {
        PublicRpcPersistResult::Applied(persisted) => *persisted,
        PublicRpcPersistResult::Stale => panic!("test corpus base was stale"),
        PublicRpcPersistResult::CompactionRequired(_) => {
            panic!("empty test corpus unexpectedly required compaction")
        }
    }
}

fn fill_public_rpc_journal_to_hard_limit(
    db: &DbStore,
    publisher: FixedBytes<32>,
) -> PersistedPoiArtifactCache {
    let mut persisted = persist_public_rpc_test_base(db, publisher);
    let generation = persisted.cache_generation;
    let store = PoiCorpusStore::new(db, generation, publisher);
    for _ in 0..POI_CORPUS_JOURNAL_MAX_DELTA_COUNT {
        let range_start_index = persisted.cache.progress().next_event_index;
        let expected_base = persisted.expected_base();
        let starting_record = Some(persisted.metadata_only());
        let starting_head = persisted.journal_head.clone();
        let (candidate, delta) = append_public_rpc_test_event(persisted.cache);
        persisted = match store
            .commit_public_rpc(
                candidate,
                range_start_index,
                expected_base,
                starting_record.as_ref(),
                starting_head.as_ref(),
                &delta,
                None,
            )
            .expect("append test journal delta")
        {
            PublicRpcPersistResult::Applied(persisted) => *persisted,
            PublicRpcPersistResult::Stale => panic!("test journal append was stale"),
            PublicRpcPersistResult::CompactionRequired(_) => {
                panic!("test journal reached hard limit before the declared maximum")
            }
        };
    }
    persisted
}

fn test_db(name: &str) -> (Arc<DbStore>, PathBuf) {
    let root_dir = temp_db_root(name);
    let db = Arc::new(
        DbStore::open(DbConfig {
            root_dir: root_dir.clone(),
        })
        .expect("open db"),
    );
    (db, root_dir)
}

fn test_wallet_scan_chunk<F>(
    start: u64,
    end: u64,
    bytes: &[u8],
    update_metadata: F,
) -> VerifiedIndexedArtifactChunk
where
    F: FnOnce(&mut DatasetDescriptorMetadata),
{
    let mut metadata = DatasetDescriptorMetadata {
        catalog_generation: Some(1),
        checkpoint_block: Some(end),
        ..Default::default()
    };
    update_metadata(&mut metadata);
    let descriptor = IndexedArtifactDescriptor {
        dataset_kind: IndexedDatasetKind::WalletScan,
        scope: test_wallet_scan_scope(),
        range: IndexedArtifactRange {
            kind: IndexedArtifactRangeKind::Block,
            start,
            end,
        },
        row_count: 0,
        cid: format!("test-wallet-scan-{start}-{end}"),
        sha256: FixedBytes::from_slice(&Sha256::digest(bytes)),
        byte_size: u64::try_from(bytes.len()).expect("test chunk byte size"),
        encoding_version: INDEXED_ARTIFACT_CHUNK_FORMAT_VERSION,
        compression: CompressionAlgorithm::None,
        metadata,
    };
    VerifiedIndexedArtifactChunk {
        descriptor,
        bytes: bytes.to_vec(),
    }
}

fn test_wallet_scan_scope() -> ChainScope {
    ChainScope {
        chain_type: ChainType::Evm,
        chain_id: 1,
        railgun_contract: Address::from([0x11; 20]),
    }
}

fn temp_db_root(name: &str) -> PathBuf {
    let unique = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system time")
        .as_nanos();
    std::env::temp_dir().join(format!("sync-service-data-plane-{name}-{unique}"))
}
