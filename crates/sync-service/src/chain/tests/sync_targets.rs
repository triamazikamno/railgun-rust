use super::*;

#[test]
fn complete_stream_checkpoint_uses_target_for_non_full_pages() {
    let checkpoint = complete_stream_checkpoint(2, 10, 100, [20_u64, 40].into_iter());

    assert_eq!(checkpoint, 100);
}

#[test]
fn complete_stream_checkpoint_stops_before_partial_final_block() {
    let checkpoint = complete_stream_checkpoint(3, 3, 100, [20_u64, 25, 25].into_iter());

    assert_eq!(checkpoint, 24);
}

#[test]
fn wallet_backfill_starts_after_indexed_checkpoint() {
    assert_eq!(wallet_backfill_from_block(99, 10), 100);
    assert_eq!(wallet_backfill_from_block(0, 10), 10);
}

#[test]
fn wallet_startup_warm_from_block_is_bounded_by_start_and_range() {
    assert_eq!(wallet_startup_warm_from_block(100, 110, 10), 101);
    assert_eq!(wallet_startup_warm_from_block(105, 110, 10), 105);
    assert_eq!(wallet_startup_warm_from_block(0, 3, 10), 0);
}

#[test]
fn historical_remote_target_stops_before_cached_warm_suffix() {
    assert_eq!(
        wallet_remote_target_before_cached_suffix(10_000, Some(9_501)),
        9_500
    );
    assert_eq!(
        wallet_remote_target_before_cached_suffix(10_000, None),
        10_000
    );
}

#[test]
fn open_ended_wallet_backfill_target_tracks_safe_head() {
    let mut cursor = test_wallet_backfill(100, true);

    cursor.refresh_target(105);
    assert_eq!(cursor.target_block, 105);

    cursor.refresh_target(103);
    assert_eq!(cursor.target_block, 105);
}

#[test]
fn fixed_wallet_backfill_target_does_not_follow_safe_head() {
    let mut cursor = test_wallet_backfill(100, false);

    cursor.refresh_target(105);

    assert_eq!(cursor.target_block, 100);
}

#[test]
fn zero_wallet_backfill_target_initializes_from_safe_head() {
    let mut cursor = test_wallet_backfill(0, false);

    cursor.refresh_target(105);

    assert_eq!(cursor.target_block, 105);
}

#[tokio::test]
async fn startup_sync_target_waits_for_safe_head_when_open_ended() {
    let (safe_head_tx, safe_head_rx) = watch::channel(0);
    let cancel = CancellationToken::new();
    let waiter = wait_for_startup_sync_target(safe_head_rx, None, 0, &cancel);

    safe_head_tx.send(123).expect("send safe head");

    assert_eq!(waiter.await, Some(123));
}

#[tokio::test]
async fn startup_sync_target_uses_existing_fixed_target_without_waiting() {
    let (_safe_head_tx, safe_head_rx) = watch::channel(0);
    let cancel = CancellationToken::new();

    assert_eq!(
        wait_for_startup_sync_target(safe_head_rx, Some(900), 900, &cancel).await,
        Some(900)
    );
}

#[test]
fn squid_tail_after_artifact_continues_only_when_squid_covers_more_blocks() {
    assert_eq!(
        squid_tail_target_after_artifact(151, 150, 200, 180),
        Some(180)
    );
    assert_eq!(
        squid_tail_target_after_artifact(151, 150, 200, 250),
        Some(200)
    );
    assert_eq!(squid_tail_target_after_artifact(151, 150, 200, 150), None);
    assert_eq!(squid_tail_target_after_artifact(201, 150, 200, 250), None);
    assert_eq!(squid_tail_target_after_artifact(151, 200, 200, 250), None);
}

#[test]
fn artifact_failure_falls_back_to_squid_only_before_checkpoint() {
    assert!(artifact_failure_can_fallback_to_squid(true, 99, 99));
    assert!(!artifact_failure_can_fallback_to_squid(true, 100, 99));
    assert!(!artifact_failure_can_fallback_to_squid(false, 99, 99));
}

#[test]
fn wallet_reorg_backfill_starts_after_forest_reset() {
    assert_eq!(wallet_reorg_backfill_from_block(250, 100), 250);
    assert_eq!(wallet_reorg_backfill_from_block(50, 100), 100);
}

#[test]
fn pending_tip_sticks_to_slightly_lagging_wallet_progress() {
    assert_eq!(pending_tip_from_block(1_000, 995, 500), 996);
    assert_eq!(pending_tip_from_block(1_000, 1_000, 500), 1_001);
    assert_eq!(pending_tip_from_block(1_000, 1_001, 500), 1_001);
}

#[test]
fn pending_tip_does_not_expand_to_historical_wallet_lag() {
    assert_eq!(pending_tip_from_block(1_000, 100, 500), 1_001);
}

#[test]
fn pending_tip_provider_must_cover_target() {
    assert!(pending_tip_provider_covers_target(1_010, 1_010));
    assert!(pending_tip_provider_covers_target(1_011, 1_010));
    assert!(!pending_tip_provider_covers_target(1_009, 1_010));
}

#[test]
fn wallet_sync_target_caps_to_debug_block() {
    assert_eq!(wallet_sync_target(1_000, None), 1_000);
    assert_eq!(wallet_sync_target(1_000, Some(900)), 900);
    assert_eq!(wallet_sync_target(1_000, Some(1_100)), 1_000);
    assert_eq!(wallet_sync_target(0, Some(900)), 900);
}

#[test]
fn forest_reorg_decision_skips_without_comparable_hashes() {
    assert_eq!(
        ForestReorgDecision::from_confirmed_hash(100, 100, [0u8; 32], Some([1u8; 32])),
        ForestReorgDecision::Skip
    );
    assert_eq!(
        ForestReorgDecision::from_confirmed_hash(100, 99, [1u8; 32], Some([2u8; 32])),
        ForestReorgDecision::Skip
    );
    assert_eq!(
        ForestReorgDecision::from_confirmed_hash(100, 100, [1u8; 32], None),
        ForestReorgDecision::Skip
    );
}

#[test]
fn forest_reorg_decision_requires_confirmed_mismatch() {
    assert_eq!(
        ForestReorgDecision::from_confirmed_hash(100, 100, [1u8; 32], Some([1u8; 32])),
        ForestReorgDecision::Match
    );
    assert_eq!(
        ForestReorgDecision::from_confirmed_hash(100, 100, [1u8; 32], Some([2u8; 32])),
        ForestReorgDecision::Mismatch
    );
}

#[tokio::test]
async fn forest_meta_check_reads_matching_hash_once_and_rewinds_only_on_agreeing_pair() {
    let scope = test_scope();
    let stored_hash = [0x11; 32];
    for (hash_bytes, expected, reads) in [
        (vec![0x11], ForestMetaCheck::Match, 1),
        (
            vec![0xaa, 0xaa],
            ForestMetaCheck::Mismatch {
                current_hash: [0xaa; 32],
            },
            2,
        ),
        (vec![0xaa, 0xbb, 0xbb], ForestMetaCheck::Unconfirmed, 2),
    ] {
        let queue = std::sync::Mutex::new(std::collections::VecDeque::from(hash_bytes.clone()));
        let rpc = JsonRpcServer::spawn_handler(move |request: &serde_json::Value| {
            let block_number = hex_quantity(&request["params"][0]);
            let block = queue
                .lock()
                .expect("hash queue")
                .pop_front()
                .map(|hash_byte| {
                    rpc_block(block_number, test_block_timestamp(block_number), hash_byte)
                });
            serde_json::json!({ "result": block })
        });
        let chain = log_fetch_chain(&scope, rpc.url.clone(), 100);
        let provider = chain.rpcs.random_provider().expect("rpc provider");

        let check = chain
            .check_forest_meta(&provider.provider, None, 120, stored_hash, 120)
            .await
            .expect("check forest meta");

        let bodies = rpc.drain_request_bodies();
        assert_eq!(check, expected, "responses {hash_bytes:x?}");
        assert_eq!(bodies.len(), reads, "responses {hash_bytes:x?}");
        assert_eq!(header_blocks(&bodies), vec![120; reads]);
    }
}

#[test]
fn wallet_startup_hedge_is_limited_to_one_rpc_range() {
    assert_eq!(wallet_startup_hedge_block_count(100, 10, 110), Some(10));
    assert!(should_hedge_wallet_startup(100, 10, 110, 10));
    assert!(!should_hedge_wallet_startup(100, 10, 111, 10));
    assert!(!should_hedge_wallet_startup(100, 10, 0, 10));
    assert!(!should_hedge_wallet_startup(100, 10, 110, 0));
    assert!(!should_hedge_wallet_startup(110, 10, 110, 10));
}

#[test]
fn combined_log_event_signatures_cover_homogeneous_ranges() {
    let legacy = combined_log_event_signatures_for_range(10, 99, 100, 200)
        .expect("legacy range can be combined");
    assert_eq!(legacy.len(), 4);
    assert!(legacy.contains(&CommitmentBatch::SIGNATURE_HASH));
    assert!(legacy.contains(&GeneratedCommitmentBatch::SIGNATURE_HASH));
    assert!(legacy.contains(&Nullifiers::SIGNATURE_HASH));
    assert!(legacy.contains(&Nullified::SIGNATURE_HASH));

    let legacy_shield = combined_log_event_signatures_for_range(100, 200, 100, 200)
        .expect("legacy shield range can be combined");
    assert_eq!(legacy_shield.len(), 4);
    assert!(legacy_shield.contains(&Transact::SIGNATURE_HASH));
    assert!(legacy_shield.contains(&RailgunLegacyShieldEvents::Shield::SIGNATURE_HASH));
    assert!(legacy_shield.contains(&Nullifiers::SIGNATURE_HASH));
    assert!(legacy_shield.contains(&Nullified::SIGNATURE_HASH));

    let modern = combined_log_event_signatures_for_range(201, 300, 100, 200)
        .expect("modern range can be combined");
    assert_eq!(modern.len(), 4);
    assert!(modern.contains(&Transact::SIGNATURE_HASH));
    assert!(modern.contains(&Shield::SIGNATURE_HASH));
    assert!(modern.contains(&Nullifiers::SIGNATURE_HASH));
    assert!(modern.contains(&Nullified::SIGNATURE_HASH));
}

#[test]
fn combined_log_event_signatures_skip_boundary_crossing_ranges() {
    assert!(combined_log_event_signatures_for_range(99, 100, 100, 200).is_none());
    assert!(combined_log_event_signatures_for_range(200, 201, 100, 200).is_none());
}

#[test]
fn indexed_wallet_page_kind_is_legacy_only_before_v2_start() {
    assert_eq!(
        IndexedWalletPageKind::for_from_block(99, 100),
        IndexedWalletPageKind::Legacy
    );
    assert_eq!(
        IndexedWalletPageKind::for_from_block(100, 100),
        IndexedWalletPageKind::Modern
    );
    assert_eq!(
        IndexedWalletPageKind::for_from_block(99, 0),
        IndexedWalletPageKind::Modern
    );
}

#[test]
fn indexed_wallet_to_block_splits_at_v2_start() {
    assert_eq!(
        IndexedWalletPageKind::Legacy.to_block(50, 200_000, 100, 300_000),
        99
    );
    assert_eq!(
        IndexedWalletPageKind::Modern.to_block(100, 200_000, 100, 300_000),
        200_000
    );
    assert_eq!(
        IndexedWalletPageKind::Legacy.to_block(50, 60, 100, 300_000),
        60
    );
}

#[test]
fn indexed_wallet_to_block_uses_configured_range() {
    assert_eq!(
        IndexedWalletPageKind::Modern.to_block(100, 10_000_000, 0, 1_000_000),
        1_000_099
    );
    assert_eq!(
        IndexedWalletPageKind::Modern.to_block(100, 10_000_000, 0, 5_000_000),
        5_000_099
    );
}

#[tokio::test]
async fn txid_background_waits_for_wallet_ready() {
    let (ready_tx, ready_rx) =
        tokio::sync::watch::channel(test_wallet_observation(WalletReadiness::Syncing));
    let cancel = tokio_util::sync::CancellationToken::new();
    let task = tokio::spawn(wait_for_wallet_ready(ready_rx, cancel));

    tokio::task::yield_now().await;
    assert!(!task.is_finished());

    ready_tx
        .send(test_wallet_observation(WalletReadiness::Ready))
        .expect("ready receiver");
    let ready = tokio::time::timeout(std::time::Duration::from_secs(1), task)
        .await
        .expect("ready wait completed")
        .expect("ready task completed");
    assert!(ready);
}

#[tokio::test]
async fn txid_background_wait_exits_when_wallet_cancelled() {
    let (_ready_tx, ready_rx) =
        tokio::sync::watch::channel(test_wallet_observation(WalletReadiness::Syncing));
    let cancel = tokio_util::sync::CancellationToken::new();
    let task = tokio::spawn(wait_for_wallet_ready(ready_rx, cancel.clone()));

    cancel.cancel();
    let ready = tokio::time::timeout(std::time::Duration::from_secs(1), task)
        .await
        .expect("ready wait completed")
        .expect("ready task completed");
    assert!(!ready);
}

#[tokio::test]
async fn txid_background_wait_survives_recoverable_wallet_failure() {
    let (ready_tx, ready_rx) =
        tokio::sync::watch::channel(test_wallet_observation(WalletReadiness::Syncing));
    let cancel = tokio_util::sync::CancellationToken::new();
    let task = tokio::spawn(wait_for_wallet_ready(ready_rx, cancel));

    ready_tx
        .send(test_wallet_observation(WalletReadiness::Failed(
            WalletReadinessError::BackfillUnavailable,
        )))
        .expect("ready receiver");
    tokio::task::yield_now().await;
    assert!(!task.is_finished());

    ready_tx
        .send(test_wallet_observation(WalletReadiness::Ready))
        .expect("ready receiver");
    let ready = tokio::time::timeout(std::time::Duration::from_secs(1), task)
        .await
        .expect("ready wait completed")
        .expect("ready task completed");
    assert!(ready);
}

#[tokio::test]
async fn txid_background_wait_exits_when_wallet_shuts_down() {
    let (ready_tx, ready_rx) =
        tokio::sync::watch::channel(test_wallet_observation(WalletReadiness::Syncing));
    let cancel = tokio_util::sync::CancellationToken::new();
    let task = tokio::spawn(wait_for_wallet_ready(ready_rx, cancel));

    ready_tx
        .send(test_wallet_observation(WalletReadiness::Shutdown))
        .expect("ready receiver");
    let ready = tokio::time::timeout(std::time::Duration::from_secs(1), task)
        .await
        .expect("ready wait completed")
        .expect("ready task completed");
    assert!(!ready);
}

#[test]
fn wallet_apply_result_accepted_progress_advances_only_committed_results() {
    assert_eq!(
        WalletBackfillApplyResult::Committed { committed_to: 105 }.accepted_committed_to(),
        Some(105)
    );
    assert_eq!(
        WalletBackfillApplyResult::AlreadyCovered { committed_to: 105 }.accepted_committed_to(),
        Some(105)
    );
    assert_eq!(
        WalletBackfillApplyResult::Rejected {
            committed_to: 999,
            reason: WalletBackfillRejectReason::Shutdown,
        }
        .accepted_committed_to(),
        None
    );
}

#[test]
fn rpc_and_indexed_wallet_scan_applies_use_normalized_rows() {
    let read_scope = PublicScanReadScope::new(PublicDataPlaneEpoch::new(0));
    let batch = Arc::new(LogBatch {
        from_block: 10,
        to_block: 20,
        logs: Vec::new(),
        block_timestamps: HashMap::new(),
        to_block_hash: Some([7; 32]),
        read_scope,
    });

    let rpc_apply = WalletScanApply::rows_from_log_batch(10, 20, &batch, PublicScanSource::Rpc)
        .expect("normalize RPC rows");
    let indexed_apply = WalletScanApply::indexed_rows(
        10,
        20,
        WalletScanInputRows::default(),
        read_scope,
        WalletIndexedCatchUpSource::Squid,
    );

    assert!(matches!(
        &rpc_apply.rows.payload,
        WalletScanRowsPayload::Rows(_)
    ));
    assert!(matches!(
        &indexed_apply.rows.payload,
        WalletScanRowsPayload::Rows(_)
    ));
    assert_eq!(rpc_apply.rows.to_block_hash, Some([7; 32]));
    assert_eq!(indexed_apply.rows.to_block_hash, None);
}

#[tokio::test]
async fn wallet_send_helpers_reject_when_worker_channel_closed() {
    let (sender, receiver) = mpsc::channel(1);
    drop(receiver);
    let batch = Arc::new(LogBatch {
        from_block: 101,
        to_block: 105,
        logs: Vec::new(),
        block_timestamps: HashMap::new(),
        to_block_hash: None,
        read_scope: PublicScanReadScope::new(PublicDataPlaneEpoch::new(0)),
    });
    let token = test_sync_token(0, 1);

    assert_eq!(
        send_wallet_scan_apply(
            "test",
            &sender,
            WalletScanApply::rows_from_log_batch(101, 105, &batch, PublicScanSource::Rpc)
                .expect("normalize empty log payload"),
            token,
        )
        .await,
        WalletBackfillApplyResult::Rejected {
            committed_to: 104,
            reason: WalletBackfillRejectReason::Shutdown,
        }
    );
    assert_eq!(
        send_wallet_target("test", &sender, 105, token).await,
        WalletBackfillStartResult::Rejected {
            committed_to: 104,
            reason: WalletBackfillRejectReason::Shutdown,
        }
    );
}

fn test_wallet_backfill(target_block: u64, follow_safe_head: bool) -> WalletBackfill {
    let (sender, _receiver) = mpsc::channel(1);
    WalletBackfill::new(
        100,
        target_block,
        follow_safe_head,
        100,
        None,
        test_backfill_driver(sender, 0, 1),
        std::time::Instant::now(),
    )
}

fn test_wallet_observation(readiness: WalletReadiness) -> WalletObservation {
    let view = if readiness == WalletReadiness::Shutdown {
        WalletViewState::Inactive {
            reason: WalletInactiveReason::Shutdown,
            reset_generation: 0,
        }
    } else {
        WalletViewState::Current(WalletCurrentSnapshot::new(
            0,
            0,
            0,
            Arc::<[WalletUtxo]>::from(Vec::new()),
            Arc::new(WalletPendingOverlay::default()),
        ))
    };
    WalletObservation::new(view, readiness)
}

async fn send_wallet_scan_apply(
    cache_key: &str,
    sender: &mpsc::Sender<BackfillEvent>,
    apply: WalletScanApply,
    token: WalletSyncToken,
) -> WalletBackfillApplyResult {
    WalletBackfillDriver::from_token(token, sender.clone())
        .apply(cache_key, apply)
        .await
}
