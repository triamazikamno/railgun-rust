use std::collections::HashMap;
use std::sync::Arc;

use alloy::sol_types::SolEvent;
use tokio::sync::{mpsc, watch};
use tokio_util::sync::CancellationToken;

use super::service::{
    await_live_log_task_shutdown, wait_for_startup_sync_target, wait_for_wallet_ready,
};
use super::{
    CommitmentBatch, ForestReorgDecision, GeneratedCommitmentBatch, IndexedWalletArtifactProbe,
    IndexedWalletPageKind, Nullified, Nullifiers, RailgunLegacyShieldEvents, Shield, Transact,
    WalletBackfill, WalletTailFallbackState, artifact_failure_can_fallback_to_squid,
    combined_log_event_signatures_for_range, complete_stream_checkpoint,
    drain_pending_backfill_requests, pending_tip_from_block, pending_tip_provider_covers_target,
    send_wallet_startup_events, should_hedge_wallet_startup, squid_tail_target_after_artifact,
    wallet_backfill_from_block, wallet_backfill_lag_blocks, wallet_reorg_backfill_from_block,
    wallet_startup_hedge_block_count, wallet_sync_target,
    wallet_tail_fallback_lag_threshold_blocks,
};
use crate::types::{BackfillEvent, BackfillRequest, LogBatch, SyncProgressStage};

fn test_wallet_backfill(target_block: u64, follow_safe_head: bool) -> WalletBackfill {
    let (sender, _receiver) = mpsc::channel(1);
    WalletBackfill::new(
        100,
        target_block,
        follow_safe_head,
        100,
        0,
        None,
        sender,
        std::time::Instant::now(),
    )
}

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

#[test]
fn wallet_backfill_progress_tracks_cursor_range() {
    let (sender, _receiver) = mpsc::channel(1);
    let (progress_tx, progress_rx) = watch::channel(None);
    let mut cursor = WalletBackfill::new(
        100,
        0,
        false,
        100,
        0,
        Some(progress_tx),
        sender,
        std::time::Instant::now(),
    );

    cursor.send_progress(100);
    assert!(progress_rx.borrow().is_none());

    cursor.refresh_target(200);
    cursor.send_progress(150);

    let progress = (*progress_rx.borrow()).expect("progress update should be emitted");
    assert_eq!(progress.stage, SyncProgressStage::IndexingUtxos);
    assert_eq!(progress.start_block, 100);
    assert_eq!(progress.current_block, 150);
    assert_eq!(progress.target_block, 200);
}

#[test]
fn active_backfill_drains_reset_replacement_request() {
    let (request_tx, mut request_rx) = mpsc::channel(4);
    let (old_sender, _old_receiver) = mpsc::channel(1);
    let (new_sender, _new_receiver) = mpsc::channel(1);
    let mut cursors = HashMap::new();
    cursors.insert(
        "test".to_string(),
        WalletBackfill::new(
            100,
            1_000,
            true,
            100,
            0,
            None,
            old_sender,
            std::time::Instant::now(),
        ),
    );

    request_tx
        .try_send(BackfillRequest::Add {
            cache_key: "test".to_string(),
            from_block: 80,
            to_block: 150,
            follow_safe_head: true,
            progress_start_block: 80,
            reset_generation: 1,
            progress_tx: None,
            sender: new_sender,
        })
        .expect("queue reset replacement backfill");

    drain_pending_backfill_requests(&mut request_rx, &mut cursors);

    let cursor = cursors.get("test").expect("cursor retained");
    assert_eq!(cursor.from_block, 80);
    assert_eq!(cursor.target_block, 150);
    assert!(cursor.follow_safe_head);
    assert_eq!(cursor.progress_start_block, 80);
    assert_eq!(cursor.reset_generation, 1);
}

#[test]
fn wallet_tail_fallback_thresholds_are_chain_specific() {
    assert_eq!(wallet_tail_fallback_lag_threshold_blocks(1), 10);
    assert_eq!(wallet_tail_fallback_lag_threshold_blocks(56), 15);
    assert_eq!(wallet_tail_fallback_lag_threshold_blocks(137), 22);
    assert_eq!(wallet_tail_fallback_lag_threshold_blocks(42161), 45);
}

#[test]
fn wallet_tail_fallback_requires_lag_stall_and_cooldown() {
    let now = std::time::Instant::now();
    let (sender, _receiver) = mpsc::channel(1);
    let mut cursor = WalletBackfill::new(
        100,
        160,
        true,
        100,
        0,
        None,
        sender,
        now - std::time::Duration::from_secs(20),
    );

    assert_eq!(
        wallet_backfill_lag_blocks(cursor.from_block, cursor.target_block),
        61
    );
    assert!(cursor.should_try_indexed_tail_fallback(
        42161,
        now,
        std::time::Duration::from_secs(15),
        std::time::Duration::from_secs(60),
    ));

    cursor.mark_indexed_tail_attempt(now);
    assert!(!cursor.should_try_indexed_tail_fallback(
        42161,
        now + std::time::Duration::from_secs(30),
        std::time::Duration::from_secs(15),
        std::time::Duration::from_secs(60),
    ));
    assert!(cursor.should_try_indexed_tail_fallback(
        42161,
        now + std::time::Duration::from_secs(60),
        std::time::Duration::from_secs(15),
        std::time::Duration::from_secs(60),
    ));

    cursor.mark_progress(150, now + std::time::Duration::from_secs(60));
    assert!(!cursor.should_try_indexed_tail_fallback(
        42161,
        now + std::time::Duration::from_secs(70),
        std::time::Duration::from_secs(15),
        std::time::Duration::from_secs(60),
    ));
}

#[test]
fn ready_wallet_tail_fallback_state_tracks_progress_and_cooldown() {
    let now = std::time::Instant::now();
    let mut state = WalletTailFallbackState::new(100, now - std::time::Duration::from_secs(20));

    assert!(state.should_try_indexed_tail_fallback(
        42161,
        101,
        160,
        now,
        std::time::Duration::from_secs(15),
        std::time::Duration::from_secs(60),
    ));

    state.mark_indexed_tail_attempt(now);
    assert!(!state.should_try_indexed_tail_fallback(
        42161,
        101,
        160,
        now + std::time::Duration::from_secs(30),
        std::time::Duration::from_secs(15),
        std::time::Duration::from_secs(60),
    ));

    state.update_last_scanned(130, now + std::time::Duration::from_secs(30));
    assert!(!state.should_try_indexed_tail_fallback(
        42161,
        131,
        190,
        now + std::time::Duration::from_secs(40),
        std::time::Duration::from_secs(15),
        std::time::Duration::from_secs(60),
    ));

    assert!(state.should_try_indexed_tail_fallback(
        42161,
        131,
        190,
        now + std::time::Duration::from_secs(90),
        std::time::Duration::from_secs(15),
        std::time::Duration::from_secs(60),
    ));
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
fn indexed_wallet_artifact_target_uses_lesser_of_artifact_height_and_safe_head() {
    let probe = IndexedWalletArtifactProbe {
        latest_indexed_block: 150,
        catalog_count: 1,
    };

    assert_eq!(probe.catch_up_target(200), 150);
    assert_eq!(probe.catch_up_target(120), 120);
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

#[test]
fn wallet_startup_hedge_is_limited_to_one_rpc_range() {
    assert_eq!(wallet_startup_hedge_block_count(100, 10, 110), Some(10));
    assert!(should_hedge_wallet_startup(100, 10, 110, 10, false));
    assert!(!should_hedge_wallet_startup(100, 10, 111, 10, false));
    assert!(!should_hedge_wallet_startup(100, 10, 0, 10, false));
    assert!(!should_hedge_wallet_startup(100, 10, 110, 0, false));
    assert!(!should_hedge_wallet_startup(110, 10, 110, 10, false));
    assert!(!should_hedge_wallet_startup(100, 10, 110, 10, true));
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
    let (ready_tx, ready_rx) = tokio::sync::watch::channel(false);
    let cancel = tokio_util::sync::CancellationToken::new();
    let task = tokio::spawn(wait_for_wallet_ready(ready_rx, cancel));

    tokio::task::yield_now().await;
    assert!(!task.is_finished());

    ready_tx.send(true).expect("ready receiver");
    let ready = tokio::time::timeout(std::time::Duration::from_secs(1), task)
        .await
        .expect("ready wait completed")
        .expect("ready task completed");
    assert!(ready);
}

#[tokio::test]
async fn txid_background_wait_exits_when_wallet_cancelled() {
    let (_ready_tx, ready_rx) = tokio::sync::watch::channel(false);
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
async fn chain_shutdown_waits_for_live_log_worker() {
    let (release_tx, release_rx) = tokio::sync::oneshot::channel::<()>();
    let task = tokio::spawn(async move {
        let _ = release_rx.await;
    });
    let live_log_task = Arc::new(tokio::sync::Mutex::new(Some(task)));
    let waiter_task = tokio::spawn({
        let live_log_task = Arc::clone(&live_log_task);
        async move {
            await_live_log_task_shutdown(live_log_task.as_ref(), 1).await;
        }
    });

    tokio::task::yield_now().await;
    assert!(!waiter_task.is_finished());

    release_tx.send(()).expect("release live log worker");
    tokio::time::timeout(std::time::Duration::from_secs(1), waiter_task)
        .await
        .expect("shutdown wait completed")
        .expect("shutdown task completed");
    assert!(live_log_task.lock().await.is_none());
}

#[tokio::test]
async fn wallet_startup_events_send_done_before_follow_safe_head_backfill_runs() {
    let (sender, mut receiver) = mpsc::channel(4);
    let batch = Arc::new(LogBatch {
        from_block: 101,
        to_block: 105,
        logs: Vec::new(),
        block_timestamps: HashMap::new(),
        to_block_hash: None,
    });

    let sent = send_wallet_startup_events(
        "test",
        vec![BackfillEvent::Logs(batch)],
        Some(105),
        7,
        &sender,
    )
    .await;

    assert!(sent);
    let Some(BackfillEvent::LogsAtGeneration {
        batch,
        reset_generation,
    }) = receiver.recv().await
    else {
        panic!("startup logs should be sent first");
    };
    assert_eq!(batch.to_block, 105);
    assert_eq!(reset_generation, 7);
    let Some(BackfillEvent::DoneAtGeneration {
        last_block,
        reset_generation,
    }) = receiver.recv().await
    else {
        panic!("startup done should be sent after logs");
    };
    assert_eq!(last_block, 105);
    assert_eq!(reset_generation, 7);
    assert!(receiver.try_recv().is_err());
}
