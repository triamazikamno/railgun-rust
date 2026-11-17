use super::*;
use std::sync::{
    Arc,
    atomic::{AtomicU64, Ordering},
    mpsc,
};
use std::time::Duration;

fn test_actor_state(last_scanned: u64) -> (WalletActorState, watch::Receiver<WalletObservation>) {
    WalletActorState::new(
        1,
        1,
        0,
        last_scanned,
        0,
        None,
        false,
        WalletViewState::Current(crate::types::WalletCurrentSnapshot::new(
            last_scanned,
            0,
            0,
            Arc::<[railgun_wallet::WalletUtxo]>::from(Vec::new()),
            Arc::new(crate::types::WalletPendingOverlay::default()),
        )),
    )
}

#[test]
fn retire_poisons_terminal_shutdown_publish() {
    let cell = WalletActorLifecycleCell::new();
    assert!(cell.mark_stopping());
    cell.mark_retired(|| {});
    assert_eq!(cell.get(), WalletActorLifecycle::Retired);
    assert!(!cell.publish_terminal_shutdown_if_allowed(true, |_token| {
        panic!("retired actor must not publish terminal shutdown");
    }));
}

#[test]
fn terminal_shutdown_publish_runs_under_fence_once() {
    let cell = WalletActorLifecycleCell::new();
    assert!(cell.mark_stopping());
    let mut published = 0_u32;
    assert!(cell.publish_terminal_shutdown_if_allowed(true, |_token| {
        published += 1;
    }));
    assert_eq!(published, 1);
    assert!(!cell.publish_terminal_shutdown_if_allowed(true, |_token| {
        published += 1;
    }));
    assert_eq!(published, 1);
}

#[test]
fn observation_publication_preserves_workflow_and_terminal_clears_submission_projection() {
    let initial_view = WalletViewState::Current(crate::types::WalletCurrentSnapshot::new(
        7,
        0,
        0,
        Arc::<[railgun_wallet::WalletUtxo]>::from(Vec::new()),
        Arc::new(crate::types::WalletPendingOverlay::default()),
    ));
    let (publisher, receiver) = WalletObservationPublisher::new(initial_view);
    assert_eq!(
        receiver.borrow().ppoi_workflow_status(),
        &WalletPpoiWorkflowStatus::default()
    );
    let status = WalletPpoiWorkflowStatus {
        awaiting_recovery: 5,
        awaiting_public_txid_data: 0,
        awaiting_poi_data: 0,
        retrying_recovery: 0,
        recovery_needs_attention: 0,
        awaiting_submission: 1,
        awaiting_validation: 2,
        needs_attention: 3,
        validation_revision: 4,
    };
    let submissions: Arc<[WalletPpoiSubmissionStatus]> =
        Arc::from(vec![WalletPpoiSubmissionStatus {
            output_commitment: alloy::primitives::FixedBytes::from([0x42; 32]),
            last_submission_at: 17,
        }]);
    publisher.publish_ppoi_workflow_projection(status, submissions.clone());
    publisher.publish_readiness(WalletReadiness::Failed(WalletReadinessError::ApplyFailed));
    assert_eq!(
        receiver.borrow().ppoi_submission_statuses(),
        submissions.as_ref()
    );
    publisher.publish_view(WalletViewState::ResetPending {
        intent_id: 1,
        from_block: 5,
        reset_generation: 1,
    });
    assert_eq!(
        receiver.borrow().ppoi_submission_statuses(),
        [] as [WalletPpoiSubmissionStatus; 0]
    );
    publisher.publish(
        WalletViewState::Current(crate::types::WalletCurrentSnapshot::new(
            9,
            1,
            1,
            Arc::<[railgun_wallet::WalletUtxo]>::from(Vec::new()),
            Arc::new(crate::types::WalletPendingOverlay::default()),
        )),
        WalletReadiness::Syncing,
    );
    assert_eq!(receiver.borrow().ppoi_workflow_status(), &status);
    assert_eq!(
        receiver.borrow().ppoi_submission_statuses(),
        [] as [WalletPpoiSubmissionStatus; 0]
    );

    publisher.publish_terminal(WalletInactiveReason::Shutdown, 1);
    assert_eq!(
        receiver.borrow().ppoi_workflow_status(),
        &WalletPpoiWorkflowStatus {
            validation_revision: 4,
            ..WalletPpoiWorkflowStatus::default()
        }
    );
    assert_eq!(
        receiver.borrow().ppoi_submission_statuses(),
        [] as [WalletPpoiSubmissionStatus; 0]
    );
}

#[test]
fn retire_flips_identity_under_same_fence_as_state() {
    let cell = WalletActorLifecycleCell::new();
    let actor_id = AtomicU64::new(7);
    cell.mark_retired(|| {
        actor_id.store(0, Ordering::Release);
    });
    assert_eq!(cell.get(), WalletActorLifecycle::Retired);
    assert_eq!(actor_id.load(Ordering::Acquire), 0);
}

#[test]
fn active_apply_rejects_after_retire() {
    let cell = WalletActorLifecycleCell::new();
    assert!(
        cell.with_active_apply(true, |_token| 1_u32)
            .is_ok_and(|v| v == 1)
    );
    cell.mark_retired(|| {});
    assert!(cell.with_active_apply(true, |_token| 2_u32).is_err());
}

#[test]
fn retire_waits_for_in_flight_durable_apply_and_fences_later_applies() {
    let cell = Arc::new(WalletActorLifecycleCell::new());
    let (apply_started_tx, apply_started_rx) = mpsc::channel();
    let (release_apply_tx, release_apply_rx) = mpsc::channel();
    let apply_cell = Arc::clone(&cell);
    let apply = std::thread::spawn(move || {
        apply_cell
            .with_active_apply(true, |_token| {
                apply_started_tx.send(()).expect("signal active apply");
                release_apply_rx.recv().expect("release active apply");
            })
            .expect("active apply accepted");
    });
    apply_started_rx.recv().expect("active apply started");

    let (retire_started_tx, retire_started_rx) = mpsc::channel();
    let (retired_tx, retired_rx) = mpsc::channel();
    let retire_cell = Arc::clone(&cell);
    let retire = std::thread::spawn(move || {
        retire_started_tx.send(()).expect("signal retire attempt");
        retire_cell.mark_retired(|| {});
        retired_tx.send(()).expect("signal retirement");
    });
    retire_started_rx.recv().expect("retire attempt started");
    assert!(retired_rx.recv_timeout(Duration::from_millis(25)).is_err());

    release_apply_tx.send(()).expect("release durable apply");
    apply.join().expect("join active apply");
    retired_rx
        .recv_timeout(Duration::from_secs(1))
        .expect("retirement completed");
    retire.join().expect("join retirement");
    assert_eq!(cell.get(), WalletActorLifecycle::Retired);
    assert!(cell.with_active_apply(true, |_token| ()).is_err());
}

#[test]
fn active_apply_rejects_when_not_current() {
    let cell = WalletActorLifecycleCell::new();
    assert!(cell.with_active_apply(false, |_token| ()).is_err());
}

#[test]
fn actor_transition_publishes_derived_readiness_without_duplicate_notifications() {
    let (mut state, mut readiness_rx) = test_actor_state(10);
    let token = WalletSyncToken::for_test(1, 1, 0, 1);

    state.test_transition(|mut state| {
        assert!(state.accept_target(token, 10));
        assert!(state.complete_backfill_job(token));
    });
    assert_eq!(
        readiness_rx.borrow_and_update().readiness(),
        &WalletReadiness::Ready
    );

    state.test_transition(|mut state| {
        state.durable_poi_status_commit_ok(0, WalletPoiRefreshSelection::Required);
    });
    assert!(
        !readiness_rx
            .has_changed()
            .expect("readiness sender remains active")
    );
}

#[test]
fn persistence_recovery_requires_matching_operation_or_cursor_coverage() {
    let (mut state, readiness_rx) = test_actor_state(100);
    let live = WalletSyncToken::for_test(1, 1, 0, 1);
    let unrelated = WalletSyncToken::for_test(1, 1, 0, 2);
    state.test_transition(|mut state| {
        assert!(state.accept_target(live, 101));
        assert!(state.accept_target(unrelated, 101));
        assert!(state.sync_progress_persist_failed(live, 101, 101));
    });
    assert_eq!(state.test_persistence_range_for(live), Some((101, 101)));
    assert_eq!(
        readiness_rx.borrow().readiness(),
        &WalletReadiness::Failed(WalletReadinessError::PersistenceFailed)
    );

    state.test_transition(|mut state| {
        state.durable_poi_status_commit_ok(0, WalletPoiRefreshSelection::Required);
        assert!(!state.durable_backfill_completion_commit_ok(live));
        assert!(!state.durable_backfill_completion_commit_ok(unrelated));
        assert!(state.retire_job(live));
    });
    assert_eq!(state.test_persistence_range_for(live), Some((101, 101)));
    assert_eq!(
        readiness_rx.borrow().readiness(),
        &WalletReadiness::Failed(WalletReadinessError::PersistenceFailed)
    );

    state.test_transition(|mut state| {
        assert!(state.durable_sync_progress_commit_ok(unrelated, 101, 101));
        assert!(state.complete_backfill_job(unrelated));
    });
    assert_eq!(readiness_rx.borrow().readiness(), &WalletReadiness::Ready);
}

#[test]
fn operation_failure_recovers_only_from_matching_operation() {
    let (mut state, readiness_rx) = test_actor_state(100);
    let completed = WalletSyncToken::for_test(1, 1, 0, 1);
    state.test_transition(|mut state| {
        assert!(state.accept_target(completed, 100));
        assert!(state.complete_backfill_job(completed));
        state.poi_status_persist_failed(0, WalletPoiRefreshSelection::Required);
    });
    assert_eq!(
        readiness_rx.borrow().readiness(),
        &WalletReadiness::Failed(WalletReadinessError::PersistenceFailed)
    );

    state.test_transition(|mut state| state.durable_reset_replay_commit_ok(7));
    assert_eq!(
        readiness_rx.borrow().readiness(),
        &WalletReadiness::Failed(WalletReadinessError::PersistenceFailed)
    );

    state.test_transition(|mut state| {
        state.durable_poi_status_commit_ok(0, WalletPoiRefreshSelection::Recoverable);
        state.durable_poi_status_commit_ok(1, WalletPoiRefreshSelection::Required);
    });
    assert_eq!(
        readiness_rx.borrow().readiness(),
        &WalletReadiness::Failed(WalletReadinessError::PersistenceFailed)
    );

    state.test_transition(|mut state| {
        state.durable_poi_status_commit_ok(0, WalletPoiRefreshSelection::Required);
    });
    assert_eq!(readiness_rx.borrow().readiness(), &WalletReadiness::Ready);
}

#[test]
fn contiguous_cursor_coverage_recovers_failed_progress_from_another_job() {
    let (mut state, readiness_rx) = test_actor_state(100);
    let failed = WalletSyncToken::for_test(1, 1, 0, 1);
    let covering = WalletSyncToken::for_test(1, 1, 0, 2);
    state.test_transition(|mut state| {
        assert!(state.accept_target(failed, 101));
        assert!(state.sync_progress_persist_failed(failed, 101, 101));
        assert!(state.accept_target(covering, 101));
        assert!(state.durable_sync_progress_commit_ok(covering, 101, 101));
    });

    assert_eq!(state.test_persistence_range_for(failed), None);
    assert!(!state.has_persistence_failure());
    assert_eq!(readiness_rx.borrow().readiness(), &WalletReadiness::Syncing);
}

#[test]
fn failed_progress_survives_retirement_until_covering_successor_commit() {
    let (mut state, readiness_rx) = test_actor_state(100);
    let failed = WalletSyncToken::for_test(1, 1, 0, 1);
    let successor = WalletSyncToken::for_test(1, 1, 0, 2);
    state.test_transition(|mut state| {
        assert!(state.accept_target(failed, 101));
        assert!(state.sync_progress_persist_failed(failed, 101, 101));
        assert!(state.accept_target(successor, 101));
        assert!(state.retire_job(failed));
    });

    assert_eq!(state.test_persistence_range_for(failed), Some((101, 101)));
    assert_eq!(
        state.test_persistence_range_for(successor),
        Some((101, 101))
    );
    assert_eq!(
        readiness_rx.borrow().readiness(),
        &WalletReadiness::Failed(WalletReadinessError::PersistenceFailed)
    );

    state.test_transition(|mut state| {
        assert!(state.durable_sync_progress_commit_ok(successor, 101, 101));
        assert!(state.complete_backfill_job(successor));
    });
    assert_eq!(readiness_rx.borrow().readiness(), &WalletReadiness::Ready);
}

#[test]
fn poi_failure_rebases_through_reset_and_requires_current_generation_recovery() {
    let (mut state, readiness_rx) = test_actor_state(100);
    let selection = WalletPoiRefreshSelection::Required;
    state.test_transition(|mut state| state.poi_status_persist_failed(0, selection));

    let pending = PendingWalletReset::new(7, 90, 1, WalletResetReplayPlan::new(0, 120, false));
    state.test_transition(|mut state| state.accept_reset(pending));
    assert!(!state.has_failed_poi_status_refresh(0, selection));
    assert!(state.has_failed_poi_status_refresh(1, selection));

    state.test_transition(|mut state| state.mark_pending_reset_rewind_committed(89));
    assert!(state.has_failed_poi_status_refresh(1, selection));
    assert_eq!(
        readiness_rx.borrow().readiness(),
        &WalletReadiness::Failed(WalletReadinessError::PersistenceFailed)
    );

    state.test_transition(|mut state| state.durable_poi_status_commit_ok(0, selection));
    assert!(state.has_failed_poi_status_refresh(1, selection));

    // The same exact method is used after durable success or complete current-state
    // obsolescence proof; only the rebased generation may discharge the requirement.
    state.test_transition(|mut state| state.durable_poi_status_commit_ok(1, selection));
    assert!(!state.has_persistence_failure());
}

#[test]
fn poi_failure_selections_are_isolated_bounded_and_merged() {
    let (mut state, _) = test_actor_state(100);
    state.test_transition(|mut state| {
        state.poi_status_persist_failed(0, WalletPoiRefreshSelection::Required);
        state.poi_status_persist_failed(0, WalletPoiRefreshSelection::RequiredOrRecoverable);
        state.poi_status_persist_failed(0, WalletPoiRefreshSelection::RecoverableStale { now: 10 });
        state.poi_status_persist_failed(0, WalletPoiRefreshSelection::RecoverableStale { now: 20 });
        state.poi_status_persist_failed(0, WalletPoiRefreshSelection::Recoverable);
        state.poi_status_persist_failed(
            0,
            WalletPoiRefreshSelection::CorpusRevision {
                blocked_shields_changed: false,
            },
        );
        state.poi_status_persist_failed(
            0,
            WalletPoiRefreshSelection::CorpusRevision {
                blocked_shields_changed: true,
            },
        );
    });

    assert_eq!(state.test_poi_requirement_count(), 5);
    assert_eq!(
        state.failed_poi_status_refresh_selection(0),
        Some(WalletPoiRefreshSelection::Required)
    );
    assert!(
        !state.has_failed_poi_status_refresh(
            0,
            WalletPoiRefreshSelection::RecoverableStale { now: 10 }
        )
    );
    assert!(
        state.has_failed_poi_status_refresh(
            0,
            WalletPoiRefreshSelection::RecoverableStale { now: 20 }
        )
    );
    assert!(state.has_failed_poi_status_refresh(
        0,
        WalletPoiRefreshSelection::CorpusRevision {
            blocked_shields_changed: true,
        }
    ));

    for now in 21..1000 {
        state.test_transition(|mut state| {
            state.poi_status_persist_failed(0, WalletPoiRefreshSelection::RecoverableStale { now });
        });
    }
    assert_eq!(state.test_poi_requirement_count(), 5);
    assert!(state.has_failed_poi_status_refresh(
        0,
        WalletPoiRefreshSelection::RecoverableStale { now: 999 }
    ));
}

#[test]
fn persistence_categories_recover_only_from_matching_proof() {
    let (mut state, _) = test_actor_state(100);
    let token = WalletSyncToken::for_test(1, 1, 0, 1);
    state.test_transition(|mut state| {
        assert!(state.accept_target(token, 110));
        assert!(state.sync_progress_persist_failed(token, 101, 110));
        assert!(state.backfill_completion_persist_failed(token));
        state.poi_status_persist_failed(0, WalletPoiRefreshSelection::Required);
        state.reset_replay_persist_failed(7);
    });

    state.test_transition(|mut state| state.durable_reset_replay_commit_ok(7));
    assert_eq!(state.test_reset_replay_requirement(), None);
    assert_eq!(state.test_persistence_range_for(token), Some((101, 110)));
    assert_eq!(state.test_completion_requirement(), Some((token, 110)));
    assert!(state.has_failed_poi_status_refresh(0, WalletPoiRefreshSelection::Required));

    state.test_transition(|mut state| {
        state.durable_poi_status_commit_ok(0, WalletPoiRefreshSelection::Required);
    });
    assert_eq!(state.test_persistence_range_for(token), Some((101, 110)));
    assert_eq!(state.test_completion_requirement(), Some((token, 110)));
}

#[test]
fn reset_replay_progress_start_is_owned_by_its_admitted_job() {
    let (mut state, _) = test_actor_state(100);
    let replay = WalletSyncToken::for_test(1, 1, 0, 1);
    let other = WalletSyncToken::for_test(1, 1, 0, 2);
    state.test_transition(|mut state| {
        assert!(state.accept_target(replay, 200));
        state.set_pending_reset_replay_admitted(Some((replay, 150)));
    });

    assert_eq!(state.progress_start_block(replay), Some(150));
    assert_eq!(state.progress_start_block(other), None);

    state.test_transition(|mut state| state.clear_pending_reset());
    assert_eq!(state.progress_start_block(replay), Some(150));

    state.test_transition(|mut state| assert!(state.retire_job(replay)));
    assert_eq!(state.progress_start_block(replay), None);
}

#[test]
fn completion_failure_survives_driver_loss_until_covering_completion() {
    let (mut state, readiness_rx) = test_actor_state(100);
    let failed = WalletSyncToken::for_test(1, 1, 0, 1);
    state.test_transition(|mut state| {
        assert!(state.accept_target(failed, 110));
        assert!(state.backfill_completion_persist_failed(failed));
        assert!(state.fail_job_backfill_unavailable(failed));
    });
    assert_eq!(state.test_completion_requirement(), Some((failed, 110)));
    assert_eq!(state.test_active_job_count(), 0);
    assert_eq!(
        readiness_rx.borrow().readiness(),
        &WalletReadiness::Failed(WalletReadinessError::PersistenceFailed)
    );

    let replacement = WalletSyncToken::for_test(1, 1, 0, 2);
    state.test_transition(|mut state| {
        assert!(state.accept_target(replacement, 110));
        assert!(state.backfill_dispatch_admitted(replacement));
        assert!(state.durable_sync_progress_commit_ok(replacement, 101, 110));
        assert!(state.durable_backfill_completion_commit_ok(replacement));
        assert!(state.complete_backfill_job(replacement));
    });
    assert_eq!(state.test_completion_requirement(), None);
    assert_eq!(readiness_rx.borrow().readiness(), &WalletReadiness::Ready);
}

#[test]
fn multiple_job_faults_coexist_and_covering_dispatch_clears_only_covered_faults() {
    let (mut state, readiness_rx) = test_actor_state(100);
    let first = WalletSyncToken::for_test(1, 1, 0, 1);
    let second = WalletSyncToken::for_test(1, 1, 0, 2);
    state.test_transition(|mut state| {
        assert!(state.accept_target(first, 150));
        assert!(state.fail_job_backfill_unavailable(first));
        assert!(state.accept_target(second, 200));
        assert!(state.fail_job_apply_failed(second));
    });
    assert_eq!(state.test_job_failure_count(), 2);
    assert!(state.test_has_job_failure(first));
    assert!(state.test_has_job_failure(second));
    assert_eq!(
        readiness_rx.borrow().readiness(),
        &WalletReadiness::Failed(WalletReadinessError::BackfillUnavailable)
    );

    let partial = WalletSyncToken::for_test(1, 1, 0, 3);
    state.test_transition(|mut state| {
        assert!(state.accept_target(partial, 150));
        assert!(state.backfill_dispatch_admitted(partial));
    });
    assert_eq!(state.test_job_failure_count(), 1);
    assert!(!state.test_has_job_failure(first));
    assert!(state.test_has_job_failure(second));
    assert_eq!(
        readiness_rx.borrow().readiness(),
        &WalletReadiness::Failed(WalletReadinessError::ApplyFailed)
    );

    let covering = WalletSyncToken::for_test(1, 1, 0, 4);
    state.test_transition(|mut state| {
        assert!(state.accept_target(covering, 200));
        assert!(state.backfill_dispatch_admitted(covering));
    });
    assert_eq!(state.test_job_failure_count(), 0);
}

#[test]
fn job_failure_reason_type_has_no_persistence_variant() {
    let reasons = [
        WalletJobFailureReason::BackfillUnavailable,
        WalletJobFailureReason::TargetNotReached { target_block: 10 },
        WalletJobFailureReason::ApplyFailed,
    ];
    assert!(
        reasons
            .into_iter()
            .all(|reason| { reason.readiness_error() != WalletReadinessError::PersistenceFailed })
    );
}

#[test]
fn reset_supersedes_old_generation_failures_but_rebases_poi() {
    let (mut state, readiness_rx) = test_actor_state(100);
    let token = WalletSyncToken::for_test(1, 1, 0, 1);
    state.test_transition(|mut state| {
        assert!(state.accept_target(token, 110));
        assert!(state.sync_progress_persist_failed(token, 101, 110));
        assert!(state.backfill_completion_persist_failed(token));
        state.poi_status_persist_failed(0, WalletPoiRefreshSelection::Required);
        state.reset_replay_persist_failed(6);
        assert!(state.fail_job_backfill_unavailable(token));
    });

    let pending = PendingWalletReset::new(7, 90, 1, WalletResetReplayPlan::new(0, 120, false));
    state.test_transition(|mut state| state.accept_reset(pending));
    assert_eq!(state.test_active_job_count(), 0);
    assert_eq!(state.test_job_failure_count(), 0);
    assert_eq!(state.test_persistence_range_for(token), None);
    assert_eq!(state.test_completion_requirement(), None);
    assert_eq!(state.test_reset_replay_requirement(), None);
    assert!(state.has_failed_poi_status_refresh(1, WalletPoiRefreshSelection::Required));

    state.test_transition(|mut state| state.mark_pending_reset_rewind_committed(89));
    assert!(state.has_failed_poi_status_refresh(1, WalletPoiRefreshSelection::Required));
    assert_eq!(
        readiness_rx.borrow().readiness(),
        &WalletReadiness::Failed(WalletReadinessError::PersistenceFailed)
    );
}

#[test]
fn terminal_shutdown_destroys_every_failure_category() {
    let (mut state, readiness_rx) = test_actor_state(100);
    let token = WalletSyncToken::for_test(1, 1, 0, 1);
    state.test_transition(|mut state| {
        assert!(state.accept_target(token, 110));
        assert!(state.sync_progress_persist_failed(token, 101, 110));
        assert!(state.backfill_completion_persist_failed(token));
        state.poi_status_persist_failed(0, WalletPoiRefreshSelection::Required);
        state.reset_replay_persist_failed(7);
        assert!(state.fail_job_backfill_unavailable(token));
    });

    let terminal = WalletActorTerminalToken {
        _fence: PhantomData,
    };
    state.transition_terminal_shutdown(&terminal, WalletInactiveReason::Shutdown, 0);

    assert!(!state.has_persistence_failure());
    assert_eq!(state.test_job_failure_count(), 0);
    assert_eq!(state.test_active_job_count(), 0);
    assert_eq!(
        readiness_rx.borrow().readiness(),
        &WalletReadiness::Shutdown
    );
}

// Compile-fail intent: token must not escape. If this compiled, HRTB is broken.
// fn token_cannot_escape() {
//     let cell = WalletActorLifecycleCell::new();
//     let _escaped = cell.with_active_apply(true, |token| token).unwrap();
// }
