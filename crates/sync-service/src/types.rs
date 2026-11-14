mod backfill;
mod config;
mod poi_cache;
mod private_commit;
mod progress;
mod scan;
mod wallet_state;
mod wallet_store;

pub use backfill::{
    WalletBackfillApplyResult, WalletBackfillDriver, WalletBackfillFinishResult,
    WalletBackfillGrant, WalletBackfillRejectReason, WalletBackfillResetResult,
    WalletBackfillStartResult,
};
pub use config::{
    ChainConfig, ChainKey, DEFAULT_INDEXED_WALLET_BLOCK_RANGE, GlobalPoiPolicy,
    IndexedArtifactManifestSource, IndexedArtifactSourceConfig, PoiArtifactManifestSource,
    PoiArtifactSourceConfig, PoiProxyFallback, RailgunSyncOptions, WalletConfig,
};
pub use poi_cache::{
    PoiArtifactCacheAttemptId, PoiArtifactCacheFailureKind, PoiArtifactCacheGraphProgress,
    PoiArtifactCacheListProgress, PoiArtifactCachePhase, PoiArtifactCacheProgress,
};
pub use private_commit::{
    PendingOutputPoiContextIntent, WalletCheckpointMutation, WalletPrivateCommit,
    WalletSyncActorStateCommit, WalletUtxoMutation,
};
pub use progress::{
    PublicScanSource, SyncProgressSender, SyncProgressStage, SyncProgressUnit, SyncProgressUpdate,
    WalletIndexedCatchUpSource, WalletIndexedCatchUpStatus,
};
pub use scan::{LogBatch, PublicDataPlaneEpoch, PublicScanReadScope, SharedLogBatch};
pub use wallet_state::{
    WalletCurrentSnapshot, WalletInactiveReason, WalletObservation, WalletPendingOverlay,
    WalletPendingSpent, WalletPendingSpentMarkOutcome, WalletPpoiSubmissionStatus,
    WalletPpoiWorkflowStatus, WalletPrivateRequestError, WalletReadiness, WalletReadinessError,
    WalletReadinessWaitError, WalletResetRewindStatus, WalletSchedulableProgress, WalletViewState,
};
pub use wallet_store::WalletCacheStore;

pub(crate) use backfill::{
    BackfillEvent, BackfillRequest, WalletBackfillOwnerDisposition, WalletBackfillOwnerSignal,
    WalletResetReplayPlan, WalletResetToken, WalletSyncTargetLease, WalletSyncToken,
};
pub(crate) use poi_cache::{LocalPoiCaches, PoiCorpusRevision, WalletLocalPoiCaches};
pub(crate) use scan::{WalletScanApply, WalletScanRows, WalletScanRowsPayload};

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use super::{
        GlobalPoiPolicy, LocalPoiCaches, PoiArtifactCacheFailureKind,
        PoiArtifactCacheGraphProgress, PoiArtifactCachePhase, PoiArtifactCacheProgress,
        PoiArtifactManifestSource, PoiArtifactSourceConfig, PoiCorpusRevision, PoiProxyFallback,
        PublicScanSource, RailgunSyncOptions, SyncProgressStage, SyncProgressUnit,
        SyncProgressUpdate,
    };
    use alloy::primitives::FixedBytes;
    use poi::SensitiveUrl;
    use url::Url;

    fn sentinel_url(label: &str) -> SensitiveUrl {
        Url::parse(&format!(
            "https://user-{label}:password-{label}@host-{label}.invalid/path-{label}?query={label}#fragment-{label}"
        ))
        .expect("sentinel URL")
        .into()
    }

    fn assert_no_endpoint_sentinels(formatted: &str) {
        for sentinel in ["rpc-sentinel", "manifest-sentinel", "gateway-sentinel"] {
            assert!(
                !formatted.contains(sentinel),
                "endpoint leaked {sentinel}: {formatted}"
            );
        }
    }

    #[test]
    fn poi_policy_and_nested_artifact_debug_are_endpoint_safe() {
        let artifact_source = PoiArtifactSourceConfig {
            trusted_publisher_pubkey: FixedBytes::from([0x42; 32]),
            manifest_source: PoiArtifactManifestSource::Url(sentinel_url("manifest-sentinel")),
            gateway_urls: vec![sentinel_url("gateway-sentinel")],
            gateway_pool: None,
            max_manifest_age: Some(std::time::Duration::from_mins(1)),
        };
        let indexed = GlobalPoiPolicy::IndexedArtifacts {
            artifact_source: artifact_source.clone(),
            rpc_url: sentinel_url("rpc-sentinel"),
            wallet_read_fallback: PoiProxyFallback::OnCorpusUnavailable,
        };
        let proxy = GlobalPoiPolicy::PoiProxy {
            rpc_url: sentinel_url("rpc-sentinel"),
        };

        assert_no_endpoint_sentinels(&format!("{artifact_source:?}"));
        assert_no_endpoint_sentinels(&format!("{indexed:?}"));
        assert_no_endpoint_sentinels(&format!("{proxy:?}"));
        assert_eq!(
            indexed.rpc_url(),
            match &indexed {
                GlobalPoiPolicy::IndexedArtifacts { rpc_url, .. } => rpc_url,
                GlobalPoiPolicy::PoiProxy { .. } => unreachable!(),
            }
        );
    }

    #[tokio::test]
    async fn poi_corpus_revision_publication_waits_for_readiness_fence() {
        let caches = LocalPoiCaches::new_for_test(BTreeMap::new());
        let revision_rx = caches.committed_revision_rx();
        let readiness_fence = caches.revision_read_fence().await;
        let write_fence = caches.revision_write_fence();
        tokio::pin!(write_fence);

        tokio::select! {
            biased;
            _ = &mut write_fence => panic!("corpus writer crossed readiness fence"),
            () = tokio::task::yield_now() => {}
        }
        assert_eq!(*revision_rx.borrow(), PoiCorpusRevision::default());

        drop(readiness_fence);
        let _write_fence = write_fence.await;
        caches.publish_committed_revision(true);

        assert_eq!(
            *revision_rx.borrow(),
            PoiCorpusRevision {
                revision: 1,
                blocked_shields_revision: 1,
            }
        );
    }

    #[test]
    fn default_indexed_wallet_ranges_are_chain_specific() {
        assert_eq!(
            RailgunSyncOptions::for_chain(1, 100, std::time::Duration::from_secs(1))
                .unwrap()
                .indexed_wallet_block_range,
            300_000
        );
        assert_eq!(
            RailgunSyncOptions::for_chain(56, 100, std::time::Duration::from_secs(1))
                .unwrap()
                .indexed_wallet_block_range,
            1_000_000
        );
        assert_eq!(
            RailgunSyncOptions::for_chain(137, 100, std::time::Duration::from_secs(1))
                .unwrap()
                .indexed_wallet_block_range,
            1_000_000
        );
        assert_eq!(
            RailgunSyncOptions::for_chain(42161, 100, std::time::Duration::from_secs(1))
                .unwrap()
                .indexed_wallet_block_range,
            5_000_000
        );
        assert_eq!(
            RailgunSyncOptions::for_chain(8453, 100, std::time::Duration::from_secs(1))
                .unwrap()
                .indexed_wallet_block_range,
            1_000_000
        );
    }

    #[test]
    fn sync_progress_percent_uses_block_distance() {
        let progress =
            SyncProgressUpdate::new(SyncProgressStage::SynchronizingCommitments, 100, 150, 300);

        assert_eq!(progress.percent(), 25);
        assert_eq!(progress.source, None);
        assert_eq!(
            progress.with_source(PublicScanSource::Rpc).source,
            Some(PublicScanSource::Rpc)
        );
    }

    #[test]
    fn sync_progress_percent_uses_chunk_distance_for_utxo_prep() {
        let progress = SyncProgressUpdate::artifact_chunk(
            SyncProgressStage::PreparingUtxoIndex,
            25,
            100,
            3,
            12,
        );

        assert_eq!(progress.percent(), 25);
        assert_eq!(
            progress.unit,
            SyncProgressUnit::ArtifactChunk {
                completed: 3,
                total: 12
            }
        );
    }

    #[test]
    fn sync_progress_percent_is_clamped() {
        let early = SyncProgressUpdate::new(SyncProgressStage::IndexingUtxos, 100, 99, 300);
        let late = SyncProgressUpdate::new(SyncProgressStage::IndexingUtxos, 100, 400, 300);

        assert_eq!(early.percent(), 0);
        assert_eq!(late.percent(), 100);
    }

    #[test]
    fn poi_artifact_cache_progress_percent_handles_zero_totals() {
        let progress = PoiArtifactCacheProgress {
            attempt_id: super::PoiArtifactCacheAttemptId::new(1),
            generation: 7,
            chain_id: 1,
            phase: PoiArtifactCachePhase::LoadingPersisted,
            completed_lists: 0,
            total_lists: 0,
            current_list_key: None,
            current_event_index: None,
            target_event_index: None,
            list_progress: Vec::new(),
            graph: PoiArtifactCacheGraphProgress::default(),
            ready_for_wallet_checks: false,
            last_error: None,
        };

        assert_eq!(progress.percent(), 0);
        assert!(progress.is_active());
        assert!(!progress.is_ready());
        assert!(!progress.is_error());
    }

    #[test]
    fn poi_artifact_cache_progress_reports_ready_and_error_state() {
        let ready = PoiArtifactCacheProgress {
            attempt_id: super::PoiArtifactCacheAttemptId::new(2),
            generation: 8,
            chain_id: 1,
            phase: PoiArtifactCachePhase::Ready,
            completed_lists: 1,
            total_lists: 1,
            current_list_key: None,
            current_event_index: None,
            target_event_index: None,
            list_progress: Vec::new(),
            graph: PoiArtifactCacheGraphProgress::default(),
            ready_for_wallet_checks: true,
            last_error: None,
        };
        let error = PoiArtifactCacheProgress {
            phase: PoiArtifactCachePhase::Failed,
            ready_for_wallet_checks: false,
            last_error: Some("failed".to_string()),
            ..ready.clone()
        };

        assert_eq!(ready.percent(), 100);
        assert!(ready.is_ready());
        assert!(error.is_error());
        assert!(!error.is_active());
        assert_eq!(
            error.failure_kind(),
            Some(PoiArtifactCacheFailureKind::ServingCorpusUnavailable)
        );
    }
}
