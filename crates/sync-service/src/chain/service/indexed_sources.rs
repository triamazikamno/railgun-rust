use crate::chain::logs::INDEXED_SQUID_STEP_DEADLINE;
use crate::chain::squid_tail_target_after_artifact;

use super::{
    ChainService, IndexedWalletArtifactSession, Instant, PublicDataPlaneDiagnosticKind,
    PublicScanRange, PublicScanReadScope, PublicScanSource, QuickSyncClient, SyncProgressSender,
    WalletConfig, WalletStartupSyncError, debug, warn,
};

pub(super) struct SquidIndexedWalletReadSession {
    client: QuickSyncClient,
    indexed_height: u64,
    read_scope: PublicScanReadScope,
}

impl SquidIndexedWalletReadSession {
    pub(super) const fn client(&self) -> &QuickSyncClient {
        &self.client
    }

    pub(super) const fn indexed_height(&self) -> u64 {
        self.indexed_height
    }

    pub(super) const fn read_scope(&self) -> PublicScanReadScope {
        self.read_scope
    }
}

impl ChainService {
    pub(super) async fn probe_squid_indexed_wallet_source(
        &self,
        cfg: &WalletConfig,
    ) -> Option<SquidIndexedWalletReadSession> {
        self.probe_squid_indexed_wallet_source_for_label(&cfg.cache_key)
            .await
    }

    pub(super) async fn probe_squid_indexed_wallet_source_for_label(
        &self,
        cache_key: &str,
    ) -> Option<SquidIndexedWalletReadSession> {
        let Some(endpoint) = self.chain.sync.quick_sync_endpoint.clone() else {
            debug!(cache_key = %cache_key, "no indexed endpoint configured; using RPC wallet backfill");
            return None;
        };
        let client = QuickSyncClient::with_http_client(endpoint, self.chain.http_client.clone());
        let read_scope = self.begin_public_scan_read();
        let probe_started = Instant::now();
        let probe = match client.probe_indexed_wallet_support().await {
            Ok(probe) => probe,
            Err(err) => {
                warn!(
                    err = %WalletStartupSyncError::from(err).without_url(),
                    cache_key = %cache_key,
                    "indexed wallet probe failed; using RPC backfill"
                );
                return None;
            }
        };
        debug!(
            cache_key = %cache_key,
            elapsed_ms = probe_started.elapsed().as_millis(),
            "indexed wallet probe complete"
        );
        Some(SquidIndexedWalletReadSession {
            client,
            indexed_height: probe.height,
            read_scope,
        })
    }

    pub(super) async fn probe_squid_tail_after_artifact(
        &self,
        cfg: &WalletConfig,
        from_block: u64,
        artifact_target: u64,
        safe_head: u64,
    ) -> Option<(SquidIndexedWalletReadSession, u64)> {
        if artifact_target >= safe_head {
            return None;
        }
        let started = Instant::now();
        let tail_blocks = safe_head - artifact_target;
        // A one-page tail goes to RPC backfill without waiting on Squid.
        if self
            .chain
            .should_skip_indexed_forest_catch_up(artifact_target + 1, safe_head)
        {
            debug!(
                cache_key = %cfg.cache_key,
                artifact_target,
                safe_head,
                tail_blocks,
                elapsed_ms = started.elapsed().as_millis(),
                "Squid step skipped for one-page tail"
            );
            return None;
        }
        let Ok(session) = tokio::time::timeout(
            INDEXED_SQUID_STEP_DEADLINE,
            self.probe_squid_indexed_wallet_source(cfg),
        )
        .await
        else {
            debug!(
                cache_key = %cfg.cache_key,
                artifact_target,
                safe_head,
                tail_blocks,
                elapsed_ms = started.elapsed().as_millis(),
                "Squid step deadline passed"
            );
            return None;
        };
        let session = session?;
        let target = squid_tail_target_after_artifact(
            from_block,
            artifact_target,
            safe_head,
            session.indexed_height(),
        )?;
        Some((session, target))
    }

    pub(super) async fn prepare_indexed_wallet_artifact_session(
        &self,
        cfg: &WalletConfig,
        from_block: u64,
        safe_head: u64,
        progress_tx: Option<&SyncProgressSender>,
    ) -> Option<IndexedWalletArtifactSession> {
        self.prepare_indexed_wallet_artifact_session_for_label(
            &cfg.cache_key,
            from_block,
            safe_head,
            progress_tx,
        )
        .await
    }

    pub(super) async fn prepare_indexed_wallet_artifact_session_for_label(
        &self,
        cache_key: &str,
        from_block: u64,
        safe_head: u64,
        progress_tx: Option<&SyncProgressSender>,
    ) -> Option<IndexedWalletArtifactSession> {
        self.chain.sync.indexed_artifact_source.as_ref()?;
        let read_scope = self.begin_public_scan_read();
        let range = PublicScanRange::new(from_block, safe_head);
        self.public_data_plane
            .record_source_decision(
                PublicDataPlaneDiagnosticKind::ArtifactProgress,
                PublicScanSource::IndexedArtifacts,
                range,
                read_scope,
                "wallet-scan artifact preparation started",
            )
            .await;
        let artifact_session_started = Instant::now();
        match IndexedWalletArtifactSession::prepare(
            &self.chain,
            from_block,
            safe_head,
            read_scope,
            &self.public_data_plane,
            progress_tx,
        )
        .await
        {
            Ok(Some(session)) => {
                self.public_data_plane
                    .record_source_decision(
                        PublicDataPlaneDiagnosticKind::ArtifactProgress,
                        PublicScanSource::IndexedArtifacts,
                        range,
                        read_scope,
                        format!(
                            "wallet-scan artifact preparation complete: {} chunks",
                            session.chunk_count()
                        ),
                    )
                    .await;
                debug!(
                    cache_key = %cache_key,
                    from_block,
                    safe_head,
                    latest_indexed_block = session.latest_indexed_block(),
                    catalog_count = session.catalog_count(),
                    chunk_count = session.chunk_count(),
                    elapsed_ms = artifact_session_started.elapsed().as_millis(),
                    "indexed wallet artifact session prepared"
                );
                Some(session)
            }
            Ok(None) => {
                self.public_data_plane
                    .record_source_decision(
                        PublicDataPlaneDiagnosticKind::ArtifactProgress,
                        PublicScanSource::IndexedArtifacts,
                        range,
                        read_scope,
                        "wallet-scan artifact preparation unavailable",
                    )
                    .await;
                self.public_data_plane
                    .record_source_decision(
                        PublicDataPlaneDiagnosticKind::SourceFallback,
                        PublicScanSource::IndexedArtifacts,
                        range,
                        read_scope,
                        "wallet-scan artifact preparation unavailable; falling back",
                    )
                    .await;
                debug!(
                    cache_key = %cache_key,
                    from_block,
                    safe_head,
                    elapsed_ms = artifact_session_started.elapsed().as_millis(),
                    "indexed wallet artifact session unavailable"
                );
                None
            }
            Err(err) => {
                self.public_data_plane
                    .record_source_decision(
                        PublicDataPlaneDiagnosticKind::ArtifactProgress,
                        PublicScanSource::IndexedArtifacts,
                        range,
                        read_scope,
                        "wallet-scan artifact preparation failed",
                    )
                    .await;
                self.public_data_plane
                    .record_source_decision(
                        PublicDataPlaneDiagnosticKind::SourceFallback,
                        PublicScanSource::IndexedArtifacts,
                        range,
                        read_scope,
                        "wallet-scan artifact preparation failed; falling back",
                    )
                    .await;
                warn!(
                    err = %WalletStartupSyncError::from(err).without_url(),
                    cache_key = %cache_key,
                    from_block,
                    safe_head,
                    elapsed_ms = artifact_session_started.elapsed().as_millis(),
                    "indexed wallet artifact session failed; falling back to configured indexed sources"
                );
                None
            }
        }
    }
}
