use super::*;

pub(crate) fn wallet_poi_status_refresh_needed(
    wallet_utxos: &[WalletUtxo],
    active_list_keys: &[FixedBytes<32>],
) -> bool {
    wallet_poi_status_refresh_needed_for_selection(
        wallet_utxos,
        active_list_keys,
        WalletPoiRefreshSelection::Required,
    )
}

pub(super) fn wallet_poi_status_refresh_needed_for_selection(
    wallet_utxos: &[WalletUtxo],
    active_list_keys: &[FixedBytes<32>],
    selection: WalletPoiRefreshSelection,
) -> bool {
    !active_list_keys.is_empty()
        && wallet_utxos.iter().any(|wallet_utxo| {
            !wallet_utxo.is_spent() && selection.matches_wallet_utxo(wallet_utxo, active_list_keys)
        })
}

pub(super) fn blinded_commitment_type(kind: UtxoCommitmentKind) -> BlindedCommitmentType {
    match kind {
        UtxoCommitmentKind::Shield => BlindedCommitmentType::Shield,
        UtxoCommitmentKind::Transact => BlindedCommitmentType::Transact,
    }
}

pub(crate) fn wallet_poi_status_client(
    poi_rpc_url: &Url,
    http_client: Option<&reqwest::Client>,
) -> Option<PoiRpcClient> {
    Some(match http_client {
        Some(http_client) => {
            PoiRpcClient::with_http_client(poi_rpc_url.clone(), http_client.clone())
        }
        None => PoiRpcClient::new(poi_rpc_url.clone()),
    })
}

pub(crate) enum WalletPoiRuntime {
    IndexedArtifacts {
        client: PoiRpcClient,
        wallet_read_fallback: PoiProxyFallback,
    },
    PoiProxy {
        client: PoiRpcClient,
    },
}

impl WalletPoiRuntime {
    pub(crate) fn from_policy(
        policy: &GlobalPoiPolicy,
        http_client: Option<&reqwest::Client>,
    ) -> Self {
        let client = wallet_poi_status_client(policy.rpc_url(), http_client)
            .expect("POI RPC client construction is infallible");
        match policy {
            GlobalPoiPolicy::IndexedArtifacts {
                wallet_read_fallback,
                ..
            } => Self::IndexedArtifacts {
                client,
                wallet_read_fallback: *wallet_read_fallback,
            },
            GlobalPoiPolicy::PoiProxy { .. } => Self::PoiProxy { client },
        }
    }

    /// Raw client for public POI operations and for constructing the private gateway.
    /// Wallet-private effects must not call this client directly.
    pub(crate) const fn public_client(&self) -> &PoiRpcClient {
        match self {
            Self::IndexedArtifacts { client, .. } | Self::PoiProxy { client } => client,
        }
    }

    pub(crate) const fn is_indexed_artifacts(&self) -> bool {
        matches!(self, Self::IndexedArtifacts { .. })
    }

    pub(crate) const fn wallet_read_fallback_enabled(&self) -> bool {
        matches!(
            self,
            Self::IndexedArtifacts {
                wallet_read_fallback: PoiProxyFallback::OnCorpusUnavailable,
                ..
            }
        )
    }
}

pub(crate) struct WalletWorkerServices {
    pub db: Arc<DbStore>,
    pub rpcs: Arc<QueryRpcPool>,
    pub http_client: Option<reqwest::Client>,
    pub indexed_artifact_source: Option<IndexedArtifactSourceConfig>,
    pub poi_runtime: WalletPoiRuntime,
    pub forest: Arc<RwLock<MerkleForest>>,
    pub backfill_tx: mpsc::Sender<crate::types::BackfillRequest>,
    pub backfill_sender: mpsc::Sender<BackfillEvent>,
    pub public_data_plane: ChainPublicDataPlane,
}

pub(super) fn now_epoch_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |duration| duration.as_secs())
}

impl WalletHandle {
    pub async fn wait_until_ready(&mut self) {
        loop {
            match &*self.readiness_rx.borrow() {
                WalletReadiness::Ready | WalletReadiness::Failed(_) | WalletReadiness::Shutdown => {
                    break;
                }
                WalletReadiness::Syncing => {}
            }
            if self.readiness_rx.changed().await.is_err() {
                break;
            }
        }
    }
}

#[derive(Default)]
pub(super) struct WalletPersistState {
    pub(super) needs_full_persist: bool,
    pub(super) pending_cache_reset: Option<u64>,
}

impl WalletPersistState {
    pub(super) fn persist_progress(
        &mut self,
        cache_store: &dyn WalletCacheStore,
        permit: &WalletPrivateMutationPermit<'_>,
        request: WalletProgressPersist<'_>,
    ) -> Result<bool, WalletCacheError> {
        self.persist_progress_with_private_effects(
            cache_store,
            permit,
            request,
            WalletProgressPrivateEffects::default(),
        )
    }

    pub(super) fn persist_progress_with_private_effects(
        &mut self,
        cache_store: &dyn WalletCacheStore,
        permit: &WalletPrivateMutationPermit<'_>,
        request: WalletProgressPersist<'_>,
        effects: WalletProgressPrivateEffects<'_>,
    ) -> Result<bool, WalletCacheError> {
        permit
            .with_durable_apply(|token| {
                self.commit_progress_with_token(cache_store, permit, &token, request, effects)
            })
            .map_err(|_| WalletCacheError::Crypto)?
    }

    /// Durable progress commit under an existing active-apply token (no re-fence).
    pub(super) fn commit_progress_with_token(
        &mut self,
        cache_store: &dyn WalletCacheStore,
        permit: &WalletPrivateMutationPermit<'_>,
        token: &WalletActorCommitToken<'_>,
        request: WalletProgressPersist<'_>,
        effects: WalletProgressPrivateEffects<'_>,
    ) -> Result<bool, WalletCacheError> {
        let full_persist =
            request.changed || self.needs_full_persist || self.pending_cache_reset.is_some();
        if full_persist {
            let persist_started = Instant::now();
            return match cache_store.commit_wallet_private_state(WalletPrivateCommit::new(
                token,
                permit,
                effects.pending_output_context_chain_id,
                request.snapshot,
                true,
                request.last_scanned,
                request.last_scanned_block_hash,
                effects.pending_output_context_updates,
                effects.pending_output_context_deletes,
                effects.output_poi_recovery_updates,
            )) {
                Ok(()) => {
                    self.needs_full_persist = false;
                    self.pending_cache_reset = None;
                    debug!(
                        cache_key = %request.cache_key,
                        rows = request.snapshot.len(),
                        last_scanned = request.last_scanned,
                        changed = request.changed,
                        elapsed_ms = persist_started.elapsed().as_millis(),
                        "persisted wallet full snapshot"
                    );
                    Ok(true)
                }
                Err(err) => {
                    self.needs_full_persist = true;
                    debug!(
                        ?err,
                        cache_key = %request.cache_key,
                        rows = request.snapshot.len(),
                        last_scanned = request.last_scanned,
                        changed = request.changed,
                        elapsed_ms = persist_started.elapsed().as_millis(),
                        "failed to persist wallet full snapshot"
                    );
                    Err(err)
                }
            };
        }

        let meta_started = Instant::now();
        cache_store.commit_wallet_private_state(WalletPrivateCommit::new(
            token,
            permit,
            effects.pending_output_context_chain_id,
            request.snapshot,
            false,
            request.last_scanned,
            request.last_scanned_block_hash,
            effects.pending_output_context_updates,
            effects.pending_output_context_deletes,
            effects.output_poi_recovery_updates,
        ))?;
        debug!(
            cache_key = %request.cache_key,
            last_scanned = request.last_scanned,
            elapsed_ms = meta_started.elapsed().as_millis(),
            "persisted wallet metadata progress"
        );
        Ok(false)
    }
}

pub(super) struct WalletLiveMetadataFlush {
    pub(super) last_persisted_block: u64,
    pub(super) last_persisted_at: Instant,
}

impl WalletLiveMetadataFlush {
    pub(super) fn new(last_persisted_block: u64, now: Instant) -> Self {
        Self {
            last_persisted_block,
            last_persisted_at: now,
        }
    }

    #[cfg(test)]
    pub(super) fn should_flush(&self, last_scanned: u64, now: Instant) -> bool {
        last_scanned.saturating_sub(self.last_persisted_block) >= WALLET_METADATA_LIVE_FLUSH_BLOCKS
            || now.duration_since(self.last_persisted_at) >= WALLET_METADATA_LIVE_FLUSH_INTERVAL
    }

    pub(super) fn mark_persisted(&mut self, last_persisted_block: u64, now: Instant) {
        self.last_persisted_block = last_persisted_block;
        self.last_persisted_at = now;
    }
}

pub(super) struct WalletProgressPersist<'a> {
    pub(super) cache_key: &'a str,
    pub(super) snapshot: &'a [WalletUtxo],
    pub(super) last_scanned: u64,
    pub(super) last_scanned_block_hash: Option<[u8; 32]>,
    pub(super) changed: bool,
}

#[derive(Default)]
pub(super) struct WalletProgressPrivateEffects<'a> {
    pub(super) pending_output_context_chain_id: u64,
    pub(super) pending_output_context_updates: &'a [PendingOutputPoiContextRecord],
    pub(super) pending_output_context_deletes: &'a [FixedBytes<32>],
    pub(super) output_poi_recovery_updates: &'a [OutputPoiRecoveryRecord],
}

pub(super) struct OutputPoiRecoveryRun<'a> {
    pub(super) authority: &'a WalletPrivateMutationAuthority<'a>,
    pub(super) db: &'a DbStore,
    pub(super) cache_store: &'a dyn WalletCacheStore,
    pub(super) cfg: &'a WalletConfig,
    pub(super) public_data_plane: &'a ChainPublicDataPlane,
    pub(super) rpcs: &'a QueryRpcPool,
    pub(super) http_client: Option<&'a reqwest::Client>,
    pub(super) indexed_artifact_source: Option<&'a IndexedArtifactSourceConfig>,
    pub(super) poi_runtime: &'a WalletPoiRuntime,
    pub(super) forest: &'a Arc<RwLock<MerkleForest>>,
    pub(super) utxos: &'a Arc<RwLock<Vec<WalletUtxo>>>,
    pub(super) client: &'a PoiRpcClient,
    pub(super) private_poi: &'a WalletPrivatePoiClients,
    pub(super) active_list_keys: &'a [FixedBytes<32>],
    pub(super) force_retry: bool,
}

impl OutputPoiRecoveryRun<'_> {
    pub(super) async fn recover_missing(self) -> usize {
        if self.cfg.spending_public_key.is_none() || self.cfg.poi_recovery_prover.is_none() {
            return 0;
        }
        if let Err(reason) = self.authority.revalidate() {
            debug!(?reason, cache_key = %self.cfg.cache_key, "output POI recovery skipped");
            return 0;
        }
        let snapshot = self.utxos.read().await.clone();
        mark_valid_output_poi_recoveries(
            self.authority,
            self.db,
            self.cache_store,
            self.cfg,
            &snapshot,
            self.active_list_keys,
        )
        .await;
        if output_poi_recovery_candidates(&snapshot, self.active_list_keys).is_empty() {
            return 0;
        }
        if matches!(self.poi_runtime, WalletPoiRuntime::IndexedArtifacts { .. })
            && !self.poi_runtime.wallet_read_fallback_enabled()
            && !self
                .public_data_plane
                .poi_corpus_ready_for_lists(
                    PublicPoiCorpusKey::wallet_default(self.cfg.chain.chain_id),
                    self.active_list_keys,
                )
                .await
        {
            log_local_poi_cache_unavailable(self.cfg, "output_poi_recovery");
            return 0;
        }
        let forest = self.forest.read().await.clone();
        recover_missing_output_pois(OutputPoiRecoveryRequest {
            authority: self.authority,
            db: self.db,
            cache_store: self.cache_store,
            cfg: self.cfg,
            public_data_plane: self.public_data_plane,
            rpcs: self.rpcs,
            http_client: self.http_client,
            indexed_artifact_source: self.indexed_artifact_source,
            forest: &forest,
            poi_client: self.client,
            private_poi: self.private_poi,
            poi_runtime: self.poi_runtime,
            active_list_keys: self.active_list_keys,
            wallet_utxos: &snapshot,
            force_retry: self.force_retry,
        })
        .await
    }
}
