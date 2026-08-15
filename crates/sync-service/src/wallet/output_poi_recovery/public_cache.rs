use super::{
    ChainPublicDataPlane, ChainScope, ChainType, DEFAULT_TXID_VERSION, EVM_CHAIN_TYPE, FixedBytes,
    IndexedArtifactSourceConfig, Instant, OUTPUT_POI_RECOVERY_TRANSIENT_RETRY_AFTER,
    OutputPoiRecoveryStatus, PoiRpcClient, PostTransactionPoiData, PublicTxidCacheKey,
    PublicTxidLatestValidated, PublicTxidProofRequest, PublicTxidProofTarget,
    PublicTxidSyncRequest, PublicTxidTransaction, RecoveryChunk, RecoveryFailure, TREE_LEAF_COUNT,
    TxidPublicCacheError, TxidPublicProof, U256, ValidatedRailgunTxidStatus, WalletConfig, debug,
    hex, railgun_txid_leaf_hash_with_output_start, warn,
};

#[derive(Debug)]
pub(in crate::wallet) struct RecoveredOutputTxidData {
    pub(in crate::wallet) poi_data: PostTransactionPoiData,
}

pub(in crate::wallet) struct PublicCacheTxidRecoveryRequest<'a> {
    pub(in crate::wallet) public_data_plane: &'a ChainPublicDataPlane,
    pub(in crate::wallet) cfg: &'a WalletConfig,
    pub(in crate::wallet) poi_client: &'a PoiRpcClient,
    pub(in crate::wallet) http_client: Option<&'a reqwest::Client>,
    pub(in crate::wallet) indexed_artifact_source: Option<&'a IndexedArtifactSourceConfig>,
    pub(in crate::wallet) recovery_chunk: &'a RecoveryChunk,
    pub(in crate::wallet) started: Instant,
}

pub(in crate::wallet) struct PublicCacheTxidRefreshRequest<'a> {
    pub(in crate::wallet) public_data_plane: &'a ChainPublicDataPlane,
    pub(in crate::wallet) cfg: &'a WalletConfig,
    pub(in crate::wallet) poi_client: &'a PoiRpcClient,
    pub(in crate::wallet) http_client: Option<&'a reqwest::Client>,
    pub(in crate::wallet) indexed_artifact_source: Option<&'a IndexedArtifactSourceConfig>,
    pub(in crate::wallet) cache_key: PublicTxidCacheKey,
}

pub(in crate::wallet) async fn refresh_public_txid_cache(
    request: PublicCacheTxidRefreshRequest<'_>,
) -> Result<(), RecoveryFailure> {
    let PublicCacheTxidRefreshRequest {
        public_data_plane,
        cfg,
        poi_client,
        http_client,
        indexed_artifact_source,
        cache_key,
    } = request;
    let endpoint = cfg.quick_sync_endpoint.as_ref();
    if endpoint.is_none() && indexed_artifact_source.is_none() {
        return Err(RecoveryFailure::retryable_category(
            OutputPoiRecoveryStatus::TxFetchFailed,
            "public_txid_fetch_failed",
            "no TXID synchronization source is configured",
            OUTPUT_POI_RECOVERY_TRANSIENT_RETRY_AFTER,
        ));
    }
    let latest_validated = poi_client
        .latest_validated_railgun_txid(DEFAULT_TXID_VERSION, EVM_CHAIN_TYPE, cfg.chain.chain_id)
        .await
        .map_err(|err| {
            RecoveryFailure::retryable_category(
                OutputPoiRecoveryStatus::MissingMerkleProof,
                "public_txid_fetch_failed",
                format!("fetch latest validated TXID failed: {err}"),
                OUTPUT_POI_RECOVERY_TRANSIENT_RETRY_AFTER,
            )
        })?;
    let latest = PublicTxidLatestValidated {
        txid_index: latest_validated_txid_index(&latest_validated)?,
        merkleroot: latest_validated_txid_root(&latest_validated)?,
    };
    public_data_plane
        .sync_txid_public_cache(PublicTxidSyncRequest {
            key: cache_key.clone(),
            endpoint,
            http_client,
            latest,
            indexed_artifact_source,
        })
        .await
        .map_err(|err| txid_public_cache_failure(&err))?;
    validate_public_txid_checkpoints(public_data_plane, &cache_key, latest, poi_client).await
}

async fn validate_public_txid_checkpoints(
    public_data_plane: &ChainPublicDataPlane,
    cache_key: &PublicTxidCacheKey,
    latest: PublicTxidLatestValidated,
    poi_client: &PoiRpcClient,
) -> Result<(), RecoveryFailure> {
    let candidates = public_data_plane
        .txid_public_checkpoint_candidates(cache_key, latest.txid_index)
        .await
        .map_err(|err| txid_public_cache_failure(&err))?;
    for candidate in candidates {
        let accepted = poi_client
            .validate_txid_merkleroot(
                DEFAULT_TXID_VERSION,
                EVM_CHAIN_TYPE,
                cache_key.scope.chain_id,
                candidate.tree,
                candidate.index,
                &candidate.merkleroot,
            )
            .await
            .map_err(|err| {
                RecoveryFailure::retryable_category(
                    OutputPoiRecoveryStatus::MissingMerkleProof,
                    "public_txid_fetch_failed",
                    format!("validate public TXID checkpoint failed: {err}"),
                    OUTPUT_POI_RECOVERY_TRANSIENT_RETRY_AFTER,
                )
            })?;
        if !accepted {
            return Err(RecoveryFailure::retryable_category(
                OutputPoiRecoveryStatus::MissingMerkleProof,
                "public_txid_fetch_failed",
                "POI node rejected a public TXID checkpoint",
                OUTPUT_POI_RECOVERY_TRANSIENT_RETRY_AFTER,
            ));
        }
        public_data_plane
            .commit_txid_public_checkpoint(cache_key, candidate)
            .await
            .map_err(|err| txid_public_cache_failure(&err))?;
    }
    Ok(())
}

pub(in crate::wallet) async fn public_txid_rows_for_outer_hash(
    request: PublicCacheTxidRefreshRequest<'_>,
    outer_transaction_hash: FixedBytes<32>,
) -> Result<Vec<PublicTxidTransaction>, RecoveryFailure> {
    match request
        .public_data_plane
        .txid_transactions_for_outer_hash(&request.cache_key, outer_transaction_hash)
    {
        Ok(rows) if !rows.is_empty() => return Ok(rows),
        Ok(_) | Err(TxidPublicCacheError::CacheNotReady { .. }) => {}
        Err(err) => return Err(txid_public_cache_failure(&err)),
    }
    let public_data_plane = request.public_data_plane;
    let cache_key = request.cache_key.clone();
    refresh_public_txid_cache(request).await?;
    let rows = public_data_plane
        .txid_transactions_for_outer_hash(&cache_key, outer_transaction_hash)
        .map_err(|err| txid_public_cache_failure(&err))?;
    if rows.is_empty() {
        return Err(RecoveryFailure::retryable_category(
            OutputPoiRecoveryStatus::TxFetchFailed,
            "public_txid_fetch_failed",
            "source transaction is missing from validated public TXID data",
            OUTPUT_POI_RECOVERY_TRANSIENT_RETRY_AFTER,
        ));
    }
    Ok(rows)
}

pub(in crate::wallet) async fn recovered_output_txid_data_from_public_cache(
    request: PublicCacheTxidRecoveryRequest<'_>,
) -> Result<RecoveredOutputTxidData, RecoveryFailure> {
    let PublicCacheTxidRecoveryRequest {
        public_data_plane,
        cfg,
        poi_client,
        http_client,
        indexed_artifact_source,
        recovery_chunk,
        started,
    } = request;
    let cache_key = PublicTxidCacheKey::new(
        ChainScope {
            chain_type: ChainType::Evm,
            chain_id: cfg.chain.chain_id,
            railgun_contract: cfg.chain.contract,
        },
        DEFAULT_TXID_VERSION,
    );
    let expected_leaf = railgun_txid_leaf_hash_with_output_start(
        recovery_chunk.chunk.railgun_txid(),
        u64::from(recovery_chunk.chunk.tree_number),
        U256::from(recovery_chunk.output_start_global),
    );
    let target = recovery_chunk.target_txid_index.map_or(
        PublicTxidProofTarget::UnknownIndex {
            expected_leaf_hash: expected_leaf,
            output_start_global: recovery_chunk.output_start_global,
        },
        |txid_index| PublicTxidProofTarget::KnownIndex {
            txid_index,
            expected_leaf_hash: expected_leaf,
            output_start_global: recovery_chunk.output_start_global,
        },
    );
    let proof_started = Instant::now();
    let (cached, proof_source, cache_sync_elapsed_ms) = if let Some(proof) =
        try_artifact_bounded_proof(public_data_plane, &cache_key, target)?
    {
        (proof, "artifact_bounded", 0)
    } else {
        let cached_latest = match public_data_plane.cached_txid_latest_validated(&cache_key) {
            Ok(latest) => latest,
            Err(err) => {
                warn!(
                    chain_id = cfg.chain.chain_id,
                    target_txid_index = recovery_chunk.target_txid_index,
                    failure_category = "latest_validated_lookup_failed",
                    "output POI recovery TXID data failed"
                );
                return Err(txid_public_cache_failure(&err));
            }
        };
        let cached_proof = if let Some(latest) = cached_latest
            && target
                .txid_index()
                .is_none_or(|target_index| target_index <= latest.txid_index)
        {
            match public_data_plane.txid_public_proof(&PublicTxidProofRequest {
                key: cache_key.clone(),
                target,
            }) {
                Ok(proof) => Some(proof),
                Err(err) => {
                    if matches!(&err, TxidPublicCacheError::CacheNotReady { .. })
                        || (target.txid_index().is_none()
                            && matches!(&err, TxidPublicCacheError::MissingTarget))
                    {
                        None
                    } else {
                        warn!(
                            chain_id = cfg.chain.chain_id,
                            target_txid_index = recovery_chunk.target_txid_index,
                            proof_source = "cache",
                            failure_category = txid_public_cache_failure_category(&err),
                            "output POI recovery TXID data failed"
                        );
                        return Err(txid_public_cache_failure(&err));
                    }
                }
            }
        } else {
            None
        };
        if let Some(proof) = cached_proof {
            (proof, "cache", 0)
        } else {
            let cache_sync_started = Instant::now();
            let refresh_result = refresh_public_txid_cache(PublicCacheTxidRefreshRequest {
                public_data_plane,
                cfg,
                poi_client,
                http_client,
                indexed_artifact_source,
                cache_key: cache_key.clone(),
            })
            .await;
            let cache_sync_elapsed_ms = cache_sync_started.elapsed().as_millis();
            match refresh_result {
                Ok(()) => {
                    let proof = match public_data_plane.txid_public_proof(&PublicTxidProofRequest {
                        key: cache_key,
                        target,
                    }) {
                        Ok(proof) => proof,
                        Err(err) => {
                            warn!(
                                chain_id = cfg.chain.chain_id,
                                target_txid_index = recovery_chunk.target_txid_index,
                                proof_source = "after_refresh",
                                failure_category = txid_public_cache_failure_category(&err),
                                "output POI recovery TXID data failed"
                            );
                            return Err(txid_public_cache_failure(&err));
                        }
                    };
                    (proof, "after_refresh", cache_sync_elapsed_ms)
                }
                Err(refresh_error) => {
                    if let Some(proof) =
                        try_artifact_bounded_proof(public_data_plane, &cache_key, target)?
                    {
                        (proof, "artifact_bounded", cache_sync_elapsed_ms)
                    } else {
                        warn!(
                            chain_id = cfg.chain.chain_id,
                            target_txid_index = recovery_chunk.target_txid_index,
                            failure_category = "cache_refresh_failed",
                            "output POI recovery TXID data failed"
                        );
                        return Err(refresh_error);
                    }
                }
            }
        }
    };
    let proof_elapsed_ms = proof_started.elapsed().as_millis();
    let target_index = cached.target_txid_index % TREE_LEAF_COUNT;
    let txid_merkleroot = FixedBytes::from(cached.proof.root.to_be_bytes::<32>());
    debug!(
        chain_id = cfg.chain.chain_id,
        cache_sync_elapsed_ms,
        txid_tree_elapsed_ms = proof_elapsed_ms,
        elapsed_ms = started.elapsed().as_millis(),
        proof_source,
        "output POI recovery TXID data ready from public cache"
    );

    Ok(RecoveredOutputTxidData {
        poi_data: PostTransactionPoiData {
            txid_leaf_hash: FixedBytes::from(cached.proof.leaf.to_be_bytes::<32>()),
            txid_merkleroot,
            txid_merkleroot_index: cached.root_txid_index,
            txid_merkle_proof_indices: U256::from(target_index),
            txid_merkle_proof_path_elements: cached.proof.path_elements.to_vec(),
            utxo_batch_global_start_position_out: U256::from(recovery_chunk.output_start_global),
        },
    })
}

fn try_artifact_bounded_proof(
    public_data_plane: &ChainPublicDataPlane,
    cache_key: &PublicTxidCacheKey,
    target: PublicTxidProofTarget,
) -> Result<Option<TxidPublicProof>, RecoveryFailure> {
    match public_data_plane.txid_artifact_bounded_proof(&PublicTxidProofRequest {
        key: cache_key.clone(),
        target,
    }) {
        Ok(proof) => Ok(Some(proof)),
        Err(TxidPublicCacheError::CacheNotReady { .. } | TxidPublicCacheError::MissingTarget) => {
            Ok(None)
        }
        Err(err) => Err(txid_public_cache_failure(&err)),
    }
}

const fn txid_public_cache_failure_category(err: &TxidPublicCacheError) -> &'static str {
    match err {
        TxidPublicCacheError::LeafMismatch => "leaf_mismatch",
        TxidPublicCacheError::RootMismatch => "root_mismatch",
        TxidPublicCacheError::MissingLeaf { .. } => "missing_leaf",
        TxidPublicCacheError::CacheNotReady { .. } => "cache_not_ready",
        TxidPublicCacheError::MissingTarget => "target_missing",
        TxidPublicCacheError::AmbiguousTarget => "ambiguous_target",
        TxidPublicCacheError::Db(_)
        | TxidPublicCacheError::Io(_)
        | TxidPublicCacheError::Encode(_)
        | TxidPublicCacheError::Decode(_)
        | TxidPublicCacheError::Sync(_)
        | TxidPublicCacheError::Artifact(_)
        | TxidPublicCacheError::MetadataMismatch(_)
        | TxidPublicCacheError::StalePublicCacheGeneration { .. } => "metadata_or_storage_error",
    }
}

pub(super) fn latest_validated_txid_index(
    latest_validated: &ValidatedRailgunTxidStatus,
) -> Result<u64, RecoveryFailure> {
    latest_validated.validated_txid_index.ok_or_else(|| {
        RecoveryFailure::retryable_category(
            OutputPoiRecoveryStatus::MissingMerkleProof,
            "public_txid_fetch_failed",
            "POI node did not return a latest validated TXID index",
            OUTPUT_POI_RECOVERY_TRANSIENT_RETRY_AFTER,
        )
    })
}

pub(super) fn latest_validated_txid_root(
    latest_validated: &ValidatedRailgunTxidStatus,
) -> Result<Option<FixedBytes<32>>, RecoveryFailure> {
    let Some(root) = latest_validated.validated_merkleroot.as_deref() else {
        return Ok(None);
    };
    let root = root.strip_prefix("0x").unwrap_or(root);
    let bytes = hex::decode(root).map_err(|err| {
        RecoveryFailure::retryable_category(
            OutputPoiRecoveryStatus::MissingMerkleProof,
            "public_txid_fetch_failed",
            format!("latest validated TXID root is not hex: {err}"),
            OUTPUT_POI_RECOVERY_TRANSIENT_RETRY_AFTER,
        )
    })?;
    let bytes: [u8; 32] = bytes.try_into().map_err(|bytes: Vec<u8>| {
        RecoveryFailure::retryable_category(
            OutputPoiRecoveryStatus::MissingMerkleProof,
            "public_txid_fetch_failed",
            format!(
                "latest validated TXID root has {} bytes, expected 32",
                bytes.len()
            ),
            OUTPUT_POI_RECOVERY_TRANSIENT_RETRY_AFTER,
        )
    })?;
    Ok(Some(FixedBytes::from(bytes)))
}

pub(super) fn txid_public_cache_failure(err: &TxidPublicCacheError) -> RecoveryFailure {
    let status = match err {
        TxidPublicCacheError::AmbiguousTarget => OutputPoiRecoveryStatus::UnsupportedShape,
        TxidPublicCacheError::MissingTarget
        | TxidPublicCacheError::CacheNotReady { .. }
        | TxidPublicCacheError::MissingLeaf { .. }
        | TxidPublicCacheError::LeafMismatch
        | TxidPublicCacheError::RootMismatch => OutputPoiRecoveryStatus::MissingMerkleProof,
        TxidPublicCacheError::Db(_)
        | TxidPublicCacheError::Io(_)
        | TxidPublicCacheError::Encode(_)
        | TxidPublicCacheError::Decode(_)
        | TxidPublicCacheError::Sync(_)
        | TxidPublicCacheError::Artifact(_)
        | TxidPublicCacheError::MetadataMismatch(_)
        | TxidPublicCacheError::StalePublicCacheGeneration { .. } => {
            OutputPoiRecoveryStatus::TxFetchFailed
        }
    };
    let message = format!("TXID public cache failed: {err}");
    if matches!(status, OutputPoiRecoveryStatus::UnsupportedShape) {
        RecoveryFailure::permanent_category(status, "unsupported_transaction_shape", message)
    } else {
        RecoveryFailure::retryable_category(
            status,
            "public_txid_fetch_failed",
            message,
            OUTPUT_POI_RECOVERY_TRANSIENT_RETRY_AFTER,
        )
    }
}
