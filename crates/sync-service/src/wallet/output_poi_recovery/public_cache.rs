use super::*;

#[derive(Debug)]
pub(in crate::wallet) struct RecoveredOutputTxidData {
    pub(super) target_txid_index: u64,
    pub(super) poi_data: PostTransactionPoiData,
}

pub(in crate::wallet) struct PublicCacheTxidRecoveryRequest<'a> {
    pub(in crate::wallet) public_data_plane: &'a ChainPublicDataPlane,
    pub(in crate::wallet) cfg: &'a WalletConfig,
    pub(in crate::wallet) poi_client: &'a PoiRpcClient,
    pub(in crate::wallet) http_client: Option<&'a reqwest::Client>,
    pub(in crate::wallet) indexed_artifact_source: Option<&'a IndexedArtifactSourceConfig>,
    pub(in crate::wallet) source_tx_hash: FixedBytes<32>,
    pub(in crate::wallet) output_commitment: FixedBytes<32>,
    pub(in crate::wallet) recovery_chunk: &'a RecoveryChunk,
    pub(in crate::wallet) started: Instant,
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
        source_tx_hash,
        output_commitment,
        recovery_chunk,
        started,
    } = request;
    let endpoint = cfg.quick_sync_endpoint.as_ref();
    if endpoint.is_none() && indexed_artifact_source.is_none() {
        return Err(RecoveryFailure::retryable(
            OutputPoiRecoveryStatus::TxFetchFailed,
            "no quick-sync endpoint configured for TXID proof recovery",
            OUTPUT_POI_RECOVERY_TRANSIENT_RETRY_AFTER,
        ));
    }
    let cache_key =
        PublicTxidCacheKey::new(EVM_CHAIN_TYPE, cfg.chain.chain_id, DEFAULT_TXID_VERSION);
    let latest_validated_started = Instant::now();
    let required_txid_index = recovery_chunk.target_txid_index.unwrap_or(0);
    let (latest_validated, latest_validated_source) = match public_data_plane
        .cached_txid_latest_validated(&cache_key)
        .map_err(txid_public_cache_failure)?
    {
        Some(latest) if latest.txid_index >= required_txid_index => (latest, "cache"),
        _ => {
            let latest_validated = poi_client
                .latest_validated_railgun_txid(
                    DEFAULT_TXID_VERSION,
                    EVM_CHAIN_TYPE,
                    cfg.chain.chain_id,
                )
                .await
                .map_err(|err| {
                    RecoveryFailure::retryable(
                        OutputPoiRecoveryStatus::MissingMerkleProof,
                        format!("fetch latest validated TXID failed: {err}"),
                        OUTPUT_POI_RECOVERY_TRANSIENT_RETRY_AFTER,
                    )
                })?;
            let latest = PublicTxidLatestValidated {
                txid_index: latest_validated_txid_index(&latest_validated)?,
                merkleroot: latest_validated_txid_root(&latest_validated)?,
            };
            (latest, "rpc")
        }
    };
    let latest_validated_elapsed_ms = latest_validated_started.elapsed().as_millis();
    let cache_sync_started = Instant::now();
    let railgun_contract = cfg.chain.contract.to_string();
    public_data_plane
        .sync_txid_public_cache(PublicTxidSyncRequest {
            key: cache_key.clone(),
            endpoint,
            http_client,
            railgun_contract: &railgun_contract,
            latest: latest_validated,
            indexed_artifact_source,
        })
        .await
        .map_err(txid_public_cache_failure)?;
    let cache_sync_elapsed_ms = cache_sync_started.elapsed().as_millis();

    let expected_leaf = railgun_txid_leaf_hash_with_output_start(
        recovery_chunk.chunk.railgun_txid(),
        u64::from(recovery_chunk.chunk.tree_number),
        U256::from(recovery_chunk.output_start_global),
    );
    let proof_started = Instant::now();
    let cached = public_data_plane
        .txid_public_proof(PublicTxidProofRequest {
            key: cache_key,
            target_txid_index: recovery_chunk.target_txid_index,
            expected_leaf_hash: expected_leaf,
            output_start_global: recovery_chunk.output_start_global,
            latest: latest_validated,
        })
        .map_err(txid_public_cache_failure)?;
    let proof_elapsed_ms = proof_started.elapsed().as_millis();
    let target_tree = cached.target_txid_index / TREE_LEAF_COUNT;
    let target_index = cached.target_txid_index % TREE_LEAF_COUNT;
    let root_index = cached.root_txid_index % TREE_LEAF_COUNT;
    let txid_merkleroot = FixedBytes::from(cached.proof.root.to_be_bytes::<32>());
    let validate_root_started = Instant::now();
    let valid_root = poi_client
        .validate_txid_merkleroot(
            DEFAULT_TXID_VERSION,
            EVM_CHAIN_TYPE,
            cfg.chain.chain_id,
            target_tree,
            root_index,
            &txid_merkleroot,
        )
        .await
        .map_err(|err| {
            RecoveryFailure::retryable(
                OutputPoiRecoveryStatus::MissingMerkleProof,
                format!("validate recovered TXID merkleroot failed: {err}"),
                OUTPUT_POI_RECOVERY_TRANSIENT_RETRY_AFTER,
            )
        })?;
    let validate_root_elapsed_ms = validate_root_started.elapsed().as_millis();
    if !valid_root {
        return Err(RecoveryFailure::retryable(
            OutputPoiRecoveryStatus::MissingMerkleProof,
            "POI node rejected recovered TXID merkleroot",
            OUTPUT_POI_RECOVERY_TRANSIENT_RETRY_AFTER,
        ));
    }
    debug!(
        cache_key = %cfg.cache_key,
        source_tx_hash = %hex::encode(source_tx_hash),
        output_commitment = %hex::encode(output_commitment),
        target_txid_index = cached.target_txid_index,
        root_txid_index = cached.root_txid_index,
        target_tree,
        target_index,
        leaf_count = root_index.saturating_add(1),
        latest_validated_elapsed_ms,
        latest_validated_source,
        cache_sync_elapsed_ms,
        txid_tree_elapsed_ms = proof_elapsed_ms,
        validate_root_elapsed_ms,
        elapsed_ms = started.elapsed().as_millis(),
        "output POI recovery TXID data ready from public cache"
    );

    Ok(RecoveredOutputTxidData {
        target_txid_index: cached.target_txid_index,
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

pub(super) fn latest_validated_txid_index(
    latest_validated: &ValidatedRailgunTxidStatus,
) -> Result<u64, RecoveryFailure> {
    latest_validated.validated_txid_index.ok_or_else(|| {
        RecoveryFailure::retryable(
            OutputPoiRecoveryStatus::MissingMerkleProof,
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
        RecoveryFailure::retryable(
            OutputPoiRecoveryStatus::MissingMerkleProof,
            format!("latest validated TXID root is not hex: {err}"),
            OUTPUT_POI_RECOVERY_TRANSIENT_RETRY_AFTER,
        )
    })?;
    let bytes: [u8; 32] = bytes.try_into().map_err(|bytes: Vec<u8>| {
        RecoveryFailure::retryable(
            OutputPoiRecoveryStatus::MissingMerkleProof,
            format!(
                "latest validated TXID root has {} bytes, expected 32",
                bytes.len()
            ),
            OUTPUT_POI_RECOVERY_TRANSIENT_RETRY_AFTER,
        )
    })?;
    Ok(Some(FixedBytes::from(bytes)))
}

pub(super) fn txid_public_cache_failure(err: TxidPublicCacheError) -> RecoveryFailure {
    let status = match &err {
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
        | TxidPublicCacheError::MetadataMismatch(_) => OutputPoiRecoveryStatus::TxFetchFailed,
    };
    let message = format!("TXID public cache failed: {err}");
    if matches!(status, OutputPoiRecoveryStatus::UnsupportedShape) {
        RecoveryFailure::permanent(status, message)
    } else {
        RecoveryFailure::retryable(status, message, OUTPUT_POI_RECOVERY_TRANSIENT_RETRY_AFTER)
    }
}
