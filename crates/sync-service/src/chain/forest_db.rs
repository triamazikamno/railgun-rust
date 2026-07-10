use super::{
    Arc, ChainConfig, ChainError, DEFAULT_PAGE_SIZE, DbStore, DynProvider, FixedBytes, Instant,
    MerkleForest, MerkleForestSnapshot, Path, PathBuf, PersistError, QuickSyncClient,
    QuickSyncConfig, RwLock, SNAPSHOT_VERSION, SyncProgressStage, SyncProgressUpdate, async_trait,
    debug, info, parse_anchor_block, run_merkle_artifact_catch_up_into,
    run_quick_sync_into_with_progress, send_sync_progress, warn,
};

#[cfg(test)]
use super::{Address, Duration, QueryRpcPool};

#[async_trait]
pub(super) trait MerkleForestDbExt {
    async fn load_or_initialize_forest(
        &self,
        chain: &ChainConfig,
        safe_head: u64,
        provider: Option<&DynProvider>,
        archive_provider: Option<&DynProvider>,
    ) -> Result<(Arc<RwLock<MerkleForest>>, u64, PathBuf, u64), ChainError>;
    fn anchor_dir(&self) -> PathBuf;
    fn find_latest_anchor(&self, chain: &ChainConfig)
    -> Result<Option<(PathBuf, u64)>, ChainError>;
}

#[async_trait]
impl MerkleForestDbExt for DbStore {
    async fn load_or_initialize_forest(
        &self,
        chain: &ChainConfig,
        safe_head: u64,
        provider: Option<&DynProvider>,
        archive_provider: Option<&DynProvider>,
    ) -> Result<(Arc<RwLock<MerkleForest>>, u64, PathBuf, u64), ChainError> {
        let mut forest = MerkleForest::new();
        let mut last_processed = chain.deployment_block.saturating_sub(1);
        let file_name = format!("forest-{}-{}.msgpack", chain.chain_id, chain.contract);
        self.ensure_blob_dir("merkle_forest")?;
        let relative = Self::relative_blob_path("merkle_forest", &file_name);
        let mut snapshot_path = self.resolve_path(&relative);
        let mut last_anchor = 0;

        if let Ok(Some(meta)) =
            self.get_merkle_forest_meta(chain.chain_id, &chain.contract.to_string())
        {
            let path = self.resolve_path(&meta.relative_path);
            match MerkleForestSnapshot::load(&path, chain.chain_id, chain.contract) {
                Ok(Some(snapshot)) => {
                    forest = snapshot.forest;
                    last_processed = snapshot.last_processed_block;
                    snapshot_path = path;
                }
                Ok(None) => {}
                Err(err) => {
                    warn!(?err, path = %path.display(), "failed to load merkle forest snapshot");
                }
            }
        }

        if let Ok(Some((anchor_path, anchor_block))) = self.find_latest_anchor(chain) {
            last_anchor = anchor_block;
            if last_processed < anchor_block {
                match MerkleForestSnapshot::load(&anchor_path, chain.chain_id, chain.contract) {
                    Ok(Some(snapshot)) => {
                        forest = snapshot.forest;
                        last_processed = snapshot.last_processed_block;
                        snapshot_path = anchor_path;
                    }
                    Ok(None) => {}
                    Err(err) => {
                        warn!(?err, path = %anchor_path.display(), "failed to load anchor snapshot");
                    }
                }
            }
        }

        let mut from_block = last_processed.saturating_add(1).max(chain.deployment_block);
        let mut artifact_catch_up_applied = false;
        if chain.should_skip_merkle_artifact_catch_up(from_block, safe_head) {
            debug!(
                chain_id = chain.chain_id,
                from_block,
                safe_head,
                block_range = chain.block_range,
                tail_blocks = safe_head.saturating_sub(from_block).saturating_add(1),
                "skipping merkle artifact catch-up for small tail"
            );
        } else if chain.indexed_artifact_source.is_some() && from_block <= safe_head {
            let artifact_started = Instant::now();
            let artifact_start_block = from_block;
            let mut candidate = forest.clone();
            let progress_tx = chain.progress_tx.clone();
            send_sync_progress(
                progress_tx.as_ref(),
                SyncProgressUpdate::artifact_preparation(
                    SyncProgressStage::SynchronizingCommitments,
                    0,
                    100,
                ),
            );
            match run_merkle_artifact_catch_up_into(
                &mut candidate,
                chain,
                artifact_start_block,
                safe_head,
                progress_tx.as_ref(),
            )
            .await
            {
                Ok(Some(catch_up)) => {
                    let target = catch_up.target_block;
                    let provider_block_hash = match provider {
                        Some(provider) => chain
                            .fetch_confirmed_block_hash(provider, archive_provider, target)
                            .await
                            .unwrap_or_else(|err| {
                                warn!(
                                    ?err,
                                    target,
                                    "failed to fetch confirmed artifact forest target block hash"
                                );
                                None
                            }),
                        None => None,
                    };
                    match persist_indexed_artifact_forest_snapshot(
                        self,
                        chain,
                        &snapshot_path,
                        target,
                        provider_block_hash,
                        catch_up.target_block_hash,
                        &candidate,
                    ) {
                        Ok(true) => {
                            forest = candidate;
                            last_processed = target;
                            from_block =
                                last_processed.saturating_add(1).max(chain.deployment_block);
                            artifact_catch_up_applied = true;
                            send_sync_progress(
                                progress_tx.as_ref(),
                                SyncProgressUpdate::artifact_applied(
                                    SyncProgressStage::SynchronizingCommitments,
                                ),
                            );
                            info!(
                                chain_id = chain.chain_id,
                                from_block = artifact_start_block,
                                target,
                                commitments = catch_up.progress.commitments,
                                elapsed_ms = artifact_started.elapsed().as_millis(),
                                "artifact-backed merkle forest catch-up complete"
                            );
                        }
                        Ok(false) => {
                            warn!(
                                chain_id = chain.chain_id,
                                target,
                                artifact_block_hash = %FixedBytes::<32>::from(catch_up.target_block_hash),
                                provider_block_hash = ?provider_block_hash.map(FixedBytes::<32>::from),
                                "artifact-backed merkle forest target hash mismatch; falling back to configured indexed sources"
                            );
                        }
                        Err(err) => {
                            warn!(
                                ?err,
                                fallback_from = last_processed,
                                "artifact-backed merkle forest persistence failed; falling back to configured indexed sources"
                            );
                        }
                    }
                }
                Ok(None) => {
                    debug!(
                        chain_id = chain.chain_id,
                        from_block = artifact_start_block,
                        safe_head,
                        elapsed_ms = artifact_started.elapsed().as_millis(),
                        "merkle artifact catch-up unavailable"
                    );
                }
                Err(err) => {
                    warn!(
                        ?err,
                        chain_id = chain.chain_id,
                        from_block = artifact_start_block,
                        safe_head,
                        elapsed_ms = artifact_started.elapsed().as_millis(),
                        "merkle artifact catch-up failed; falling back to configured indexed sources"
                    );
                }
            }
        }

        if let Some(endpoint) = chain.quick_sync_endpoint.clone() {
            let client = match chain.http_client.clone() {
                Some(http_client) => {
                    QuickSyncClient::with_http_client(endpoint.clone(), http_client)
                }
                None => QuickSyncClient::new(endpoint.clone()),
            };
            match client.fetch_squid_height().await {
                Ok(indexed_height) => {
                    let target = indexed_height.min(safe_head);
                    info!(
                        chain_id = chain.chain_id,
                        indexed_height,
                        safe_head,
                        current_block = last_processed,
                        target,
                        "indexed forest catch-up target"
                    );
                    if target > last_processed {
                        let start_block = from_block;
                        if start_block <= target {
                            let mut candidate = forest.clone();
                            let config = QuickSyncConfig {
                                endpoint,
                                start_block,
                                end_block: Some(target),
                                page_size: DEFAULT_PAGE_SIZE,
                                http_client: chain.http_client.clone(),
                            };
                            let progress_tx = chain.progress_tx.clone();
                            send_sync_progress(
                                progress_tx.as_ref(),
                                commitment_sync_progress_update(
                                    artifact_catch_up_applied,
                                    start_block,
                                    start_block,
                                    target,
                                ),
                            );
                            match run_quick_sync_into_with_progress(
                                &mut candidate,
                                config,
                                |progress| {
                                    send_sync_progress(
                                        progress_tx.as_ref(),
                                        commitment_sync_progress_update(
                                            artifact_catch_up_applied,
                                            progress.start_block,
                                            progress.latest_block,
                                            target,
                                        ),
                                    );
                                },
                            )
                            .await
                            {
                                Ok(progress) => {
                                    let block_hash = match provider {
                                        Some(provider) => chain
                                            .fetch_confirmed_block_hash(
                                                provider,
                                                archive_provider,
                                                target,
                                            )
                                            .await
                                            .unwrap_or_else(|err| {
                                                warn!(
                                                    ?err,
                                                    target,
                                                    "failed to fetch confirmed indexed forest target block hash"
                                                );
                                                None
                                            }),
                                        None => None,
                                    };
                                    match persist_indexed_forest_snapshot(
                                        self,
                                        chain,
                                        &snapshot_path,
                                        target,
                                        block_hash,
                                        &candidate,
                                    ) {
                                        Ok(()) => {
                                            forest = candidate;
                                            last_processed = target;
                                            send_sync_progress(
                                                progress_tx.as_ref(),
                                                commitment_sync_progress_update(
                                                    artifact_catch_up_applied,
                                                    start_block,
                                                    target,
                                                    target,
                                                ),
                                            );
                                            info!(
                                                chain_id = chain.chain_id,
                                                from_block = start_block,
                                                target,
                                                commitments = progress.commitments,
                                                "indexed forest catch-up complete"
                                            );
                                        }
                                        Err(err) => {
                                            warn!(
                                                ?err,
                                                fallback_from = last_processed,
                                                "indexed forest catch-up persistence failed; falling back to RPC"
                                            );
                                        }
                                    }
                                }
                                Err(err) => {
                                    warn!(
                                        ?err,
                                        fallback_from = last_processed,
                                        "indexed forest catch-up failed; falling back to RPC"
                                    );
                                }
                            }
                        }
                    }
                }
                Err(err) => {
                    warn!(
                        ?err,
                        "indexed forest status query failed; falling back to RPC"
                    );
                }
            }
        }

        Ok((
            Arc::new(RwLock::new(forest)),
            last_processed,
            snapshot_path,
            last_anchor,
        ))
    }

    fn anchor_dir(&self) -> PathBuf {
        self.blob_dir().join("merkle_forest").join("anchors")
    }

    fn find_latest_anchor(
        &self,
        chain: &ChainConfig,
    ) -> Result<Option<(PathBuf, u64)>, ChainError> {
        let dir = self.anchor_dir();
        if !dir.exists() {
            return Ok(None);
        }
        let mut latest: Option<(PathBuf, u64)> = None;
        for entry in std::fs::read_dir(&dir).map_err(PersistError::Io)? {
            let entry = entry.map_err(PersistError::Io)?;
            let name = entry.file_name();
            let Some(name) = name.to_str() else {
                continue;
            };
            if let Some(block) = parse_anchor_block(chain.chain_id, chain.contract, name) {
                let path = entry.path();
                match &latest {
                    Some((_, latest_block)) if *latest_block >= block => {}
                    _ => latest = Some((path, block)),
                }
            }
        }
        Ok(latest)
    }
}

fn persist_indexed_forest_snapshot(
    db: &DbStore,
    chain: &ChainConfig,
    snapshot_path: &Path,
    last_block: u64,
    block_hash: Option<[u8; 32]>,
    forest: &MerkleForest,
) -> Result<(), ChainError> {
    MerkleForestSnapshot::write(
        snapshot_path,
        chain.chain_id,
        chain.contract,
        last_block,
        forest,
    )?;
    db.update_merkle_forest_meta(
        chain.chain_id,
        &chain.contract.to_string(),
        snapshot_path,
        last_block,
        SNAPSHOT_VERSION,
        block_hash.unwrap_or([0u8; 32]),
    )?;
    Ok(())
}

fn persist_indexed_artifact_forest_snapshot(
    db: &DbStore,
    chain: &ChainConfig,
    snapshot_path: &Path,
    last_block: u64,
    provider_block_hash: Option<[u8; 32]>,
    artifact_block_hash: [u8; 32],
    forest: &MerkleForest,
) -> Result<bool, ChainError> {
    if provider_block_hash.is_some_and(|provider_hash| provider_hash != artifact_block_hash) {
        return Ok(false);
    }
    persist_indexed_forest_snapshot(
        db,
        chain,
        snapshot_path,
        last_block,
        Some(artifact_block_hash),
        forest,
    )?;
    Ok(true)
}

const fn commitment_sync_progress_update(
    is_tail: bool,
    start_block: u64,
    current_block: u64,
    target_block: u64,
) -> SyncProgressUpdate {
    if is_tail {
        SyncProgressUpdate::commitment_tail(start_block, current_block, target_block)
    } else {
        SyncProgressUpdate::new(
            SyncProgressStage::SynchronizingCommitments,
            start_block,
            current_block,
            target_block,
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use crate::{IndexedArtifactManifestSource, IndexedArtifactSourceConfig};
    use alloy::primitives::U256;
    use local_db::DbConfig;
    use merkletree::tree::MerkleTreeUpdate;
    use url::Url;

    #[test]
    fn persist_indexed_forest_snapshot_writes_reorg_metadata() {
        let root_dir = temp_db_root("persist-indexed-forest-snapshot");
        let db = DbStore::open(DbConfig {
            root_dir: root_dir.clone(),
        })
        .expect("open db");
        db.ensure_blob_dir("merkle_forest")
            .expect("create merkle forest blob dir");
        let chain = chain_config();
        let relative = DbStore::relative_blob_path(
            "merkle_forest",
            &format!("forest-{}-{}.msgpack", chain.chain_id, chain.contract),
        );
        let snapshot_path = db.resolve_path(&relative);
        let mut forest = MerkleForest::new();
        forest
            .insert_leaf(MerkleTreeUpdate {
                tree_number: 0,
                tree_position: 0,
                hash: U256::from(1),
            })
            .expect("insert leaf");
        forest.compute_roots();
        let block_hash = [0x44; 32];

        persist_indexed_forest_snapshot(
            &db,
            &chain,
            &snapshot_path,
            123,
            Some(block_hash),
            &forest,
        )
        .expect("persist snapshot");

        let meta = db
            .get_merkle_forest_meta(chain.chain_id, &chain.contract.to_string())
            .expect("read forest meta")
            .expect("forest meta present");
        assert_eq!(meta.last_block, 123);
        assert_eq!(meta.hash, block_hash);
        let snapshot = MerkleForestSnapshot::load(&snapshot_path, chain.chain_id, chain.contract)
            .expect("load snapshot")
            .expect("snapshot present");
        assert_eq!(snapshot.last_processed_block, 123);

        drop(db);
        std::fs::remove_dir_all(root_dir).expect("remove temp db dir");
    }

    #[test]
    fn persist_indexed_artifact_forest_snapshot_rejects_provider_hash_mismatch() {
        let root_dir = temp_db_root("persist-indexed-artifact-forest-snapshot-mismatch");
        let db = DbStore::open(DbConfig {
            root_dir: root_dir.clone(),
        })
        .expect("open db");
        db.ensure_blob_dir("merkle_forest")
            .expect("create merkle forest blob dir");
        let chain = chain_config();
        let relative = DbStore::relative_blob_path(
            "merkle_forest",
            &format!("forest-{}-{}.msgpack", chain.chain_id, chain.contract),
        );
        let snapshot_path = db.resolve_path(&relative);
        let mut forest = MerkleForest::new();
        forest
            .insert_leaf(MerkleTreeUpdate {
                tree_number: 0,
                tree_position: 0,
                hash: U256::from(1),
            })
            .expect("insert leaf");
        forest.compute_roots();
        persist_indexed_forest_snapshot(
            &db,
            &chain,
            &snapshot_path,
            100,
            Some([0x10; 32]),
            &forest,
        )
        .expect("seed snapshot metadata");

        let persisted = persist_indexed_artifact_forest_snapshot(
            &db,
            &chain,
            &snapshot_path,
            123,
            Some([0x55; 32]),
            [0x44; 32],
            &forest,
        )
        .expect("hash mismatch should be handled");

        assert!(!persisted);
        let meta = db
            .get_merkle_forest_meta(chain.chain_id, &chain.contract.to_string())
            .expect("read forest meta")
            .expect("forest meta present");
        assert_eq!(meta.last_block, 100);
        assert_eq!(meta.hash, [0x10; 32]);

        drop(db);
        std::fs::remove_dir_all(root_dir).expect("remove temp db dir");
    }

    #[test]
    fn skips_merkle_artifact_catch_up_for_small_tail() {
        let mut chain = chain_config();
        chain.indexed_artifact_source = Some(indexed_artifact_source());
        chain.block_range = 100;

        assert!(chain.should_skip_merkle_artifact_catch_up(101, 200));
        assert!(chain.should_skip_merkle_artifact_catch_up(200, 200));
    }

    #[test]
    fn uses_merkle_artifact_catch_up_for_large_tail() {
        let mut chain = chain_config();
        chain.indexed_artifact_source = Some(indexed_artifact_source());
        chain.block_range = 100;

        assert!(!chain.should_skip_merkle_artifact_catch_up(100, 200));
    }

    #[test]
    fn uses_merkle_artifact_catch_up_without_source_or_when_past_safe_head() {
        let mut chain = chain_config();
        chain.block_range = 100;

        assert!(!chain.should_skip_merkle_artifact_catch_up(101, 200));

        chain.indexed_artifact_source = Some(indexed_artifact_source());
        assert!(!chain.should_skip_merkle_artifact_catch_up(201, 200));
    }

    fn chain_config() -> ChainConfig {
        ChainConfig {
            chain_id: 1,
            contract: Address::ZERO,
            rpcs: Arc::new(QueryRpcPool::new(
                vec![Url::parse("http://127.0.0.1:8545").expect("rpc url")],
                Duration::from_secs(1),
            )),
            archive_rpc_url: None,
            archive_until_block: 0,
            deployment_block: 1,
            v2_start_block: 1,
            legacy_shield_block: 1,
            block_range: 100,
            indexed_wallet_block_range: 100,
            poll_interval: Duration::from_secs(1),
            finality_depth: 0,
            quick_sync_endpoint: None,
            indexed_artifact_source: None,
            anchor_interval: 0,
            anchor_retention: 0,
            http_client: None,
            progress_tx: None,
        }
    }

    fn indexed_artifact_source() -> IndexedArtifactSourceConfig {
        IndexedArtifactSourceConfig {
            trusted_publisher_pubkey: FixedBytes::from([0x22; 32]),
            manifest_source: IndexedArtifactManifestSource::Url(
                Url::parse("https://artifact.example/manifest.json").expect("url"),
            ),
            gateway_urls: vec![Url::parse("https://gateway.example").expect("url")],
            max_manifest_age: None,
            concurrency: 6,
            max_in_flight_bytes: 64 * 1024 * 1024,
        }
    }

    fn temp_db_root(name: &str) -> PathBuf {
        let unique = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("system clock")
            .as_nanos();
        let dir = std::env::temp_dir().join(format!("sync-service-{name}-{unique}"));
        std::fs::create_dir_all(&dir).expect("create temp db dir");
        dir
    }
}
