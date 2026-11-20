use super::*;

pub(super) fn forest_meta(db: &DbStore, chain: &ChainConfig) -> Option<(u64, [u8; 32])> {
    db.get_merkle_forest_meta(
        chain.deployment.chain_id,
        &chain.deployment.contract.to_string(),
    )
    .expect("read forest meta")
    .map(|meta| (meta.last_block, meta.hash))
}

pub(super) fn open_forest_db(name: &str) -> (PathBuf, Arc<DbStore>) {
    let root_dir = temp_db_root(name);
    let db = DbStore::open(DbConfig {
        root_dir: root_dir.clone(),
    })
    .expect("open db");
    (root_dir, Arc::new(db))
}

pub(super) const SQUID_HEIGHT_300: &str = r#"{"data":{"squidStatus":{"height":"300"}}}"#;

pub(super) struct LiveForestFixture {
    pub(super) root_dir: PathBuf,
    pub(super) service: Arc<ChainService>,
    pub(super) forest_rx: watch::Receiver<u64>,
    pub(super) snapshot_path: PathBuf,
    pub(super) task: tokio::task::JoinHandle<()>,
}

impl LiveForestFixture {
    /// Starts the live forest loop at `forest_block` behind a fixed
    /// `safe_head`, with the given RPC endpoints and a Squid endpoint.
    pub(super) async fn spawn(
        name: &str,
        rpc_urls: Vec<Url>,
        squid_url: Url,
        forest_block: u64,
        safe_head: u64,
    ) -> Self {
        let rpcs = Arc::new(QueryRpcPool::new(rpc_urls, Duration::from_secs(1)));
        Self::spawn_with(
            name,
            rpcs,
            forest_block,
            safe_head,
            ChainPoiSubmitterHandle::detached_for_test(),
            |chain| {
                chain.sync.quick_sync_endpoint = Some(squid_url);
            },
        )
        .await
    }

    /// Starts the live forest loop with 10-block pages, so a lag of more than
    /// 640 blocks is far behind, one provider that stays available after a
    /// failed request, and a Squid endpoint.
    pub(super) async fn spawn_far_behind(
        name: &str,
        rpc_url: Url,
        squid_url: Url,
        forest_block: u64,
        safe_head: u64,
        progress_tx: Option<crate::types::SyncProgressSender>,
    ) -> Self {
        let rpcs = Arc::new(QueryRpcPool::new(vec![rpc_url], Duration::ZERO));
        Self::spawn_with(
            name,
            rpcs,
            forest_block,
            safe_head,
            ChainPoiSubmitterHandle::detached_for_test(),
            move |chain| {
                chain.sync.block_range = 10;
                chain.sync.quick_sync_endpoint = Some(squid_url);
                chain.progress_tx = progress_tx;
            },
        )
        .await
    }

    pub(super) async fn spawn_with(
        name: &str,
        rpcs: Arc<QueryRpcPool>,
        forest_block: u64,
        safe_head: u64,
        poi_submitter: ChainPoiSubmitterHandle,
        configure: impl FnOnce(&mut ChainConfig),
    ) -> Self {
        let root_dir = temp_db_root(name);
        let db = Arc::new(
            DbStore::open(DbConfig {
                root_dir: root_dir.clone(),
            })
            .expect("open db"),
        );
        db.ensure_blob_dir("merkle_forest")
            .expect("create merkle forest blob dir");
        let snapshot_path = db.resolve_path(&DbStore::relative_blob_path(
            "merkle_forest",
            "live-forest.msgpack",
        ));
        let mut chain = test_chain_config(&test_scope(), Arc::clone(&rpcs), None);
        configure(&mut chain);
        let public_data_plane =
            ChainPublicDataPlane::new(Arc::clone(&db), Arc::new(AtomicU64::new(0)));
        let service = test_chain_service_with_poi_submitter(
            db,
            chain,
            public_data_plane,
            test_proxy_poi_policy(),
            poi_submitter,
        )
        .0;
        service.forest_last_tx.send_replace(forest_block);
        service.safe_head_tx.send_replace(safe_head);
        let forest_rx = service.forest_last_tx.subscribe();
        let task = spawn_live_log_loop(
            Arc::clone(&service),
            rpcs,
            None,
            service.forest_last_tx.subscribe(),
            service.safe_head_tx.subscribe(),
            snapshot_path.clone(),
            service.cancel.clone(),
        );
        // Let the loop start its stall period at the current paused instant.
        for _ in 0..8 {
            tokio::task::yield_now().await;
        }
        Self {
            root_dir,
            service,
            forest_rx,
            snapshot_path,
            task,
        }
    }

    pub(super) fn meta(&self) -> Option<(u64, [u8; 32])> {
        forest_meta(&self.service.db, &self.service.chain)
    }

    /// Last block of the persisted forest snapshot, if one was written.
    pub(super) fn snapshot_block(&self) -> Option<u64> {
        let deployment = &self.service.chain.deployment;
        merkletree::persist::MerkleForestSnapshot::load(
            &self.snapshot_path,
            deployment.chain_id,
            deployment.contract,
        )
        .expect("read forest snapshot")
        .map(|snapshot| snapshot.last_processed_block)
    }

    pub(super) fn stall_period(&self) -> Duration {
        wallet_tail_fallback_stale_timeout(self.service.chain.block_time)
    }

    pub(super) async fn stop(self) {
        let Self {
            root_dir,
            service,
            task,
            ..
        } = self;
        service.cancel.cancel();
        task.await.expect("live forest loop exits");
        drop(service);
        fs::remove_dir_all(root_dir).expect("remove temp db dir");
    }
}
