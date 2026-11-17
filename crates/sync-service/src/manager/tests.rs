use std::fs;
use std::net::TcpListener;
use std::sync::Barrier;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use alloy::primitives::Address;
use broadcaster_core::query_rpc_pool::QueryRpcPool;
use local_db::DbConfig;
use url::Url;

use super::*;
use crate::types::{PoiArtifactManifestSource, PoiArtifactSourceConfig, PoiProxyFallback};

struct StalledRpc {
    url: Url,
    accepted: tokio::sync::Mutex<tokio::sync::mpsc::UnboundedReceiver<()>>,
    release: Arc<AtomicBool>,
}

impl StalledRpc {
    async fn wait_for_request(&self) {
        tokio::time::timeout(Duration::from_secs(2), self.accepted.lock().await.recv())
            .await
            .expect("stalled RPC request timeout")
            .expect("stalled RPC request");
    }
}

impl Drop for StalledRpc {
    fn drop(&mut self) {
        self.release.store(true, Ordering::Release);
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn manager_ownership_is_exclusive_and_released_by_shutdown() {
    let (db, root) = test_db("manager-ownership");
    let first =
        Arc::new(SyncManager::new(Arc::clone(&db), proxy_policy()).expect("acquire first manager"));

    assert!(matches!(
        SyncManager::new(Arc::clone(&db), proxy_policy()),
        Err(SyncManagerError::DatabaseAlreadyOwned { .. })
    ));

    first.shutdown().await;
    let replacement = SyncManager::new(Arc::clone(&db), proxy_policy())
        .expect("replace manager after orderly shutdown");
    assert!(matches!(
        first.reset_public_sync_caches().await,
        Err(SyncManagerError::Shutdown)
    ));
    replacement.shutdown().await;

    drop(replacement);
    drop(first);
    drop(db);
    fs::remove_dir_all(root).expect("remove manager ownership db");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn manager_shutdown_aborts_pending_wallet_poi_jobs_before_releasing_ownership() {
    let (db, root) = test_db("manager-tracked-poi-job");
    let manager =
        SyncManager::new(Arc::clone(&db), proxy_policy()).expect("acquire manager ownership");
    let contract = Address::from([0x51; 20]);
    let service = manager
        .add_chain(chain_config(1, contract))
        .await
        .expect("add chain");
    let wallet = service
        .register_wallet(WalletConfig {
            chain: ChainKey {
                chain_id: 1,
                contract,
            },
            cache_key: local_db::WalletCacheKey::from_opaque_bytes(b"tracked-poi-job")
                .expect("wallet cache key"),
            start_block: Some(0),
            sync_to_block: None,
            quick_sync_endpoint: None,
            scan_keys: broadcaster_core::crypto::railgun::ViewingKeyData {
                viewing_private_key: [0u8; 32],
                viewing_public_key: [0u8; 32],
                nullifying_key: alloy::primitives::U256::ZERO,
                master_public_key: alloy::primitives::U256::ZERO,
            },
            spending_public_key: None,
            progress_tx: None,
            cache_store: None,
            poi_recovery_prover: None,
            use_indexed_wallet_catch_up: false,
        })
        .await
        .expect("register wallet");
    // The job holds a data-plane clone, which carries the manager's runtime lease.
    let sentinel = Arc::new(());
    let job_sentinel = Arc::downgrade(&sentinel);
    let (started_tx, started_rx) = tokio::sync::oneshot::channel();
    service
        .send_wallet_backfill_event_for_test(
            crate::types::BackfillEvent::HoldTrackedPoiJobForTest {
                sentinel,
                started: started_tx,
            },
        )
        .await;
    tokio::time::timeout(Duration::from_secs(2), started_rx)
        .await
        .expect("tracked job starts")
        .expect("tracked job start signal");

    manager.shutdown().await;
    assert!(
        job_sentinel.upgrade().is_none(),
        "manager shutdown returns only after the tracked job is gone"
    );
    drop(wallet);
    drop(service);
    // The wallet terminal reaper keeps its own data-plane clone until it takes the
    // registration gate, which shutdown releases on return. The tracked job never
    // completes, so without the abort this wait times out.
    let replacement = tokio::time::timeout(Duration::from_secs(2), async {
        loop {
            match SyncManager::new(Arc::clone(&db), proxy_policy()) {
                Ok(manager) => break manager,
                Err(SyncManagerError::DatabaseAlreadyOwned { .. }) => {
                    tokio::task::yield_now().await;
                }
                Err(error) => panic!("unexpected replacement-manager error: {error}"),
            }
        }
    })
    .await
    .expect("admit a new manager after shutdown with a pending POI job");
    replacement.shutdown().await;

    drop(replacement);
    drop(manager);
    drop(db);
    fs::remove_dir_all(root).expect("remove tracked POI job db");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn dropped_manager_keeps_runtime_admission_until_chain_runtime_stops() {
    let (db, root) = test_db("dropped-manager-runtime-ownership");
    let manager =
        SyncManager::new(Arc::clone(&db), proxy_policy()).expect("acquire manager ownership");
    let service = manager
        .add_chain(chain_config(1, Address::from([0x21; 20])))
        .await
        .expect("start guarded chain runtime");

    drop(manager);

    assert!(service.shutdown_started());
    assert!(matches!(
        SyncManager::new(Arc::clone(&db), proxy_policy()),
        Err(SyncManagerError::DatabaseAlreadyOwned { .. })
    ));

    service.shutdown().await;
    drop(service);
    let replacement = tokio::time::timeout(Duration::from_secs(2), async {
        loop {
            match SyncManager::new(Arc::clone(&db), proxy_policy()) {
                Ok(manager) => break manager,
                Err(SyncManagerError::DatabaseAlreadyOwned { .. }) => {
                    tokio::task::yield_now().await;
                }
                Err(error) => panic!("unexpected replacement-manager error: {error}"),
            }
        }
    })
    .await
    .expect("chain runtime releases admission after cancellation");
    replacement.shutdown().await;

    drop(replacement);
    drop(db);
    fs::remove_dir_all(root).expect("remove dropped manager ownership db");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn concurrent_manager_acquisition_has_one_winner() {
    let (db, root) = test_db("concurrent-manager-ownership");
    let barrier = Arc::new(Barrier::new(2));
    let acquire = |db: Arc<DbStore>, barrier: Arc<Barrier>| {
        tokio::task::spawn_blocking(move || {
            barrier.wait();
            SyncManager::new(db, proxy_policy())
        })
    };
    let (first, second) = tokio::join!(
        acquire(Arc::clone(&db), Arc::clone(&barrier)),
        acquire(Arc::clone(&db), barrier),
    );
    let first = first.expect("first acquisition task");
    let second = second.expect("second acquisition task");
    assert_eq!(usize::from(first.is_ok()) + usize::from(second.is_ok()), 1);
    assert!(
        first
            .as_ref()
            .err()
            .or_else(|| second.as_ref().err())
            .is_some_and(|error| matches!(error, SyncManagerError::DatabaseAlreadyOwned { .. }))
    );
    let winner = first
        .ok()
        .or_else(|| second.ok())
        .expect("one manager wins");
    winner.shutdown().await;

    drop(winner);
    drop(db);
    fs::remove_dir_all(root).expect("remove concurrent manager ownership db");
}

#[tokio::test]
async fn concurrent_exact_chain_admission_returns_one_service() {
    let (db, root) = test_db("concurrent-chain-admission");
    let manager =
        SyncManager::new(Arc::clone(&db), proxy_policy()).expect("acquire manager ownership");
    let cfg = chain_config(1, Address::from([0x11; 20]));

    let (first, second) = tokio::join!(
        manager.add_chain(cfg.clone()),
        manager.add_chain(cfg.clone()),
    );
    let first = first.expect("first exact chain admission");
    let second = second.expect("second exact chain admission");
    assert!(Arc::ptr_eq(&first, &second));
    assert_eq!(manager.chain_count_for_test(), 1);

    manager.shutdown().await;
    drop(first);
    drop(second);
    drop(manager);
    drop(db);
    fs::remove_dir_all(root).expect("remove concurrent chain admission db");
}

#[tokio::test]
async fn existing_chain_admission_does_not_wait_for_public_cache_reset() {
    let (db, root) = test_db("existing-chain-during-reset");
    let manager =
        SyncManager::new(Arc::clone(&db), proxy_policy()).expect("acquire manager ownership");
    let cfg = chain_config(1, Address::from([0x19; 20]));
    let first = manager
        .add_chain(cfg.clone())
        .await
        .expect("start existing chain");
    {
        let mut state = manager
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let (reset, _) = watch::channel(false);
        state.reset = Some(reset);
    }

    let reused = tokio::time::timeout(Duration::from_millis(100), manager.add_chain(cfg))
        .await
        .expect("existing chain admission must not wait for public cache reset")
        .expect("reuse existing chain");

    assert!(Arc::ptr_eq(&first, &reused));
    let reset = manager
        .state
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .reset
        .take()
        .expect("held public cache reset admission");
    let _ = reset.send(true);
    manager.shutdown().await;

    drop(first);
    drop(reused);
    drop(manager);
    drop(db);
    fs::remove_dir_all(root).expect("remove existing-chain reset db");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn shutdown_cancels_stalled_chain_preparation() {
    let (db, root) = test_db("shutdown-stalled-chain");
    let manager = Arc::new(
        SyncManager::new(Arc::clone(&db), proxy_policy()).expect("acquire manager ownership"),
    );
    let stalled = stalled_rpc();
    let cfg = chain_config_with_rpc(1, Address::from([0x12; 20]), stalled.url.clone());
    let start = tokio::spawn({
        let manager = Arc::clone(&manager);
        async move { manager.add_chain(cfg).await }
    });
    stalled.wait_for_request().await;

    tokio::time::timeout(Duration::from_secs(2), manager.shutdown())
        .await
        .expect("shutdown must not wait for stalled RPC");
    assert!(matches!(
        start.await.expect("chain start task"),
        Err(SyncManagerError::Shutdown)
    ));
    assert_eq!(manager.chain_count_for_test(), 0);

    drop(stalled);
    drop(manager);
    drop(db);
    fs::remove_dir_all(root).expect("remove stalled shutdown db");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn cancelled_removal_keeps_admission_until_owned_cleanup_finishes() {
    let (db, root) = test_db("cancelled-removal-admission");
    let manager = Arc::new(
        SyncManager::new(Arc::clone(&db), proxy_policy()).expect("acquire manager ownership"),
    );
    let contract = Address::from([0x18; 20]);
    let key = ChainKey {
        chain_id: 1,
        contract,
    };
    let pending_done = {
        let mut state = manager
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let (done, done_rx) = watch::channel(false);
        state.pending_starts.insert(
            key,
            PendingChainStart {
                id: 1,
                cancel: CancellationToken::new(),
                cancellation: None,
                done,
            },
        );
        done_rx
    };
    let removal = tokio::spawn({
        let manager = Arc::clone(&manager);
        async move { manager.remove_chain(&key).await }
    });
    tokio::time::timeout(Duration::from_secs(1), async {
        loop {
            if manager
                .state
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .removals
                .contains_key(&key)
            {
                break;
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("removal admission installed");
    removal.abort();
    let _ = removal.await;

    let replacement = tokio::spawn({
        let manager = Arc::clone(&manager);
        async move { manager.add_chain(chain_config(1, contract)).await }
    });
    tokio::task::yield_now().await;
    assert!(!replacement.is_finished());
    let pending = manager
        .state
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .pending_starts
        .remove(&key)
        .expect("pending start remains until cleanup");
    let _ = pending.done.send(true);
    drop(pending_done);
    let service = tokio::time::timeout(Duration::from_secs(2), replacement)
        .await
        .expect("replacement admitted after owned cleanup")
        .expect("replacement task")
        .expect("replacement chain");
    manager.shutdown().await;

    drop(service);
    drop(manager);
    drop(db);
    fs::remove_dir_all(root).expect("remove cancelled removal db");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn shutdown_cleanup_survives_initiating_future_cancellation() {
    let (db, root) = test_db("cancelled-shutdown-cleanup");
    let manager = Arc::new(
        SyncManager::new(Arc::clone(&db), proxy_policy()).expect("acquire manager ownership"),
    );
    {
        let mut state = manager
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let (reset, _) = watch::channel(false);
        state.reset = Some(reset);
    }
    let first = tokio::spawn({
        let manager = Arc::clone(&manager);
        async move { manager.shutdown().await }
    });
    tokio::time::timeout(Duration::from_secs(1), async {
        loop {
            if manager
                .state
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .lifecycle
                == SyncManagerLifecycle::Stopping
            {
                break;
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("manager enters stopping state");
    let second = tokio::spawn({
        let manager = Arc::clone(&manager);
        async move { manager.shutdown().await }
    });
    tokio::task::yield_now().await;
    assert!(!second.is_finished());
    first.abort();
    let _ = first.await;

    let reset = manager
        .state
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .reset
        .take()
        .expect("active reset admission");
    let _ = reset.send(true);
    tokio::time::timeout(Duration::from_secs(2), second)
        .await
        .expect("owned shutdown cleanup completes")
        .expect("second shutdown waiter");
    let replacement = SyncManager::new(Arc::clone(&db), proxy_policy())
        .expect("shutdown task releases runtime ownership");
    replacement.shutdown().await;

    drop(replacement);
    drop(manager);
    drop(db);
    fs::remove_dir_all(root).expect("remove cancelled shutdown db");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn removal_cancels_stalled_start_and_allows_replacement() {
    let (db, root) = test_db("remove-stalled-chain");
    let manager = Arc::new(
        SyncManager::new(Arc::clone(&db), proxy_policy()).expect("acquire manager ownership"),
    );
    let stalled = stalled_rpc();
    let contract = Address::from([0x13; 20]);
    let cfg = chain_config_with_rpc(1, contract, stalled.url.clone());
    let key = ChainKey {
        chain_id: cfg.deployment.chain_id,
        contract,
    };
    let start = tokio::spawn({
        let manager = Arc::clone(&manager);
        async move { manager.add_chain(cfg).await }
    });
    stalled.wait_for_request().await;

    tokio::time::timeout(Duration::from_secs(2), manager.remove_chain(&key))
        .await
        .expect("removal must cancel stalled start");
    assert!(matches!(
        start.await.expect("chain start task"),
        Err(SyncManagerError::ChainStartRemoved)
    ));
    manager
        .add_chain(chain_config(1, contract))
        .await
        .expect("replacement after cancelled removal");
    manager.shutdown().await;

    drop(stalled);
    drop(manager);
    drop(db);
    fs::remove_dir_all(root).expect("remove stalled removal db");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn public_cache_reset_cancels_stalled_start_and_releases_admission() {
    let (db, root) = test_db("reset-stalled-chain");
    let manager = Arc::new(
        SyncManager::new(Arc::clone(&db), proxy_policy()).expect("acquire manager ownership"),
    );
    let stalled = stalled_rpc();
    let contract = Address::from([0x14; 20]);
    let cfg = chain_config_with_rpc(1, contract, stalled.url.clone());
    let start = tokio::spawn({
        let manager = Arc::clone(&manager);
        async move { manager.add_chain(cfg).await }
    });
    stalled.wait_for_request().await;

    tokio::time::timeout(Duration::from_secs(2), manager.reset_public_sync_caches())
        .await
        .expect("reset must cancel stalled start")
        .expect("reset public caches");
    assert!(matches!(
        start.await.expect("chain start task"),
        Err(SyncManagerError::ChainStartReset)
    ));
    manager
        .add_chain(chain_config(1, contract))
        .await
        .expect("replacement after reset admission");
    manager.shutdown().await;

    drop(stalled);
    drop(manager);
    drop(db);
    fs::remove_dir_all(root).expect("remove stalled reset db");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn dropped_chain_start_future_releases_pending_admission() {
    let (db, root) = test_db("dropped-stalled-chain");
    let manager = Arc::new(
        SyncManager::new(Arc::clone(&db), proxy_policy()).expect("acquire manager ownership"),
    );
    let stalled = stalled_rpc();
    let contract = Address::from([0x15; 20]);
    let start = tokio::spawn({
        let manager = Arc::clone(&manager);
        let cfg = chain_config_with_rpc(1, contract, stalled.url.clone());
        async move { manager.add_chain(cfg).await }
    });
    stalled.wait_for_request().await;
    start.abort();
    let Err(join_error) = start.await else {
        panic!("aborted chain start completed");
    };
    assert!(join_error.is_cancelled());

    manager
        .add_chain(chain_config(1, contract))
        .await
        .expect("replacement after dropped start future");
    manager.shutdown().await;

    drop(stalled);
    drop(manager);
    drop(db);
    fs::remove_dir_all(root).expect("remove dropped start db");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn indexed_conflict_includes_pending_chain_start() {
    let (db, root) = test_db("pending-indexed-conflict");
    let manager = Arc::new(
        SyncManager::new(Arc::clone(&db), indexed_policy()).expect("acquire manager ownership"),
    );
    let stalled = stalled_rpc();
    let first_contract = Address::from([0x16; 20]);
    let first = tokio::spawn({
        let manager = Arc::clone(&manager);
        let cfg = chain_config_with_rpc(1, first_contract, stalled.url.clone());
        async move { manager.add_chain(cfg).await }
    });
    stalled.wait_for_request().await;
    let second_contract = Address::from([0x17; 20]);

    assert!(matches!(
        manager.add_chain(chain_config(1, second_contract)).await,
        Err(SyncManagerError::PoiCoordinatorConflict {
            chain_id: 1,
            existing_contract,
            requested_contract,
        }) if existing_contract == first_contract && requested_contract == second_contract
    ));
    manager.shutdown().await;
    assert!(matches!(
        first.await.expect("pending indexed start"),
        Err(SyncManagerError::Shutdown)
    ));

    drop(stalled);
    drop(manager);
    drop(db);
    fs::remove_dir_all(root).expect("remove pending indexed conflict db");
}

#[tokio::test]
async fn indexed_policy_owns_chain_id_while_proxy_preserves_contract_scoping() {
    let (indexed_db, indexed_root) = test_db("indexed-chain-ownership");
    let indexed = SyncManager::new(Arc::clone(&indexed_db), indexed_policy())
        .expect("acquire indexed manager");
    indexed
        .add_chain(chain_config(1, Address::from([0x21; 20])))
        .await
        .expect("add indexed chain");
    assert!(matches!(
        indexed
            .add_chain(chain_config(1, Address::from([0x22; 20])))
            .await,
        Err(SyncManagerError::PoiCoordinatorConflict {
            chain_id: 1,
            existing_contract,
            requested_contract,
        }) if existing_contract == Address::from([0x21; 20])
            && requested_contract == Address::from([0x22; 20])
    ));
    indexed
        .add_chain(chain_config(2, Address::from([0x23; 20])))
        .await
        .expect("add distinct indexed chain");
    indexed.shutdown().await;

    let (proxy_db, proxy_root) = test_db("proxy-contract-scoping");
    let proxy =
        SyncManager::new(Arc::clone(&proxy_db), proxy_policy()).expect("acquire proxy manager");
    proxy
        .add_chain(chain_config(1, Address::from([0x31; 20])))
        .await
        .expect("add first proxy contract");
    proxy
        .add_chain(chain_config(1, Address::from([0x32; 20])))
        .await
        .expect("add second proxy contract");
    assert_eq!(proxy.chain_count_for_test(), 2);
    proxy.shutdown().await;

    drop(indexed);
    drop(indexed_db);
    fs::remove_dir_all(indexed_root).expect("remove indexed ownership db");
    drop(proxy);
    drop(proxy_db);
    fs::remove_dir_all(proxy_root).expect("remove proxy contract db");
}

#[tokio::test]
async fn shutdown_is_terminal_idempotent_and_allows_chain_replacement_before_it() {
    let (db, root) = test_db("manager-shutdown");
    let manager =
        SyncManager::new(Arc::clone(&db), proxy_policy()).expect("acquire manager ownership");
    let contract = Address::from([0x41; 20]);
    let cfg = chain_config(1, contract);
    let first = manager
        .add_chain(cfg.clone())
        .await
        .expect("add initial chain");
    manager
        .remove_chain(&ChainKey {
            chain_id: cfg.deployment.chain_id,
            contract: cfg.deployment.contract,
        })
        .await;
    let replacement = manager
        .add_chain(chain_config(1, contract))
        .await
        .expect("re-add chain after complete removal");
    assert!(!Arc::ptr_eq(&first, &replacement));

    manager.shutdown().await;
    manager.shutdown().await;
    assert!(matches!(
        manager.add_chain(chain_config(1, contract)).await,
        Err(SyncManagerError::Shutdown)
    ));

    drop(first);
    drop(replacement);
    drop(manager);
    drop(db);
    fs::remove_dir_all(root).expect("remove manager shutdown db");
}

fn proxy_policy() -> GlobalPoiPolicy {
    GlobalPoiPolicy::PoiProxy {
        rpc_url: Url::parse("http://127.0.0.1:1").expect("proxy URL").into(),
    }
}

fn indexed_policy() -> GlobalPoiPolicy {
    GlobalPoiPolicy::IndexedArtifacts {
        artifact_source: PoiArtifactSourceConfig {
            trusted_publisher_pubkey: [0x42; 32].into(),
            manifest_source: PoiArtifactManifestSource::Url(
                Url::parse("http://127.0.0.1:1/manifest.json")
                    .expect("manifest URL")
                    .into(),
            ),
            gateway_urls: Vec::new(),
            gateway_pool: None,
            max_manifest_age: None,
        },
        rpc_url: Url::parse("http://127.0.0.1:1")
            .expect("POI RPC URL")
            .into(),
        wallet_read_fallback: PoiProxyFallback::Disabled,
    }
}

fn chain_config(chain_id: u64, contract: Address) -> ChainConfig {
    ChainConfig {
        deployment: broadcaster_core::deployment::RailgunDeployment {
            chain_id,
            contract,
            deployment_block: 0,
            v2_start_block: 0,
            legacy_shield_block: 0,
            relay_adapt_contract: None,
            relay_adapt_7702_contract: Address::ZERO,
            relay_adapt_7702_delegates: &[],
            relay_adapt_history: &[],
        },
        sync: crate::RailgunSyncOptions {
            archive_until_block: 0,
            block_range: 100,
            indexed_wallet_block_range: 100,
            poll_interval: Duration::from_mins(1),
            quick_sync_endpoint: None,
            indexed_artifact_source: None,
            anchor_interval: 1000,
            anchor_retention: 5,
        },
        rpcs: Arc::new(QueryRpcPool::new(
            vec![Url::parse("http://127.0.0.1:1").expect("RPC URL")],
            Duration::from_millis(1),
        )),
        archive_rpc_url: None,
        archive_rpc_http_client: None,
        block_time: Duration::from_secs(12),
        finality_depth: 0,
        http_client: reqwest::Client::new(),
        progress_tx: None,
        poi_submission_routes: None,
    }
}

fn chain_config_with_rpc(chain_id: u64, contract: Address, rpc_url: Url) -> ChainConfig {
    let mut cfg = chain_config(chain_id, contract);
    cfg.rpcs = Arc::new(QueryRpcPool::new(vec![rpc_url], Duration::from_millis(1)));
    cfg
}

fn stalled_rpc() -> StalledRpc {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind stalled RPC server");
    listener
        .set_nonblocking(true)
        .expect("set stalled RPC listener nonblocking");
    let url = Url::parse(&format!(
        "http://{}",
        listener.local_addr().expect("stalled RPC local addr")
    ))
    .expect("stalled RPC URL");
    let (accepted_tx, accepted) = tokio::sync::mpsc::unbounded_channel();
    let release = Arc::new(AtomicBool::new(false));
    let thread_release = Arc::clone(&release);
    std::thread::spawn(move || {
        let mut streams = Vec::new();
        while !thread_release.load(Ordering::Acquire) {
            match listener.accept() {
                Ok((stream, _)) => {
                    streams.push(stream);
                    let _ = accepted_tx.send(());
                }
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                    std::thread::sleep(Duration::from_millis(5));
                }
                Err(_) => break,
            }
        }
    });
    StalledRpc {
        url,
        accepted: tokio::sync::Mutex::new(accepted),
        release,
    }
}

fn test_db(name: &str) -> (Arc<DbStore>, PathBuf) {
    let root = temp_db_root(name);
    fs::create_dir_all(&root).expect("create test db root");
    let db = Arc::new(
        DbStore::open(DbConfig {
            root_dir: root.clone(),
        })
        .expect("open test db"),
    );
    (db, root)
}

fn temp_db_root(name: &str) -> PathBuf {
    static COUNTER: AtomicU64 = AtomicU64::new(0);
    let unique = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system time")
        .as_nanos();
    let counter = COUNTER.fetch_add(1, Ordering::Relaxed);
    std::env::temp_dir().join(format!("sync-manager-{name}-{unique}-{counter}"))
}
