use super::*;

#[tokio::test]
async fn cached_public_coverage_partial_segment_does_not_publish_ready() {
    let root_dir = temp_db_root("cached-coverage-no-intermediate-ready");
    let db = Arc::new(
        DbStore::open(DbConfig {
            root_dir: root_dir.clone(),
        })
        .expect("open db"),
    );
    let scope = test_scope();
    let rpcs = Arc::new(QueryRpcPool::new(
        vec![Url::parse("http://127.0.0.1:1").expect("rpc url")],
        Duration::from_secs(1),
    ));
    let chain = test_chain_config(&scope, Arc::clone(&rpcs), None);
    let public_data_plane = ChainPublicDataPlane::new(
        Arc::clone(&db),
        Arc::new(std::sync::atomic::AtomicU64::new(0)),
    );
    let service = test_chain_service(Arc::clone(&db), chain, public_data_plane.clone());
    let cfg = test_wallet_config(&scope, Url::parse("http://127.0.0.1:1").expect("url"));
    public_data_plane
        .record_public_scan_coverage(PublicScanCoverageWrite {
            range: PublicScanRange::new(101, 150),
            source: PublicScanSource::Rpc,
            row_count: 0,
            read_scope: PublicScanReadScope::new(PublicDataPlaneEpoch::new(0)),
        })
        .await
        .expect("record cached coverage");
    let (_live_tx, live_rx) = broadcast::channel(8);
    let (backfill_tx, backfill_rx) = mpsc::channel(8);
    let (backfill_request_tx, _backfill_request_rx) = mpsc::channel(8);
    let cancel = CancellationToken::new();
    let handle = spawn_wallet_worker(
        WalletWorkerServices {
            db: Arc::clone(&db),
            http_client: None,
            indexed_artifact_source: None,
            poi_runtime: test_wallet_poi_runtime(),
            forest: Arc::new(RwLock::new(MerkleForest::new())),
            backfill_tx: backfill_request_tx,
            backfill_sender: backfill_tx.clone(),
            public_data_plane: public_data_plane.clone(),
            poi_submitter: ChainPoiSubmitterHandle::detached_for_test(),
        },
        cfg.clone(),
        1,
        live_rx,
        backfill_rx,
        cancel.clone(),
        Vec::new(),
        100,
    )
    .await
    .expect("spawn wallet worker");

    let outcome = service
        .apply_cached_public_scan_coverage(
            WalletSyncContext {
                cfg: &cfg,
                start_block: 0,
                handle: &handle,
                backfill_sender: &backfill_tx,
            },
            100,
            200,
            crate::types::WalletSchedulableProgress {
                last_scanned: 100,
                reset_generation: 0,
            },
        )
        .await;

    assert_eq!(outcome.checkpoint, 150);
    assert!(!outcome.finished);
    assert_eq!(handle.last_scanned(), Some(150));
    assert_eq!(handle.readiness(), WalletReadiness::Syncing);

    cancel.cancel();
    drop(db);
    fs::remove_dir_all(root_dir).expect("remove temp db dir");
}

#[tokio::test]
async fn public_scan_coverage_arbitrates_uncached_range_through_sources() {
    let root_dir = temp_db_root("public-coverage-source-arbitration");
    let db = Arc::new(
        DbStore::open(DbConfig {
            root_dir: root_dir.clone(),
        })
        .expect("open db"),
    );
    let scope = ChainScope {
        chain_type: ChainType::Evm,
        chain_id: 1,
        railgun_contract: Address::from([0xbb; 20]),
    };
    let artifact_source = checkpointed_wallet_artifact_source(&scope, 100, 150, 150);
    let rpcs = Arc::new(QueryRpcPool::new(
        vec![Url::parse("http://127.0.0.1:1").expect("rpc url")],
        Duration::from_secs(1),
    ));
    let chain = test_chain_config(&scope, Arc::clone(&rpcs), Some(artifact_source.config));
    let public_data_plane = ChainPublicDataPlane::new(
        Arc::clone(&db),
        Arc::new(std::sync::atomic::AtomicU64::new(0)),
    );
    let service = test_chain_service(Arc::clone(&db), chain, public_data_plane.clone());

    let answer = service
        .public_data_plane()
        .public_scan_coverage(PublicScanRange::new(100, 150))
        .await
        .expect("public coverage answer");

    assert!(matches!(
        answer,
        PublicCoverageAnswer::ReplayableEmpty {
            range: PublicScanRange {
                from_block: 100,
                to_block: 150
            },
            source: PublicScanSource::IndexedArtifacts,
            epoch: PublicDataPlaneEpoch { value: 0 },
        }
    ));
    let diagnostics = public_data_plane.diagnostics().await;
    assert!(diagnostics.events.iter().any(|event| {
        event.kind == PublicDataPlaneDiagnosticKind::SourceSelected
            && event.source == Some(PublicScanSource::IndexedArtifacts)
            && event.range == Some(PublicScanRange::new(100, 150))
    }));

    drop(db);
    drop(artifact_source.server);
    fs::remove_dir_all(root_dir).expect("remove temp db dir");
}

#[tokio::test]
async fn public_scan_coverage_distinguishes_row_bearing_cached_coverage() {
    let root_dir = temp_db_root("public-coverage-row-bearing-cache");
    let db = Arc::new(
        DbStore::open(DbConfig {
            root_dir: root_dir.clone(),
        })
        .expect("open db"),
    );
    let scope = ChainScope {
        chain_type: ChainType::Evm,
        chain_id: 1,
        railgun_contract: Address::from([0xbb; 20]),
    };
    let rpcs = Arc::new(QueryRpcPool::new(
        vec![Url::parse("http://127.0.0.1:1").expect("rpc url")],
        Duration::from_secs(1),
    ));
    let chain = test_chain_config(&scope, Arc::clone(&rpcs), None);
    let public_data_plane = ChainPublicDataPlane::new(
        Arc::clone(&db),
        Arc::new(std::sync::atomic::AtomicU64::new(0)),
    );
    let range = PublicScanRange::new(100, 110);
    public_data_plane
        .record_public_scan_coverage(PublicScanCoverageWrite {
            range,
            source: PublicScanSource::Rpc,
            row_count: 7,
            read_scope: public_data_plane.begin_public_scan_read(),
        })
        .await
        .expect("record row-bearing coverage");
    let service = test_chain_service(Arc::clone(&db), chain, public_data_plane.clone());

    let answer = service
        .public_data_plane()
        .public_scan_coverage(range)
        .await
        .expect("public coverage answer");

    assert_eq!(
        answer,
        PublicCoverageAnswer::CoveredWithRows {
            range,
            source: PublicScanSource::Rpc,
            epoch: PublicDataPlaneEpoch::new(0),
        }
    );
    assert!(
        public_data_plane
            .cached_wallet_scan_apply(range.from_block, range.to_block)
            .await
            .is_none(),
        "row-bearing coverage must not be replayed as empty coverage"
    );

    drop(service);
    drop(db);
    fs::remove_dir_all(root_dir).expect("remove temp db dir");
}

#[tokio::test]
async fn saved_poi_source_block_rows_uses_bound_service_for_exact_block() {
    let root_dir = temp_db_root("saved-poi-source-block-bound-service");
    let db = Arc::new(
        DbStore::open(DbConfig {
            root_dir: root_dir.clone(),
        })
        .expect("open db"),
    );
    let squid = GraphqlServer::spawn_controlled(
        vec![
            squid_wallet_probe(200),
            squid_wallet_page_with_nullifier(120),
        ],
        None,
    );
    let rpcs = Arc::new(QueryRpcPool::new(Vec::new(), Duration::from_secs(1)));
    let mut chain = test_chain_config(&test_scope(), rpcs, None);
    chain.sync.quick_sync_endpoint = Some(squid.url.clone());
    let public_data_plane = ChainPublicDataPlane::new(Arc::clone(&db), Arc::new(AtomicU64::new(0)));
    let service = test_chain_service(Arc::clone(&db), chain, public_data_plane.clone());
    public_data_plane.bind_scan_service(&service);

    let answer = public_data_plane
        .saved_poi_source_block_rows(120)
        .await
        .expect("fetch saved PPOI source block");
    let PublicScanRowsAnswer::Rows(rows) = answer else {
        panic!("the bound service must fetch uncached source block rows");
    };
    assert_eq!(rows.range, PublicScanRange::new(120, 120));
    assert_eq!(rows.source, PublicScanSource::Squid);
    assert_eq!(rows.rows.nullifiers.len(), 1);

    let requests = squid.requests.try_iter().collect::<Vec<_>>();
    assert_eq!(requests.len(), 2);
    let page_request = json_rpc_request_body(&requests[1]);
    assert_eq!(page_request["variables"]["fromBlock"], "120");
    assert_eq!(page_request["variables"]["toBlock"], "120");

    drop(service);
    drop(public_data_plane);
    drop(db);
    fs::remove_dir_all(root_dir).expect("remove temp db dir");
}

#[tokio::test]
async fn output_poi_source_block_rows_fetches_whole_artifact_and_filters_locally() {
    let (root_dir, db) = open_forest_db("output-poi-source-block-artifact");
    let scope = test_scope();
    let ciphertext = merkletree::slow::types::CommitmentCiphertext {
        ciphertext: [FixedBytes::from([0x44; 32]); 4],
        blindedSenderViewingKey: FixedBytes::from([0x55; 32]),
        blindedReceiverViewingKey: FixedBytes::from([0x66; 32]),
        annotationData: vec![0x77].into(),
        memo: vec![0x88].into(),
    };
    let encoded_ciphertext = ciphertext.abi_encode();
    let mut payload = Vec::new();
    write_u64(&mut payload, 3);
    for (block_number, position) in [(119, 25_807), (120, 25_808), (120, 25_809)] {
        write_u64(&mut payload, block_number);
        write_u64(&mut payload, 1_700_000_000 + block_number);
        payload.extend_from_slice(&[0x33; 32]);
        payload.extend_from_slice(&4_u32.to_le_bytes());
        write_u64(&mut payload, position);
        payload.extend_from_slice(&U256::from(position).to_be_bytes::<32>());
        payload.extend_from_slice(
            &u32::try_from(encoded_ciphertext.len())
                .expect("ciphertext length")
                .to_le_bytes(),
        );
        payload.extend_from_slice(&encoded_ciphertext);
    }
    let payload_len = u64::try_from(payload.len()).expect("payload length");
    let chunk_bytes = IndexedArtifactChunkEnvelope::new(
        IndexedArtifactChunkEnvelopeHeader::new(
            IndexedDatasetKind::WalletScan,
            scope.clone(),
            IndexedArtifactRange {
                kind: IndexedArtifactRangeKind::Block,
                start: 100,
                end: 150,
            },
            3,
            payload_len,
            vec![IndexedArtifactChunkSection {
                section_id: 1,
                offset: 0,
                byte_length: payload_len,
            }],
        ),
        payload,
    )
    .encode()
    .expect("encode wallet scan chunk");
    let chunk_cid = raw_cid(&chunk_bytes);
    let descriptor = wallet_artifact_descriptor(
        scope.clone(),
        100,
        150,
        3,
        chunk_cid,
        &chunk_bytes,
        DatasetDescriptorMetadata {
            checkpoint_block: Some(150),
            ..Default::default()
        },
        CompressionAlgorithm::None,
    );
    let (artifact_source, _) = wallet_artifact_source_for_chunks(
        &scope,
        vec![(descriptor, chunk_cid, chunk_bytes)],
        false,
        3,
        false,
    );
    let rpcs = Arc::new(QueryRpcPool::new(Vec::new(), Duration::from_secs(1)));
    let chain = test_chain_config(&scope, rpcs, Some(artifact_source.config.clone()));
    let public_data_plane = ChainPublicDataPlane::new(Arc::clone(&db), Arc::new(AtomicU64::new(0)));
    let service = test_chain_service(Arc::clone(&db), chain, public_data_plane.clone());
    public_data_plane.bind_scan_service(&service);

    for _ in 0..2 {
        let answer = public_data_plane
            .output_poi_source_block_rows(120)
            .await
            .expect("read artifact source block");
        let PublicScanRowsAnswer::Rows(rows) = answer else {
            panic!("source block output rows must be available");
        };
        assert_eq!(rows.range, PublicScanRange::new(120, 120));
        assert_eq!(rows.rows.transact_commitments.len(), 2);
        for (row, position) in rows.rows.transact_commitments.iter().zip([25_808, 25_809]) {
            assert_eq!(row.tree_number, 4);
            assert_eq!(row.tree_position, position);
            assert_eq!(row.hash, U256::from(position));
            assert_eq!(row.source.block_number, 120);
            assert_eq!(row.ciphertext, ciphertext.ciphertext);
            assert_eq!(
                row.blinded_sender_viewing_key,
                ciphertext.blindedSenderViewingKey
            );
            assert_eq!(
                row.blinded_receiver_viewing_key,
                ciphertext.blindedReceiverViewingKey
            );
            assert_eq!(row.annotation_data, ciphertext.annotationData);
            assert_eq!(row.memo, ciphertext.memo);
        }
    }
    let paths = artifact_source.server.requested_paths();
    assert_eq!(paths.len(), 3, "second read must reuse retained rows");
    assert_eq!(paths[0], "/manifest.json");
    assert!(paths[1..].iter().all(|path| path.starts_with("/ipfs/")));
    assert!(paths.contains(&format!("/ipfs/{chunk_cid}?format=car&dag-scope=entity")));

    drop(service);
    drop(public_data_plane);
    drop(db);
    fs::remove_dir_all(root_dir).expect("remove temp db dir");
}

#[tokio::test]
async fn output_poi_source_block_rows_never_queries_squid_or_rpc() {
    for failing_artifacts in [false, true] {
        let (root_dir, db) = open_forest_db("output-poi-source-block-private");
        let scope = test_scope();
        let (squid_listener, squid_port) = silent_server();
        let (rpc_listener, rpc_port) = silent_server();
        let rpcs = Arc::new(QueryRpcPool::new(
            vec![Url::parse(&format!("http://127.0.0.1:{rpc_port}")).expect("rpc url")],
            Duration::from_millis(100),
        ));
        let artifact_server = PathServer::spawn(HashMap::new(), 1);
        let artifact_config = failing_artifacts.then(|| IndexedArtifactSourceConfig {
            trusted_publisher_pubkey: FixedBytes::from([7; 32]),
            manifest_source: IndexedArtifactManifestSource::Url(
                artifact_server
                    .url
                    .join("/missing.json")
                    .expect("manifest url"),
            ),
            gateway_urls: vec![artifact_server.url.clone()],
            gateway_pool: None,
            manifest_reuse: crate::IndexedArtifactManifestReuse::default(),
            max_manifest_age: None,
            concurrency: 1,
            max_in_flight_bytes: 1024 * 1024,
        });
        let mut chain = test_chain_config(&scope, rpcs, artifact_config);
        chain.sync.quick_sync_endpoint =
            Some(Url::parse(&format!("http://127.0.0.1:{squid_port}")).expect("squid url"));
        let public_data_plane =
            ChainPublicDataPlane::new(Arc::clone(&db), Arc::new(AtomicU64::new(0)));
        let service = test_chain_service(Arc::clone(&db), chain, public_data_plane.clone());
        public_data_plane.bind_scan_service(&service);

        let answer = public_data_plane
            .output_poi_source_block_rows(120)
            .await
            .expect("unavailable artifacts are retryable missing data");
        assert!(matches!(answer, PublicScanRowsAnswer::Missing { .. }));
        assert_eq!(drain_backlog_connections(&squid_listener), 0);
        assert_eq!(drain_backlog_connections(&rpc_listener), 0);
        assert_eq!(
            artifact_server.request_count(),
            u64::from(failing_artifacts)
        );
        assert!(
            public_data_plane
                .diagnostics()
                .await
                .events
                .iter()
                .all(|event| { event.kind != PublicDataPlaneDiagnosticKind::SourceFallback })
        );

        drop(service);
        drop(public_data_plane);
        drop(db);
        fs::remove_dir_all(root_dir).expect("remove temp db dir");
    }
}

#[tokio::test]
async fn public_scan_rows_rejects_source_result_after_epoch_invalidation() {
    for artifact_only in [false, true] {
        let root_dir = temp_db_root("public-scan-rows-stale-source-result");
        let db = Arc::new(
            DbStore::open(DbConfig {
                root_dir: root_dir.clone(),
            })
            .expect("open db"),
        );
        let scope = ChainScope {
            chain_type: ChainType::Evm,
            chain_id: 1,
            railgun_contract: Address::from([0xbb; 20]),
        };
        let (artifact_source, block) =
            checkpointed_wallet_artifact_source_with_blocked_manifest(&scope, 100, 150, 150);
        let PathServerBlockControl {
            request_started,
            release,
        } = block;
        let rpcs = Arc::new(QueryRpcPool::new(
            vec![Url::parse("http://127.0.0.1:1").expect("rpc url")],
            Duration::from_secs(1),
        ));
        let chain = test_chain_config(&scope, Arc::clone(&rpcs), Some(artifact_source.config));
        let public_data_plane = ChainPublicDataPlane::new(
            Arc::clone(&db),
            Arc::new(std::sync::atomic::AtomicU64::new(0)),
        );
        let service = test_chain_service(Arc::clone(&db), chain, public_data_plane.clone());
        public_data_plane.bind_scan_service(&service);
        let public_handle = service.public_data_plane();
        let source_data_plane = public_data_plane.clone();
        let source_range = if artifact_only {
            PublicScanRange::new(120, 120)
        } else {
            PublicScanRange::new(100, 150)
        };
        let scan_task = tokio::spawn(async move {
            if artifact_only {
                source_data_plane.output_poi_source_block_rows(120).await
            } else {
                public_handle.public_scan_rows(source_range).await
            }
        });

        tokio::time::timeout(
            Duration::from_secs(2),
            tokio::task::spawn_blocking(move || {
                request_started
                    .recv()
                    .expect("artifact manifest fetch started");
            }),
        )
        .await
        .expect("artifact manifest fetch started")
        .expect("manifest wait task completed");
        public_data_plane
            .invalidate_public_scan_coverage_from(100)
            .await;
        release.send(()).expect("release artifact manifest fetch");

        let error = scan_task
            .await
            .expect("public scan task completed")
            .expect_err("stale public scan rows must be rejected");
        assert!(matches!(
            error,
            ChainError::PublicDataPlane(PublicDataPlaneError::StaleEpoch {
                expected: 1,
                actual: 0
            })
        ));
        let diagnostics = public_data_plane.diagnostics().await;
        assert!(diagnostics.events.iter().any(|event| {
            event.kind == PublicDataPlaneDiagnosticKind::CoverageRejected
                && event.source == Some(PublicScanSource::IndexedArtifacts)
                && event.range == Some(source_range)
        }));

        drop(db);
        drop(artifact_source.server);
        fs::remove_dir_all(root_dir).expect("remove temp db dir");
    }
}

#[tokio::test]
async fn public_scan_rows_rpc_fallback_returns_only_bounded_proven_range() {
    let root_dir = temp_db_root("public-scan-rpc-bounded-proven-range");
    let db = Arc::new(
        DbStore::open(DbConfig {
            root_dir: root_dir.clone(),
        })
        .expect("open db"),
    );
    let scope = ChainScope {
        chain_type: ChainType::Evm,
        chain_id: 1,
        railgun_contract: Address::from([0xbb; 20]),
    };
    let rpc = JsonRpcServer::spawn(vec![
        serde_json::json!("0x96"),
        serde_json::json!([]),
        rpc_block(150, 1_700_000_150, 0x15),
    ]);
    let rpcs = Arc::new(QueryRpcPool::new(
        vec![rpc.url.clone()],
        Duration::from_secs(1),
    ));
    let mut chain = test_chain_config(&scope, Arc::clone(&rpcs), None);
    chain.sync.block_range = 100;
    chain.sync.indexed_wallet_block_range = 1_000;
    chain.finality_depth = 0;
    let public_data_plane = ChainPublicDataPlane::new(
        Arc::clone(&db),
        Arc::new(std::sync::atomic::AtomicU64::new(0)),
    );
    let service = test_chain_service(Arc::clone(&db), chain, public_data_plane.clone());

    let answer = service
        .public_data_plane()
        .public_scan_rows(PublicScanRange::new(100, 500))
        .await
        .expect("public scan rows");

    let PublicScanRowsAnswer::Rows(rows) = answer else {
        panic!("RPC fallback should return normalized rows");
    };
    assert_eq!(rows.range, PublicScanRange::new(100, 150));
    assert_eq!(rows.source, PublicScanSource::Rpc);
    assert_eq!(rows.row_count(), 0);
    assert!(matches!(
        public_data_plane
            .cached_public_scan_coverage(PublicScanRange::new(100, 150))
            .await,
        PublicCoverageAnswer::ReplayableEmpty { .. }
    ));
    assert!(matches!(
        public_data_plane
            .cached_public_scan_coverage(PublicScanRange::new(151, 199))
            .await,
        PublicCoverageAnswer::Missing { .. }
    ));
    let _block_number_request = rpc
        .requests
        .recv_timeout(Duration::from_secs(1))
        .expect("block number request");
    let logs_request = rpc
        .requests
        .recv_timeout(Duration::from_secs(1))
        .expect("logs request");
    assert!(logs_request.contains("eth_getLogs"));
    assert!(logs_request.contains(r#""fromBlock":"0x64""#));
    assert!(logs_request.contains(r#""toBlock":"0x96""#));
    assert!(!logs_request.contains(r#""toBlock":"0x1f4""#));
    let _block_hash_request = rpc
        .requests
        .recv_timeout(Duration::from_secs(1))
        .expect("block hash request");
    let replay = service
        .public_data_plane()
        .public_scan_rows(PublicScanRange::new(100, 150))
        .await
        .expect("replay cached RPC public scan rows");
    assert!(matches!(
        replay,
        PublicScanRowsAnswer::CompleteCoverage {
            range: PublicScanRange {
                from_block: 100,
                to_block: 150,
            },
            row_count: 0,
            ..
        }
    ));
    assert!(
        rpc.requests.try_recv().is_err(),
        "ordinary public scan RPC rows must remain reusable",
    );

    drop(service);
    drop(db);
    fs::remove_dir_all(root_dir).expect("remove temp db dir");
}

#[tokio::test]
async fn public_scan_rows_rpc_fallback_does_not_reuse_missing_endpoint_coverage() {
    let root_dir = temp_db_root("public-scan-rpc-missing-endpoint");
    let db = Arc::new(
        DbStore::open(DbConfig {
            root_dir: root_dir.clone(),
        })
        .expect("open db"),
    );
    let scope = ChainScope {
        chain_type: ChainType::Evm,
        chain_id: 1,
        railgun_contract: Address::from([0xbb; 20]),
    };
    let rpc = JsonRpcServer::spawn(vec![
        serde_json::json!("0x96"),
        serde_json::json!([]),
        serde_json::Value::Null,
        serde_json::json!("0x96"),
        serde_json::json!([]),
        rpc_block(150, 1_700_000_150, 0x15),
    ]);
    let rpcs = Arc::new(QueryRpcPool::new(
        vec![rpc.url.clone()],
        Duration::from_secs(1),
    ));
    let mut chain = test_chain_config(&scope, rpcs, None);
    chain.sync.block_range = 100;
    chain.sync.indexed_wallet_block_range = 1_000;
    chain.finality_depth = 0;
    let public_data_plane = ChainPublicDataPlane::new(
        Arc::clone(&db),
        Arc::new(std::sync::atomic::AtomicU64::new(0)),
    );
    let service = test_chain_service(Arc::clone(&db), chain, public_data_plane.clone());
    let range = PublicScanRange::new(100, 500);

    let error = service
        .public_data_plane()
        .public_scan_rows(range)
        .await
        .expect_err("missing RPC endpoint must reject the public scan");
    assert!(matches!(error, ChainError::BackfillRequestFailed));
    assert!(matches!(
        public_data_plane
            .cached_public_scan_coverage(PublicScanRange::new(100, 150))
            .await,
        PublicCoverageAnswer::Missing { .. }
    ));

    let retry = service
        .public_data_plane()
        .public_scan_rows(range)
        .await
        .expect("later scan must query RPC rather than reuse rejected coverage");
    assert!(matches!(
        retry,
        PublicScanRowsAnswer::Rows(PublicScanRows {
            range: PublicScanRange {
                from_block: 100,
                to_block: 150,
            },
            ..
        })
    ));

    drop(service);
    drop(db);
    fs::remove_dir_all(root_dir).expect("remove temp db dir");
}

#[tokio::test]
async fn public_scan_rows_records_squid_to_rpc_fallback_diagnostic() {
    let root_dir = temp_db_root("public-scan-squid-rpc-fallback-diagnostic");
    let db = Arc::new(
        DbStore::open(DbConfig {
            root_dir: root_dir.clone(),
        })
        .expect("open db"),
    );
    let scope = ChainScope {
        chain_type: ChainType::Evm,
        chain_id: 1,
        railgun_contract: Address::from([0xbb; 20]),
    };
    let squid = GraphqlServer::spawn(vec![
        r#"{"data":{"squidStatus":{"height":"150"},"transactCommitments":[],"shieldCommitments":[],"nullifiers":[],"legacyEncryptedCommitments":[],"legacyGeneratedCommitments":[]}}"#,
        r#"{"errors":[{"message":"boom"}]}"#,
    ]);
    let rpc = JsonRpcServer::spawn(vec![
        serde_json::json!("0x96"),
        serde_json::json!([]),
        rpc_block(150, 1_700_000_150, 0x15),
    ]);
    let rpcs = Arc::new(QueryRpcPool::new(
        vec![rpc.url.clone()],
        Duration::from_secs(1),
    ));
    let mut chain = test_chain_config(&scope, Arc::clone(&rpcs), None);
    chain.sync.quick_sync_endpoint = Some(squid.url.clone());
    chain.sync.block_range = 100;
    chain.sync.indexed_wallet_block_range = 100;
    let public_data_plane = ChainPublicDataPlane::new(
        Arc::clone(&db),
        Arc::new(std::sync::atomic::AtomicU64::new(0)),
    );
    let service = test_chain_service(Arc::clone(&db), chain, public_data_plane.clone());

    let answer = service
        .public_data_plane()
        .public_scan_rows(PublicScanRange::new(100, 150))
        .await
        .expect("public scan rows fallback");

    let PublicScanRowsAnswer::Rows(rows) = answer else {
        panic!("RPC fallback should return normalized rows");
    };
    assert_eq!(rows.range, PublicScanRange::new(100, 150));
    assert_eq!(rows.source, PublicScanSource::Rpc);
    let diagnostics = public_data_plane.diagnostics().await;
    assert!(diagnostics.events.iter().any(|event| {
        event.kind == PublicDataPlaneDiagnosticKind::SourceSelected
            && event.source == Some(PublicScanSource::Squid)
            && event.range == Some(PublicScanRange::new(100, 150))
    }));
    assert!(diagnostics.events.iter().any(|event| {
        event.kind == PublicDataPlaneDiagnosticKind::SourceFallback
            && event.source == Some(PublicScanSource::Rpc)
            && event.range == Some(PublicScanRange::new(100, 150))
            && event.reason.contains("Squid failed")
    }));
    assert!(diagnostics.events.iter().any(|event| {
        event.kind == PublicDataPlaneDiagnosticKind::SourceSelected
            && event.source == Some(PublicScanSource::Rpc)
            && event.range == Some(PublicScanRange::new(100, 150))
    }));

    drop(service);
    drop(db);
    fs::remove_dir_all(root_dir).expect("remove temp db dir");
}

#[tokio::test]
async fn public_scan_rows_records_archive_rpc_fallback_diagnostic_at_boundary() {
    let root_dir = temp_db_root("public-scan-archive-rpc-fallback-diagnostic");
    let db = Arc::new(
        DbStore::open(DbConfig {
            root_dir: root_dir.clone(),
        })
        .expect("open db"),
    );
    let scope = ChainScope {
        chain_type: ChainType::Evm,
        chain_id: 1,
        railgun_contract: Address::from([0xbb; 20]),
    };
    let squid = GraphqlServer::spawn(vec![
        r#"{"data":{"squidStatus":{"height":"150"},"transactCommitments":[],"shieldCommitments":[],"nullifiers":[],"legacyEncryptedCommitments":[],"legacyGeneratedCommitments":[]}}"#,
        r#"{"errors":[{"message":"boom"}]}"#,
    ]);
    let rpc = JsonRpcServer::spawn(vec![
        serde_json::json!("0x96"),
        serde_json::json!([]),
        serde_json::json!([]),
        rpc_block(100, 1_700_000_100, 0x10),
        rpc_block(150, 1_700_000_150, 0x15),
    ]);
    let rpcs = Arc::new(QueryRpcPool::new(
        vec![rpc.url.clone()],
        Duration::from_secs(1),
    ));
    let mut chain = test_chain_config(&scope, Arc::clone(&rpcs), None);
    chain.sync.quick_sync_endpoint = Some(squid.url.clone());
    chain.sync.archive_until_block = 100;
    chain.sync.block_range = 100;
    chain.sync.indexed_wallet_block_range = 100;
    let public_data_plane = ChainPublicDataPlane::new(
        Arc::clone(&db),
        Arc::new(std::sync::atomic::AtomicU64::new(0)),
    );
    let service = test_chain_service(Arc::clone(&db), chain, public_data_plane.clone());

    let answer = service
        .public_data_plane()
        .public_scan_rows(PublicScanRange::new(100, 150))
        .await
        .expect("public scan rows archive fallback");

    let PublicScanRowsAnswer::Rows(rows) = answer else {
        panic!("Archive RPC fallback should return normalized rows");
    };
    assert_eq!(rows.range, PublicScanRange::new(100, 150));
    assert_eq!(rows.source, PublicScanSource::ArchiveRpc);
    assert_eq!(
        public_data_plane
            .cached_public_scan_coverage(PublicScanRange::new(100, 150))
            .await,
        PublicCoverageAnswer::ReplayableEmpty {
            range: PublicScanRange::new(100, 150),
            source: PublicScanSource::ArchiveRpc,
            epoch: PublicDataPlaneEpoch::new(0),
        }
    );
    let diagnostics = public_data_plane.diagnostics().await;
    assert!(diagnostics.events.iter().any(|event| {
        event.kind == PublicDataPlaneDiagnosticKind::SourceFallback
            && event.source == Some(PublicScanSource::ArchiveRpc)
            && event.range == Some(PublicScanRange::new(100, 150))
            && event.reason.contains("Squid failed")
    }));
    assert!(diagnostics.events.iter().any(|event| {
        event.kind == PublicDataPlaneDiagnosticKind::SourceSelected
            && event.source == Some(PublicScanSource::ArchiveRpc)
            && event.range == Some(PublicScanRange::new(100, 150))
    }));
    assert!(diagnostics.events.iter().any(|event| {
        event.kind == PublicDataPlaneDiagnosticKind::CoverageRecorded
            && event.source == Some(PublicScanSource::ArchiveRpc)
            && event.range == Some(PublicScanRange::new(100, 150))
    }));

    drop(service);
    drop(db);
    fs::remove_dir_all(root_dir).expect("remove temp db dir");
}

#[tokio::test]
async fn public_scan_rows_rejects_missing_archive_boundary_without_recording_coverage() {
    let root_dir = temp_db_root("public-scan-missing-archive-boundary");
    let db = Arc::new(
        DbStore::open(DbConfig {
            root_dir: root_dir.clone(),
        })
        .expect("open db"),
    );
    let scope = ChainScope {
        chain_type: ChainType::Evm,
        chain_id: 1,
        railgun_contract: Address::from([0xbb; 20]),
    };
    let rpc = JsonRpcServer::spawn(vec![
        serde_json::json!("0x96"),
        serde_json::json!([]),
        serde_json::json!([]),
        serde_json::Value::Null,
    ]);
    let rpcs = Arc::new(QueryRpcPool::new(
        vec![rpc.url.clone()],
        Duration::from_secs(1),
    ));
    let mut chain = test_chain_config(&scope, rpcs, None);
    chain.sync.archive_until_block = 100;
    chain.sync.block_range = 100;
    chain.sync.indexed_wallet_block_range = 100;
    let public_data_plane = ChainPublicDataPlane::new(
        Arc::clone(&db),
        Arc::new(std::sync::atomic::AtomicU64::new(0)),
    );
    let service = test_chain_service(Arc::clone(&db), chain, public_data_plane.clone());

    let error = service
        .public_data_plane()
        .public_scan_rows(PublicScanRange::new(100, 150))
        .await
        .expect_err("missing archive boundary must reject the public scan");
    assert!(matches!(error, ChainError::BackfillRequestFailed));
    assert!(matches!(
        public_data_plane
            .cached_public_scan_coverage(PublicScanRange::new(100, 150))
            .await,
        PublicCoverageAnswer::Missing { .. }
    ));

    drop(service);
    drop(db);
    fs::remove_dir_all(root_dir).expect("remove temp db dir");
}
