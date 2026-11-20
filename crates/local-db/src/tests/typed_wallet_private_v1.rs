use super::*;

#[test]
fn typed_wallet_private_dual_version_delete_rolls_back_atomically() {
    let root_dir = temp_db_root();
    let store = DbStore::open(DbConfig {
        root_dir: root_dir.clone(),
    })
    .expect("open db");
    let namespace = WalletPrivateNamespaceId::new(1, wallet_cache_key(0x39));
    let pending = sample_pending_output_record(
        namespace.chain_id,
        namespace.wallet_id.as_str(),
        FixedBytes::from([0xb1; 32]),
    );
    store
        .put_pending_output_poi_context(&pending)
        .expect("put v2 pending");
    put_raw_pending_output_record(
        &store,
        &pending.key(),
        &encode(&pending).expect("encode v1 pending"),
    );

    let error = store
        .delete_typed_wallet_private_row_transaction(
            &namespace,
            WalletPrivateRecordKind::PendingOutputPoiContext,
            &pending.key(),
            pending.output_commitment.as_slice(),
            || {
                Err(DbError::Io(std::io::Error::other(
                    "injected typed delete failure",
                )))
            },
        )
        .expect_err("typed delete must roll back");
    assert!(matches!(error, DbError::Io(_)));
    assert!(
        store
            .get_opaque_wallet_private_row(
                &namespace,
                WalletPrivateRecordKind::PendingOutputPoiContext,
                pending.output_commitment.as_slice(),
            )
            .expect("read v2 after rollback")
            .is_some()
    );
    assert!(raw_pending_output_record_exists(&store, &pending.key()));
    assert!(
        !store
            .wallet_private_compaction_requested()
            .expect("read rolled-back compaction marker")
    );

    let recovery = sample_output_poi_recovery_record(
        namespace.chain_id,
        namespace.wallet_id.as_str(),
        FixedBytes::from([0xb2; 32]),
    );
    put_raw_output_poi_recovery_record(
        &store,
        &recovery.key(),
        &encode(&recovery).expect("encode v1 recovery"),
    );
    let recovery_row = OpaqueWalletPrivateRow {
        row_id: recovery.output_commitment.to_vec(),
        payload: encode(&recovery).expect("encode v2 recovery"),
    };
    let error = store
        .put_typed_wallet_private_row_transaction(
            &namespace,
            WalletPrivateRecordKind::OutputPoiRecovery,
            &recovery.key(),
            &recovery_row,
            || {
                Err(DbError::Io(std::io::Error::other(
                    "injected typed put failure",
                )))
            },
        )
        .expect_err("typed put must roll back");
    assert!(matches!(error, DbError::Io(_)));
    assert!(
        store
            .get_opaque_wallet_private_row(
                &namespace,
                WalletPrivateRecordKind::OutputPoiRecovery,
                recovery.output_commitment.as_slice(),
            )
            .expect("read v2 recovery after rollback")
            .is_none()
    );
    assert_eq!(
        store
            .list_wallet_private_v1_rows(&namespace)
            .expect("read v1 recovery after rollback")
            .output_poi_recoveries
            .len(),
        1
    );
    assert!(
        !store
            .wallet_private_compaction_requested()
            .expect("read put rollback compaction marker")
    );

    drop(store);
    fs::remove_dir_all(root_dir).expect("remove temp db dir");
}

#[test]
fn typed_wallet_private_point_reads_validate_exact_identity_and_v2_precedence() {
    let root_dir = temp_db_root();
    let store = DbStore::open(DbConfig {
        root_dir: root_dir.clone(),
    })
    .expect("open db");
    let namespace = WalletPrivateNamespaceId::new(1, wallet_cache_key(0x3a));
    let pending = sample_pending_output_record(
        namespace.chain_id,
        namespace.wallet_id.as_str(),
        FixedBytes::from([0xc1; 32]),
    );
    let recovery = sample_output_poi_recovery_record(
        namespace.chain_id,
        namespace.wallet_id.as_str(),
        FixedBytes::from([0xc2; 32]),
    );
    put_raw_pending_output_record(
        &store,
        &pending.key(),
        &encode(&pending).expect("encode v1 pending"),
    );
    put_raw_output_poi_recovery_record(
        &store,
        &recovery.key(),
        &encode(&recovery).expect("encode v1 recovery"),
    );
    for kind in [
        WalletPrivateRecordKind::PendingOutputPoiContext,
        WalletPrivateRecordKind::OutputPoiRecovery,
    ] {
        store
            .put_opaque_wallet_private_row(
                &namespace,
                kind,
                &OpaqueWalletPrivateRow {
                    row_id: vec![0xee; 32],
                    payload: vec![0xc1],
                },
            )
            .expect("put unrelated malformed opaque row");
    }
    assert!(
        store
            .get_pending_output_poi_context(
                namespace.chain_id,
                namespace.wallet_id.as_str(),
                &pending.output_commitment,
            )
            .expect("exact pending v1 fallback")
            .is_some()
    );
    assert!(
        store
            .get_output_poi_recovery(
                namespace.chain_id,
                namespace.wallet_id.as_str(),
                &recovery.output_commitment,
            )
            .expect("exact recovery v1 fallback")
            .is_some()
    );
    let v1_rows = store
        .list_wallet_private_v1_rows(&namespace)
        .expect("generic opaque writes preserve v1 rows");
    assert_eq!(v1_rows.pending_output_contexts.len(), 1);
    assert_eq!(v1_rows.output_poi_recoveries.len(), 1);

    let mut newer_recovery = recovery.clone();
    newer_recovery.attempt_count = 9;
    store
        .put_opaque_wallet_private_row(
            &namespace,
            WalletPrivateRecordKind::OutputPoiRecovery,
            &OpaqueWalletPrivateRow {
                row_id: recovery.output_commitment.to_vec(),
                payload: encode(&newer_recovery).expect("encode newer v2 recovery"),
            },
        )
        .expect("put exact v2 recovery");
    assert_eq!(
        store
            .get_output_poi_recovery(
                namespace.chain_id,
                namespace.wallet_id.as_str(),
                &recovery.output_commitment,
            )
            .expect("read v2 precedence")
            .expect("v2 recovery present")
            .attempt_count,
        9
    );

    let mismatched = sample_pending_output_record(
        namespace.chain_id,
        namespace.wallet_id.as_str(),
        FixedBytes::from([0xcf; 32]),
    );
    store
        .put_opaque_wallet_private_row(
            &namespace,
            WalletPrivateRecordKind::PendingOutputPoiContext,
            &OpaqueWalletPrivateRow {
                row_id: pending.output_commitment.to_vec(),
                payload: encode(&mismatched).expect("encode mismatched v2 pending"),
            },
        )
        .expect("put mismatched v2 pending");
    assert!(matches!(
        store.get_pending_output_poi_context(
            namespace.chain_id,
            namespace.wallet_id.as_str(),
            &pending.output_commitment,
        ),
        Err(DbError::WalletPrivateRecordIdentityMismatch { .. })
    ));
    let mismatched_recovery = sample_output_poi_recovery_record(
        namespace.chain_id,
        namespace.wallet_id.as_str(),
        FixedBytes::from([0xce; 32]),
    );
    store
        .put_opaque_wallet_private_row(
            &namespace,
            WalletPrivateRecordKind::OutputPoiRecovery,
            &OpaqueWalletPrivateRow {
                row_id: recovery.output_commitment.to_vec(),
                payload: encode(&mismatched_recovery).expect("encode mismatched v2 recovery"),
            },
        )
        .expect("put mismatched v2 recovery");
    assert!(matches!(
        store.get_output_poi_recovery(
            namespace.chain_id,
            namespace.wallet_id.as_str(),
            &recovery.output_commitment,
        ),
        Err(DbError::WalletPrivateRecordIdentityMismatch { .. })
    ));

    drop(store);
    fs::remove_dir_all(root_dir).expect("remove temp db dir");
}

#[test]
fn typed_wallet_private_lists_isolate_v1_record_kinds() {
    let root_dir = temp_db_root();
    let store = DbStore::open(DbConfig {
        root_dir: root_dir.clone(),
    })
    .expect("open db");
    let pending_namespace = WalletPrivateNamespaceId::new(1, wallet_cache_key(0x3b));
    let recovery_namespace = WalletPrivateNamespaceId::new(1, wallet_cache_key(0x3c));
    let pending = sample_pending_output_record(
        pending_namespace.chain_id,
        pending_namespace.wallet_id.as_str(),
        FixedBytes::from([0xd1; 32]),
    );
    let recovery = sample_output_poi_recovery_record(
        recovery_namespace.chain_id,
        recovery_namespace.wallet_id.as_str(),
        FixedBytes::from([0xd2; 32]),
    );
    put_raw_pending_output_record(
        &store,
        &pending.key(),
        &encode(&pending).expect("encode valid pending"),
    );
    put_raw_output_poi_recovery_record(
        &store,
        &OutputPoiRecoveryRecord::key_for(
            pending_namespace.chain_id,
            pending_namespace.wallet_id.as_str(),
            &FixedBytes::from([0xde; 32]),
        ),
        &[0xc1],
    );
    assert_eq!(
        store
            .list_pending_output_poi_contexts(
                pending_namespace.chain_id,
                pending_namespace.wallet_id.as_str(),
            )
            .expect("pending list ignores malformed recovery rows")
            .len(),
        1
    );

    put_raw_output_poi_recovery_record(
        &store,
        &recovery.key(),
        &encode(&recovery).expect("encode valid recovery"),
    );
    put_raw_pending_output_record(
        &store,
        &PendingOutputPoiContextRecord::key_for(
            recovery_namespace.chain_id,
            recovery_namespace.wallet_id.as_str(),
            &FixedBytes::from([0xdf; 32]),
        ),
        &[0xc1],
    );
    assert_eq!(
        store
            .list_output_poi_recoveries(
                recovery_namespace.chain_id,
                recovery_namespace.wallet_id.as_str(),
            )
            .expect("recovery list ignores malformed pending rows")
            .len(),
        1
    );

    drop(store);
    fs::remove_dir_all(root_dir).expect("remove temp db dir");
}

#[test]
fn typed_wallet_private_read_is_snapshot_consistent_with_v1_to_v2_put() {
    let root_dir = temp_db_root();
    let store = Arc::new(
        DbStore::open(DbConfig {
            root_dir: root_dir.clone(),
        })
        .expect("open db"),
    );
    let namespace = WalletPrivateNamespaceId::new(1, wallet_cache_key(0x3d));
    let pending = sample_pending_output_record(
        namespace.chain_id,
        namespace.wallet_id.as_str(),
        FixedBytes::from([0xe1; 32]),
    );
    put_raw_pending_output_record(
        &store,
        &pending.key(),
        &encode(&pending).expect("encode v1 pending"),
    );
    let row = OpaqueWalletPrivateRow {
        row_id: pending.output_commitment.to_vec(),
        payload: encode(&pending).expect("encode v2 pending"),
    };
    let (ready_tx, ready_rx) = std::sync::mpsc::channel();
    let (release_tx, release_rx) = std::sync::mpsc::channel();
    let writer_store = Arc::clone(&store);
    let writer_namespace = namespace.clone();
    let writer_key = pending.key();
    let writer = std::thread::spawn(move || {
        writer_store.put_typed_wallet_private_row_transaction(
            &writer_namespace,
            WalletPrivateRecordKind::PendingOutputPoiContext,
            &writer_key,
            &row,
            || {
                ready_tx.send(()).expect("signal staged typed put");
                release_rx.recv().expect("release typed put");
                Ok(())
            },
        )
    });
    ready_rx.recv().expect("typed put reached pre-commit hook");

    let read = store
        .get_pending_output_poi_context_with_probe_hook(
            namespace.chain_id,
            namespace.wallet_id.as_str(),
            &pending.output_commitment,
            || {
                release_tx.send(()).expect("release typed put commit");
                writer
                    .join()
                    .expect("join typed put")
                    .map_err(|error| DbError::Io(std::io::Error::other(error.to_string())))
            },
        )
        .expect("read old snapshot after inter-probe put commit");
    assert!(read.is_some());
    assert!(
        store
            .get_pending_output_poi_context(
                namespace.chain_id,
                namespace.wallet_id.as_str(),
                &pending.output_commitment,
            )
            .expect("read new snapshot after put")
            .is_some()
    );

    store
        .delete_pending_output_poi_context(
            namespace.chain_id,
            namespace.wallet_id.as_str(),
            &pending.output_commitment,
        )
        .expect("clear point-read fixture");
    put_raw_pending_output_record(
        &store,
        &pending.key(),
        &encode(&pending).expect("restore v1 pending"),
    );
    assert_eq!(
        store
            .list_pending_output_poi_contexts_with_probe_hook(
                namespace.chain_id,
                namespace.wallet_id.as_str(),
                || store.put_pending_output_poi_context(&pending),
            )
            .expect("list retains its v1 snapshot after inter-probe put commit")
            .len(),
        1
    );

    drop(store);
    fs::remove_dir_all(root_dir).expect("remove temp db dir");
}

#[test]
fn wallet_private_v1_migration_is_atomic_and_namespace_scoped() {
    let root_dir = temp_db_root();
    let store = DbStore::open(DbConfig {
        root_dir: root_dir.clone(),
    })
    .expect("open db");
    let namespace = WalletPrivateNamespaceId::new(1, wallet_cache_key(0x35));
    let other = WalletPrivateNamespaceId::new(1, wallet_cache_key(0x36));
    let pending = sample_pending_output_record(
        namespace.chain_id,
        namespace.wallet_id.as_str(),
        FixedBytes::from([0x81; 32]),
    );
    let recovery = sample_output_poi_recovery_record(
        namespace.chain_id,
        namespace.wallet_id.as_str(),
        FixedBytes::from([0x82; 32]),
    );
    let other_pending = sample_pending_output_record(
        other.chain_id,
        other.wallet_id.as_str(),
        FixedBytes::from([0x83; 32]),
    );
    put_raw_pending_output_record(
        &store,
        &pending.key(),
        &encode(&pending).expect("encode v1 pending"),
    );
    put_raw_output_poi_recovery_record(
        &store,
        &recovery.key(),
        &encode(&recovery).expect("encode v1 recovery"),
    );
    put_raw_pending_output_record(
        &store,
        &other_pending.key(),
        &encode(&other_pending).expect("encode other v1 pending"),
    );
    let sources = store
        .list_wallet_private_v1_rows(&namespace)
        .expect("list migration sources");
    let pending_destinations = [OpaqueWalletPrivateRow {
        row_id: vec![0xa1, 0xa2],
        payload: b"encrypted-pending".to_vec(),
    }];
    let recovery_destinations = [OpaqueWalletPrivateRow {
        row_id: vec![0xb1, 0xb2],
        payload: b"encrypted-recovery".to_vec(),
    }];
    let batch = WalletPrivateV1MigrationBatch {
        namespace: &namespace,
        pending_output_context_sources: &sources.pending_output_contexts,
        output_poi_recovery_sources: &sources.output_poi_recoveries,
        pending_output_context_destinations: &pending_destinations,
        output_poi_recovery_destinations: &recovery_destinations,
    };

    let result = store.migrate_wallet_private_v1_rows_transaction(&batch, || {
        Err(DbError::Io(std::io::Error::other(
            "injected migration failure",
        )))
    });
    assert!(result.is_err());
    assert_eq!(
        store
            .list_wallet_private_v1_rows(&namespace)
            .expect("list rolled-back sources"),
        sources
    );
    assert_eq!(
        store
            .list_opaque_wallet_private_rows(
                &namespace,
                WalletPrivateRecordKind::PendingOutputPoiContext,
            )
            .expect("list rolled-back destinations"),
        [] as [OpaqueWalletPrivateRow; 0]
    );

    assert_eq!(
        store
            .migrate_wallet_private_v1_rows(&batch)
            .expect("migrate v1 rows"),
        WalletPrivateV1MigrationReport {
            pending_output_context_rows: 1,
            output_poi_recovery_rows: 1,
        }
    );
    assert_eq!(
        store
            .list_opaque_wallet_private_rows(
                &namespace,
                WalletPrivateRecordKind::PendingOutputPoiContext,
            )
            .expect("list migrated pending rows"),
        pending_destinations
    );
    assert_eq!(
        store
            .list_wallet_private_v1_rows(&namespace)
            .expect("list consumed v1 rows")
            .pending_output_contexts,
        [] as [crate::WalletPrivateV1Row; 0]
    );
    assert_eq!(
        store
            .list_wallet_private_v1_rows(&other)
            .expect("list other namespace v1 rows")
            .pending_output_contexts
            .len(),
        1
    );

    drop(store);
    fs::remove_dir_all(root_dir).expect("remove temp db dir");
}

#[test]
fn wallet_private_canonicalization_is_versioned_atomic_and_idempotent() {
    let root_dir = temp_db_root();
    let store = DbStore::open(DbConfig {
        root_dir: root_dir.clone(),
    })
    .expect("open store");
    let canonical = WalletPrivateNamespaceId::new(1, wallet_cache_key(0x91));
    let legacy = WalletPrivateNamespaceId::new(1, wallet_cache_key(0x92));
    let pending = sample_pending_output_record(
        legacy.chain_id,
        legacy.wallet_id.as_str(),
        FixedBytes::from([0x93; 32]),
    );
    put_raw_pending_output_record(
        &store,
        &pending.key(),
        &encode(&pending).expect("encode legacy v1 pending"),
    );
    let canonical_recovery = OpaqueWalletPrivateRow {
        row_id: vec![0xa1, 0xa2],
        payload: b"canonical-recovery".to_vec(),
    };
    let legacy_recovery = OpaqueWalletPrivateRow {
        row_id: vec![0xb1, 0xb2],
        payload: b"legacy-recovery".to_vec(),
    };
    store
        .put_opaque_wallet_private_row(
            &canonical,
            WalletPrivateRecordKind::OutputPoiRecovery,
            &canonical_recovery,
        )
        .expect("seed canonical recovery");
    store
        .put_opaque_wallet_private_row(
            &legacy,
            WalletPrivateRecordKind::OutputPoiRecovery,
            &legacy_recovery,
        )
        .expect("seed legacy recovery");

    let canonical_v1 = store
        .list_wallet_private_v1_rows(&canonical)
        .expect("list canonical v1");
    let legacy_v1 = store
        .list_wallet_private_v1_rows(&legacy)
        .expect("list legacy v1");
    let canonical_recovery_sources = store
        .list_opaque_wallet_private_rows(&canonical, WalletPrivateRecordKind::OutputPoiRecovery)
        .expect("list canonical recovery sources");
    let legacy_recovery_sources = store
        .list_opaque_wallet_private_rows(&legacy, WalletPrivateRecordKind::OutputPoiRecovery)
        .expect("list legacy recovery sources");
    let pending_destinations = [OpaqueWalletPrivateRow {
        row_id: vec![0xc1, 0xc2],
        payload: b"canonical-pending".to_vec(),
    }];
    let recovery_destinations = [canonical_recovery];
    let batch = WalletPrivateCanonicalizationBatch {
        canonical_namespace: &canonical,
        legacy_namespace: Some(&legacy),
        target_version: 1,
        pending_output_contexts: WalletPrivateCanonicalizationKindBatch {
            canonical_v1_sources: &canonical_v1.pending_output_contexts,
            legacy_v1_sources: &legacy_v1.pending_output_contexts,
            canonical_v2_destinations: &pending_destinations,
            ..WalletPrivateCanonicalizationKindBatch::default()
        },
        output_poi_recoveries: WalletPrivateCanonicalizationKindBatch {
            canonical_v1_sources: &canonical_v1.output_poi_recoveries,
            legacy_v1_sources: &legacy_v1.output_poi_recoveries,
            canonical_v2_sources: &canonical_recovery_sources,
            legacy_v2_sources: &legacy_recovery_sources,
            canonical_v2_destinations: &recovery_destinations,
        },
    };

    let result = store.canonicalize_wallet_private_rows_transaction(&batch, || {
        Err(DbError::Io(std::io::Error::other(
            "injected canonicalization failure",
        )))
    });
    assert!(result.is_err());
    assert_eq!(
        store
            .wallet_private_canonicalization_version(&canonical)
            .expect("read rolled-back marker"),
        0
    );
    assert_eq!(
        store
            .list_wallet_private_v1_rows(&legacy)
            .expect("list rolled-back legacy v1"),
        legacy_v1
    );
    assert_eq!(
        store
            .list_opaque_wallet_private_rows(&legacy, WalletPrivateRecordKind::OutputPoiRecovery,)
            .expect("list rolled-back legacy v2"),
        legacy_recovery_sources
    );

    assert_eq!(
        store
            .canonicalize_wallet_private_rows(&batch)
            .expect("canonicalize wallet-private rows"),
        WalletPrivateCanonicalizationReport {
            pending_output_context_rows: 1,
            output_poi_recovery_rows: 1,
            plaintext_rows_removed: 1,
        }
    );
    assert_eq!(
        store
            .wallet_private_canonicalization_version(&canonical)
            .expect("read canonicalization marker"),
        1
    );
    assert_eq!(
        store
            .list_opaque_wallet_private_rows(
                &canonical,
                WalletPrivateRecordKind::PendingOutputPoiContext,
            )
            .expect("list canonical pending rows"),
        pending_destinations
    );
    assert_eq!(
        store
            .list_opaque_wallet_private_rows(
                &canonical,
                WalletPrivateRecordKind::OutputPoiRecovery,
            )
            .expect("list canonical recovery rows"),
        recovery_destinations
    );
    assert_eq!(
        store
            .list_wallet_private_v1_rows(&legacy)
            .expect("list consumed legacy v1")
            .pending_output_contexts,
        [] as [crate::WalletPrivateV1Row; 0]
    );
    assert_eq!(
        store
            .list_opaque_wallet_private_rows(&legacy, WalletPrivateRecordKind::OutputPoiRecovery,)
            .expect("list consumed legacy v2"),
        [] as [OpaqueWalletPrivateRow; 0]
    );
    assert_eq!(
        store
            .canonicalize_wallet_private_rows(&batch)
            .expect("repeat canonicalization"),
        WalletPrivateCanonicalizationReport::default()
    );

    drop(store);
    fs::remove_dir_all(root_dir).expect("remove temp db dir");
}
