use super::{
    APP_SETTINGS_TABLE, BLOB_INDEX_TABLE, CURRENT_SCHEMA_VERSION, CanonicalBlobMetaIdentity,
    DESKTOP_WALLET_VAULT_TABLE, DbConfig, DbError, DbStore, DesktopWalletVaultRecord,
    MERKLE_FOREST_INDEX_TABLE, META_TABLE, Meta, OUTPUT_POI_RECOVERY_TABLE,
    OUTPUT_POI_RECOVERY_V2_TABLE, OpaqueWalletPrivateRow, OpaqueWalletPrivateRowMutation,
    OutputPoiRecoveryRecord, OutputPoiRecoveryStatus, PENDING_FEE_NOTE_ASSURANCE_TABLE,
    PENDING_OUTPUT_POI_CONTEXT_TABLE, PENDING_OUTPUT_POI_CONTEXT_V2_TABLE,
    POI_ARTIFACT_CACHE_GENERATION_KEY, POI_ARTIFACT_CACHE_TABLE, PendingFeeNoteAssuranceRecord,
    PendingOutputPoiContextRecord, PendingOutputPoiRole, PoiArtifactCacheCommitCondition,
    PoiArtifactCacheCommitOutcome, PoiArtifactCacheRecord, PoiArtifactDescriptorRecord,
    PoiCacheRecordSource, PoiCorpusRpcHealthRecord, PoiCorpusValidationRecord,
    PoiPublisherManifestObservation, PoiPublisherManifestWatermarkRecord, StoredRecord,
    TERMINAL_FEE_NOTE_ASSURANCE_TABLE, WALLET_META_TABLE, WALLET_SYNC_ACTOR_STATE_TABLE,
    WALLET_UTXO_TABLE, WalletCacheKey, WalletDeletionBatch, WalletDeletionReport, WalletMeta,
    WalletMetaMutation, WalletPendingResetRecord, WalletPrivateCanonicalizationBatch,
    WalletPrivateCanonicalizationKindBatch, WalletPrivateCanonicalizationReport,
    WalletPrivateNamespaceDeletionReport, WalletPrivateNamespaceId, WalletPrivateRecordKind,
    WalletPrivateStateBatch, WalletPrivateV1MigrationBatch, WalletPrivateV1MigrationReport,
    WalletSyncActorStateRecord, WalletUtxoRowMutation, ZKEY_INDEX_TABLE, decode, encode,
};
use alloy::primitives::{Address, Bytes, FixedBytes, U256, keccak256};
use alloy::uint;
use broadcaster_core::transact::{FeeNoteAssuranceContext, PreTxPoi, SnarkJsProof};
use redb::{Database, ReadableDatabase, ReadableTable, ReadableTableMetadata, TableHandle};
use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

static TEMP_DB_COUNTER: AtomicU64 = AtomicU64::new(0);

fn wallet_cache_key(byte: u8) -> WalletCacheKey {
    WalletCacheKey::from_opaque_id([byte; 16])
}

#[test]
fn wallet_cache_keys_are_canonical_delimiter_free_and_preserve_opaque_ids() {
    let opaque = "11".repeat(16);
    let parsed: WalletCacheKey = opaque.parse().expect("parse alpha wallet cache key");
    assert_eq!(parsed.as_str(), opaque);
    assert!(!parsed.as_str().contains('|'));
    assert!("wallet|1|contract".parse::<WalletCacheKey>().is_err());
    assert!("AA".parse::<WalletCacheKey>().is_err());
    assert!(WalletCacheKey::from_opaque_bytes(&[]).is_err());

    let first = WalletCacheKey::new("wallet", 1, Address::from([0x22; 20]));
    let second = WalletCacheKey::new("wallet|1", 1, Address::from([0x22; 20]));
    assert_ne!(first, second);
    assert!(!first.as_str().contains('|'));
    let encoded = rmp_serde::to_vec_named(&first).expect("serialize wallet cache key");
    assert_eq!(
        rmp_serde::from_slice::<WalletCacheKey>(&encoded).expect("deserialize wallet cache key"),
        first
    );
}

fn temp_db_root() -> PathBuf {
    let dir = std::env::temp_dir().join("railgun-broadcaster-local-db-tests");
    fs::create_dir_all(&dir).expect("create temp db dir");
    let pid = std::process::id();
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |duration| duration.as_nanos());
    let counter = TEMP_DB_COUNTER.fetch_add(1, Ordering::Relaxed);
    dir.join(format!("db-{pid}-{nanos}-{counter}"))
}

#[test]
fn database_directory_lock_rejects_second_store_for_same_root() {
    let root_dir = temp_db_root();
    let store = DbStore::open(DbConfig {
        root_dir: root_dir.clone(),
    })
    .expect("open first db");

    assert!(matches!(
        DbStore::open(DbConfig {
            root_dir: root_dir.clone(),
        }),
        Err(DbError::DatabaseInUse { path })
            if path == root_dir.join("railgun").join("db.lock")
    ));

    drop(store);
    fs::remove_dir_all(root_dir).expect("remove temp db dir");
}

#[test]
fn database_directory_lock_releases_after_store_drop() {
    let root_dir = temp_db_root();
    let store = DbStore::open(DbConfig {
        root_dir: root_dir.clone(),
    })
    .expect("open first db");
    drop(store);

    let reopened = DbStore::open(DbConfig {
        root_dir: root_dir.clone(),
    })
    .expect("reopen db after lock release");
    drop(reopened);
    fs::remove_dir_all(root_dir).expect("remove temp db dir");
}

#[test]
fn database_directory_locks_are_scoped_by_root() {
    let first_root = temp_db_root();
    let second_root = temp_db_root();
    let first = DbStore::open(DbConfig {
        root_dir: first_root.clone(),
    })
    .expect("open first root");
    let second = DbStore::open(DbConfig {
        root_dir: second_root.clone(),
    })
    .expect("open second root");

    drop((first, second));
    fs::remove_dir_all(first_root).expect("remove first temp db dir");
    fs::remove_dir_all(second_root).expect("remove second temp db dir");
}

#[test]
fn canonical_blob_meta_identity_requires_direct_child_components() {
    let identity =
        CanonicalBlobMetaIdentity::from_leaf("poi_v4_artifact_chunks", "poi-v4-artifact-0123.bin")
            .expect("generate direct-child identity");
    assert_eq!(
        identity.relative_path(),
        "blobs/poi_v4_artifact_chunks/poi-v4-artifact-0123.bin"
    );

    for (kind, leaf) in [
        ("", "leaf.bin"),
        (".", "leaf.bin"),
        ("..", "leaf.bin"),
        ("nested/kind", "leaf.bin"),
        (r"nested\kind", "leaf.bin"),
        ("kind:stream", "leaf.bin"),
        ("kind\0suffix", "leaf.bin"),
        ("kind", ""),
        ("kind", "."),
        ("kind", ".."),
        ("kind", "nested/leaf.bin"),
        ("kind", r"nested\leaf.bin"),
        ("kind", "leaf:stream"),
        ("kind", "leaf\0suffix"),
    ] {
        assert!(matches!(
            CanonicalBlobMetaIdentity::from_leaf(kind, leaf),
            Err(DbError::InvalidBlobRelativePath { .. })
        ));
    }
}

#[test]
fn checked_blob_open_handles_regular_missing_and_directory_entries() {
    use std::io::Read;

    let root_dir = temp_db_root();
    let store = DbStore::open(DbConfig {
        root_dir: root_dir.clone(),
    })
    .expect("open db");
    let kind = "blob-file-operations";
    let kind_dir = store.ensure_blob_dir(kind).expect("create kind");
    let identity = CanonicalBlobMetaIdentity::from_leaf(kind, "leaf.bin").expect("identity");

    assert!(
        store
            .open_blob_meta_file(&identity)
            .expect("missing open")
            .is_none()
    );
    fs::write(kind_dir.join("leaf.bin"), b"regular bytes").expect("write regular leaf");
    let mut file = store
        .open_blob_meta_file(&identity)
        .expect("open regular leaf")
        .expect("regular leaf exists");
    let mut bytes = Vec::new();
    file.read_to_end(&mut bytes).expect("read regular leaf");
    assert_eq!(bytes, b"regular bytes");
    drop(file);
    fs::remove_file(kind_dir.join("leaf.bin")).expect("remove regular leaf");
    fs::create_dir(kind_dir.join("leaf.bin")).expect("create directory leaf");
    assert!(matches!(
        store.open_blob_meta_file(&identity),
        Err(DbError::UnsafeBlobEntry { .. })
    ));
    drop(store);
    fs::remove_dir_all(root_dir).expect("remove temp db dir");
}

#[cfg(unix)]
#[test]
fn checked_blob_open_rejects_static_symlink_parent_and_leaf() {
    use std::os::unix::fs::symlink;

    let root_dir = temp_db_root();
    let store = DbStore::open(DbConfig {
        root_dir: root_dir.clone(),
    })
    .expect("open db");
    let external_dir = root_dir.join("external");
    fs::create_dir_all(&external_dir).expect("create external dir");
    fs::write(external_dir.join("leaf.bin"), b"sentinel").expect("write sentinel");

    let parent_kind = "symlink-parent";
    symlink(&external_dir, store.blob_dir().join(parent_kind)).expect("create parent symlink");
    let parent_identity =
        CanonicalBlobMetaIdentity::from_leaf(parent_kind, "leaf.bin").expect("parent identity");
    assert!(matches!(
        store.open_blob_meta_file(&parent_identity),
        Err(DbError::UnsafeBlobEntry { .. })
    ));
    let leaf_kind = "symlink-leaf";
    let kind_dir = store.ensure_blob_dir(leaf_kind).expect("create real kind");
    let leaf_path = kind_dir.join("leaf.bin");
    symlink(external_dir.join("leaf.bin"), &leaf_path).expect("create leaf symlink");
    let leaf_identity =
        CanonicalBlobMetaIdentity::from_leaf(leaf_kind, "leaf.bin").expect("leaf identity");
    assert!(matches!(
        store.open_blob_meta_file(&leaf_identity),
        Err(DbError::UnsafeBlobEntry { .. })
    ));
    assert_eq!(
        fs::read(external_dir.join("leaf.bin")).expect("read sentinel"),
        b"sentinel"
    );

    drop(store);
    fs::remove_dir_all(root_dir).expect("remove temp db dir");
}

#[cfg(windows)]
#[test]
fn checked_blob_open_rejects_static_reparse_parent_and_leaf() {
    use std::os::windows::fs::{symlink_dir, symlink_file};

    let root_dir = temp_db_root();
    let store = DbStore::open(DbConfig {
        root_dir: root_dir.clone(),
    })
    .expect("open db");
    let external_dir = root_dir.join("external");
    fs::create_dir_all(&external_dir).expect("create external dir");
    let external_file = external_dir.join("leaf.bin");
    fs::write(&external_file, b"sentinel").expect("write sentinel");

    let parent_kind = "reparse-parent";
    if let Err(error) = symlink_dir(&external_dir, store.blob_dir().join(parent_kind)) {
        if error.kind() == std::io::ErrorKind::PermissionDenied
            || error.raw_os_error() == Some(1314)
        {
            drop(store);
            fs::remove_dir_all(root_dir).expect("remove skipped test root");
            return;
        }
        panic!("create parent reparse fixture: {error}");
    }
    let parent_identity =
        CanonicalBlobMetaIdentity::from_leaf(parent_kind, "leaf.bin").expect("parent identity");
    assert!(matches!(
        store.open_blob_meta_file(&parent_identity),
        Err(DbError::UnsafeBlobEntry { .. })
    ));

    let leaf_kind = "reparse-leaf";
    let kind_dir = store.ensure_blob_dir(leaf_kind).expect("create real kind");
    let leaf_path = kind_dir.join("leaf.bin");
    symlink_file(&external_file, &leaf_path).expect("create leaf reparse fixture");
    let leaf_identity =
        CanonicalBlobMetaIdentity::from_leaf(leaf_kind, "leaf.bin").expect("leaf identity");
    assert!(matches!(
        store.open_blob_meta_file(&leaf_identity),
        Err(DbError::UnsafeBlobEntry { .. })
    ));
    assert_eq!(fs::read(external_file).expect("read sentinel"), b"sentinel");

    drop(store);
    fs::remove_dir_all(root_dir).expect("remove temp db dir");
}

#[test]
fn failed_create_new_does_not_remove_preexisting_temp_entry() {
    let root_dir = temp_db_root();
    let store = DbStore::open(DbConfig {
        root_dir: root_dir.clone(),
    })
    .expect("open db");
    let kind = "atomic-preexisting-temp";
    let kind_dir = store.ensure_blob_dir(kind).expect("create kind directory");
    let temp_name = ".preexisting-temp";
    let temp_path = kind_dir.join(temp_name);
    fs::write(&temp_path, b"preexisting").expect("write preexisting temp entry");

    assert!(
        store
            .replace_blob_file_atomic_with_test_temp_name(
                kind,
                "final.bin",
                b"new bytes",
                temp_name,
            )
            .is_err()
    );
    assert_eq!(
        fs::read(&temp_path).expect("read preexisting temp entry"),
        b"preexisting"
    );

    drop(store);
    fs::remove_dir_all(root_dir).expect("remove temp db dir");
}

#[test]
fn atomic_blob_replace_allows_missing_and_existing_regular_file() {
    let root_dir = temp_db_root();
    let store = DbStore::open(DbConfig {
        root_dir: root_dir.clone(),
    })
    .expect("open db");
    let kind = "atomic-regular";
    let path = store
        .ensure_blob_dir(kind)
        .expect("create kind")
        .join("final.bin");

    store
        .replace_blob_file_atomic(kind, "final.bin", b"created")
        .expect("create missing file");
    assert_eq!(fs::read(&path).expect("read created file"), b"created");

    fs::write(&path, b"old").expect("write old file");

    store
        .replace_blob_file_atomic(kind, "final.bin", b"new")
        .expect("replace regular file");
    assert_eq!(fs::read(path).expect("read new file"), b"new");

    drop(store);
    fs::remove_dir_all(root_dir).expect("remove temp db dir");
}

#[test]
fn atomic_blob_replace_cleans_temp_after_unsafe_destination_rejection() {
    let root_dir = temp_db_root();
    let store = DbStore::open(DbConfig {
        root_dir: root_dir.clone(),
    })
    .expect("open db");
    let kind = "atomic-directory-final";
    let kind_dir = store.ensure_blob_dir(kind).expect("create kind");
    fs::create_dir(kind_dir.join("final.bin")).expect("create final directory");

    assert!(matches!(
        store.replace_blob_file_atomic(kind, "final.bin", b"new"),
        Err(DbError::UnsafeBlobEntry { .. })
    ));
    assert_no_atomic_temps(&kind_dir);

    drop(store);
    fs::remove_dir_all(root_dir).expect("remove temp db dir");
}

#[cfg(unix)]
#[test]
fn atomic_blob_replace_rejects_final_symlink_without_touching_target() {
    use std::os::unix::fs::symlink;

    let root_dir = temp_db_root();
    let store = DbStore::open(DbConfig {
        root_dir: root_dir.clone(),
    })
    .expect("open db");
    let kind = "atomic-final-symlink";
    let kind_dir = store.ensure_blob_dir(kind).expect("create kind");
    let external_target = root_dir.join("external-atomic-target.bin");
    fs::write(&external_target, b"sentinel").expect("write external target");
    symlink(&external_target, kind_dir.join("final.bin")).expect("create final symlink");

    assert!(matches!(
        store.replace_blob_file_atomic(kind, "final.bin", b"new"),
        Err(DbError::UnsafeBlobEntry { .. })
    ));
    assert_eq!(
        fs::read(external_target).expect("read external target"),
        b"sentinel"
    );
    assert_no_atomic_temps(&kind_dir);

    drop(store);
    fs::remove_dir_all(root_dir).expect("remove temp db dir");
}

#[cfg(windows)]
#[test]
fn atomic_blob_replace_rejects_final_reparse_without_touching_target() {
    use std::os::windows::fs::symlink_file;

    let root_dir = temp_db_root();
    let store = DbStore::open(DbConfig {
        root_dir: root_dir.clone(),
    })
    .expect("open db");
    let kind = "atomic-final-reparse";
    let kind_dir = store.ensure_blob_dir(kind).expect("create kind");
    let external_target = root_dir.join("external-atomic-target.bin");
    fs::write(&external_target, b"sentinel").expect("write external target");
    if let Err(error) = symlink_file(&external_target, kind_dir.join("final.bin")) {
        if error.kind() == std::io::ErrorKind::PermissionDenied
            || error.raw_os_error() == Some(1314)
        {
            drop(store);
            fs::remove_dir_all(root_dir).expect("remove skipped test root");
            return;
        }
        panic!("create final reparse fixture: {error}");
    }

    assert!(matches!(
        store.replace_blob_file_atomic(kind, "final.bin", b"new"),
        Err(DbError::UnsafeBlobEntry { .. })
    ));
    assert_eq!(
        fs::read(external_target).expect("read external target"),
        b"sentinel"
    );
    assert_no_atomic_temps(&kind_dir);

    drop(store);
    fs::remove_dir_all(root_dir).expect("remove temp db dir");
}

#[cfg(unix)]
#[test]
fn blob_kind_purge_unlinks_root_symlink_without_following_target() {
    use std::os::unix::fs::symlink;

    let root_dir = temp_db_root();
    let store = DbStore::open(DbConfig {
        root_dir: root_dir.clone(),
    })
    .expect("open db");
    let kind = "purge-root-symlink";
    let external = root_dir.join("external-purge-root");
    fs::create_dir_all(&external).expect("create external tree");
    fs::write(external.join("sentinel"), b"sentinel").expect("write sentinel");
    symlink(&external, store.blob_dir().join(kind)).expect("symlink kind root");

    store.purge_blob_kind(kind).expect("purge root symlink");
    assert_eq!(
        fs::read(external.join("sentinel")).expect("read sentinel"),
        b"sentinel"
    );
    assert!(store.blob_dir().join(kind).is_dir());
    assert!(
        !fs::symlink_metadata(store.blob_dir().join(kind))
            .expect("read replacement kind")
            .file_type()
            .is_symlink()
    );
    drop(store);
    fs::remove_dir_all(root_dir).expect("remove temp db dir");
}

#[cfg(windows)]
#[test]
fn windows_blob_kind_purge_replaces_root_reparse_without_following_target() {
    use std::os::windows::fs::symlink_dir;

    let root_dir = temp_db_root();
    let store = DbStore::open(DbConfig {
        root_dir: root_dir.clone(),
    })
    .expect("open db");
    let kind = "purge-root-reparse";
    let external = root_dir.join("external-purge-root");
    fs::create_dir_all(&external).expect("create external tree");
    fs::write(external.join("sentinel"), b"sentinel").expect("write sentinel");
    if let Err(error) = symlink_dir(&external, store.blob_dir().join(kind)) {
        if error.kind() == std::io::ErrorKind::PermissionDenied
            || error.raw_os_error() == Some(1314)
        {
            drop(store);
            fs::remove_dir_all(root_dir).expect("remove skipped test root");
            return;
        }
        panic!("create root reparse fixture: {error}");
    }

    store.purge_blob_kind(kind).expect("purge root reparse");
    assert_eq!(
        fs::read(external.join("sentinel")).expect("read external sentinel"),
        b"sentinel"
    );
    let recreated = store.blob_dir().join(kind);
    assert!(recreated.is_dir());
    assert!(
        !fs::symlink_metadata(recreated)
            .expect("read recreated kind")
            .file_type()
            .is_symlink()
    );

    drop(store);
    fs::remove_dir_all(root_dir).expect("remove temp db dir");
}

#[test]
fn blob_kind_purge_removes_nested_regular_tree_and_recreates_kind() {
    let root_dir = temp_db_root();
    let store = DbStore::open(DbConfig {
        root_dir: root_dir.clone(),
    })
    .expect("open db");
    let kind = "purge-nested-regular";
    let kind_dir = store.ensure_blob_dir(kind).expect("create kind");
    fs::create_dir_all(kind_dir.join("one/two/three")).expect("create nested tree");
    fs::write(kind_dir.join("root.bin"), b"root").expect("write root file");
    fs::write(kind_dir.join("one/two/three/leaf.bin"), b"leaf").expect("write leaf file");

    store.purge_blob_kind(kind).expect("purge regular tree");
    let recreated = store.blob_dir().join(kind);
    assert!(recreated.is_dir());
    assert!(
        fs::read_dir(recreated)
            .expect("read recreated kind")
            .next()
            .is_none()
    );

    drop(store);
    fs::remove_dir_all(root_dir).expect("remove temp db dir");
}

fn assert_no_atomic_temps(kind_dir: &std::path::Path) {
    assert!(
        fs::read_dir(kind_dir)
            .expect("read kind directory")
            .filter_map(Result::ok)
            .all(|entry| !entry
                .file_name()
                .to_string_lossy()
                .starts_with(".railgun-blob-"))
    );
}

fn sample_record(chain_id: u64, public_tx_hash: FixedBytes<32>) -> PendingFeeNoteAssuranceRecord {
    PendingFeeNoteAssuranceRecord {
        chain_id,
        public_tx_hash,
        context: FeeNoteAssuranceContext {
            chain_type: 0,
            txid_version: "V3_PoseidonMerkle".to_string(),
            railgun_txid: uint!(5_U256),
            utxo_tree_in: 9,
            fee_commitment: FixedBytes::from([1u8; 32]),
            fee_note_npk: FixedBytes::from([2u8; 32]),
            pre_transaction_pois_per_txid_leaf_per_list: BTreeMap::new(),
            required_poi_list_keys: vec![FixedBytes::from([4u8; 32])],
        },
    }
}

fn sample_pre_tx_poi(byte: u8) -> PreTxPoi {
    PreTxPoi {
        snark_proof: SnarkJsProof {
            pi_a: [U256::from(byte), U256::from(byte + 1)],
            pi_b: [
                [U256::from(byte + 2), U256::from(byte + 3)],
                [U256::from(byte + 4), U256::from(byte + 5)],
            ],
            pi_c: [U256::from(byte + 6), U256::from(byte + 7)],
        },
        txid_merkleroot: FixedBytes::from([byte; 32]),
        poi_merkleroots: vec![FixedBytes::from([byte + 1; 32])],
        blinded_commitments_out: vec![FixedBytes::from([byte + 2; 32])],
        railgun_txid_if_has_unshield: Bytes::copy_from_slice(&[0_u8]),
    }
}

fn sample_pending_output_record(
    chain_id: u64,
    wallet_id: &str,
    output_commitment: FixedBytes<32>,
) -> PendingOutputPoiContextRecord {
    let list_key = FixedBytes::from([0x44; 32]);
    let txid_leaf = FixedBytes::from([0x55; 32]);
    PendingOutputPoiContextRecord {
        chain_id,
        wallet_id: wallet_id.to_string(),
        txid_version: "V2_PoseidonMerkle".to_string(),
        output_commitment,
        output_npk: FixedBytes::from([0x66; 32]),
        utxo_tree_in: 9,
        railgun_txid: uint!(7_U256),
        txid_merkleroot_index: None,
        pre_transaction_pois_per_txid_leaf_per_list: BTreeMap::from([(list_key, {
            BTreeMap::from([(txid_leaf, sample_pre_tx_poi(0x10))])
        })]),
        required_poi_list_keys: vec![list_key],
        output_role: PendingOutputPoiRole::Recipient,
        created_at: 123,
        source_operation_id: None,
        observation: None,
        submitted_poi_list_keys: Vec::new(),
        terminal_error: None,
    }
}

fn sample_output_poi_recovery_record(
    chain_id: u64,
    wallet_id: &str,
    output_commitment: FixedBytes<32>,
) -> OutputPoiRecoveryRecord {
    OutputPoiRecoveryRecord {
        chain_id,
        wallet_id: wallet_id.to_string(),
        output_commitment,
        source_tx_hash: FixedBytes::from([0x55; 32]),
        tx_input: Some(vec![1, 2, 3]),
        status: OutputPoiRecoveryStatus::NotSelfOriginated,
        created_at: 10,
        updated_at: 20,
        last_detection_at: Some(20),
        last_submission_at: None,
        next_retry_at: None,
        attempt_count: 1,
        last_error: Some("external sender".to_string()),
    }
}

fn schema_seven_pending_output_key(record: &PendingOutputPoiContextRecord) -> String {
    format!(
        "{}|{}",
        record.chain_id,
        alloy::hex::encode(record.output_commitment)
    )
}

fn put_raw_pending_output_record(store: &DbStore, key: &str, payload: &[u8]) {
    let txn = store.db.begin_write().expect("begin raw pending write");
    {
        let mut table = txn
            .open_table(PENDING_OUTPUT_POI_CONTEXT_TABLE)
            .expect("open pending table");
        table.insert(key, payload).expect("insert raw pending row");
    }
    txn.commit().expect("commit raw pending write");
}

fn put_raw_output_poi_recovery_record(store: &DbStore, key: &str, payload: &[u8]) {
    let txn = store.db.begin_write().expect("begin raw recovery write");
    {
        let mut table = txn
            .open_table(OUTPUT_POI_RECOVERY_TABLE)
            .expect("open recovery table");
        table.insert(key, payload).expect("insert raw recovery row");
    }
    txn.commit().expect("commit raw recovery write");
}

fn raw_pending_output_record_exists(store: &DbStore, key: &str) -> bool {
    let txn = store.db.begin_read().expect("begin raw pending read");
    let table = txn
        .open_table(PENDING_OUTPUT_POI_CONTEXT_TABLE)
        .expect("open pending table");
    table.get(key).expect("read raw pending row").is_some()
}

fn put_raw_poi_artifact_record(store: &DbStore, key: &str, payload: &[u8]) {
    let txn = store.db.begin_write().expect("begin raw POI corpus write");
    {
        let mut table = txn
            .open_table(POI_ARTIFACT_CACHE_TABLE)
            .expect("open POI corpus table");
        table
            .insert(key, payload)
            .expect("insert raw POI corpus row");
    }
    txn.commit().expect("commit raw POI corpus write");
}

fn sample_poi_artifact_cache_record(
    chain_id: u64,
    list_key: FixedBytes<32>,
) -> PoiArtifactCacheRecord {
    let descriptor = PoiArtifactDescriptorRecord {
        cid: "bafybeihash".to_string(),
        sha256: "00".repeat(32),
        byte_size: 16,
    };
    PoiArtifactCacheRecord {
        chain_type: 0,
        chain_id,
        txid_version: "V3_PoseidonMerkle".to_string(),
        list_key,
        cache_generation: 0,
        source: PoiCacheRecordSource::IndexedArtifacts,
        validation: PoiCorpusValidationRecord::Legacy,
        legacy_observed_manifest_sequence: 7,
        base_descriptor: descriptor.clone(),
        applied_delta_descriptors: vec![descriptor.clone()],
        blocked_shields_descriptor: descriptor,
        artifact_tip_index: Some(99),
        artifact_tip_root: Some(FixedBytes::from([0x77; 32])),
        current_tip_index: 99,
        current_tip_root: FixedBytes::from([0x77; 32]),
        cache_payload: vec![1, 2, 3, 4],
        legacy_last_successful_rpc_sync_at_ms: None,
        updated_at: 0,
    }
}

#[test]
fn legacy_poi_artifact_cache_record_defaults_to_indexed_artifact_source() {
    #[derive(serde::Serialize)]
    struct LegacyPoiArtifactCacheRecord {
        chain_type: u8,
        chain_id: u64,
        txid_version: String,
        list_key: FixedBytes<32>,
        last_accepted_manifest_sequence: u64,
        base_descriptor: PoiArtifactDescriptorRecord,
        applied_delta_descriptors: Vec<PoiArtifactDescriptorRecord>,
        blocked_shields_descriptor: PoiArtifactDescriptorRecord,
        current_tip_index: u64,
        current_tip_root: FixedBytes<32>,
        cache_payload: Vec<u8>,
        last_successful_rpc_sync_at_ms: Option<u64>,
        updated_at: u64,
    }

    let current = sample_poi_artifact_cache_record(1, FixedBytes::from([0x71; 32]));
    let encoded = encode(&LegacyPoiArtifactCacheRecord {
        chain_type: current.chain_type,
        chain_id: current.chain_id,
        txid_version: current.txid_version,
        list_key: current.list_key,
        last_accepted_manifest_sequence: current.legacy_observed_manifest_sequence,
        base_descriptor: current.base_descriptor,
        applied_delta_descriptors: current.applied_delta_descriptors,
        blocked_shields_descriptor: current.blocked_shields_descriptor,
        current_tip_index: current.current_tip_index,
        current_tip_root: current.current_tip_root,
        cache_payload: current.cache_payload,
        last_successful_rpc_sync_at_ms: Some(42),
        updated_at: current.updated_at,
    })
    .expect("encode legacy POI cache record");
    let decoded: PoiArtifactCacheRecord = decode(&encoded).expect("decode legacy POI cache record");

    assert_eq!(decoded.source, PoiCacheRecordSource::IndexedArtifacts);
    assert_eq!(decoded.validation, PoiCorpusValidationRecord::Legacy);
    assert_eq!(decoded.cache_generation, 0);
    assert_eq!(decoded.legacy_observed_manifest_sequence, 7);
    assert_eq!(decoded.artifact_tip_index, None);
    assert_eq!(decoded.artifact_tip_root, None);
    assert_eq!(decoded.legacy_last_successful_rpc_sync_at_ms, Some(42));
}

#[test]
fn poi_corpus_candidate_commit_rechecks_generation_watermark_and_base_atomically() {
    let root_dir = temp_db_root();
    let store = DbStore::open(DbConfig {
        root_dir: root_dir.clone(),
    })
    .expect("open db");
    let publisher = FixedBytes::from([0x41; 32]);
    let existing = sample_poi_artifact_cache_record(1, FixedBytes::from([0x42; 32]));
    store
        .put_poi_artifact_cache(&existing)
        .expect("seed corpus");
    store
        .advance_poi_publisher_manifest_watermark(publisher, 5)
        .expect("observe publisher sequence");
    let mut candidate = existing.clone();
    candidate.current_tip_root = FixedBytes::from([0x43; 32]);
    let expected_payload_hash = Some(keccak256(&existing.cache_payload));

    assert_eq!(
        store
            .commit_poi_artifact_cache_if_current(
                &candidate,
                PoiArtifactCacheCommitCondition {
                    expected_generation: 0,
                    expected_publisher: Some((publisher, 5)),
                    expected_manifest_hash: None,
                    expected_payload_hash,
                },
            )
            .expect("commit current candidate"),
        PoiArtifactCacheCommitOutcome::Applied
    );
    assert_eq!(
        store
            .get_poi_artifact_cache(0, 1, "V3_PoseidonMerkle", &candidate.list_key)
            .expect("read committed candidate")
            .expect("candidate present")
            .cache_generation,
        0
    );

    store
        .advance_poi_publisher_manifest_watermark(publisher, 6)
        .expect("advance publisher concurrently");
    assert_eq!(
        store
            .commit_poi_artifact_cache_if_current(
                &existing,
                PoiArtifactCacheCommitCondition {
                    expected_generation: 0,
                    expected_publisher: Some((publisher, 5)),
                    expected_manifest_hash: None,
                    expected_payload_hash: Some(keccak256(&candidate.cache_payload)),
                },
            )
            .expect("reject stale candidate"),
        PoiArtifactCacheCommitOutcome::PublisherSequenceConflict { actual: Some(6) }
    );

    drop(store);
    fs::remove_dir_all(root_dir).expect("remove temp db dir");
}

#[test]
fn poi_corpus_candidate_commit_rechecks_exact_manifest_hash() {
    let root_dir = temp_db_root();
    let store = DbStore::open(DbConfig {
        root_dir: root_dir.clone(),
    })
    .expect("open db");
    let publisher = FixedBytes::from([0x44; 32]);
    let accepted_hash = FixedBytes::from([0x45; 32]);
    let candidate = sample_poi_artifact_cache_record(1, FixedBytes::from([0x46; 32]));
    store
        .observe_poi_v4_publisher_manifest(publisher, 5, accepted_hash)
        .expect("observe exact publication");

    assert_eq!(
        store
            .commit_poi_artifact_cache_if_current(
                &candidate,
                PoiArtifactCacheCommitCondition {
                    expected_generation: 0,
                    expected_publisher: Some((publisher, 5)),
                    expected_manifest_hash: Some(FixedBytes::from([0x47; 32])),
                    expected_payload_hash: None,
                },
            )
            .expect("reject wrong publication hash"),
        PoiArtifactCacheCommitOutcome::PublisherManifestConflict {
            actual: Some(accepted_hash)
        }
    );

    drop(store);
    fs::remove_dir_all(root_dir).expect("remove temp db dir");
}

#[test]
fn pending_fee_note_assurance_roundtrip_and_listing() {
    let root_dir = temp_db_root();
    let store = DbStore::open(DbConfig {
        root_dir: root_dir.clone(),
    })
    .expect("open db");

    let record = sample_record(1, FixedBytes::from([0x11; 32]));
    store
        .put_pending_fee_note_assurance(&record)
        .expect("store assurance record");

    let loaded = store
        .get_pending_fee_note_assurance(record.chain_id, &record.public_tx_hash)
        .expect("load assurance record")
        .expect("record present");
    assert_eq!(loaded.context.txid_version, record.context.txid_version);
    assert_eq!(loaded.context.railgun_txid, record.context.railgun_txid);
    assert_eq!(
        loaded.context.required_poi_list_keys,
        record.context.required_poi_list_keys
    );

    let records = store
        .list_pending_fee_note_assurance(record.chain_id)
        .expect("list pending assurance records");
    assert_eq!(records.len(), 1);
    assert_eq!(records[0].public_tx_hash, record.public_tx_hash);

    assert!(
        store
            .list_terminal_fee_note_assurance(record.chain_id)
            .expect("list terminal assurance records")
            .is_empty()
    );

    drop(store);
    fs::remove_dir_all(root_dir).expect("remove temp db dir");
}

#[test]
fn delete_pending_fee_note_assurance_removes_record() {
    let root_dir = temp_db_root();
    let store = DbStore::open(DbConfig {
        root_dir: root_dir.clone(),
    })
    .expect("open db");

    let record = sample_record(56, FixedBytes::from([0x22; 32]));
    let key = record.key();
    assert!(key.starts_with("56|"));

    store
        .put_pending_fee_note_assurance(&record)
        .expect("store assurance record");
    store
        .delete_pending_fee_note_assurance(record.chain_id, &record.public_tx_hash)
        .expect("delete assurance record");

    assert!(
        store
            .get_pending_fee_note_assurance(record.chain_id, &record.public_tx_hash)
            .expect("load deleted record")
            .is_none()
    );

    drop(store);
    fs::remove_dir_all(root_dir).expect("remove temp db dir");
}

#[test]
fn marking_fee_note_assurance_terminal_moves_record() {
    let root_dir = temp_db_root();
    let store = DbStore::open(DbConfig {
        root_dir: root_dir.clone(),
    })
    .expect("open db");

    let record = sample_record(99, FixedBytes::from([0x33; 32]));
    store
        .put_pending_fee_note_assurance(&record)
        .expect("store assurance record");
    store
        .mark_fee_note_assurance_terminal(
            &record,
            super::FeeNoteAssuranceTerminalOutcome::CommitmentMismatch,
        )
        .expect("mark assurance record terminal");

    assert!(
        store
            .get_pending_fee_note_assurance(record.chain_id, &record.public_tx_hash)
            .expect("load pending assurance record")
            .is_none()
    );
    assert!(
        store
            .list_pending_fee_note_assurance(record.chain_id)
            .expect("list pending assurance records")
            .is_empty()
    );

    let terminal = store
        .get_terminal_fee_note_assurance(record.chain_id, &record.public_tx_hash)
        .expect("load terminal assurance record")
        .expect("terminal record present");
    assert_eq!(
        terminal.outcome,
        super::FeeNoteAssuranceTerminalOutcome::CommitmentMismatch
    );
    assert_eq!(terminal.context.railgun_txid, record.context.railgun_txid);

    let terminal_records = store
        .list_terminal_fee_note_assurance(record.chain_id)
        .expect("list terminal assurance records");
    assert_eq!(terminal_records.len(), 1);
    assert_eq!(terminal_records[0].public_tx_hash, record.public_tx_hash);

    drop(store);
    fs::remove_dir_all(root_dir).expect("remove temp db dir");
}

#[test]
fn pending_output_poi_context_roundtrip_and_listing() {
    let root_dir = temp_db_root();
    let store = DbStore::open(DbConfig {
        root_dir: root_dir.clone(),
    })
    .expect("open db");

    let wallet_id = wallet_cache_key(0x01).to_string();
    let other_wallet_id = wallet_cache_key(0x02).to_string();
    let record = sample_pending_output_record(1, &wallet_id, FixedBytes::from([0x77; 32]));
    store
        .put_pending_output_poi_context(&record)
        .expect("store pending output POI context");

    let loaded = store
        .get_pending_output_poi_context(
            record.chain_id,
            &record.wallet_id,
            &record.output_commitment,
        )
        .expect("load pending output POI context")
        .expect("record present");
    assert_eq!(loaded.wallet_id, record.wallet_id);
    assert_eq!(loaded.txid_version, record.txid_version);
    assert_eq!(loaded.output_npk, record.output_npk);
    assert_eq!(loaded.output_role, PendingOutputPoiRole::Recipient);
    assert_eq!(loaded.required_poi_list_keys, record.required_poi_list_keys);
    assert!(loaded.observation.is_none());
    assert!(loaded.submitted_poi_list_keys.is_empty());
    assert!(loaded.terminal_error.is_none());

    let records = store
        .list_pending_output_poi_contexts(record.chain_id, &record.wallet_id)
        .expect("list pending output POI contexts");
    assert_eq!(records.len(), 1);
    assert_eq!(records[0].output_commitment, record.output_commitment);
    assert!(
        store
            .list_pending_output_poi_contexts(2, &record.wallet_id)
            .expect("list other chain pending output POI contexts")
            .is_empty()
    );
    assert!(
        store
            .list_pending_output_poi_contexts(record.chain_id, &other_wallet_id)
            .expect("list other wallet pending output POI contexts")
            .is_empty()
    );
    store
        .delete_pending_output_poi_context(
            record.chain_id,
            &record.wallet_id,
            &record.output_commitment,
        )
        .expect("delete pending output POI context");
    assert!(
        store
            .get_pending_output_poi_context(
                record.chain_id,
                &record.wallet_id,
                &record.output_commitment,
            )
            .expect("load deleted pending output POI context")
            .is_none()
    );

    drop(store);
    fs::remove_dir_all(root_dir).expect("remove temp db dir");
}

#[test]
fn output_poi_recovery_roundtrip_and_wallet_listing() {
    let root_dir = temp_db_root();
    let store = DbStore::open(DbConfig {
        root_dir: root_dir.clone(),
    })
    .expect("open db");

    let record = sample_output_poi_recovery_record(
        1,
        wallet_cache_key(0x0a).as_str(),
        FixedBytes::from([0x44; 32]),
    );
    let other_wallet = OutputPoiRecoveryRecord {
        wallet_id: wallet_cache_key(0x0b).to_string(),
        output_commitment: FixedBytes::from([0x66; 32]),
        ..record.clone()
    };

    store
        .put_output_poi_recovery(&record)
        .expect("store recovery record");
    store
        .put_output_poi_recovery(&other_wallet)
        .expect("store other wallet recovery record");

    let loaded = store
        .get_output_poi_recovery(
            record.chain_id,
            &record.wallet_id,
            &record.output_commitment,
        )
        .expect("load recovery record")
        .expect("record present");
    assert_eq!(loaded.status, OutputPoiRecoveryStatus::NotSelfOriginated);
    assert_eq!(loaded.source_tx_hash, record.source_tx_hash);
    assert_eq!(loaded.tx_input, record.tx_input);
    assert_eq!(loaded.last_error, record.last_error);

    let records = store
        .list_output_poi_recoveries(record.chain_id, &record.wallet_id)
        .expect("list wallet recovery records");
    assert_eq!(records.len(), 1);
    assert_eq!(records[0].output_commitment, record.output_commitment);

    drop(store);
    fs::remove_dir_all(root_dir).expect("remove temp db dir");
}

#[test]
fn app_settings_records_are_transactional_plaintext_records() {
    let root_dir = temp_db_root();
    let store = DbStore::open(DbConfig {
        root_dir: root_dir.clone(),
    })
    .expect("open db");

    assert!(
        store
            .get_app_settings_record("wallet-settings")
            .expect("load missing settings")
            .is_none()
    );

    store
        .put_app_settings_record("wallet-settings", b"settings-v1")
        .expect("store settings");
    store
        .put_app_settings_record("other-settings", b"other")
        .expect("store other settings");
    let max_prefix_key = format!("{}-settings", char::MAX);
    store
        .put_app_settings_record(&max_prefix_key, b"max-prefix")
        .expect("store max-prefix settings");

    assert_eq!(
        store
            .get_app_settings_record("wallet-settings")
            .expect("load settings")
            .expect("settings present"),
        b"settings-v1"
    );

    let records = store
        .list_app_settings_records("wallet")
        .expect("list settings records");
    assert_eq!(records.len(), 1);
    assert_eq!(records[0].key, "wallet-settings");
    assert_eq!(records[0].payload, b"settings-v1");
    assert_eq!(
        store
            .list_app_settings_records("")
            .expect("list all settings records")
            .len(),
        3
    );
    assert_eq!(
        store
            .list_app_settings_records(&char::MAX.to_string())
            .expect("list max-prefix settings")
            .len(),
        1
    );

    store
        .delete_app_settings_record("wallet-settings")
        .expect("delete settings");
    assert!(
        store
            .get_app_settings_record("wallet-settings")
            .expect("load deleted settings")
            .is_none()
    );

    drop(store);
    fs::remove_dir_all(root_dir).expect("remove temp db dir");
}

#[test]
fn poi_publisher_manifest_watermarks_round_trip_and_are_isolated() {
    let root_dir = temp_db_root();
    let store = DbStore::open(DbConfig {
        root_dir: root_dir.clone(),
    })
    .expect("open db");
    let first = PoiPublisherManifestWatermarkRecord {
        publisher_pubkey: FixedBytes::from([0x11; 32]),
        accepted_sequence: 7,
        accepted_manifest_hash: None,
        updated_at: u64::MAX,
    };
    let second = PoiPublisherManifestWatermarkRecord {
        publisher_pubkey: FixedBytes::from([0x22; 32]),
        accepted_sequence: 9,
        accepted_manifest_hash: None,
        updated_at: u64::MAX,
    };
    assert_eq!(
        first.key(),
        format!(
            "railgun:ppoi-sidecar:v1:publisher-manifest-watermark:{}",
            "11".repeat(32)
        )
    );

    store
        .advance_poi_publisher_manifest_watermark(first.publisher_pubkey, first.accepted_sequence)
        .expect("store first publisher watermark");
    store
        .advance_poi_publisher_manifest_watermark(second.publisher_pubkey, second.accepted_sequence)
        .expect("store second publisher watermark");
    store
        .put_app_settings_record("wallet-settings", b"settings-v1")
        .expect("store unrelated app setting");

    let loaded_first = store
        .get_poi_publisher_manifest_watermark(&first.publisher_pubkey)
        .expect("load first publisher watermark")
        .expect("first publisher watermark present");
    let loaded_second = store
        .get_poi_publisher_manifest_watermark(&second.publisher_pubkey)
        .expect("load second publisher watermark")
        .expect("second publisher watermark present");
    assert_ne!(loaded_first.updated_at, first.updated_at);
    assert_ne!(loaded_second.updated_at, second.updated_at);
    let mut expected_first = first.clone();
    expected_first.updated_at = loaded_first.updated_at;
    let mut expected_second = second.clone();
    expected_second.updated_at = loaded_second.updated_at;
    assert_eq!(loaded_first, expected_first);
    assert_eq!(loaded_second, expected_second);
    let retained = store
        .advance_poi_publisher_manifest_watermark(first.publisher_pubkey, 5)
        .expect("retain monotonic publisher watermark")
        .0;
    assert_eq!(retained.accepted_sequence, 7);
    assert!(
        store
            .get_poi_publisher_manifest_watermark(&FixedBytes::from([0x33; 32]))
            .expect("load missing publisher watermark")
            .is_none()
    );
    assert_eq!(
        store
            .get_app_settings_record("wallet-settings")
            .expect("load unrelated app setting")
            .expect("unrelated app setting present"),
        b"settings-v1"
    );

    let mismatched_key = PoiPublisherManifestWatermarkRecord::key_for(&second.publisher_pubkey);
    store
        .put_app_settings_record(&mismatched_key, &encode(&first).expect("encode watermark"))
        .expect("store mismatched publisher watermark");
    assert!(matches!(
        store.get_poi_publisher_manifest_watermark(&second.publisher_pubkey),
        Err(DbError::InvalidPpoiSidecarRecord { .. })
    ));

    drop(store);
    fs::remove_dir_all(root_dir).expect("remove temp db dir");
}

#[test]
fn poi_v4_publisher_manifest_binding_is_atomic_and_durable() {
    let root_dir = temp_db_root();
    let publisher = FixedBytes::from([0x51; 32]);
    let first_hash = FixedBytes::from([0x52; 32]);
    let second_hash = FixedBytes::from([0x53; 32]);
    {
        let store = DbStore::open(DbConfig {
            root_dir: root_dir.clone(),
        })
        .expect("open db");
        store
            .advance_poi_publisher_manifest_watermark(publisher, 7)
            .expect("seed unbound legacy watermark");
        assert!(matches!(
            store
                .observe_poi_v4_publisher_manifest(publisher, 7, first_hash)
                .expect("bind publication"),
            PoiPublisherManifestObservation::Accepted { changed: true, .. }
        ));
        assert!(matches!(
            store
                .observe_poi_v4_publisher_manifest(publisher, 7, first_hash)
                .expect("observe same publication"),
            PoiPublisherManifestObservation::Accepted { changed: false, .. }
        ));
        assert!(matches!(
            store
                .observe_poi_v4_publisher_manifest(publisher, 7, second_hash)
                .expect("reject equivocation"),
            PoiPublisherManifestObservation::Equivocation { .. }
        ));
    }
    let reopened = DbStore::open(DbConfig {
        root_dir: root_dir.clone(),
    })
    .expect("reopen db");
    let watermark = reopened
        .get_poi_publisher_manifest_watermark(&publisher)
        .expect("read watermark")
        .expect("watermark present");
    assert_eq!(watermark.accepted_sequence, 7);
    assert_eq!(watermark.accepted_manifest_hash, Some(first_hash));
    let (retained, advanced) = reopened
        .advance_poi_publisher_manifest_watermark(publisher, 7)
        .expect("equal legacy observation preserves binding");
    assert!(!advanced);
    assert_eq!(retained.accepted_manifest_hash, Some(first_hash));
    assert!(matches!(
        reopened
            .observe_poi_v4_publisher_manifest(publisher, 6, first_hash)
            .expect("reject rollback"),
        PoiPublisherManifestObservation::Rollback { .. }
    ));
    let (unbound, advanced) = reopened
        .advance_poi_publisher_manifest_watermark(publisher, 8)
        .expect("higher legacy observation advances unbound");
    assert!(advanced);
    assert_eq!(unbound.accepted_manifest_hash, None);
    assert!(matches!(
        reopened
            .observe_poi_v4_publisher_manifest(publisher, 8, second_hash)
            .expect("bind higher publication"),
        PoiPublisherManifestObservation::Accepted { changed: true, .. }
    ));

    drop(reopened);
    fs::remove_dir_all(root_dir).expect("remove temp db dir");
}

#[test]
fn poi_corpus_rpc_health_records_round_trip_and_are_isolated() {
    let root_dir = temp_db_root();
    let store = DbStore::open(DbConfig {
        root_dir: root_dir.clone(),
    })
    .expect("open db");
    let first = PoiCorpusRpcHealthRecord {
        chain_type: 0,
        chain_id: 1,
        txid_version: "V3|PoseidonMerkle".to_string(),
        list_key: FixedBytes::from([0x44; 32]),
        cache_generation: 3,
        last_successful_rpc_sync_at_ms: Some(1_700_000_000_123),
        updated_at: u64::MAX,
    };
    let second = PoiCorpusRpcHealthRecord {
        chain_type: 0,
        chain_id: 137,
        txid_version: "V3|PoseidonMerkle".to_string(),
        list_key: FixedBytes::from([0x55; 32]),
        cache_generation: 4,
        last_successful_rpc_sync_at_ms: None,
        updated_at: u64::MAX,
    };
    assert_eq!(
        first.key(),
        format!(
            "railgun:ppoi-sidecar:v1:corpus-rpc-health:00:0000000000000001:{}:{}",
            alloy::hex::encode(first.txid_version.as_bytes()),
            "44".repeat(32)
        )
    );
    assert_ne!(
        first.key(),
        PoiCorpusRpcHealthRecord::key_for(1, first.chain_id, &first.txid_version, &first.list_key,)
    );
    assert_ne!(
        first.key(),
        PoiCorpusRpcHealthRecord::key_for(
            first.chain_type,
            2,
            &first.txid_version,
            &first.list_key,
        )
    );
    assert_ne!(
        first.key(),
        PoiCorpusRpcHealthRecord::key_for(
            first.chain_type,
            first.chain_id,
            "V3|Poseidon|Merkle",
            &first.list_key,
        )
    );
    assert_ne!(
        first.key(),
        PoiCorpusRpcHealthRecord::key_for(
            first.chain_type,
            first.chain_id,
            &first.txid_version,
            &FixedBytes::from([0x45; 32]),
        )
    );

    store
        .put_poi_corpus_rpc_health(&first)
        .expect("store first corpus RPC health");
    store
        .put_poi_corpus_rpc_health(&second)
        .expect("store second corpus RPC health");

    let loaded_first = store
        .get_poi_corpus_rpc_health(
            first.chain_type,
            first.chain_id,
            &first.txid_version,
            &first.list_key,
        )
        .expect("load first corpus RPC health")
        .expect("first corpus RPC health present");
    let loaded_second = store
        .get_poi_corpus_rpc_health(
            second.chain_type,
            second.chain_id,
            &second.txid_version,
            &second.list_key,
        )
        .expect("load second corpus RPC health")
        .expect("second corpus RPC health present");
    assert_ne!(loaded_first.updated_at, first.updated_at);
    assert_ne!(loaded_second.updated_at, second.updated_at);
    let mut expected_first = first.clone();
    expected_first.updated_at = loaded_first.updated_at;
    let mut expected_second = second.clone();
    expected_second.updated_at = loaded_second.updated_at;
    assert_eq!(loaded_first, expected_first);
    assert_eq!(loaded_second, expected_second);
    assert!(
        store
            .get_poi_corpus_rpc_health(
                first.chain_type,
                first.chain_id,
                "V2_PoseidonMerkle",
                &first.list_key,
            )
            .expect("load isolated corpus RPC health")
            .is_none()
    );

    let mismatched_key = PoiCorpusRpcHealthRecord::key_for(
        second.chain_type,
        second.chain_id,
        &second.txid_version,
        &second.list_key,
    );
    store
        .put_app_settings_record(
            &mismatched_key,
            &encode(&first).expect("encode corpus RPC health"),
        )
        .expect("store mismatched corpus RPC health");
    assert!(matches!(
        store.get_poi_corpus_rpc_health(
            second.chain_type,
            second.chain_id,
            &second.txid_version,
            &second.list_key,
        ),
        Err(DbError::InvalidPpoiSidecarRecord { .. })
    ));

    drop(store);
    fs::remove_dir_all(root_dir).expect("remove temp db dir");
}

#[test]
fn poi_artifact_cache_scan_isolates_undecodable_rows() {
    let root_dir = temp_db_root();
    let store = DbStore::open(DbConfig {
        root_dir: root_dir.clone(),
    })
    .expect("open db");
    let record = sample_poi_artifact_cache_record(1, FixedBytes::from([0x61; 32]));
    store
        .put_poi_artifact_cache(&record)
        .expect("store valid POI corpus");
    let undecodable_key = PoiArtifactCacheRecord::key_for(
        record.chain_type,
        138,
        &record.txid_version,
        &record.list_key,
    );
    let txn = store.db.begin_write().expect("begin malformed row write");
    {
        let mut table = txn
            .open_table(POI_ARTIFACT_CACHE_TABLE)
            .expect("open POI corpus table");
        table
            .insert(undecodable_key.as_str(), &[0xc1_u8][..])
            .expect("insert malformed POI corpus");
    }
    txn.commit().expect("commit malformed row");

    let mismatched_key = PoiArtifactCacheRecord::key_for(
        record.chain_type,
        137,
        &record.txid_version,
        &record.list_key,
    );
    let txn = store.db.begin_write().expect("begin mismatched row write");
    {
        let mut table = txn
            .open_table(POI_ARTIFACT_CACHE_TABLE)
            .expect("open POI corpus table");
        table
            .insert(
                mismatched_key.as_str(),
                encode(&record)
                    .expect("encode mismatched POI corpus")
                    .as_slice(),
            )
            .expect("insert mismatched POI corpus");
    }
    txn.commit().expect("commit mismatched row");

    assert!(matches!(
        store.get_poi_artifact_cache(
            record.chain_type,
            137,
            &record.txid_version,
            &record.list_key,
        ),
        Err(DbError::InvalidPpoiCorpusRecord { .. })
    ));
    assert!(matches!(
        store
            .inspect_poi_artifact_cache(
                record.chain_type,
                137,
                &record.txid_version,
                &record.list_key,
            )
            .expect("inspect mismatched corpus"),
        StoredRecord::Corrupt { .. }
    ));
    assert!(matches!(
        store
            .inspect_poi_artifact_cache(
                record.chain_type,
                138,
                &record.txid_version,
                &record.list_key,
            )
            .expect("inspect undecodable corpus"),
        StoredRecord::Corrupt { .. }
    ));

    let scan = store
        .scan_poi_artifact_caches()
        .expect("scan POI corpus records");
    assert_eq!(scan.records.len(), 1);
    let mut expected = record.clone();
    expected.updated_at = scan.records[0].updated_at;
    assert_eq!(scan.records, vec![expected]);
    assert_eq!(scan.invalid_keys, vec![mismatched_key, undecodable_key]);

    let mut replacement = record;
    replacement.chain_id = 138;
    store
        .put_poi_artifact_cache(&replacement)
        .expect("replace corrupt canonical corpus");
    assert!(matches!(
        store
            .inspect_poi_artifact_cache(
                replacement.chain_type,
                replacement.chain_id,
                &replacement.txid_version,
                &replacement.list_key,
            )
            .expect("inspect replacement corpus"),
        StoredRecord::Valid(_)
    ));

    drop(store);
    fs::remove_dir_all(root_dir).expect("remove temp db dir");
}

#[test]
fn wallet_sync_actor_state_records_round_trip_and_list_by_chain() {
    let root_dir = temp_db_root();
    let store = DbStore::open(DbConfig {
        root_dir: root_dir.clone(),
    })
    .expect("open db");

    let record = WalletSyncActorStateRecord {
        chain_id: 1,
        wallet_id: wallet_cache_key(0x0a).to_string(),
        highest_accepted_reset_intent: 9,
        pending_reset: Some(WalletPendingResetRecord {
            intent_id: 9,
            from_block: 42,
            replay_start_block: 40,
            replay_target_block: 100,
            follow_safe_head: true,
        }),
        updated_at: 123,
    };
    store
        .put_wallet_sync_actor_state(&record)
        .expect("store wallet sync actor state");
    store
        .put_wallet_sync_actor_state(&WalletSyncActorStateRecord {
            chain_id: 2,
            wallet_id: wallet_cache_key(0x0b).to_string(),
            highest_accepted_reset_intent: 1,
            pending_reset: None,
            updated_at: 456,
        })
        .expect("store other chain wallet sync actor state");

    assert_eq!(
        store
            .get_wallet_sync_actor_state(1, &record.wallet_id)
            .expect("load wallet sync actor state")
            .expect("wallet sync actor state present"),
        record
    );
    let chain_records = store
        .list_wallet_sync_actor_states_for_chain(1)
        .expect("list wallet sync actor states");
    assert_eq!(chain_records, vec![record]);

    drop(store);
    fs::remove_dir_all(root_dir).expect("remove temp db dir");
}

#[test]
fn wallet_private_namespace_deletion_is_complete_isolated_and_idempotent() {
    let root_dir = temp_db_root();
    let store = DbStore::open(DbConfig {
        root_dir: root_dir.clone(),
    })
    .expect("open db");
    let target = WalletPrivateNamespaceId::new(
        1,
        WalletCacheKey::new("0zk-test-wallet", 1, Address::from([0x11; 20])),
    );
    let other_wallet = WalletPrivateNamespaceId::new(1, wallet_cache_key(0x22));
    let target_meta = WalletMeta {
        last_scanned_block: 42,
        updated_at: 10,
        last_scanned_block_hash: Some([0x11; 32]),
    };
    let other_meta = WalletMeta {
        last_scanned_block: 84,
        updated_at: 20,
        last_scanned_block_hash: Some([0x22; 32]),
    };
    let target_actor_state = WalletSyncActorStateRecord {
        chain_id: target.chain_id,
        wallet_id: target.wallet_id.to_string(),
        highest_accepted_reset_intent: 3,
        pending_reset: None,
        updated_at: 30,
    };
    let other_wallet_actor_state = WalletSyncActorStateRecord {
        chain_id: other_wallet.chain_id,
        wallet_id: other_wallet.wallet_id.to_string(),
        highest_accepted_reset_intent: 4,
        pending_reset: None,
        updated_at: 40,
    };
    let other_chain_actor_state = WalletSyncActorStateRecord {
        chain_id: 2,
        wallet_id: target.wallet_id.to_string(),
        highest_accepted_reset_intent: 5,
        pending_reset: None,
        updated_at: 50,
    };
    let target_pending_a = sample_pending_output_record(
        target.chain_id,
        target.wallet_id.as_str(),
        FixedBytes::from([0x31; 32]),
    );
    let target_pending_b = sample_pending_output_record(
        target.chain_id,
        target.wallet_id.as_str(),
        FixedBytes::from([0x32; 32]),
    );
    let other_wallet_pending = sample_pending_output_record(
        other_wallet.chain_id,
        other_wallet.wallet_id.as_str(),
        FixedBytes::from([0x33; 32]),
    );
    let other_chain_pending =
        sample_pending_output_record(2, target.wallet_id.as_str(), FixedBytes::from([0x34; 32]));
    let target_recovery = sample_output_poi_recovery_record(
        target.chain_id,
        target.wallet_id.as_str(),
        FixedBytes::from([0x41; 32]),
    );
    let other_wallet_recovery = sample_output_poi_recovery_record(
        other_wallet.chain_id,
        other_wallet.wallet_id.as_str(),
        FixedBytes::from([0x42; 32]),
    );
    let other_chain_recovery = sample_output_poi_recovery_record(
        2,
        target.wallet_id.as_str(),
        FixedBytes::from([0x43; 32]),
    );
    let target_v1_pending = sample_pending_output_record(
        target.chain_id,
        target.wallet_id.as_str(),
        FixedBytes::from([0x35; 32]),
    );
    let target_v1_recovery = sample_output_poi_recovery_record(
        target.chain_id,
        target.wallet_id.as_str(),
        FixedBytes::from([0x44; 32]),
    );
    let public_poi_cache =
        sample_poi_artifact_cache_record(target.chain_id, FixedBytes::from([0x51; 32]));

    store
        .put_wallet_utxo(&target.wallet_id, "utxo-1", b"target-1")
        .expect("store first target UTXO");
    store
        .put_wallet_utxo(&target.wallet_id, "utxo-2", b"target-2")
        .expect("store second target UTXO");
    store
        .put_wallet_utxo(&target.wallet_id, "~legacy", b"target-legacy")
        .expect("store lexical-boundary target UTXO");
    store
        .put_wallet_utxo(&target.wallet_id, "legacy|utxo", b"delimiter-supported")
        .expect("store delimiter-bearing target UTXO");
    store
        .put_wallet_utxo(&other_wallet.wallet_id, "utxo-1", b"other")
        .expect("store other wallet UTXO");
    store
        .put_wallet_meta(&target.wallet_id, &target_meta)
        .expect("store target metadata");
    store
        .put_wallet_meta(&other_wallet.wallet_id, &other_meta)
        .expect("store other wallet metadata");
    for actor_state in [
        &target_actor_state,
        &other_wallet_actor_state,
        &other_chain_actor_state,
    ] {
        store
            .put_wallet_sync_actor_state(actor_state)
            .expect("store actor state");
    }
    for pending in [
        &target_pending_a,
        &target_pending_b,
        &other_wallet_pending,
        &other_chain_pending,
    ] {
        store
            .put_pending_output_poi_context(pending)
            .expect("store pending output context");
    }
    for recovery in [
        &target_recovery,
        &other_wallet_recovery,
        &other_chain_recovery,
    ] {
        store
            .put_output_poi_recovery(recovery)
            .expect("store output recovery");
    }
    put_raw_pending_output_record(
        &store,
        &target_v1_pending.key(),
        &encode(&target_v1_pending).expect("encode target v1 pending context"),
    );
    put_raw_output_poi_recovery_record(
        &store,
        &target_v1_recovery.key(),
        &encode(&target_v1_recovery).expect("encode target v1 recovery"),
    );
    store
        .put_poi_artifact_cache(&public_poi_cache)
        .expect("store public POI cache");

    let report = store
        .delete_wallet_private_namespace(&target)
        .expect("delete target wallet-private namespace");
    assert_eq!(
        report,
        WalletPrivateNamespaceDeletionReport {
            wallet_utxo_rows: 4,
            wallet_meta_rows: 1,
            wallet_sync_actor_state_rows: 1,
            pending_output_poi_context_rows: 3,
            output_poi_recovery_rows: 2,
        }
    );
    assert!(
        store
            .list_wallet_utxos(&target.wallet_id)
            .expect("list deleted target UTXOs")
            .is_empty()
    );
    assert!(
        store
            .get_wallet_meta(&target.wallet_id)
            .expect("load deleted target metadata")
            .is_none()
    );
    assert!(
        store
            .get_wallet_sync_actor_state(target.chain_id, target.wallet_id.as_str())
            .expect("load deleted target actor state")
            .is_none()
    );
    assert!(
        store
            .list_pending_output_poi_contexts(target.chain_id, target.wallet_id.as_str())
            .expect("list deleted target pending contexts")
            .is_empty()
    );
    assert!(
        store
            .list_output_poi_recoveries(target.chain_id, target.wallet_id.as_str())
            .expect("list deleted target recoveries")
            .is_empty()
    );

    assert_eq!(
        store
            .list_wallet_utxos(&other_wallet.wallet_id)
            .expect("list other wallet UTXOs")
            .len(),
        1
    );
    assert!(
        store
            .get_wallet_meta(&other_wallet.wallet_id)
            .expect("load other wallet metadata")
            .is_some()
    );
    assert!(
        store
            .get_wallet_sync_actor_state(other_wallet.chain_id, other_wallet.wallet_id.as_str())
            .expect("load other wallet actor state")
            .is_some()
    );
    assert_eq!(
        store
            .list_pending_output_poi_contexts(
                other_wallet.chain_id,
                other_wallet.wallet_id.as_str(),
            )
            .expect("list other wallet pending contexts")
            .len(),
        1
    );
    assert_eq!(
        store
            .list_output_poi_recoveries(other_wallet.chain_id, other_wallet.wallet_id.as_str(),)
            .expect("list other wallet recoveries")
            .len(),
        1
    );
    assert!(
        store
            .get_wallet_sync_actor_state(2, target.wallet_id.as_str())
            .expect("load other chain actor state")
            .is_some()
    );
    assert_eq!(
        store
            .list_pending_output_poi_contexts(2, target.wallet_id.as_str())
            .expect("list other chain pending contexts")
            .len(),
        1
    );
    assert_eq!(
        store
            .list_output_poi_recoveries(2, target.wallet_id.as_str())
            .expect("list other chain recoveries")
            .len(),
        1
    );
    assert!(
        store
            .get_poi_artifact_cache(
                public_poi_cache.chain_type,
                public_poi_cache.chain_id,
                &public_poi_cache.txid_version,
                &public_poi_cache.list_key,
            )
            .expect("load preserved public POI cache")
            .is_some()
    );

    assert_eq!(
        store
            .delete_wallet_private_namespace(&target)
            .expect("repeat target namespace deletion"),
        WalletPrivateNamespaceDeletionReport::default()
    );
    assert_eq!(
        store
            .delete_wallet_private_namespace(&WalletPrivateNamespaceId::new(
                99,
                wallet_cache_key(0x99)
            ),)
            .expect("delete empty namespace"),
        WalletPrivateNamespaceDeletionReport::default()
    );

    drop(store);
    fs::remove_dir_all(root_dir).expect("remove temp db dir");
}

#[test]
fn wallet_private_namespace_deletion_rolls_back_before_commit_failure() {
    let root_dir = temp_db_root();
    let store = DbStore::open(DbConfig {
        root_dir: root_dir.clone(),
    })
    .expect("open db");
    let identity = WalletPrivateNamespaceId::new(1, wallet_cache_key(0x11));
    let actor_state = WalletSyncActorStateRecord {
        chain_id: identity.chain_id,
        wallet_id: identity.wallet_id.to_string(),
        highest_accepted_reset_intent: 3,
        pending_reset: None,
        updated_at: 30,
    };
    let pending = sample_pending_output_record(
        identity.chain_id,
        identity.wallet_id.as_str(),
        FixedBytes::from([0x61; 32]),
    );
    let recovery = sample_output_poi_recovery_record(
        identity.chain_id,
        identity.wallet_id.as_str(),
        FixedBytes::from([0x62; 32]),
    );
    store
        .put_wallet_utxo(&identity.wallet_id, "utxo-1", b"target")
        .expect("store target UTXO");
    store
        .put_wallet_meta(
            &identity.wallet_id,
            &WalletMeta {
                last_scanned_block: 42,
                updated_at: 10,
                last_scanned_block_hash: None,
            },
        )
        .expect("store target metadata");
    store
        .put_wallet_sync_actor_state(&actor_state)
        .expect("store target actor state");
    store
        .put_pending_output_poi_context(&pending)
        .expect("store target pending context");
    store
        .put_output_poi_recovery(&recovery)
        .expect("store target recovery");

    let result = store.delete_wallet_private_namespace_transaction(&identity, || {
        Err(DbError::Io(std::io::Error::other(
            "injected pre-commit failure",
        )))
    });
    assert!(result.is_err());
    assert_eq!(
        store
            .list_wallet_utxos(&identity.wallet_id)
            .expect("list rolled-back UTXOs")
            .len(),
        1
    );
    assert!(
        store
            .get_wallet_meta(&identity.wallet_id)
            .expect("load rolled-back metadata")
            .is_some()
    );
    assert!(
        store
            .get_wallet_sync_actor_state(identity.chain_id, identity.wallet_id.as_str())
            .expect("load rolled-back actor state")
            .is_some()
    );
    assert_eq!(
        store
            .list_pending_output_poi_contexts(identity.chain_id, identity.wallet_id.as_str())
            .expect("list rolled-back pending contexts")
            .len(),
        1
    );
    assert_eq!(
        store
            .list_output_poi_recoveries(identity.chain_id, identity.wallet_id.as_str())
            .expect("list rolled-back recoveries")
            .len(),
        1
    );

    drop(store);
    fs::remove_dir_all(root_dir).expect("remove temp db dir");
}

#[test]
fn wallet_private_state_and_vault_records_commit_atomically() {
    let root_dir = temp_db_root();
    let store = DbStore::open(DbConfig {
        root_dir: root_dir.clone(),
    })
    .expect("open db");
    let namespace = WalletPrivateNamespaceId::new(1, wallet_cache_key(0x21));
    let utxos = [("new-utxo".to_string(), b"new-payload".to_vec())];
    let meta = WalletMeta {
        last_scanned_block: 90,
        updated_at: 10,
        last_scanned_block_hash: None,
    };
    let actor_state = WalletSyncActorStateRecord {
        chain_id: namespace.chain_id,
        wallet_id: namespace.wallet_id.to_string(),
        highest_accepted_reset_intent: 7,
        pending_reset: None,
        updated_at: 20,
    };
    let vault_records = [DesktopWalletVaultRecord {
        key: "wallet-chain-metadata|21".to_string(),
        payload: b"encrypted-metadata".to_vec(),
    }];

    store
        .batch_commit_wallet_private_state_with_vault_records(
            &WalletPrivateStateBatch {
                namespace: &namespace,
                utxos: WalletUtxoRowMutation::Replace(&utxos),
                metadata: WalletMetaMutation::Set(&meta),
                sync_actor_state: Some(&actor_state),
                pending_output_contexts: OpaqueWalletPrivateRowMutation::default(),
                output_poi_recoveries: OpaqueWalletPrivateRowMutation::default(),
            },
            &vault_records,
        )
        .expect("commit private state and vault record");

    assert_eq!(
        store
            .list_wallet_utxos(&namespace.wallet_id)
            .expect("list committed UTXOs")[0]
            .payload
            .as_slice(),
        b"new-payload"
    );
    let stored_meta = store
        .get_wallet_meta(&namespace.wallet_id)
        .expect("load committed metadata")
        .expect("committed metadata present");
    assert_eq!(stored_meta.last_scanned_block, meta.last_scanned_block);
    assert_eq!(stored_meta.updated_at, meta.updated_at);
    assert_eq!(
        stored_meta.last_scanned_block_hash,
        meta.last_scanned_block_hash
    );
    assert_eq!(
        store
            .get_wallet_sync_actor_state(namespace.chain_id, namespace.wallet_id.as_str())
            .expect("load committed actor state"),
        Some(actor_state)
    );
    assert_eq!(
        store
            .get_desktop_wallet_vault_record(&vault_records[0].key)
            .expect("load committed vault record"),
        Some(vault_records[0].payload.clone())
    );

    drop(store);
    fs::remove_dir_all(root_dir).expect("remove temp db dir");
}

#[test]
fn wallet_private_state_and_vault_records_roll_back_before_commit_failure() {
    let root_dir = temp_db_root();
    let store = DbStore::open(DbConfig {
        root_dir: root_dir.clone(),
    })
    .expect("open db");
    let namespace = WalletPrivateNamespaceId::new(1, wallet_cache_key(0x22));
    let original_meta = WalletMeta {
        last_scanned_block: 150,
        updated_at: 1,
        last_scanned_block_hash: Some([0xaa; 32]),
    };
    let original_actor_state = WalletSyncActorStateRecord {
        chain_id: namespace.chain_id,
        wallet_id: namespace.wallet_id.to_string(),
        highest_accepted_reset_intent: 4,
        pending_reset: None,
        updated_at: 1,
    };
    store
        .put_wallet_utxo(&namespace.wallet_id, "old-utxo", b"old-payload")
        .expect("seed old UTXO");
    store
        .put_wallet_meta(&namespace.wallet_id, &original_meta)
        .expect("seed old metadata");
    store
        .put_wallet_sync_actor_state(&original_actor_state)
        .expect("seed old actor state");
    store
        .put_desktop_wallet_vault_record("wallet-chain-metadata|22", b"old-encrypted-metadata")
        .expect("seed old vault record");

    let replacement_utxos = [("new-utxo".to_string(), b"new-payload".to_vec())];
    let replacement_meta = WalletMeta {
        last_scanned_block: 90,
        updated_at: 2,
        last_scanned_block_hash: None,
    };
    let replacement_actor_state = WalletSyncActorStateRecord {
        chain_id: namespace.chain_id,
        wallet_id: namespace.wallet_id.to_string(),
        highest_accepted_reset_intent: 5,
        pending_reset: None,
        updated_at: 2,
    };
    let vault_records = [DesktopWalletVaultRecord {
        key: "wallet-chain-metadata|22".to_string(),
        payload: b"new-encrypted-metadata".to_vec(),
    }];
    let result = store.batch_commit_wallet_private_state_with_vault_records_transaction(
        &WalletPrivateStateBatch {
            namespace: &namespace,
            utxos: WalletUtxoRowMutation::Replace(&replacement_utxos),
            metadata: WalletMetaMutation::Set(&replacement_meta),
            sync_actor_state: Some(&replacement_actor_state),
            pending_output_contexts: OpaqueWalletPrivateRowMutation::default(),
            output_poi_recoveries: OpaqueWalletPrivateRowMutation::default(),
        },
        &vault_records,
        || {
            Err(DbError::Io(std::io::Error::other(
                "injected pre-commit failure",
            )))
        },
    );

    assert!(result.is_err());
    let stored_utxos = store
        .list_wallet_utxos(&namespace.wallet_id)
        .expect("list rolled-back UTXOs");
    assert_eq!(stored_utxos.len(), 1);
    assert_eq!(stored_utxos[0].utxo_id, "old-utxo");
    assert_eq!(stored_utxos[0].payload.as_slice(), b"old-payload");
    let stored_meta = store
        .get_wallet_meta(&namespace.wallet_id)
        .expect("load rolled-back metadata")
        .expect("rolled-back metadata present");
    assert_eq!(
        stored_meta.last_scanned_block,
        original_meta.last_scanned_block
    );
    assert_eq!(stored_meta.updated_at, original_meta.updated_at);
    assert_eq!(
        stored_meta.last_scanned_block_hash,
        original_meta.last_scanned_block_hash
    );
    assert_eq!(
        store
            .get_wallet_sync_actor_state(namespace.chain_id, namespace.wallet_id.as_str())
            .expect("load rolled-back actor state"),
        Some(original_actor_state)
    );
    assert_eq!(
        store
            .get_desktop_wallet_vault_record(&vault_records[0].key)
            .expect("load rolled-back vault record"),
        Some(b"old-encrypted-metadata".to_vec())
    );

    drop(store);
    fs::remove_dir_all(root_dir).expect("remove temp db dir");
}

#[test]
fn wallet_deletion_batch_is_atomic_across_namespaces_and_vault_records() {
    let root_dir = temp_db_root();
    let store = DbStore::open(DbConfig {
        root_dir: root_dir.clone(),
    })
    .expect("open db");
    let namespaces = [
        WalletPrivateNamespaceId::new(1, wallet_cache_key(0x71)),
        WalletPrivateNamespaceId::new(137, wallet_cache_key(0x72)),
    ];
    for (index, namespace) in namespaces.iter().enumerate() {
        store
            .put_wallet_utxo(&namespace.wallet_id, "utxo", b"encrypted")
            .expect("store wallet UTXO");
        store
            .put_wallet_meta(
                &namespace.wallet_id,
                &WalletMeta {
                    last_scanned_block: index as u64,
                    updated_at: 10,
                    last_scanned_block_hash: None,
                },
            )
            .expect("store wallet metadata");
        store
            .put_wallet_sync_actor_state(&WalletSyncActorStateRecord {
                chain_id: namespace.chain_id,
                wallet_id: namespace.wallet_id.to_string(),
                highest_accepted_reset_intent: 3,
                pending_reset: None,
                updated_at: 30,
            })
            .expect("store wallet sync actor state");
        store
            .put_pending_output_poi_context(&sample_pending_output_record(
                namespace.chain_id,
                namespace.wallet_id.as_str(),
                FixedBytes::from([0x81 + index as u8; 32]),
            ))
            .expect("store pending output context");
        store
            .put_output_poi_recovery(&sample_output_poi_recovery_record(
                namespace.chain_id,
                namespace.wallet_id.as_str(),
                FixedBytes::from([0x91 + index as u8; 32]),
            ))
            .expect("store output recovery");
    }
    let delete_keys = vec![
        "wallet-meta|delete-a".to_string(),
        "wallet-view|delete-b".to_string(),
    ];
    let put_records = vec![
        ("hardware-reservation|a".to_string(), b"reserved-a".to_vec()),
        ("hardware-reservation|b".to_string(), b"reserved-b".to_vec()),
    ];
    store
        .put_desktop_wallet_vault_records(&[
            (delete_keys[0].clone(), b"metadata".to_vec()),
            (delete_keys[1].clone(), b"view".to_vec()),
            (put_records[0].0.clone(), b"old-reservation".to_vec()),
            ("wallet-meta|other".to_string(), b"other".to_vec()),
        ])
        .expect("seed vault records");
    let batch = WalletDeletionBatch {
        private_namespaces: &namespaces,
        desktop_wallet_vault_delete_keys: &delete_keys,
        desktop_wallet_vault_put_records: &put_records,
    };

    let hook_called = std::cell::Cell::new(false);
    let result = store.delete_wallet_transaction(&batch, || {
        hook_called.set(true);
        Err(DbError::Io(std::io::Error::other(
            "injected wallet deletion failure",
        )))
    });
    assert!(result.is_err());
    assert!(hook_called.get());
    for namespace in &namespaces {
        assert_eq!(
            store
                .list_wallet_utxos(&namespace.wallet_id)
                .expect("list rolled-back wallet UTXOs")
                .len(),
            1
        );
        assert!(
            store
                .get_wallet_meta(&namespace.wallet_id)
                .expect("load rolled-back wallet metadata")
                .is_some()
        );
        assert!(
            store
                .get_wallet_sync_actor_state(namespace.chain_id, namespace.wallet_id.as_str())
                .expect("load rolled-back wallet sync actor state")
                .is_some()
        );
        assert_eq!(
            store
                .list_pending_output_poi_contexts(namespace.chain_id, namespace.wallet_id.as_str(),)
                .expect("list rolled-back pending output contexts")
                .len(),
            1
        );
        assert_eq!(
            store
                .list_output_poi_recoveries(namespace.chain_id, namespace.wallet_id.as_str())
                .expect("list rolled-back output recoveries")
                .len(),
            1
        );
    }
    for key in &delete_keys {
        assert!(
            store
                .get_desktop_wallet_vault_record(key)
                .expect("load rolled-back deleted vault record")
                .is_some()
        );
    }
    assert_eq!(
        store
            .get_desktop_wallet_vault_record(&put_records[0].0)
            .expect("load rolled-back updated vault record")
            .expect("original updated vault record present"),
        b"old-reservation"
    );
    assert!(
        store
            .get_desktop_wallet_vault_record(&put_records[1].0)
            .expect("load rolled-back inserted vault record")
            .is_none()
    );

    assert_eq!(
        store.delete_wallet(&batch).expect("commit wallet deletion"),
        WalletDeletionReport {
            private_namespace_rows: WalletPrivateNamespaceDeletionReport {
                wallet_utxo_rows: 2,
                wallet_meta_rows: 2,
                wallet_sync_actor_state_rows: 2,
                pending_output_poi_context_rows: 2,
                output_poi_recovery_rows: 2,
            },
            desktop_wallet_vault_rows_deleted: 2,
            desktop_wallet_vault_rows_put: 2,
        }
    );
    for namespace in &namespaces {
        assert!(
            store
                .list_wallet_utxos(&namespace.wallet_id)
                .expect("list deleted wallet UTXOs")
                .is_empty()
        );
    }
    for key in &delete_keys {
        assert!(
            store
                .get_desktop_wallet_vault_record(key)
                .expect("load deleted vault record")
                .is_none()
        );
    }
    for (key, payload) in &put_records {
        assert_eq!(
            store
                .get_desktop_wallet_vault_record(key)
                .expect("load put vault record")
                .expect("put vault record present")
                .as_slice(),
            payload.as_slice()
        );
    }
    assert_eq!(
        store
            .get_desktop_wallet_vault_record("wallet-meta|other")
            .expect("load unrelated vault record")
            .expect("unrelated vault record present"),
        b"other"
    );

    drop(store);
    fs::remove_dir_all(root_dir).expect("remove temp db dir");
}

#[test]
fn opaque_wallet_private_v2_rows_are_isolated_by_namespace_and_kind() {
    let root_dir = temp_db_root();
    let store = DbStore::open(DbConfig {
        root_dir: root_dir.clone(),
    })
    .expect("open db");
    let first = WalletPrivateNamespaceId::new(1, wallet_cache_key(0x31));
    let second = WalletPrivateNamespaceId::new(1, wallet_cache_key(0x32));
    let semantic_output_commitment = FixedBytes::from([0xcc; 32]);
    let row = OpaqueWalletPrivateRow {
        row_id: vec![0x10, 0x20, 0x30],
        payload: b"opaque-ciphertext".to_vec(),
    };
    assert_ne!(row.row_id, semantic_output_commitment.as_slice());

    store
        .put_opaque_wallet_private_row(
            &first,
            WalletPrivateRecordKind::PendingOutputPoiContext,
            &row,
        )
        .expect("put first pending row");
    store
        .put_opaque_wallet_private_row(
            &second,
            WalletPrivateRecordKind::PendingOutputPoiContext,
            &OpaqueWalletPrivateRow {
                row_id: row.row_id.clone(),
                payload: b"other-wallet".to_vec(),
            },
        )
        .expect("put second pending row");
    store
        .put_opaque_wallet_private_row(
            &first,
            WalletPrivateRecordKind::OutputPoiRecovery,
            &OpaqueWalletPrivateRow {
                row_id: row.row_id.clone(),
                payload: b"other-kind".to_vec(),
            },
        )
        .expect("put first recovery row");

    assert_eq!(
        store
            .get_opaque_wallet_private_row(
                &first,
                WalletPrivateRecordKind::PendingOutputPoiContext,
                &row.row_id,
            )
            .expect("get first pending row"),
        Some(row.clone())
    );
    assert_eq!(
        store
            .list_opaque_wallet_private_rows(
                &second,
                WalletPrivateRecordKind::PendingOutputPoiContext,
            )
            .expect("list second pending rows")[0]
            .payload,
        b"other-wallet"
    );
    assert_eq!(
        store
            .list_opaque_wallet_private_rows(&first, WalletPrivateRecordKind::OutputPoiRecovery,)
            .expect("list first recovery rows")[0]
            .payload,
        b"other-kind"
    );

    let txn = store.db.begin_read().expect("begin raw v2 read");
    let pending_table = txn
        .open_table(PENDING_OUTPUT_POI_CONTEXT_V2_TABLE)
        .expect("open pending v2 table");
    for entry in pending_table.iter().expect("iterate pending v2 rows") {
        let (key, _) = entry.expect("read pending v2 row");
        assert!(
            !key.value()
                .contains(&alloy::hex::encode(semantic_output_commitment))
        );
    }
    drop(pending_table);
    drop(txn);

    drop(store);
    fs::remove_dir_all(root_dir).expect("remove temp db dir");
}

#[test]
fn opaque_wallet_private_rows_commit_atomically_with_plaintext_state() {
    let root_dir = temp_db_root();
    let store = DbStore::open(DbConfig {
        root_dir: root_dir.clone(),
    })
    .expect("open db");
    let namespace = WalletPrivateNamespaceId::new(1, wallet_cache_key(0x33));
    let meta = WalletMeta {
        last_scanned_block: 55,
        updated_at: 10,
        last_scanned_block_hash: Some([0x44; 32]),
    };
    let actor_state = WalletSyncActorStateRecord {
        chain_id: namespace.chain_id,
        wallet_id: namespace.wallet_id.to_string(),
        highest_accepted_reset_intent: 9,
        pending_reset: None,
        updated_at: 11,
    };
    let pending = [OpaqueWalletPrivateRow {
        row_id: vec![0x01],
        payload: b"pending-ciphertext".to_vec(),
    }];
    let recoveries = [OpaqueWalletPrivateRow {
        row_id: vec![0x02],
        payload: b"recovery-ciphertext".to_vec(),
    }];
    let batch = WalletPrivateStateBatch {
        namespace: &namespace,
        utxos: WalletUtxoRowMutation::Preserve,
        metadata: WalletMetaMutation::Set(&meta),
        sync_actor_state: Some(&actor_state),
        pending_output_contexts: OpaqueWalletPrivateRowMutation {
            updates: &pending,
            deletes: &[],
        },
        output_poi_recoveries: OpaqueWalletPrivateRowMutation {
            updates: &recoveries,
            deletes: &[],
        },
    };

    let result =
        store.batch_commit_wallet_private_state_with_vault_records_transaction(&batch, &[], || {
            Err(DbError::Io(std::io::Error::other("injected failure")))
        });
    assert!(result.is_err());
    assert!(
        store
            .get_wallet_meta(&namespace.wallet_id)
            .expect("load rolled-back metadata")
            .is_none()
    );
    assert!(
        store
            .list_opaque_wallet_private_rows(
                &namespace,
                WalletPrivateRecordKind::PendingOutputPoiContext,
            )
            .expect("list rolled-back pending rows")
            .is_empty()
    );

    store
        .batch_commit_wallet_private_state(&batch)
        .expect("commit private state batch");
    assert_eq!(
        store
            .get_wallet_meta(&namespace.wallet_id)
            .expect("load committed metadata")
            .expect("metadata present")
            .last_scanned_block,
        55
    );
    assert_eq!(
        store
            .get_wallet_sync_actor_state(namespace.chain_id, namespace.wallet_id.as_str())
            .expect("load committed actor state"),
        Some(actor_state)
    );
    assert_eq!(
        store
            .list_opaque_wallet_private_rows(
                &namespace,
                WalletPrivateRecordKind::OutputPoiRecovery,
            )
            .expect("list committed recoveries"),
        recoveries
    );

    drop(store);
    fs::remove_dir_all(root_dir).expect("remove temp db dir");
}

#[test]
fn typed_db_store_pending_and_recovery_records_use_plaintext_v2_encoding() {
    let root_dir = temp_db_root();
    let store = DbStore::open(DbConfig {
        root_dir: root_dir.clone(),
    })
    .expect("open db");
    let namespace = WalletPrivateNamespaceId::new(1, wallet_cache_key(0x34));
    let pending = sample_pending_output_record(
        namespace.chain_id,
        namespace.wallet_id.as_str(),
        FixedBytes::from([0x71; 32]),
    );
    let recovery = sample_output_poi_recovery_record(
        namespace.chain_id,
        namespace.wallet_id.as_str(),
        FixedBytes::from([0x72; 32]),
    );

    store
        .put_pending_output_poi_context(&pending)
        .expect("put typed pending context");
    store
        .put_output_poi_recovery(&recovery)
        .expect("put typed recovery");

    assert_eq!(
        store
            .get_pending_output_poi_context(
                namespace.chain_id,
                namespace.wallet_id.as_str(),
                &pending.output_commitment,
            )
            .expect("get typed pending context")
            .expect("pending context present")
            .output_npk,
        pending.output_npk
    );
    assert_eq!(
        store
            .get_output_poi_recovery(
                namespace.chain_id,
                namespace.wallet_id.as_str(),
                &recovery.output_commitment,
            )
            .expect("get typed recovery")
            .expect("recovery present")
            .source_tx_hash,
        recovery.source_tx_hash
    );
    assert!(
        store
            .list_wallet_private_v1_rows(&namespace)
            .expect("list v1 rows")
            .pending_output_contexts
            .is_empty()
    );
    let opaque_pending = store
        .list_opaque_wallet_private_rows(
            &namespace,
            WalletPrivateRecordKind::PendingOutputPoiContext,
        )
        .expect("list opaque pending rows");
    assert_eq!(
        opaque_pending[0].row_id,
        pending.output_commitment.as_slice()
    );
    assert_eq!(
        decode::<PendingOutputPoiContextRecord>(&opaque_pending[0].payload)
            .expect("decode plaintext DbStore payload")
            .output_commitment,
        pending.output_commitment
    );

    drop(store);
    fs::remove_dir_all(root_dir).expect("remove temp db dir");
}

#[test]
fn typed_db_store_reads_shipped_v1_wallet_private_records() {
    let root_dir = temp_db_root();
    let store = DbStore::open(DbConfig {
        root_dir: root_dir.clone(),
    })
    .expect("open db");
    let namespace = WalletPrivateNamespaceId::new(1, wallet_cache_key(0x37));
    let pending = sample_pending_output_record(
        namespace.chain_id,
        namespace.wallet_id.as_str(),
        FixedBytes::from([0x91; 32]),
    );
    let recovery = sample_output_poi_recovery_record(
        namespace.chain_id,
        namespace.wallet_id.as_str(),
        FixedBytes::from([0x92; 32]),
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

    assert_eq!(
        store
            .get_pending_output_poi_context(
                namespace.chain_id,
                namespace.wallet_id.as_str(),
                &pending.output_commitment,
            )
            .expect("get v1 pending")
            .expect("v1 pending present")
            .output_commitment,
        pending.output_commitment
    );
    let recoveries = store
        .list_output_poi_recoveries(namespace.chain_id, namespace.wallet_id.as_str())
        .expect("list v1 recoveries");
    assert_eq!(recoveries.len(), 1);
    assert_eq!(recoveries[0].output_commitment, recovery.output_commitment);
    assert_eq!(recoveries[0].source_tx_hash, recovery.source_tx_hash);

    drop(store);
    fs::remove_dir_all(root_dir).expect("remove temp db dir");
}

#[test]
fn typed_wallet_private_crud_consumes_shipped_v1_rows() {
    let root_dir = temp_db_root();
    let store = DbStore::open(DbConfig {
        root_dir: root_dir.clone(),
    })
    .expect("open db");
    let namespace = WalletPrivateNamespaceId::new(1, wallet_cache_key(0x38));
    let pending = sample_pending_output_record(
        namespace.chain_id,
        namespace.wallet_id.as_str(),
        FixedBytes::from([0xa1; 32]),
    );
    let recovery = sample_output_poi_recovery_record(
        namespace.chain_id,
        namespace.wallet_id.as_str(),
        FixedBytes::from([0xa2; 32]),
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

    store
        .delete_pending_output_poi_context(
            namespace.chain_id,
            namespace.wallet_id.as_str(),
            &pending.output_commitment,
        )
        .expect("delete v1 pending");
    store
        .delete_output_poi_recovery(
            namespace.chain_id,
            namespace.wallet_id.as_str(),
            &recovery.output_commitment,
        )
        .expect("delete v1 recovery");
    assert!(
        store
            .get_pending_output_poi_context(
                namespace.chain_id,
                namespace.wallet_id.as_str(),
                &pending.output_commitment,
            )
            .expect("read deleted pending")
            .is_none()
    );
    assert!(
        store
            .get_output_poi_recovery(
                namespace.chain_id,
                namespace.wallet_id.as_str(),
                &recovery.output_commitment,
            )
            .expect("read deleted recovery")
            .is_none()
    );
    let v1_rows = store
        .list_wallet_private_v1_rows(&namespace)
        .expect("list remaining v1 rows");
    assert!(v1_rows.pending_output_contexts.is_empty());
    assert!(v1_rows.output_poi_recoveries.is_empty());
    assert!(
        store
            .wallet_private_compaction_requested()
            .expect("read committed compaction marker")
    );

    put_raw_pending_output_record(
        &store,
        &pending.key(),
        &encode(&pending).expect("encode replacement v1 pending"),
    );
    store
        .put_pending_output_poi_context(&pending)
        .expect("put consumes matching v1 pending");
    assert!(
        store
            .list_wallet_private_v1_rows(&namespace)
            .expect("list v1 rows after typed pending put")
            .pending_output_contexts
            .is_empty()
    );
    put_raw_pending_output_record(
        &store,
        &pending.key(),
        &encode(&pending).expect("encode shadow v1 pending"),
    );
    store
        .delete_pending_output_poi_context(
            namespace.chain_id,
            namespace.wallet_id.as_str(),
            &pending.output_commitment,
        )
        .expect("delete both pending versions");
    assert!(
        store
            .get_pending_output_poi_context(
                namespace.chain_id,
                namespace.wallet_id.as_str(),
                &pending.output_commitment,
            )
            .expect("read dual-version deletion")
            .is_none()
    );
    store
        .delete_pending_output_poi_context(
            namespace.chain_id,
            namespace.wallet_id.as_str(),
            &pending.output_commitment,
        )
        .expect("repeat pending deletion");

    put_raw_output_poi_recovery_record(
        &store,
        &recovery.key(),
        &encode(&recovery).expect("encode replacement v1 recovery"),
    );
    store
        .put_output_poi_recovery(&recovery)
        .expect("put consumes matching v1 recovery");
    assert!(
        store
            .list_wallet_private_v1_rows(&namespace)
            .expect("list v1 rows after typed put")
            .output_poi_recoveries
            .is_empty()
    );
    put_raw_output_poi_recovery_record(
        &store,
        &recovery.key(),
        &encode(&recovery).expect("encode shadow v1 recovery"),
    );
    store
        .delete_output_poi_recovery(
            namespace.chain_id,
            namespace.wallet_id.as_str(),
            &recovery.output_commitment,
        )
        .expect("delete both recovery versions");
    assert!(
        store
            .get_output_poi_recovery(
                namespace.chain_id,
                namespace.wallet_id.as_str(),
                &recovery.output_commitment,
            )
            .expect("read dual-version recovery deletion")
            .is_none()
    );
    store
        .delete_output_poi_recovery(
            namespace.chain_id,
            namespace.wallet_id.as_str(),
            &recovery.output_commitment,
        )
        .expect("repeat recovery deletion");

    drop(store);
    fs::remove_dir_all(root_dir).expect("remove temp db dir");
}

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
    assert!(
        store
            .list_opaque_wallet_private_rows(
                &namespace,
                WalletPrivateRecordKind::PendingOutputPoiContext,
            )
            .expect("list rolled-back destinations")
            .is_empty()
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
    assert!(
        store
            .list_wallet_private_v1_rows(&namespace)
            .expect("list consumed v1 rows")
            .pending_output_contexts
            .is_empty()
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
    assert!(
        store
            .list_wallet_private_v1_rows(&legacy)
            .expect("list consumed legacy v1")
            .pending_output_contexts
            .is_empty()
    );
    assert!(
        store
            .list_opaque_wallet_private_rows(&legacy, WalletPrivateRecordKind::OutputPoiRecovery,)
            .expect("list consumed legacy v2")
            .is_empty()
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

#[test]
fn clear_poi_artifact_cache_removes_only_poi_artifact_records() {
    let root_dir = temp_db_root();
    let store = DbStore::open(DbConfig {
        root_dir: root_dir.clone(),
    })
    .expect("open db");

    let record_a = sample_poi_artifact_cache_record(1, FixedBytes::from([0x11; 32]));
    let record_b = sample_poi_artifact_cache_record(137, FixedBytes::from([0x22; 32]));
    store
        .put_poi_artifact_cache(&record_a)
        .expect("store first POI artifact cache");
    store
        .put_poi_artifact_cache(&record_b)
        .expect("store second POI artifact cache");
    store
        .put_app_settings_record("wallet-settings", b"settings-v1")
        .expect("store settings");
    store
        .put_desktop_wallet_vault_record("vault|meta", b"encrypted metadata")
        .expect("store vault metadata");

    let (removed, generation) = store
        .clear_poi_artifact_cache_with_generation()
        .expect("clear POI artifact cache");

    assert_eq!(removed, 2);
    assert_eq!(generation, 1);
    assert_eq!(
        store
            .poi_artifact_cache_generation()
            .expect("load POI artifact cache generation"),
        generation
    );
    assert!(
        store
            .get_poi_artifact_cache(
                record_a.chain_type,
                record_a.chain_id,
                &record_a.txid_version,
                &record_a.list_key,
            )
            .expect("load first cleared POI artifact cache")
            .is_none()
    );
    assert!(
        store
            .get_poi_artifact_cache(
                record_b.chain_type,
                record_b.chain_id,
                &record_b.txid_version,
                &record_b.list_key,
            )
            .expect("load second cleared POI artifact cache")
            .is_none()
    );
    assert_eq!(
        store
            .get_app_settings_record("wallet-settings")
            .expect("load settings after POI cache clear")
            .expect("settings still present"),
        b"settings-v1"
    );
    assert_eq!(
        store
            .get_desktop_wallet_vault_record("vault|meta")
            .expect("load vault metadata after POI cache clear")
            .expect("vault metadata still present"),
        b"encrypted metadata"
    );

    drop(store);
    fs::remove_dir_all(root_dir).expect("remove temp db dir");
}

#[test]
fn desktop_wallet_vault_records_are_isolated_by_prefix() {
    let root_dir = temp_db_root();
    let store = DbStore::open(DbConfig {
        root_dir: root_dir.clone(),
    })
    .expect("open db");

    store
        .put_desktop_wallet_vault_record("vault|meta", b"encrypted metadata")
        .expect("store metadata");
    store
        .put_desktop_wallet_vault_record("wallet-cache|opaque-a|row-1", b"encrypted row 1")
        .expect("store row 1");
    store
        .put_desktop_wallet_vault_record("wallet-cache|opaque-b|row-2", b"encrypted row 2")
        .expect("store row 2");
    let max_prefix_key = format!("{}-vault", char::MAX);
    store
        .put_desktop_wallet_vault_record(&max_prefix_key, b"max-prefix")
        .expect("store max-prefix vault record");

    let meta = store
        .get_desktop_wallet_vault_record("vault|meta")
        .expect("load metadata")
        .expect("metadata present");
    assert_eq!(meta, b"encrypted metadata");

    assert!(
        !store
            .put_desktop_wallet_vault_record_if_absent("vault|meta", b"replacement")
            .expect("skip existing metadata")
    );
    assert_eq!(
        store
            .get_desktop_wallet_vault_record("vault|meta")
            .expect("load unchanged metadata")
            .expect("metadata present"),
        b"encrypted metadata"
    );
    assert!(
        store
            .put_desktop_wallet_vault_record_if_absent("vault|new", b"new metadata")
            .expect("insert missing metadata")
    );
    assert_eq!(
        store
            .get_desktop_wallet_vault_record("vault|new")
            .expect("load inserted metadata")
            .expect("metadata present"),
        b"new metadata"
    );
    assert_eq!(
        store
            .list_desktop_wallet_vault_records("")
            .expect("list all vault records")
            .len(),
        5
    );
    assert_eq!(
        store
            .list_desktop_wallet_vault_records(&char::MAX.to_string())
            .expect("list max-prefix vault records")
            .len(),
        1
    );

    let cache_a = store
        .list_desktop_wallet_vault_records("wallet-cache|opaque-a|")
        .expect("list cache records");
    assert_eq!(cache_a.len(), 1);
    assert_eq!(cache_a[0].key, "wallet-cache|opaque-a|row-1");
    assert_eq!(cache_a[0].payload, b"encrypted row 1");

    store
        .put_desktop_wallet_vault_records(&[
            (
                "wallet-cache|opaque-a|row-3".to_string(),
                b"encrypted row 3".to_vec(),
            ),
            (
                "wallet-chain-meta|opaque-a".to_string(),
                b"metadata".to_vec(),
            ),
        ])
        .expect("batch put cache records");
    let cache_a = store
        .list_desktop_wallet_vault_records("wallet-cache|opaque-a|")
        .expect("list updated cache records");
    assert_eq!(cache_a.len(), 2);
    assert!(
        store
            .get_desktop_wallet_vault_record("wallet-chain-meta|opaque-a")
            .expect("load metadata")
            .is_some()
    );

    store
        .replace_desktop_wallet_vault_prefix_with_records(
            "wallet-cache|opaque-a|",
            &[(
                "wallet-chain-meta|opaque-a".to_string(),
                b"reset-meta".to_vec(),
            )],
        )
        .expect("replace cache prefix");
    assert!(
        store
            .list_desktop_wallet_vault_records("wallet-cache|opaque-a|")
            .expect("list reset cache records")
            .is_empty()
    );
    assert_eq!(
        store
            .get_desktop_wallet_vault_record("wallet-chain-meta|opaque-a")
            .expect("load reset metadata")
            .expect("metadata present"),
        b"reset-meta"
    );

    store
        .delete_desktop_wallet_vault_record("wallet-cache|opaque-a|row-1")
        .expect("delete cache record");
    assert!(
        store
            .get_desktop_wallet_vault_record("wallet-cache|opaque-a|row-1")
            .expect("load deleted cache record")
            .is_none()
    );
    store
        .replace_desktop_wallet_vault_prefix_with_records("", &[])
        .expect("clear all vault records with empty prefix");
    assert!(
        store
            .list_desktop_wallet_vault_records("")
            .expect("list cleared vault records")
            .is_empty()
    );

    drop(store);
    fs::remove_dir_all(root_dir).expect("remove temp db dir");
}

#[test]
fn desktop_wallet_vault_batch_update_rolls_back_as_one_transaction() {
    let root_dir = temp_db_root();
    let store = DbStore::open(DbConfig {
        root_dir: root_dir.clone(),
    })
    .expect("open db");
    let delete_keys = vec![
        "wallet-meta|target".to_string(),
        "wallet-view|target".to_string(),
    ];
    let reservation = vec![(
        "hardware-reservation|target".to_string(),
        b"reserved".to_vec(),
    )];
    store
        .put_desktop_wallet_vault_records(&[
            (delete_keys[0].clone(), b"metadata".to_vec()),
            (delete_keys[1].clone(), b"view".to_vec()),
            ("wallet-meta|other".to_string(), b"other".to_vec()),
        ])
        .expect("seed vault records");

    let result =
        store.update_desktop_wallet_vault_records_transaction(&delete_keys, &reservation, || {
            Err(DbError::Io(std::io::Error::other("injected batch failure")))
        });
    assert!(result.is_err());
    for key in &delete_keys {
        assert!(
            store
                .get_desktop_wallet_vault_record(key)
                .expect("load rolled-back record")
                .is_some()
        );
    }
    assert!(
        store
            .get_desktop_wallet_vault_record(&reservation[0].0)
            .expect("load rolled-back reservation")
            .is_none()
    );

    store
        .update_desktop_wallet_vault_records(&delete_keys, &reservation)
        .expect("commit vault batch update");
    for key in &delete_keys {
        assert!(
            store
                .get_desktop_wallet_vault_record(key)
                .expect("load deleted record")
                .is_none()
        );
    }
    assert_eq!(
        store
            .get_desktop_wallet_vault_record(&reservation[0].0)
            .expect("load committed reservation")
            .expect("reservation present"),
        b"reserved"
    );
    assert_eq!(
        store
            .get_desktop_wallet_vault_record("wallet-meta|other")
            .expect("load preserved other wallet")
            .expect("other wallet present"),
        b"other"
    );

    drop(store);
    fs::remove_dir_all(root_dir).expect("remove temp db dir");
}

#[test]
fn schema_seven_migration_moves_alpha_wallet_cache_rows_atomically() {
    let root_dir = temp_db_root();
    let wallet_id = wallet_cache_key(0x42);
    let row_id = "ab".repeat(32);
    let legacy_key = format!("wallet-cache-row|{wallet_id}|{row_id}");
    let unrelated_key = "wallet-chain-meta|opaque-wallet";
    let payload = b"alpha-6-encrypted-row";
    let pending_output =
        sample_pending_output_record(1, wallet_id.as_str(), FixedBytes::from([0x91; 32]));
    let legacy_pending_key = schema_seven_pending_output_key(&pending_output);
    let pending_payload = encode(&pending_output).expect("encode alpha pending context");

    {
        let store = DbStore::open(DbConfig {
            root_dir: root_dir.clone(),
        })
        .expect("open db");
        store
            .put_desktop_wallet_vault_records(&[
                (legacy_key.clone(), payload.to_vec()),
                (unrelated_key.to_string(), b"encrypted metadata".to_vec()),
            ])
            .expect("store alpha wallet records");
        store
            .put_app_settings_record("wallet-settings", b"settings")
            .expect("store settings");
        put_raw_pending_output_record(&store, &legacy_pending_key, &pending_payload);
        store
            .write_meta(&Meta {
                schema_version: 7,
                app_version: "0.1.0-alpha.6".to_string(),
                created_at: 123,
            })
            .expect("write schema-7 meta");
    }

    let reopened = DbStore::open(DbConfig {
        root_dir: root_dir.clone(),
    })
    .expect("migrate schema-7 db");
    let meta = reopened
        .read_meta()
        .expect("read migrated meta")
        .expect("migrated meta present");
    assert_eq!(meta.schema_version, CURRENT_SCHEMA_VERSION);
    assert_eq!(meta.created_at, 123);
    assert_eq!(
        reopened
            .list_wallet_utxos(&wallet_id)
            .expect("list migrated UTXOs"),
        vec![super::WalletUtxoRecord {
            utxo_id: row_id,
            payload: payload.to_vec(),
        }]
    );
    assert!(
        reopened
            .get_desktop_wallet_vault_record(&legacy_key)
            .expect("load removed legacy row")
            .is_none()
    );
    assert_eq!(
        decode::<PendingOutputPoiContextRecord>(
            &reopened
                .list_wallet_private_v1_rows(&WalletPrivateNamespaceId::new(
                    pending_output.chain_id,
                    wallet_id.clone(),
                ))
                .expect("load migrated pending context")
                .pending_output_contexts[0]
                .payload,
        )
        .expect("decode migrated pending context")
        .wallet_id,
        wallet_id.as_str()
    );
    assert!(!raw_pending_output_record_exists(
        &reopened,
        &legacy_pending_key
    ));
    assert_eq!(
        reopened
            .get_desktop_wallet_vault_record(unrelated_key)
            .expect("load preserved metadata")
            .expect("metadata present"),
        b"encrypted metadata"
    );
    assert_eq!(
        reopened
            .get_app_settings_record("wallet-settings")
            .expect("load preserved settings")
            .expect("settings present"),
        b"settings"
    );
    assert!(
        !fs::read_dir(root_dir.join("railgun"))
            .expect("read railgun dir")
            .any(|entry| entry
                .expect("read dir entry")
                .file_name()
                .to_string_lossy()
                .starts_with("db.redb.bak."))
    );

    drop(reopened);
    let reopened = DbStore::open(DbConfig {
        root_dir: root_dir.clone(),
    })
    .expect("reopen migrated db");
    assert_eq!(
        reopened
            .list_wallet_utxos(&wallet_id)
            .expect("list idempotently migrated UTXOs")
            .len(),
        1
    );
    let namespace = WalletPrivateNamespaceId::new(pending_output.chain_id, wallet_id);
    assert_eq!(
        reopened
            .delete_wallet_private_namespace(&namespace)
            .expect("delete migrated namespace")
            .pending_output_poi_context_rows,
        1
    );
    assert!(!raw_pending_output_record_exists(
        &reopened,
        &legacy_pending_key
    ));
    assert!(!raw_pending_output_record_exists(
        &reopened,
        &pending_output.key()
    ));
    drop(reopened);
    fs::remove_dir_all(root_dir).expect("remove temp db dir");
}

#[test]
fn schema_nine_released_poi_corpus_fixture_preserves_record_and_binds_generation() {
    #[derive(serde::Serialize)]
    struct ReleasedSchemaNinePoiArtifactCacheRecord {
        chain_type: u8,
        chain_id: u64,
        txid_version: String,
        list_key: FixedBytes<32>,
        source: PoiCacheRecordSource,
        validation: PoiCorpusValidationRecord,
        last_accepted_manifest_sequence: u64,
        base_descriptor: PoiArtifactDescriptorRecord,
        applied_delta_descriptors: Vec<PoiArtifactDescriptorRecord>,
        blocked_shields_descriptor: PoiArtifactDescriptorRecord,
        artifact_tip_index: Option<u64>,
        artifact_tip_root: Option<FixedBytes<32>>,
        current_tip_index: u64,
        current_tip_root: FixedBytes<32>,
        cache_payload: Vec<u8>,
        last_successful_rpc_sync_at_ms: Option<u64>,
        updated_at: u64,
    }

    let root_dir = temp_db_root();
    let fixture = sample_poi_artifact_cache_record(1, FixedBytes::from([0xa1; 32]));
    let key = fixture.key();
    let payload = encode(&ReleasedSchemaNinePoiArtifactCacheRecord {
        chain_type: fixture.chain_type,
        chain_id: fixture.chain_id,
        txid_version: fixture.txid_version.clone(),
        list_key: fixture.list_key,
        source: fixture.source,
        validation: fixture.validation.clone(),
        last_accepted_manifest_sequence: fixture.legacy_observed_manifest_sequence,
        base_descriptor: fixture.base_descriptor.clone(),
        applied_delta_descriptors: fixture.applied_delta_descriptors.clone(),
        blocked_shields_descriptor: fixture.blocked_shields_descriptor.clone(),
        artifact_tip_index: fixture.artifact_tip_index,
        artifact_tip_root: fixture.artifact_tip_root,
        current_tip_index: fixture.current_tip_index,
        current_tip_root: fixture.current_tip_root,
        cache_payload: fixture.cache_payload.clone(),
        last_successful_rpc_sync_at_ms: fixture.legacy_last_successful_rpc_sync_at_ms,
        updated_at: fixture.updated_at,
    })
    .expect("encode released schema-9 fixture");
    {
        let store = DbStore::open(DbConfig {
            root_dir: root_dir.clone(),
        })
        .expect("open fixture db");
        put_raw_poi_artifact_record(&store, &key, &payload);
        store
            .put_app_settings_record(
                POI_ARTIFACT_CACHE_GENERATION_KEY,
                &encode(&4_u64).expect("encode generation"),
            )
            .expect("seed generation");
        store
            .write_meta(&Meta {
                schema_version: 9,
                app_version: "0.1.0-alpha.9".to_string(),
                created_at: 321,
            })
            .expect("write schema-9 meta");
    }

    let reopened = DbStore::open(DbConfig {
        root_dir: root_dir.clone(),
    })
    .expect("migrate released schema-9 fixture");
    let migrated = reopened
        .get_poi_artifact_cache(0, 1, "V3_PoseidonMerkle", &fixture.list_key)
        .expect("read migrated corpus")
        .expect("migrated corpus present");
    assert_eq!(migrated.cache_generation, 4);
    assert_eq!(migrated.cache_payload, fixture.cache_payload);
    assert_eq!(
        reopened
            .read_meta()
            .expect("read migrated meta")
            .expect("meta present")
            .schema_version,
        CURRENT_SCHEMA_VERSION
    );

    drop(reopened);
    fs::remove_dir_all(root_dir).expect("remove fixture db");
}

#[test]
fn schema_nine_poi_corpus_migration_rejects_key_conflict_without_mutation() {
    let root_dir = temp_db_root();
    let store = DbStore::open(DbConfig {
        root_dir: root_dir.clone(),
    })
    .expect("open db");
    let record = sample_poi_artifact_cache_record(1, FixedBytes::from([0xa2; 32]));
    let conflicting_key = PoiArtifactCacheRecord::key_for(
        record.chain_type,
        137,
        &record.txid_version,
        &record.list_key,
    );
    let payload = encode(&record).expect("encode conflicting corpus");
    put_raw_poi_artifact_record(&store, &conflicting_key, &payload);
    let schema_nine = Meta {
        schema_version: 9,
        app_version: "0.1.0-alpha.9".to_string(),
        created_at: 322,
    };
    store.write_meta(&schema_nine).expect("write schema-9 meta");

    assert!(matches!(
        store.run_migrations_transaction(&schema_nine, 10, || Ok(())),
        Err(DbError::InvalidSchemaNinePpoiCorpusRecord { key }) if key == conflicting_key
    ));
    assert_eq!(
        store
            .read_meta()
            .expect("read retained meta")
            .expect("meta present")
            .schema_version,
        9
    );
    assert_eq!(
        store
            .db
            .begin_read()
            .expect("begin retained row read")
            .open_table(POI_ARTIFACT_CACHE_TABLE)
            .expect("open POI corpus table")
            .get(conflicting_key.as_str())
            .expect("read retained row")
            .expect("retained row present")
            .value(),
        payload.as_slice()
    );

    drop(store);
    fs::remove_dir_all(root_dir).expect("remove temp db dir");
}

#[test]
fn schema_nine_poi_corpus_migration_rejects_malformed_row_without_mutation() {
    let root_dir = temp_db_root();
    let store = DbStore::open(DbConfig {
        root_dir: root_dir.clone(),
    })
    .expect("open db");
    let key =
        PoiArtifactCacheRecord::key_for(0, 1, "V3_PoseidonMerkle", &FixedBytes::from([0xa3; 32]));
    let payload = b"not-msgpack";
    put_raw_poi_artifact_record(&store, &key, payload);
    let schema_nine = Meta {
        schema_version: 9,
        app_version: "0.1.0-alpha.9".to_string(),
        created_at: 323,
    };
    store.write_meta(&schema_nine).expect("write schema-9 meta");

    assert!(matches!(
        store.run_migrations_transaction(&schema_nine, 10, || Ok(())),
        Err(DbError::InvalidSchemaNinePpoiCorpusRecord { key: invalid }) if invalid == key
    ));
    assert_eq!(
        store
            .read_meta()
            .expect("read retained meta")
            .expect("meta present")
            .schema_version,
        9
    );
    assert_eq!(
        store
            .db
            .begin_read()
            .expect("begin retained row read")
            .open_table(POI_ARTIFACT_CACHE_TABLE)
            .expect("open POI corpus table")
            .get(key.as_str())
            .expect("read retained row")
            .expect("retained row present")
            .value(),
        payload
    );

    drop(store);
    fs::remove_dir_all(root_dir).expect("remove temp db dir");
}

#[test]
fn schema_eight_to_current_preserves_existing_rows() {
    let root_dir = temp_db_root();
    let store = DbStore::open(DbConfig {
        root_dir: root_dir.clone(),
    })
    .expect("open store");
    store
        .put_app_settings_record("schema-nine-sentinel", b"preserved")
        .expect("write sentinel");
    store
        .write_meta(&Meta {
            schema_version: 8,
            app_version: "pre-canonicalization".to_string(),
            created_at: 123,
        })
        .expect("write schema-eight metadata");
    drop(store);

    let reopened = DbStore::open(DbConfig {
        root_dir: root_dir.clone(),
    })
    .expect("migrate schema eight to current");
    assert_eq!(
        reopened
            .read_meta()
            .expect("read metadata")
            .expect("metadata present")
            .schema_version,
        CURRENT_SCHEMA_VERSION
    );
    assert_eq!(
        reopened
            .get_app_settings_record("schema-nine-sentinel")
            .expect("read sentinel")
            .expect("sentinel present"),
        b"preserved"
    );

    drop(reopened);
    fs::remove_dir_all(root_dir).expect("remove temp db dir");
}

#[test]
fn schema_seven_migration_failure_rolls_back_rows_and_version() {
    let root_dir = temp_db_root();
    let wallet_id = wallet_cache_key(0x43);
    let row_id = "cd".repeat(32);
    let legacy_key = format!("wallet-cache-row|{wallet_id}|{row_id}");
    let pending_output =
        sample_pending_output_record(1, wallet_id.as_str(), FixedBytes::from([0x92; 32]));
    let legacy_pending_key = schema_seven_pending_output_key(&pending_output);
    let store = DbStore::open(DbConfig {
        root_dir: root_dir.clone(),
    })
    .expect("open db");
    store
        .put_desktop_wallet_vault_records(&[(legacy_key.clone(), b"encrypted".to_vec())])
        .expect("store alpha wallet row");
    put_raw_pending_output_record(
        &store,
        &legacy_pending_key,
        &encode(&pending_output).expect("encode alpha pending context"),
    );
    let schema_seven = Meta {
        schema_version: 7,
        app_version: "0.1.0-alpha.6".to_string(),
        created_at: 123,
    };
    store
        .write_meta(&schema_seven)
        .expect("write schema-7 meta");

    let result = store.run_migrations_transaction(&schema_seven, 8, || {
        Err(DbError::Io(std::io::Error::other(
            "injected migration failure",
        )))
    });
    assert!(result.is_err());
    assert_eq!(
        store
            .read_meta()
            .expect("read rolled-back meta")
            .expect("meta present")
            .schema_version,
        7
    );
    assert_eq!(
        store
            .get_desktop_wallet_vault_record(&legacy_key)
            .expect("load rolled-back legacy row")
            .expect("legacy row present"),
        b"encrypted"
    );
    assert!(
        store
            .list_wallet_utxos(&wallet_id)
            .expect("list rolled-back target rows")
            .is_empty()
    );
    assert!(raw_pending_output_record_exists(
        &store,
        &legacy_pending_key
    ));
    assert!(!raw_pending_output_record_exists(
        &store,
        &pending_output.key()
    ));

    drop(store);
    fs::remove_dir_all(root_dir).expect("remove temp db dir");
}

#[test]
fn schema_seven_migration_rejects_malformed_pending_context_without_mutation() {
    let root_dir = temp_db_root();
    let store = DbStore::open(DbConfig {
        root_dir: root_dir.clone(),
    })
    .expect("open db");
    let malformed_key = format!("1|{}", "ab".repeat(32));
    put_raw_pending_output_record(&store, &malformed_key, b"not-msgpack");
    let schema_seven = Meta {
        schema_version: 7,
        app_version: "0.1.0-alpha.6".to_string(),
        created_at: 123,
    };
    store
        .write_meta(&schema_seven)
        .expect("write schema-7 meta");

    assert!(matches!(
        store.run_migrations_transaction(&schema_seven, 8, || Ok(())),
        Err(DbError::InvalidSchemaSevenPendingOutputPoiContext { .. })
    ));
    assert_eq!(
        store
            .read_meta()
            .expect("read retained meta")
            .expect("meta present")
            .schema_version,
        7
    );
    assert!(raw_pending_output_record_exists(&store, &malformed_key));

    drop(store);
    fs::remove_dir_all(root_dir).expect("remove temp db dir");
}

#[test]
fn schema_seven_migration_rejects_incomplete_pending_context_without_mutation() {
    #[derive(serde::Serialize)]
    struct IdentityOnlyPendingOutputContext {
        chain_id: u64,
        wallet_id: String,
        output_commitment: FixedBytes<32>,
    }

    let root_dir = temp_db_root();
    let store = DbStore::open(DbConfig {
        root_dir: root_dir.clone(),
    })
    .expect("open db");
    let wallet_id = WalletCacheKey::from_opaque_bytes(b"incomplete-pending-wallet")
        .expect("incomplete pending wallet key");
    let identity = IdentityOnlyPendingOutputContext {
        chain_id: 1,
        wallet_id: wallet_id.to_string(),
        output_commitment: FixedBytes::from([0x93; 32]),
    };
    let legacy_key = format!(
        "{}|{}",
        identity.chain_id,
        alloy::hex::encode(identity.output_commitment)
    );
    let canonical_key = PendingOutputPoiContextRecord::key_for(
        identity.chain_id,
        wallet_id.as_str(),
        &identity.output_commitment,
    );
    let payload = encode(&identity).expect("encode incomplete pending context");
    put_raw_pending_output_record(&store, &legacy_key, &payload);
    let schema_seven = Meta {
        schema_version: 7,
        app_version: "0.1.0-alpha.6".to_string(),
        created_at: 123,
    };
    store
        .write_meta(&schema_seven)
        .expect("write schema-7 meta");

    assert!(matches!(
        store.run_migrations_transaction(&schema_seven, 8, || Ok(())),
        Err(DbError::InvalidSchemaSevenPendingOutputPoiContext { .. })
    ));
    assert_eq!(
        store
            .read_meta()
            .expect("read retained meta")
            .expect("meta present")
            .schema_version,
        7
    );
    assert_eq!(
        store
            .db
            .begin_read()
            .expect("begin retained row read")
            .open_table(PENDING_OUTPUT_POI_CONTEXT_TABLE)
            .expect("open pending table")
            .get(legacy_key.as_str())
            .expect("read retained source row")
            .expect("source row present")
            .value(),
        payload.as_slice()
    );
    assert!(!raw_pending_output_record_exists(&store, &canonical_key));

    drop(store);
    fs::remove_dir_all(root_dir).expect("remove temp db dir");
}

#[test]
fn schema_seven_migration_rejects_malformed_cache_rows_without_mutation() {
    let root_dir = temp_db_root();
    let malformed_key = format!("wallet-cache-row|not-hex|{}", "ab".repeat(32));
    let store = DbStore::open(DbConfig {
        root_dir: root_dir.clone(),
    })
    .expect("open db");
    store
        .put_desktop_wallet_vault_records(&[(malformed_key.clone(), b"encrypted".to_vec())])
        .expect("store malformed alpha wallet row");
    let schema_seven = Meta {
        schema_version: 7,
        app_version: "0.1.0-alpha.6".to_string(),
        created_at: 123,
    };
    store
        .write_meta(&schema_seven)
        .expect("write schema-7 meta");

    assert!(matches!(
        store.run_migrations_transaction(&schema_seven, 8, || Ok(())),
        Err(DbError::InvalidLegacyDesktopWalletCacheRowKey { .. })
    ));
    assert_eq!(
        store
            .read_meta()
            .expect("read unchanged meta")
            .expect("meta present")
            .schema_version,
        7
    );
    assert_eq!(
        store
            .get_desktop_wallet_vault_record(&malformed_key)
            .expect("load preserved malformed row")
            .expect("malformed row present"),
        b"encrypted"
    );

    drop(store);
    fs::remove_dir_all(root_dir).expect("remove temp db dir");
}

#[test]
fn opening_schema_seven_malformed_cache_fixture_preserves_table_set_and_rows() {
    let root_dir = temp_db_root();
    let railgun_dir = root_dir.join("railgun");
    fs::create_dir_all(&railgun_dir).expect("create alpha railgun dir");
    let database_path = railgun_dir.join("db.redb");
    let wallet_id = wallet_cache_key(0x44);
    let row_id = "ef".repeat(32);
    let valid_key = format!("wallet-cache-row|{wallet_id}|{row_id}");
    let malformed_key = format!("wallet-cache-row|not-hex|{}", "ab".repeat(32));
    let valid_payload = b"alpha-encrypted-row";
    let malformed_payload = b"malformed-key-payload";
    let schema_seven_meta = encode(&Meta {
        schema_version: 7,
        app_version: "0.1.0-alpha.6".to_string(),
        created_at: 123,
    })
    .expect("encode schema-7 meta");

    let db = Database::create(&database_path).expect("create alpha database");
    let txn = db.begin_write().expect("begin alpha fixture write");
    txn.open_table(META_TABLE).expect("create alpha meta table");
    txn.open_table(BLOB_INDEX_TABLE)
        .expect("create alpha blob table");
    txn.open_table(MERKLE_FOREST_INDEX_TABLE)
        .expect("create alpha Merkle table");
    txn.open_table(ZKEY_INDEX_TABLE)
        .expect("create alpha zkey table");
    txn.open_table(WALLET_UTXO_TABLE)
        .expect("create alpha UTXO table");
    txn.open_table(WALLET_META_TABLE)
        .expect("create alpha wallet meta table");
    txn.open_table(PENDING_FEE_NOTE_ASSURANCE_TABLE)
        .expect("create alpha pending assurance table");
    txn.open_table(TERMINAL_FEE_NOTE_ASSURANCE_TABLE)
        .expect("create alpha terminal assurance table");
    txn.open_table(PENDING_OUTPUT_POI_CONTEXT_TABLE)
        .expect("create alpha pending output table");
    txn.open_table(OUTPUT_POI_RECOVERY_TABLE)
        .expect("create alpha output recovery table");
    txn.open_table(POI_ARTIFACT_CACHE_TABLE)
        .expect("create alpha POI cache table");
    txn.open_table(APP_SETTINGS_TABLE)
        .expect("create alpha settings table");
    {
        let mut table = txn
            .open_table(DESKTOP_WALLET_VAULT_TABLE)
            .expect("create alpha vault table");
        table
            .insert(valid_key.as_str(), valid_payload.as_slice())
            .expect("insert valid alpha row");
        table
            .insert(malformed_key.as_str(), malformed_payload.as_slice())
            .expect("insert malformed alpha row");
    }
    {
        let mut table = txn.open_table(META_TABLE).expect("open alpha meta table");
        table
            .insert("meta", schema_seven_meta.as_slice())
            .expect("insert schema-7 meta");
    }
    txn.commit().expect("commit alpha fixture");

    let read_txn = db.begin_read().expect("begin alpha table read");
    let tables_before = read_txn
        .list_tables()
        .expect("list alpha tables")
        .map(|table| table.name().to_string())
        .collect::<BTreeSet<_>>();
    assert!(!tables_before.contains(WALLET_SYNC_ACTOR_STATE_TABLE.name()));
    drop(read_txn);
    drop(db);

    assert!(matches!(
        DbStore::open(DbConfig {
            root_dir: root_dir.clone(),
        }),
        Err(DbError::InvalidLegacyDesktopWalletCacheRowKey { .. })
    ));

    let db = Database::open(&database_path).expect("reopen failed alpha migration");
    let read_txn = db.begin_read().expect("begin retained fixture read");
    let tables_after = read_txn
        .list_tables()
        .expect("list retained tables")
        .map(|table| table.name().to_string())
        .collect::<BTreeSet<_>>();
    assert_eq!(tables_after, tables_before);
    assert!(!tables_after.contains(WALLET_SYNC_ACTOR_STATE_TABLE.name()));
    {
        let table = read_txn.open_table(META_TABLE).expect("open retained meta");
        assert_eq!(
            table
                .get("meta")
                .expect("read retained meta")
                .expect("retained meta present")
                .value(),
            schema_seven_meta.as_slice()
        );
    }
    {
        let table = read_txn
            .open_table(DESKTOP_WALLET_VAULT_TABLE)
            .expect("open retained vault");
        assert_eq!(
            table
                .get(valid_key.as_str())
                .expect("read retained valid row")
                .expect("retained valid row present")
                .value(),
            valid_payload
        );
        assert_eq!(
            table
                .get(malformed_key.as_str())
                .expect("read retained malformed row")
                .expect("retained malformed row present")
                .value(),
            malformed_payload
        );
    }
    assert!(
        read_txn
            .open_table(WALLET_UTXO_TABLE)
            .expect("open retained UTXO table")
            .is_empty()
            .expect("read retained UTXO table")
    );

    drop(read_txn);
    let txn = db.begin_write().expect("begin fixture repair");
    {
        let mut table = txn
            .open_table(DESKTOP_WALLET_VAULT_TABLE)
            .expect("open fixture vault");
        table
            .remove(malformed_key.as_str())
            .expect("remove malformed fixture row");
    }
    txn.commit().expect("commit fixture repair");
    drop(db);

    let store = DbStore::open(DbConfig {
        root_dir: root_dir.clone(),
    })
    .expect("migrate repaired alpha fixture");
    let read_txn = store.db.begin_read().expect("begin migrated table read");
    let migrated_tables = read_txn
        .list_tables()
        .expect("list migrated tables")
        .map(|table| table.name().to_string())
        .collect::<BTreeSet<_>>();
    let mut expected_tables = tables_before;
    expected_tables.insert(WALLET_SYNC_ACTOR_STATE_TABLE.name().to_string());
    expected_tables.insert(PENDING_OUTPUT_POI_CONTEXT_V2_TABLE.name().to_string());
    expected_tables.insert(OUTPUT_POI_RECOVERY_V2_TABLE.name().to_string());
    assert_eq!(migrated_tables, expected_tables);
    drop(read_txn);
    assert_eq!(
        store
            .read_meta()
            .expect("read migrated meta")
            .expect("migrated meta present")
            .schema_version,
        CURRENT_SCHEMA_VERSION
    );
    assert_eq!(
        store
            .list_wallet_utxos(&wallet_id)
            .expect("list migrated fixture rows"),
        vec![super::WalletUtxoRecord {
            utxo_id: row_id,
            payload: valid_payload.to_vec(),
        }]
    );
    assert!(
        store
            .get_desktop_wallet_vault_record(&valid_key)
            .expect("load migrated source row")
            .is_none()
    );

    drop(store);
    fs::remove_dir_all(root_dir).expect("remove temp db dir");
}

#[test]
fn reopen_older_schema_db_backs_up_and_recreates() {
    let root_dir = temp_db_root();
    let wallet_id = wallet_cache_key(0x51);

    {
        let store = DbStore::open(DbConfig {
            root_dir: root_dir.clone(),
        })
        .expect("open db");

        let wallet_meta = WalletMeta {
            last_scanned_block: 42,
            updated_at: 99,
            last_scanned_block_hash: Some([7u8; 32]),
        };
        store
            .put_wallet_meta(&wallet_id, &wallet_meta)
            .expect("write wallet meta");

        store
            .write_meta(&Meta {
                schema_version: 3,
                app_version: "0.0.0".to_string(),
                created_at: 123,
            })
            .expect("write schema-3 meta");
    }

    let reopened = DbStore::open(DbConfig {
        root_dir: root_dir.clone(),
    })
    .expect("reopen db");

    assert!(
        reopened
            .get_wallet_meta(&wallet_id)
            .expect("load wallet meta")
            .is_none()
    );

    let meta = reopened
        .read_meta()
        .expect("read meta")
        .expect("meta present");
    assert_eq!(meta.schema_version, CURRENT_SCHEMA_VERSION);
    assert!(
        fs::read_dir(root_dir.join("railgun"))
            .expect("read railgun dir")
            .any(|entry| entry
                .expect("read dir entry")
                .file_name()
                .to_string_lossy()
                .starts_with("db.redb.bak."))
    );

    drop(reopened);
    fs::remove_dir_all(root_dir).expect("remove temp db dir");
}
