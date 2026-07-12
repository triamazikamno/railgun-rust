use super::{
    APP_SETTINGS_TABLE, BLOB_INDEX_TABLE, CURRENT_SCHEMA_VERSION, DESKTOP_WALLET_VAULT_TABLE,
    DbConfig, DbError, DbStore, MERKLE_FOREST_INDEX_TABLE, META_TABLE, Meta,
    OUTPUT_POI_RECOVERY_TABLE, OutputPoiRecoveryRecord, OutputPoiRecoveryStatus,
    PENDING_FEE_NOTE_ASSURANCE_TABLE, PENDING_OUTPUT_POI_CONTEXT_TABLE, POI_ARTIFACT_CACHE_TABLE,
    PendingFeeNoteAssuranceRecord, PendingOutputPoiContextRecord, PendingOutputPoiRole,
    PoiArtifactCacheRecord, PoiArtifactDescriptorRecord, PoiCacheRecordSource,
    PoiCorpusRpcHealthRecord, PoiCorpusValidationRecord, PoiPublisherManifestWatermarkRecord,
    StoredRecord, TERMINAL_FEE_NOTE_ASSURANCE_TABLE, WALLET_META_TABLE,
    WALLET_SYNC_ACTOR_STATE_TABLE, WALLET_UTXO_TABLE, WalletCacheKey, WalletMeta,
    WalletPendingResetRecord, WalletPrivateNamespaceDeletionReport, WalletPrivateNamespaceId,
    WalletSyncActorStateRecord, ZKEY_INDEX_TABLE, decode, encode,
};
use alloy::primitives::{Address, Bytes, FixedBytes, U256};
use alloy::uint;
use broadcaster_core::transact::{FeeNoteAssuranceContext, PreTxPoi, SnarkJsProof};
use redb::{Database, ReadableDatabase, ReadableTableMetadata, TableHandle};
use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::PathBuf;
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

fn raw_pending_output_record_exists(store: &DbStore, key: &str) -> bool {
    let txn = store.db.begin_read().expect("begin raw pending read");
    let table = txn
        .open_table(PENDING_OUTPUT_POI_CONTEXT_TABLE)
        .expect("open pending table");
    table.get(key).expect("read raw pending row").is_some()
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
    assert_eq!(decoded.legacy_observed_manifest_sequence, 7);
    assert_eq!(decoded.artifact_tip_index, None);
    assert_eq!(decoded.artifact_tip_root, None);
    assert_eq!(decoded.legacy_last_successful_rpc_sync_at_ms, Some(42));
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
            .list_pending_output_poi_contexts(record.chain_id, "other-wallet")
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
        updated_at: u64::MAX,
    };
    let second = PoiPublisherManifestWatermarkRecord {
        publisher_pubkey: FixedBytes::from([0x22; 32]),
        accepted_sequence: 9,
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
            pending_output_poi_context_rows: 2,
            output_poi_recovery_rows: 1,
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
        reopened
            .get_pending_output_poi_context(
                pending_output.chain_id,
                wallet_id.as_str(),
                &pending_output.output_commitment,
            )
            .expect("load migrated pending context")
            .expect("migrated pending context present")
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
