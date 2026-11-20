use super::{
    AppTable, AppTableWriter, BLOB_INDEX_TABLE, ByteTableDefinition, CURRENT_SCHEMA_VERSION,
    CanonicalBlobMetaIdentity, DbConfig, DbError, DbStore, ExpectedPoiCorpusJournalState,
    MERKLE_FOREST_INDEX_TABLE, META_KEY, META_TABLE, Meta, OUTPUT_POI_RECOVERY_TABLE,
    OUTPUT_POI_RECOVERY_V2_TABLE, OpaqueWalletPrivateRow, OpaqueWalletPrivateRowMutation,
    OutputPoiRecoveryRecord, OutputPoiRecoveryStatus, PENDING_OUTPUT_POI_CONTEXT_TABLE,
    PENDING_OUTPUT_POI_CONTEXT_V2_TABLE, POI_ARTIFACT_CACHE_GENERATION_KEY,
    POI_ARTIFACT_CACHE_TABLE, POI_CORPUS_JOURNAL_FORMAT_VERSION,
    POI_CORPUS_JOURNAL_MAX_PAYLOAD_BYTES, POI_CORPUS_JOURNAL_TABLE, POI_SIDECAR_STATE_TABLE,
    PendingOutputPoiContextRecord, PendingOutputPoiRole, PoiArtifactCacheRecord,
    PoiArtifactDescriptorRecord, PoiCacheRecordSource, PoiCorpusBlockedSnapshotRecord,
    PoiCorpusJournalCommitCondition, PoiCorpusJournalCommitOutcome, PoiCorpusJournalDeltaRecord,
    PoiCorpusJournalHeadRecord, PoiCorpusJournalInspection, PoiCorpusRpcHealthRecord,
    PoiCorpusValidationRecord, PoiPublisherManifestObservation,
    PoiPublisherManifestWatermarkRecord, SENDER_TRANSACTION_CANDIDATE_V1_TABLE, StoredRecord,
    WALLET_META_TABLE, WALLET_SYNC_ACTOR_STATE_TABLE, WALLET_UTXO_TABLE, WalletCacheKey,
    WalletMeta, WalletMetaMutation, WalletPendingResetRecord, WalletPrivateCanonicalizationBatch,
    WalletPrivateCanonicalizationKindBatch, WalletPrivateCanonicalizationReport,
    WalletPrivateNamespaceDeletionReport, WalletPrivateNamespaceId, WalletPrivateRecordKind,
    WalletPrivateStateBatch, WalletPrivateV1MigrationBatch, WalletPrivateV1MigrationReport,
    WalletSyncActorStateRecord, WalletUtxoRowMutation, ZKEY_INDEX_TABLE, decode, encode,
};
use alloy::primitives::{Address, Bytes, FixedBytes, U256, keccak256};
use alloy::uint;
use broadcaster_core::transact::{PreTxPoi, SnarkJsProof};
use redb::{
    Database, ReadableDatabase, ReadableTable, ReadableTableMetadata, TableDefinition, TableHandle,
};
use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

// Application tables that existing databases still carry; `local-db` no longer owns them.
const APP_SETTINGS: AppTable = AppTable::new("app_settings_v1");
const DESKTOP_WALLET_VAULT: AppTable = AppTable::new("desktop_wallet_vault_v1");
const RAW_APP_SETTINGS_TABLE: ByteTableDefinition = TableDefinition::new("app_settings_v1");
const RAW_DESKTOP_WALLET_VAULT_TABLE: ByteTableDefinition =
    TableDefinition::new("desktop_wallet_vault_v1");
const RAW_PENDING_FEE_NOTE_ASSURANCE_TABLE: ByteTableDefinition =
    TableDefinition::new("fee_note_assurance_pending");
const RAW_TERMINAL_FEE_NOTE_ASSURANCE_TABLE: ByteTableDefinition =
    TableDefinition::new("fee_note_assurance_terminal");
/// The tables of a schema-10 database. Schema 11 adds `sender_transaction_candidate_v1`.
const SCHEMA_TEN_TABLES: [ByteTableDefinition; 17] = [
    META_TABLE,
    BLOB_INDEX_TABLE,
    MERKLE_FOREST_INDEX_TABLE,
    ZKEY_INDEX_TABLE,
    WALLET_UTXO_TABLE,
    WALLET_META_TABLE,
    WALLET_SYNC_ACTOR_STATE_TABLE,
    RAW_PENDING_FEE_NOTE_ASSURANCE_TABLE,
    RAW_TERMINAL_FEE_NOTE_ASSURANCE_TABLE,
    PENDING_OUTPUT_POI_CONTEXT_TABLE,
    OUTPUT_POI_RECOVERY_TABLE,
    PENDING_OUTPUT_POI_CONTEXT_V2_TABLE,
    OUTPUT_POI_RECOVERY_V2_TABLE,
    POI_ARTIFACT_CACHE_TABLE,
    POI_CORPUS_JOURNAL_TABLE,
    RAW_APP_SETTINGS_TABLE,
    RAW_DESKTOP_WALLET_VAULT_TABLE,
];

static TEMP_DB_COUNTER: AtomicU64 = AtomicU64::new(0);

fn put_app_row(store: &DbStore, table: AppTable, key: &str, value: &[u8]) {
    store
        .write_app_tables(|tables| tables.insert(table, key, value))
        .expect("write app table row");
}

fn get_app_row(store: &DbStore, table: AppTable, key: &str) -> Option<Vec<u8>> {
    store
        .read_app_tables(|tables| tables.get(table, key))
        .expect("read app table row")
}

fn wallet_cache_key(byte: u8) -> WalletCacheKey {
    WalletCacheKey::from_opaque_id([byte; 16])
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

fn put_raw_wallet_meta(store: &DbStore, key: &str, payload: &[u8]) {
    let txn = store.db.begin_write().expect("begin raw wallet meta write");
    {
        let mut table = txn
            .open_table(WALLET_META_TABLE)
            .expect("open wallet meta table");
        table
            .insert(key, payload)
            .expect("insert raw wallet meta row");
    }
    txn.commit().expect("commit raw wallet meta write");
}

fn put_raw_wallet_utxo(store: &DbStore, key: &str, payload: &[u8]) {
    let txn = store.db.begin_write().expect("begin raw wallet UTXO write");
    {
        let mut table = txn
            .open_table(WALLET_UTXO_TABLE)
            .expect("open wallet UTXO table");
        table
            .insert(key, payload)
            .expect("insert raw wallet UTXO row");
    }
    txn.commit().expect("commit raw wallet UTXO write");
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

fn sample_journal_head(
    base: &PoiArtifactCacheRecord,
    event_cursor: u64,
    leaf_cursor: u64,
    current_tip_root: FixedBytes<32>,
) -> PoiCorpusJournalHeadRecord {
    let mut corpus = base.clone();
    corpus.current_tip_index = event_cursor.saturating_sub(1);
    corpus.current_tip_root = current_tip_root;
    corpus.cache_payload.clear();
    PoiCorpusJournalHeadRecord {
        format_version: POI_CORPUS_JOURNAL_FORMAT_VERSION,
        revision: 0,
        base_revision: 0,
        base_payload_hash: FixedBytes::ZERO,
        event_cursor,
        leaf_cursor,
        blocked_revision: None,
        blocked_payload_hash: None,
        delta_count: 0,
        delta_payload_bytes: 0,
        corpus,
    }
}

fn sample_journal_delta(
    base: &PoiArtifactCacheRecord,
    event_start_cursor: u64,
    event_end_cursor: u64,
    start_tip_root: FixedBytes<32>,
    end_tip_root: FixedBytes<32>,
) -> PoiCorpusJournalDeltaRecord {
    PoiCorpusJournalDeltaRecord {
        format_version: 0,
        chain_type: base.chain_type,
        chain_id: base.chain_id,
        txid_version: base.txid_version.clone(),
        list_key: base.list_key,
        cache_generation: 0,
        revision: 0,
        previous_revision: 0,
        base_revision: 0,
        event_start_cursor,
        event_end_cursor,
        leaf_start_cursor: event_start_cursor,
        leaf_end_cursor: event_end_cursor,
        start_tip_root,
        end_tip_root,
        payload: vec![0x81, 0x82, 0x83],
        updated_at: 0,
    }
}

fn implicit_journal_condition(base: &PoiArtifactCacheRecord) -> PoiCorpusJournalCommitCondition {
    PoiCorpusJournalCommitCondition {
        expected_generation: base.cache_generation,
        expected_publisher: None,
        expected_manifest_hash: None,
        expected_state: ExpectedPoiCorpusJournalState::ImplicitBase {
            base_payload_hash: keccak256(&base.cache_payload),
            event_cursor: base.current_tip_index.saturating_add(1),
            leaf_cursor: base.current_tip_index.saturating_add(1),
            current_tip_root: base.current_tip_root,
        },
    }
}

fn explicit_journal_condition(
    head: &PoiCorpusJournalHeadRecord,
) -> PoiCorpusJournalCommitCondition {
    PoiCorpusJournalCommitCondition {
        expected_generation: head.corpus.cache_generation,
        expected_publisher: None,
        expected_manifest_hash: None,
        expected_state: ExpectedPoiCorpusJournalState::Head {
            revision: head.revision,
            base_revision: head.base_revision,
            base_payload_hash: head.base_payload_hash,
            event_cursor: head.event_cursor,
            leaf_cursor: head.leaf_cursor,
            current_tip_root: head.corpus.current_tip_root,
        },
    }
}

fn insert_raw_poi_journal_row(store: &DbStore, key: &str, payload: &[u8]) {
    let txn = store.db.begin_write().expect("start raw journal write");
    {
        let mut table = txn
            .open_table(POI_CORPUS_JOURNAL_TABLE)
            .expect("open POI journal table");
        table
            .insert(key, payload)
            .expect("insert raw POI journal row");
    }
    txn.commit().expect("commit raw POI journal write");
}

fn remove_raw_poi_journal_row(store: &DbStore, key: &str) {
    let txn = store.db.begin_write().expect("start raw journal delete");
    {
        let mut table = txn
            .open_table(POI_CORPUS_JOURNAL_TABLE)
            .expect("open POI journal table");
        table.remove(key).expect("remove raw POI journal row");
    }
    txn.commit().expect("commit raw POI journal delete");
}

mod app_tables_and_vault;
mod opaque_and_typed_store;
mod paths_and_locks;
mod poi_corpus_inspection;
mod poi_corpus_journal;
mod poi_records;
mod schema_nine_and_failures;
mod schema_reopen_and_sidecars;
mod schema_seven_and_eleven;
mod typed_wallet_private_v1;
mod wallet_private_state;
