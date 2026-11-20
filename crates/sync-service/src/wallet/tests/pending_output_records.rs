use super::*;

pub(super) fn sample_pre_tx_poi(_byte: u8) -> PreTxPoi {
    current_poi_fixture("ppoi_3x3").pre_tx_poi
}

#[derive(serde::Deserialize)]
pub(super) struct CurrentPoiFixture {
    pub(super) pre_tx_poi: PreTxPoi,
    pub(super) public_context: CurrentPoiPublicContext,
}

#[derive(serde::Deserialize)]
pub(super) struct CurrentPoiPublicContext {
    pub(super) commitments_out: Vec<U256>,
    pub(super) output_npks: Vec<U256>,
    pub(super) output_values: Vec<U256>,
    pub(super) output_start_global: U256,
    pub(super) railgun_txid: U256,
    pub(super) input_tree: u64,
}

pub(super) fn current_poi_fixture(name: &str) -> CurrentPoiFixture {
    let bytes: &[u8] = match name {
        "ppoi_3x3" => include_bytes!("../../../../core/tests/fixtures/ppoi_3x3.json"),
        "ppoi_3x3_two_outputs" => {
            include_bytes!("../../../../core/tests/fixtures/ppoi_3x3_two_outputs.json")
        }
        _ => panic!("unknown PPOI test fixture"),
    };
    serde_json::from_slice(bytes).expect("current proof fixture")
}

pub(super) fn previous_key_pending_context(
    context: &PendingOutputPoiContextRecord,
) -> PendingOutputPoiContextRecord {
    let fixture: CurrentPoiFixture = serde_json::from_slice(include_bytes!(
        "../../../../core/tests/fixtures/ppoi_3x3_previous.json"
    ))
    .expect("previous-key proof fixture");
    let mut old = context.clone();
    for per_leaf in old.pre_transaction_pois_per_txid_leaf_per_list.values_mut() {
        for poi in per_leaf.values_mut() {
            *poi = fixture.pre_tx_poi.clone();
        }
    }
    old
}

pub(super) fn pending_output_record(
    chain_id: u64,
    output_commitment: FixedBytes<32>,
    list_key: FixedBytes<32>,
) -> PendingOutputPoiContextRecord {
    let txid_leaf = FixedBytes::from([0x55; 32]);
    PendingOutputPoiContextRecord {
        chain_id,
        wallet_id: test_cache_key("wallet-1").to_string(),
        txid_version: DEFAULT_TXID_VERSION.to_string(),
        output_commitment,
        output_npk: FixedBytes::from([0x66; 32]),
        utxo_tree_in: 9,
        railgun_txid: uint!(7_U256),
        txid_merkleroot_index: None,
        pre_transaction_pois_per_txid_leaf_per_list: BTreeMap::from([(
            list_key,
            BTreeMap::from([(txid_leaf, sample_pre_tx_poi(0x10))]),
        )]),
        required_poi_list_keys: vec![list_key],
        output_role: PendingOutputPoiRole::Recipient,
        created_at: 123,
        source_operation_id: None,
        observation: None,
        submitted_poi_list_keys: Vec::new(),
        terminal_error: None,
    }
}

pub(super) fn matching_pending_output_record(
    cfg: &WalletConfig,
    wallet_utxo: &WalletUtxo,
    list_key: FixedBytes<32>,
) -> PendingOutputPoiContextRecord {
    let mut record = pending_output_record(
        cfg.chain.chain_id,
        wallet_utxo.utxo.poi.commitment,
        list_key,
    );
    record.wallet_id = cfg.cache_key.to_string();
    record.output_npk = wallet_utxo.utxo.poi.npk;
    record.observation = Some(local_db::PendingOutputPoiObservation {
        output_tree: u64::from(wallet_utxo.utxo.tree),
        output_position: wallet_utxo.utxo.position,
        tx_hash: wallet_utxo.utxo.source.tx_hash,
        block_number: wallet_utxo.utxo.source.block_number,
        block_timestamp: wallet_utxo.utxo.source.block_timestamp,
    });
    record
}

pub(super) fn external_pending_output_record(
    cfg: &WalletConfig,
    byte: u8,
    list_key: FixedBytes<32>,
    output_role: PendingOutputPoiRole,
) -> PendingOutputPoiContextRecord {
    let mut record =
        pending_output_record(cfg.chain.chain_id, FixedBytes::from([byte; 32]), list_key);
    record.wallet_id = cfg.cache_key.to_string();
    record.output_role = output_role;
    record.observation = Some(local_db::PendingOutputPoiObservation {
        output_tree: u64::from(byte),
        output_position: u64::from(byte) + 1,
        tx_hash: source(byte).tx_hash,
        block_number: u64::from(byte),
        block_timestamp: 1_700_000_000 + u64::from(byte),
    });
    record
}

pub(super) fn recovered_outgoing_pending_group(
    cfg: &WalletConfig,
    list_key: FixedBytes<32>,
) -> Vec<PendingOutputPoiContextRecord> {
    let source = source(0xd0);
    let fixture = current_poi_fixture("ppoi_3x3_two_outputs");
    let global: u128 = fixture.public_context.output_start_global.to();
    let material = BTreeMap::from([(
        list_key,
        BTreeMap::from([(FixedBytes::from([0xd3; 32]), fixture.pre_tx_poi.clone())]),
    )]);
    fixture
        .public_context
        .commitments_out
        .iter()
        .enumerate()
        .map(|(index, commitment)| {
            let mut record = external_pending_output_record(
                cfg,
                0xd1 + u8::try_from(index).expect("bounded output index"),
                list_key,
                PendingOutputPoiRole::RecoveredOutgoing,
            );
            record.txid_merkleroot_index = Some(77);
            record.source_operation_id = Some("test-recovered-sender-inner-7".to_string());
            record.output_commitment = FixedBytes::from(commitment.to_be_bytes::<32>());
            record.output_npk =
                FixedBytes::from(fixture.public_context.output_npks[index].to_be_bytes::<32>());
            record.utxo_tree_in = fixture.public_context.input_tree;
            record.railgun_txid = fixture.public_context.railgun_txid;
            let position = global + u128::try_from(index).expect("bounded index");
            record.observation = Some(local_db::PendingOutputPoiObservation {
                output_tree: u64::try_from(position / u128::from(TREE_LEAF_COUNT))
                    .expect("output tree"),
                output_position: u64::try_from(position % u128::from(TREE_LEAF_COUNT))
                    .expect("output position"),
                tx_hash: source.tx_hash,
                block_number: source.block_number,
                block_timestamp: source.block_timestamp,
            });
            record.pre_transaction_pois_per_txid_leaf_per_list = material.clone();
            record
        })
        .collect()
}

pub(super) fn seed_recovered_outgoing_pending_group(
    store: &DbStore,
    cfg: &WalletConfig,
    records: &[PendingOutputPoiContextRecord],
) {
    for record in records {
        store
            .put_pending_output_poi_context(record)
            .expect("store recovered outgoing context");
        let mut recovery = output_poi_recovery_record(
            cfg.chain.chain_id,
            &cfg.cache_key,
            record.output_commitment,
            OutputPoiRecoveryStatus::Recoverable,
            None,
        );
        recovery.source_tx_hash = record.observation.as_ref().expect("observation").tx_hash;
        store
            .put_output_poi_recovery(&recovery)
            .expect("store recovered outgoing recovery");
    }
}

pub(super) struct SenderMaterializationTestFixture {
    pub(super) cfg: WalletConfig,
    pub(super) candidate: SenderTransactionCandidate,
    pub(super) input: WalletUtxo,
    pub(super) pending: Vec<PendingOutputPoiContextRecord>,
    pub(super) recoveries: Vec<OutputPoiRecoveryRecord>,
    pub(super) fence: SenderCandidatePublicDataFence,
}

pub(super) fn output_poi_recovery_record(
    chain_id: u64,
    wallet_id: &str,
    output_commitment: FixedBytes<32>,
    status: OutputPoiRecoveryStatus,
    next_retry_at: Option<u64>,
) -> OutputPoiRecoveryRecord {
    OutputPoiRecoveryRecord {
        chain_id,
        wallet_id: wallet_id.to_string(),
        output_commitment,
        source_tx_hash: FixedBytes::from([0x99; 32]),
        tx_input: None,
        status,
        created_at: 1,
        updated_at: 1,
        last_detection_at: Some(1),
        last_submission_at: None,
        next_retry_at,
        attempt_count: 0,
        last_error: None,
    }
}

pub(super) fn wallet_ppoi_workflow_status_for_test(
    store: &DbStore,
    cfg: &WalletConfig,
    active_list_keys: &[FixedBytes<32>],
    validation_revision: u64,
) -> WalletPpoiWorkflowStatus {
    wallet_ppoi_workflow_status_after_mutations(
        store,
        cfg,
        active_list_keys,
        validation_revision,
        PoiPrivateRows::default(),
    )
    .expect("derive workflow status")
    .status
}
