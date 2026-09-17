use super::*;
use alloy::primitives::{Bytes, U256};
use broadcaster_core::contracts::railgun::CommitmentCiphertext;
use broadcaster_core::transact::{DEFAULT_TXID_VERSION, SnarkJsProof};
use local_db::PendingOutputPoiRole;
use std::sync::atomic::{AtomicUsize, Ordering};
use tokio::sync::Notify;

#[derive(Default)]
struct Transport {
    calls: Mutex<Vec<(FixedBytes<32>, u64, u64, usize)>>,
    failures: AtomicUsize,
    block: bool,
    release: Notify,
    transact_calls: AtomicUsize,
}

#[async_trait::async_trait]
impl PendingOutputPoiSubmitter for Transport {
    async fn submit_single_commitment_proofs(
        &self,
        _: &str,
        _: u8,
        _: u64,
        context: &SingleCommitmentProofContext,
        tree: u64,
        position: u64,
    ) -> Result<(), PoiError> {
        self.calls.lock().unwrap().push((
            context.commitment,
            tree,
            position,
            context.pre_transaction_pois_per_txid_leaf_per_list.len(),
        ));
        if self.block {
            self.release.notified().await;
        }
        if self
            .failures
            .fetch_update(Ordering::SeqCst, Ordering::SeqCst, |n| n.checked_sub(1))
            .is_ok()
        {
            return Err(PoiError::MerkleRootsRejected);
        }
        Ok(())
    }

    async fn submit_transact_proof(
        &self,
        _: &str,
        _: u8,
        _: u64,
        _: &FixedBytes<32>,
        _: u64,
        _: &PreTxPoi,
    ) -> Result<(), PoiError> {
        self.transact_calls.fetch_add(1, Ordering::SeqCst);
        if self.block {
            self.release.notified().await;
        }
        Ok(())
    }
}

fn context(byte: u8) -> SingleCommitmentProofContext {
    SingleCommitmentProofContext {
        txid_version: DEFAULT_TXID_VERSION.to_owned(),
        railgun_txid: U256::from(7),
        utxo_tree_in: 4,
        commitment: FixedBytes::repeat_byte(byte),
        npk: FixedBytes::repeat_byte(0x33),
        pre_transaction_pois_per_txid_leaf_per_list: BTreeMap::from([(
            FixedBytes::repeat_byte(0x44),
            BTreeMap::from([(
                FixedBytes::repeat_byte(0x55),
                PreTxPoi {
                    snark_proof: SnarkJsProof {
                        pi_a: [U256::from(1); 2],
                        pi_b: [[U256::from(2); 2]; 2],
                        pi_c: [U256::from(3); 2],
                    },
                    txid_merkleroot: FixedBytes::repeat_byte(0x66),
                    poi_merkleroots: vec![FixedBytes::repeat_byte(0x77)],
                    blinded_commitments_out: vec![FixedBytes::repeat_byte(0x88)],
                    railgun_txid_if_has_unshield: Bytes::from(vec![0]),
                },
            )]),
        )]),
    }
}

fn record(context: &SingleCommitmentProofContext) -> PendingOutputPoiContextRecord {
    PendingOutputPoiContextRecord {
        chain_id: 1,
        wallet_id: "sender".to_owned(),
        txid_version: context.txid_version.clone(),
        output_commitment: context.commitment,
        output_npk: context.npk,
        utxo_tree_in: context.utxo_tree_in,
        railgun_txid: context.railgun_txid,
        txid_merkleroot_index: None,
        pre_transaction_pois_per_txid_leaf_per_list: context
            .pre_transaction_pois_per_txid_leaf_per_list
            .clone(),
        required_poi_list_keys: context
            .pre_transaction_pois_per_txid_leaf_per_list
            .keys()
            .copied()
            .collect(),
        output_role: PendingOutputPoiRole::Recipient,
        created_at: 1,
        source_operation_id: None,
        observation: None,
        submitted_poi_list_keys: vec![],
        terminal_error: None,
    }
}

fn log(commitments: &[FixedBytes<32>], position: u64) -> Log {
    let data = Transact {
        treeNumber: U256::from(4),
        startPosition: U256::from(position),
        hash: commitments.to_vec(),
        ciphertext: commitments
            .iter()
            .map(|_| CommitmentCiphertext {
                ciphertext: [FixedBytes::ZERO; 4],
                blindedSenderViewingKey: FixedBytes::ZERO,
                blindedReceiverViewingKey: FixedBytes::ZERO,
                annotationData: Bytes::new(),
                memo: Bytes::new(),
            })
            .collect(),
    }
    .encode_log_data();
    Log {
        inner: alloy::primitives::Log {
            address: Address::repeat_byte(0x11),
            data,
        },
        block_number: Some(100),
        block_hash: Some(FixedBytes::repeat_byte(0x99)),
        transaction_hash: Some(FixedBytes::repeat_byte(0x22)),
        ..Log::default()
    }
}

fn service(transport: &Arc<Transport>) -> Arc<ChainPoiSubmitter> {
    Arc::new(ChainPoiSubmitter::new(
        1,
        Address::repeat_byte(0x11),
        transport.clone(),
        CancellationToken::new(),
    ))
}

async fn drain() {
    for _ in 0..10 {
        tokio::task::yield_now().await;
    }
}

#[tokio::test(start_paused = true)]
async fn retained_contexts_submit_from_chain_logs_after_sender_is_gone() {
    let transport = Arc::new(Transport::default());
    let service = service(&transport);
    let sender = vec![record(&context(1)), record(&context(2))];
    service.retain(&sender);
    drop(sender);
    assert!(transport.calls.lock().unwrap().is_empty());
    service.observe_logs(&[log(
        &[
            context(1).commitment,
            FixedBytes::ZERO,
            context(2).commitment,
        ],
        100,
    )]);
    drain().await;
    assert_eq!(
        *transport.calls.lock().unwrap(),
        vec![
            (context(1).commitment, 4, 100, 1),
            (context(2).commitment, 4, 102, 1)
        ]
    );
}

#[tokio::test(start_paused = true)]
async fn active_wallet_and_chain_share_inflight_and_completed_submissions() {
    let transport = Arc::new(Transport {
        block: true,
        ..Transport::default()
    });
    let service = service(&transport);
    let context = context(1);
    service.retain(&[record(&context)]);
    service.observe_logs(&[log(&[context.commitment], 100)]);
    let waiter = tokio::spawn({
        let service = service.clone();
        let context = context.clone();
        async move { service.submit_single(&context, 4, 100).await }
    });
    drain().await;
    assert_eq!(transport.calls.lock().unwrap().len(), 1);
    transport.release.notify_waiters();
    waiter.await.unwrap().unwrap();
    service.observe_logs(&[log(&[context.commitment], 100)]);
    service.submit_single(&context, 4, 100).await.unwrap();
    assert_eq!(transport.calls.lock().unwrap().len(), 1);
}

#[tokio::test(start_paused = true)]
async fn cancelled_wallet_waiter_does_not_cancel_chain_retry() {
    let transport = Arc::new(Transport {
        failures: AtomicUsize::new(1),
        ..Transport::default()
    });
    let service = service(&transport);
    let waiter = tokio::spawn({
        let service = service.clone();
        async move { service.submit_single(&context(1), 4, 100).await }
    });
    drain().await;
    assert_eq!(transport.calls.lock().unwrap().len(), 1);
    waiter.abort();
    let _ = waiter.await;
    tokio::time::advance(RETRY_INTERVAL).await;
    drain().await;
    service.submit_single(&context(1), 4, 100).await.unwrap();
    assert_eq!(transport.calls.lock().unwrap().len(), 2);
}

#[tokio::test(start_paused = true)]
async fn deduplication_is_per_list_and_location_and_allows_explicit_retry() {
    let transport = Arc::new(Transport::default());
    let service = service(&transport);
    let first = context(1);
    let mut both = first.clone();
    both.pre_transaction_pois_per_txid_leaf_per_list.insert(
        FixedBytes::repeat_byte(0x45),
        first
            .pre_transaction_pois_per_txid_leaf_per_list
            .values()
            .next()
            .unwrap()
            .clone(),
    );
    service.submit_single(&first, 4, 100).await.unwrap();
    service.submit_single(&both, 4, 100).await.unwrap();
    assert_eq!(transport.calls.lock().unwrap().len(), 2);
    service.submit_single(&first, 4, 101).await.unwrap();
    assert_eq!(transport.calls.lock().unwrap().len(), 3);
    service.retry_completed();
    service.submit_single(&first, 4, 101).await.unwrap();
    assert_eq!(transport.calls.lock().unwrap().len(), 4);
    tokio::time::advance(SUCCESS_TTL).await;
    service.submit_single(&first, 4, 101).await.unwrap();
    assert_eq!(transport.calls.lock().unwrap().len(), 5);
}

#[tokio::test(start_paused = true)]
async fn unrelated_removed_and_expired_logs_do_not_submit() {
    let transport = Arc::new(Transport::default());
    let service = service(&transport);
    service.retain(&[record(&context(1))]);
    let mut wrong_contract = log(&[context(1).commitment], 100);
    wrong_contract.inner.address = Address::ZERO;
    let mut removed = log(&[context(1).commitment], 100);
    removed.removed = true;
    service.observe_logs(&[wrong_contract, removed, log(&[context(2).commitment], 100)]);
    drain().await;
    assert!(transport.calls.lock().unwrap().is_empty());
    tokio::time::advance(JOB_TIMEOUT).await;
    service.observe_logs(&[log(&[context(1).commitment], 100)]);
    drain().await;
    assert!(transport.calls.lock().unwrap().is_empty());
}

#[tokio::test(start_paused = true)]
async fn reset_and_shutdown_cancel_owned_transport_and_clear_prepared_contexts() {
    let transport = Arc::new(Transport {
        block: true,
        ..Transport::default()
    });
    let service = service(&transport);
    service.retain(&[record(&context(2))]);
    let waiter = tokio::spawn({
        let service = service.clone();
        async move { service.submit_single(&context(1), 4, 100).await }
    });
    drain().await;
    service.reset().await;
    assert!(waiter.await.unwrap().is_err());
    service.observe_logs(&[log(&[context(2).commitment], 100)]);
    drain().await;
    assert_eq!(transport.calls.lock().unwrap().len(), 1);
    let waiter = tokio::spawn({
        let service = service.clone();
        async move { service.submit_single(&context(1), 4, 100).await }
    });
    drain().await;
    service.cancel();
    assert!(waiter.await.unwrap().is_err());
    assert!(service.submit_single(&context(1), 4, 100).await.is_err());
    assert_eq!(transport.calls.lock().unwrap().len(), 2);
}

#[tokio::test(start_paused = true)]
async fn transact_proofs_also_survive_waiter_cancellation_and_deduplicate() {
    let transport = Arc::new(Transport {
        block: true,
        ..Transport::default()
    });
    let service = service(&transport);
    let context = context(1);
    let (list, proofs) = context
        .pre_transaction_pois_per_txid_leaf_per_list
        .iter()
        .next()
        .unwrap();
    let proof = proofs.values().next().unwrap();
    let waiter = tokio::spawn({
        let service = service.clone();
        let proof = proof.clone();
        let list = *list;
        async move {
            service
                .submit_transact(DEFAULT_TXID_VERSION, list, 42, &proof)
                .await
        }
    });
    drain().await;
    waiter.abort();
    let _ = waiter.await;
    transport.release.notify_waiters();
    drain().await;
    service
        .submit_transact(DEFAULT_TXID_VERSION, *list, 42, proof)
        .await
        .unwrap();
    assert_eq!(transport.transact_calls.load(Ordering::SeqCst), 1);
}

#[tokio::test(start_paused = true)]
async fn confirmed_location_cancels_a_tentative_submission_at_a_different_position() {
    let transport = Arc::new(Transport {
        block: true,
        ..Transport::default()
    });
    let service = service(&transport);
    service.retain(&[record(&context(1))]);
    let waiter = tokio::spawn({
        let service = service.clone();
        async move { service.submit_single(&context(1), 4, 99).await }
    });
    drain().await;
    service.observe_logs(&[log(&[context(1).commitment], 100)]);
    assert!(waiter.await.unwrap().is_err());
    drain().await;
    transport.release.notify_waiters();
    drain().await;
    service.submit_single(&context(1), 4, 100).await.unwrap();
    assert_eq!(
        *transport.calls.lock().unwrap(),
        vec![
            (context(1).commitment, 4, 99, 1),
            (context(1).commitment, 4, 100, 1)
        ]
    );
}

#[tokio::test(start_paused = true)]
async fn all_lists_are_handed_off_before_waiting_for_the_first_submission() {
    let transport = Arc::new(Transport {
        block: true,
        ..Transport::default()
    });
    let service = service(&transport);
    let mut context = context(1);
    let proofs = context
        .pre_transaction_pois_per_txid_leaf_per_list
        .values()
        .next()
        .unwrap()
        .clone();
    context
        .pre_transaction_pois_per_txid_leaf_per_list
        .insert(FixedBytes::repeat_byte(0x45), proofs);
    let waiter = tokio::spawn({
        let service = service.clone();
        let context = context.clone();
        async move { service.submit_single(&context, 4, 100).await }
    });
    drain().await;
    assert_eq!(transport.calls.lock().unwrap().len(), 2);
    waiter.abort();
    let _ = waiter.await;
    transport.release.notify_waiters();
    drain().await;
    service.submit_single(&context, 4, 100).await.unwrap();
    assert_eq!(transport.calls.lock().unwrap().len(), 2);
}
