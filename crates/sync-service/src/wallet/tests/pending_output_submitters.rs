use super::*;

#[derive(Default)]
pub(super) struct RecordingPendingOutputPoiSubmitter {
    pub(super) calls: Mutex<Vec<(FixedBytes<32>, u64, u64)>>,
    pub(super) list_key_calls: Mutex<Vec<Vec<FixedBytes<32>>>>,
    pub(super) fail_next: Mutex<bool>,
    pub(super) next_remote_error: Mutex<Option<RecordingPendingOutputPoiRemoteError>>,
}

#[derive(Clone, Copy)]
pub(super) enum RecordingPendingOutputPoiRemoteError {
    MissingRailgunTxid,
    Other,
}

impl RecordingPendingOutputPoiSubmitter {
    pub(super) fn fail_next(&self) {
        *self.fail_next.lock().expect("fail next") = true;
    }

    pub(super) fn fail_next_missing_railgun_txid(&self) {
        *self.next_remote_error.lock().expect("remote error") =
            Some(RecordingPendingOutputPoiRemoteError::MissingRailgunTxid);
    }

    pub(super) fn fail_next_other_remote_error(&self) {
        *self.next_remote_error.lock().expect("remote error") =
            Some(RecordingPendingOutputPoiRemoteError::Other);
    }

    pub(super) fn take_error(&self) -> Option<PoiError> {
        if let Some(error) = self.next_remote_error.lock().expect("remote error").take() {
            let message = match error {
                RecordingPendingOutputPoiRemoteError::MissingRailgunTxid => {
                    "Could not find railgun txid"
                }
                RecordingPendingOutputPoiRemoteError::Other => "different remote failure",
            };
            return Some(PoiError::RpcRequest {
                source: PoiRpcError::JsonRpc {
                    code: -1,
                    message: message.to_owned(),
                    data: None,
                },
            });
        }
        let mut fail_next = self.fail_next.lock().expect("fail next");
        if *fail_next {
            *fail_next = false;
            Some(PoiError::MerkleRootsRejected)
        } else {
            None
        }
    }

    pub(super) fn calls(&self) -> Vec<(FixedBytes<32>, u64, u64)> {
        self.calls.lock().expect("submission calls").clone()
    }

    pub(super) fn list_key_calls(&self) -> Vec<Vec<FixedBytes<32>>> {
        self.list_key_calls
            .lock()
            .expect("submission list key calls")
            .clone()
    }
}

#[async_trait]
impl PendingOutputPoiSubmitter for RecordingPendingOutputPoiSubmitter {
    async fn submit_single_commitment_proofs(
        &self,
        _txid_version: &str,
        _chain_type: u8,
        _chain_id: u64,
        context: &SingleCommitmentProofContext,
        utxo_tree_out: u64,
        utxo_position_out: u64,
    ) -> Result<(), PoiError> {
        self.list_key_calls
            .lock()
            .expect("submission list key calls")
            .push(
                context
                    .pre_transaction_pois_per_txid_leaf_per_list
                    .keys()
                    .copied()
                    .collect(),
            );
        self.calls.lock().expect("submission calls").push((
            context.commitment,
            utxo_tree_out,
            utxo_position_out,
        ));
        if let Some(error) = self.take_error() {
            return Err(error);
        }
        Ok(())
    }

    async fn submit_transact_proof(
        &self,
        _txid_version: &str,
        _chain_type: u8,
        _chain_id: u64,
        list_key: &FixedBytes<32>,
        txid_merkleroot_index: u64,
        poi: &PreTxPoi,
    ) -> Result<(), PoiError> {
        self.list_key_calls
            .lock()
            .expect("submission list key calls")
            .push(vec![*list_key]);
        self.calls.lock().expect("submission calls").push((
            poi.blinded_commitments_out
                .first()
                .copied()
                .unwrap_or_default(),
            txid_merkleroot_index,
            0,
        ));
        if let Some(error) = self.take_error() {
            return Err(error);
        }
        Ok(())
    }
}

pub(super) struct BlockingPendingOutputPoiSubmitter {
    pub(super) started: tokio::sync::Mutex<Option<oneshot::Sender<()>>>,
    pub(super) release: tokio::sync::Mutex<Option<oneshot::Receiver<()>>>,
    pub(super) calls: Mutex<Vec<(FixedBytes<32>, u64, u64)>>,
}

pub(super) struct ResetAfterFirstPendingOutputPoiSubmitter {
    pub(super) handle: WalletHandle,
    pub(super) calls: AtomicU64,
}

pub(super) struct InvalidateOwnedSubstituteAfterSubmitter {
    pub(super) handle: WalletHandle,
    pub(super) list_key: FixedBytes<32>,
    pub(super) calls: AtomicU64,
}

impl ResetAfterFirstPendingOutputPoiSubmitter {
    pub(super) fn new(handle: WalletHandle) -> Self {
        Self {
            handle,
            calls: AtomicU64::new(0),
        }
    }

    pub(super) fn calls(&self) -> u64 {
        self.calls.load(Ordering::Acquire)
    }
}

#[async_trait]
impl PendingOutputPoiSubmitter for ResetAfterFirstPendingOutputPoiSubmitter {
    async fn submit_single_commitment_proofs(
        &self,
        _txid_version: &str,
        _chain_type: u8,
        _chain_id: u64,
        _context: &SingleCommitmentProofContext,
        _utxo_tree_out: u64,
        _utxo_position_out: u64,
    ) -> Result<(), PoiError> {
        self.calls.fetch_add(1, Ordering::AcqRel);
        let _ = self.handle.advance_reset_generation().await;
        Ok(())
    }

    async fn submit_transact_proof(
        &self,
        _txid_version: &str,
        _chain_type: u8,
        _chain_id: u64,
        _list_key: &FixedBytes<32>,
        _txid_merkleroot_index: u64,
        _poi: &PreTxPoi,
    ) -> Result<(), PoiError> {
        let call = self.calls.fetch_add(1, Ordering::AcqRel);
        if call == 0 {
            let _ = self.handle.advance_reset_generation().await;
        }
        Ok(())
    }
}

#[async_trait]
impl PendingOutputPoiSubmitter for InvalidateOwnedSubstituteAfterSubmitter {
    async fn submit_single_commitment_proofs(
        &self,
        _txid_version: &str,
        _chain_type: u8,
        _chain_id: u64,
        _context: &SingleCommitmentProofContext,
        _utxo_tree_out: u64,
        _utxo_position_out: u64,
    ) -> Result<(), PoiError> {
        unreachable!("recovered outgoing group uses transact submission")
    }

    async fn submit_transact_proof(
        &self,
        _txid_version: &str,
        _chain_type: u8,
        _chain_id: u64,
        _list_key: &FixedBytes<32>,
        _txid_merkleroot_index: u64,
        _poi: &PreTxPoi,
    ) -> Result<(), PoiError> {
        self.calls.fetch_add(1, Ordering::AcqRel);
        self.handle.utxos.write().await[0]
            .utxo
            .poi
            .statuses
            .insert(self.list_key, PoiStatus::Missing);
        Ok(())
    }
}

impl BlockingPendingOutputPoiSubmitter {
    pub(super) fn new(started: oneshot::Sender<()>, release: oneshot::Receiver<()>) -> Self {
        Self {
            started: tokio::sync::Mutex::new(Some(started)),
            release: tokio::sync::Mutex::new(Some(release)),
            calls: Mutex::new(Vec::new()),
        }
    }

    pub(super) fn calls(&self) -> Vec<(FixedBytes<32>, u64, u64)> {
        self.calls
            .lock()
            .expect("blocking submission calls")
            .clone()
    }

    pub(super) async fn wait_for_release(&self) {
        if let Some(started) = self.started.lock().await.take() {
            let _ = started.send(());
        }
        if let Some(release) = self.release.lock().await.take() {
            let _ = release.await;
        }
    }
}

#[async_trait]
impl PendingOutputPoiSubmitter for BlockingPendingOutputPoiSubmitter {
    async fn submit_single_commitment_proofs(
        &self,
        _txid_version: &str,
        _chain_type: u8,
        _chain_id: u64,
        context: &SingleCommitmentProofContext,
        utxo_tree_out: u64,
        utxo_position_out: u64,
    ) -> Result<(), PoiError> {
        self.wait_for_release().await;
        self.calls.lock().expect("blocking submission calls").push((
            context.commitment,
            utxo_tree_out,
            utxo_position_out,
        ));
        Ok(())
    }

    async fn submit_transact_proof(
        &self,
        _txid_version: &str,
        _chain_type: u8,
        _chain_id: u64,
        _list_key: &FixedBytes<32>,
        txid_merkleroot_index: u64,
        poi: &PreTxPoi,
    ) -> Result<(), PoiError> {
        self.wait_for_release().await;
        self.calls.lock().expect("blocking submission calls").push((
            poi.blinded_commitments_out
                .first()
                .copied()
                .unwrap_or_default(),
            txid_merkleroot_index,
            0,
        ));
        Ok(())
    }
}
