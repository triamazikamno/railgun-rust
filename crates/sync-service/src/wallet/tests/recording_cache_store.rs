use super::*;

#[derive(Debug, Clone, Copy, Default)]
pub(super) struct RecordingCacheState {
    pub(super) store_calls: usize,
    pub(super) meta_calls: usize,
    pub(super) reset_calls: usize,
    pub(super) pending_output_read_calls: usize,
    pub(super) pending_output_list_calls: usize,
    pub(super) output_recovery_read_calls: usize,
    pub(super) fail_next_store: bool,
    pub(super) fail_next_commit: bool,
    pub(super) fail_pending_output_list_call: Option<usize>,
    pub(super) candidate_list_calls: usize,
    pub(super) fail_next_candidate_list: bool,
}

pub(super) struct RecordingCacheStore {
    pub(super) db: Arc<DbStore>,
    pub(super) state: Mutex<RecordingCacheState>,
    pub(super) context_replacement: Mutex<Option<(usize, PendingOutputPoiContextRecord)>>,
}

impl RecordingCacheStore {
    pub(super) fn new(db: Arc<DbStore>) -> Self {
        Self {
            db,
            state: Mutex::default(),
            context_replacement: Mutex::default(),
        }
    }

    pub(super) fn replace_context_before_recovery_read(
        &self,
        call_index: usize,
        replacement: PendingOutputPoiContextRecord,
    ) {
        *self.context_replacement.lock().expect("replacement state") =
            Some((call_index, replacement));
    }

    pub(super) fn fail_next_store(&self) {
        self.state.lock().expect("cache state").fail_next_store = true;
    }

    pub(super) fn fail_next_commit(&self) {
        self.state.lock().expect("cache state").fail_next_commit = true;
    }

    pub(super) fn fail_pending_output_list_call(&self, call_index: usize) {
        self.state
            .lock()
            .expect("cache state")
            .fail_pending_output_list_call = Some(call_index);
    }

    pub(super) fn fail_next_candidate_list(&self) {
        self.state
            .lock()
            .expect("cache state")
            .fail_next_candidate_list = true;
    }

    pub(super) fn state(&self) -> RecordingCacheState {
        *self.state.lock().expect("cache state")
    }
}

impl WalletCacheStore for RecordingCacheStore {
    fn commit_wallet_private_state(
        &self,
        commit: WalletPrivateCommit<'_>,
    ) -> Result<(), WalletCacheError> {
        if matches!(commit.utxo_mutation(), WalletUtxoMutation::Replace(_)) {
            let mut state = self.state.lock().expect("cache state");
            state.store_calls += 1;
            if state.fail_next_store {
                state.fail_next_store = false;
                return Err(WalletCacheError::Crypto);
            }
        } else {
            self.state.lock().expect("cache state").meta_calls += 1;
        }
        let mut state = self.state.lock().expect("cache state");
        if state.fail_next_commit {
            state.fail_next_commit = false;
            return Err(WalletCacheError::Crypto);
        }
        drop(state);
        <DbStore as WalletCacheStore>::commit_wallet_private_state(self.db.as_ref(), commit)
    }

    fn load_wallet_utxos(
        &self,
        _wallet_id: &WalletCacheKey,
    ) -> Result<Vec<WalletUtxo>, WalletCacheError> {
        Ok(Vec::new())
    }

    fn get_wallet_meta(
        &self,
        _wallet_id: &WalletCacheKey,
    ) -> Result<Option<WalletMeta>, WalletCacheError> {
        Ok(None)
    }

    fn get_wallet_sync_actor_state(
        &self,
        _chain_id: u64,
        _wallet_id: &WalletCacheKey,
    ) -> Result<Option<WalletSyncActorStateRecord>, WalletCacheError> {
        Ok(None)
    }

    fn put_wallet_sync_actor_state(
        &self,
        commit: WalletSyncActorStateCommit<'_>,
    ) -> Result<(), WalletCacheError> {
        self.db.put_wallet_sync_actor_state(commit.state())?;
        Ok(())
    }

    fn get_pending_output_poi_context(
        &self,
        chain_id: u64,
        wallet_id: &WalletCacheKey,
        output_commitment: &FixedBytes<32>,
    ) -> Result<Option<PendingOutputPoiContextRecord>, WalletCacheError> {
        self.state
            .lock()
            .expect("cache state")
            .pending_output_read_calls += 1;
        <DbStore as WalletCacheStore>::get_pending_output_poi_context(
            self.db.as_ref(),
            chain_id,
            wallet_id,
            output_commitment,
        )
    }

    fn list_pending_output_poi_contexts(
        &self,
        chain_id: u64,
        wallet_id: &WalletCacheKey,
    ) -> Result<Vec<PendingOutputPoiContextRecord>, WalletCacheError> {
        let mut state = self.state.lock().expect("cache state");
        state.pending_output_read_calls += 1;
        let call_index = state.pending_output_list_calls;
        state.pending_output_list_calls += 1;
        if state.fail_pending_output_list_call == Some(call_index) {
            state.fail_pending_output_list_call = None;
            return Err(WalletCacheError::Crypto);
        }
        drop(state);
        <DbStore as WalletCacheStore>::list_pending_output_poi_contexts(
            self.db.as_ref(),
            chain_id,
            wallet_id,
        )
    }

    fn get_output_poi_recovery(
        &self,
        chain_id: u64,
        wallet_id: &WalletCacheKey,
        output_commitment: &FixedBytes<32>,
    ) -> Result<Option<OutputPoiRecoveryRecord>, WalletCacheError> {
        let call_index = {
            let mut state = self.state.lock().expect("cache state");
            let call_index = state.output_recovery_read_calls;
            state.output_recovery_read_calls += 1;
            call_index
        };
        let replacement = {
            let mut replacement = self.context_replacement.lock().expect("replacement state");
            if replacement
                .as_ref()
                .is_some_and(|(replace_at, _)| *replace_at == call_index)
            {
                replacement.take().map(|(_, replacement)| replacement)
            } else {
                None
            }
        };
        if let Some(replacement) = replacement {
            self.db.put_pending_output_poi_context(&replacement)?;
        }
        <DbStore as WalletCacheStore>::get_output_poi_recovery(
            self.db.as_ref(),
            chain_id,
            wallet_id,
            output_commitment,
        )
    }

    fn list_output_poi_recoveries(
        &self,
        chain_id: u64,
        wallet_id: &WalletCacheKey,
    ) -> Result<Vec<OutputPoiRecoveryRecord>, WalletCacheError> {
        self.state
            .lock()
            .expect("cache state")
            .output_recovery_read_calls += 1;
        <DbStore as WalletCacheStore>::list_output_poi_recoveries(
            self.db.as_ref(),
            chain_id,
            wallet_id,
        )
    }

    fn get_sender_transaction_candidate(
        &self,
        chain_id: u64,
        wallet_id: &WalletCacheKey,
        outer_transaction_hash: &FixedBytes<32>,
    ) -> Result<Option<crate::SenderTransactionCandidate>, WalletCacheError> {
        <DbStore as WalletCacheStore>::get_sender_transaction_candidate(
            self.db.as_ref(),
            chain_id,
            wallet_id,
            outer_transaction_hash,
        )
    }

    fn list_sender_transaction_candidates(
        &self,
        chain_id: u64,
        wallet_id: &WalletCacheKey,
    ) -> Result<Vec<crate::SenderTransactionCandidate>, WalletCacheError> {
        let mut state = self.state.lock().expect("cache state");
        state.candidate_list_calls += 1;
        if state.fail_next_candidate_list {
            state.fail_next_candidate_list = false;
            return Err(WalletCacheError::Crypto);
        }
        drop(state);
        <DbStore as WalletCacheStore>::list_sender_transaction_candidates(
            self.db.as_ref(),
            chain_id,
            wallet_id,
        )
    }
}
