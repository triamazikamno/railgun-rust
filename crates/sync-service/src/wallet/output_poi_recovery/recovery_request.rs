#[allow(clippy::wildcard_imports)]
use super::*;

impl OutputPoiRecoveryRequest<'_> {
    pub(in crate::wallet) async fn local_proof_source_if_ready(
        &self,
        required_poi_list_keys: &[FixedBytes<32>],
    ) -> Option<(
        LocalPoiMerkleProofSource,
        PoiCorpusRevision,
        PublicPoiCorpusHandle,
    )> {
        match self.poi_runtime {
            WalletPoiRuntime::IndexedArtifacts { .. } => {
                let corpus = self
                    .public_data_plane
                    .ensure_poi_corpus(PublicPoiCorpusKey::wallet_default(self.cfg.chain.chain_id))
                    .await
                    .ok()?;
                // Read the revision and check readiness against the same published corpus. The
                // fence is released before returning, so callers never hold it across proof
                // generation or a wallet actor round trip.
                let revision_fence = corpus.revision_read_fence().await;
                let revision = *corpus.committed_revision_rx().borrow();
                let source = corpus.merkle_proof_source();
                let ready = source
                    .available_for_lists(self.cfg.chain.chain_id, required_poi_list_keys)
                    .await;
                drop(revision_fence);
                ready.then_some((source, revision, corpus))
            }
            WalletPoiRuntime::PoiProxy { .. } => None,
        }
    }

    pub(in crate::wallet) async fn resolve_proof_source(
        &self,
        required_poi_list_keys: &[FixedBytes<32>],
    ) -> OutputPoiProofSourceResolution {
        if let Some((source, revision, corpus)) = self
            .local_proof_source_if_ready(required_poi_list_keys)
            .await
        {
            OutputPoiProofSourceResolution::Local {
                source,
                revision,
                corpus,
            }
        } else {
            OutputPoiProofSourceResolution::Unavailable
        }
    }
}

impl OutputPoiRecoveryRequest<'_> {
    pub(super) async fn candidate_still_current(
        &self,
        candidate: &WalletUtxo,
        required_poi_list_keys: &[FixedBytes<32>],
    ) -> bool {
        output_poi_recovery_candidate_still_current(
            self.authority,
            self.cache_store,
            self.cfg,
            candidate,
            required_poi_list_keys,
        )
        .await
    }
}

async fn output_poi_recovery_candidate_still_current(
    authority: &WalletPrivateMutationAuthority<'_>,
    cache_store: &dyn WalletCacheStore,
    cfg: &WalletConfig,
    candidate: &WalletUtxo,
    required_poi_list_keys: &[FixedBytes<32>],
) -> bool {
    if required_poi_list_keys.is_empty() {
        return false;
    }
    if authority.revalidate().is_err() {
        debug!(target: LOG_TARGET,
            chain_id = cfg.chain.chain_id,
            "output POI recovery side effect rejected"
        );
        return false;
    }
    let Ok(snapshot) = authority.wallet_utxos().await else {
        debug!(target: LOG_TARGET,
            chain_id = cfg.chain.chain_id,
            "output POI recovery side effect skipped before wallet state check"
        );
        return false;
    };
    if !snapshot.iter().any(|wallet_utxo| {
        !wallet_utxo.is_spent()
            && wallet_utxo.utxo.tree == candidate.utxo.tree
            && wallet_utxo.utxo.position == candidate.utxo.position
            && wallet_utxo.utxo.source.tx_hash == candidate.utxo.source.tx_hash
            && wallet_utxo.utxo.poi.commitment == candidate.utxo.poi.commitment
            && output_poi_statuses_are_recoverable_for_lists(
                &wallet_utxo.utxo.poi,
                required_poi_list_keys,
            )
    }) {
        debug!(target: LOG_TARGET,
            chain_id = cfg.chain.chain_id,
            "output POI recovery side effect skipped; output no longer matches wallet state"
        );
        return false;
    }
    match cache_store.get_output_poi_recovery(
        cfg.chain.chain_id,
        &cfg.cache_key,
        &candidate.utxo.poi.commitment,
    ) {
        Ok(record) if output_poi_recovery_source_matches_candidate(record.as_ref(), candidate) => {}
        Ok(_) => {
            debug!(target: LOG_TARGET,
                chain_id = cfg.chain.chain_id,
                "output POI recovery side effect skipped; cached recovery source transaction is stale"
            );
            return false;
        }
        Err(_) => {
            debug!(target: LOG_TARGET,
                chain_id = cfg.chain.chain_id,
                "output POI recovery side effect skipped; recovery source could not be checked"
            );
            return false;
        }
    }
    if authority.revalidate().is_err() {
        debug!(target: LOG_TARGET,
            chain_id = cfg.chain.chain_id,
            "output POI recovery side effect rejected after wallet state check"
        );
        return false;
    }
    true
}
